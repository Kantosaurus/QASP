"""Tests for the token revocation system."""

from __future__ import annotations

import threading
import time
from unittest.mock import patch

import pytest

from qasp.identity import DID
from qasp.protocol.capability import (
    CapabilityToken,
    TokenRevokedError,
    attenuate_token,
    create_token,
    verify_token,
)
from qasp.protocol.revocation import (
    NORMAL_GRACE_PERIOD_SECONDS,
    CertificateRevocationList,
    InvalidRevocationError,
    RevocationEntry,
    RevocationReason,
    RevocationUrgency,
    TokenAlreadyRevokedError,
    check_revocation,
    revoke_token,
)


# =============================================================================
# RevocationUrgency Tests
# =============================================================================


class TestRevocationUrgency:
    """Tests for RevocationUrgency enum."""

    def test_enum_values(self) -> None:
        """Urgency enum has correct integer values."""
        assert RevocationUrgency.CRITICAL == 0
        assert RevocationUrgency.NORMAL == 1
        assert RevocationUrgency.PLANNED == 2

    def test_ordering(self) -> None:
        """Urgency values are ordered by severity (lower = more urgent)."""
        assert RevocationUrgency.CRITICAL < RevocationUrgency.NORMAL
        assert RevocationUrgency.NORMAL < RevocationUrgency.PLANNED


# =============================================================================
# RevocationReason Tests
# =============================================================================


class TestRevocationReason:
    """Tests for RevocationReason enum."""

    def test_enum_values(self) -> None:
        """Reason enum has correct integer values."""
        assert RevocationReason.UNSPECIFIED == 0
        assert RevocationReason.KEY_COMPROMISE == 1
        assert RevocationReason.PRIVILEGE_WITHDRAWN == 2
        assert RevocationReason.TOKEN_SUPERSEDED == 3
        assert RevocationReason.DELEGATION_REVOKED == 4
        assert RevocationReason.OWNER_REQUEST == 5
        assert RevocationReason.CONSTRAINT_VIOLATION == 6


# =============================================================================
# RevocationEntry Tests
# =============================================================================


class TestRevocationEntry:
    """Tests for RevocationEntry dataclass."""

    def test_creation(self) -> None:
        """Can create a RevocationEntry."""
        entry = RevocationEntry(
            token_id=b"\x01" * 32,
            revocation_time=1000,
            effective_time=1300,
            reason=RevocationReason.KEY_COMPROMISE,
            urgency=RevocationUrgency.NORMAL,
            revoker_did="did:qasp:test",
            parent_revocation_id=None,
            signature=b"\x00" * 64,
        )
        assert entry.token_id == b"\x01" * 32
        assert entry.revocation_time == 1000
        assert entry.effective_time == 1300
        assert entry.reason == RevocationReason.KEY_COMPROMISE
        assert entry.urgency == RevocationUrgency.NORMAL

    def test_immutability(self) -> None:
        """RevocationEntry is frozen."""
        entry = RevocationEntry(
            token_id=b"\x01" * 32,
            revocation_time=1000,
            effective_time=1300,
            reason=RevocationReason.KEY_COMPROMISE,
            urgency=RevocationUrgency.NORMAL,
            revoker_did="did:qasp:test",
            parent_revocation_id=None,
            signature=b"\x00" * 64,
        )
        with pytest.raises(AttributeError):
            entry.token_id = b"\x02" * 32  # type: ignore[misc]


# =============================================================================
# CRL Registration Tests
# =============================================================================


class TestCRLRegistration:
    """Tests for CRL token registration."""

    def test_register_single_token(
        self,
        crl: CertificateRevocationList,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """Can register a single root token."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
        )
        crl.register_token(token)
        # Token should be registered but not revoked
        assert not crl.is_revoked(token.token_id)

    def test_register_delegation_chain(
        self,
        crl: CertificateRevocationList,
        registered_token_chain: tuple[CapabilityToken, CapabilityToken, CapabilityToken],
    ) -> None:
        """Can register a delegation chain and parent-child index is built."""
        root, child, grandchild = registered_token_chain
        # All registered, none revoked
        assert not crl.is_revoked(root.token_id)
        assert not crl.is_revoked(child.token_id)
        assert not crl.is_revoked(grandchild.token_id)

    def test_parent_child_index(
        self,
        crl: CertificateRevocationList,
        registered_token_chain: tuple[CapabilityToken, CapabilityToken, CapabilityToken],
    ) -> None:
        """get_descendants returns all descendants of a token."""
        root, child, grandchild = registered_token_chain
        descendants = crl.get_descendants(root.token_id)
        assert child.token_id in descendants
        assert grandchild.token_id in descendants
        assert len(descendants) == 2


# =============================================================================
# CRL Revocation Tests
# =============================================================================


class TestCRLRevocation:
    """Tests for CRL revoke operation."""

    def test_critical_urgency(
        self,
        crl: CertificateRevocationList,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """Critical revocation is immediately effective."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
        )
        crl.register_token(token)

        entries = crl.revoke(
            token_id=token.token_id,
            reason=RevocationReason.KEY_COMPROMISE,
            urgency=RevocationUrgency.CRITICAL,
            revoker_did=str(issuer_did),
            revoker_secret_key=issuer_secret_key,
        )
        assert len(entries) == 1
        assert entries[0].effective_time == entries[0].revocation_time
        assert crl.is_revoked(token.token_id)

    def test_normal_urgency(
        self,
        crl: CertificateRevocationList,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """Normal revocation has a grace period."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
        )
        crl.register_token(token)

        entries = crl.revoke(
            token_id=token.token_id,
            reason=RevocationReason.PRIVILEGE_WITHDRAWN,
            urgency=RevocationUrgency.NORMAL,
            revoker_did=str(issuer_did),
            revoker_secret_key=issuer_secret_key,
        )
        assert len(entries) == 1
        assert entries[0].effective_time == entries[0].revocation_time + NORMAL_GRACE_PERIOD_SECONDS

    def test_planned_urgency(
        self,
        crl: CertificateRevocationList,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """Planned revocation uses scheduled_time."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
        )
        crl.register_token(token)

        future_time = int(time.time()) + 86400
        entries = crl.revoke(
            token_id=token.token_id,
            reason=RevocationReason.TOKEN_SUPERSEDED,
            urgency=RevocationUrgency.PLANNED,
            revoker_did=str(issuer_did),
            revoker_secret_key=issuer_secret_key,
            scheduled_time=future_time,
        )
        assert len(entries) == 1
        assert entries[0].effective_time == future_time

    def test_already_revoked_raises(
        self,
        crl: CertificateRevocationList,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """Revoking an already-revoked token raises TokenAlreadyRevokedError."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
        )
        crl.register_token(token)

        crl.revoke(
            token_id=token.token_id,
            reason=RevocationReason.KEY_COMPROMISE,
            urgency=RevocationUrgency.CRITICAL,
            revoker_did=str(issuer_did),
            revoker_secret_key=issuer_secret_key,
        )

        with pytest.raises(TokenAlreadyRevokedError):
            crl.revoke(
                token_id=token.token_id,
                reason=RevocationReason.KEY_COMPROMISE,
                urgency=RevocationUrgency.CRITICAL,
                revoker_did=str(issuer_did),
                revoker_secret_key=issuer_secret_key,
            )

    def test_signed_entries(
        self,
        crl: CertificateRevocationList,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """Revocation entries have non-empty signatures."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
        )
        crl.register_token(token)

        entries = crl.revoke(
            token_id=token.token_id,
            reason=RevocationReason.KEY_COMPROMISE,
            urgency=RevocationUrgency.CRITICAL,
            revoker_did=str(issuer_did),
            revoker_secret_key=issuer_secret_key,
        )
        assert len(entries[0].signature) > 0


# =============================================================================
# Revocation Cascade Tests
# =============================================================================


class TestRevocationCascade:
    """Tests for cascade revocation of delegation chains."""

    def test_cascade_to_children(
        self,
        crl: CertificateRevocationList,
        registered_token_chain: tuple[CapabilityToken, CapabilityToken, CapabilityToken],
        issuer_did: DID,
        issuer_secret_key: bytes,
    ) -> None:
        """Revoking root cascades to all descendants."""
        root, child, grandchild = registered_token_chain
        entries = crl.revoke(
            token_id=root.token_id,
            reason=RevocationReason.KEY_COMPROMISE,
            urgency=RevocationUrgency.CRITICAL,
            revoker_did=str(issuer_did),
            revoker_secret_key=issuer_secret_key,
        )
        assert len(entries) == 3
        assert crl.is_revoked(root.token_id)
        assert crl.is_revoked(child.token_id)
        assert crl.is_revoked(grandchild.token_id)

    def test_cascade_reason_is_delegation_revoked(
        self,
        crl: CertificateRevocationList,
        registered_token_chain: tuple[CapabilityToken, CapabilityToken, CapabilityToken],
        issuer_did: DID,
        issuer_secret_key: bytes,
    ) -> None:
        """Cascaded entries have DELEGATION_REVOKED reason."""
        root, child, grandchild = registered_token_chain
        entries = crl.revoke(
            token_id=root.token_id,
            reason=RevocationReason.KEY_COMPROMISE,
            urgency=RevocationUrgency.CRITICAL,
            revoker_did=str(issuer_did),
            revoker_secret_key=issuer_secret_key,
        )
        # Root keeps original reason
        assert entries[0].reason == RevocationReason.KEY_COMPROMISE
        # Children get DELEGATION_REVOKED
        for entry in entries[1:]:
            assert entry.reason == RevocationReason.DELEGATION_REVOKED

    def test_cascade_partial_only_descendants(
        self,
        crl: CertificateRevocationList,
        registered_token_chain: tuple[CapabilityToken, CapabilityToken, CapabilityToken],
        issuer_did: DID,
        issuer_secret_key: bytes,
    ) -> None:
        """Revoking a middle token only cascades to its descendants."""
        root, child, grandchild = registered_token_chain
        entries = crl.revoke(
            token_id=child.token_id,
            reason=RevocationReason.PRIVILEGE_WITHDRAWN,
            urgency=RevocationUrgency.CRITICAL,
            revoker_did=str(issuer_did),
            revoker_secret_key=issuer_secret_key,
        )
        # child + grandchild revoked
        assert len(entries) == 2
        assert not crl.is_revoked(root.token_id)
        assert crl.is_revoked(child.token_id)
        assert crl.is_revoked(grandchild.token_id)

    def test_cascade_branching(
        self,
        crl: CertificateRevocationList,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        delegate_did: DID,
        third_party_did: DID,
    ) -> None:
        """Cascade works with branching delegation (multiple children)."""
        root = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read", "write"},
            max_delegation_depth=2,
        )
        crl.register_token(root)

        child_a = attenuate_token(
            parent_token=root,
            delegator_secret_key=subject_secret_key,
            new_subject_did=delegate_did,
        )
        crl.register_token(child_a)

        child_b = attenuate_token(
            parent_token=root,
            delegator_secret_key=subject_secret_key,
            new_subject_did=third_party_did,
        )
        crl.register_token(child_b)

        entries = crl.revoke(
            token_id=root.token_id,
            reason=RevocationReason.KEY_COMPROMISE,
            urgency=RevocationUrgency.CRITICAL,
            revoker_did=str(issuer_did),
            revoker_secret_key=issuer_secret_key,
        )
        assert len(entries) == 3
        assert crl.is_revoked(child_a.token_id)
        assert crl.is_revoked(child_b.token_id)

    def test_cascade_same_effective_time(
        self,
        crl: CertificateRevocationList,
        registered_token_chain: tuple[CapabilityToken, CapabilityToken, CapabilityToken],
        issuer_did: DID,
        issuer_secret_key: bytes,
    ) -> None:
        """All cascade entries share the same effective_time."""
        root, child, grandchild = registered_token_chain
        entries = crl.revoke(
            token_id=root.token_id,
            reason=RevocationReason.KEY_COMPROMISE,
            urgency=RevocationUrgency.CRITICAL,
            revoker_did=str(issuer_did),
            revoker_secret_key=issuer_secret_key,
        )
        effective_times = {e.effective_time for e in entries}
        assert len(effective_times) == 1


# =============================================================================
# CRL Lookup Tests
# =============================================================================


class TestCRLLookup:
    """Tests for CRL lookup operations."""

    def test_is_revoked_true(
        self,
        crl: CertificateRevocationList,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """is_revoked returns True for a revoked token."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
        )
        crl.register_token(token)
        crl.revoke(
            token_id=token.token_id,
            reason=RevocationReason.KEY_COMPROMISE,
            urgency=RevocationUrgency.CRITICAL,
            revoker_did=str(issuer_did),
            revoker_secret_key=issuer_secret_key,
        )
        assert crl.is_revoked(token.token_id)

    def test_is_revoked_false(
        self,
        crl: CertificateRevocationList,
    ) -> None:
        """is_revoked returns False for an unknown token ID."""
        assert not crl.is_revoked(b"\xff" * 32)

    def test_grace_period_before(
        self,
        crl: CertificateRevocationList,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """Token in grace period is not yet effectively revoked."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
        )
        crl.register_token(token)
        crl.revoke(
            token_id=token.token_id,
            reason=RevocationReason.PRIVILEGE_WITHDRAWN,
            urgency=RevocationUrgency.NORMAL,
            revoker_did=str(issuer_did),
            revoker_secret_key=issuer_secret_key,
        )
        entry = crl.get_entry(token.token_id)
        assert entry is not None
        # Check just before effective time
        assert not crl.is_revoked(token.token_id, at_time=entry.revocation_time)

    def test_grace_period_after(
        self,
        crl: CertificateRevocationList,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """Token after grace period is effectively revoked."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
        )
        crl.register_token(token)
        crl.revoke(
            token_id=token.token_id,
            reason=RevocationReason.PRIVILEGE_WITHDRAWN,
            urgency=RevocationUrgency.NORMAL,
            revoker_did=str(issuer_did),
            revoker_secret_key=issuer_secret_key,
        )
        entry = crl.get_entry(token.token_id)
        assert entry is not None
        # Check at effective time
        assert crl.is_revoked(token.token_id, at_time=entry.effective_time)

    def test_planned_before_scheduled(
        self,
        crl: CertificateRevocationList,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """Planned revocation is not effective before scheduled time."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
        )
        crl.register_token(token)
        future_time = int(time.time()) + 86400
        crl.revoke(
            token_id=token.token_id,
            reason=RevocationReason.TOKEN_SUPERSEDED,
            urgency=RevocationUrgency.PLANNED,
            revoker_did=str(issuer_did),
            revoker_secret_key=issuer_secret_key,
            scheduled_time=future_time,
        )
        assert not crl.is_revoked(token.token_id, at_time=future_time - 1)

    def test_planned_after_scheduled(
        self,
        crl: CertificateRevocationList,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """Planned revocation is effective at and after scheduled time."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
        )
        crl.register_token(token)
        future_time = int(time.time()) + 86400
        crl.revoke(
            token_id=token.token_id,
            reason=RevocationReason.TOKEN_SUPERSEDED,
            urgency=RevocationUrgency.PLANNED,
            revoker_did=str(issuer_did),
            revoker_secret_key=issuer_secret_key,
            scheduled_time=future_time,
        )
        assert crl.is_revoked(token.token_id, at_time=future_time)

    def test_contains(
        self,
        crl: CertificateRevocationList,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """__contains__ checks entry existence regardless of grace period."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
        )
        crl.register_token(token)
        assert token.token_id not in crl
        crl.revoke(
            token_id=token.token_id,
            reason=RevocationReason.PRIVILEGE_WITHDRAWN,
            urgency=RevocationUrgency.NORMAL,
            revoker_did=str(issuer_did),
            revoker_secret_key=issuer_secret_key,
        )
        # Contains should be True even during grace period
        assert token.token_id in crl

    def test_get_entry(
        self,
        crl: CertificateRevocationList,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """get_entry returns the entry or None."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
        )
        crl.register_token(token)

        assert crl.get_entry(token.token_id) is None

        crl.revoke(
            token_id=token.token_id,
            reason=RevocationReason.KEY_COMPROMISE,
            urgency=RevocationUrgency.CRITICAL,
            revoker_did=str(issuer_did),
            revoker_secret_key=issuer_secret_key,
        )
        entry = crl.get_entry(token.token_id)
        assert entry is not None
        assert entry.token_id == token.token_id
        assert entry.reason == RevocationReason.KEY_COMPROMISE


# =============================================================================
# CRL Process Message Tests
# =============================================================================


class TestCRLProcessMessage:
    """Tests for process_revocation_message."""

    def test_valid_revocation(
        self,
        crl: CertificateRevocationList,
        issuer_did: DID,
        issuer_public_key: bytes,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """process_revocation_message creates entries on valid input."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
        )
        crl.register_token(token)

        entries = crl.process_revocation_message(
            token_id=token.token_id,
            reason=RevocationReason.KEY_COMPROMISE,
            urgency=RevocationUrgency.CRITICAL,
            revoker_did=str(issuer_did),
            revoker_public_key=issuer_public_key,
            revoker_secret_key=issuer_secret_key,
        )
        assert len(entries) == 1
        assert crl.is_revoked(token.token_id)

    def test_invalid_signature(
        self,
        crl: CertificateRevocationList,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
        subject_public_key: bytes,
    ) -> None:
        """process_revocation_message raises on mismatched key."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
        )
        crl.register_token(token)

        with pytest.raises(InvalidRevocationError):
            crl.process_revocation_message(
                token_id=token.token_id,
                reason=RevocationReason.KEY_COMPROMISE,
                urgency=RevocationUrgency.CRITICAL,
                revoker_did=str(issuer_did),
                revoker_public_key=subject_public_key,  # wrong key
                revoker_secret_key=issuer_secret_key,
            )

    def test_cascade_trigger(
        self,
        crl: CertificateRevocationList,
        registered_token_chain: tuple[CapabilityToken, CapabilityToken, CapabilityToken],
        issuer_did: DID,
        issuer_public_key: bytes,
        issuer_secret_key: bytes,
    ) -> None:
        """process_revocation_message cascades to descendants."""
        root, child, grandchild = registered_token_chain
        entries = crl.process_revocation_message(
            token_id=root.token_id,
            reason=RevocationReason.KEY_COMPROMISE,
            urgency=RevocationUrgency.CRITICAL,
            revoker_did=str(issuer_did),
            revoker_public_key=issuer_public_key,
            revoker_secret_key=issuer_secret_key,
        )
        assert len(entries) == 3
        assert crl.is_revoked(child.token_id)
        assert crl.is_revoked(grandchild.token_id)


# =============================================================================
# Thread Safety Tests
# =============================================================================


class TestCRLThreadSafety:
    """Tests for CRL thread safety."""

    def test_concurrent_revoke_and_check(
        self,
        crl: CertificateRevocationList,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """Concurrent revoke and check operations don't crash."""
        tokens = []
        for _ in range(10):
            token = create_token(
                issuer_did=issuer_did,
                issuer_secret_key=issuer_secret_key,
                subject_did=subject_did,
                resource_uri="qasp://test/resource",
                verbs={"read"},
            )
            crl.register_token(token)
            tokens.append(token)

        errors: list[Exception] = []

        def revoke_worker(tok: CapabilityToken) -> None:
            try:
                crl.revoke(
                    token_id=tok.token_id,
                    reason=RevocationReason.KEY_COMPROMISE,
                    urgency=RevocationUrgency.CRITICAL,
                    revoker_did=str(issuer_did),
                    revoker_secret_key=issuer_secret_key,
                )
            except Exception as e:
                errors.append(e)

        def check_worker() -> None:
            try:
                for tok in tokens:
                    crl.is_revoked(tok.token_id)
            except Exception as e:
                errors.append(e)

        threads = []
        for tok in tokens:
            threads.append(threading.Thread(target=revoke_worker, args=(tok,)))
        for _ in range(5):
            threads.append(threading.Thread(target=check_worker))

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0

    def test_concurrent_register_and_revoke(
        self,
        crl: CertificateRevocationList,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        delegate_did: DID,
    ) -> None:
        """Concurrent register and revoke operations don't crash."""
        root = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read", "write"},
            max_delegation_depth=2,
        )
        crl.register_token(root)

        children = []
        for _ in range(5):
            child = attenuate_token(
                parent_token=root,
                delegator_secret_key=subject_secret_key,
                new_subject_did=delegate_did,
            )
            children.append(child)

        errors: list[Exception] = []

        def register_worker(tok: CapabilityToken) -> None:
            try:
                crl.register_token(tok)
            except Exception as e:
                errors.append(e)

        def revoke_worker() -> None:
            try:
                crl.revoke(
                    token_id=root.token_id,
                    reason=RevocationReason.KEY_COMPROMISE,
                    urgency=RevocationUrgency.CRITICAL,
                    revoker_did=str(issuer_did),
                    revoker_secret_key=issuer_secret_key,
                )
            except Exception as e:
                errors.append(e)

        threads = []
        for child in children:
            threads.append(threading.Thread(target=register_worker, args=(child,)))
        threads.append(threading.Thread(target=revoke_worker))

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert crl.is_revoked(root.token_id)


# =============================================================================
# CRL Cleanup Tests
# =============================================================================


class TestCRLCleanup:
    """Tests for CRL cleanup of old entries."""

    def test_removes_old_entries(
        self,
        crl: CertificateRevocationList,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """cleanup_expired removes entries older than max_age."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
        )
        crl.register_token(token)

        # Patch time.time to make revocation appear old
        now = time.time()
        with patch("qasp.protocol.revocation.time") as mock_time:
            mock_time.time.return_value = now - 7200  # 2 hours ago
            crl.revoke(
                token_id=token.token_id,
                reason=RevocationReason.KEY_COMPROMISE,
                urgency=RevocationUrgency.CRITICAL,
                revoker_did=str(issuer_did),
                revoker_secret_key=issuer_secret_key,
            )

        with patch("qasp.protocol.revocation.time") as mock_time:
            mock_time.time.return_value = now
            removed = crl.cleanup_expired(max_age_seconds=3600)

        assert removed == 1
        assert crl.get_entry(token.token_id) is None

    def test_keeps_recent_entries(
        self,
        crl: CertificateRevocationList,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """cleanup_expired keeps entries newer than max_age."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
        )
        crl.register_token(token)
        crl.revoke(
            token_id=token.token_id,
            reason=RevocationReason.KEY_COMPROMISE,
            urgency=RevocationUrgency.CRITICAL,
            revoker_did=str(issuer_did),
            revoker_secret_key=issuer_secret_key,
        )
        removed = crl.cleanup_expired(max_age_seconds=3600)
        assert removed == 0
        assert crl.get_entry(token.token_id) is not None


# =============================================================================
# verify_token with CRL Tests
# =============================================================================


class TestVerifyTokenWithCRL:
    """Tests for verify_token integration with CRL."""

    def test_verify_unchanged_without_crl(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
    ) -> None:
        """verify_token works as before when no CRL is passed."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
        )
        assert verify_token(token, issuer_public_key) is True

    def test_verify_raises_for_revoked(
        self,
        crl: CertificateRevocationList,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
    ) -> None:
        """verify_token raises TokenRevokedError for revoked token."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
        )
        crl.register_token(token)
        crl.revoke(
            token_id=token.token_id,
            reason=RevocationReason.KEY_COMPROMISE,
            urgency=RevocationUrgency.CRITICAL,
            revoker_did=str(issuer_did),
            revoker_secret_key=issuer_secret_key,
        )
        with pytest.raises(TokenRevokedError):
            verify_token(token, issuer_public_key, crl=crl)

    def test_verify_passes_for_non_revoked(
        self,
        crl: CertificateRevocationList,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
    ) -> None:
        """verify_token passes when token is not revoked."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
        )
        crl.register_token(token)
        assert verify_token(token, issuer_public_key, crl=crl) is True


# =============================================================================
# Convenience Function Tests
# =============================================================================


class TestRevokeTokenConvenience:
    """Tests for the revoke_token convenience function."""

    def test_delegates_to_crl(
        self,
        crl: CertificateRevocationList,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """revoke_token delegates to crl.revoke."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
        )
        crl.register_token(token)

        entries = revoke_token(
            crl=crl,
            token_id=token.token_id,
            reason=RevocationReason.KEY_COMPROMISE,
            urgency=RevocationUrgency.CRITICAL,
            revoker_did=str(issuer_did),
            revoker_secret_key=issuer_secret_key,
        )
        assert len(entries) == 1
        assert crl.is_revoked(token.token_id)

    def test_check_revocation_convenience(
        self,
        crl: CertificateRevocationList,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """check_revocation delegates to crl.is_revoked."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
        )
        crl.register_token(token)

        assert not check_revocation(crl, token.token_id)

        crl.revoke(
            token_id=token.token_id,
            reason=RevocationReason.KEY_COMPROMISE,
            urgency=RevocationUrgency.CRITICAL,
            revoker_did=str(issuer_did),
            revoker_secret_key=issuer_secret_key,
        )
        assert check_revocation(crl, token.token_id)


# =============================================================================
# CRL get_pending Tests
# =============================================================================


class TestCRLGetPending:
    """Tests for CRL get_pending method."""

    def test_pending_during_grace_period(
        self,
        crl: CertificateRevocationList,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """get_pending returns entries in grace period."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
        )
        crl.register_token(token)
        crl.revoke(
            token_id=token.token_id,
            reason=RevocationReason.PRIVILEGE_WITHDRAWN,
            urgency=RevocationUrgency.NORMAL,
            revoker_did=str(issuer_did),
            revoker_secret_key=issuer_secret_key,
        )
        pending = crl.get_pending()
        assert len(pending) == 1
        assert pending[0].token_id == token.token_id

    def test_no_pending_for_critical(
        self,
        crl: CertificateRevocationList,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """get_pending returns empty for critical revocations (immediate)."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
        )
        crl.register_token(token)
        crl.revoke(
            token_id=token.token_id,
            reason=RevocationReason.KEY_COMPROMISE,
            urgency=RevocationUrgency.CRITICAL,
            revoker_did=str(issuer_did),
            revoker_secret_key=issuer_secret_key,
        )
        pending = crl.get_pending()
        assert len(pending) == 0
