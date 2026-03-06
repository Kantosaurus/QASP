"""Conformance tests for token revocation.

Tests cascade BFS, grace periods, and urgency levels.
"""

from __future__ import annotations

import time

import pytest

from qasp.crypto import signatures
from qasp.identity.did import DID, create_did
from qasp.protocol.capability import (
    CapabilityToken,
    attenuate_token,
    create_token,
)
from qasp.protocol.revocation import (
    NORMAL_GRACE_PERIOD_SECONDS,
    CertificateRevocationList,
    RevocationReason,
    RevocationUrgency,
    TokenAlreadyRevokedError,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def revoker_keypair() -> tuple[bytes, bytes]:
    return signatures.generate_keypair()


@pytest.fixture
def revoker_did(revoker_keypair: tuple[bytes, bytes]) -> DID:
    did, _ = create_did(revoker_keypair[0])
    return did


@pytest.fixture
def token_chain(
    alice_keypair: tuple[bytes, bytes],
    alice_did: tuple[DID, ...],
    alpha_keypair: tuple[bytes, bytes],
    alpha_did: tuple[DID, ...],
    beta_keypair: tuple[bytes, bytes],
    beta_did: tuple[DID, ...],
    gamma_keypair: tuple[bytes, bytes],
    gamma_did: tuple[DID, ...],
) -> tuple[CapabilityToken, CapabilityToken, CapabilityToken, CertificateRevocationList]:
    """Create a 3-level delegation chain registered in a CRL."""
    crl = CertificateRevocationList()

    root = create_token(
        issuer_did=alice_did[0],
        issuer_secret_key=alice_keypair[1],
        subject_did=alpha_did[0],
        resource_uri="arm://test/compute/gpu",
        verbs={"read", "write"},
        max_delegation_depth=3,
    )
    crl.register_token(root)

    child = attenuate_token(
        parent_token=root,
        delegator_secret_key=alpha_keypair[1],
        new_subject_did=beta_did[0],
    )
    crl.register_token(child)

    grandchild = attenuate_token(
        parent_token=child,
        delegator_secret_key=beta_keypair[1],
        new_subject_did=gamma_did[0],
    )
    crl.register_token(grandchild)

    return root, child, grandchild, crl


# =============================================================================
# Cascade BFS Revocation
# =============================================================================


class TestCascadeRevocation:
    """Verify BFS cascade revocation of delegation chains."""

    def test_revoke_root_cascades_to_all(
        self,
        token_chain: tuple[CapabilityToken, CapabilityToken, CapabilityToken, CertificateRevocationList],
        revoker_keypair: tuple[bytes, bytes],
        revoker_did: DID,
    ) -> None:
        root, child, grandchild, crl = token_chain

        entries = crl.revoke(
            token_id=root.token_id,
            reason=RevocationReason.KEY_COMPROMISE,
            urgency=RevocationUrgency.CRITICAL,
            revoker_did=str(revoker_did),
            revoker_secret_key=revoker_keypair[1],
        )

        # Root + child + grandchild = 3 entries
        assert len(entries) == 3
        assert root.token_id in crl
        assert child.token_id in crl
        assert grandchild.token_id in crl

    def test_revoke_middle_cascades_to_descendants(
        self,
        token_chain: tuple[CapabilityToken, CapabilityToken, CapabilityToken, CertificateRevocationList],
        revoker_keypair: tuple[bytes, bytes],
        revoker_did: DID,
    ) -> None:
        root, child, grandchild, crl = token_chain

        entries = crl.revoke(
            token_id=child.token_id,
            reason=RevocationReason.PRIVILEGE_WITHDRAWN,
            urgency=RevocationUrgency.CRITICAL,
            revoker_did=str(revoker_did),
            revoker_secret_key=revoker_keypair[1],
        )

        # Child + grandchild = 2 entries
        assert len(entries) == 2
        assert root.token_id not in crl
        assert child.token_id in crl
        assert grandchild.token_id in crl

    def test_revoke_leaf_no_cascade(
        self,
        token_chain: tuple[CapabilityToken, CapabilityToken, CapabilityToken, CertificateRevocationList],
        revoker_keypair: tuple[bytes, bytes],
        revoker_did: DID,
    ) -> None:
        root, child, grandchild, crl = token_chain

        entries = crl.revoke(
            token_id=grandchild.token_id,
            reason=RevocationReason.OWNER_REQUEST,
            urgency=RevocationUrgency.CRITICAL,
            revoker_did=str(revoker_did),
            revoker_secret_key=revoker_keypair[1],
        )

        assert len(entries) == 1
        assert root.token_id not in crl
        assert child.token_id not in crl
        assert grandchild.token_id in crl


# =============================================================================
# Grace Periods
# =============================================================================


class TestGracePeriods:
    """Verify urgency-based grace period handling."""

    def test_critical_immediate_effect(
        self,
        token_chain: tuple[CapabilityToken, CapabilityToken, CapabilityToken, CertificateRevocationList],
        revoker_keypair: tuple[bytes, bytes],
        revoker_did: DID,
    ) -> None:
        root, _, _, crl = token_chain

        crl.revoke(
            token_id=root.token_id,
            reason=RevocationReason.KEY_COMPROMISE,
            urgency=RevocationUrgency.CRITICAL,
            revoker_did=str(revoker_did),
            revoker_secret_key=revoker_keypair[1],
        )

        entry = crl.get_entry(root.token_id)
        assert entry is not None
        assert entry.effective_time == entry.revocation_time
        assert crl.is_revoked(root.token_id)

    def test_normal_grace_period(
        self,
        token_chain: tuple[CapabilityToken, CapabilityToken, CapabilityToken, CertificateRevocationList],
        revoker_keypair: tuple[bytes, bytes],
        revoker_did: DID,
    ) -> None:
        root, _, _, crl = token_chain

        crl.revoke(
            token_id=root.token_id,
            reason=RevocationReason.PRIVILEGE_WITHDRAWN,
            urgency=RevocationUrgency.NORMAL,
            revoker_did=str(revoker_did),
            revoker_secret_key=revoker_keypair[1],
        )

        entry = crl.get_entry(root.token_id)
        assert entry is not None
        assert entry.effective_time == entry.revocation_time + NORMAL_GRACE_PERIOD_SECONDS

        # Not yet effective at revocation_time
        assert not crl.is_revoked(root.token_id, at_time=entry.revocation_time)

        # Effective after grace period
        assert crl.is_revoked(root.token_id, at_time=entry.effective_time)

    def test_planned_scheduled_time(
        self,
        token_chain: tuple[CapabilityToken, CapabilityToken, CapabilityToken, CertificateRevocationList],
        revoker_keypair: tuple[bytes, bytes],
        revoker_did: DID,
    ) -> None:
        root, _, _, crl = token_chain
        scheduled = int(time.time()) + 3600  # 1 hour from now

        crl.revoke(
            token_id=root.token_id,
            reason=RevocationReason.TOKEN_SUPERSEDED,
            urgency=RevocationUrgency.PLANNED,
            revoker_did=str(revoker_did),
            revoker_secret_key=revoker_keypair[1],
            scheduled_time=scheduled,
        )

        entry = crl.get_entry(root.token_id)
        assert entry is not None
        assert entry.effective_time == scheduled
        assert not crl.is_revoked(root.token_id, at_time=int(time.time()))
        assert crl.is_revoked(root.token_id, at_time=scheduled)


# =============================================================================
# Double Revocation
# =============================================================================


class TestDoubleRevocation:
    """Verify double-revocation rejection."""

    def test_already_revoked_raises(
        self,
        token_chain: tuple[CapabilityToken, CapabilityToken, CapabilityToken, CertificateRevocationList],
        revoker_keypair: tuple[bytes, bytes],
        revoker_did: DID,
    ) -> None:
        root, _, _, crl = token_chain

        crl.revoke(
            token_id=root.token_id,
            reason=RevocationReason.KEY_COMPROMISE,
            urgency=RevocationUrgency.CRITICAL,
            revoker_did=str(revoker_did),
            revoker_secret_key=revoker_keypair[1],
        )

        with pytest.raises(TokenAlreadyRevokedError):
            crl.revoke(
                token_id=root.token_id,
                reason=RevocationReason.KEY_COMPROMISE,
                urgency=RevocationUrgency.CRITICAL,
                revoker_did=str(revoker_did),
                revoker_secret_key=revoker_keypair[1],
            )


# =============================================================================
# Descendant Query
# =============================================================================


class TestDescendantQuery:
    """Verify get_descendants returns correct BFS order."""

    def test_get_descendants(
        self,
        token_chain: tuple[CapabilityToken, CapabilityToken, CapabilityToken, CertificateRevocationList],
    ) -> None:
        root, child, grandchild, crl = token_chain

        descendants = crl.get_descendants(root.token_id)
        assert child.token_id in descendants
        assert grandchild.token_id in descendants
        assert len(descendants) == 2
