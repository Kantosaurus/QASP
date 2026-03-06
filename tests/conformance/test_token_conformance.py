"""Conformance tests for capability token operations.

Tests create, verify, attenuate, split, aggregate, chain depth,
and temporal constraints.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

import pytest

from qasp.crypto import signatures
from qasp.identity.did import DID, create_did
from qasp.protocol.capability import (
    AttenuationError,
    CapabilityToken,
    Constraints,
    DelegationDepthExceeded,
    TokenExpiredError,
    TokenNotYetValidError,
    VerbSet,
    attenuate_token,
    create_token,
    split_token,
    verify_delegation_chain,
    verify_token,
)


# =============================================================================
# Token Creation and Verification
# =============================================================================


class TestTokenCreateVerify:
    """Verify token creation and signature verification."""

    def test_create_and_verify(
        self,
        alice_keypair: tuple[bytes, bytes],
        alice_did: tuple[DID, ...],
        alpha_did: tuple[DID, ...],
    ) -> None:
        token = create_token(
            issuer_did=alice_did[0],
            issuer_secret_key=alice_keypair[1],
            subject_did=alpha_did[0],
            resource_uri="arm://test/compute/gpu",
            verbs={"read", "write"},
        )

        assert token.issuer_did == alice_did[0]
        assert token.subject_did == alpha_did[0]
        assert token.resource_uri == "arm://test/compute/gpu"
        assert "read" in token.verbs
        assert "write" in token.verbs

        # Verify with correct key
        verify_token(token, alice_keypair[0])

    def test_verify_wrong_key_fails(
        self,
        alice_keypair: tuple[bytes, bytes],
        alice_did: tuple[DID, ...],
        alpha_did: tuple[DID, ...],
        beta_keypair: tuple[bytes, bytes],
    ) -> None:
        token = create_token(
            issuer_did=alice_did[0],
            issuer_secret_key=alice_keypair[1],
            subject_did=alpha_did[0],
            resource_uri="arm://test/compute/gpu",
            verbs={"read"},
        )

        with pytest.raises(Exception):
            verify_token(token, beta_keypair[0])

    def test_token_cbor_roundtrip(
        self,
        alice_keypair: tuple[bytes, bytes],
        alice_did: tuple[DID, ...],
        alpha_did: tuple[DID, ...],
    ) -> None:
        token = create_token(
            issuer_did=alice_did[0],
            issuer_secret_key=alice_keypair[1],
            subject_did=alpha_did[0],
            resource_uri="arm://test/compute/gpu",
            verbs={"read", "write", "execute"},
            constraints=Constraints(quantity_limit=100, max_spend=500),
        )

        cbor_data = token.to_cbor_with_signature()
        restored = CapabilityToken.from_cbor(cbor_data)

        assert restored.token_id == token.token_id
        assert restored.issuer_did == token.issuer_did
        assert restored.resource_uri == token.resource_uri
        assert set(restored.verbs) == set(token.verbs)


# =============================================================================
# Attenuation
# =============================================================================


class TestTokenAttenuation:
    """Verify capability attenuation rules."""

    def test_attenuate_reduces_verbs(
        self, root_token: CapabilityToken, alpha_keypair: tuple[bytes, bytes],
        gamma_did: tuple[DID, ...],
    ) -> None:
        child = attenuate_token(
            parent_token=root_token,
            delegator_secret_key=alpha_keypair[1],
            new_subject_did=gamma_did[0],
            reduced_verbs=VerbSet({"read"}),
        )

        assert set(child.verbs) == {"read"}
        assert child.delegation_chain_length == root_token.delegation_chain_length + 1

    def test_attenuate_cannot_add_verbs(
        self, root_token: CapabilityToken, alpha_keypair: tuple[bytes, bytes],
        gamma_did: tuple[DID, ...],
    ) -> None:
        with pytest.raises(AttenuationError):
            attenuate_token(
                parent_token=root_token,
                delegator_secret_key=alpha_keypair[1],
                new_subject_did=gamma_did[0],
                reduced_verbs=VerbSet({"read", "write", "execute", "admin"}),
            )

    def test_attenuate_reduces_quantity(
        self, root_token: CapabilityToken, alpha_keypair: tuple[bytes, bytes],
        gamma_did: tuple[DID, ...],
    ) -> None:
        child = attenuate_token(
            parent_token=root_token,
            delegator_secret_key=alpha_keypair[1],
            new_subject_did=gamma_did[0],
            tightened_constraints=Constraints(quantity_limit=50),
        )

        assert child.constraints.quantity_limit == 50

    def test_attenuate_cannot_increase_quantity(
        self, root_token: CapabilityToken, alpha_keypair: tuple[bytes, bytes],
        gamma_did: tuple[DID, ...],
    ) -> None:
        # Implementation caps to parent's quantity rather than raising
        child = attenuate_token(
            parent_token=root_token,
            delegator_secret_key=alpha_keypair[1],
            new_subject_did=gamma_did[0],
            tightened_constraints=Constraints(quantity_limit=200),
        )
        # The result should be capped at the parent's limit
        assert child.constraints.quantity_limit <= root_token.constraints.quantity_limit


# =============================================================================
# Chain Depth
# =============================================================================


class TestChainDepth:
    """Verify delegation chain depth enforcement."""

    def test_max_depth_respected(
        self,
        alice_keypair: tuple[bytes, bytes],
        alice_did: tuple[DID, ...],
        alpha_keypair: tuple[bytes, bytes],
        alpha_did: tuple[DID, ...],
        beta_keypair: tuple[bytes, bytes],
        beta_did: tuple[DID, ...],
        gamma_keypair: tuple[bytes, bytes],
        gamma_did: tuple[DID, ...],
    ) -> None:
        # Create root with max_delegation_depth=2
        root = create_token(
            issuer_did=alice_did[0],
            issuer_secret_key=alice_keypair[1],
            subject_did=alpha_did[0],
            resource_uri="arm://test/compute/gpu",
            verbs={"read"},
            max_delegation_depth=2,
        )

        # Depth 1: ok
        child = attenuate_token(
            parent_token=root,
            delegator_secret_key=alpha_keypair[1],
            new_subject_did=beta_did[0],
        )

        # Depth 2: ok (max)
        grandchild = attenuate_token(
            parent_token=child,
            delegator_secret_key=beta_keypair[1],
            new_subject_did=gamma_did[0],
        )

        # Depth 3: should fail
        extra_kp = signatures.generate_keypair()
        extra_did, _ = create_did(extra_kp[0])
        with pytest.raises(DelegationDepthExceeded):
            attenuate_token(
                parent_token=grandchild,
                delegator_secret_key=gamma_keypair[1],
                new_subject_did=extra_did,
            )


# =============================================================================
# Splitting
# =============================================================================


class TestTokenSplitting:
    """Verify token quantity splitting."""

    def test_split_preserves_total(
        self,
        alice_keypair: tuple[bytes, bytes],
        alice_did: tuple[DID, ...],
        alpha_did: tuple[DID, ...],
    ) -> None:
        token = create_token(
            issuer_did=alice_did[0],
            issuer_secret_key=alice_keypair[1],
            subject_did=alpha_did[0],
            resource_uri="arm://test/compute/gpu",
            verbs={"read"},
            constraints=Constraints(quantity_limit=100),
            max_delegation_depth=1,
        )

        parts = split_token(token, alice_keypair[1], [40, 60])
        assert len(parts) == 2
        assert parts[0].constraints.quantity_limit == 40
        assert parts[1].constraints.quantity_limit == 60


# =============================================================================
# Temporal Constraints
# =============================================================================


class TestTemporalConstraints:
    """Verify not_before and not_after enforcement."""

    def test_expired_token_rejected(
        self,
        alice_keypair: tuple[bytes, bytes],
        alice_did: tuple[DID, ...],
        alpha_did: tuple[DID, ...],
    ) -> None:
        token = create_token(
            issuer_did=alice_did[0],
            issuer_secret_key=alice_keypair[1],
            subject_did=alpha_did[0],
            resource_uri="arm://test/compute/gpu",
            verbs={"read"},
            validity_seconds=0,  # Immediately expired
        )

        with pytest.raises(TokenExpiredError):
            verify_token(token, alice_keypair[0])

    def test_not_yet_valid_token_rejected(
        self,
        alice_keypair: tuple[bytes, bytes],
        alice_did: tuple[DID, ...],
        alpha_did: tuple[DID, ...],
    ) -> None:
        future = datetime.now(UTC) + timedelta(hours=1)
        token = create_token(
            issuer_did=alice_did[0],
            issuer_secret_key=alice_keypair[1],
            subject_did=alpha_did[0],
            resource_uri="arm://test/compute/gpu",
            verbs={"read"},
            constraints=Constraints(not_before=future),
        )

        with pytest.raises(TokenNotYetValidError):
            verify_token(token, alice_keypair[0])


# =============================================================================
# Delegation Chain Verification
# =============================================================================


class TestDelegationChainVerification:
    """Verify delegation chain verification."""

    def test_valid_chain(
        self,
        root_token: CapabilityToken,
        child_token: CapabilityToken,
        alice_keypair: tuple[bytes, bytes],
    ) -> None:
        chain = [root_token, child_token]
        result = verify_delegation_chain(chain, alice_keypair[0])
        assert result is True

    def test_chain_with_tampered_token_fails(
        self,
        root_token: CapabilityToken,
        child_token: CapabilityToken,
        alice_keypair: tuple[bytes, bytes],
    ) -> None:
        # Tamper with child's verbs to escalate privileges beyond parent
        import dataclasses
        tampered = dataclasses.replace(
            child_token,
            verbs=VerbSet({"read", "write", "execute", "admin"}),
        )
        chain = [root_token, tampered]
        with pytest.raises(Exception):
            verify_delegation_chain(chain, alice_keypair[0])
