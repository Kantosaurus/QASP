"""Tests for capability token engine."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from qasp.identity import DID, DIDRegistry
from qasp.protocol.capability import (
    AttenuationError,
    CapabilityToken,
    Constraints,
    DelegationDepthExceeded,
    InvalidDelegationChainError,
    InvalidTokenError,
    LocalDIDResolver,
    TokenConstraintViolation,
    TokenNotYetValidError,
    TokenUsage,
    VerbSet,
    attenuate_token,
    create_token,
    split_token,
    verify_delegation_chain,
    verify_token,
)

# =============================================================================
# VerbSet Tests
# =============================================================================


class TestVerbSet:
    """Tests for VerbSet data structure."""

    def test_create_from_set(self) -> None:
        """Can create VerbSet from set."""
        verbs = VerbSet({"read", "write"})
        assert "read" in verbs
        assert "write" in verbs
        assert len(verbs) == 2

    def test_create_from_list(self) -> None:
        """Can create VerbSet from list."""
        verbs = VerbSet(["read", "write", "execute"])
        assert len(verbs) == 3

    def test_issubset(self) -> None:
        """issubset correctly identifies subset relationship."""
        parent = VerbSet({"read", "write", "delete"})
        child = VerbSet({"read", "write"})
        assert child.issubset(parent)
        assert not parent.issubset(child)

    def test_intersection(self) -> None:
        """intersection returns common verbs."""
        v1 = VerbSet({"read", "write", "delete"})
        v2 = VerbSet({"read", "execute"})
        result = v1.intersection(v2)
        assert result.verbs == frozenset({"read"})

    def test_immutable(self) -> None:
        """VerbSet is immutable (frozen)."""
        verbs = VerbSet({"read"})
        with pytest.raises(AttributeError):
            verbs.verbs = frozenset({"write"})  # type: ignore


# =============================================================================
# Constraints Tests
# =============================================================================


class TestConstraints:
    """Tests for Constraints data structure."""

    def test_default_constraints(self) -> None:
        """Default constraints have None/empty values."""
        c = Constraints()
        assert c.not_before is None
        assert c.not_after is None
        assert c.quantity_limit is None
        assert c.rate_limit is None
        assert c.max_spend is None

    def test_is_tighter_than_equal(self) -> None:
        """Equal constraints are considered tighter."""
        c1 = Constraints(quantity_limit=10)
        c2 = Constraints(quantity_limit=10)
        assert c1.is_tighter_than(c2)

    def test_is_tighter_than_less_quantity(self) -> None:
        """Smaller quantity limit is tighter."""
        parent = Constraints(quantity_limit=10)
        child = Constraints(quantity_limit=5)
        assert child.is_tighter_than(parent)
        assert not parent.is_tighter_than(child)

    def test_is_tighter_than_earlier_expiry(self) -> None:
        """Earlier expiry is tighter."""
        now = datetime.now(UTC)
        parent = Constraints(not_after=now + timedelta(hours=2))
        child = Constraints(not_after=now + timedelta(hours=1))
        assert child.is_tighter_than(parent)

    def test_is_tighter_than_later_start(self) -> None:
        """Later not_before is tighter."""
        now = datetime.now(UTC)
        parent = Constraints(not_before=now)
        child = Constraints(not_before=now + timedelta(hours=1))
        assert child.is_tighter_than(parent)

    def test_is_tighter_than_subset_data_scope(self) -> None:
        """Subset data scope is tighter."""
        parent = Constraints(data_scope=frozenset({"a", "b", "c"}))
        child = Constraints(data_scope=frozenset({"a", "b"}))
        assert child.is_tighter_than(parent)

    def test_tighten_quantity(self) -> None:
        """tighten reduces quantity limit."""
        base = Constraints(quantity_limit=10)
        delta = Constraints(quantity_limit=5)
        result = base.tighten(delta)
        assert result.quantity_limit == 5

    def test_tighten_expiry(self) -> None:
        """tighten takes earlier expiry."""
        now = datetime.now(UTC)
        base = Constraints(not_after=now + timedelta(hours=2))
        delta = Constraints(not_after=now + timedelta(hours=1))
        result = base.tighten(delta)
        assert result.not_after == delta.not_after


# =============================================================================
# Token Creation Tests
# =============================================================================


class TestTokenCreation:
    """Tests for token creation."""

    def test_create_token(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """Can create a basic capability token."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/compute/instance-1",
            verbs={"read", "execute"},
        )
        assert token.issuer_did == issuer_did
        assert token.subject_did == subject_did
        assert "read" in token.verbs
        assert "execute" in token.verbs

    def test_token_has_signature(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """Token has a signature."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/compute",
            verbs={"read"},
        )
        assert token.signature is not None
        assert len(token.signature) > 0

    def test_token_has_token_id(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """Token has a token_id."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/compute",
            verbs={"read"},
        )
        assert token.token_id is not None
        assert len(token.token_id) == 32  # SHA-384[:32]

    def test_token_has_nonce(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """Token has a random nonce."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/compute",
            verbs={"read"},
        )
        assert token.nonce is not None
        assert len(token.nonce) == 16

    def test_token_cbor_roundtrip(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """Token can be serialized to CBOR and back."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/compute",
            verbs={"read", "write"},
            constraints=Constraints(quantity_limit=100, quantity_unit="vCPU-h"),
        )
        cbor_data = token.to_cbor_with_signature()
        restored = CapabilityToken.from_cbor(cbor_data)

        assert restored.token_id == token.token_id
        assert restored.issuer_did == token.issuer_did
        assert restored.subject_did == token.subject_did
        assert restored.resource_uri == token.resource_uri
        assert restored.verbs.verbs == token.verbs.verbs
        assert restored.constraints.quantity_limit == token.constraints.quantity_limit
        assert restored.signature == token.signature

    def test_token_with_audience(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
        audience_did: DID,
    ) -> None:
        """Token can have an audience DID."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/compute",
            verbs={"read"},
            audience_did=audience_did,
        )
        assert token.audience_did == audience_did

    def test_token_with_delegation_depth(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """Token can specify max delegation depth."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/compute",
            verbs={"read"},
            max_delegation_depth=3,
        )
        assert token.max_delegation_depth == 3
        assert token.delegation_chain_length == 0

    def test_token_compute_hash(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """Token hash is computed correctly."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/compute",
            verbs={"read"},
        )
        hash1 = token.compute_hash()
        hash2 = token.compute_hash()
        assert hash1 == hash2  # Deterministic
        assert len(hash1) == 48  # SHA-384


# =============================================================================
# Token Verification Tests
# =============================================================================


class TestTokenVerification:
    """Tests for token verification."""

    def test_verify_valid_token(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
    ) -> None:
        """Valid token verifies successfully."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/compute",
            verbs={"read"},
        )
        assert verify_token(token, issuer_public_key)

    def test_verify_wrong_key_fails(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_public_key: bytes,  # Wrong key
        subject_did: DID,
    ) -> None:
        """Verification fails with wrong public key."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/compute",
            verbs={"read"},
        )
        with pytest.raises(InvalidTokenError) as exc_info:
            verify_token(token, subject_public_key)
        assert "signature verification failed" in str(exc_info.value)

    def test_verify_expired_token(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """Verification fails for expired token."""
        # Create token with very short validity
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/compute",
            verbs={"read"},
            validity_seconds=1,
        )

        # Check that is_expired works
        future = datetime.now(UTC) + timedelta(seconds=10)
        assert token.is_expired(future)

    def test_verify_not_yet_valid_token(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
    ) -> None:
        """Verification fails for not-yet-valid token."""
        future_start = datetime.now(UTC) + timedelta(hours=1)
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/compute",
            verbs={"read"},
            constraints=Constraints(not_before=future_start),
        )

        with pytest.raises(TokenNotYetValidError):
            verify_token(token, issuer_public_key, check_expiry=True)

    def test_verify_without_expiry_check(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
    ) -> None:
        """Can verify token without checking expiry."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/compute",
            verbs={"read"},
        )
        assert verify_token(token, issuer_public_key, check_expiry=False)


# =============================================================================
# Constraint Verification Tests
# =============================================================================


class TestConstraintVerification:
    """Tests for constraint verification with usage tracking."""

    def test_quantity_constraint(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
    ) -> None:
        """Quantity constraint is enforced."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/compute",
            verbs={"execute"},
            constraints=Constraints(quantity_limit=100, quantity_unit="vCPU-h"),
        )

        # Within limit
        usage_ok = TokenUsage(quantity_consumed=50)
        assert verify_token(token, issuer_public_key, usage=usage_ok)

        # Exceeds limit
        usage_exceeded = TokenUsage(quantity_consumed=150)
        with pytest.raises(TokenConstraintViolation) as exc_info:
            verify_token(token, issuer_public_key, usage=usage_exceeded)
        assert "Quantity limit exceeded" in str(exc_info.value)

    def test_rate_constraint(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
    ) -> None:
        """Rate constraint is enforced."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/api",
            verbs={"call"},
            constraints=Constraints(rate_limit=10, rate_period_seconds=60),
        )

        # Within rate
        now = datetime.now(UTC)
        usage_ok = TokenUsage(
            operations_in_period=5,
            period_start=now - timedelta(seconds=30),
        )
        assert verify_token(token, issuer_public_key, usage=usage_ok)

        # Exceeds rate
        usage_exceeded = TokenUsage(
            operations_in_period=15,
            period_start=now - timedelta(seconds=30),
        )
        with pytest.raises(TokenConstraintViolation) as exc_info:
            verify_token(token, issuer_public_key, usage=usage_exceeded)
        assert "Rate limit exceeded" in str(exc_info.value)

    def test_data_scope_constraint(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
    ) -> None:
        """Data scope constraint is enforced."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/data",
            verbs={"read"},
            constraints=Constraints(data_scope=frozenset({"public", "internal"})),
        )

        # Within scope
        usage_ok = TokenUsage(data_accessed={"public"})
        assert verify_token(token, issuer_public_key, usage=usage_ok)

        # Out of scope
        usage_exceeded = TokenUsage(data_accessed={"public", "secret"})
        with pytest.raises(TokenConstraintViolation) as exc_info:
            verify_token(token, issuer_public_key, usage=usage_exceeded)
        assert "Data scope violation" in str(exc_info.value)

    def test_max_spend_constraint(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
    ) -> None:
        """Max spend constraint is enforced."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/billing",
            verbs={"purchase"},
            constraints=Constraints(max_spend=1000, spend_currency="USD"),
        )

        # Within budget
        usage_ok = TokenUsage(total_spend=500)
        assert verify_token(token, issuer_public_key, usage=usage_ok)

        # Over budget
        usage_exceeded = TokenUsage(total_spend=1500)
        with pytest.raises(TokenConstraintViolation) as exc_info:
            verify_token(token, issuer_public_key, usage=usage_exceeded)
        assert "Spend limit exceeded" in str(exc_info.value)


# =============================================================================
# Token Attenuation Tests
# =============================================================================


class TestTokenAttenuation:
    """Tests for token attenuation (delegation)."""

    def test_attenuate_token(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        delegate_did: DID,
    ) -> None:
        """Can attenuate a token to delegate to another entity."""
        parent = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/compute",
            verbs={"read", "write", "execute"},
            max_delegation_depth=2,
        )

        child = attenuate_token(
            parent_token=parent,
            delegator_secret_key=subject_secret_key,
            new_subject_did=delegate_did,
            reduced_verbs=VerbSet({"read", "write"}),
        )

        assert child.subject_did == delegate_did
        assert child.issuer_did == subject_did  # Delegator becomes issuer
        assert "read" in child.verbs
        assert "write" in child.verbs
        assert "execute" not in child.verbs

    def test_attenuate_reduces_verbs(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        delegate_did: DID,
    ) -> None:
        """Attenuation reduces verbs."""
        parent = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/compute",
            verbs={"read", "write", "delete"},
            max_delegation_depth=1,
        )

        child = attenuate_token(
            parent_token=parent,
            delegator_secret_key=subject_secret_key,
            new_subject_did=delegate_did,
            reduced_verbs=VerbSet({"read"}),
        )

        assert len(child.verbs) == 1
        assert "read" in child.verbs
        assert "write" not in child.verbs

    def test_attenuate_reduces_depth(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        delegate_did: DID,
    ) -> None:
        """Attenuation reduces delegation depth."""
        parent = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/compute",
            verbs={"read"},
            max_delegation_depth=3,
        )

        child = attenuate_token(
            parent_token=parent,
            delegator_secret_key=subject_secret_key,
            new_subject_did=delegate_did,
        )

        assert child.max_delegation_depth == 2  # Reduced by 1
        assert child.delegation_chain_length == 1  # Incremented by 1

    def test_attenuate_has_parent_hash(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        delegate_did: DID,
    ) -> None:
        """Attenuated token references parent hash."""
        parent = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/compute",
            verbs={"read"},
            max_delegation_depth=1,
        )

        child = attenuate_token(
            parent_token=parent,
            delegator_secret_key=subject_secret_key,
            new_subject_did=delegate_did,
        )

        assert child.parent_token_hash is not None
        assert child.parent_token_hash == parent.compute_hash()

    def test_cannot_expand_verbs(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        delegate_did: DID,
    ) -> None:
        """Cannot attenuate to verbs not held."""
        parent = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/compute",
            verbs={"read"},
            max_delegation_depth=1,
        )

        with pytest.raises(AttenuationError) as exc_info:
            attenuate_token(
                parent_token=parent,
                delegator_secret_key=subject_secret_key,
                new_subject_did=delegate_did,
                reduced_verbs=VerbSet({"read", "write"}),  # write not held
            )
        assert "Cannot delegate verbs not held" in str(exc_info.value)

    def test_attenuate_no_delegation_fails(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        delegate_did: DID,
    ) -> None:
        """Cannot attenuate token with no delegation allowed."""
        parent = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/compute",
            verbs={"read"},
            max_delegation_depth=0,  # No delegation
        )

        with pytest.raises(DelegationDepthExceeded) as exc_info:
            attenuate_token(
                parent_token=parent,
                delegator_secret_key=subject_secret_key,
                new_subject_did=delegate_did,
            )
        assert "does not allow delegation" in str(exc_info.value)

    def test_attenuate_tightens_constraints(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        delegate_did: DID,
    ) -> None:
        """Attenuation can tighten constraints."""
        parent = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/compute",
            verbs={"execute"},
            constraints=Constraints(quantity_limit=100),
            max_delegation_depth=1,
        )

        child = attenuate_token(
            parent_token=parent,
            delegator_secret_key=subject_secret_key,
            new_subject_did=delegate_did,
            tightened_constraints=Constraints(quantity_limit=50),
        )

        assert child.constraints.quantity_limit == 50


# =============================================================================
# Token Splitting Tests
# =============================================================================


class TestTokenSplitting:
    """Tests for token splitting."""

    def test_split_token(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
    ) -> None:
        """Can split a token into multiple tokens."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/compute",
            verbs={"execute"},
            constraints=Constraints(quantity_limit=100, quantity_unit="vCPU-h"),
            max_delegation_depth=1,
        )

        splits = split_token(
            token=token,
            holder_secret_key=subject_secret_key,
            split_amounts=[30, 40, 20],
        )

        assert len(splits) == 3
        assert splits[0].constraints.quantity_limit == 30
        assert splits[1].constraints.quantity_limit == 40
        assert splits[2].constraints.quantity_limit == 20

    def test_split_preserves_verbs(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
    ) -> None:
        """Split tokens preserve the parent's verbs."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/compute",
            verbs={"read", "execute"},
            constraints=Constraints(quantity_limit=100),
            max_delegation_depth=1,
        )

        splits = split_token(
            token=token,
            holder_secret_key=subject_secret_key,
            split_amounts=[50, 50],
        )

        for s in splits:
            assert "read" in s.verbs
            assert "execute" in s.verbs

    def test_split_exceeds_quantity_fails(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
    ) -> None:
        """Cannot split beyond quantity limit."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/compute",
            verbs={"execute"},
            constraints=Constraints(quantity_limit=100),
            max_delegation_depth=1,
        )

        with pytest.raises(TokenConstraintViolation) as exc_info:
            split_token(
                token=token,
                holder_secret_key=subject_secret_key,
                split_amounts=[60, 60],  # Total 120 > 100
            )
        assert "exceeds quantity_limit" in str(exc_info.value)

    def test_split_no_quantity_fails(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
    ) -> None:
        """Cannot split token without quantity_limit."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/compute",
            verbs={"execute"},
            max_delegation_depth=1,
        )

        with pytest.raises(AttenuationError) as exc_info:
            split_token(
                token=token,
                holder_secret_key=subject_secret_key,
                split_amounts=[50, 50],
            )
        assert "without quantity_limit" in str(exc_info.value)

    def test_split_to_different_subjects(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        delegate_did: DID,
        third_party_did: DID,
    ) -> None:
        """Can split token to different subjects."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/compute",
            verbs={"execute"},
            constraints=Constraints(quantity_limit=100),
            max_delegation_depth=1,
        )

        splits = split_token(
            token=token,
            holder_secret_key=subject_secret_key,
            split_amounts=[50, 50],
            new_subject_dids=[delegate_did, third_party_did],
        )

        assert splits[0].subject_did == delegate_did
        assert splits[1].subject_did == third_party_did


# =============================================================================
# Delegation Chain Verification Tests
# =============================================================================


class TestDelegationChain:
    """Tests for delegation chain verification."""

    def test_verify_single_token_chain(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
    ) -> None:
        """Can verify a chain with single token."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/compute",
            verbs={"read"},
        )
        assert verify_delegation_chain([token], issuer_public_key)

    def test_verify_two_token_chain(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        delegate_did: DID,
        did_registry: DIDRegistry,
    ) -> None:
        """Can verify a chain with two tokens."""
        root = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/compute",
            verbs={"read", "write"},
            max_delegation_depth=1,
        )

        child = attenuate_token(
            parent_token=root,
            delegator_secret_key=subject_secret_key,
            new_subject_did=delegate_did,
            reduced_verbs=VerbSet({"read"}),
        )

        resolver = LocalDIDResolver(did_registry)
        assert verify_delegation_chain(
            [root, child],
            issuer_public_key,
            did_resolver=resolver,
        )

    def test_verify_chain_depth_3(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        delegate_did: DID,
        delegate_secret_key: bytes,
        third_party_did: DID,
        did_registry: DIDRegistry,
    ) -> None:
        """Can verify a chain with depth 3."""
        # Root token
        root = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/compute",
            verbs={"read", "write", "delete"},
            max_delegation_depth=3,
        )

        # First delegation
        level1 = attenuate_token(
            parent_token=root,
            delegator_secret_key=subject_secret_key,
            new_subject_did=delegate_did,
            reduced_verbs=VerbSet({"read", "write"}),
        )

        # Second delegation
        level2 = attenuate_token(
            parent_token=level1,
            delegator_secret_key=delegate_secret_key,
            new_subject_did=third_party_did,
            reduced_verbs=VerbSet({"read"}),
        )

        resolver = LocalDIDResolver(did_registry)
        assert verify_delegation_chain(
            [root, level1, level2],
            issuer_public_key,
            did_resolver=resolver,
        )

        # Check chain properties
        assert level2.delegation_chain_length == 2
        assert level2.max_delegation_depth == 1

    def test_empty_chain_fails(self, issuer_public_key: bytes) -> None:
        """Empty chain verification fails."""
        with pytest.raises(InvalidDelegationChainError) as exc_info:
            verify_delegation_chain([], issuer_public_key)
        assert "Empty token chain" in str(exc_info.value)

    def test_broken_chain_fails(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        delegate_did: DID,
    ) -> None:
        """Broken chain (wrong parent hash) verification fails."""
        root = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/compute",
            verbs={"read"},
            max_delegation_depth=1,
        )

        # Create another root instead of attenuating
        fake_child = create_token(
            issuer_did=subject_did,
            issuer_secret_key=subject_secret_key,
            subject_did=delegate_did,
            resource_uri="/resources/compute",
            verbs={"read"},
        )

        with pytest.raises(InvalidDelegationChainError) as exc_info:
            verify_delegation_chain([root, fake_child], issuer_public_key)
        assert "parent_token_hash mismatch" in str(exc_info.value)

    def test_root_cannot_have_parent(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        delegate_did: DID,
    ) -> None:
        """Root token in chain cannot have parent hash."""
        root = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/compute",
            verbs={"read"},
            max_delegation_depth=1,
        )

        child = attenuate_token(
            parent_token=root,
            delegator_secret_key=subject_secret_key,
            new_subject_did=delegate_did,
        )

        # Try to use child as root
        with pytest.raises(InvalidDelegationChainError) as exc_info:
            verify_delegation_chain([child], issuer_public_key)
        assert "cannot have a parent_token_hash" in str(exc_info.value)

    def test_chain_verbs_must_be_subset(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        delegate_did: DID,
        did_registry: DIDRegistry,
    ) -> None:
        """Each token in chain must have verbs subset of parent."""
        root = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/resources/compute",
            verbs={"read", "write"},
            max_delegation_depth=1,
        )

        # Proper attenuation
        child = attenuate_token(
            parent_token=root,
            delegator_secret_key=subject_secret_key,
            new_subject_did=delegate_did,
            reduced_verbs=VerbSet({"read"}),
        )

        resolver = LocalDIDResolver(did_registry)
        assert verify_delegation_chain(
            [root, child],
            issuer_public_key,
            did_resolver=resolver,
        )


# =============================================================================
# CBOR Encoding Edge Cases
# =============================================================================


class TestCBOREncoding:
    """Tests for CBOR encoding edge cases."""

    def test_invalid_cbor_raises(self) -> None:
        """Invalid CBOR data raises InvalidTokenError."""
        with pytest.raises(InvalidTokenError):
            CapabilityToken.from_cbor(b"not valid cbor")

    def test_missing_field_raises(self) -> None:
        """Missing required field raises InvalidTokenError."""
        import cbor2

        invalid_data = cbor2.dumps({"token_id": "abc"})  # Missing other fields
        with pytest.raises(InvalidTokenError):
            CapabilityToken.from_cbor(invalid_data)
