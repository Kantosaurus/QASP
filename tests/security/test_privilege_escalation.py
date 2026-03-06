"""Security tests for privilege escalation resistance.

Security property: Attenuation is algebraically monotonic — rights can only decrease.
"""

from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from qasp.crypto import signatures
from qasp.identity import DID, DIDRegistry, create_did
from qasp.protocol.capability import (
    AttenuationError,
    CapabilityToken,
    Constraints,
    InvalidDelegationChainError,
    LocalDIDResolver,
    VerbSet,
    attenuate_token,
    create_token,
    verify_delegation_chain,
)
from qasp.crypto.signatures import sign

# =============================================================================
# Hypothesis Strategies (from test_capability_properties.py)
# =============================================================================

COMMON_VERBS = [
    "read", "write", "execute", "delete", "create",
    "update", "list", "admin", "invoke", "subscribe",
]


@st.composite
def verb_set_strategy(draw: st.DrawFn) -> VerbSet:
    """Generate an arbitrary VerbSet with 1-5 verbs."""
    verbs = draw(
        st.lists(
            st.sampled_from(COMMON_VERBS),
            min_size=1,
            max_size=5,
            unique=True,
        )
    )
    return VerbSet(set(verbs))


@st.composite
def subset_verb_set_strategy(draw: st.DrawFn, parent: VerbSet) -> VerbSet:
    """Generate a VerbSet that is a subset of the parent."""
    assume(len(parent) > 0)
    parent_list = list(parent.verbs)
    selected = draw(
        st.lists(
            st.sampled_from(parent_list),
            min_size=1,
            max_size=len(parent_list),
            unique=True,
        )
    )
    return VerbSet(set(selected))


# =============================================================================
# Helpers
# =============================================================================


def _encode_token_data_for_signing(token: CapabilityToken) -> bytes:
    """Re-encode token data for signing (uses token.to_cbor())."""
    return token.to_cbor()


def _forge_child_token(
    parent: CapabilityToken,
    delegate_sk: bytes,
    new_subject_did: DID,
    verbs: VerbSet,
    constraints: Constraints,
) -> CapabilityToken:
    """Create a forged child token with arbitrary verbs/constraints."""
    nonce = os.urandom(16)
    token_id = hashlib.sha384(str(parent.subject_did).encode() + nonce).digest()[:32]
    parent_hash = parent.compute_hash()

    forged = CapabilityToken(
        token_id=token_id,
        issuer_did=parent.subject_did,
        subject_did=new_subject_did,
        audience_did=parent.audience_did,
        resource_uri=parent.resource_uri,
        verbs=verbs,
        constraints=constraints,
        issued_at=datetime.now(UTC),
        nonce=nonce,
        signature=b"",  # placeholder
        parent_token_hash=parent_hash,
        max_delegation_depth=parent.max_delegation_depth - 1,
        delegation_chain_length=parent.delegation_chain_length + 1,
    )
    sig = sign(delegate_sk, forged.to_cbor())
    return CapabilityToken(
        token_id=forged.token_id,
        issuer_did=forged.issuer_did,
        subject_did=forged.subject_did,
        audience_did=forged.audience_did,
        resource_uri=forged.resource_uri,
        verbs=forged.verbs,
        constraints=forged.constraints,
        issued_at=forged.issued_at,
        nonce=forged.nonce,
        signature=sig,
        parent_token_hash=forged.parent_token_hash,
        max_delegation_depth=forged.max_delegation_depth,
        delegation_chain_length=forged.delegation_chain_length,
    )


# =============================================================================
# Verb Expansion Tests
# =============================================================================


@pytest.mark.security
class TestVerbExpansionBlocked:
    """Attenuation cannot add verbs the parent does not hold."""

    def test_adding_verb_during_attenuation_raises(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        delegate_did: DID,
    ) -> None:
        """Attenuating with a superset of parent verbs raises AttenuationError."""
        parent = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
            max_delegation_depth=2,
        )
        with pytest.raises(AttenuationError):
            attenuate_token(
                parent_token=parent,
                delegator_secret_key=subject_secret_key,
                new_subject_did=delegate_did,
                reduced_verbs=VerbSet({"read", "admin"}),
            )

    def test_forged_token_with_extra_verbs_fails_chain_verification(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        delegate_did: DID,
        did_resolver: LocalDIDResolver,
    ) -> None:
        """Manually forged child with extra verbs fails delegation chain check."""
        parent = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
            max_delegation_depth=2,
        )

        forged_child = _forge_child_token(
            parent=parent,
            delegate_sk=subject_secret_key,
            new_subject_did=delegate_did,
            verbs=VerbSet({"read", "write"}),  # Extra verb
            constraints=parent.constraints,
        )

        with pytest.raises(InvalidDelegationChainError, match="verbs not granted"):
            verify_delegation_chain(
                [parent, forged_child],
                issuer_public_key,
                did_resolver=did_resolver,
                check_expiry=False,
            )

    def test_frozen_token_prevents_field_mutation(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """CapabilityToken is frozen; direct attribute mutation raises."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
        )
        with pytest.raises(AttributeError):
            token.verbs = VerbSet({"read", "write", "admin"})  # type: ignore[misc]


# =============================================================================
# Constraint Loosening Tests
# =============================================================================


@pytest.mark.security
class TestConstraintLooseningBlocked:
    """Attenuation cannot loosen constraints."""

    def test_loosened_quantity_limit_fails_chain(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        delegate_did: DID,
        did_resolver: LocalDIDResolver,
    ) -> None:
        """Forged child with higher quantity_limit fails chain verification."""
        parent = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
            constraints=Constraints(quantity_limit=10),
            max_delegation_depth=2,
        )

        forged_child = _forge_child_token(
            parent=parent,
            delegate_sk=subject_secret_key,
            new_subject_did=delegate_did,
            verbs=parent.verbs,
            constraints=Constraints(
                quantity_limit=20,  # Loosened
                not_after=parent.constraints.not_after,
            ),
        )

        with pytest.raises(InvalidDelegationChainError, match="constraints"):
            verify_delegation_chain(
                [parent, forged_child],
                issuer_public_key,
                did_resolver=did_resolver,
                check_expiry=False,
            )

    def test_extended_not_after_fails_chain(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        delegate_did: DID,
        did_resolver: LocalDIDResolver,
    ) -> None:
        """Forged child with later not_after fails chain verification."""
        now = datetime.now(UTC)
        parent = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
            max_delegation_depth=2,
            validity_seconds=3600,
        )

        forged_child = _forge_child_token(
            parent=parent,
            delegate_sk=subject_secret_key,
            new_subject_did=delegate_did,
            verbs=parent.verbs,
            constraints=Constraints(
                not_after=now + timedelta(hours=2),  # Loosened beyond parent
            ),
        )

        with pytest.raises(InvalidDelegationChainError, match="constraints"):
            verify_delegation_chain(
                [parent, forged_child],
                issuer_public_key,
                did_resolver=did_resolver,
                check_expiry=False,
            )

    def test_expanded_data_scope_fails_chain(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        delegate_did: DID,
        did_resolver: LocalDIDResolver,
    ) -> None:
        """Forged child with expanded data_scope fails chain verification."""
        parent = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
            constraints=Constraints(data_scope=frozenset({"a", "b"})),
            max_delegation_depth=2,
        )

        forged_child = _forge_child_token(
            parent=parent,
            delegate_sk=subject_secret_key,
            new_subject_did=delegate_did,
            verbs=parent.verbs,
            constraints=Constraints(
                data_scope=frozenset({"a", "b", "c"}),  # Expanded
                not_after=parent.constraints.not_after,
            ),
        )

        with pytest.raises(InvalidDelegationChainError, match="constraints"):
            verify_delegation_chain(
                [parent, forged_child],
                issuer_public_key,
                did_resolver=did_resolver,
                check_expiry=False,
            )


# =============================================================================
# Property-Based Escalation Tests
# =============================================================================


@pytest.mark.security
@pytest.mark.property
class TestPrivilegeEscalationProperties:
    """Hypothesis property tests for monotonic attenuation."""

    @given(verbs=verb_set_strategy())
    @settings(max_examples=50)
    def test_attenuated_verbs_always_subset(self, verbs: VerbSet) -> None:
        """Attenuated child verbs are always a subset of parent verbs."""
        issuer_pk, issuer_sk = signatures.generate_keypair()
        subject_pk, subject_sk = signatures.generate_keypair()
        delegate_pk, _ = signatures.generate_keypair()
        issuer_did, _ = create_did(issuer_pk)
        subject_did, _ = create_did(subject_pk)
        delegate_did, _ = create_did(delegate_pk)

        parent = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_sk,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs=verbs,
            max_delegation_depth=2,
        )
        child = attenuate_token(
            parent_token=parent,
            delegator_secret_key=subject_sk,
            new_subject_did=delegate_did,
        )
        assert child.verbs.issubset(parent.verbs)

    @given(verbs=verb_set_strategy())
    @settings(max_examples=50)
    def test_extra_verb_always_rejected(self, verbs: VerbSet) -> None:
        """Adding a verb not in parent always raises AttenuationError."""
        # Find a verb not in the parent set
        all_verbs = set(COMMON_VERBS)
        available = all_verbs - verbs.verbs
        assume(len(available) > 0)
        extra_verb = next(iter(available))

        issuer_pk, issuer_sk = signatures.generate_keypair()
        subject_pk, subject_sk = signatures.generate_keypair()
        delegate_pk, _ = signatures.generate_keypair()
        issuer_did, _ = create_did(issuer_pk)
        subject_did, _ = create_did(subject_pk)
        delegate_did, _ = create_did(delegate_pk)

        parent = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_sk,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs=verbs,
            max_delegation_depth=2,
        )
        with pytest.raises(AttenuationError):
            attenuate_token(
                parent_token=parent,
                delegator_secret_key=subject_sk,
                new_subject_did=delegate_did,
                reduced_verbs=VerbSet(verbs.verbs | {extra_verb}),
            )

    @given(verbs=verb_set_strategy())
    @settings(max_examples=30)
    def test_chain_verification_catches_forged_wider_verbs(
        self, verbs: VerbSet,
    ) -> None:
        """Widened verbs on forged leaf always detected by chain verification."""
        all_verbs = set(COMMON_VERBS)
        available = all_verbs - verbs.verbs
        assume(len(available) > 0)
        extra_verb = next(iter(available))

        issuer_pk, issuer_sk = signatures.generate_keypair()
        subject_pk, subject_sk = signatures.generate_keypair()
        delegate_pk, _ = signatures.generate_keypair()
        issuer_did, issuer_doc = create_did(issuer_pk)
        subject_did, subject_doc = create_did(subject_pk)
        delegate_did, delegate_doc = create_did(delegate_pk)

        registry = DIDRegistry()
        registry.register(issuer_doc)
        registry.register(subject_doc)
        registry.register(delegate_doc)
        resolver = LocalDIDResolver(registry)

        parent = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_sk,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs=verbs,
            max_delegation_depth=2,
        )

        forged_child = _forge_child_token(
            parent=parent,
            delegate_sk=subject_sk,
            new_subject_did=delegate_did,
            verbs=VerbSet(verbs.verbs | {extra_verb}),
            constraints=parent.constraints,
        )

        with pytest.raises(InvalidDelegationChainError):
            verify_delegation_chain(
                [parent, forged_child],
                issuer_pk,
                did_resolver=resolver,
                check_expiry=False,
            )
