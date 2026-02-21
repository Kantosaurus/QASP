"""Tests for signature aggregation in delegation chains."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from qasp.crypto import signatures
from qasp.crypto.signatures import verify as sig_verify
from qasp.identity import DID, DIDRegistry, create_did
from qasp.protocol.aggregation import (
    DelegationChain,
    aggregate_sign,
    aggregate_verify_chain,
    attenuate_token_aggregate,
)
from qasp.protocol.capability import (
    AttenuationError,
    Constraints,
    DelegationDepthExceeded,
    InvalidDelegationChainError,
    LocalDIDResolver,
    TokenExpiredError,
    VerbSet,
    create_token,
    verify_delegation_chain,
)


# =============================================================================
# Helpers
# =============================================================================


def _make_entity() -> tuple[bytes, bytes, DID, object]:
    """Generate a fresh entity (pk, sk, did, did_document)."""
    pk, sk = signatures.generate_keypair()
    did, doc = create_did(pk)
    return pk, sk, did, doc


def _build_aggregate_chain(
    entities: list[tuple[bytes, bytes, DID, object]],
    resource_uri: str = "qasp://test/aggregate",
    verbs: set[str] | None = None,
    max_depth: int | None = None,
) -> list[CapabilityToken]:
    """Build an aggregate chain from a list of entities.

    entities[0] is the root issuer. entities[1] is the root subject and first
    delegator, etc.  The chain length equals ``len(entities) - 1``.
    """
    from qasp.protocol.capability import CapabilityToken

    if verbs is None:
        verbs = {"read", "write", "execute"}
    if max_depth is None:
        max_depth = len(entities) - 1  # enough for the full chain

    issuer_pk, issuer_sk, issuer_did, _ = entities[0]
    subject_did = entities[1][2]

    root = create_token(
        issuer_did=issuer_did,
        issuer_secret_key=issuer_sk,
        subject_did=subject_did,
        resource_uri=resource_uri,
        verbs=verbs,
        max_delegation_depth=max_depth,
    )

    tokens: list[CapabilityToken] = [root]
    current_agg = root.signature

    # Each entity[i] (for i >= 1) delegates to entity[i+1]
    for i in range(1, len(entities) - 1):
        _, delegator_sk, _, _ = entities[i]
        next_did = entities[i + 1][2]
        token, current_agg = attenuate_token_aggregate(
            parent_token=tokens[-1],
            delegator_sk=delegator_sk,
            new_subject_did=next_did,
            previous_aggregate=current_agg,
        )
        tokens.append(token)

    return tokens


def _registry_from_entities(
    entities: list[tuple[bytes, bytes, DID, object]],
) -> DIDRegistry:
    """Create a DIDRegistry with all entities registered."""
    registry = DIDRegistry()
    for _, _, _, doc in entities:
        registry.register(doc)
    return registry


# =============================================================================
# TestAggregateSign
# =============================================================================


class TestAggregateSign:
    """Tests for the aggregate_sign primitive."""

    def test_basic_signing(self, issuer_secret_key: bytes) -> None:
        """aggregate_sign returns a non-empty bytes signature."""
        prev_agg = b"\x00" * 48
        token_cbor = b"some token data"
        sig = aggregate_sign(issuer_secret_key, prev_agg, token_cbor)
        assert isinstance(sig, bytes)
        assert len(sig) > 0

    def test_verifiable_signature(
        self,
        issuer_keypair: tuple[bytes, bytes],
    ) -> None:
        """The signature verifies against SHA-384(prev_agg || token_cbor)."""
        pk, sk = issuer_keypair
        prev_agg = b"\x01" * 48
        token_cbor = b"deterministic token data"

        sig = aggregate_sign(sk, prev_agg, token_cbor)

        expected_digest = hashlib.sha384(prev_agg + token_cbor).digest()
        assert sig_verify(pk, expected_digest, sig)

    def test_different_inputs_different_aggregates(
        self,
        issuer_secret_key: bytes,
    ) -> None:
        """Different token data produces different aggregate signatures."""
        prev_agg = b"\x00" * 48
        sig1 = aggregate_sign(issuer_secret_key, prev_agg, b"data_a")
        sig2 = aggregate_sign(issuer_secret_key, prev_agg, b"data_b")
        assert sig1 != sig2

    def test_different_aggregates_different_output(
        self,
        issuer_secret_key: bytes,
    ) -> None:
        """Different previous aggregates produce different signatures."""
        token_cbor = b"same data"
        sig1 = aggregate_sign(issuer_secret_key, b"\x00" * 48, token_cbor)
        sig2 = aggregate_sign(issuer_secret_key, b"\xff" * 48, token_cbor)
        assert sig1 != sig2


# =============================================================================
# TestAggregateVerifyChain
# =============================================================================


class TestAggregateVerifyChain:
    """Tests for aggregate_verify_chain."""

    def test_empty_chain_error(self, issuer_public_key: bytes) -> None:
        """Empty token list raises InvalidDelegationChainError."""
        with pytest.raises(InvalidDelegationChainError, match="Empty"):
            aggregate_verify_chain([], issuer_public_key)

    def test_root_only_chain(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
    ) -> None:
        """A single root token verifies successfully."""
        root = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/root-only",
            verbs={"read"},
            max_delegation_depth=0,
        )
        assert aggregate_verify_chain([root], issuer_public_key)

    def test_depth_2_chain(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        delegate_did: DID,
        did_registry: DIDRegistry,
    ) -> None:
        """A root + 1 delegation aggregate chain verifies."""
        root = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/depth2",
            verbs={"read", "write"},
            max_delegation_depth=3,
        )
        token1, _agg = attenuate_token_aggregate(
            parent_token=root,
            delegator_sk=subject_secret_key,
            new_subject_did=delegate_did,
            previous_aggregate=root.signature,
        )
        resolver = LocalDIDResolver(did_registry)
        assert aggregate_verify_chain(
            [root, token1], issuer_public_key, did_resolver=resolver
        )

    def test_depth_3_chain(
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
        """A root + 2 delegation aggregate chain verifies."""
        root = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/depth3",
            verbs={"read", "write", "execute"},
            max_delegation_depth=5,
        )
        token1, agg1 = attenuate_token_aggregate(
            parent_token=root,
            delegator_sk=subject_secret_key,
            new_subject_did=delegate_did,
            previous_aggregate=root.signature,
        )
        token2, _agg2 = attenuate_token_aggregate(
            parent_token=token1,
            delegator_sk=delegate_secret_key,
            new_subject_did=third_party_did,
            previous_aggregate=agg1,
        )
        resolver = LocalDIDResolver(did_registry)
        assert aggregate_verify_chain(
            [root, token1, token2],
            issuer_public_key,
            did_resolver=resolver,
        )

    def test_depth_5_chain(self) -> None:
        """A root + 4 delegation aggregate chain verifies."""
        entities = [_make_entity() for _ in range(6)]
        registry = _registry_from_entities(entities)
        resolver = LocalDIDResolver(registry)

        tokens = _build_aggregate_chain(entities)
        root_pk = entities[0][0]

        assert aggregate_verify_chain(
            tokens, root_pk, did_resolver=resolver
        )

    def test_without_resolver_structural_only(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        delegate_did: DID,
    ) -> None:
        """Without a DID resolver, only structural checks are performed."""
        root = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/no-resolver",
            verbs={"read"},
            max_delegation_depth=2,
        )
        token1, _agg = attenuate_token_aggregate(
            parent_token=root,
            delegator_sk=subject_secret_key,
            new_subject_did=delegate_did,
            previous_aggregate=root.signature,
        )
        # No resolver: signature not checked, but structural checks pass
        assert aggregate_verify_chain(
            [root, token1], issuer_public_key, did_resolver=None
        )


# =============================================================================
# TestTamperDetection
# =============================================================================


class TestTamperDetection:
    """Tests that tampered chains are rejected."""

    @pytest.fixture
    def chain_3(
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
    ) -> tuple[list, bytes, LocalDIDResolver]:
        """Build a valid 3-token aggregate chain for tamper tests."""
        root = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/tamper",
            verbs={"read", "write", "execute"},
            max_delegation_depth=5,
        )
        token1, agg1 = attenuate_token_aggregate(
            parent_token=root,
            delegator_sk=subject_secret_key,
            new_subject_did=delegate_did,
            previous_aggregate=root.signature,
        )
        token2, _agg2 = attenuate_token_aggregate(
            parent_token=token1,
            delegator_sk=delegate_secret_key,
            new_subject_did=third_party_did,
            previous_aggregate=agg1,
        )
        resolver = LocalDIDResolver(did_registry)
        return [root, token1, token2], issuer_public_key, resolver

    def test_modify_intermediate_token_data(
        self,
        chain_3: tuple[list, bytes, LocalDIDResolver],
    ) -> None:
        """Modifying an intermediate token's data breaks the chain."""
        tokens, root_pk, resolver = chain_3
        tampered = replace(tokens[1], resource_uri="qasp://hacked")
        with pytest.raises(InvalidDelegationChainError):
            aggregate_verify_chain(
                [tokens[0], tampered, tokens[2]], root_pk, resolver
            )

    def test_modify_intermediate_aggregate(
        self,
        chain_3: tuple[list, bytes, LocalDIDResolver],
    ) -> None:
        """Modifying an intermediate token's aggregate signature breaks the chain."""
        tokens, root_pk, resolver = chain_3
        bad_sig = bytes(len(tokens[1].signature))  # all zeros
        tampered = replace(tokens[1], signature=bad_sig)
        with pytest.raises(InvalidDelegationChainError):
            aggregate_verify_chain(
                [tokens[0], tampered, tokens[2]], root_pk, resolver
            )

    def test_swap_tokens_in_chain(
        self,
        chain_3: tuple[list, bytes, LocalDIDResolver],
    ) -> None:
        """Swapping token order breaks the chain."""
        tokens, root_pk, resolver = chain_3
        with pytest.raises(InvalidDelegationChainError):
            aggregate_verify_chain(
                [tokens[0], tokens[2], tokens[1]], root_pk, resolver
            )

    def test_modify_root_signature(
        self,
        chain_3: tuple[list, bytes, LocalDIDResolver],
    ) -> None:
        """Modifying the root token's signature breaks verification."""
        tokens, root_pk, resolver = chain_3
        bad_sig = bytes(len(tokens[0].signature))
        tampered_root = replace(tokens[0], signature=bad_sig)
        with pytest.raises(InvalidDelegationChainError):
            aggregate_verify_chain(
                [tampered_root, tokens[1], tokens[2]], root_pk, resolver
            )


# =============================================================================
# TestAttenuateTokenAggregate
# =============================================================================


class TestAttenuateTokenAggregate:
    """Tests for attenuate_token_aggregate."""

    @pytest.fixture
    def root_token(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> CapabilityToken:
        from qasp.protocol.capability import CapabilityToken

        return create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/attenuate",
            verbs={"read", "write", "execute"},
            max_delegation_depth=5,
            constraints=Constraints(
                not_after=datetime.now(UTC) + timedelta(hours=1),
                quantity_limit=100,
            ),
        )

    def test_basic_attenuation(
        self,
        root_token: CapabilityToken,
        subject_secret_key: bytes,
        delegate_did: DID,
    ) -> None:
        """attenuate_token_aggregate produces a token and aggregate."""
        token, agg = attenuate_token_aggregate(
            parent_token=root_token,
            delegator_sk=subject_secret_key,
            new_subject_did=delegate_did,
            previous_aggregate=root_token.signature,
        )
        assert isinstance(token, type(root_token))
        assert isinstance(agg, bytes)
        assert len(agg) > 0

    def test_returns_correct_aggregate(
        self,
        root_token: CapabilityToken,
        subject_secret_key: bytes,
        delegate_did: DID,
    ) -> None:
        """Returned aggregate equals the token's signature field."""
        token, agg = attenuate_token_aggregate(
            parent_token=root_token,
            delegator_sk=subject_secret_key,
            new_subject_did=delegate_did,
            previous_aggregate=root_token.signature,
        )
        assert token.signature == agg

    def test_verb_reduction(
        self,
        root_token: CapabilityToken,
        subject_secret_key: bytes,
        delegate_did: DID,
    ) -> None:
        """Reduced verbs are respected in the new token."""
        reduced = VerbSet({"read"})
        token, _ = attenuate_token_aggregate(
            parent_token=root_token,
            delegator_sk=subject_secret_key,
            new_subject_did=delegate_did,
            previous_aggregate=root_token.signature,
            reduced_verbs=reduced,
        )
        assert token.verbs.verbs == frozenset({"read"})

    def test_verb_not_subset_raises(
        self,
        root_token: CapabilityToken,
        subject_secret_key: bytes,
        delegate_did: DID,
    ) -> None:
        """Requesting verbs not in parent raises AttenuationError."""
        bad_verbs = VerbSet({"read", "delete"})
        with pytest.raises(AttenuationError, match="Cannot delegate"):
            attenuate_token_aggregate(
                parent_token=root_token,
                delegator_sk=subject_secret_key,
                new_subject_did=delegate_did,
                previous_aggregate=root_token.signature,
                reduced_verbs=bad_verbs,
            )

    def test_constraint_tightening(
        self,
        root_token: CapabilityToken,
        subject_secret_key: bytes,
        delegate_did: DID,
    ) -> None:
        """Tightened constraints are applied correctly."""
        tighter = Constraints(quantity_limit=50)
        token, _ = attenuate_token_aggregate(
            parent_token=root_token,
            delegator_sk=subject_secret_key,
            new_subject_did=delegate_did,
            previous_aggregate=root_token.signature,
            tightened_constraints=tighter,
        )
        assert token.constraints.quantity_limit == 50

    def test_depth_management(
        self,
        root_token: CapabilityToken,
        subject_secret_key: bytes,
        delegate_did: DID,
    ) -> None:
        """Depth decrements and chain_length increments correctly."""
        token, _ = attenuate_token_aggregate(
            parent_token=root_token,
            delegator_sk=subject_secret_key,
            new_subject_did=delegate_did,
            previous_aggregate=root_token.signature,
        )
        assert token.max_delegation_depth == root_token.max_delegation_depth - 1
        assert token.delegation_chain_length == root_token.delegation_chain_length + 1

    def test_expired_parent_raises(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        delegate_did: DID,
    ) -> None:
        """Attenuating an expired parent raises TokenExpiredError."""
        expired_root = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/expired",
            verbs={"read"},
            max_delegation_depth=2,
            validity_seconds=0,  # expires immediately
        )
        with pytest.raises(TokenExpiredError):
            attenuate_token_aggregate(
                parent_token=expired_root,
                delegator_sk=subject_secret_key,
                new_subject_did=delegate_did,
                previous_aggregate=expired_root.signature,
            )

    def test_depth_exceeded_raises(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        delegate_did: DID,
    ) -> None:
        """Attenuating a token with max_delegation_depth=0 raises."""
        root = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/no-depth",
            verbs={"read"},
            max_delegation_depth=0,
        )
        with pytest.raises(DelegationDepthExceeded):
            attenuate_token_aggregate(
                parent_token=root,
                delegator_sk=subject_secret_key,
                new_subject_did=delegate_did,
                previous_aggregate=root.signature,
            )

    def test_parent_hash_set(
        self,
        root_token: CapabilityToken,
        subject_secret_key: bytes,
        delegate_did: DID,
    ) -> None:
        """The delegated token's parent_token_hash matches parent's hash."""
        token, _ = attenuate_token_aggregate(
            parent_token=root_token,
            delegator_sk=subject_secret_key,
            new_subject_did=delegate_did,
            previous_aggregate=root_token.signature,
        )
        assert token.parent_token_hash == root_token.compute_hash()

    def test_issuer_is_parent_subject(
        self,
        root_token: CapabilityToken,
        subject_secret_key: bytes,
        delegate_did: DID,
    ) -> None:
        """The delegated token's issuer is the parent's subject."""
        token, _ = attenuate_token_aggregate(
            parent_token=root_token,
            delegator_sk=subject_secret_key,
            new_subject_did=delegate_did,
            previous_aggregate=root_token.signature,
        )
        assert token.issuer_did == root_token.subject_did


# =============================================================================
# TestDelegationChain
# =============================================================================


class TestDelegationChain:
    """Tests for the DelegationChain container."""

    def test_from_tokens_empty_raises(self) -> None:
        """from_tokens with empty list raises."""
        with pytest.raises(InvalidDelegationChainError, match="Empty"):
            DelegationChain.from_tokens([])

    def test_from_tokens_creates_chain(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """from_tokens creates a valid DelegationChain."""
        root = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/chain",
            verbs={"read"},
        )
        chain = DelegationChain.from_tokens([root], is_aggregated=False)
        assert chain.tokens == (root,)
        assert chain.is_aggregated is False

    def test_properties_root_leaf_depth(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        delegate_did: DID,
    ) -> None:
        """root, leaf, and depth properties work correctly."""
        root = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/props",
            verbs={"read"},
            max_delegation_depth=3,
        )
        token1, _ = attenuate_token_aggregate(
            parent_token=root,
            delegator_sk=subject_secret_key,
            new_subject_did=delegate_did,
            previous_aggregate=root.signature,
        )
        chain = DelegationChain.from_tokens([root, token1], is_aggregated=True)

        assert chain.root is root
        assert chain.leaf is token1
        assert chain.depth == 1

    def test_aggregate_signature_property(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        delegate_did: DID,
    ) -> None:
        """aggregate_signature returns leaf signature for aggregated chains."""
        root = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/agg-prop",
            verbs={"read"},
            max_delegation_depth=3,
        )
        token1, agg = attenuate_token_aggregate(
            parent_token=root,
            delegator_sk=subject_secret_key,
            new_subject_did=delegate_did,
            previous_aggregate=root.signature,
        )
        chain = DelegationChain.from_tokens([root, token1], is_aggregated=True)
        assert chain.aggregate_signature == agg

    def test_aggregate_signature_none_for_non_aggregated(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """aggregate_signature returns None for non-aggregated chains."""
        root = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/non-agg",
            verbs={"read"},
        )
        chain = DelegationChain.from_tokens([root], is_aggregated=False)
        assert chain.aggregate_signature is None

    def test_verify_aggregated(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        delegate_did: DID,
        did_registry: DIDRegistry,
    ) -> None:
        """DelegationChain.verify() works for aggregated chains."""
        root = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/verify-agg",
            verbs={"read"},
            max_delegation_depth=3,
        )
        token1, _ = attenuate_token_aggregate(
            parent_token=root,
            delegator_sk=subject_secret_key,
            new_subject_did=delegate_did,
            previous_aggregate=root.signature,
        )
        chain = DelegationChain.from_tokens([root, token1], is_aggregated=True)
        resolver = LocalDIDResolver(did_registry)
        assert chain.verify(issuer_public_key, did_resolver=resolver)

    def test_verify_non_aggregated(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        delegate_did: DID,
        did_registry: DIDRegistry,
    ) -> None:
        """DelegationChain.verify() works for non-aggregated chains."""
        from qasp.protocol.capability import attenuate_token

        root = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/verify-std",
            verbs={"read"},
            max_delegation_depth=3,
        )
        token1 = attenuate_token(
            parent_token=root,
            delegator_secret_key=subject_secret_key,
            new_subject_did=delegate_did,
        )
        chain = DelegationChain.from_tokens(
            [root, token1], is_aggregated=False
        )
        resolver = LocalDIDResolver(did_registry)
        assert chain.verify(issuer_public_key, did_resolver=resolver)

    def test_verify_root_only_aggregated(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
    ) -> None:
        """Root-only chain with is_aggregated=True uses standard verification."""
        root = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/root-agg",
            verbs={"read"},
        )
        chain = DelegationChain.from_tokens([root], is_aggregated=True)
        # depth=0 so falls through to verify_delegation_chain
        assert chain.verify(issuer_public_key)

    def test_frozen(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ) -> None:
        """DelegationChain is immutable."""
        root = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/frozen",
            verbs={"read"},
        )
        chain = DelegationChain.from_tokens([root])
        with pytest.raises(AttributeError):
            chain.is_aggregated = True  # type: ignore


# =============================================================================
# TestBackwardCompatibility
# =============================================================================


class TestBackwardCompatibility:
    """Tests that non-aggregated chains remain fully functional."""

    def test_standard_chain_via_delegation_chain(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        delegate_did: DID,
        did_registry: DIDRegistry,
    ) -> None:
        """A standard (non-aggregated) chain verifies via DelegationChain."""
        from qasp.protocol.capability import attenuate_token

        root = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/compat",
            verbs={"read", "write"},
            max_delegation_depth=3,
        )
        child = attenuate_token(
            parent_token=root,
            delegator_secret_key=subject_secret_key,
            new_subject_did=delegate_did,
        )
        chain = DelegationChain.from_tokens(
            [root, child], is_aggregated=False
        )
        resolver = LocalDIDResolver(did_registry)
        assert chain.verify(issuer_public_key, did_resolver=resolver)

    def test_standard_chain_direct_verify(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        delegate_did: DID,
        did_registry: DIDRegistry,
    ) -> None:
        """verify_delegation_chain still works independently of aggregation."""
        from qasp.protocol.capability import attenuate_token

        root = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/direct",
            verbs={"read"},
            max_delegation_depth=2,
        )
        child = attenuate_token(
            parent_token=root,
            delegator_secret_key=subject_secret_key,
            new_subject_did=delegate_did,
        )
        resolver = LocalDIDResolver(did_registry)
        assert verify_delegation_chain(
            [root, child], issuer_public_key, did_resolver=resolver
        )

    def test_aggregated_not_verifiable_as_standard(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        delegate_did: DID,
        did_registry: DIDRegistry,
    ) -> None:
        """An aggregate chain fails standard verify_delegation_chain sig checks.

        The aggregate signature doesn't match the standard per-token digest,
        so individual signature verification must fail.
        """
        root = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/mixed",
            verbs={"read"},
            max_delegation_depth=3,
        )
        token1, _ = attenuate_token_aggregate(
            parent_token=root,
            delegator_sk=subject_secret_key,
            new_subject_did=delegate_did,
            previous_aggregate=root.signature,
        )
        resolver = LocalDIDResolver(did_registry)
        # Standard verification will fail on the aggregate token's signature
        with pytest.raises(InvalidDelegationChainError):
            verify_delegation_chain(
                [root, token1], issuer_public_key, did_resolver=resolver
            )
