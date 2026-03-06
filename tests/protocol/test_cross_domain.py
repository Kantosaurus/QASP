"""Tests for cross-domain delegation."""

from __future__ import annotations

import pytest

from qasp.crypto.signatures import generate_keypair
from qasp.identity import DID, DIDDocument, DIDRegistry, create_did
from qasp.identity.binding import (
    OwnerBinding,
    Permission,
    create_owner_binding,
)
from qasp.protocol.aggregation import DelegationChain, attenuate_token_aggregate
from qasp.protocol.capability import (
    CapabilityToken,
    LocalDIDResolver,
    VerbSet,
    create_token,
)
from qasp.protocol.cross_domain import (
    CrossDomainBindingError,
    CrossDomainDelegation,
    CrossDomainPermissionError,
    CrossDomainVerificationError,
    EndorsementExpiredError,
    InvalidAcceptanceError,
    InvalidEndorsementError,
    OwnerAcceptance,
    OwnerEndorsement,
    attenuate_token_cross_domain_aggregate,
    create_acceptance,
    create_cross_domain_delegation,
    create_endorsement,
    revoke_cross_domain_delegation,
    verify_acceptance,
    verify_cross_domain_delegation,
    verify_endorsement,
)
from qasp.protocol.revocation import CertificateRevocationList


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def alice_keypair() -> tuple[bytes, bytes]:
    return generate_keypair()


@pytest.fixture
def alice_pk(alice_keypair: tuple[bytes, bytes]) -> bytes:
    return alice_keypair[0]


@pytest.fixture
def alice_sk(alice_keypair: tuple[bytes, bytes]) -> bytes:
    return alice_keypair[1]


@pytest.fixture
def bob_keypair() -> tuple[bytes, bytes]:
    return generate_keypair()


@pytest.fixture
def bob_pk(bob_keypair: tuple[bytes, bytes]) -> bytes:
    return bob_keypair[0]


@pytest.fixture
def bob_sk(bob_keypair: tuple[bytes, bytes]) -> bytes:
    return bob_keypair[1]


@pytest.fixture
def alpha_keypair() -> tuple[bytes, bytes]:
    return generate_keypair()


@pytest.fixture
def alpha_pk(alpha_keypair: tuple[bytes, bytes]) -> bytes:
    return alpha_keypair[0]


@pytest.fixture
def alpha_sk(alpha_keypair: tuple[bytes, bytes]) -> bytes:
    return alpha_keypair[1]


@pytest.fixture
def beta_keypair() -> tuple[bytes, bytes]:
    return generate_keypair()


@pytest.fixture
def beta_pk(beta_keypair: tuple[bytes, bytes]) -> bytes:
    return beta_keypair[0]


@pytest.fixture
def beta_sk(beta_keypair: tuple[bytes, bytes]) -> bytes:
    return beta_keypair[1]


@pytest.fixture
def issuer_keypair() -> tuple[bytes, bytes]:
    return generate_keypair()


@pytest.fixture
def issuer_pk(issuer_keypair: tuple[bytes, bytes]) -> bytes:
    return issuer_keypair[0]


@pytest.fixture
def issuer_sk(issuer_keypair: tuple[bytes, bytes]) -> bytes:
    return issuer_keypair[1]


@pytest.fixture
def alice_did(alice_pk: bytes) -> DID:
    did, _ = create_did(alice_pk)
    return did


@pytest.fixture
def alice_did_doc(alice_pk: bytes) -> DIDDocument:
    _, doc = create_did(alice_pk)
    return doc


@pytest.fixture
def bob_did(bob_pk: bytes) -> DID:
    did, _ = create_did(bob_pk)
    return did


@pytest.fixture
def bob_did_doc(bob_pk: bytes) -> DIDDocument:
    _, doc = create_did(bob_pk)
    return doc


@pytest.fixture
def alpha_did(alpha_pk: bytes) -> DID:
    did, _ = create_did(alpha_pk)
    return did


@pytest.fixture
def alpha_did_doc(alpha_pk: bytes) -> DIDDocument:
    _, doc = create_did(alpha_pk)
    return doc


@pytest.fixture
def beta_did(beta_pk: bytes) -> DID:
    did, _ = create_did(beta_pk)
    return did


@pytest.fixture
def beta_did_doc(beta_pk: bytes) -> DIDDocument:
    _, doc = create_did(beta_pk)
    return doc


@pytest.fixture
def issuer_did(issuer_pk: bytes) -> DID:
    did, _ = create_did(issuer_pk)
    return did


@pytest.fixture
def issuer_did_doc(issuer_pk: bytes) -> DIDDocument:
    _, doc = create_did(issuer_pk)
    return doc


@pytest.fixture
def root_token(
    issuer_did: DID,
    issuer_sk: bytes,
    alpha_did: DID,
) -> CapabilityToken:
    return create_token(
        issuer_did=issuer_did,
        issuer_secret_key=issuer_sk,
        subject_did=alpha_did,
        resource_uri="qasp://data/documents",
        verbs={"read", "write", "execute"},
        max_delegation_depth=5,
        validity_seconds=7200,
    )


@pytest.fixture
def attenuated_token(
    root_token: CapabilityToken,
    alpha_sk: bytes,
    beta_did: DID,
) -> CapabilityToken:
    token, _ = attenuate_token_aggregate(
        parent_token=root_token,
        delegator_sk=alpha_sk,
        new_subject_did=beta_did,
        previous_aggregate=root_token.signature,
        reduced_verbs=VerbSet({"read", "write"}),
    )
    return token


@pytest.fixture
def source_binding(
    alpha_did: DID,
    alice_did: DID,
    alice_sk: bytes,
) -> OwnerBinding:
    return create_owner_binding(
        agent_did=alpha_did,
        owner_did=alice_did,
        owner_secret_key=alice_sk,
        permissions={
            Permission.RESOURCE_DELEGATE,
            Permission.RESOURCE_REQUEST,
        },
    )


@pytest.fixture
def target_binding(
    beta_did: DID,
    bob_did: DID,
    bob_sk: bytes,
) -> OwnerBinding:
    return create_owner_binding(
        agent_did=beta_did,
        owner_did=bob_did,
        owner_secret_key=bob_sk,
        permissions={
            Permission.RESOURCE_REQUEST,
            Permission.COMM_ACCEPT,
        },
    )


@pytest.fixture
def endorsement(
    alice_did: DID,
    alice_sk: bytes,
    bob_did: DID,
    attenuated_token: CapabilityToken,
) -> OwnerEndorsement:
    return create_endorsement(
        endorser_did=alice_did,
        endorser_sk=alice_sk,
        target_owner_did=bob_did,
        attenuated_token=attenuated_token,
        purpose="share document access",
    )


@pytest.fixture
def acceptance(
    bob_did: DID,
    bob_sk: bytes,
    attenuated_token: CapabilityToken,
    endorsement: OwnerEndorsement,
) -> OwnerAcceptance:
    return create_acceptance(
        acceptor_did=bob_did,
        acceptor_sk=bob_sk,
        attenuated_token=attenuated_token,
        endorsement=endorsement,
    )


@pytest.fixture
def delegation_chain(
    root_token: CapabilityToken,
    attenuated_token: CapabilityToken,
) -> DelegationChain:
    return DelegationChain.from_tokens(
        [root_token, attenuated_token],
        is_aggregated=True,
    )


@pytest.fixture
def did_resolver(
    issuer_did_doc: DIDDocument,
    alpha_did_doc: DIDDocument,
    beta_did_doc: DIDDocument,
) -> LocalDIDResolver:
    registry = DIDRegistry()
    registry.register(issuer_did_doc)
    registry.register(alpha_did_doc)
    registry.register(beta_did_doc)
    return LocalDIDResolver(registry)


@pytest.fixture
def cross_domain_delegation(
    attenuated_token: CapabilityToken,
    delegation_chain: DelegationChain,
    source_binding: OwnerBinding,
    endorsement: OwnerEndorsement,
    target_binding: OwnerBinding,
    acceptance: OwnerAcceptance,
) -> CrossDomainDelegation:
    return create_cross_domain_delegation(
        attenuated_token=attenuated_token,
        delegation_chain=delegation_chain,
        source_binding=source_binding,
        endorsement=endorsement,
        target_binding=target_binding,
        acceptance=acceptance,
    )


# =============================================================================
# TestOwnerEndorsement
# =============================================================================


class TestOwnerEndorsement:

    def test_create_endorsement(
        self,
        alice_did: DID,
        alice_sk: bytes,
        bob_did: DID,
        attenuated_token: CapabilityToken,
    ) -> None:
        endorsement = create_endorsement(
            endorser_did=alice_did,
            endorser_sk=alice_sk,
            target_owner_did=bob_did,
            attenuated_token=attenuated_token,
            purpose="test delegation",
        )

        assert endorsement.endorser_did == alice_did
        assert endorsement.target_owner_did == bob_did
        assert endorsement.purpose == "test delegation"
        assert len(endorsement.nonce) == 16
        assert len(endorsement.signature) > 0
        assert endorsement.token_hash == attenuated_token.compute_hash()

    def test_endorsement_cbor_roundtrip(
        self, endorsement: OwnerEndorsement
    ) -> None:
        cbor_data = endorsement.to_cbor()
        assert isinstance(cbor_data, bytes)
        assert len(cbor_data) > 0

    def test_endorsement_hash(self, endorsement: OwnerEndorsement) -> None:
        h = endorsement.compute_hash()
        assert len(h) == 48  # SHA-384
        assert endorsement.compute_hash() == h

    def test_verify_endorsement_valid(
        self,
        endorsement: OwnerEndorsement,
        alice_pk: bytes,
        attenuated_token: CapabilityToken,
    ) -> None:
        assert verify_endorsement(endorsement, alice_pk, attenuated_token) is True

    def test_verify_endorsement_wrong_key(
        self,
        endorsement: OwnerEndorsement,
        bob_pk: bytes,
        attenuated_token: CapabilityToken,
    ) -> None:
        with pytest.raises(InvalidEndorsementError, match="signature"):
            verify_endorsement(endorsement, bob_pk, attenuated_token)

    def test_verify_endorsement_wrong_token(
        self,
        endorsement: OwnerEndorsement,
        alice_pk: bytes,
        root_token: CapabilityToken,
    ) -> None:
        with pytest.raises(InvalidEndorsementError, match="token_hash"):
            verify_endorsement(endorsement, alice_pk, root_token)

    def test_verify_endorsement_expired(
        self,
        alice_did: DID,
        alice_sk: bytes,
        alice_pk: bytes,
        bob_did: DID,
        attenuated_token: CapabilityToken,
    ) -> None:
        endorsement = create_endorsement(
            endorser_did=alice_did,
            endorser_sk=alice_sk,
            target_owner_did=bob_did,
            attenuated_token=attenuated_token,
            validity_seconds=0,
        )
        with pytest.raises(EndorsementExpiredError):
            verify_endorsement(endorsement, alice_pk, attenuated_token)

    def test_verify_endorsement_skip_expiry(
        self,
        alice_did: DID,
        alice_sk: bytes,
        alice_pk: bytes,
        bob_did: DID,
        attenuated_token: CapabilityToken,
    ) -> None:
        endorsement = create_endorsement(
            endorser_did=alice_did,
            endorser_sk=alice_sk,
            target_owner_did=bob_did,
            attenuated_token=attenuated_token,
            validity_seconds=0,
        )
        assert verify_endorsement(
            endorsement, alice_pk, attenuated_token, check_expiry=False
        ) is True


# =============================================================================
# TestOwnerAcceptance
# =============================================================================


class TestOwnerAcceptance:

    def test_create_acceptance(
        self,
        bob_did: DID,
        bob_sk: bytes,
        attenuated_token: CapabilityToken,
        endorsement: OwnerEndorsement,
    ) -> None:
        acc = create_acceptance(
            acceptor_did=bob_did,
            acceptor_sk=bob_sk,
            attenuated_token=attenuated_token,
            endorsement=endorsement,
        )

        assert acc.acceptor_did == bob_did
        assert acc.token_hash == attenuated_token.compute_hash()
        assert acc.endorsement_hash == endorsement.compute_hash()
        assert len(acc.nonce) == 16
        assert len(acc.signature) > 0

    def test_verify_acceptance_valid(
        self,
        acceptance: OwnerAcceptance,
        bob_pk: bytes,
        attenuated_token: CapabilityToken,
        endorsement: OwnerEndorsement,
    ) -> None:
        assert verify_acceptance(
            acceptance, bob_pk, attenuated_token, endorsement
        ) is True

    def test_verify_acceptance_wrong_key(
        self,
        acceptance: OwnerAcceptance,
        alice_pk: bytes,
        attenuated_token: CapabilityToken,
        endorsement: OwnerEndorsement,
    ) -> None:
        with pytest.raises(InvalidAcceptanceError, match="signature"):
            verify_acceptance(acceptance, alice_pk, attenuated_token, endorsement)

    def test_verify_acceptance_wrong_token(
        self,
        acceptance: OwnerAcceptance,
        bob_pk: bytes,
        root_token: CapabilityToken,
        endorsement: OwnerEndorsement,
    ) -> None:
        with pytest.raises(InvalidAcceptanceError, match="token_hash"):
            verify_acceptance(acceptance, bob_pk, root_token, endorsement)

    def test_verify_acceptance_wrong_endorsement(
        self,
        acceptance: OwnerAcceptance,
        bob_pk: bytes,
        attenuated_token: CapabilityToken,
        alice_did: DID,
        alice_sk: bytes,
        bob_did: DID,
    ) -> None:
        different_endorsement = create_endorsement(
            endorser_did=alice_did,
            endorser_sk=alice_sk,
            target_owner_did=bob_did,
            attenuated_token=attenuated_token,
            purpose="different purpose",
        )
        with pytest.raises(InvalidAcceptanceError, match="endorsement_hash"):
            verify_acceptance(
                acceptance, bob_pk, attenuated_token, different_endorsement
            )


# =============================================================================
# TestCrossDomainVerification
# =============================================================================


class TestCrossDomainVerification:

    def test_full_verification_passes(
        self,
        cross_domain_delegation: CrossDomainDelegation,
        alice_pk: bytes,
        bob_pk: bytes,
        issuer_pk: bytes,
        did_resolver: LocalDIDResolver,
    ) -> None:
        assert verify_cross_domain_delegation(
            delegation=cross_domain_delegation,
            source_owner_pk=alice_pk,
            target_owner_pk=bob_pk,
            root_issuer_pk=issuer_pk,
            did_resolver=did_resolver,
        ) is True

    def test_delegation_id_is_deterministic(
        self, cross_domain_delegation: CrossDomainDelegation
    ) -> None:
        assert len(cross_domain_delegation.delegation_id) == 32

    def test_check1_chain_invalid(
        self,
        cross_domain_delegation: CrossDomainDelegation,
        alice_pk: bytes,
        bob_pk: bytes,
        did_resolver: LocalDIDResolver,
    ) -> None:
        wrong_pk, _ = generate_keypair()
        with pytest.raises(CrossDomainVerificationError, match="Chain"):
            verify_cross_domain_delegation(
                delegation=cross_domain_delegation,
                source_owner_pk=alice_pk,
                target_owner_pk=bob_pk,
                root_issuer_pk=wrong_pk,
                did_resolver=did_resolver,
            )

    def test_check3_source_binding_wrong_key(
        self,
        cross_domain_delegation: CrossDomainDelegation,
        bob_pk: bytes,
        issuer_pk: bytes,
        did_resolver: LocalDIDResolver,
    ) -> None:
        wrong_pk, _ = generate_keypair()
        with pytest.raises(CrossDomainBindingError, match="Source"):
            verify_cross_domain_delegation(
                delegation=cross_domain_delegation,
                source_owner_pk=wrong_pk,
                target_owner_pk=bob_pk,
                root_issuer_pk=issuer_pk,
                did_resolver=did_resolver,
            )

    def test_check3_source_binding_missing_permission(
        self,
        attenuated_token: CapabilityToken,
        delegation_chain: DelegationChain,
        alpha_did: DID,
        alice_did: DID,
        alice_sk: bytes,
        alice_pk: bytes,
        endorsement: OwnerEndorsement,
        target_binding: OwnerBinding,
        acceptance: OwnerAcceptance,
        bob_pk: bytes,
        issuer_pk: bytes,
        did_resolver: LocalDIDResolver,
    ) -> None:
        binding_no_delegate = create_owner_binding(
            agent_did=alpha_did,
            owner_did=alice_did,
            owner_secret_key=alice_sk,
            permissions={Permission.RESOURCE_REQUEST},
        )
        delegation = create_cross_domain_delegation(
            attenuated_token=attenuated_token,
            delegation_chain=delegation_chain,
            source_binding=binding_no_delegate,
            endorsement=endorsement,
            target_binding=target_binding,
            acceptance=acceptance,
        )
        with pytest.raises(CrossDomainPermissionError, match="RESOURCE_DELEGATE"):
            verify_cross_domain_delegation(
                delegation=delegation,
                source_owner_pk=alice_pk,
                target_owner_pk=bob_pk,
                root_issuer_pk=issuer_pk,
                did_resolver=did_resolver,
            )

    def test_check3_endorsement_invalid(
        self,
        attenuated_token: CapabilityToken,
        delegation_chain: DelegationChain,
        source_binding: OwnerBinding,
        target_binding: OwnerBinding,
        acceptance: OwnerAcceptance,
        alice_pk: bytes,
        bob_did: DID,
        bob_sk: bytes,
        bob_pk: bytes,
        issuer_pk: bytes,
        did_resolver: LocalDIDResolver,
    ) -> None:
        bad_endorsement = create_endorsement(
            endorser_did=source_binding.owner_did,
            endorser_sk=bob_sk,
            target_owner_did=bob_did,
            attenuated_token=attenuated_token,
            purpose="bad",
        )
        delegation = create_cross_domain_delegation(
            attenuated_token=attenuated_token,
            delegation_chain=delegation_chain,
            source_binding=source_binding,
            endorsement=bad_endorsement,
            target_binding=target_binding,
            acceptance=acceptance,
        )
        with pytest.raises(InvalidEndorsementError):
            verify_cross_domain_delegation(
                delegation=delegation,
                source_owner_pk=alice_pk,
                target_owner_pk=bob_pk,
                root_issuer_pk=issuer_pk,
                did_resolver=did_resolver,
            )

    def test_check4_target_binding_wrong_key(
        self,
        cross_domain_delegation: CrossDomainDelegation,
        alice_pk: bytes,
        issuer_pk: bytes,
        did_resolver: LocalDIDResolver,
    ) -> None:
        wrong_pk, _ = generate_keypair()
        with pytest.raises(CrossDomainBindingError, match="Target"):
            verify_cross_domain_delegation(
                delegation=cross_domain_delegation,
                source_owner_pk=alice_pk,
                target_owner_pk=wrong_pk,
                root_issuer_pk=issuer_pk,
                did_resolver=did_resolver,
            )

    def test_check4_acceptance_invalid(
        self,
        attenuated_token: CapabilityToken,
        delegation_chain: DelegationChain,
        source_binding: OwnerBinding,
        endorsement: OwnerEndorsement,
        target_binding: OwnerBinding,
        alice_pk: bytes,
        alice_sk: bytes,
        bob_pk: bytes,
        issuer_pk: bytes,
        did_resolver: LocalDIDResolver,
    ) -> None:
        bad_acceptance = create_acceptance(
            acceptor_did=target_binding.owner_did,
            acceptor_sk=alice_sk,
            attenuated_token=attenuated_token,
            endorsement=endorsement,
        )
        delegation = create_cross_domain_delegation(
            attenuated_token=attenuated_token,
            delegation_chain=delegation_chain,
            source_binding=source_binding,
            endorsement=endorsement,
            target_binding=target_binding,
            acceptance=bad_acceptance,
        )
        with pytest.raises(InvalidAcceptanceError):
            verify_cross_domain_delegation(
                delegation=delegation,
                source_owner_pk=alice_pk,
                target_owner_pk=bob_pk,
                root_issuer_pk=issuer_pk,
                did_resolver=did_resolver,
            )


# =============================================================================
# TestCrossDomainRevocation
# =============================================================================


class TestCrossDomainRevocation:

    def test_revoke_cross_domain_delegation(
        self,
        cross_domain_delegation: CrossDomainDelegation,
        alice_did: DID,
        alice_sk: bytes,
    ) -> None:
        from qasp.protocol.revocation import RevocationUrgency

        crl = CertificateRevocationList()
        crl.register_token(cross_domain_delegation.attenuated_token)

        revoked_ids = revoke_cross_domain_delegation(
            delegation=cross_domain_delegation,
            revoker_did=alice_did,
            revoker_sk=alice_sk,
            crl=crl,
            urgency=RevocationUrgency.CRITICAL,
        )

        assert cross_domain_delegation.attenuated_token.token_id in revoked_ids
        assert crl.is_revoked(cross_domain_delegation.attenuated_token.token_id)

    def test_revoke_cascades_to_descendants(
        self,
        cross_domain_delegation: CrossDomainDelegation,
        alice_did: DID,
        alice_sk: bytes,
        beta_sk: bytes,
        beta_pk: bytes,
    ) -> None:
        from qasp.protocol.revocation import RevocationUrgency

        crl = CertificateRevocationList()
        crl.register_token(cross_domain_delegation.attenuated_token)

        child_did, _ = create_did(generate_keypair()[0])
        child_token, _ = attenuate_token_aggregate(
            parent_token=cross_domain_delegation.attenuated_token,
            delegator_sk=beta_sk,
            new_subject_did=child_did,
            previous_aggregate=cross_domain_delegation.attenuated_token.signature,
            reduced_verbs=VerbSet({"read"}),
        )
        crl.register_token(child_token)

        revoked_ids = revoke_cross_domain_delegation(
            delegation=cross_domain_delegation,
            revoker_did=alice_did,
            revoker_sk=alice_sk,
            crl=crl,
            urgency=RevocationUrgency.CRITICAL,
        )

        assert len(revoked_ids) == 2
        assert child_token.token_id in revoked_ids


# =============================================================================
# TestCrossDomainAggregation
# =============================================================================


class TestCrossDomainAggregation:

    def test_attenuate_cross_domain_aggregate(
        self,
        root_token: CapabilityToken,
        alpha_sk: bytes,
        beta_did: DID,
    ) -> None:
        token, aggregate = attenuate_token_cross_domain_aggregate(
            parent_token=root_token,
            delegator_sk=alpha_sk,
            new_subject_did=beta_did,
            previous_aggregate=root_token.signature,
            reduced_verbs=VerbSet({"read", "write"}),
        )

        assert token.subject_did == beta_did
        assert token.verbs == VerbSet({"read", "write"})
        assert len(aggregate) > 0
        assert token.signature == aggregate

    def test_cross_domain_chain_verifies_with_aggregate(
        self,
        root_token: CapabilityToken,
        alpha_sk: bytes,
        beta_did: DID,
        issuer_pk: bytes,
        alpha_did_doc: DIDDocument,
        beta_did_doc: DIDDocument,
    ) -> None:
        token, _ = attenuate_token_cross_domain_aggregate(
            parent_token=root_token,
            delegator_sk=alpha_sk,
            new_subject_did=beta_did,
            previous_aggregate=root_token.signature,
        )

        registry = DIDRegistry()
        registry.register(alpha_did_doc)
        registry.register(beta_did_doc)
        resolver = LocalDIDResolver(registry)

        chain = DelegationChain.from_tokens(
            [root_token, token], is_aggregated=True
        )
        assert chain.verify(issuer_pk, resolver) is True
