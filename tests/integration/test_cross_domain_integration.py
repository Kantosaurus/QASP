"""Integration tests for cross-domain delegation.

Tests end-to-end flows including message encoding/decoding,
rejection scenarios, and revocation cascades across domain boundaries.
"""

from __future__ import annotations

import pytest

from qasp.crypto.signatures import generate_keypair
from qasp.framing.codec import decode_frame, encode_frame
from qasp.framing.messages import (
    DelegationGrant,
    DelegationRequest,
    MessageType,
)
from qasp.identity import DID, DIDDocument, DIDRegistry, create_did
from qasp.identity.binding import Permission, create_owner_binding
from qasp.protocol.aggregation import DelegationChain, attenuate_token_aggregate
from qasp.protocol.capability import (
    LocalDIDResolver,
    VerbSet,
    create_token,
)
from qasp.protocol.cross_domain import (
    create_acceptance,
    create_cross_domain_delegation,
    create_endorsement,
    revoke_cross_domain_delegation,
    verify_cross_domain_delegation,
)
from qasp.protocol.revocation import CertificateRevocationList, RevocationUrgency


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def setup():
    """Set up a complete cross-domain scenario with all parties."""
    issuer_pk, issuer_sk = generate_keypair()
    alice_pk, alice_sk = generate_keypair()
    bob_pk, bob_sk = generate_keypair()
    alpha_pk, alpha_sk = generate_keypair()
    beta_pk, beta_sk = generate_keypair()

    issuer_did, issuer_doc = create_did(issuer_pk)
    alice_did, alice_doc = create_did(alice_pk)
    bob_did, bob_doc = create_did(bob_pk)
    alpha_did, alpha_doc = create_did(alpha_pk)
    beta_did, beta_doc = create_did(beta_pk)

    registry = DIDRegistry()
    registry.register(issuer_doc)
    registry.register(alice_doc)
    registry.register(bob_doc)
    registry.register(alpha_doc)
    registry.register(beta_doc)
    resolver = LocalDIDResolver(registry)

    return {
        "issuer": (issuer_did, issuer_pk, issuer_sk),
        "alice": (alice_did, alice_pk, alice_sk),
        "bob": (bob_did, bob_pk, bob_sk),
        "alpha": (alpha_did, alpha_pk, alpha_sk),
        "beta": (beta_did, beta_pk, beta_sk),
        "resolver": resolver,
    }


# =============================================================================
# End-to-End Flow
# =============================================================================


class TestEndToEndFlow:

    def test_complete_delegation_flow(self, setup) -> None:
        issuer_did, issuer_pk, issuer_sk = setup["issuer"]
        alice_did, alice_pk, alice_sk = setup["alice"]
        bob_did, bob_pk, bob_sk = setup["bob"]
        alpha_did, alpha_pk, alpha_sk = setup["alpha"]
        beta_did, beta_pk, beta_sk = setup["beta"]
        resolver = setup["resolver"]

        # Step 1: Root token for Alpha
        root_token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_sk,
            subject_did=alpha_did,
            resource_uri="qasp://api/model-inference",
            verbs={"read", "write", "execute"},
            max_delegation_depth=5,
        )

        # Step 2: Alpha attenuates for Beta
        attenuated, _ = attenuate_token_aggregate(
            parent_token=root_token,
            delegator_sk=alpha_sk,
            new_subject_did=beta_did,
            previous_aggregate=root_token.signature,
            reduced_verbs=VerbSet({"read", "execute"}),
        )

        # Step 3: Delegation chain
        chain = DelegationChain.from_tokens(
            [root_token, attenuated], is_aggregated=True
        )

        # Step 4: Alice binds Alpha
        source_binding = create_owner_binding(
            agent_did=alpha_did,
            owner_did=alice_did,
            owner_secret_key=alice_sk,
            permissions={Permission.RESOURCE_DELEGATE, Permission.RESOURCE_REQUEST},
        )

        # Step 5: Alice endorses
        endorsement = create_endorsement(
            endorser_did=alice_did,
            endorser_sk=alice_sk,
            target_owner_did=bob_did,
            attenuated_token=attenuated,
            purpose="share model inference access",
        )

        # Step 6: Bob binds Beta
        target_binding = create_owner_binding(
            agent_did=beta_did,
            owner_did=bob_did,
            owner_secret_key=bob_sk,
            permissions={Permission.RESOURCE_REQUEST, Permission.COMM_ACCEPT},
        )

        # Step 7: Bob accepts
        acceptance = create_acceptance(
            acceptor_did=bob_did,
            acceptor_sk=bob_sk,
            attenuated_token=attenuated,
            endorsement=endorsement,
        )

        # Step 8: Create delegation record
        delegation = create_cross_domain_delegation(
            attenuated_token=attenuated,
            delegation_chain=chain,
            source_binding=source_binding,
            endorsement=endorsement,
            target_binding=target_binding,
            acceptance=acceptance,
        )

        # Step 9: Verify
        assert verify_cross_domain_delegation(
            delegation=delegation,
            source_owner_pk=alice_pk,
            target_owner_pk=bob_pk,
            root_issuer_pk=issuer_pk,
            did_resolver=resolver,
        ) is True
        assert len(delegation.delegation_id) == 32

    def test_message_encoding_delegation_request(self) -> None:
        hmac_key = b"k" * 48

        request = DelegationRequest(
            request_id=b"\x01" * 16,
            attenuated_token=b"\x02" * 32,
            delegation_chain=b"\x03" * 64,
            source_binding=b"\x04" * 32,
            endorsement=b"\x05" * 32,
            target_owner_did="did:qasp:bob123",
            target_agent_did="did:qasp:beta456",
        )

        frame = encode_frame(request, hmac_key)
        decoded, consumed = decode_frame(frame, hmac_key)

        assert isinstance(decoded, DelegationRequest)
        assert decoded.request_id == request.request_id
        assert decoded.target_owner_did == "did:qasp:bob123"
        assert decoded.target_agent_did == "did:qasp:beta456"
        assert consumed == len(frame)

    def test_message_encoding_delegation_grant(self) -> None:
        hmac_key = b"k" * 48

        grant = DelegationGrant(
            request_id=b"\x01" * 16,
            acceptance=b"\x02" * 32,
            target_binding=b"\x03" * 32,
            delegation_id=b"\x04" * 32,
            status=0,
            rejection_reason="",
        )

        frame = encode_frame(grant, hmac_key)
        decoded, consumed = decode_frame(frame, hmac_key)

        assert isinstance(decoded, DelegationGrant)
        assert decoded.status == 0
        assert decoded.delegation_id == grant.delegation_id

    def test_message_type_values(self) -> None:
        assert MessageType.DELEGATION_REQUEST == 0x17
        assert MessageType.DELEGATION_GRANT == 0x18


# =============================================================================
# Rejection Scenario
# =============================================================================


class TestRejectionScenario:

    def test_rejection_message(self) -> None:
        hmac_key = b"k" * 48

        grant = DelegationGrant(
            request_id=b"\x01" * 16,
            status=1,
            rejection_reason="Insufficient trust score",
        )

        frame = encode_frame(grant, hmac_key)
        decoded, _ = decode_frame(frame, hmac_key)

        assert isinstance(decoded, DelegationGrant)
        assert decoded.status == 1
        assert decoded.rejection_reason == "Insufficient trust score"


# =============================================================================
# Revocation Cascade
# =============================================================================


class TestRevocationCascade:

    def test_revocation_cascade_cross_domain(self, setup) -> None:
        issuer_did, issuer_pk, issuer_sk = setup["issuer"]
        alice_did, alice_pk, alice_sk = setup["alice"]
        bob_did, bob_pk, bob_sk = setup["bob"]
        alpha_did, alpha_pk, alpha_sk = setup["alpha"]
        beta_did, beta_pk, beta_sk = setup["beta"]

        root_token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_sk,
            subject_did=alpha_did,
            resource_uri="qasp://data/shared",
            verbs={"read"},
            max_delegation_depth=5,
        )

        attenuated, _ = attenuate_token_aggregate(
            parent_token=root_token,
            delegator_sk=alpha_sk,
            new_subject_did=beta_did,
            previous_aggregate=root_token.signature,
        )

        chain = DelegationChain.from_tokens(
            [root_token, attenuated], is_aggregated=True
        )

        source_binding = create_owner_binding(
            agent_did=alpha_did,
            owner_did=alice_did,
            owner_secret_key=alice_sk,
            permissions={Permission.RESOURCE_DELEGATE},
        )
        endorsement = create_endorsement(
            endorser_did=alice_did,
            endorser_sk=alice_sk,
            target_owner_did=bob_did,
            attenuated_token=attenuated,
        )
        target_binding = create_owner_binding(
            agent_did=beta_did,
            owner_did=bob_did,
            owner_secret_key=bob_sk,
            permissions={Permission.RESOURCE_REQUEST},
        )
        acceptance = create_acceptance(
            acceptor_did=bob_did,
            acceptor_sk=bob_sk,
            attenuated_token=attenuated,
            endorsement=endorsement,
        )

        delegation = create_cross_domain_delegation(
            attenuated_token=attenuated,
            delegation_chain=chain,
            source_binding=source_binding,
            endorsement=endorsement,
            target_binding=target_binding,
            acceptance=acceptance,
        )

        # Beta further delegates
        child_pk, child_sk = generate_keypair()
        child_did, _ = create_did(child_pk)
        child_token, _ = attenuate_token_aggregate(
            parent_token=attenuated,
            delegator_sk=beta_sk,
            new_subject_did=child_did,
            previous_aggregate=attenuated.signature,
        )

        crl = CertificateRevocationList()
        crl.register_token(root_token)
        crl.register_token(attenuated)
        crl.register_token(child_token)

        revoked_ids = revoke_cross_domain_delegation(
            delegation=delegation,
            revoker_did=alice_did,
            revoker_sk=alice_sk,
            crl=crl,
            urgency=RevocationUrgency.CRITICAL,
        )

        assert attenuated.token_id in revoked_ids
        assert child_token.token_id in revoked_ids
        assert crl.is_revoked(attenuated.token_id)
        assert crl.is_revoked(child_token.token_id)
        assert not crl.is_revoked(root_token.token_id)
