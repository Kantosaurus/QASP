"""Tests for threshold-signed capability tokens."""

from __future__ import annotations

import pytest

from qasp.crypto.signatures import generate_keypair, verify
from qasp.crypto.threshold import DKGParticipant, DKGResult
from qasp.identity.did import DID, create_did
from qasp.identity.group import create_threshold_group
from qasp.protocol.capability import (
    Constraints,
    VerbSet,
    verify_token,
)
from qasp.protocol.threshold_delegation import (
    ThresholdTokenMetadata,
    attenuate_token_threshold,
    create_threshold_metadata,
    create_threshold_signed_token,
)


def run_dkg(threshold: int, num_participants: int) -> list[DKGResult]:
    """Helper: run a complete DKG ceremony."""
    participants = [
        DKGParticipant(i, threshold, num_participants)
        for i in range(1, num_participants + 1)
    ]
    commitments = [p.round1_generate_commitment() for p in participants]
    all_shares = [p.round2_send_shares(commitments) for p in participants]
    t_values = {p.index: p._t_i for p in participants}

    results = []
    for p in participants:
        my_shares = []
        for sender_shares in all_shares:
            for msg in sender_shares:
                if msg.to_index == p.index:
                    my_shares.append(msg)
        result = p.round3_verify_and_complete(my_shares, t_values)
        results.append(result)
    return results


@pytest.fixture()
def setup_2_of_3():
    """Set up a 2-of-3 threshold group with DKG results."""
    dkg_results = run_dkg(2, 3)

    member_dids = []
    for _ in range(3):
        pk, _sk = generate_keypair()
        did, _doc = create_did(pk)
        member_dids.append(did)

    group = create_threshold_group(dkg_results, member_dids)

    # Subject DID
    sub_pk, sub_sk = generate_keypair()
    subject_did, _ = create_did(sub_pk)

    return group, dkg_results, subject_did, sub_pk, sub_sk


class TestCreateThresholdSignedToken:
    def test_basic_token_creation(self, setup_2_of_3):
        group, dkg_results, subject_did, sub_pk, sub_sk = setup_2_of_3

        token = create_threshold_signed_token(
            group=group,
            dkg_results=[dkg_results[0], dkg_results[2]],
            signer_indices=[1, 3],
            subject_did=subject_did,
            resource_uri="qasp://data/reports",
            verbs={"read"},
        )

        assert token.issuer_did == group.group_did
        assert token.subject_did == subject_did
        assert token.resource_uri == "qasp://data/reports"
        assert "read" in token.verbs.verbs
        assert len(token.signature) == 3309

    def test_token_verifies_with_group_pk(self, setup_2_of_3):
        group, dkg_results, subject_did, sub_pk, sub_sk = setup_2_of_3

        token = create_threshold_signed_token(
            group=group,
            dkg_results=[dkg_results[0], dkg_results[1]],
            signer_indices=[1, 2],
            subject_did=subject_did,
            resource_uri="qasp://data/reports",
            verbs={"read", "write"},
        )

        # verify_token uses the same CBOR encoding + ML-DSA-65 verify
        assert verify_token(token, group.group_public_key, check_expiry=False)

    def test_signature_is_standard_mldsa65(self, setup_2_of_3):
        group, dkg_results, subject_did, sub_pk, sub_sk = setup_2_of_3

        token = create_threshold_signed_token(
            group=group,
            dkg_results=[dkg_results[1], dkg_results[2]],
            signer_indices=[2, 3],
            subject_did=subject_did,
            resource_uri="qasp://data/x",
            verbs={"read"},
        )

        # Direct liboqs verify on the raw signature
        message = token.to_cbor()
        assert verify(group.group_public_key, message, token.signature)

    def test_token_with_constraints(self, setup_2_of_3):
        group, dkg_results, subject_did, sub_pk, sub_sk = setup_2_of_3

        constraints = Constraints(
            quantity_limit=100,
            quantity_unit="tokens",
            purpose="testing",
        )

        token = create_threshold_signed_token(
            group=group,
            dkg_results=[dkg_results[0], dkg_results[2]],
            signer_indices=[1, 3],
            subject_did=subject_did,
            resource_uri="qasp://data/x",
            verbs={"read"},
            constraints=constraints,
        )

        assert token.constraints.quantity_limit == 100
        assert token.constraints.purpose == "testing"
        assert verify_token(token, group.group_public_key, check_expiry=False)

    def test_different_quorums_both_valid(self, setup_2_of_3):
        group, dkg_results, subject_did, sub_pk, sub_sk = setup_2_of_3

        for indices in [[1, 2], [1, 3], [2, 3]]:
            results = [dkg_results[i - 1] for i in indices]
            token = create_threshold_signed_token(
                group=group,
                dkg_results=results,
                signer_indices=indices,
                subject_did=subject_did,
                resource_uri="qasp://data/x",
                verbs={"read"},
            )
            assert verify_token(token, group.group_public_key, check_expiry=False)

    def test_token_with_delegation_depth(self, setup_2_of_3):
        group, dkg_results, subject_did, sub_pk, sub_sk = setup_2_of_3

        token = create_threshold_signed_token(
            group=group,
            dkg_results=[dkg_results[0], dkg_results[1]],
            signer_indices=[1, 2],
            subject_did=subject_did,
            resource_uri="qasp://data/x",
            verbs={"read", "write"},
            max_delegation_depth=2,
        )

        assert token.max_delegation_depth == 2
        assert token.delegation_chain_length == 0
        assert verify_token(token, group.group_public_key, check_expiry=False)


class TestAttenuateTokenThreshold:
    def test_attenuation_by_individual(self, setup_2_of_3):
        """Threshold root token -> individual attenuates -> verify chain."""
        group, dkg_results, subject_did, sub_pk, sub_sk = setup_2_of_3

        # Create root token with delegation allowed
        root = create_threshold_signed_token(
            group=group,
            dkg_results=[dkg_results[0], dkg_results[1]],
            signer_indices=[1, 2],
            subject_did=subject_did,
            resource_uri="qasp://data/reports",
            verbs={"read", "write", "delete"},
            max_delegation_depth=2,
        )

        assert verify_token(root, group.group_public_key, check_expiry=False)

        # Subject attenuates to a new DID using standard attenuate_token
        from qasp.protocol.capability import attenuate_token

        delegate_pk, _delegate_sk = generate_keypair()
        delegate_did, _ = create_did(delegate_pk)

        child = attenuate_token(
            parent_token=root,
            delegator_secret_key=sub_sk,
            new_subject_did=delegate_did,
            reduced_verbs=VerbSet({"read"}),
        )

        assert child.issuer_did == subject_did
        assert child.subject_did == delegate_did
        assert child.delegation_chain_length == 1
        assert verify_token(child, sub_pk, check_expiry=False)


class TestThresholdTokenMetadata:
    def test_metadata_creation(self, setup_2_of_3):
        group, dkg_results, subject_did, sub_pk, sub_sk = setup_2_of_3

        signer_indices = [1, 3]
        token = create_threshold_signed_token(
            group=group,
            dkg_results=[dkg_results[0], dkg_results[2]],
            signer_indices=signer_indices,
            subject_did=subject_did,
            resource_uri="qasp://data/x",
            verbs={"read"},
        )

        meta = create_threshold_metadata(group, signer_indices, token)

        assert isinstance(meta, ThresholdTokenMetadata)
        assert meta.group_did == group.group_did
        assert meta.threshold == 2
        assert meta.num_participants == 3
        assert meta.signer_indices == (1, 3)
        assert len(meta.signer_dids) == 2
        assert meta.token_id == token.token_id
