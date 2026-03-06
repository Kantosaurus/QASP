"""Tests for threshold group DID."""

from __future__ import annotations

import pytest

from qasp.crypto.threshold import DKGParticipant, DKGResult
from qasp.identity.did import DID, DIDDocument, DIDRegistry, create_did
from qasp.identity.exceptions import ThresholdGroupError
from qasp.identity.group import (
    THRESHOLD_POLICY_SERVICE_TYPE,
    ThresholdGroup,
    create_threshold_group,
    get_threshold_policy,
    is_threshold_did,
    register_threshold_group,
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
def dkg_results_2_of_3():
    return run_dkg(2, 3)


@pytest.fixture()
def member_dids():
    """Create 3 member DIDs from random keys."""
    from qasp.crypto.signatures import generate_keypair

    dids = []
    for _ in range(3):
        pk, _sk = generate_keypair()
        did, _doc = create_did(pk)
        dids.append(did)
    return dids


class TestCreateThresholdGroup:
    def test_basic_creation(self, dkg_results_2_of_3, member_dids):
        group = create_threshold_group(dkg_results_2_of_3, member_dids)

        assert isinstance(group, ThresholdGroup)
        assert group.threshold == 2
        assert group.num_participants == 3
        assert len(group.member_dids) == 3
        assert len(group.member_indices) == 3
        assert group.group_public_key == dkg_results_2_of_3[0].group_public_key
        assert len(group.group_public_key) == 1952

    def test_group_did_derives_from_combined_pk(self, dkg_results_2_of_3, member_dids):
        group = create_threshold_group(dkg_results_2_of_3, member_dids)

        # Group DID should verify against the combined public key
        assert group.group_did.verify_key(group.group_public_key)

    def test_group_did_document_has_threshold_policy(self, dkg_results_2_of_3, member_dids):
        group = create_threshold_group(dkg_results_2_of_3, member_dids)

        assert THRESHOLD_POLICY_SERVICE_TYPE in group.group_did_document.service_endpoints
        endpoint = group.group_did_document.service_endpoints[THRESHOLD_POLICY_SERVICE_TYPE]
        assert endpoint == "2-of-3"

    def test_member_indices_mapping(self, dkg_results_2_of_3, member_dids):
        group = create_threshold_group(dkg_results_2_of_3, member_dids)

        for i, did in enumerate(member_dids):
            assert group.member_indices[str(did)] == i + 1

    def test_no_dkg_results(self, member_dids):
        with pytest.raises(ThresholdGroupError, match="No DKG results"):
            create_threshold_group([], member_dids)

    def test_mismatched_dids_count(self, dkg_results_2_of_3):
        from qasp.crypto.signatures import generate_keypair

        pk, _ = generate_keypair()
        did, _ = create_did(pk)
        with pytest.raises(ThresholdGroupError, match="must match"):
            create_threshold_group(dkg_results_2_of_3, [did, did])

    def test_inconsistent_dkg_results(self, dkg_results_2_of_3, member_dids):
        # Run a second independent DKG to get a different group key
        other_results = run_dkg(2, 3)

        # Mix results from different DKG ceremonies
        mixed = [dkg_results_2_of_3[0], other_results[1], dkg_results_2_of_3[2]]
        with pytest.raises(ThresholdGroupError, match="different group public key"):
            create_threshold_group(mixed, member_dids)


class TestRegisterThresholdGroup:
    def test_register_and_lookup(self, dkg_results_2_of_3, member_dids):
        group = create_threshold_group(dkg_results_2_of_3, member_dids)
        registry = DIDRegistry()

        register_threshold_group(group, registry)

        doc = registry.lookup(group.group_did)
        assert doc.did == group.group_did
        assert doc.get_public_key() == group.group_public_key


class TestIsThresholdDid:
    def test_threshold_did_returns_true(self, dkg_results_2_of_3, member_dids):
        group = create_threshold_group(dkg_results_2_of_3, member_dids)
        assert is_threshold_did(group.group_did_document) is True

    def test_regular_did_returns_false(self):
        from qasp.crypto.signatures import generate_keypair

        pk, _ = generate_keypair()
        _, doc = create_did(pk)
        assert is_threshold_did(doc) is False


class TestGetThresholdPolicy:
    def test_returns_policy(self, dkg_results_2_of_3, member_dids):
        group = create_threshold_group(dkg_results_2_of_3, member_dids)
        policy = get_threshold_policy(group.group_did_document)
        assert policy == (2, 3)

    def test_returns_none_for_regular_did(self):
        from qasp.crypto.signatures import generate_keypair

        pk, _ = generate_keypair()
        _, doc = create_did(pk)
        assert get_threshold_policy(doc) is None

    def test_malformed_endpoint(self):
        from qasp.crypto.signatures import generate_keypair

        pk, _ = generate_keypair()
        did, _ = create_did(pk)
        doc = DIDDocument(
            did=did,
            service_endpoints={THRESHOLD_POLICY_SERVICE_TYPE: "bad-format"},
        )
        assert get_threshold_policy(doc) is None
