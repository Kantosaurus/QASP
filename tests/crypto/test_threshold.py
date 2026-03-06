"""Tests for DKG protocol and threshold signing."""

from __future__ import annotations

import pytest

from qasp.crypto.exceptions import (
    DKGCommitmentMismatchError,
    DKGProtocolError,
    ThresholdConfigError,
    ThresholdSigningError,
)
from qasp.crypto.threshold import (
    DKGParticipant,
    DKGResult,
    DKGState,
    SigningState,
    ThresholdCoordinator,
    ThresholdSigner,
    threshold_sign_with_retry,
)


def run_dkg(threshold: int, num_participants: int) -> list[DKGResult]:
    """Helper: run a complete DKG ceremony."""
    participants = [
        DKGParticipant(i, threshold, num_participants)
        for i in range(1, num_participants + 1)
    ]

    # Round 1
    commitments = [p.round1_generate_commitment() for p in participants]

    # Round 2
    all_shares = [p.round2_send_shares(commitments) for p in participants]

    # Collect t values from each participant
    t_values = {p.index: p._t_i for p in participants}

    # Round 3: Each participant gets shares from all others
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


class TestDKGConfig:
    def test_threshold_too_small(self):
        with pytest.raises(ThresholdConfigError, match="Threshold must be >= 2"):
            DKGParticipant(1, threshold=1, num_participants=3)

    def test_num_participants_less_than_threshold(self):
        with pytest.raises(ThresholdConfigError):
            DKGParticipant(1, threshold=4, num_participants=3)

    def test_index_out_of_range(self):
        with pytest.raises(ThresholdConfigError):
            DKGParticipant(0, threshold=2, num_participants=3)
        with pytest.raises(ThresholdConfigError):
            DKGParticipant(4, threshold=2, num_participants=3)


class TestDKGProtocol:
    def test_2_of_3_dkg(self):
        """All participants should derive the same group public key."""
        results = run_dkg(2, 3)
        assert len(results) == 3
        # All should have same group pk
        pk = results[0].group_public_key
        assert len(pk) == 1952
        for r in results[1:]:
            assert r.group_public_key == pk

    def test_3_of_5_dkg(self):
        results = run_dkg(3, 5)
        pk = results[0].group_public_key
        for r in results[1:]:
            assert r.group_public_key == pk

    def test_dkg_same_rho(self):
        results = run_dkg(2, 3)
        rho = results[0].group_rho
        for r in results[1:]:
            assert r.group_rho == rho

    def test_dkg_same_tr(self):
        results = run_dkg(2, 3)
        tr = results[0].group_tr
        for r in results[1:]:
            assert r.group_tr == tr

    def test_state_machine_enforcement(self):
        p = DKGParticipant(1, 2, 3)
        # Can't do round2 before round1
        with pytest.raises(DKGProtocolError, match="COMMITTED"):
            p.round2_send_shares([])

    def test_commitment_mismatch(self):
        p1 = DKGParticipant(1, 2, 2)
        p2 = DKGParticipant(2, 2, 2)
        c1 = p1.round1_generate_commitment()
        c2 = p2.round1_generate_commitment()
        # Tamper with c2's commitment hash
        from dataclasses import replace
        tampered = replace(c2, commitment_hash=b"\x00" * 48)
        with pytest.raises(DKGCommitmentMismatchError):
            p1.round2_send_shares([c1, tampered])


class TestThresholdSigning:
    def test_2_of_3_sign_and_verify(self):
        """Threshold signature should verify with liboqs."""
        results = run_dkg(2, 3)
        message = b"test message for threshold signing"

        # Pick 2 of 3 signers
        signer_indices = [1, 3]
        signers = []
        for idx in signer_indices:
            r = results[idx - 1]
            signers.append(ThresholdSigner(r, message, signer_indices))

        coordinator = ThresholdCoordinator(
            group_public_key=results[0].group_public_key,
            group_t=results[0].group_t,
            group_t0=results[0].group_t0,
            group_t1=results[0].group_t1,
            group_tr=results[0].group_tr,
            group_rho=results[0].group_rho,
            signer_indices=signer_indices,
        )

        sig = threshold_sign_with_retry(signers, coordinator, message)
        assert sig is not None
        assert len(sig.signature) == 3309
        assert set(sig.signer_indices) == set(signer_indices)

        # Verify with liboqs
        from qasp.crypto.signatures import verify
        assert verify(results[0].group_public_key, message, sig.signature)

    def test_different_quorums_same_key(self):
        """Different signer subsets should all produce valid signatures."""
        results = run_dkg(2, 3)
        message = b"quorum test"

        for signer_indices in [[1, 2], [1, 3], [2, 3]]:
            signers = [
                ThresholdSigner(results[i - 1], message, signer_indices)
                for i in signer_indices
            ]
            coordinator = ThresholdCoordinator(
                group_public_key=results[0].group_public_key,
                group_t=results[0].group_t,
                group_t0=results[0].group_t0,
                group_t1=results[0].group_t1,
                group_tr=results[0].group_tr,
                group_rho=results[0].group_rho,
                signer_indices=signer_indices,
            )
            sig = threshold_sign_with_retry(signers, coordinator, message)
            assert sig is not None
            from qasp.crypto.signatures import verify
            assert verify(results[0].group_public_key, message, sig.signature)

    def test_insufficient_signers(self):
        results = run_dkg(3, 5)
        with pytest.raises(ThresholdSigningError, match="Need at least"):
            ThresholdSigner(results[0], b"msg", [1, 2])  # Only 2, need 3

    def test_signer_not_in_set(self):
        results = run_dkg(2, 3)
        with pytest.raises(ThresholdSigningError, match="not in signer set"):
            ThresholdSigner(results[0], b"msg", [2, 3])  # index 1 not in {2,3}

    def test_signing_state_machine(self):
        results = run_dkg(2, 3)
        signer = ThresholdSigner(results[0], b"msg", [1, 2])
        # Can't do round2 before round1
        with pytest.raises(ThresholdSigningError, match="COMMITTED"):
            signer.round2_open([])
