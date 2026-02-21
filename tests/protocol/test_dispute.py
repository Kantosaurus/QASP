"""Tests for dispute resolution protocol logic."""

from __future__ import annotations

import os

import pytest

from qasp.crypto.signatures import generate_keypair
from qasp.framing.messages import DisputeEvidence, DisputeOpen
from qasp.protocol.dispute import (
    DisputeRecord,
    DisputeState,
    DisputeType,
    EvidenceType,
    InvalidDisputeStateError,
    VerdictCode,
    create_dispute_open,
    create_evidence_submission,
    verify_evidence,
    InvalidEvidenceError,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def submitter_keypair() -> tuple[bytes, bytes]:
    return generate_keypair()


@pytest.fixture
def submitter_public_key(submitter_keypair: tuple[bytes, bytes]) -> bytes:
    return submitter_keypair[0]


@pytest.fixture
def submitter_secret_key(submitter_keypair: tuple[bytes, bytes]) -> bytes:
    return submitter_keypair[1]


@pytest.fixture
def other_keypair() -> tuple[bytes, bytes]:
    return generate_keypair()


@pytest.fixture
def other_public_key(other_keypair: tuple[bytes, bytes]) -> bytes:
    return other_keypair[0]


# =============================================================================
# TestDisputeCreation
# =============================================================================


class TestDisputeCreation:
    """Tests for creating DisputeOpen messages."""

    def test_create_dispute_open(self) -> None:
        """create_dispute_open() builds a valid DisputeOpen message."""
        token_id = os.urandom(32)
        receipt_hash = os.urandom(48)
        msg, dispute_id = create_dispute_open(
            token_id=token_id,
            dispute_type=DisputeType.USAGE_MISMATCH,
            claimed_value=1000,
            receipt_range_hash=receipt_hash,
        )
        assert isinstance(msg, DisputeOpen)
        assert msg.dispute_id == dispute_id
        assert msg.token_id == token_id
        assert msg.dispute_type == DisputeType.USAGE_MISMATCH
        assert msg.claimed_value == 1000
        assert msg.evidence_hash == receipt_hash

    def test_dispute_id_is_random(self) -> None:
        """Each dispute gets a unique ID."""
        _, id1 = create_dispute_open(
            b"tok", DisputeType.OVERCHARGE, 0, b"hash"
        )
        _, id2 = create_dispute_open(
            b"tok", DisputeType.OVERCHARGE, 0, b"hash"
        )
        assert id1 != id2

    def test_all_dispute_types(self) -> None:
        """All dispute types can be used."""
        for dt in DisputeType:
            msg, _ = create_dispute_open(
                b"tok", dt, 100, b"hash"
            )
            assert msg.dispute_type == int(dt)


# =============================================================================
# TestEvidenceSubmission
# =============================================================================


class TestEvidenceSubmission:
    """Tests for evidence creation and verification."""

    def test_create_evidence(
        self,
        submitter_secret_key: bytes,
    ) -> None:
        """create_evidence_submission() returns a signed message."""
        dispute_id = os.urandom(32)
        data = b"receipt chain data"
        msg = create_evidence_submission(
            dispute_id=dispute_id,
            evidence_type=EvidenceType.RECEIPT_CHAIN,
            evidence_data=data,
            submitter_secret_key=submitter_secret_key,
        )
        assert isinstance(msg, DisputeEvidence)
        assert msg.dispute_id == dispute_id
        assert msg.evidence_type == EvidenceType.RECEIPT_CHAIN
        assert msg.evidence_data == data
        assert len(msg.signature) > 0

    def test_verify_evidence_valid(
        self,
        submitter_secret_key: bytes,
        submitter_public_key: bytes,
    ) -> None:
        """verify_evidence() accepts valid signature."""
        msg = create_evidence_submission(
            dispute_id=os.urandom(32),
            evidence_type=EvidenceType.RECEIPT_CHAIN,
            evidence_data=b"evidence",
            submitter_secret_key=submitter_secret_key,
        )
        assert verify_evidence(msg, submitter_public_key)

    def test_verify_evidence_wrong_key(
        self,
        submitter_secret_key: bytes,
        other_public_key: bytes,
    ) -> None:
        """verify_evidence() rejects evidence signed with wrong key."""
        msg = create_evidence_submission(
            dispute_id=os.urandom(32),
            evidence_type=EvidenceType.RECEIPT_CHAIN,
            evidence_data=b"evidence",
            submitter_secret_key=submitter_secret_key,
        )
        with pytest.raises(InvalidEvidenceError):
            verify_evidence(msg, other_public_key)


# =============================================================================
# TestDisputeState
# =============================================================================


class TestDisputeState:
    """Tests for dispute state transitions."""

    def _make_record(self) -> DisputeRecord:
        return DisputeRecord(
            dispute_id=os.urandom(32),
            token_id=os.urandom(32),
            claimant_did="did:qasp:claimant",
            respondent_did="did:qasp:respondent",
            dispute_type=DisputeType.USAGE_MISMATCH,
        )

    def test_initial_state_is_open(self) -> None:
        """New dispute starts in OPEN state."""
        record = self._make_record()
        assert record.state == DisputeState.OPEN

    def test_valid_transitions(self) -> None:
        """Full lifecycle: OPEN -> EVIDENCE -> UNDER_REVIEW -> RESOLVED."""
        record = self._make_record()
        record.transition_to(DisputeState.EVIDENCE_SUBMISSION)
        assert record.state == DisputeState.EVIDENCE_SUBMISSION
        record.transition_to(DisputeState.UNDER_REVIEW)
        assert record.state == DisputeState.UNDER_REVIEW
        record.transition_to(DisputeState.RESOLVED)
        assert record.state == DisputeState.RESOLVED

    def test_invalid_transition_raises(self) -> None:
        """Invalid state transition raises InvalidDisputeStateError."""
        record = self._make_record()
        with pytest.raises(InvalidDisputeStateError):
            record.transition_to(DisputeState.RESOLVED)

    def test_cannot_transition_from_resolved(self) -> None:
        """Cannot transition from RESOLVED."""
        record = self._make_record()
        record.transition_to(DisputeState.EVIDENCE_SUBMISSION)
        record.transition_to(DisputeState.UNDER_REVIEW)
        record.transition_to(DisputeState.RESOLVED)
        with pytest.raises(InvalidDisputeStateError):
            record.transition_to(DisputeState.OPEN)


# =============================================================================
# TestDisputeErrors
# =============================================================================


class TestDisputeErrors:
    """Tests for dispute error conditions."""

    def test_skip_evidence_state(self) -> None:
        """Cannot skip from OPEN directly to UNDER_REVIEW."""
        record = DisputeRecord(
            dispute_id=os.urandom(32),
            token_id=os.urandom(32),
            claimant_did="did:qasp:a",
            respondent_did="did:qasp:b",
            dispute_type=DisputeType.OVERCHARGE,
        )
        with pytest.raises(InvalidDisputeStateError):
            record.transition_to(DisputeState.UNDER_REVIEW)

    def test_verdict_codes(self) -> None:
        """All verdict codes have expected values."""
        assert VerdictCode.CLAIMANT_WINS == 1
        assert VerdictCode.RESPONDENT_WINS == 2
        assert VerdictCode.SPLIT == 3
        assert VerdictCode.DISMISSED == 4

    def test_evidence_types(self) -> None:
        """All evidence types have expected values."""
        assert EvidenceType.RECEIPT_CHAIN == 1
        assert EvidenceType.CAPABILITY_TOKEN == 2
        assert EvidenceType.REPLAY_TRACE == 3
