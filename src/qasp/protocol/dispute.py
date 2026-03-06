"""Dispute resolution protocol logic.

This module implements the dispute resolution subsystem for QASP,
including dispute lifecycle management, evidence handling, and
wire message construction for DisputeOpen (0x0D), DisputeEvidence (0x0E),
and DisputeVerdict (0x0F) messages.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum, IntEnum

from qasp.crypto.signatures import sign, verify
from qasp.framing.messages import DisputeEvidence, DisputeOpen
from qasp.protocol.states import ProtocolError

__all__ = [
    "DisputeError",
    "DisputeNotFoundError",
    "DisputeRecord",
    "DisputeState",
    "DisputeType",
    "DuplicateDisputeError",
    "EvidencePackage",
    "EvidenceType",
    "InvalidDisputeStateError",
    "InvalidEvidenceError",
    "VerdictCode",
    "create_dispute_open",
    "create_evidence_submission",
    "verify_evidence",
]


# =============================================================================
# Enums
# =============================================================================


class DisputeType(IntEnum):
    """Types of disputes that can be opened."""

    USAGE_MISMATCH = 1
    OVERCHARGE = 2
    UNAUTHORIZED_ACCESS = 3
    SERVICE_FAILURE = 4
    RECONCILIATION_FAILURE = 5


class VerdictCode(IntEnum):
    """Possible verdict outcomes."""

    CLAIMANT_WINS = 1
    RESPONDENT_WINS = 2
    SPLIT = 3
    DISMISSED = 4


class EvidenceType(IntEnum):
    """Types of evidence that can be submitted."""

    RECEIPT_CHAIN = 1
    CAPABILITY_TOKEN = 2
    REPLAY_TRACE = 3


class DisputeState(Enum):
    """Lifecycle states of a dispute."""

    OPEN = "open"
    EVIDENCE_SUBMISSION = "evidence_submission"
    UNDER_REVIEW = "under_review"
    RESOLVED = "resolved"


# Valid state transitions
_VALID_DISPUTE_TRANSITIONS: dict[DisputeState, frozenset[DisputeState]] = {
    DisputeState.OPEN: frozenset({DisputeState.EVIDENCE_SUBMISSION}),
    DisputeState.EVIDENCE_SUBMISSION: frozenset({DisputeState.UNDER_REVIEW}),
    DisputeState.UNDER_REVIEW: frozenset({DisputeState.RESOLVED}),
    DisputeState.RESOLVED: frozenset(),
}


# =============================================================================
# Exception Hierarchy
# =============================================================================


class DisputeError(ProtocolError):
    """Base exception for dispute errors."""


class InvalidDisputeStateError(DisputeError):
    """Raised when a dispute operation is invalid for the current state."""

    def __init__(self, current: DisputeState, target: DisputeState) -> None:
        self.current_state = current
        self.target_state = target
        super().__init__(
            f"Invalid state transition: {current.value} -> {target.value}"
        )


class DisputeNotFoundError(DisputeError):
    """Raised when a dispute cannot be found."""


class InvalidEvidenceError(DisputeError):
    """Raised when evidence is invalid."""


class DuplicateDisputeError(DisputeError):
    """Raised when attempting to create a duplicate dispute."""


# =============================================================================
# Data Classes
# =============================================================================


@dataclass(frozen=True)
class EvidencePackage:
    """A signed evidence submission."""

    evidence_type: EvidenceType
    data: bytes
    submitter_did: str
    timestamp: datetime
    signature: bytes


@dataclass
class DisputeRecord:
    """Tracks the full lifecycle of a dispute."""

    dispute_id: bytes
    token_id: bytes
    claimant_did: str
    respondent_did: str
    dispute_type: DisputeType
    state: DisputeState = DisputeState.OPEN
    claimed_value: int = 0
    evidence: list[EvidencePackage] = field(default_factory=list)
    opened_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    resolved_at: datetime | None = None
    verdict: VerdictCode | None = None
    reconciliation_attempted: bool = False
    agent_chain_cbor: bytes = b""
    server_chain_cbor: bytes = b""
    divergence_point_seq: int = 0
    trace_entries: list[bytes] = field(default_factory=list)
    fault_attribution: str = ""

    def transition_to(self, new_state: DisputeState) -> None:
        """Transition to a new state, validating the transition.

        Raises:
            InvalidDisputeStateError: If the transition is not valid.
        """
        valid = _VALID_DISPUTE_TRANSITIONS.get(self.state, frozenset())
        if new_state not in valid:
            raise InvalidDisputeStateError(self.state, new_state)
        self.state = new_state


# =============================================================================
# Wire Message Construction
# =============================================================================


def create_dispute_open(
    token_id: bytes,
    dispute_type: DisputeType,
    claimed_value: int,
    receipt_range_hash: bytes,
    *,
    agent_chain_cbor: bytes = b"",
    server_chain_cbor: bytes = b"",
    divergence_point_seq: int = 0,
) -> tuple[DisputeOpen, bytes]:
    """Build a DisputeOpen wire message.

    Args:
        token_id: The token related to the dispute.
        dispute_type: Type of dispute.
        claimed_value: Value claimed by the disputant.
        receipt_range_hash: SHA-384 hash of the receipt range.
        agent_chain_cbor: Agent's CBOR receipt chain (stored on record, not wire).
        server_chain_cbor: Server's CBOR receipt chain (stored on record, not wire).
        divergence_point_seq: First disagreeing receipt sequence number.

    Returns:
        Tuple of (DisputeOpen message, dispute_id).
    """
    _ = agent_chain_cbor, server_chain_cbor, divergence_point_seq  # stored on record
    dispute_id = os.urandom(32)
    msg = DisputeOpen(
        dispute_id=dispute_id,
        token_id=token_id,
        dispute_type=int(dispute_type),
        claimed_value=claimed_value,
        evidence_hash=receipt_range_hash,
    )
    return msg, dispute_id


def create_evidence_submission(
    dispute_id: bytes,
    evidence_type: EvidenceType,
    evidence_data: bytes,
    submitter_secret_key: bytes,
) -> DisputeEvidence:
    """Build a DisputeEvidence wire message with signed evidence.

    Args:
        dispute_id: The dispute to submit evidence for.
        evidence_type: Type of evidence.
        evidence_data: Raw evidence data.
        submitter_secret_key: ML-DSA-65 secret key for signing.

    Returns:
        A signed DisputeEvidence message.
    """
    sig = sign(submitter_secret_key, evidence_data)
    return DisputeEvidence(
        dispute_id=dispute_id,
        evidence_type=int(evidence_type),
        evidence_data=evidence_data,
        signature=sig,
    )


def verify_evidence(
    evidence: DisputeEvidence,
    submitter_public_key: bytes,
) -> bool:
    """Verify the ML-DSA-65 signature on a DisputeEvidence message.

    Args:
        evidence: The evidence message to verify.
        submitter_public_key: The submitter's public key.

    Returns:
        True if the signature is valid.

    Raises:
        InvalidEvidenceError: If verification fails.
    """
    try:
        return verify(submitter_public_key, evidence.evidence_data, evidence.signature)
    except Exception as e:
        raise InvalidEvidenceError(f"Evidence signature verification failed: {e}") from e
