"""Divergence detection and reconciliation protocol.

This module implements the pre-dispute reconciliation subsystem for QASP:
- DivergenceDetector: stateless helper for comparing agent vs server costs
- ReconciliationSession: sans-I/O FSM for the reconciliation exchange
- Auto-resolution logic (higher-seq-wins, use-average, agreed, failed)

Reconciliation is a separate FSM from the dispute system. It runs during a
60-second grace period before escalating to a formal dispute.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, IntEnum

import cbor2

from qasp.crypto.signatures import sign, verify
from qasp.framing.messages import ReconciliationRequest, ReconciliationResponse
from qasp.protocol.accounting import Receipt, ReceiptChain
from qasp.protocol.events import (
    Event,
    ReconciliationFailed,
    ReconciliationStarted,
    ReconciliationSucceeded,
)
from qasp.protocol.states import ProtocolError

__all__ = [
    "DEFAULT_TOLERANCE_FLOOR",
    "DEFAULT_TOLERANCE_PERCENT",
    "GRACE_PERIOD_SECONDS",
    "MAX_EVIDENCE_SIZE_BYTES",
    "MAX_RECEIPT_RANGE",
    "MAX_TRACE_ENTRIES_PER_TOKEN",
    "DivergenceDetector",
    "ReconciliationBoundsError",
    "ReconciliationError",
    "ReconciliationSession",
    "ReconciliationState",
    "ReconciliationTimeoutError",
    "ResolutionMethod",
]

# =============================================================================
# Constants
# =============================================================================

GRACE_PERIOD_SECONDS = 60
DEFAULT_TOLERANCE_PERCENT = 0.01  # 1%
DEFAULT_TOLERANCE_FLOOR = 1  # minimum absolute tolerance
MAX_RECEIPT_RANGE = 100
MAX_TRACE_ENTRIES_PER_TOKEN = 50
MAX_EVIDENCE_SIZE_BYTES = 1_048_576  # 1 MiB


# =============================================================================
# Exceptions
# =============================================================================


class ReconciliationError(ProtocolError):
    """Base exception for reconciliation errors."""


class ReconciliationTimeoutError(ReconciliationError):
    """Raised when the reconciliation grace period has expired."""


class ReconciliationBoundsError(ReconciliationError):
    """Raised when receipt range or evidence size exceeds bounds."""


# =============================================================================
# Enums
# =============================================================================


class ReconciliationState(Enum):
    """States of a reconciliation session."""

    IDLE = "idle"
    REQUESTED = "requested"
    CHAIN_EXCHANGE = "chain_exchange"
    AUTO_RESOLVED = "auto_resolved"
    FAILED = "failed"


class ResolutionMethod(IntEnum):
    """Methods for auto-resolving a metering divergence."""

    AGREED = 0
    HIGHER_SEQ_WINS = 1
    USE_AVERAGE = 2
    FAILED = 3


# =============================================================================
# DivergenceDetector
# =============================================================================


class DivergenceDetector:
    """Stateless helper for detecting metering divergences.

    Compares a reported cost against a locally tracked cost using
    a percentage-based tolerance with an absolute floor.
    """

    def __init__(
        self,
        tolerance_percent: float = DEFAULT_TOLERANCE_PERCENT,
        tolerance_floor: int = DEFAULT_TOLERANCE_FLOOR,
    ) -> None:
        self._tolerance_percent = tolerance_percent
        self._tolerance_floor = tolerance_floor

    def compute_tolerance(self, total_cost: int) -> int:
        """Compute the tolerance threshold for a given total cost.

        Returns:
            max(percent * total_cost, floor), rounded to int.
        """
        return max(int(self._tolerance_percent * total_cost), self._tolerance_floor)

    def check(
        self, reported_cost: int, local_cost: int,
    ) -> tuple[bool, int]:
        """Check if reported and local costs diverge beyond tolerance.

        Returns:
            (diverged, tolerance) — True if |reported - local| > tolerance.
        """
        tolerance = self.compute_tolerance(max(reported_cost, local_cost))
        difference = abs(reported_cost - local_cost)
        return difference > tolerance, tolerance


# =============================================================================
# CBOR helpers
# =============================================================================


def _encode_reconciliation_request_data(
    meter_id: bytes,
    start_seq: int,
    end_seq: int,
    chain_cbor: bytes,
    detected_cost_diff: int,
    timestamp: int,
) -> bytes:
    """CBOR-encode ReconciliationRequest fields for signing."""
    return cbor2.dumps({
        "meter_id": meter_id,
        "start_seq": start_seq,
        "end_seq": end_seq,
        "chain_cbor": chain_cbor,
        "detected_cost_diff": detected_cost_diff,
        "timestamp": timestamp,
    })


def _encode_reconciliation_response_data(
    meter_id: bytes,
    start_seq: int,
    end_seq: int,
    chain_cbor: bytes,
    resolution: int,
    agreed_cost: int,
    timestamp: int,
) -> bytes:
    """CBOR-encode ReconciliationResponse fields for signing."""
    return cbor2.dumps({
        "meter_id": meter_id,
        "start_seq": start_seq,
        "end_seq": end_seq,
        "chain_cbor": chain_cbor,
        "resolution": resolution,
        "agreed_cost": agreed_cost,
        "timestamp": timestamp,
    })


# =============================================================================
# ReconciliationSession
# =============================================================================


class ReconciliationSession:
    """Sans-I/O per-meter reconciliation session.

    Manages the reconciliation exchange between agent and server,
    with a grace period timeout and auto-resolution logic.
    """

    def __init__(
        self,
        meter_id: bytes,
        signing_key: bytes,
        local_chain: ReceiptChain | None = None,
        created_at: float | None = None,
    ) -> None:
        self._meter_id = meter_id
        self._signing_key = signing_key
        self._local_chain = local_chain or ReceiptChain()
        self._state = ReconciliationState.IDLE
        self._created_at = created_at if created_at is not None else time.time()
        self._agreed_cost: int | None = None
        self._resolution: ResolutionMethod | None = None

    @property
    def state(self) -> ReconciliationState:
        return self._state

    @property
    def meter_id(self) -> bytes:
        return self._meter_id

    @property
    def agreed_cost(self) -> int | None:
        return self._agreed_cost

    @property
    def resolution(self) -> ResolutionMethod | None:
        return self._resolution

    def is_expired(self, current_time: float | None = None) -> bool:
        """Check if the grace period has expired."""
        now = current_time if current_time is not None else time.time()
        return (now - self._created_at) >= GRACE_PERIOD_SECONDS

    def create_request(
        self,
        start_seq: int,
        end_seq: int,
        detected_cost_diff: int,
    ) -> tuple[ReconciliationRequest, list[Event]]:
        """Create a reconciliation request (agent-side).

        Raises:
            ReconciliationError: If not in IDLE state.
            ReconciliationBoundsError: If receipt range exceeds MAX_RECEIPT_RANGE.
        """
        if self._state != ReconciliationState.IDLE:
            raise ReconciliationError(
                f"Cannot create request in state {self._state.value}"
            )
        if end_seq - start_seq + 1 > MAX_RECEIPT_RANGE:
            raise ReconciliationBoundsError(
                f"Receipt range {end_seq - start_seq + 1} exceeds "
                f"maximum {MAX_RECEIPT_RANGE}"
            )

        chain_cbor = self._local_chain.to_cbor()
        if len(chain_cbor) > MAX_EVIDENCE_SIZE_BYTES:
            raise ReconciliationBoundsError(
                f"Chain CBOR size {len(chain_cbor)} exceeds "
                f"maximum {MAX_EVIDENCE_SIZE_BYTES}"
            )

        timestamp = int(time.time())
        data = _encode_reconciliation_request_data(
            self._meter_id, start_seq, end_seq,
            chain_cbor, detected_cost_diff, timestamp,
        )
        sig = sign(self._signing_key, data)

        request = ReconciliationRequest(
            meter_id=self._meter_id,
            start_seq=start_seq,
            end_seq=end_seq,
            chain_cbor=chain_cbor,
            detected_cost_diff=detected_cost_diff,
            timestamp=timestamp,
            signature=sig,
        )
        self._state = ReconciliationState.REQUESTED

        events: list[Event] = [
            ReconciliationStarted(
                meter_id=self._meter_id,
                start_seq=start_seq,
                end_seq=end_seq,
            )
        ]
        return request, events

    def process_request(
        self,
        request: ReconciliationRequest,
        peer_public_key: bytes,
    ) -> tuple[ReconciliationResponse, list[Event]]:
        """Process a reconciliation request (server-side).

        Verifies the request signature, compares chains, and
        attempts auto-resolution.

        Raises:
            ReconciliationError: If signature verification fails.
            ReconciliationTimeoutError: If the session has expired.
        """
        if self.is_expired():
            raise ReconciliationTimeoutError("Reconciliation grace period expired")

        # Verify request signature
        data = _encode_reconciliation_request_data(
            request.meter_id, request.start_seq, request.end_seq,
            request.chain_cbor, request.detected_cost_diff, request.timestamp,
        )
        try:
            verify(peer_public_key, data, request.signature)
        except Exception as e:
            raise ReconciliationError(
                f"Reconciliation request signature invalid: {e}"
            ) from e

        self._state = ReconciliationState.CHAIN_EXCHANGE

        # Deserialize peer chain
        peer_chain = ReceiptChain.from_cbor(request.chain_cbor)

        # Attempt auto-resolution
        method, agreed_cost = self._attempt_auto_resolution(
            self._local_chain, peer_chain,
        )

        if method == ResolutionMethod.FAILED:
            self._state = ReconciliationState.FAILED
        else:
            self._state = ReconciliationState.AUTO_RESOLVED
            self._agreed_cost = agreed_cost
            self._resolution = method

        # Build response
        local_chain_cbor = self._local_chain.to_cbor()
        timestamp = int(time.time())
        resp_data = _encode_reconciliation_response_data(
            request.meter_id, request.start_seq, request.end_seq,
            local_chain_cbor, int(method), agreed_cost, timestamp,
        )
        sig = sign(self._signing_key, resp_data)

        response = ReconciliationResponse(
            meter_id=request.meter_id,
            start_seq=request.start_seq,
            end_seq=request.end_seq,
            chain_cbor=local_chain_cbor,
            resolution=int(method),
            agreed_cost=agreed_cost,
            timestamp=timestamp,
            signature=sig,
        )

        events: list[Event] = []
        if method == ResolutionMethod.FAILED:
            events.append(ReconciliationFailed(
                meter_id=request.meter_id,
                reason="Auto-resolution failed: too many discrepancies or large diff",
            ))
        else:
            events.append(ReconciliationSucceeded(
                meter_id=request.meter_id,
                resolution_method=int(method),
                agreed_cost=agreed_cost,
            ))

        return response, events

    def process_response(
        self,
        response: ReconciliationResponse,
        peer_public_key: bytes,
    ) -> tuple[bool, list[Event]]:
        """Process a reconciliation response (agent-side).

        Returns:
            (resolved, events) — True if reconciliation succeeded.

        Raises:
            ReconciliationError: If not in REQUESTED state or sig invalid.
            ReconciliationTimeoutError: If the session has expired.
        """
        if self._state != ReconciliationState.REQUESTED:
            raise ReconciliationError(
                f"Cannot process response in state {self._state.value}"
            )
        if self.is_expired():
            raise ReconciliationTimeoutError("Reconciliation grace period expired")

        # Verify response signature
        data = _encode_reconciliation_response_data(
            response.meter_id, response.start_seq, response.end_seq,
            response.chain_cbor, response.resolution, response.agreed_cost,
            response.timestamp,
        )
        try:
            verify(peer_public_key, data, response.signature)
        except Exception as e:
            raise ReconciliationError(
                f"Reconciliation response signature invalid: {e}"
            ) from e

        method = ResolutionMethod(response.resolution)
        events: list[Event] = []

        if method == ResolutionMethod.FAILED:
            self._state = ReconciliationState.FAILED
            events.append(ReconciliationFailed(
                meter_id=response.meter_id,
                reason="Server could not auto-resolve",
            ))
            return False, events

        self._state = ReconciliationState.AUTO_RESOLVED
        self._agreed_cost = response.agreed_cost
        self._resolution = method
        events.append(ReconciliationSucceeded(
            meter_id=response.meter_id,
            resolution_method=int(method),
            agreed_cost=response.agreed_cost,
        ))
        return True, events

    def _attempt_auto_resolution(
        self,
        local_chain: ReceiptChain,
        peer_chain: ReceiptChain,
    ) -> tuple[ResolutionMethod, int]:
        """Compare local and peer receipt chains and attempt auto-resolution.

        Resolution rules:
        1. If chains match exactly -> AGREED
        2. If only the last receipt differs -> HIGHER_SEQ_WINS
        3. If total difference <= tolerance -> USE_AVERAGE
        4. If >1 divergence point or diff too large -> FAILED

        Returns:
            (method, agreed_cost)
        """
        local_receipts = local_chain.receipts
        peer_receipts = peer_chain.receipts

        if not local_receipts and not peer_receipts:
            return ResolutionMethod.AGREED, 0

        # Build sequence -> receipt maps
        local_by_seq = {r.sequence_number: r for r in local_receipts}
        peer_by_seq = {r.sequence_number: r for r in peer_receipts}
        all_seqs = sorted(set(local_by_seq.keys()) | set(peer_by_seq.keys()))

        # Find discrepancies
        discrepancies: list[tuple[int, int, int]] = []
        for seq in all_seqs:
            local_cost = local_by_seq[seq].total_cost if seq in local_by_seq else 0
            peer_cost = peer_by_seq[seq].total_cost if seq in peer_by_seq else 0
            if local_cost != peer_cost:
                discrepancies.append((seq, local_cost, peer_cost))

        if not discrepancies:
            # Chains agree — use local total
            total_cost = local_receipts[-1].total_cost if local_receipts else 0
            return ResolutionMethod.AGREED, total_cost

        if len(discrepancies) == 1:
            seq, local_cost, peer_cost = discrepancies[0]
            max_seq = max(all_seqs)
            if seq == max_seq:
                # Only last receipt differs -> higher sequence wins
                # Take the receipt from the chain with the higher last seq
                local_max = max(local_by_seq.keys()) if local_by_seq else 0
                peer_max = max(peer_by_seq.keys()) if peer_by_seq else 0
                if local_max >= peer_max:
                    return ResolutionMethod.HIGHER_SEQ_WINS, local_cost
                return ResolutionMethod.HIGHER_SEQ_WINS, peer_cost

        # Check if total difference is within tolerance
        total_local = local_receipts[-1].total_cost if local_receipts else 0
        total_peer = peer_receipts[-1].total_cost if peer_receipts else 0
        total_diff = abs(total_local - total_peer)
        detector = DivergenceDetector()
        tolerance = detector.compute_tolerance(max(total_local, total_peer))

        if total_diff <= tolerance:
            avg = (total_local + total_peer) // 2
            return ResolutionMethod.USE_AVERAGE, avg

        return ResolutionMethod.FAILED, 0
