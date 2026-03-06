"""Tests for divergence detection and reconciliation protocol."""

from __future__ import annotations

import os
import time

import pytest

from qasp.crypto.signatures import generate_keypair, sign
from qasp.protocol.accounting import Meter, Receipt, ReceiptChain
from qasp.protocol.events import (
    DivergenceDetected,
    MeterReportReceived,
    ReconciliationFailed,
    ReconciliationStarted,
    ReconciliationSucceeded,
)
from qasp.protocol.reconciliation import (
    DEFAULT_TOLERANCE_FLOOR,
    DEFAULT_TOLERANCE_PERCENT,
    GRACE_PERIOD_SECONDS,
    MAX_RECEIPT_RANGE,
    DivergenceDetector,
    ReconciliationBoundsError,
    ReconciliationError,
    ReconciliationSession,
    ReconciliationState,
    ReconciliationTimeoutError,
    ResolutionMethod,
)


# =============================================================================
# Helpers
# =============================================================================


def _make_receipt(
    signing_key: bytes,
    meter_id: bytes,
    seq: int,
    total_units: int,
    total_cost: int,
    prev_hash: bytes = b"",
) -> Receipt:
    """Create a signed receipt for testing."""
    from datetime import UTC, datetime

    receipt = Receipt(
        records=[],
        total_units=total_units,
        total_cost=total_cost,
        issued_at=datetime.now(UTC),
        issuer="test",
        signature=b"",
        sequence_number=seq,
        prev_hash=prev_hash,
        meter_id=meter_id,
    )
    sig = sign(signing_key, receipt.signable_bytes())
    return Receipt(
        records=receipt.records,
        total_units=receipt.total_units,
        total_cost=receipt.total_cost,
        issued_at=receipt.issued_at,
        issuer=receipt.issuer,
        signature=sig,
        sequence_number=receipt.sequence_number,
        prev_hash=receipt.prev_hash,
        meter_id=receipt.meter_id,
    )


def _build_chain(signing_key: bytes, meter_id: bytes, costs: list[int]) -> ReceiptChain:
    """Build a receipt chain with the given per-receipt total_cost values."""
    chain = ReceiptChain()
    prev_hash = b""
    for i, cost in enumerate(costs, start=1):
        receipt = _make_receipt(signing_key, meter_id, i, cost, cost, prev_hash)
        chain.append(receipt)
        prev_hash = receipt.compute_hash()
    return chain


# =============================================================================
# TestDivergenceDetector
# =============================================================================


class TestDivergenceDetector:
    """Tests for DivergenceDetector."""

    def test_tolerance_computation_percentage(self) -> None:
        """Percentage-based tolerance for large costs."""
        d = DivergenceDetector()
        # 1% of 1000 = 10, which is > floor of 1
        assert d.compute_tolerance(1000) == 10

    def test_tolerance_computation_floor(self) -> None:
        """Floor used when percentage is too small."""
        d = DivergenceDetector()
        # 1% of 50 = 0 (int), falls back to floor of 1
        assert d.compute_tolerance(50) == DEFAULT_TOLERANCE_FLOOR

    def test_tolerance_zero_cost(self) -> None:
        """Zero cost returns the floor."""
        d = DivergenceDetector()
        assert d.compute_tolerance(0) == DEFAULT_TOLERANCE_FLOOR

    def test_no_divergence_within_tolerance(self) -> None:
        """No divergence when difference is within tolerance."""
        d = DivergenceDetector()
        diverged, tolerance = d.check(1000, 1005)
        # tolerance = 10 (1% of 1005), diff = 5 <= 10
        assert not diverged
        assert tolerance == 10

    def test_divergence_beyond_tolerance(self) -> None:
        """Divergence detected when difference exceeds tolerance."""
        d = DivergenceDetector()
        diverged, tolerance = d.check(1000, 1020)
        # tolerance = 10 (1% of 1020), diff = 20 > 10
        assert diverged

    def test_exact_boundary_not_diverged(self) -> None:
        """Difference exactly equal to tolerance is not diverged."""
        d = DivergenceDetector(tolerance_percent=0.1, tolerance_floor=1)
        # 10% of 100 = 10, diff = 10, not diverged (need >)
        diverged, _ = d.check(100, 110)
        assert not diverged

    def test_custom_tolerance(self) -> None:
        """Custom tolerance parameters work."""
        d = DivergenceDetector(tolerance_percent=0.05, tolerance_floor=5)
        assert d.compute_tolerance(200) == 10  # 5% of 200
        assert d.compute_tolerance(10) == 5  # floor kicks in


# =============================================================================
# TestReconciliationSession
# =============================================================================


class TestReconciliationSession:
    """Tests for ReconciliationSession FSM."""

    @pytest.fixture
    def agent_keypair(self) -> tuple[bytes, bytes]:
        return generate_keypair()

    @pytest.fixture
    def server_keypair(self) -> tuple[bytes, bytes]:
        return generate_keypair()

    @pytest.fixture
    def meter_id(self) -> bytes:
        return os.urandom(16)

    def test_create_request_transitions_to_requested(
        self, agent_keypair: tuple[bytes, bytes], meter_id: bytes,
    ) -> None:
        """Creating a request transitions from IDLE to REQUESTED."""
        session = ReconciliationSession(
            meter_id=meter_id, signing_key=agent_keypair[1],
        )
        assert session.state == ReconciliationState.IDLE

        request, events = session.create_request(1, 5, 100)
        assert session.state == ReconciliationState.REQUESTED
        assert request.meter_id == meter_id
        assert request.start_seq == 1
        assert request.end_seq == 5
        assert any(isinstance(e, ReconciliationStarted) for e in events)

    def test_cannot_create_request_twice(
        self, agent_keypair: tuple[bytes, bytes], meter_id: bytes,
    ) -> None:
        """Cannot create request when not in IDLE."""
        session = ReconciliationSession(
            meter_id=meter_id, signing_key=agent_keypair[1],
        )
        session.create_request(1, 5, 100)
        with pytest.raises(ReconciliationError):
            session.create_request(1, 5, 100)

    def test_receipt_range_bounds_enforced(
        self, agent_keypair: tuple[bytes, bytes], meter_id: bytes,
    ) -> None:
        """Receipt range exceeding MAX_RECEIPT_RANGE is rejected."""
        session = ReconciliationSession(
            meter_id=meter_id, signing_key=agent_keypair[1],
        )
        with pytest.raises(ReconciliationBoundsError):
            session.create_request(1, MAX_RECEIPT_RANGE + 2, 100)

    def test_auto_resolution_agreed(
        self,
        agent_keypair: tuple[bytes, bytes],
        server_keypair: tuple[bytes, bytes],
        meter_id: bytes,
    ) -> None:
        """Identical chains resolve with AGREED."""
        agent_pk, agent_sk = agent_keypair
        server_pk, server_sk = server_keypair

        # Both sides have identical chains
        chain = _build_chain(server_sk, meter_id, [100, 200, 300])

        agent_session = ReconciliationSession(
            meter_id=meter_id, signing_key=agent_sk, local_chain=chain,
        )
        server_session = ReconciliationSession(
            meter_id=meter_id, signing_key=server_sk, local_chain=chain,
        )

        request, _ = agent_session.create_request(1, 3, 0)
        response, server_events = server_session.process_request(request, agent_pk)

        assert response.resolution == int(ResolutionMethod.AGREED)
        assert response.agreed_cost == 300
        assert any(isinstance(e, ReconciliationSucceeded) for e in server_events)

        resolved, agent_events = agent_session.process_response(response, server_pk)
        assert resolved
        assert agent_session.state == ReconciliationState.AUTO_RESOLVED
        assert agent_session.agreed_cost == 300

    def test_auto_resolution_higher_seq_wins(
        self,
        agent_keypair: tuple[bytes, bytes],
        server_keypair: tuple[bytes, bytes],
        meter_id: bytes,
    ) -> None:
        """Single divergence on last receipt resolves with HIGHER_SEQ_WINS."""
        agent_pk, agent_sk = agent_keypair
        server_pk, server_sk = server_keypair

        # Agent chain: [100, 200, 300]
        agent_chain = _build_chain(agent_sk, meter_id, [100, 200, 300])
        # Server chain: [100, 200, 310]  (last differs)
        server_chain = _build_chain(server_sk, meter_id, [100, 200, 310])

        agent_session = ReconciliationSession(
            meter_id=meter_id, signing_key=agent_sk, local_chain=agent_chain,
        )
        server_session = ReconciliationSession(
            meter_id=meter_id, signing_key=server_sk, local_chain=server_chain,
        )

        request, _ = agent_session.create_request(1, 3, 10)
        response, events = server_session.process_request(request, agent_pk)

        assert response.resolution == int(ResolutionMethod.HIGHER_SEQ_WINS)
        assert any(isinstance(e, ReconciliationSucceeded) for e in events)

    def test_auto_resolution_use_average(
        self,
        agent_keypair: tuple[bytes, bytes],
        server_keypair: tuple[bytes, bytes],
        meter_id: bytes,
    ) -> None:
        """Small total diff with multiple discrepancies resolves with USE_AVERAGE."""
        agent_pk, agent_sk = agent_keypair
        server_pk, server_sk = server_keypair

        # Multiple small discrepancies but total within tolerance
        agent_chain = _build_chain(agent_sk, meter_id, [100, 201])
        server_chain = _build_chain(server_sk, meter_id, [101, 200])

        agent_session = ReconciliationSession(
            meter_id=meter_id, signing_key=agent_sk, local_chain=agent_chain,
        )
        server_session = ReconciliationSession(
            meter_id=meter_id, signing_key=server_sk, local_chain=server_chain,
        )

        request, _ = agent_session.create_request(1, 2, 1)
        response, _ = server_session.process_request(request, agent_pk)

        # Total diff = |201 - 200| = 1, tolerance = max(1% of 201, 1) = 2
        assert response.resolution == int(ResolutionMethod.USE_AVERAGE)

    def test_auto_resolution_failed_large_diff(
        self,
        agent_keypair: tuple[bytes, bytes],
        server_keypair: tuple[bytes, bytes],
        meter_id: bytes,
    ) -> None:
        """Large divergence across multiple receipts fails auto-resolution."""
        agent_pk, agent_sk = agent_keypair
        server_pk, server_sk = server_keypair

        # Multiple divergence points AND large total diff
        agent_chain = _build_chain(agent_sk, meter_id, [100, 200])
        server_chain = _build_chain(server_sk, meter_id, [300, 500])

        agent_session = ReconciliationSession(
            meter_id=meter_id, signing_key=agent_sk, local_chain=agent_chain,
        )
        server_session = ReconciliationSession(
            meter_id=meter_id, signing_key=server_sk, local_chain=server_chain,
        )

        request, _ = agent_session.create_request(1, 2, 300)
        response, events = server_session.process_request(request, agent_pk)

        assert response.resolution == int(ResolutionMethod.FAILED)
        assert any(isinstance(e, ReconciliationFailed) for e in events)

        resolved, agent_events = agent_session.process_response(response, server_pk)
        assert not resolved
        assert agent_session.state == ReconciliationState.FAILED

    def test_grace_period_expiry(
        self, agent_keypair: tuple[bytes, bytes], meter_id: bytes,
    ) -> None:
        """Session expires after grace period."""
        session = ReconciliationSession(
            meter_id=meter_id,
            signing_key=agent_keypair[1],
            created_at=time.time() - GRACE_PERIOD_SECONDS - 1,
        )
        assert session.is_expired()

    def test_not_expired_within_grace_period(
        self, agent_keypair: tuple[bytes, bytes], meter_id: bytes,
    ) -> None:
        """Session not expired within grace period."""
        session = ReconciliationSession(
            meter_id=meter_id, signing_key=agent_keypair[1],
        )
        assert not session.is_expired()


# =============================================================================
# TestResourceManagerDivergence
# =============================================================================


class TestResourceManagerDivergence:
    """Tests for divergence detection in ResourceManager."""

    @pytest.fixture
    def server_keypair(self) -> tuple[bytes, bytes]:
        return generate_keypair()

    @pytest.fixture
    def agent_keypair(self) -> tuple[bytes, bytes]:
        return generate_keypair()

    def test_divergence_event_emitted(
        self,
        server_keypair: tuple[bytes, bytes],
        agent_keypair: tuple[bytes, bytes],
    ) -> None:
        """DivergenceDetected event emitted when costs diverge."""
        from qasp.framing.messages import MeterReport, ResourceGrant, ResourceRequest
        from qasp.protocol.metering import MeterReportHandler, ResourceManager

        agent_pk, agent_sk = agent_keypair
        server_pk, server_sk = server_keypair

        detector = DivergenceDetector()
        agent_rm = ResourceManager(
            signing_key=agent_sk,
            public_key=agent_pk,
            divergence_detector=detector,
        )
        agent_rm.set_peer_public_key(server_pk)

        server_rm = ResourceManager(
            signing_key=server_sk,
            public_key=server_pk,
            is_server=True,
        )
        server_rm.set_peer_public_key(agent_pk)

        # Server grants a resource
        request = ResourceRequest(
            request_id=os.urandom(16),
            resource_type="compute",
            resource_id=os.urandom(8),
            permissions=0xFF,
            duration=3600,
        )
        meter_id = os.urandom(16)
        grant, _ = server_rm.process_resource_request(
            request, token=os.urandom(32),
            granted_permissions=0xFF, expiration=int(time.time()) + 3600,
            meter_id=meter_id, unit_price=10,
        )
        agent_rm.process_resource_grant(grant, unit_price=10)

        # Agent tracks local usage at cost 100
        agent_rm.record_local_usage(meter_id, 10, cost=100)

        # Server records usage at higher cost and generates report
        server_rm.record_usage(meter_id, 20, 0)  # 20 * 10 = cost 200
        report, receipt, _ = server_rm.generate_meter_report(meter_id)

        # Agent processes report — should detect divergence
        result, events = agent_rm.process_meter_report(report)

        divergence_events = [e for e in events if isinstance(e, DivergenceDetected)]
        assert len(divergence_events) == 1
        assert divergence_events[0].reported_cost == 200
        assert divergence_events[0].local_cost == 100

    def test_no_divergence_within_tolerance(
        self,
        server_keypair: tuple[bytes, bytes],
        agent_keypair: tuple[bytes, bytes],
    ) -> None:
        """No DivergenceDetected when within tolerance."""
        from qasp.framing.messages import ResourceGrant, ResourceRequest
        from qasp.protocol.metering import ResourceManager

        agent_pk, agent_sk = agent_keypair
        server_pk, server_sk = server_keypair

        detector = DivergenceDetector()
        agent_rm = ResourceManager(
            signing_key=agent_sk,
            public_key=agent_pk,
            divergence_detector=detector,
        )
        agent_rm.set_peer_public_key(server_pk)

        server_rm = ResourceManager(
            signing_key=server_sk,
            public_key=server_pk,
            is_server=True,
        )
        server_rm.set_peer_public_key(agent_pk)

        request = ResourceRequest(
            request_id=os.urandom(16),
            resource_type="compute",
            resource_id=os.urandom(8),
            permissions=0xFF,
            duration=3600,
        )
        meter_id = os.urandom(16)
        grant, _ = server_rm.process_resource_request(
            request, token=os.urandom(32),
            granted_permissions=0xFF, expiration=int(time.time()) + 3600,
            meter_id=meter_id, unit_price=10,
        )
        agent_rm.process_resource_grant(grant, unit_price=10)

        # Agent tracks 100, server reports 100 (same)
        agent_rm.record_local_usage(meter_id, 10, cost=100)
        server_rm.record_usage(meter_id, 10, 0)  # 10 * 10 = 100
        report, _, _ = server_rm.generate_meter_report(meter_id)

        _, events = agent_rm.process_meter_report(report)
        divergence_events = [e for e in events if isinstance(e, DivergenceDetected)]
        assert len(divergence_events) == 0
