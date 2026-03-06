"""Tests for metering and resource lifecycle management."""

from __future__ import annotations

import time

import pytest

from qasp.crypto.signatures import generate_keypair
from qasp.framing.messages import (
    MeterAck,
    MeterReport,
    ResourceDeny,
    ResourceGrant,
    ResourceRelease,
    ResourceRequest,
    ResourceSuspend,
)
from qasp.protocol.capability import Constraints
from qasp.protocol.events import (
    MeterAckSent,
    MeterReportReceived,
    ResourceDenied,
    ResourceGranted,
    ResourceReleased,
    ResourceRequested,
    ResourceSuspended,
)
from qasp.protocol.metering import (
    InvalidMeterReportError,
    InvalidResourceStateError,
    MeterReportHandler,
    MeteringError,
    ResourceManager,
    ResourceNotFoundError,
    ResourceState,
    SuspendReason,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def server_keypair() -> tuple[bytes, bytes]:
    return generate_keypair()


@pytest.fixture
def server_public_key(server_keypair: tuple[bytes, bytes]) -> bytes:
    return server_keypair[0]


@pytest.fixture
def server_secret_key(server_keypair: tuple[bytes, bytes]) -> bytes:
    return server_keypair[1]


@pytest.fixture
def agent_keypair() -> tuple[bytes, bytes]:
    return generate_keypair()


@pytest.fixture
def agent_public_key(agent_keypair: tuple[bytes, bytes]) -> bytes:
    return agent_keypair[0]


@pytest.fixture
def agent_secret_key(agent_keypair: tuple[bytes, bytes]) -> bytes:
    return agent_keypair[1]


@pytest.fixture
def server_rm(
    server_secret_key: bytes,
    server_public_key: bytes,
    agent_public_key: bytes,
) -> ResourceManager:
    rm = ResourceManager(server_secret_key, server_public_key, is_server=True)
    rm.set_peer_public_key(agent_public_key)
    return rm


@pytest.fixture
def agent_rm(
    agent_secret_key: bytes,
    agent_public_key: bytes,
    server_public_key: bytes,
) -> ResourceManager:
    rm = ResourceManager(agent_secret_key, agent_public_key, is_server=False)
    rm.set_peer_public_key(server_public_key)
    return rm


# =============================================================================
# TestMeterReportHandler
# =============================================================================


class TestMeterReportHandler:
    """Tests for MeterReportHandler create/verify methods."""

    def test_create_and_verify_meter_report(
        self, server_secret_key: bytes, server_public_key: bytes,
    ) -> None:
        report = MeterReportHandler.create_meter_report(
            meter_id=b"meter_01",
            seq=1,
            usage_count=100,
            usage_bytes=2048,
            cost=500,
            signing_key=server_secret_key,
        )
        assert isinstance(report, MeterReport)
        assert report.meter_id == b"meter_01"
        assert report.sequence_number == 1
        assert report.usage_count == 100
        assert report.usage_bytes == 2048
        assert report.cost == 500
        assert len(report.signature) > 0

        assert MeterReportHandler.verify_meter_report(report, server_public_key)

    def test_meter_report_tamper_detection(
        self, server_secret_key: bytes, server_public_key: bytes,
    ) -> None:
        report = MeterReportHandler.create_meter_report(
            meter_id=b"meter_01",
            seq=1,
            usage_count=100,
            usage_bytes=2048,
            cost=500,
            signing_key=server_secret_key,
        )
        # Tamper with usage_count
        tampered = MeterReport(
            meter_id=report.meter_id,
            sequence_number=report.sequence_number,
            usage_count=999,
            usage_bytes=report.usage_bytes,
            cost=report.cost,
            timestamp=report.timestamp,
            signature=report.signature,
        )
        with pytest.raises(InvalidMeterReportError):
            MeterReportHandler.verify_meter_report(tampered, server_public_key)

    def test_meter_report_wrong_key(
        self, server_secret_key: bytes, agent_public_key: bytes,
    ) -> None:
        report = MeterReportHandler.create_meter_report(
            meter_id=b"meter_01",
            seq=1,
            usage_count=10,
            usage_bytes=0,
            cost=0,
            signing_key=server_secret_key,
        )
        with pytest.raises(InvalidMeterReportError):
            MeterReportHandler.verify_meter_report(report, agent_public_key)

    def test_create_and_verify_meter_ack(
        self, agent_secret_key: bytes, agent_public_key: bytes,
    ) -> None:
        ack = MeterReportHandler.create_meter_ack(
            meter_id=b"meter_01",
            acked_seq=3,
            acked_usage=300,
            signing_key=agent_secret_key,
        )
        assert isinstance(ack, MeterAck)
        assert ack.meter_id == b"meter_01"
        assert ack.acked_sequence == 3
        assert ack.acked_usage == 300

        assert MeterReportHandler.verify_meter_ack(ack, agent_public_key)

    def test_meter_ack_tamper_detection(
        self, agent_secret_key: bytes, agent_public_key: bytes,
    ) -> None:
        ack = MeterReportHandler.create_meter_ack(
            meter_id=b"meter_01",
            acked_seq=3,
            acked_usage=300,
            signing_key=agent_secret_key,
        )
        tampered = MeterAck(
            meter_id=ack.meter_id,
            acked_sequence=ack.acked_sequence,
            acked_usage=999,
            signature=ack.signature,
        )
        with pytest.raises(InvalidMeterReportError):
            MeterReportHandler.verify_meter_ack(tampered, agent_public_key)


# =============================================================================
# TestResourceRequestGrant
# =============================================================================


class TestResourceRequestGrant:
    """Tests for resource request and grant flow."""

    def test_create_resource_request(self, agent_rm: ResourceManager) -> None:
        request, events = agent_rm.create_resource_request(
            resource_type="compute",
            resource_id=b"res_001",
            permissions=0x03,
            duration=3600,
        )
        assert isinstance(request, ResourceRequest)
        assert request.resource_type == "compute"
        assert request.resource_id == b"res_001"
        assert request.permissions == 0x03
        assert len(events) == 1
        assert isinstance(events[0], ResourceRequested)

    def test_process_resource_grant(self, agent_rm: ResourceManager) -> None:
        request, _ = agent_rm.create_resource_request(
            resource_type="compute",
            resource_id=b"res_001",
            permissions=0x03,
            duration=3600,
        )
        grant = ResourceGrant(
            request_id=request.request_id,
            token=b"token_001",
            granted_permissions=0x03,
            expiration=int(time.time()) + 3600,
            meter_id=b"meter_01",
        )
        events = agent_rm.process_resource_grant(grant)
        assert len(events) == 1
        assert isinstance(events[0], ResourceGranted)
        assert events[0].token_id == b"token_001"
        assert events[0].granted_permissions == 0x03

    def test_deny_resource_request(self, server_rm: ResourceManager) -> None:
        deny, events = server_rm.deny_resource_request(
            request_id=b"req_001",
            reason=1,
            message="insufficient credits",
        )
        assert isinstance(deny, ResourceDeny)
        assert deny.reason == 1
        assert len(events) == 1
        assert isinstance(events[0], ResourceDenied)

    def test_process_resource_deny(self, agent_rm: ResourceManager) -> None:
        request, _ = agent_rm.create_resource_request(
            resource_type="compute",
            resource_id=b"res_001",
            permissions=0x03,
            duration=3600,
        )
        deny = ResourceDeny(
            request_id=request.request_id,
            reason=1,
            message="not authorized",
        )
        events = agent_rm.process_resource_deny(deny)
        assert len(events) == 1
        assert isinstance(events[0], ResourceDenied)

    def test_server_process_resource_request(
        self, server_rm: ResourceManager,
    ) -> None:
        request = ResourceRequest(
            request_id=b"req_001",
            resource_type="storage",
            resource_id=b"res_002",
            permissions=0x01,
            duration=7200,
        )
        grant, events = server_rm.process_resource_request(
            request=request,
            token=b"token_002",
            granted_permissions=0x01,
            expiration=int(time.time()) + 7200,
            meter_id=b"meter_02",
        )
        assert isinstance(grant, ResourceGrant)
        assert grant.request_id == b"req_001"
        assert grant.token == b"token_002"
        assert grant.meter_id == b"meter_02"
        assert len(events) == 1
        assert isinstance(events[0], ResourceGranted)


# =============================================================================
# TestMeteringLifecycle
# =============================================================================


class TestMeteringLifecycle:
    """Tests for the full metering lifecycle."""

    def _setup_granted_resource(
        self,
        server_rm: ResourceManager,
        agent_rm: ResourceManager,
    ) -> bytes:
        """Set up a granted resource, returns meter_id."""
        request, _ = agent_rm.create_resource_request(
            resource_type="compute",
            resource_id=b"res_001",
            permissions=0x03,
            duration=3600,
            request_id=b"req_lifecycle",
        )
        meter_id = b"meter_life"
        grant, _ = server_rm.process_resource_request(
            request=request,
            token=b"token_life",
            granted_permissions=0x03,
            expiration=int(time.time()) + 3600,
            meter_id=meter_id,
        )
        agent_rm.process_resource_grant(grant)
        return meter_id

    def test_full_lifecycle(
        self, server_rm: ResourceManager, agent_rm: ResourceManager,
    ) -> None:
        """request -> grant -> record -> report -> ack -> release"""
        meter_id = self._setup_granted_resource(server_rm, agent_rm)

        # Record usage on server
        server_rm.record_usage(meter_id, units=50, data_bytes=1024)

        # Generate report from server
        report, receipt, report_events = server_rm.generate_meter_report(meter_id)
        assert report.usage_count == 50
        assert report.usage_bytes == 1024
        assert receipt.total_units == 50

        # Agent processes report, returns ack
        response, ack_events = agent_rm.process_meter_report(report)
        assert isinstance(response, MeterAck)
        assert response.acked_usage == 50

        # Server processes ack
        ack_server_events = server_rm.process_meter_ack(response)
        assert len(ack_server_events) == 1

        # Agent releases
        release, release_events = agent_rm.create_resource_release(meter_id)
        assert isinstance(release, ResourceRelease)
        assert release.final_usage == 50
        assert len(release_events) == 1
        assert isinstance(release_events[0], ResourceReleased)

        # Server processes release
        server_events = server_rm.process_resource_release(release)
        assert len(server_events) == 1
        assert isinstance(server_events[0], ResourceReleased)

    def test_multiple_reports_build_receipt_chain(
        self, server_rm: ResourceManager, agent_rm: ResourceManager,
    ) -> None:
        meter_id = self._setup_granted_resource(server_rm, agent_rm)

        for i in range(3):
            server_rm.record_usage(meter_id, units=10)
            report, receipt, _ = server_rm.generate_meter_report(meter_id)
            response, _ = agent_rm.process_meter_report(report)
            assert isinstance(response, MeterAck)
            server_rm.process_meter_ack(response)

        chain = server_rm._receipt_chains[meter_id]
        assert len(chain) == 3
        # Verify sequence numbers increment
        for i, r in enumerate(chain.receipts):
            assert r.sequence_number == i + 1


# =============================================================================
# TestConstraintEnforcement
# =============================================================================


class TestConstraintEnforcement:
    """Tests for constraint checking that triggers suspend."""

    def test_budget_exhaustion_triggers_suspend(
        self, server_rm: ResourceManager, agent_rm: ResourceManager,
    ) -> None:
        request, _ = agent_rm.create_resource_request(
            resource_type="compute",
            resource_id=b"res_budget",
            permissions=0x01,
            duration=3600,
            request_id=b"req_budget__",
        )
        constraints = Constraints(max_spend=100, spend_currency="credits")
        meter_id = b"meter_budgt"
        grant, _ = server_rm.process_resource_request(
            request=request,
            token=b"token_budgt",
            granted_permissions=0x01,
            expiration=int(time.time()) + 3600,
            meter_id=meter_id,
            constraints=constraints,
            unit_price=10,
        )
        agent_rm.process_resource_grant(grant, constraints=constraints, unit_price=10)

        # Record 11 units at price 10 => cost 110 > max_spend 100
        server_rm.record_usage(meter_id, units=11)
        report, _, _ = server_rm.generate_meter_report(meter_id)

        # Agent checks constraints, should return suspend
        response, events = agent_rm.process_meter_report(report)
        assert isinstance(response, ResourceSuspend)
        assert response.reason == SuspendReason.BUDGET_EXHAUSTED
        assert any(isinstance(e, ResourceSuspended) for e in events)

    def test_quantity_exceeded_triggers_suspend(
        self, server_rm: ResourceManager, agent_rm: ResourceManager,
    ) -> None:
        request, _ = agent_rm.create_resource_request(
            resource_type="compute",
            resource_id=b"res_quant_",
            permissions=0x01,
            duration=3600,
            request_id=b"req_quant___",
        )
        constraints = Constraints(quantity_limit=50)
        meter_id = b"meter_quant"
        grant, _ = server_rm.process_resource_request(
            request=request,
            token=b"token_quant",
            granted_permissions=0x01,
            expiration=int(time.time()) + 3600,
            meter_id=meter_id,
            constraints=constraints,
        )
        agent_rm.process_resource_grant(grant, constraints=constraints)

        # Record 51 units > quantity_limit 50
        server_rm.record_usage(meter_id, units=51)
        report, _, _ = server_rm.generate_meter_report(meter_id)

        response, events = agent_rm.process_meter_report(report)
        assert isinstance(response, ResourceSuspend)
        assert response.reason == SuspendReason.QUANTITY_EXCEEDED

    def test_normal_usage_passes_constraints(
        self, server_rm: ResourceManager, agent_rm: ResourceManager,
    ) -> None:
        request, _ = agent_rm.create_resource_request(
            resource_type="compute",
            resource_id=b"res_normal",
            permissions=0x01,
            duration=3600,
            request_id=b"req_normal__",
        )
        constraints = Constraints(quantity_limit=100, max_spend=1000)
        meter_id = b"meter_norml"
        grant, _ = server_rm.process_resource_request(
            request=request,
            token=b"token_norml",
            granted_permissions=0x01,
            expiration=int(time.time()) + 3600,
            meter_id=meter_id,
            constraints=constraints,
            unit_price=5,
        )
        agent_rm.process_resource_grant(grant, constraints=constraints, unit_price=5)

        # Record 10 units, cost = 50, both well within limits
        server_rm.record_usage(meter_id, units=10)
        report, _, _ = server_rm.generate_meter_report(meter_id)

        response, events = agent_rm.process_meter_report(report)
        assert isinstance(response, MeterAck)


# =============================================================================
# TestResourceSuspend
# =============================================================================


class TestResourceSuspend:
    """Tests for resource suspension."""

    def test_server_suspends_resource(
        self, server_rm: ResourceManager, agent_rm: ResourceManager,
    ) -> None:
        request = ResourceRequest(
            request_id=b"req_susp____",
            resource_type="compute",
            resource_id=b"res_susp__",
            permissions=0x01,
            duration=3600,
        )
        meter_id = b"meter_suspe"
        server_rm.process_resource_request(
            request=request,
            token=b"token_suspe",
            granted_permissions=0x01,
            expiration=int(time.time()) + 3600,
            meter_id=meter_id,
        )

        suspend_msg, events = server_rm.suspend_resource(
            meter_id, SuspendReason.MANUAL, resume_time=9999,
        )
        assert isinstance(suspend_msg, ResourceSuspend)
        assert suspend_msg.reason == SuspendReason.MANUAL
        assert suspend_msg.resume_time == 9999
        assert len(events) == 1
        assert isinstance(events[0], ResourceSuspended)

    def test_agent_processes_suspend(
        self, server_rm: ResourceManager, agent_rm: ResourceManager,
    ) -> None:
        request, _ = agent_rm.create_resource_request(
            resource_type="compute",
            resource_id=b"res_asusp_",
            permissions=0x01,
            duration=3600,
            request_id=b"req_asusp___",
        )
        meter_id = b"meter_asusp"
        grant, _ = server_rm.process_resource_request(
            request=request,
            token=b"token_asusp",
            granted_permissions=0x01,
            expiration=int(time.time()) + 3600,
            meter_id=meter_id,
        )
        agent_rm.process_resource_grant(grant)

        suspend_msg = ResourceSuspend(
            token_id=b"token_asusp",
            reason=SuspendReason.RATE_LIMIT_HIT,
            resume_time=5000,
        )
        events = agent_rm.process_resource_suspend(suspend_msg)
        assert len(events) == 1
        assert isinstance(events[0], ResourceSuspended)
        assert events[0].reason == SuspendReason.RATE_LIMIT_HIT

        # Resource should be in SUSPENDED state
        resource = agent_rm._resources[meter_id]
        assert resource.state == ResourceState.SUSPENDED

    def test_cannot_suspend_non_active_resource(
        self, server_rm: ResourceManager,
    ) -> None:
        request = ResourceRequest(
            request_id=b"req_badsusp_",
            resource_type="compute",
            resource_id=b"res_badsus",
            permissions=0x01,
            duration=3600,
        )
        meter_id = b"meter_badsu"
        server_rm.process_resource_request(
            request=request,
            token=b"token_badsu",
            granted_permissions=0x01,
            expiration=int(time.time()) + 3600,
            meter_id=meter_id,
        )
        # Suspend it first
        server_rm.suspend_resource(meter_id, SuspendReason.MANUAL)
        # Trying again should fail
        with pytest.raises(InvalidResourceStateError):
            server_rm.suspend_resource(meter_id, SuspendReason.MANUAL)


# =============================================================================
# TestResourceRelease
# =============================================================================


class TestResourceRelease:
    """Tests for resource release."""

    def test_signed_release_and_server_verification(
        self, server_rm: ResourceManager, agent_rm: ResourceManager,
    ) -> None:
        request, _ = agent_rm.create_resource_request(
            resource_type="compute",
            resource_id=b"res_rel___",
            permissions=0x01,
            duration=3600,
            request_id=b"req_rel_____",
        )
        meter_id = b"meter_relea"
        grant, _ = server_rm.process_resource_request(
            request=request,
            token=b"token_relea",
            granted_permissions=0x01,
            expiration=int(time.time()) + 3600,
            meter_id=meter_id,
        )
        agent_rm.process_resource_grant(grant)

        release, events = agent_rm.create_resource_release(meter_id)
        assert isinstance(release, ResourceRelease)
        assert len(release.signature) > 0
        assert len(events) == 1
        assert isinstance(events[0], ResourceReleased)

        # Server verifies the release
        server_events = server_rm.process_resource_release(release)
        assert len(server_events) == 1
        assert isinstance(server_events[0], ResourceReleased)

    def test_cannot_release_already_released(
        self, agent_rm: ResourceManager, server_rm: ResourceManager,
    ) -> None:
        request, _ = agent_rm.create_resource_request(
            resource_type="compute",
            resource_id=b"res_relrel",
            permissions=0x01,
            duration=3600,
            request_id=b"req_relrel__",
        )
        meter_id = b"meter_relre"
        grant, _ = server_rm.process_resource_request(
            request=request,
            token=b"token_relre",
            granted_permissions=0x01,
            expiration=int(time.time()) + 3600,
            meter_id=meter_id,
        )
        agent_rm.process_resource_grant(grant)
        agent_rm.create_resource_release(meter_id)

        with pytest.raises(InvalidResourceStateError):
            agent_rm.create_resource_release(meter_id)


# =============================================================================
# TestReceiptChainIntegration
# =============================================================================


class TestReceiptChainIntegration:
    """Tests for receipt chain integration with metering."""

    def test_receipt_chain_verifiable(
        self,
        server_rm: ResourceManager,
        agent_rm: ResourceManager,
        server_public_key: bytes,
    ) -> None:
        request, _ = agent_rm.create_resource_request(
            resource_type="compute",
            resource_id=b"res_chain_",
            permissions=0x01,
            duration=3600,
            request_id=b"req_chain___",
        )
        meter_id = b"meter_chain"
        grant, _ = server_rm.process_resource_request(
            request=request,
            token=b"token_chain",
            granted_permissions=0x01,
            expiration=int(time.time()) + 3600,
            meter_id=meter_id,
        )
        agent_rm.process_resource_grant(grant)

        # Generate multiple reports
        for i in range(4):
            server_rm.record_usage(meter_id, units=10)
            report, receipt, _ = server_rm.generate_meter_report(meter_id)
            response, _ = agent_rm.process_meter_report(report)
            server_rm.process_meter_ack(response)

        chain = server_rm._receipt_chains[meter_id]
        assert len(chain) == 4

        # Verify the chain with server's public key
        assert chain.verify(server_public_key)


# =============================================================================
# TestEdgeCases
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and error conditions."""

    def test_unknown_meter_id_error(self, agent_rm: ResourceManager) -> None:
        with pytest.raises(ResourceNotFoundError):
            agent_rm.create_resource_release(b"nonexistent")

    def test_record_usage_wrong_state(
        self, server_rm: ResourceManager,
    ) -> None:
        request = ResourceRequest(
            request_id=b"req_wrongst_",
            resource_type="compute",
            resource_id=b"res_wrngs_",
            permissions=0x01,
            duration=3600,
        )
        meter_id = b"meter_wrngs"
        server_rm.process_resource_request(
            request=request,
            token=b"token_wrngs",
            granted_permissions=0x01,
            expiration=int(time.time()) + 3600,
            meter_id=meter_id,
        )
        server_rm.suspend_resource(meter_id, SuspendReason.MANUAL)

        with pytest.raises(InvalidResourceStateError):
            server_rm.record_usage(meter_id, units=10)

    def test_generate_report_wrong_state(
        self, server_rm: ResourceManager,
    ) -> None:
        request = ResourceRequest(
            request_id=b"req_rptst__",
            resource_type="compute",
            resource_id=b"res_rptst_",
            permissions=0x01,
            duration=3600,
        )
        meter_id = b"meter_rptst"
        server_rm.process_resource_request(
            request=request,
            token=b"token_rptst",
            granted_permissions=0x01,
            expiration=int(time.time()) + 3600,
            meter_id=meter_id,
        )
        server_rm.suspend_resource(meter_id, SuspendReason.MANUAL)

        with pytest.raises(InvalidResourceStateError):
            server_rm.generate_meter_report(meter_id)

    def test_peer_key_not_set_error(self) -> None:
        pk, sk = generate_keypair()
        rm = ResourceManager(sk, pk, is_server=False)
        report = MeterReport(
            meter_id=b"test",
            sequence_number=1,
            usage_count=10,
            usage_bytes=0,
            cost=0,
            timestamp=int(time.time()),
            signature=b"fake",
        )
        with pytest.raises(MeteringError, match="Peer public key not set"):
            rm.process_meter_report(report)

    def test_zero_usage_report(
        self, server_rm: ResourceManager, agent_rm: ResourceManager,
    ) -> None:
        request, _ = agent_rm.create_resource_request(
            resource_type="compute",
            resource_id=b"res_zero__",
            permissions=0x01,
            duration=3600,
            request_id=b"req_zero____",
        )
        meter_id = b"meter_zero_"
        grant, _ = server_rm.process_resource_request(
            request=request,
            token=b"token_zero_",
            granted_permissions=0x01,
            expiration=int(time.time()) + 3600,
            meter_id=meter_id,
        )
        agent_rm.process_resource_grant(grant)

        # Zero-usage report should still work
        report, receipt, _ = server_rm.generate_meter_report(meter_id)
        assert report.usage_count == 0
        response, _ = agent_rm.process_meter_report(report)
        assert isinstance(response, MeterAck)

    def test_process_meter_report_non_active_resource(
        self,
        server_rm: ResourceManager,
        agent_rm: ResourceManager,
    ) -> None:
        request, _ = agent_rm.create_resource_request(
            resource_type="compute",
            resource_id=b"res_nonact",
            permissions=0x01,
            duration=3600,
            request_id=b"req_nonact__",
        )
        meter_id = b"meter_nonac"
        grant, _ = server_rm.process_resource_request(
            request=request,
            token=b"token_nonac",
            granted_permissions=0x01,
            expiration=int(time.time()) + 3600,
            meter_id=meter_id,
        )
        agent_rm.process_resource_grant(grant)

        # Release the resource first
        agent_rm.create_resource_release(meter_id)

        # Generate a report from server
        report, _, _ = server_rm.generate_meter_report(meter_id)

        # Agent should reject report for non-active resource
        with pytest.raises(InvalidResourceStateError):
            agent_rm.process_meter_report(report)
