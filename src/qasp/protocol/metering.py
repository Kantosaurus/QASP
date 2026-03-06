"""Metering and resource lifecycle management.

This module implements the protocol-level orchestration for QASP metering:
- Signed MeterReport and MeterAck creation/verification
- Resource lifecycle: Request -> Grant/Deny -> Meter -> Release/Suspend
- Constraint enforcement that triggers ResourceSuspend
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, IntEnum

import cbor2

from qasp.crypto.exceptions import InvalidSignatureError
from qasp.crypto.signatures import sign, verify
from qasp.framing.messages import (
    MeterAck,
    MeterReport,
    ResourceDeny,
    ResourceGrant,
    ResourceRelease,
    ResourceRequest,
    ResourceSuspend,
)
from qasp.protocol.accounting import Meter, Receipt, ReceiptChain
from qasp.protocol.capability import (
    Constraints,
    TemporalSchedule,
    evaluate_temporal_constraints_raw,
)
from qasp.protocol.events import (
    DivergenceDetected,
    Event,
    MeterAckSent,
    MeterReportReceived,
    ResourceDenied,
    ResourceGranted,
    ResourceReleased,
    ResourceRequested,
    ResourceSuspended,
)
from qasp.protocol.reconciliation import (
    DivergenceDetector,
    ReconciliationSession,
)

__all__ = [
    "InvalidMeterReportError",
    "InvalidResourceStateError",
    "ManagedResource",
    "MeterReportHandler",
    "MeteringError",
    "ResourceManager",
    "ResourceNotFoundError",
    "ResourceState",
    "SuspendReason",
]


# =============================================================================
# Enums
# =============================================================================


class SuspendReason(IntEnum):
    """Reason codes for resource suspension."""

    BUDGET_EXHAUSTED = 1
    QUANTITY_EXCEEDED = 2
    RATE_LIMIT_HIT = 3
    TIME_EXPIRED = 4
    MANUAL = 5


class ResourceState(Enum):
    """State of a managed resource."""

    PENDING = "pending"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    RELEASED = "released"
    DENIED = "denied"


# =============================================================================
# Exceptions
# =============================================================================


class MeteringError(Exception):
    """Base exception for metering errors."""

    alert_code: int = 60


class InvalidMeterReportError(MeteringError):
    """Raised when a meter report or ack fails verification."""

    alert_code: int = 61


class ResourceNotFoundError(MeteringError):
    """Raised when a meter_id is not found."""

    alert_code: int = 62


class InvalidResourceStateError(MeteringError):
    """Raised when an operation is invalid for the current resource state."""

    alert_code: int = 63


# =============================================================================
# Signing Helpers
# =============================================================================


def _encode_meter_report_data(
    meter_id: bytes,
    seq: int,
    usage_count: int,
    usage_bytes: int,
    cost: int,
    timestamp: int,
) -> bytes:
    """CBOR-encode MeterReport fields for signing (excludes signature)."""
    return cbor2.dumps({
        "meter_id": meter_id,
        "sequence_number": seq,
        "usage_count": usage_count,
        "usage_bytes": usage_bytes,
        "cost": cost,
        "timestamp": timestamp,
    })


def _encode_meter_ack_data(
    meter_id: bytes,
    acked_seq: int,
    acked_usage: int,
) -> bytes:
    """CBOR-encode MeterAck fields for signing (excludes signature)."""
    return cbor2.dumps({
        "meter_id": meter_id,
        "acked_sequence": acked_seq,
        "acked_usage": acked_usage,
    })


def _encode_resource_release_data(
    token_id: bytes,
    final_usage: int,
) -> bytes:
    """CBOR-encode ResourceRelease fields for signing (excludes signature)."""
    return cbor2.dumps({
        "token_id": token_id,
        "final_usage": final_usage,
    })


# =============================================================================
# ManagedResource
# =============================================================================


@dataclass
class ManagedResource:
    """A resource being tracked by the ResourceManager."""

    request_id: bytes
    resource_type: str
    resource_id: bytes
    token_id: bytes
    meter_id: bytes
    granted_permissions: int
    expiration: int
    state: ResourceState = ResourceState.ACTIVE
    constraints: Constraints | None = None
    cumulative_units: int = 0
    cumulative_cost: int = 0
    cumulative_bytes: int = 0
    unit_price: int = 0
    temporal_attenuation: TemporalSchedule | None = None
    token_issued_at: datetime | None = None
    last_report_seq: int = 0
    last_acked_seq: int = 0
    agent_tracked_units: int = 0
    agent_tracked_cost: int = 0
    reconciliation_session: ReconciliationSession | None = None


# =============================================================================
# MeterReportHandler
# =============================================================================


class MeterReportHandler:
    """Static methods for creating and verifying signed MeterReport/MeterAck."""

    @staticmethod
    def create_meter_report(
        meter_id: bytes,
        seq: int,
        usage_count: int,
        usage_bytes: int,
        cost: int,
        signing_key: bytes,
    ) -> MeterReport:
        """Create a signed MeterReport message."""
        timestamp = int(time.time())
        data = _encode_meter_report_data(
            meter_id, seq, usage_count, usage_bytes, cost, timestamp,
        )
        sig = sign(signing_key, data)
        return MeterReport(
            meter_id=meter_id,
            sequence_number=seq,
            usage_count=usage_count,
            usage_bytes=usage_bytes,
            cost=cost,
            timestamp=timestamp,
            signature=sig,
        )

    @staticmethod
    def verify_meter_report(report: MeterReport, public_key: bytes) -> bool:
        """Verify a MeterReport's signature.

        Raises:
            InvalidMeterReportError: If verification fails.
        """
        data = _encode_meter_report_data(
            report.meter_id,
            report.sequence_number,
            report.usage_count,
            report.usage_bytes,
            report.cost,
            report.timestamp,
        )
        try:
            verify(public_key, data, report.signature)
        except (InvalidSignatureError, Exception) as e:
            raise InvalidMeterReportError(
                f"MeterReport signature verification failed: {e}"
            ) from e
        return True

    @staticmethod
    def create_meter_ack(
        meter_id: bytes,
        acked_seq: int,
        acked_usage: int,
        signing_key: bytes,
    ) -> MeterAck:
        """Create a signed MeterAck message."""
        data = _encode_meter_ack_data(meter_id, acked_seq, acked_usage)
        sig = sign(signing_key, data)
        return MeterAck(
            meter_id=meter_id,
            acked_sequence=acked_seq,
            acked_usage=acked_usage,
            signature=sig,
        )

    @staticmethod
    def verify_meter_ack(ack: MeterAck, public_key: bytes) -> bool:
        """Verify a MeterAck's signature.

        Raises:
            InvalidMeterReportError: If verification fails.
        """
        data = _encode_meter_ack_data(
            ack.meter_id, ack.acked_sequence, ack.acked_usage,
        )
        try:
            verify(public_key, data, ack.signature)
        except (InvalidSignatureError, Exception) as e:
            raise InvalidMeterReportError(
                f"MeterAck signature verification failed: {e}"
            ) from e
        return True


# =============================================================================
# ResourceManager
# =============================================================================


class ResourceManager:
    """Sans-I/O resource lifecycle manager.

    Orchestrates the full resource lifecycle:
    Request -> Grant/Deny -> Meter -> Report -> Ack -> Release/Suspend

    Methods return messages and events; the caller is responsible for
    actually sending/receiving wire messages.
    """

    def __init__(
        self,
        signing_key: bytes,
        public_key: bytes,
        is_server: bool = False,
        divergence_detector: DivergenceDetector | None = None,
    ) -> None:
        self._signing_key = signing_key
        self._public_key = public_key
        self._is_server = is_server
        self._resources: dict[bytes, ManagedResource] = {}
        self._pending_requests: dict[bytes, ResourceRequest] = {}
        self._peer_public_key: bytes | None = None
        self._meters: dict[bytes, Meter] = {}
        self._receipt_chains: dict[bytes, ReceiptChain] = {}
        self._divergence_detector = divergence_detector

    def set_peer_public_key(self, key: bytes) -> None:
        """Set the peer's public key (from handshake)."""
        self._peer_public_key = key

    def _get_resource(self, meter_id: bytes) -> ManagedResource:
        """Look up a resource by meter_id, raising if not found."""
        resource = self._resources.get(meter_id)
        if resource is None:
            raise ResourceNotFoundError(
                f"No resource found for meter_id {meter_id.hex()[:16]}"
            )
        return resource

    # -----------------------------------------------------------------
    # Agent-side methods
    # -----------------------------------------------------------------

    def create_resource_request(
        self,
        resource_type: str,
        resource_id: bytes,
        permissions: int,
        duration: int,
        request_id: bytes | None = None,
    ) -> tuple[ResourceRequest, list[Event]]:
        """Create a ResourceRequest message (agent-side)."""
        if request_id is None:
            import os
            request_id = os.urandom(16)

        request = ResourceRequest(
            request_id=request_id,
            resource_type=resource_type,
            resource_id=resource_id,
            permissions=permissions,
            duration=duration,
        )
        self._pending_requests[request_id] = request
        events: list[Event] = [
            ResourceRequested(
                resource_id=resource_id,
                resource_type=resource_type,
                requested_permissions=permissions,
            )
        ]
        return request, events

    def process_resource_grant(
        self,
        grant: ResourceGrant,
        constraints: Constraints | None = None,
        unit_price: int = 0,
    ) -> list[Event]:
        """Process a ResourceGrant received from the server (agent-side)."""
        request = self._pending_requests.pop(grant.request_id, None)
        resource_type = ""
        resource_id = b""
        if request is not None:
            resource_type = request.resource_type
            resource_id = request.resource_id

        resource = ManagedResource(
            request_id=grant.request_id,
            resource_type=resource_type,
            resource_id=resource_id,
            token_id=grant.token,
            meter_id=grant.meter_id,
            granted_permissions=grant.granted_permissions,
            expiration=grant.expiration,
            state=ResourceState.ACTIVE,
            constraints=constraints,
            unit_price=unit_price,
        )
        self._resources[grant.meter_id] = resource
        self._receipt_chains[grant.meter_id] = ReceiptChain()

        return [
            ResourceGranted(
                resource_id=resource_id,
                token_id=grant.token,
                granted_permissions=grant.granted_permissions,
            )
        ]

    def process_resource_deny(self, deny: ResourceDeny) -> list[Event]:
        """Process a ResourceDeny received from the server (agent-side)."""
        request = self._pending_requests.pop(deny.request_id, None)
        resource_id = request.resource_id if request else b""

        return [
            ResourceDenied(
                resource_id=resource_id,
                reason=deny.message or f"reason_code={deny.reason}",
            )
        ]

    def process_meter_report(
        self, report: MeterReport,
    ) -> tuple[MeterAck | ResourceSuspend, list[Event]]:
        """Process a MeterReport received from the server (agent-side).

        Verifies the report signature, checks constraints, and returns
        either an ack or a suspend message.
        """
        if self._peer_public_key is None:
            raise MeteringError("Peer public key not set")

        MeterReportHandler.verify_meter_report(report, self._peer_public_key)

        resource = self._get_resource(report.meter_id)
        if resource.state != ResourceState.ACTIVE:
            raise InvalidResourceStateError(
                f"Resource is {resource.state.value}, expected ACTIVE"
            )

        resource.cumulative_units = report.usage_count
        resource.cumulative_bytes = report.usage_bytes
        resource.cumulative_cost = report.cost
        resource.last_report_seq = report.sequence_number

        events: list[Event] = [
            MeterReportReceived(
                meter_id=report.meter_id,
                usage_count=report.usage_count,
                usage_bytes=report.usage_bytes,
                timestamp=report.timestamp,
            )
        ]

        # Divergence detection (non-blocking side-channel)
        if (
            self._divergence_detector is not None
            and resource.agent_tracked_units > 0
        ):
            diverged, tolerance = self._divergence_detector.check(
                report.cost, resource.agent_tracked_cost,
            )
            if diverged:
                events.append(DivergenceDetected(
                    meter_id=report.meter_id,
                    reported_cost=report.cost,
                    local_cost=resource.agent_tracked_cost,
                    difference=abs(report.cost - resource.agent_tracked_cost),
                    tolerance=tolerance,
                ))
                if resource.reconciliation_session is None:
                    chain = self._receipt_chains.get(report.meter_id)
                    resource.reconciliation_session = ReconciliationSession(
                        meter_id=report.meter_id,
                        signing_key=self._signing_key,
                        local_chain=chain,
                    )

        # Check constraints
        suspend_msg = self.check_constraints(report.meter_id)
        if suspend_msg is not None:
            resource.state = ResourceState.SUSPENDED
            events.append(
                ResourceSuspended(
                    resource_id=resource.resource_id,
                    token_id=resource.token_id,
                    reason=suspend_msg.reason,
                    resume_time=suspend_msg.resume_time,
                )
            )
            return suspend_msg, events

        ack = MeterReportHandler.create_meter_ack(
            meter_id=report.meter_id,
            acked_seq=report.sequence_number,
            acked_usage=report.usage_count,
            signing_key=self._signing_key,
        )
        events.append(
            MeterAckSent(
                meter_id=report.meter_id,
                acked_count=report.usage_count,
            )
        )
        return ack, events

    def create_resource_release(
        self, meter_id: bytes,
    ) -> tuple[ResourceRelease, list[Event]]:
        """Create a signed ResourceRelease message (agent-side)."""
        resource = self._get_resource(meter_id)
        if resource.state not in (ResourceState.ACTIVE, ResourceState.SUSPENDED):
            raise InvalidResourceStateError(
                f"Cannot release resource in state {resource.state.value}"
            )

        data = _encode_resource_release_data(
            resource.token_id, resource.cumulative_units,
        )
        sig = sign(self._signing_key, data)

        release = ResourceRelease(
            token_id=resource.token_id,
            final_usage=resource.cumulative_units,
            signature=sig,
        )
        resource.state = ResourceState.RELEASED
        events: list[Event] = [
            ResourceReleased(
                resource_id=resource.resource_id,
                token_id=resource.token_id,
            )
        ]
        return release, events

    def process_resource_suspend(self, suspend: ResourceSuspend) -> list[Event]:
        """Process a ResourceSuspend received from the server (agent-side)."""
        # Find resource by token_id
        resource = None
        for r in self._resources.values():
            if r.token_id == suspend.token_id:
                resource = r
                break
        if resource is None:
            raise ResourceNotFoundError(
                f"No resource found for token_id {suspend.token_id.hex()[:16]}"
            )
        resource.state = ResourceState.SUSPENDED
        return [
            ResourceSuspended(
                resource_id=resource.resource_id,
                token_id=resource.token_id,
                reason=suspend.reason,
                resume_time=suspend.resume_time,
            )
        ]

    # -----------------------------------------------------------------
    # Agent-side local tracking & reconciliation
    # -----------------------------------------------------------------

    def record_local_usage(
        self, meter_id: bytes, units: int, cost: int = 0,
    ) -> None:
        """Record local usage tracked by the agent.

        Called by the application layer when the agent performs operations,
        enabling divergence detection when server meter reports arrive.
        """
        resource = self._get_resource(meter_id)
        resource.agent_tracked_units += units
        resource.agent_tracked_cost += cost

    def create_reconciliation_request(
        self, meter_id: bytes,
    ) -> tuple[ReconciliationRequest, list[Event]]:
        """Create a reconciliation request for a divergent meter."""
        resource = self._get_resource(meter_id)
        session = resource.reconciliation_session
        if session is None:
            chain = self._receipt_chains.get(meter_id)
            session = ReconciliationSession(
                meter_id=meter_id,
                signing_key=self._signing_key,
                local_chain=chain,
            )
            resource.reconciliation_session = session

        start_seq = 1
        end_seq = resource.last_report_seq or 1
        diff = abs(resource.cumulative_cost - resource.agent_tracked_cost)
        return session.create_request(start_seq, end_seq, diff)

    def process_reconciliation_request(
        self, request: ReconciliationRequest,
    ) -> tuple[ReconciliationResponse, list[Event]]:
        """Process a reconciliation request (server-side)."""
        if self._peer_public_key is None:
            raise MeteringError("Peer public key not set")

        resource = self._get_resource(request.meter_id)
        chain = self._receipt_chains.get(request.meter_id)
        session = ReconciliationSession(
            meter_id=request.meter_id,
            signing_key=self._signing_key,
            local_chain=chain,
        )
        resource.reconciliation_session = session
        return session.process_request(request, self._peer_public_key)

    def process_reconciliation_response(
        self, response: ReconciliationResponse,
    ) -> tuple[bool, list[Event]]:
        """Process a reconciliation response (agent-side)."""
        if self._peer_public_key is None:
            raise MeteringError("Peer public key not set")

        resource = self._get_resource(response.meter_id)
        session = resource.reconciliation_session
        if session is None:
            raise MeteringError("No reconciliation session for this meter")
        return session.process_response(response, self._peer_public_key)

    # -----------------------------------------------------------------
    # Server-side methods
    # -----------------------------------------------------------------

    def process_resource_request(
        self,
        request: ResourceRequest,
        token: bytes,
        granted_permissions: int,
        expiration: int,
        meter_id: bytes,
        constraints: Constraints | None = None,
        unit_price: int = 0,
    ) -> tuple[ResourceGrant, list[Event]]:
        """Process a ResourceRequest and issue a grant (server-side)."""
        resource = ManagedResource(
            request_id=request.request_id,
            resource_type=request.resource_type,
            resource_id=request.resource_id,
            token_id=token,
            meter_id=meter_id,
            granted_permissions=granted_permissions,
            expiration=expiration,
            state=ResourceState.ACTIVE,
            constraints=constraints,
            unit_price=unit_price,
        )
        self._resources[meter_id] = resource
        self._meters[meter_id] = Meter(
            session_id=request.request_id,
            meter_id=meter_id,
            issuer="server",
        )
        self._receipt_chains[meter_id] = ReceiptChain()

        grant = ResourceGrant(
            request_id=request.request_id,
            token=token,
            granted_permissions=granted_permissions,
            expiration=expiration,
            meter_id=meter_id,
        )
        events: list[Event] = [
            ResourceGranted(
                resource_id=request.resource_id,
                token_id=token,
                granted_permissions=granted_permissions,
            )
        ]
        return grant, events

    def deny_resource_request(
        self,
        request_id: bytes,
        reason: int,
        message: str = "",
        retry_after: int = 0,
    ) -> tuple[ResourceDeny, list[Event]]:
        """Deny a resource request (server-side)."""
        deny = ResourceDeny(
            request_id=request_id,
            reason=reason,
            message=message,
            retry_after=retry_after,
        )
        return deny, [
            ResourceDenied(
                resource_id=b"",
                reason=message or f"reason_code={reason}",
            )
        ]

    def record_usage(
        self,
        meter_id: bytes,
        units: int,
        data_bytes: int = 0,
    ) -> None:
        """Record usage for a resource (server-side)."""
        resource = self._get_resource(meter_id)
        if resource.state != ResourceState.ACTIVE:
            raise InvalidResourceStateError(
                f"Cannot record usage: resource is {resource.state.value}"
            )
        resource.cumulative_units += units
        resource.cumulative_bytes += data_bytes
        resource.cumulative_cost += units * resource.unit_price

        meter = self._meters.get(meter_id)
        if meter is not None:
            meter.record("usage", "consume", units=units)

    def generate_meter_report(
        self, meter_id: bytes,
    ) -> tuple[MeterReport, Receipt, list[Event]]:
        """Generate a signed MeterReport and Receipt (server-side)."""
        resource = self._get_resource(meter_id)
        if resource.state != ResourceState.ACTIVE:
            raise InvalidResourceStateError(
                f"Cannot generate report: resource is {resource.state.value}"
            )

        resource.last_report_seq += 1
        report = MeterReportHandler.create_meter_report(
            meter_id=meter_id,
            seq=resource.last_report_seq,
            usage_count=resource.cumulative_units,
            usage_bytes=resource.cumulative_bytes,
            cost=resource.cumulative_cost,
            signing_key=self._signing_key,
        )

        # Generate receipt
        chain = self._receipt_chains[meter_id]
        prev_hash = b""
        if len(chain) > 0:
            prev_hash = chain.receipts[-1].compute_hash()

        meter = self._meters.get(meter_id)
        if meter is not None:
            receipt = meter.generate_receipt(
                self._signing_key, prev_hash=prev_hash,
            )
        else:
            receipt = Receipt(
                records=[],
                total_units=resource.cumulative_units,
                total_cost=resource.cumulative_cost,
                issued_at=__import__("datetime").datetime.now(
                    __import__("datetime").UTC
                ),
                issuer="server",
                signature=b"",
                sequence_number=resource.last_report_seq,
                prev_hash=prev_hash,
                meter_id=meter_id,
            )
            sig = sign(self._signing_key, receipt.signable_bytes())
            receipt = Receipt(
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

        chain.append(receipt)

        events: list[Event] = [
            MeterReportReceived(
                meter_id=meter_id,
                usage_count=resource.cumulative_units,
                usage_bytes=resource.cumulative_bytes,
                timestamp=report.timestamp,
            )
        ]
        return report, receipt, events

    def process_meter_ack(self, ack: MeterAck) -> list[Event]:
        """Process a MeterAck received from the agent (server-side)."""
        if self._peer_public_key is None:
            raise MeteringError("Peer public key not set")

        MeterReportHandler.verify_meter_ack(ack, self._peer_public_key)

        resource = self._get_resource(ack.meter_id)
        resource.last_acked_seq = ack.acked_sequence

        return [
            MeterAckSent(
                meter_id=ack.meter_id,
                acked_count=ack.acked_usage,
            )
        ]

    def process_resource_release(
        self, release: ResourceRelease,
    ) -> list[Event]:
        """Process a ResourceRelease from the agent (server-side)."""
        if self._peer_public_key is None:
            raise MeteringError("Peer public key not set")

        # Verify release signature
        data = _encode_resource_release_data(
            release.token_id, release.final_usage,
        )
        try:
            verify(self._peer_public_key, data, release.signature)
        except (InvalidSignatureError, Exception) as e:
            raise InvalidMeterReportError(
                f"ResourceRelease signature verification failed: {e}"
            ) from e

        # Find resource by token_id
        resource = None
        for r in self._resources.values():
            if r.token_id == release.token_id:
                resource = r
                break
        if resource is None:
            raise ResourceNotFoundError(
                f"No resource found for token_id {release.token_id.hex()[:16]}"
            )

        resource.state = ResourceState.RELEASED
        return [
            ResourceReleased(
                resource_id=resource.resource_id,
                token_id=resource.token_id,
            )
        ]

    def suspend_resource(
        self,
        meter_id: bytes,
        reason: SuspendReason,
        resume_time: int = 0,
    ) -> tuple[ResourceSuspend, list[Event]]:
        """Suspend a resource (server-side)."""
        resource = self._get_resource(meter_id)
        if resource.state != ResourceState.ACTIVE:
            raise InvalidResourceStateError(
                f"Cannot suspend: resource is {resource.state.value}"
            )

        resource.state = ResourceState.SUSPENDED
        msg = ResourceSuspend(
            token_id=resource.token_id,
            reason=int(reason),
            resume_time=resume_time,
        )
        events: list[Event] = [
            ResourceSuspended(
                resource_id=resource.resource_id,
                token_id=resource.token_id,
                reason=int(reason),
                resume_time=resume_time,
            )
        ]
        return msg, events

    # -----------------------------------------------------------------
    # Constraint checking
    # -----------------------------------------------------------------

    def check_constraints(self, meter_id: bytes) -> ResourceSuspend | None:
        """Check if cumulative usage violates constraints.

        Returns a ResourceSuspend message if violated, None otherwise.
        """
        resource = self._get_resource(meter_id)
        constraints = resource.constraints
        if constraints is None:
            return None

        # Evaluate temporal attenuation if present
        if resource.temporal_attenuation is not None and resource.token_issued_at is not None:
            constraints = evaluate_temporal_constraints_raw(
                constraints, resource.temporal_attenuation, resource.token_issued_at,
            )

        # Check quantity_limit
        if (
            constraints.quantity_limit is not None
            and resource.cumulative_units > constraints.quantity_limit
        ):
            return ResourceSuspend(
                token_id=resource.token_id,
                reason=int(SuspendReason.QUANTITY_EXCEEDED),
            )

        # Check max_spend (budget)
        if (
            constraints.max_spend is not None
            and resource.cumulative_cost > constraints.max_spend
        ):
            return ResourceSuspend(
                token_id=resource.token_id,
                reason=int(SuspendReason.BUDGET_EXHAUSTED),
            )

        # Check time expiration (not_after)
        if constraints.not_after is not None:
            now_ts = int(time.time())
            expiry_ts = int(constraints.not_after.timestamp())
            if now_ts > expiry_ts:
                return ResourceSuspend(
                    token_id=resource.token_id,
                    reason=int(SuspendReason.TIME_EXPIRED),
                )

        return None
