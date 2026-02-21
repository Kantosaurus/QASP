"""Protocol event definitions.

This module defines typed events emitted by the QASP protocol.
Events are immutable dataclasses used to communicate protocol
state changes and received data to the application layer.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "AlertReceived",
    "ConnectionClosed",
    "ConnectionError",
    "DataReceived",
    "DataSent",
    "Event",
    "HandshakeComplete",
    "HandshakeFailed",
    "HandshakeInitiated",
    "HandshakeTimeout",
    "MeterAckSent",
    "MeterReportReceived",
    "ResourceDenied",
    "ResourceGranted",
    "ResourceReleased",
    "ResourceRequested",
    "StreamClosed",
    "StreamDataReceived",
    "StreamOpened",
    "TokenIssued",
    "TokenRevoked",
    "TokenVerified",
]


@dataclass(frozen=True)
class Event:
    """Base class for protocol events.

    All protocol events inherit from this class, enabling
    type-based dispatching in event handlers.
    """


# =============================================================================
# Handshake Events
# =============================================================================


@dataclass(frozen=True)
class HandshakeInitiated(Event):
    """Handshake has been initiated.

    Attributes:
        initiator: True if this side initiated the handshake (client),
                   False if responding (server).
    """

    initiator: bool


@dataclass(frozen=True)
class HandshakeComplete(Event):
    """Handshake completed successfully.

    Attributes:
        peer_public_key: The peer's public key from the handshake.
        session_id: Unique identifier for this session.
    """

    peer_public_key: bytes
    session_id: bytes


@dataclass(frozen=True)
class HandshakeFailed(Event):
    """Handshake failed.

    Attributes:
        reason: Description of why the handshake failed.
        fatal: Whether this is a fatal error requiring connection close.
    """

    reason: str
    fatal: bool = True


@dataclass(frozen=True)
class HandshakeTimeout(Event):
    """Handshake timed out waiting for peer response.

    Attributes:
        timeout_ms: The timeout duration in milliseconds.
        retry_count: Number of retries attempted so far.
        will_retry: Whether the connection will attempt a retry.
    """

    timeout_ms: int
    retry_count: int
    will_retry: bool


# =============================================================================
# Data Events
# =============================================================================


@dataclass(frozen=True)
class DataReceived(Event):
    """Application data received from peer.

    Attributes:
        data: The decrypted application data.
        sequence_number: The message sequence number.
    """

    data: bytes
    sequence_number: int = 0


@dataclass(frozen=True)
class DataSent(Event):
    """Application data successfully queued for sending.

    Attributes:
        length: Number of bytes queued.
        sequence_number: The assigned sequence number.
    """

    length: int
    sequence_number: int


# =============================================================================
# Capability/Token Events
# =============================================================================


@dataclass(frozen=True)
class TokenIssued(Event):
    """A capability token was issued.

    Attributes:
        token_id: Unique identifier for the token.
        resource_type: Type of resource the token grants access to.
        permissions: Bitmask of granted permissions.
    """

    token_id: bytes
    resource_type: str
    permissions: int


@dataclass(frozen=True)
class TokenRevoked(Event):
    """A capability token was revoked.

    Attributes:
        token_id: Unique identifier of the revoked token.
        reason: Optional reason for revocation.
    """

    token_id: bytes
    reason: str = ""


@dataclass(frozen=True)
class TokenVerified(Event):
    """A capability token was successfully verified.

    Attributes:
        token_id: Unique identifier of the verified token.
        resource_type: Type of resource the token grants access to.
        permissions: Bitmask of granted permissions.
    """

    token_id: bytes
    resource_type: str
    permissions: int


# =============================================================================
# Resource Events
# =============================================================================


@dataclass(frozen=True)
class ResourceRequested(Event):
    """A resource access was requested.

    Attributes:
        resource_id: Identifier of the requested resource.
        resource_type: Type of resource requested.
        requested_permissions: Bitmask of requested permissions.
    """

    resource_id: bytes
    resource_type: str
    requested_permissions: int


@dataclass(frozen=True)
class ResourceGranted(Event):
    """Resource access was granted.

    Attributes:
        resource_id: Identifier of the granted resource.
        token_id: Token granting access to the resource.
        granted_permissions: Bitmask of granted permissions.
    """

    resource_id: bytes
    token_id: bytes
    granted_permissions: int


@dataclass(frozen=True)
class ResourceDenied(Event):
    """Resource access was denied.

    Attributes:
        resource_id: Identifier of the denied resource.
        reason: Reason for denial.
    """

    resource_id: bytes
    reason: str


@dataclass(frozen=True)
class ResourceReleased(Event):
    """Resource access was released.

    Attributes:
        resource_id: Identifier of the released resource.
        token_id: Token that was released.
    """

    resource_id: bytes
    token_id: bytes


# =============================================================================
# Metering Events
# =============================================================================


@dataclass(frozen=True)
class MeterReportReceived(Event):
    """A metering report was received.

    Attributes:
        meter_id: Identifier of the meter.
        usage_count: Number of usage units reported.
        usage_bytes: Number of bytes used.
        timestamp: Unix timestamp of the report.
    """

    meter_id: bytes
    usage_count: int
    usage_bytes: int
    timestamp: int


@dataclass(frozen=True)
class MeterAckSent(Event):
    """A metering acknowledgment was sent.

    Attributes:
        meter_id: Identifier of the acknowledged meter.
        acked_count: Count value that was acknowledged.
    """

    meter_id: bytes
    acked_count: int


# =============================================================================
# Connection Events
# =============================================================================


@dataclass(frozen=True)
class ConnectionClosed(Event):
    """Connection was closed.

    Attributes:
        reason: Optional reason for the close.
        graceful: True if this was a graceful close, False if abrupt.
    """

    reason: str | None = None
    graceful: bool = True


@dataclass(frozen=True)
class ConnectionError(Event):
    """Connection error occurred.

    Attributes:
        error: Description of the error.
        fatal: Whether this is a fatal error requiring connection close.
    """

    error: str
    fatal: bool = True


@dataclass(frozen=True)
class AlertReceived(Event):
    """An alert message was received.

    Attributes:
        level: Alert severity level (1=warning, 2=fatal).
        description: Alert description code.
        message: Optional human-readable message.
    """

    level: int
    description: int
    message: str = ""


# =============================================================================
# Stream Multiplexing Events
# =============================================================================


@dataclass(frozen=True)
class StreamOpened(Event):
    """A new multiplexed stream was opened.

    Attributes:
        stream_id: The unique stream identifier.
        capability_token_id: Optional associated capability token.
    """

    stream_id: int
    capability_token_id: bytes | None = None


@dataclass(frozen=True)
class StreamDataReceived(Event):
    """Data was received on a multiplexed stream.

    Attributes:
        stream_id: The stream the data was received on.
        data: The received data.
        end_stream: True if this is the last data on the stream.
    """

    stream_id: int
    data: bytes
    end_stream: bool = False


@dataclass(frozen=True)
class StreamClosed(Event):
    """A multiplexed stream was closed.

    Attributes:
        stream_id: The closed stream's identifier.
        reason: Optional reason for closure.
    """

    stream_id: int
    reason: str = ""
