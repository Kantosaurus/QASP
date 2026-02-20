"""QASP protocol implementation.

This module implements the core QASP protocol:
- QASPConnection: Sans-I/O connection management
- QASP-Shake: Post-quantum handshake protocol
- Capability tokens for access control
- Usage metering and settlement
"""

from .connection import QASPConnection
from .events import (
    AlertReceived,
    ConnectionClosed,
    ConnectionError,
    DataReceived,
    DataSent,
    Event,
    HandshakeComplete,
    HandshakeFailed,
    HandshakeInitiated,
    MeterAckSent,
    MeterReportReceived,
    ResourceDenied,
    ResourceGranted,
    ResourceReleased,
    ResourceRequested,
    TokenIssued,
    TokenRevoked,
    TokenVerified,
)
from .states import (
    VALID_TRANSITIONS,
    ConnectionState,
    ProtocolError,
    StateTransitionError,
    is_valid_transition,
)

__all__ = [
    "VALID_TRANSITIONS",
    "AlertReceived",
    "ConnectionClosed",
    "ConnectionError",
    "ConnectionState",
    "DataReceived",
    "DataSent",
    "Event",
    "HandshakeComplete",
    "HandshakeFailed",
    "HandshakeInitiated",
    "MeterAckSent",
    "MeterReportReceived",
    "ProtocolError",
    "QASPConnection",
    "ResourceDenied",
    "ResourceGranted",
    "ResourceReleased",
    "ResourceRequested",
    "StateTransitionError",
    "TokenIssued",
    "TokenRevoked",
    "TokenVerified",
    "is_valid_transition",
]
