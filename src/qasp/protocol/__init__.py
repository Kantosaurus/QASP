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
    StreamClosed,
    StreamDataReceived,
    StreamOpened,
    TokenIssued,
    TokenRevoked,
    TokenVerified,
)
from .exceptions import (
    HandshakeAuthError,
    HandshakeError,
    HandshakeKEMError,
    HandshakeSuiteError,
    HandshakeTimeoutError,
    HandshakeVersionError,
)
from .handshake import (
    Handshake,
    HandshakeConfig,
    HandshakeErrorType,
    HandshakeFailure,
    HandshakeKeys,
    HandshakeState,
)
from .states import (
    VALID_TRANSITIONS,
    ConnectionState,
    ProtocolError,
    StateTransitionError,
    is_valid_transition,
)
from .stream import (
    Stream,
    StreamFlags,
    StreamFrame,
    StreamManager,
    StreamState,
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
    "Handshake",
    "HandshakeAuthError",
    "HandshakeComplete",
    "HandshakeConfig",
    "HandshakeError",
    "HandshakeErrorType",
    "HandshakeFailed",
    "HandshakeFailure",
    "HandshakeInitiated",
    "HandshakeKEMError",
    "HandshakeKeys",
    "HandshakeState",
    "HandshakeSuiteError",
    "HandshakeTimeoutError",
    "HandshakeVersionError",
    "MeterAckSent",
    "MeterReportReceived",
    "ProtocolError",
    "QASPConnection",
    "ResourceDenied",
    "ResourceGranted",
    "ResourceReleased",
    "ResourceRequested",
    "StateTransitionError",
    "Stream",
    "StreamClosed",
    "StreamDataReceived",
    "StreamFlags",
    "StreamFrame",
    "StreamManager",
    "StreamOpened",
    "StreamState",
    "TokenIssued",
    "TokenRevoked",
    "TokenVerified",
    "is_valid_transition",
]
