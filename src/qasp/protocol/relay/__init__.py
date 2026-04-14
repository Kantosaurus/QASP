"""QASP-Relay (CapFlow) sub-protocol.

See docs/capflow-prd.docx for the canonical specification.
"""

from qasp.protocol.relay.errors import (
    DeliveryTimeoutError,
    EPOCH_ROTATION_CODE,
    InvalidScmError,
    RelayErrorCode,
    RelayOverloadedError,
    RelayProtocolError,
    SessionBudgetExhaustedError,
    TargetNotConnectedError,
    TargetRejectedError,
)
from qasp.protocol.relay.manager import RelayManager
from qasp.protocol.relay.messages import (
    RelayData,
    RelayMessageType,
    RelaySessionAccept,
    RelaySessionClose,
    RelaySessionDeny,
    RelaySessionGrant,
    RelaySessionNotify,
    RelaySessionParams,
    RelaySessionRequest,
    decode_relay_frame,
)
from qasp.protocol.relay.receipts import (
    RelayReceipt,
    RelayReceiptChain,
    RelayReceiptChainError,
    build_session_summary,
    hash_payload,
)
from qasp.protocol.relay.scm import (
    DIRECTION_A_TO_B,
    DIRECTION_B_TO_A,
    EPOCH_INTERVAL_SEC,
    EpochKeyRing,
    derive_scm,
    validate_scm,
)
from qasp.protocol.relay.session import RelaySession, RelaySessionState, TokenBucket

__all__ = [
    # errors
    "DeliveryTimeoutError",
    "EPOCH_ROTATION_CODE",
    "InvalidScmError",
    "RelayErrorCode",
    "RelayOverloadedError",
    "RelayProtocolError",
    "SessionBudgetExhaustedError",
    "TargetNotConnectedError",
    "TargetRejectedError",
    # manager
    "RelayManager",
    # messages
    "RelayData",
    "RelayMessageType",
    "RelaySessionAccept",
    "RelaySessionClose",
    "RelaySessionDeny",
    "RelaySessionGrant",
    "RelaySessionNotify",
    "RelaySessionParams",
    "RelaySessionRequest",
    "decode_relay_frame",
    # receipts
    "RelayReceipt",
    "RelayReceiptChain",
    "RelayReceiptChainError",
    "build_session_summary",
    "hash_payload",
    # scm
    "DIRECTION_A_TO_B",
    "DIRECTION_B_TO_A",
    "EPOCH_INTERVAL_SEC",
    "EpochKeyRing",
    "derive_scm",
    "validate_scm",
    # session
    "RelaySession",
    "RelaySessionState",
    "TokenBucket",
]
