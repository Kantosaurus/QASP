"""QASP-Relay error codes (PRD Table 6) and exception hierarchy."""

from __future__ import annotations

from enum import IntEnum

from qasp.protocol.states import ProtocolError

__all__ = [
    "DeliveryTimeoutError",
    "EPOCH_ROTATION_CODE",
    "InvalidScmError",
    "RelayErrorCode",
    "RelayOverloadedError",
    "RelayProtocolError",
    "SessionBudgetExhaustedError",
    "TargetNotConnectedError",
    "TargetRejectedError",
]


class RelayErrorCode(IntEnum):
    TARGET_NOT_CONNECTED = 0x20
    TARGET_REJECTED = 0x21
    INVALID_SCM = 0x22
    SESSION_BUDGET_EXHAUSTED = 0x23
    RELAY_OVERLOADED = 0x24
    DELIVERY_TIMEOUT = 0x25


EPOCH_ROTATION_CODE = 0x26  # Informational: pushed via RelayEpochUpdate, not an error.


class RelayProtocolError(ProtocolError):
    """Base exception for QASP-Relay protocol errors."""

    code: int = 0

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class TargetNotConnectedError(RelayProtocolError):
    code = RelayErrorCode.TARGET_NOT_CONNECTED


class TargetRejectedError(RelayProtocolError):
    code = RelayErrorCode.TARGET_REJECTED


class InvalidScmError(RelayProtocolError):
    code = RelayErrorCode.INVALID_SCM


class SessionBudgetExhaustedError(RelayProtocolError):
    code = RelayErrorCode.SESSION_BUDGET_EXHAUSTED


class RelayOverloadedError(RelayProtocolError):
    code = RelayErrorCode.RELAY_OVERLOADED


class DeliveryTimeoutError(RelayProtocolError):
    code = RelayErrorCode.DELIVERY_TIMEOUT
