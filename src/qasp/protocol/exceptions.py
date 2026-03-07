"""Protocol exception definitions.

This module defines exceptions specific to the QASP handshake protocol.
These exceptions provide fine-grained error handling for handshake failures,
plus unified wire-level error codes (Section 1.6).
"""

from __future__ import annotations

from enum import IntEnum

from .states import ProtocolError

__all__ = [
    "HandshakeAuthError",
    "HandshakeError",
    "HandshakeKEMError",
    "HandshakeSuiteError",
    "HandshakeTimeoutError",
    "HandshakeUpgradeRequiredError",
    "HandshakeVersionError",
    "QASPErrorCode",
    "error_code_for_exception",
]


# =============================================================================
# Wire-level error codes (Section 1.6)
# =============================================================================


class QASPErrorCode(IntEnum):
    """Unified wire-level error codes for QASP protocol messages."""

    VERSION_MISMATCH = 0x01
    SUITE_MISMATCH = 0x02
    AUTH_FAILED = 0x03
    KEM_FAILED = 0x04
    TOKEN_EXPIRED = 0x05
    TOKEN_REVOKED = 0x06
    PERMISSION_DENIED = 0x07
    RATE_LIMITED = 0x08
    RESOURCE_UNAVAILABLE = 0x09
    BUDGET_EXHAUSTED = 0x0A
    RECONCILIATION_FAILED = 0x0B
    CHANNEL_CLOSED = 0x0C
    INTERNAL_ERROR = 0xFF


class HandshakeError(ProtocolError):
    """Base exception for handshake-specific errors.

    All handshake errors inherit from this class, enabling
    targeted exception handling for handshake failures.

    Attributes:
        alert_code: The QASP alert description code for this error.
    """

    alert_code: int = 0  # close_notify (generic)

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class HandshakeVersionError(HandshakeError):
    """Raised when protocol version negotiation fails.

    This occurs when the client and server cannot agree on a
    compatible protocol version.

    Attributes:
        client_version: The version requested by the client.
        server_version: The version offered by the server.
    """

    alert_code: int = 70  # protocol_version

    def __init__(
        self,
        message: str,
        client_version: tuple[int, int] | None = None,
        server_version: tuple[int, int] | None = None,
    ) -> None:
        super().__init__(message)
        self.client_version = client_version
        self.server_version = server_version


class HandshakeSuiteError(HandshakeError):
    """Raised when cipher suite negotiation fails.

    This occurs when the client and server cannot agree on a
    mutually supported cipher suite.

    Attributes:
        client_suites: Cipher suites offered by the client.
        server_suites: Cipher suites supported by the server.
    """

    alert_code: int = 71  # insufficient_security

    def __init__(
        self,
        message: str,
        client_suites: tuple[int, ...] | None = None,
        server_suites: tuple[int, ...] | None = None,
    ) -> None:
        super().__init__(message)
        self.client_suites = client_suites
        self.server_suites = server_suites


class HandshakeAuthError(HandshakeError):
    """Raised when authentication fails during handshake.

    This occurs when signature verification fails or certificate
    validation fails.

    Attributes:
        stage: The stage at which authentication failed (e.g., "server_sig", "client_sig").
    """

    alert_code: int = 51  # decrypt_error (signature failure)

    def __init__(self, message: str, stage: str = "") -> None:
        super().__init__(message)
        self.stage = stage


class HandshakeKEMError(HandshakeError):
    """Raised when KEM operations fail during handshake.

    This occurs when encapsulation or decapsulation fails,
    indicating potential key corruption or tampering.

    Attributes:
        operation: The KEM operation that failed ("encapsulate" or "decapsulate").
    """

    alert_code: int = 50  # decode_error

    def __init__(self, message: str, operation: str = "") -> None:
        super().__init__(message)
        self.operation = operation


class HandshakeUpgradeRequiredError(HandshakeError):
    """Raised when the server requires a post-quantum capable cipher suite.

    This occurs when the server supports PQ suites but the client only
    offers classical suites, triggering downgrade resistance.

    Attributes:
        client_suites: Cipher suites offered by the client.
        server_suites: Cipher suites supported by the server.
    """

    alert_code: int = 72  # upgrade_required

    def __init__(
        self,
        message: str,
        client_suites: tuple[int, ...] | None = None,
        server_suites: tuple[int, ...] | None = None,
    ) -> None:
        super().__init__(message)
        self.client_suites = client_suites
        self.server_suites = server_suites


class HandshakeTimeoutError(HandshakeError):
    """Raised when handshake times out.

    This occurs when a handshake step does not complete within
    the configured timeout period.

    Attributes:
        stage: The stage at which the timeout occurred.
        elapsed_ms: Time elapsed before timeout in milliseconds.
    """

    alert_code: int = 0  # close_notify

    def __init__(
        self,
        message: str,
        stage: str = "",
        elapsed_ms: int = 0,
    ) -> None:
        super().__init__(message)
        self.stage = stage
        self.elapsed_ms = elapsed_ms


# =============================================================================
# Error code mapping
# =============================================================================

_EXCEPTION_TO_ERROR_CODE: dict[type, QASPErrorCode] = {
    HandshakeVersionError: QASPErrorCode.VERSION_MISMATCH,
    HandshakeSuiteError: QASPErrorCode.SUITE_MISMATCH,
    HandshakeAuthError: QASPErrorCode.AUTH_FAILED,
    HandshakeKEMError: QASPErrorCode.KEM_FAILED,
    HandshakeUpgradeRequiredError: QASPErrorCode.SUITE_MISMATCH,
    HandshakeTimeoutError: QASPErrorCode.INTERNAL_ERROR,
}


def error_code_for_exception(exc: Exception) -> QASPErrorCode:
    """Map a protocol exception to a wire-level error code.

    Args:
        exc: The exception to map.

    Returns:
        The corresponding QASPErrorCode, or INTERNAL_ERROR for unknown types.
    """
    code = _EXCEPTION_TO_ERROR_CODE.get(type(exc))
    if code is not None:
        return code
    return QASPErrorCode.INTERNAL_ERROR
