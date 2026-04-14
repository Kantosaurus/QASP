"""Tests for QASP-Relay error codes and exception hierarchy."""

import pytest

from qasp.protocol.relay.errors import (
    EPOCH_ROTATION_CODE,
    DeliveryTimeoutError,
    InvalidScmError,
    RelayErrorCode,
    RelayOverloadedError,
    RelayProtocolError,
    SessionBudgetExhaustedError,
    TargetNotConnectedError,
    TargetRejectedError,
)


class TestRelayErrorCodes:
    """Error codes match PRD Table 6 (0x20–0x26)."""

    def test_target_not_connected_code(self):
        assert RelayErrorCode.TARGET_NOT_CONNECTED == 0x20

    def test_target_rejected_code(self):
        assert RelayErrorCode.TARGET_REJECTED == 0x21

    def test_invalid_scm_code(self):
        assert RelayErrorCode.INVALID_SCM == 0x22

    def test_budget_exhausted_code(self):
        assert RelayErrorCode.SESSION_BUDGET_EXHAUSTED == 0x23

    def test_relay_overloaded_code(self):
        assert RelayErrorCode.RELAY_OVERLOADED == 0x24

    def test_delivery_timeout_code(self):
        assert RelayErrorCode.DELIVERY_TIMEOUT == 0x25

    def test_epoch_rotation_code_is_info_not_error(self):
        assert EPOCH_ROTATION_CODE == 0x26


class TestRelayExceptions:
    """Exception classes carry their code and a message."""

    @pytest.mark.parametrize(
        "cls,expected_code",
        [
            (TargetNotConnectedError, 0x20),
            (TargetRejectedError, 0x21),
            (InvalidScmError, 0x22),
            (SessionBudgetExhaustedError, 0x23),
            (RelayOverloadedError, 0x24),
            (DeliveryTimeoutError, 0x25),
        ],
    )
    def test_exception_code(self, cls, expected_code):
        exc = cls("boom")
        assert exc.code == expected_code
        assert str(exc) == "boom"
        assert isinstance(exc, RelayProtocolError)
