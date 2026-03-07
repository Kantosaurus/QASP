"""Tests for unified wire-level error codes."""

from __future__ import annotations

import pytest

from qasp.protocol.exceptions import (
    HandshakeAuthError,
    HandshakeKEMError,
    HandshakeSuiteError,
    HandshakeVersionError,
    QASPErrorCode,
    error_code_for_exception,
)


class TestQASPErrorCode:
    """Tests for the QASPErrorCode enum."""

    def test_has_13_codes(self) -> None:
        assert len(QASPErrorCode) == 13

    def test_internal_error_is_0xff(self) -> None:
        assert QASPErrorCode.INTERNAL_ERROR == 0xFF

    def test_version_mismatch_is_0x01(self) -> None:
        assert QASPErrorCode.VERSION_MISMATCH == 0x01

    def test_channel_closed_is_0x0c(self) -> None:
        assert QASPErrorCode.CHANNEL_CLOSED == 0x0C

    def test_all_codes_are_unique(self) -> None:
        values = [c.value for c in QASPErrorCode]
        assert len(values) == len(set(values))


class TestErrorCodeForException:
    """Tests for error_code_for_exception mapping."""

    def test_version_error_maps(self) -> None:
        exc = HandshakeVersionError("bad version")
        assert error_code_for_exception(exc) == QASPErrorCode.VERSION_MISMATCH

    def test_suite_error_maps(self) -> None:
        exc = HandshakeSuiteError("no common suite")
        assert error_code_for_exception(exc) == QASPErrorCode.SUITE_MISMATCH

    def test_auth_error_maps(self) -> None:
        exc = HandshakeAuthError("sig failed")
        assert error_code_for_exception(exc) == QASPErrorCode.AUTH_FAILED

    def test_kem_error_maps(self) -> None:
        exc = HandshakeKEMError("decap failed")
        assert error_code_for_exception(exc) == QASPErrorCode.KEM_FAILED

    def test_unknown_exception_returns_internal(self) -> None:
        exc = ValueError("something unexpected")
        assert error_code_for_exception(exc) == QASPErrorCode.INTERNAL_ERROR

    def test_generic_exception_returns_internal(self) -> None:
        exc = Exception("generic")
        assert error_code_for_exception(exc) == QASPErrorCode.INTERNAL_ERROR
