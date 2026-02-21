"""Fixtures for framing module tests."""

from __future__ import annotations

import pytest


@pytest.fixture
def hmac_key() -> bytes:
    """Provide a test HMAC key."""
    return b"\x00" * 32
