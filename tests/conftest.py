"""Pytest configuration and common fixtures.

This module provides shared fixtures for QASP tests.
"""

from __future__ import annotations

import pytest


@pytest.fixture
def sample_public_key() -> bytes:
    """Return a sample public key for testing."""
    return b"sample_public_key_32_bytes______"


@pytest.fixture
def sample_private_key() -> bytes:
    """Return a sample private key for testing."""
    return b"sample_private_key_32_bytes_____"


@pytest.fixture
def sample_did() -> str:
    """Return a sample DID for testing."""
    return "did:qasp:test123456789"


@pytest.fixture
def sample_session_id() -> bytes:
    """Return a sample session ID for testing."""
    return b"session_id_16___"
