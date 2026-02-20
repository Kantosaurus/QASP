"""Pytest configuration and common fixtures.

This module provides shared fixtures for QASP tests.
"""

from __future__ import annotations

import pytest
from hypothesis import Phase, Verbosity, settings

# =============================================================================
# Hypothesis Configuration
# =============================================================================

# Default profile: balanced for local development
settings.register_profile(
    "default",
    max_examples=100,
    deadline=None,  # Disable deadline for crypto operations
    suppress_health_check=[],
    verbosity=Verbosity.normal,
)

# CI profile: more thorough testing for CI pipelines
settings.register_profile(
    "ci",
    max_examples=500,
    deadline=None,
    suppress_health_check=[],
    verbosity=Verbosity.normal,
    phases=[Phase.explicit, Phase.reuse, Phase.generate, Phase.shrink],
)

# Quick profile: fast iteration during development
settings.register_profile(
    "quick",
    max_examples=10,
    deadline=None,
    suppress_health_check=[],
    verbosity=Verbosity.quiet,
)

# Debug profile: verbose output for debugging
settings.register_profile(
    "debug",
    max_examples=10,
    deadline=None,
    suppress_health_check=[],
    verbosity=Verbosity.verbose,
)

# Load profile from HYPOTHESIS_PROFILE env var, default to "default"
settings.load_profile("default")


# =============================================================================
# Common Fixtures
# =============================================================================


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


@pytest.fixture
def hmac_key() -> bytes:
    """Return a sample HMAC key for testing."""
    return b"hmac_key_for_testing_32_bytes___"
