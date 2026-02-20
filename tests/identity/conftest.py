"""Shared fixtures for identity module tests."""

from __future__ import annotations

import pytest

from qasp.crypto import signatures
from qasp.identity import DID, create_did


# =============================================================================
# ML-DSA-65 Keypair Fixtures for Identity
# =============================================================================


@pytest.fixture
def owner_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh ML-DSA-65 keypair for an owner."""
    return signatures.generate_keypair()


@pytest.fixture
def owner_public_key(owner_keypair: tuple[bytes, bytes]) -> bytes:
    """Extract owner's public key."""
    return owner_keypair[0]


@pytest.fixture
def owner_secret_key(owner_keypair: tuple[bytes, bytes]) -> bytes:
    """Extract owner's secret key."""
    return owner_keypair[1]


@pytest.fixture
def agent_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh ML-DSA-65 keypair for an agent."""
    return signatures.generate_keypair()


@pytest.fixture
def agent_public_key(agent_keypair: tuple[bytes, bytes]) -> bytes:
    """Extract agent's public key."""
    return agent_keypair[0]


@pytest.fixture
def agent_secret_key(agent_keypair: tuple[bytes, bytes]) -> bytes:
    """Extract agent's secret key."""
    return agent_keypair[1]


@pytest.fixture
def second_agent_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh ML-DSA-65 keypair for a second agent (delegation)."""
    return signatures.generate_keypair()


@pytest.fixture
def second_agent_public_key(second_agent_keypair: tuple[bytes, bytes]) -> bytes:
    """Extract second agent's public key."""
    return second_agent_keypair[0]


@pytest.fixture
def second_agent_secret_key(second_agent_keypair: tuple[bytes, bytes]) -> bytes:
    """Extract second agent's secret key."""
    return second_agent_keypair[1]


# =============================================================================
# DID Fixtures
# =============================================================================


@pytest.fixture
def sample_owner_did(owner_public_key: bytes) -> DID:
    """Create a DID for the owner."""
    did, _ = create_did(owner_public_key)
    return did


@pytest.fixture
def sample_agent_did(agent_public_key: bytes) -> DID:
    """Create a DID for the agent."""
    did, _ = create_did(agent_public_key)
    return did


@pytest.fixture
def sample_second_agent_did(second_agent_public_key: bytes) -> DID:
    """Create a DID for the second agent."""
    did, _ = create_did(second_agent_public_key)
    return did
