"""Shared fixtures for trust module tests."""

from __future__ import annotations

import hashlib

import pytest

from qasp.crypto import signatures
from qasp.identity import DID, create_did

# =============================================================================
# ML-DSA-65 Keypair Fixtures for Auditors
# =============================================================================


@pytest.fixture
def auditor_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh ML-DSA-65 keypair for an auditor."""
    return signatures.generate_keypair()


@pytest.fixture
def auditor_public_key(auditor_keypair: tuple[bytes, bytes]) -> bytes:
    """Extract auditor's public key."""
    return auditor_keypair[0]


@pytest.fixture
def auditor_secret_key(auditor_keypair: tuple[bytes, bytes]) -> bytes:
    """Extract auditor's secret key."""
    return auditor_keypair[1]


@pytest.fixture
def auditor_did(auditor_public_key: bytes) -> DID:
    """Create a DID for the auditor."""
    did, _ = create_did(auditor_public_key)
    return did


# =============================================================================
# ML-DSA-65 Keypair Fixtures for Agents
# =============================================================================


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
def agent_did(agent_public_key: bytes) -> DID:
    """Create a DID for the agent."""
    did, _ = create_did(agent_public_key)
    return did


# =============================================================================
# Second Agent Fixtures (for registry tests)
# =============================================================================


@pytest.fixture
def second_agent_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh ML-DSA-65 keypair for a second agent."""
    return signatures.generate_keypair()


@pytest.fixture
def second_agent_public_key(second_agent_keypair: tuple[bytes, bytes]) -> bytes:
    """Extract second agent's public key."""
    return second_agent_keypair[0]


@pytest.fixture
def second_agent_did(second_agent_public_key: bytes) -> DID:
    """Create a DID for the second agent."""
    did, _ = create_did(second_agent_public_key)
    return did


# =============================================================================
# Sample Code Hash Fixture
# =============================================================================


@pytest.fixture
def sample_code_hash() -> bytes:
    """Generate a sample SHA-384 code version hash (48 bytes)."""
    return hashlib.sha384(b"sample_code_version_1.0.0").digest()


@pytest.fixture
def different_code_hash() -> bytes:
    """Generate a different SHA-384 code version hash (48 bytes)."""
    return hashlib.sha384(b"sample_code_version_2.0.0").digest()


# =============================================================================
# Reputation Model Fixtures
# =============================================================================


@pytest.fixture
def reputation_model():  # noqa: ANN201
    """Create a fresh ReputationModel with uniform prior."""
    from qasp.trust.reputation import ReputationModel

    return ReputationModel()


# =============================================================================
# Behavioral Verifier Fixtures
# =============================================================================


@pytest.fixture
def behavioral_verifier(agent_did: DID):  # noqa: ANN201
    """Create a BehavioralVerifier for the test agent."""
    from qasp.trust.behavioral import BehavioralVerifier

    return BehavioralVerifier(did=str(agent_did))
