"""Shared fixtures for bridge module tests."""

from __future__ import annotations

from unittest.mock import MagicMock, PropertyMock

import pytest

from qasp.bridges.a2a_bridge import (
    AgentCapabilities,
    AgentCard,
    AgentSkill,
    QASPExtension,
)
from qasp.bridges.mcp_bridge import (
    MCPServerIdentity,
    generate_mcp_server_identity,
    inject_qasp_token,
)
from qasp.crypto import signatures
from qasp.identity import DID, DIDDocument, DIDRegistry, create_did
from qasp.protocol.capability import CapabilityToken, create_token
from qasp.protocol.connection import QASPConnection
from qasp.protocol.revocation import CertificateRevocationList
from qasp.protocol.states import ConnectionState

# =============================================================================
# ML-DSA-65 Keypair Fixtures
# =============================================================================


@pytest.fixture
def agent_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh ML-DSA-65 keypair for the local agent."""
    return signatures.generate_keypair()


@pytest.fixture
def agent_public_key(agent_keypair: tuple[bytes, bytes]) -> bytes:
    return agent_keypair[0]


@pytest.fixture
def agent_secret_key(agent_keypair: tuple[bytes, bytes]) -> bytes:
    return agent_keypair[1]


@pytest.fixture
def remote_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh ML-DSA-65 keypair for a remote agent."""
    return signatures.generate_keypair()


@pytest.fixture
def remote_public_key(remote_keypair: tuple[bytes, bytes]) -> bytes:
    return remote_keypair[0]


@pytest.fixture
def remote_secret_key(remote_keypair: tuple[bytes, bytes]) -> bytes:
    return remote_keypair[1]


@pytest.fixture
def delegate_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh ML-DSA-65 keypair for a delegate."""
    return signatures.generate_keypair()


@pytest.fixture
def delegate_public_key(delegate_keypair: tuple[bytes, bytes]) -> bytes:
    return delegate_keypair[0]


@pytest.fixture
def delegate_secret_key(delegate_keypair: tuple[bytes, bytes]) -> bytes:
    return delegate_keypair[1]


# =============================================================================
# DID Fixtures
# =============================================================================


@pytest.fixture
def agent_did(agent_public_key: bytes) -> DID:
    did, _ = create_did(agent_public_key)
    return did


@pytest.fixture
def remote_did(remote_public_key: bytes) -> DID:
    did, _ = create_did(remote_public_key)
    return did


@pytest.fixture
def delegate_did(delegate_public_key: bytes) -> DID:
    did, _ = create_did(delegate_public_key)
    return did


# =============================================================================
# Mock Connection
# =============================================================================


@pytest.fixture
def mock_connection() -> MagicMock:
    """Mock QASPConnection with is_established=True and mock session_id."""
    conn = MagicMock(spec=QASPConnection)
    type(conn).is_established = PropertyMock(return_value=True)
    type(conn).is_closed = PropertyMock(return_value=False)
    type(conn).state = PropertyMock(return_value=ConnectionState.ESTABLISHED)
    type(conn).session_id = PropertyMock(return_value=b"test_session_id_")
    conn.send_data.return_value = []
    return conn


# =============================================================================
# Capability Token Fixtures
# =============================================================================


@pytest.fixture
def sample_capability_token(
    agent_did: DID,
    agent_secret_key: bytes,
    remote_did: DID,
) -> CapabilityToken:
    """Pre-built token with max_delegation_depth=3."""
    return create_token(
        issuer_did=agent_did,
        issuer_secret_key=agent_secret_key,
        subject_did=remote_did,
        resource_uri="qasp://a2a/test/skills/summarize",
        verbs={"read", "execute"},
        max_delegation_depth=3,
    )


# =============================================================================
# Agent Card Fixtures
# =============================================================================


@pytest.fixture
def sample_skills() -> tuple[AgentSkill, ...]:
    return (
        AgentSkill(
            id="summarize",
            name="Summarize",
            description="Summarize text",
            tags=("read", "execute"),
        ),
        AgentSkill(
            id="translate",
            name="Translate",
            description="Translate text",
            tags=("read", "write"),
        ),
    )


@pytest.fixture
def sample_qasp_extension(agent_did: DID) -> QASPExtension:
    return QASPExtension(
        agent_did=str(agent_did),
        qasp_endpoint="qasp://localhost:9000",
        supported_cipher_suites=("ML-KEM-768+ML-DSA-65",),
    )


@pytest.fixture
def sample_agent_card(
    sample_skills: tuple[AgentSkill, ...],
    sample_qasp_extension: QASPExtension,
) -> AgentCard:
    """An AgentCard with skills and QASP extension."""
    caps = AgentCapabilities(
        extensions=(sample_qasp_extension.to_extension_dict(),),
    )
    return AgentCard(
        name="TestAgent",
        description="A test A2A agent",
        url="https://agent.example.com",
        skills=sample_skills,
        capabilities=caps,
    )


# =============================================================================
# MCP Bridge Fixtures
# =============================================================================


@pytest.fixture
def bridge_issuer_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh ML-DSA-65 keypair for the MCP bridge issuer."""
    return signatures.generate_keypair()


@pytest.fixture
def bridge_issuer_public_key(bridge_issuer_keypair: tuple[bytes, bytes]) -> bytes:
    return bridge_issuer_keypair[0]


@pytest.fixture
def bridge_issuer_secret_key(bridge_issuer_keypair: tuple[bytes, bytes]) -> bytes:
    return bridge_issuer_keypair[1]


@pytest.fixture
def bridge_subject_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh ML-DSA-65 keypair for the MCP bridge subject."""
    return signatures.generate_keypair()


@pytest.fixture
def bridge_subject_public_key(bridge_subject_keypair: tuple[bytes, bytes]) -> bytes:
    return bridge_subject_keypair[0]


@pytest.fixture
def bridge_subject_secret_key(bridge_subject_keypair: tuple[bytes, bytes]) -> bytes:
    return bridge_subject_keypair[1]


@pytest.fixture
def bridge_issuer_did(bridge_issuer_public_key: bytes) -> DID:
    did, _ = create_did(bridge_issuer_public_key)
    return did


@pytest.fixture
def bridge_issuer_did_document(bridge_issuer_public_key: bytes) -> DIDDocument:
    _, doc = create_did(bridge_issuer_public_key)
    return doc


@pytest.fixture
def bridge_subject_did(bridge_subject_public_key: bytes) -> DID:
    did, _ = create_did(bridge_subject_public_key)
    return did


@pytest.fixture
def bridge_subject_did_document(bridge_subject_public_key: bytes) -> DIDDocument:
    _, doc = create_did(bridge_subject_public_key)
    return doc


@pytest.fixture
def bridge_did_registry(
    bridge_issuer_did_document: DIDDocument,
    bridge_subject_did_document: DIDDocument,
) -> DIDRegistry:
    registry = DIDRegistry()
    registry.register(bridge_issuer_did_document)
    registry.register(bridge_subject_did_document)
    return registry


@pytest.fixture
def bridge_crl() -> CertificateRevocationList:
    return CertificateRevocationList()


@pytest.fixture
def server_identity() -> MCPServerIdentity:
    return generate_mcp_server_identity("test-server")


@pytest.fixture
def mcp_sample_capability_token(
    bridge_issuer_did: DID,
    bridge_issuer_secret_key: bytes,
    bridge_subject_did: DID,
) -> CapabilityToken:
    """A pre-built token for qasp://mcp/tools/test_tool with {execute}."""
    return create_token(
        issuer_did=bridge_issuer_did,
        issuer_secret_key=bridge_issuer_secret_key,
        subject_did=bridge_subject_did,
        resource_uri="qasp://mcp/tools/test_tool",
        verbs={"execute"},
    )


@pytest.fixture
def mcp_sample_token_meta(mcp_sample_capability_token: CapabilityToken) -> dict[str, str]:
    """The inject_qasp_token() output for mcp_sample_capability_token."""
    return inject_qasp_token(mcp_sample_capability_token)
