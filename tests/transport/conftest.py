"""Shared fixtures for transport module tests."""

from __future__ import annotations

import socket
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest

from qasp.transport.registry import AgentRegistry, CapEntry, create_registry_entry

if TYPE_CHECKING:
    from qasp.identity.did import DIDDocument, DIDRegistry
    from qasp.transport.discover import CapabilityAdvertisement
    from qasp.transport.tcp import TCPServer, TCPTransport


@dataclass
class MockKeypair:
    """Mock keypair for testing without crypto dependencies."""

    public_key: bytes = b"mock_public_key_" + b"0" * 16
    kem_public_key: bytes = b"mock_kem_pk_" + b"0" * 20
    sig_public_key: bytes = b"mock_sig_pk_" + b"0" * 20


class MockQASPConnection:
    """Mock QASPConnection for testing transport without crypto dependencies.

    This provides the minimal interface needed by TCPTransport for testing
    the transport layer in isolation.
    """

    def __init__(
        self,
        keypair: MockKeypair | None = None,
        is_client: bool = True,
    ) -> None:
        self._keypair = keypair or MockKeypair()
        self._is_client = is_client
        self._send_buffer = bytearray()
        self._recv_buffer = bytearray()

    def initiate_handshake(self) -> list:
        """Mock handshake initiation."""
        return []

    def send_data(self, data: bytes) -> list:
        """Mock sending data."""
        self._send_buffer.extend(data)
        return []

    def receive_bytes(self, data: bytes) -> list:
        """Mock receiving bytes."""
        self._recv_buffer.extend(data)
        return []

    def bytes_to_send(self) -> bytes:
        """Return any pending bytes to send."""
        data = bytes(self._send_buffer)
        self._send_buffer.clear()
        return data


@pytest.fixture
def mock_keypair() -> MockKeypair:
    """Create a mock keypair for testing."""
    return MockKeypair()


@pytest.fixture
def mock_connection(mock_keypair: MockKeypair) -> MockQASPConnection:
    """Create a mock QASPConnection for testing."""
    return MockQASPConnection(mock_keypair, is_client=True)


@pytest.fixture
def server_connection(mock_keypair: MockKeypair) -> MockQASPConnection:
    """Create a server-side mock QASPConnection for testing."""
    return MockQASPConnection(mock_keypair, is_client=False)


@pytest.fixture
def connection_factory(
    mock_keypair: MockKeypair,
) -> Callable[[], MockQASPConnection]:
    """Create a factory function for server-side connections."""

    def factory() -> MockQASPConnection:
        return MockQASPConnection(mock_keypair, is_client=False)

    return factory


@pytest.fixture
def free_port() -> int:
    """Get an available port for testing."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port


@pytest.fixture
async def echo_server(
    connection_factory: Callable[[], MockQASPConnection],
) -> TCPServer:
    """Start an echo server for testing.

    The server echoes back any data it receives.
    """
    from qasp.transport.tcp import TCPServer

    async def echo_handler(transport: TCPTransport) -> None:
        try:
            while True:
                data = await transport.receive(timeout=5.0)
                await transport.send(data)
        except Exception:
            pass  # Connection closed or error

    server = TCPServer(connection_factory, echo_handler)
    await server.start("127.0.0.1", 0)
    yield server
    await server.stop()


@pytest.fixture
async def multi_echo_server(
    connection_factory: Callable[[], MockQASPConnection],
) -> TCPServer:
    """Start a multi-message echo server for testing.

    The server echoes back any data it receives until connection closes.
    """
    from qasp.transport.tcp import TCPServer

    async def echo_handler(transport: TCPTransport) -> None:
        try:
            while True:
                data = await transport.receive(timeout=5.0)
                await transport.send(data)
        except Exception:
            pass

    server = TCPServer(connection_factory, echo_handler)
    await server.start("127.0.0.1", 0)
    yield server
    await server.stop()


@pytest.fixture
def discovery_keypair() -> tuple[bytes, bytes]:
    """Real ML-DSA-65 keypair for discovery integration tests."""
    from qasp.crypto.signatures import generate_keypair

    return generate_keypair()


@pytest.fixture
def mock_did() -> str:
    """Mock DID string for testing."""
    return "did:qasp:test1234567890abcdef"


@pytest.fixture
def sample_advertisement(mock_did: str) -> CapabilityAdvertisement:
    """Pre-built unsigned CapabilityAdvertisement for testing."""
    from qasp.transport.discover import CapabilityAdvertisement

    return CapabilityAdvertisement(
        did=mock_did,
        endpoints=(("127.0.0.1", 8443),),
        capabilities=frozenset({"invoke", "delegate"}),
        ttl=300,
        created_at=time.time(),
        signature=b"",
    )


@pytest.fixture
def did_registry_with_doc(
    discovery_keypair: tuple[bytes, bytes],
) -> tuple[DIDRegistry, DIDDocument, str]:
    """Create a DID registry with a registered document. Returns (registry, doc, did_str)."""
    from qasp.identity.did import DIDRegistry, create_did

    pub, _sec = discovery_keypair
    did, doc = create_did(pub)
    registry = DIDRegistry()
    registry.register(doc)
    return registry, doc, str(did)


@pytest.fixture
def agent_registry(
    did_registry_with_doc: tuple[DIDRegistry, DIDDocument, str],
) -> AgentRegistry:
    """Fresh AgentRegistry with injected DID registry."""
    registry, _doc, _did = did_registry_with_doc
    return AgentRegistry(did_registry=registry)


@pytest.fixture
def sample_cap_entries() -> tuple[CapEntry, ...]:
    """Tuple of sample CapEntry objects with varied URIs/verbs."""
    return (
        CapEntry(
            resource_uri="qasp://myhost/gpu/infer",
            verbs=frozenset({"invoke", "read"}),
            description="GPU inference endpoint",
        ),
        CapEntry(
            resource_uri="qasp://myhost/storage/upload",
            verbs=frozenset({"write", "delete"}),
            description="Storage upload endpoint",
        ),
        CapEntry(
            resource_uri="qasp://myhost/api/v1/status",
            verbs=frozenset({"read"}),
            description="Status API",
        ),
    )


@pytest.fixture
def sample_registry_entry(
    discovery_keypair: tuple[bytes, bytes],
    did_registry_with_doc: tuple[DIDRegistry, DIDDocument, str],
    sample_cap_entries: tuple[CapEntry, ...],
) -> RegistryEntry:
    """Signed RegistryEntry for testing."""
    from qasp.transport.registry import RegistryEntry, create_registry_entry

    _pub, sec = discovery_keypair
    _registry, doc, did_str = did_registry_with_doc
    return create_registry_entry(
        agent_did=did_str,
        secret_key=sec,
        did_document=doc,
        capabilities=sample_cap_entries,
        trust_score=0.85,
        audit_vcs=(),
        endpoint=("127.0.0.1", 9000),
    )
