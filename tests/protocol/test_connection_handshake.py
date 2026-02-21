"""Integration tests for QASPConnection handshake."""

from __future__ import annotations

import secrets

import pytest

from qasp.crypto import hybrid, signatures
from qasp.protocol import (
    ConnectionState,
    HandshakeComplete,
    HandshakeFailed,
    HandshakeInitiated,
    QASPConnection,
)
from qasp.protocol.handshake import HandshakeConfig

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def shared_hmac_key() -> bytes:
    """Generate a shared HMAC key for client/server."""
    return secrets.token_bytes(32)


@pytest.fixture
def client_kem_keypair() -> hybrid.HybridKeypair:
    """Generate a fresh hybrid keypair for the client."""
    return hybrid.generate_keypair()


@pytest.fixture
def server_kem_keypair() -> hybrid.HybridKeypair:
    """Generate a fresh hybrid keypair for the server."""
    return hybrid.generate_keypair()


@pytest.fixture
def client_sig_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh signature keypair for the client."""
    return signatures.generate_keypair()


@pytest.fixture
def server_sig_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh signature keypair for the server."""
    return signatures.generate_keypair()


@pytest.fixture
def client_connection(
    client_kem_keypair: hybrid.HybridKeypair,
    client_sig_keypair: tuple[bytes, bytes],
    shared_hmac_key: bytes,
) -> QASPConnection:
    """Create a client connection instance."""
    return QASPConnection(
        kem_keypair=client_kem_keypair,
        sig_keypair=client_sig_keypair,
        is_client=True,
        hmac_key=shared_hmac_key,
    )


@pytest.fixture
def server_connection(
    server_kem_keypair: hybrid.HybridKeypair,
    server_sig_keypair: tuple[bytes, bytes],
    shared_hmac_key: bytes,
) -> QASPConnection:
    """Create a server connection instance."""
    return QASPConnection(
        kem_keypair=server_kem_keypair,
        sig_keypair=server_sig_keypair,
        is_client=False,
        hmac_key=shared_hmac_key,
    )


# =============================================================================
# Full Handshake Tests
# =============================================================================


class TestFullHandshakeClientServer:
    """Test complete handshake roundtrip."""

    def test_full_handshake_completes(
        self,
        client_connection: QASPConnection,
        server_connection: QASPConnection,
    ) -> None:
        """Full handshake should complete successfully."""
        # Client initiates
        events = client_connection.initiate_handshake()
        assert any(isinstance(e, HandshakeInitiated) for e in events)
        assert client_connection.state == ConnectionState.HELLO_SENT

        # Get ClientHello bytes and send to server
        client_hello_bytes = client_connection.bytes_to_send()
        assert len(client_hello_bytes) > 0

        # Server processes ClientHello
        events = server_connection.receive_bytes(client_hello_bytes)
        assert any(isinstance(e, HandshakeInitiated) for e in events)
        assert server_connection.state == ConnectionState.HELLO_RECEIVED

        # Get ServerHello bytes and send to client
        server_hello_bytes = server_connection.bytes_to_send()
        assert len(server_hello_bytes) > 0

        # Client processes ServerHello (also sends ClientAuth)
        events = client_connection.receive_bytes(server_hello_bytes)
        assert any(isinstance(e, HandshakeComplete) for e in events)
        assert client_connection.state == ConnectionState.ESTABLISHED

        # Get ClientAuth bytes and send to server
        client_auth_bytes = client_connection.bytes_to_send()
        assert len(client_auth_bytes) > 0

        # Server processes ClientAuth
        events = server_connection.receive_bytes(client_auth_bytes)
        assert any(isinstance(e, HandshakeComplete) for e in events)
        assert server_connection.state == ConnectionState.ESTABLISHED

    def test_both_sides_have_matching_session_keys(
        self,
        client_connection: QASPConnection,
        server_connection: QASPConnection,
    ) -> None:
        """Both sides should derive the same session key."""
        # Complete handshake
        client_connection.initiate_handshake()
        server_connection.receive_bytes(client_connection.bytes_to_send())
        client_connection.receive_bytes(server_connection.bytes_to_send())
        server_connection.receive_bytes(client_connection.bytes_to_send())

        # Verify session keys match
        assert client_connection.session_key is not None
        assert server_connection.session_key is not None
        assert client_connection.session_key == server_connection.session_key

    def test_both_sides_have_matching_session_ids(
        self,
        client_connection: QASPConnection,
        server_connection: QASPConnection,
    ) -> None:
        """Both sides should derive the same session ID."""
        # Complete handshake
        client_connection.initiate_handshake()
        server_connection.receive_bytes(client_connection.bytes_to_send())
        client_connection.receive_bytes(server_connection.bytes_to_send())
        server_connection.receive_bytes(client_connection.bytes_to_send())

        # Verify session IDs match
        assert client_connection.session_id is not None
        assert server_connection.session_id is not None
        assert client_connection.session_id == server_connection.session_id

    def test_session_key_is_32_bytes(
        self,
        client_connection: QASPConnection,
        server_connection: QASPConnection,
    ) -> None:
        """Session key should be 32 bytes for AES-256."""
        # Complete handshake
        client_connection.initiate_handshake()
        server_connection.receive_bytes(client_connection.bytes_to_send())
        client_connection.receive_bytes(server_connection.bytes_to_send())
        server_connection.receive_bytes(client_connection.bytes_to_send())

        assert client_connection.session_key is not None
        assert len(client_connection.session_key) == 32

    def test_can_send_data_after_handshake(
        self,
        client_connection: QASPConnection,
        server_connection: QASPConnection,
    ) -> None:
        """Should be able to send data after handshake completes."""
        # Complete handshake
        client_connection.initiate_handshake()
        server_connection.receive_bytes(client_connection.bytes_to_send())
        client_connection.receive_bytes(server_connection.bytes_to_send())
        server_connection.receive_bytes(client_connection.bytes_to_send())

        # Send data
        events = client_connection.send_data(b"Hello, server!")
        assert len(events) > 0

        # Get data bytes
        data_bytes = client_connection.bytes_to_send()
        assert len(data_bytes) > 0


# =============================================================================
# Hybrid Mode Tests
# =============================================================================


class TestHandshakeWithHybridMode:
    """Test handshake with hybrid X25519+ML-KEM mode."""

    def test_hybrid_mode_enabled_by_default(
        self,
        client_connection: QASPConnection,
        server_connection: QASPConnection,
    ) -> None:
        """Hybrid mode should be enabled by default."""
        # Complete handshake
        client_connection.initiate_handshake()
        server_connection.receive_bytes(client_connection.bytes_to_send())
        client_connection.receive_bytes(server_connection.bytes_to_send())
        server_connection.receive_bytes(client_connection.bytes_to_send())

        # Should complete successfully
        assert client_connection.is_established
        assert server_connection.is_established

    def test_hybrid_mode_explicit(
        self,
        client_kem_keypair: hybrid.HybridKeypair,
        client_sig_keypair: tuple[bytes, bytes],
        server_kem_keypair: hybrid.HybridKeypair,
        server_sig_keypair: tuple[bytes, bytes],
        shared_hmac_key: bytes,
    ) -> None:
        """Explicit hybrid mode should work."""
        config = HandshakeConfig(enable_hybrid=True)

        client = QASPConnection(
            kem_keypair=client_kem_keypair,
            sig_keypair=client_sig_keypair,
            is_client=True,
            config=config,
            hmac_key=shared_hmac_key,
        )

        server = QASPConnection(
            kem_keypair=server_kem_keypair,
            sig_keypair=server_sig_keypair,
            is_client=False,
            config=config,
            hmac_key=shared_hmac_key,
        )

        # Complete handshake
        client.initiate_handshake()
        server.receive_bytes(client.bytes_to_send())
        client.receive_bytes(server.bytes_to_send())
        server.receive_bytes(client.bytes_to_send())

        assert client.is_established
        assert server.is_established
        assert client.session_key == server.session_key


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestHandshakeErrorSendsAlert:
    """Test that handshake errors send appropriate alerts."""

    def test_version_mismatch_sends_alert(
        self,
        server_kem_keypair: hybrid.HybridKeypair,
        server_sig_keypair: tuple[bytes, bytes],
        shared_hmac_key: bytes,
    ) -> None:
        """Version mismatch should result in alert being sent."""
        # Client with different version
        client_config = HandshakeConfig(protocol_version=(2, 0))
        client = QASPConnection(
            kem_keypair=hybrid.generate_keypair(),
            sig_keypair=signatures.generate_keypair(),
            is_client=True,
            config=client_config,
            hmac_key=shared_hmac_key,
        )

        # Server with default version
        server = QASPConnection(
            kem_keypair=server_kem_keypair,
            sig_keypair=server_sig_keypair,
            is_client=False,
            hmac_key=shared_hmac_key,
        )

        # Initiate handshake
        client.initiate_handshake()
        events = server.receive_bytes(client.bytes_to_send())

        # Server should emit HandshakeFailed
        assert any(isinstance(e, HandshakeFailed) for e in events)
        assert server.state == ConnectionState.ERROR

        # Alert should be queued for sending
        alert_bytes = server.bytes_to_send()
        assert len(alert_bytes) > 0

    def test_suite_mismatch_sends_alert(
        self,
        server_kem_keypair: hybrid.HybridKeypair,
        server_sig_keypair: tuple[bytes, bytes],
        shared_hmac_key: bytes,
    ) -> None:
        """Cipher suite mismatch should result in alert being sent."""
        # Client with unsupported suites
        client_config = HandshakeConfig(supported_cipher_suites=(99, 100))
        client = QASPConnection(
            kem_keypair=hybrid.generate_keypair(),
            sig_keypair=signatures.generate_keypair(),
            is_client=True,
            config=client_config,
            hmac_key=shared_hmac_key,
        )

        # Server with default suites
        server = QASPConnection(
            kem_keypair=server_kem_keypair,
            sig_keypair=server_sig_keypair,
            is_client=False,
            hmac_key=shared_hmac_key,
        )

        # Initiate handshake
        client.initiate_handshake()
        events = server.receive_bytes(client.bytes_to_send())

        # Server should emit HandshakeFailed
        assert any(isinstance(e, HandshakeFailed) for e in events)
        assert server.state == ConnectionState.ERROR


# =============================================================================
# State Tests
# =============================================================================


class TestConnectionStates:
    """Test connection state transitions during handshake."""

    def test_client_starts_idle(
        self, client_connection: QASPConnection
    ) -> None:
        """Client should start in IDLE state."""
        assert client_connection.state == ConnectionState.IDLE

    def test_server_starts_idle(
        self, server_connection: QASPConnection
    ) -> None:
        """Server should start in IDLE state."""
        assert server_connection.state == ConnectionState.IDLE

    def test_client_transitions_through_states(
        self,
        client_connection: QASPConnection,
        server_connection: QASPConnection,
    ) -> None:
        """Client should transition through correct states."""
        assert client_connection.state == ConnectionState.IDLE

        # After initiating
        client_connection.initiate_handshake()
        assert client_connection.state == ConnectionState.HELLO_SENT

        # After processing ServerHello
        server_connection.receive_bytes(client_connection.bytes_to_send())
        client_connection.receive_bytes(server_connection.bytes_to_send())
        assert client_connection.state == ConnectionState.ESTABLISHED

    def test_server_transitions_through_states(
        self,
        client_connection: QASPConnection,
        server_connection: QASPConnection,
    ) -> None:
        """Server should transition through correct states."""
        assert server_connection.state == ConnectionState.IDLE

        # After processing ClientHello
        client_connection.initiate_handshake()
        server_connection.receive_bytes(client_connection.bytes_to_send())
        assert server_connection.state == ConnectionState.HELLO_RECEIVED

        # After processing ClientAuth
        client_connection.receive_bytes(server_connection.bytes_to_send())
        server_connection.receive_bytes(client_connection.bytes_to_send())
        assert server_connection.state == ConnectionState.ESTABLISHED


# =============================================================================
# Property Tests
# =============================================================================


class TestConnectionProperties:
    """Test connection property accessors."""

    def test_is_established_before_handshake(
        self, client_connection: QASPConnection
    ) -> None:
        """is_established should be False before handshake."""
        assert not client_connection.is_established

    def test_is_established_after_handshake(
        self,
        client_connection: QASPConnection,
        server_connection: QASPConnection,
    ) -> None:
        """is_established should be True after handshake."""
        # Complete handshake
        client_connection.initiate_handshake()
        server_connection.receive_bytes(client_connection.bytes_to_send())
        client_connection.receive_bytes(server_connection.bytes_to_send())
        server_connection.receive_bytes(client_connection.bytes_to_send())

        assert client_connection.is_established
        assert server_connection.is_established

    def test_session_id_none_before_handshake(
        self, client_connection: QASPConnection
    ) -> None:
        """session_id should be None before handshake."""
        assert client_connection.session_id is None

    def test_session_id_set_after_handshake(
        self,
        client_connection: QASPConnection,
        server_connection: QASPConnection,
    ) -> None:
        """session_id should be set after handshake."""
        # Complete handshake
        client_connection.initiate_handshake()
        server_connection.receive_bytes(client_connection.bytes_to_send())
        client_connection.receive_bytes(server_connection.bytes_to_send())
        server_connection.receive_bytes(client_connection.bytes_to_send())

        assert client_connection.session_id is not None
        assert server_connection.session_id is not None
        assert len(client_connection.session_id) == 32

    def test_peer_kem_public_key_after_handshake(
        self,
        client_connection: QASPConnection,
        server_connection: QASPConnection,
    ) -> None:
        """peer_kem_public_key should be set after handshake."""
        # Complete handshake
        client_connection.initiate_handshake()
        server_connection.receive_bytes(client_connection.bytes_to_send())
        client_connection.receive_bytes(server_connection.bytes_to_send())
        server_connection.receive_bytes(client_connection.bytes_to_send())

        assert client_connection.peer_kem_public_key is not None
        assert server_connection.peer_kem_public_key is not None

    def test_peer_sig_public_key_after_handshake(
        self,
        client_connection: QASPConnection,
        server_connection: QASPConnection,
    ) -> None:
        """peer_sig_public_key should be set after handshake."""
        # Complete handshake
        client_connection.initiate_handshake()
        server_connection.receive_bytes(client_connection.bytes_to_send())
        client_connection.receive_bytes(server_connection.bytes_to_send())
        server_connection.receive_bytes(client_connection.bytes_to_send())

        assert client_connection.peer_sig_public_key is not None
        assert server_connection.peer_sig_public_key is not None


# =============================================================================
# Reset Tests
# =============================================================================


class TestConnectionReset:
    """Test connection reset functionality."""

    def test_reset_clears_state(
        self,
        client_connection: QASPConnection,
        server_connection: QASPConnection,
    ) -> None:
        """Reset should clear connection state."""
        # Complete handshake
        client_connection.initiate_handshake()
        server_connection.receive_bytes(client_connection.bytes_to_send())
        client_connection.receive_bytes(server_connection.bytes_to_send())
        server_connection.receive_bytes(client_connection.bytes_to_send())

        # Verify established
        assert client_connection.is_established

        # Reset
        client_connection.reset()

        # Verify reset
        assert client_connection.state == ConnectionState.IDLE
        assert client_connection.session_id is None
        assert client_connection.session_key is None
        assert not client_connection.is_established

    def test_can_handshake_after_reset(
        self,
        client_connection: QASPConnection,
        server_connection: QASPConnection,
    ) -> None:
        """Should be able to handshake again after reset."""
        # Complete first handshake
        client_connection.initiate_handshake()
        server_connection.receive_bytes(client_connection.bytes_to_send())
        client_connection.receive_bytes(server_connection.bytes_to_send())
        server_connection.receive_bytes(client_connection.bytes_to_send())

        first_session_key = client_connection.session_key

        # Reset both
        client_connection.reset()
        server_connection.reset()

        # Complete second handshake
        client_connection.initiate_handshake()
        server_connection.receive_bytes(client_connection.bytes_to_send())
        client_connection.receive_bytes(server_connection.bytes_to_send())
        server_connection.receive_bytes(client_connection.bytes_to_send())

        # New session key should differ
        assert client_connection.session_key != first_session_key
        assert client_connection.is_established


# =============================================================================
# Multiple Handshakes Tests
# =============================================================================


class TestMultipleHandshakes:
    """Test multiple independent handshakes."""

    def test_independent_handshakes_produce_different_keys(self) -> None:
        """Independent handshakes should produce different keys."""
        # First handshake (with shared HMAC key)
        hmac_key1 = secrets.token_bytes(32)
        client1 = QASPConnection(
            kem_keypair=hybrid.generate_keypair(),
            sig_keypair=signatures.generate_keypair(),
            is_client=True,
            hmac_key=hmac_key1,
        )
        server1 = QASPConnection(
            kem_keypair=hybrid.generate_keypair(),
            sig_keypair=signatures.generate_keypair(),
            is_client=False,
            hmac_key=hmac_key1,
        )

        client1.initiate_handshake()
        server1.receive_bytes(client1.bytes_to_send())
        client1.receive_bytes(server1.bytes_to_send())
        server1.receive_bytes(client1.bytes_to_send())

        # Second handshake (with different shared HMAC key)
        hmac_key2 = secrets.token_bytes(32)
        client2 = QASPConnection(
            kem_keypair=hybrid.generate_keypair(),
            sig_keypair=signatures.generate_keypair(),
            is_client=True,
            hmac_key=hmac_key2,
        )
        server2 = QASPConnection(
            kem_keypair=hybrid.generate_keypair(),
            sig_keypair=signatures.generate_keypair(),
            is_client=False,
            hmac_key=hmac_key2,
        )

        client2.initiate_handshake()
        server2.receive_bytes(client2.bytes_to_send())
        client2.receive_bytes(server2.bytes_to_send())
        server2.receive_bytes(client2.bytes_to_send())

        # Keys should differ
        assert client1.session_key != client2.session_key
        assert client1.session_id != client2.session_id
