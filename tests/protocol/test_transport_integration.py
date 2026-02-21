"""Integration tests for TCP transport with QASP handshake."""

from __future__ import annotations

import asyncio
import secrets

import pytest

from qasp.crypto import hybrid, signatures
from qasp.protocol import (
    DataReceived,
    HandshakeComplete,
    QASPConnection,
)
from qasp.transport.tcp import TCPServer, TCPTransport

# Module-level shared HMAC key for TCP transport tests
# Each test class/function that creates client-server pairs should use this
# or create their own shared key pair
_SHARED_HMAC_KEY = secrets.token_bytes(32)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def shared_hmac_key() -> bytes:
    """Generate a shared HMAC key for client/server."""
    return secrets.token_bytes(32)


@pytest.fixture
def client_connection(shared_hmac_key: bytes) -> QASPConnection:
    """Create a client QASP connection."""
    return QASPConnection(
        kem_keypair=hybrid.generate_keypair(),
        sig_keypair=signatures.generate_keypair(),
        is_client=True,
        hmac_key=shared_hmac_key,
    )


@pytest.fixture
def server_connection(shared_hmac_key: bytes) -> QASPConnection:
    """Create a server QASP connection."""
    return QASPConnection(
        kem_keypair=hybrid.generate_keypair(),
        sig_keypair=signatures.generate_keypair(),
        is_client=False,
        hmac_key=shared_hmac_key,
    )


def create_server_connection(hmac_key: bytes | None = None) -> QASPConnection:
    """Factory function for creating server connections."""
    return QASPConnection(
        kem_keypair=hybrid.generate_keypair(),
        sig_keypair=signatures.generate_keypair(),
        is_client=False,
        hmac_key=hmac_key if hmac_key is not None else _SHARED_HMAC_KEY,
    )


# =============================================================================
# TCP Transport Tests
# =============================================================================


class TestTCPTransportProperties:
    """Test TCPTransport convenience properties."""

    def test_is_established_before_handshake(
        self, client_connection: QASPConnection
    ) -> None:
        """is_established should be False before handshake."""
        transport = TCPTransport(client_connection)
        assert not transport.is_established

    def test_session_id_before_handshake(
        self, client_connection: QASPConnection
    ) -> None:
        """session_id should be None before handshake."""
        transport = TCPTransport(client_connection)
        assert transport.session_id is None


class TestClientServerHandshake:
    """Test full client-server handshake over TCP."""

    @pytest.mark.asyncio
    async def test_full_handshake_completes(self) -> None:
        """Full TCP handshake should complete successfully."""
        server_events: list = []

        async def handle_client(transport: TCPTransport) -> None:
            events = await transport.perform_handshake(timeout=10.0)
            server_events.extend(events)

        # Start server
        server = TCPServer(create_server_connection, handle_client)
        await server.start("127.0.0.1", 0)

        try:
            # Create client with shared HMAC key
            client_conn = QASPConnection(
                kem_keypair=hybrid.generate_keypair(),
                sig_keypair=signatures.generate_keypair(),
                is_client=True,
                hmac_key=_SHARED_HMAC_KEY,
            )
            client_transport = TCPTransport(client_conn)

            # Connect and handshake
            await client_transport.connect("127.0.0.1", server.port, timeout=10.0)
            client_events = await client_transport.perform_handshake(timeout=10.0)

            # Wait for server to complete
            await asyncio.sleep(0.1)

            # Verify client completed
            assert any(isinstance(e, HandshakeComplete) for e in client_events)
            assert client_transport.is_established
            assert client_transport.session_id is not None

            # Verify server completed
            assert any(isinstance(e, HandshakeComplete) for e in server_events)

            await client_transport.close()
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_handshake_produces_matching_session_keys(self) -> None:
        """Both sides should derive the same session key after handshake."""
        server_conn_holder: list[QASPConnection] = []

        async def handle_client(transport: TCPTransport) -> None:
            await transport.perform_handshake(timeout=10.0)
            server_conn_holder.append(transport.connection)
            # Keep connection alive briefly
            await asyncio.sleep(0.2)

        def connection_factory() -> QASPConnection:
            conn = create_server_connection()
            return conn

        server = TCPServer(connection_factory, handle_client)
        await server.start("127.0.0.1", 0)

        try:
            client_conn = QASPConnection(
                kem_keypair=hybrid.generate_keypair(),
                sig_keypair=signatures.generate_keypair(),
                is_client=True,
                hmac_key=_SHARED_HMAC_KEY,
            )
            client_transport = TCPTransport(client_conn)

            await client_transport.connect("127.0.0.1", server.port, timeout=10.0)
            await client_transport.perform_handshake(timeout=10.0)

            # Wait for server handler to store connection
            await asyncio.sleep(0.1)

            assert len(server_conn_holder) == 1
            server_conn = server_conn_holder[0]

            # Verify session keys match
            assert client_conn.session_key is not None
            assert server_conn.session_key is not None
            assert client_conn.session_key == server_conn.session_key

            await client_transport.close()
        finally:
            await server.stop()


class TestEncryptedDataAfterHandshake:
    """Test encrypted data exchange after handshake."""

    @pytest.mark.asyncio
    async def test_client_to_server_encrypted_data(self) -> None:
        """Client should be able to send encrypted data to server after handshake."""
        received_data: list[bytes] = []

        async def handle_client(transport: TCPTransport) -> None:
            await transport.perform_handshake(timeout=10.0)

            # Receive encrypted data
            events = await transport.receive_protocol_data()
            for event in events:
                if isinstance(event, DataReceived):
                    received_data.append(event.data)

        server = TCPServer(create_server_connection, handle_client)
        await server.start("127.0.0.1", 0)

        try:
            client_conn = QASPConnection(
                kem_keypair=hybrid.generate_keypair(),
                sig_keypair=signatures.generate_keypair(),
                is_client=True,
                hmac_key=_SHARED_HMAC_KEY,
            )
            client_transport = TCPTransport(client_conn)

            await client_transport.connect("127.0.0.1", server.port, timeout=10.0)
            await client_transport.perform_handshake(timeout=10.0)

            # Send encrypted data
            test_message = b"Hello, encrypted world!"
            await client_transport.send_protocol_data(test_message)

            # Wait for server to process
            await asyncio.sleep(0.1)

            assert len(received_data) == 1
            assert received_data[0] == test_message

            await client_transport.close()
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_server_to_client_encrypted_data(self) -> None:
        """Server should be able to send encrypted data to client after handshake."""
        test_message = b"Hello from server!"
        client_data_received = asyncio.Event()
        received_data: list[bytes] = []

        async def handle_client(transport: TCPTransport) -> None:
            await transport.perform_handshake(timeout=10.0)

            # Send data to client
            await transport.send_protocol_data(test_message)

            # Wait for client to receive
            await asyncio.sleep(0.5)

        server = TCPServer(create_server_connection, handle_client)
        await server.start("127.0.0.1", 0)

        try:
            client_conn = QASPConnection(
                kem_keypair=hybrid.generate_keypair(),
                sig_keypair=signatures.generate_keypair(),
                is_client=True,
                hmac_key=_SHARED_HMAC_KEY,
            )
            client_transport = TCPTransport(client_conn)

            await client_transport.connect("127.0.0.1", server.port, timeout=10.0)
            await client_transport.perform_handshake(timeout=10.0)

            # Receive data from server
            events = await client_transport.receive_protocol_data()
            for event in events:
                if isinstance(event, DataReceived):
                    received_data.append(event.data)
                    client_data_received.set()

            assert len(received_data) == 1
            assert received_data[0] == test_message

            await client_transport.close()
        finally:
            await server.stop()


class TestBidirectionalEncryptedCommunication:
    """Test bidirectional encrypted communication."""

    @pytest.mark.asyncio
    async def test_bidirectional_messages(self) -> None:
        """Both client and server should exchange encrypted messages."""
        server_received: list[bytes] = []
        client_received: list[bytes] = []
        handshake_done = asyncio.Event()

        async def handle_client(transport: TCPTransport) -> None:
            await transport.perform_handshake(timeout=10.0)
            handshake_done.set()

            # Receive from client
            events = await transport.receive_protocol_data()
            for event in events:
                if isinstance(event, DataReceived):
                    server_received.append(event.data)

            # Send response
            await transport.send_protocol_data(b"Server response")

            # Keep alive for client to receive
            await asyncio.sleep(0.5)

        server = TCPServer(create_server_connection, handle_client)
        await server.start("127.0.0.1", 0)

        try:
            client_conn = QASPConnection(
                kem_keypair=hybrid.generate_keypair(),
                sig_keypair=signatures.generate_keypair(),
                is_client=True,
                hmac_key=_SHARED_HMAC_KEY,
            )
            client_transport = TCPTransport(client_conn)

            await client_transport.connect("127.0.0.1", server.port, timeout=10.0)
            await client_transport.perform_handshake(timeout=10.0)

            # Send to server
            await client_transport.send_protocol_data(b"Client message")

            # Receive from server
            await asyncio.sleep(0.1)
            events = await client_transport.receive_protocol_data()
            for event in events:
                if isinstance(event, DataReceived):
                    client_received.append(event.data)

            # Verify bidirectional exchange
            assert len(server_received) == 1
            assert server_received[0] == b"Client message"
            assert len(client_received) == 1
            assert client_received[0] == b"Server response"

            await client_transport.close()
        finally:
            await server.stop()


class TestMultipleMessages:
    """Test sending multiple messages in sequence."""

    @pytest.mark.asyncio
    async def test_multiple_sequential_messages(self) -> None:
        """Multiple messages should be encrypted/decrypted correctly."""
        server_received: list[bytes] = []
        num_messages = 5

        async def handle_client(transport: TCPTransport) -> None:
            await transport.perform_handshake(timeout=10.0)

            # Receive multiple messages
            for _ in range(num_messages):
                events = await transport.receive_protocol_data()
                for event in events:
                    if isinstance(event, DataReceived):
                        server_received.append(event.data)

        server = TCPServer(create_server_connection, handle_client)
        await server.start("127.0.0.1", 0)

        try:
            client_conn = QASPConnection(
                kem_keypair=hybrid.generate_keypair(),
                sig_keypair=signatures.generate_keypair(),
                is_client=True,
                hmac_key=_SHARED_HMAC_KEY,
            )
            client_transport = TCPTransport(client_conn)

            await client_transport.connect("127.0.0.1", server.port, timeout=10.0)
            await client_transport.perform_handshake(timeout=10.0)

            # Send multiple messages
            messages = [f"Message {i}".encode() for i in range(num_messages)]
            for msg in messages:
                await client_transport.send_protocol_data(msg)

            # Wait for server to process
            await asyncio.sleep(0.2)

            assert len(server_received) == num_messages
            assert server_received == messages

            await client_transport.close()
        finally:
            await server.stop()


class TestConnectionReuse:
    """Test that connections can be reset and reused."""

    @pytest.mark.asyncio
    async def test_reset_allows_new_handshake(self) -> None:
        """After reset, connection should be able to perform new handshake."""
        handshake_count = 0

        async def handle_client(transport: TCPTransport) -> None:
            nonlocal handshake_count
            await transport.perform_handshake(timeout=10.0)
            handshake_count += 1
            await asyncio.sleep(0.1)

        server = TCPServer(create_server_connection, handle_client)
        await server.start("127.0.0.1", 0)

        try:
            # First connection
            client_conn = QASPConnection(
                kem_keypair=hybrid.generate_keypair(),
                sig_keypair=signatures.generate_keypair(),
                is_client=True,
                hmac_key=_SHARED_HMAC_KEY,
            )
            client_transport = TCPTransport(client_conn)

            await client_transport.connect("127.0.0.1", server.port, timeout=10.0)
            await client_transport.perform_handshake(timeout=10.0)

            first_session_id = client_conn.session_id
            assert first_session_id is not None

            await client_transport.close()
            await asyncio.sleep(0.1)

            # Second connection (new connection object, simulating reset)
            client_conn2 = QASPConnection(
                kem_keypair=hybrid.generate_keypair(),
                sig_keypair=signatures.generate_keypair(),
                is_client=True,
                hmac_key=_SHARED_HMAC_KEY,
            )
            client_transport2 = TCPTransport(client_conn2)

            await client_transport2.connect("127.0.0.1", server.port, timeout=10.0)
            await client_transport2.perform_handshake(timeout=10.0)

            second_session_id = client_conn2.session_id
            assert second_session_id is not None

            # Session IDs should differ
            assert first_session_id != second_session_id

            await asyncio.sleep(0.1)
            assert handshake_count == 2

            await client_transport2.close()
        finally:
            await server.stop()
