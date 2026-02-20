"""Tests for TCP transport layer."""

from __future__ import annotations

import asyncio
import struct
from typing import TYPE_CHECKING, Callable

import pytest

from qasp.transport import (
    DEFAULT_READ_SIZE,
    LENGTH_PREFIX_SIZE,
    MAX_MESSAGE_SIZE,
    ConnectionClosedError,
    ConnectionRefusedError,
    ConnectionTimeoutError,
    FramingError,
    ReceiveError,
    SendError,
    TCPServer,
    TCPTransport,
    TransportError,
    connect,
    listen,
    serve,
)

if TYPE_CHECKING:
    from .conftest import MockKeypair, MockQASPConnection


# =============================================================================
# Constants Tests
# =============================================================================


class TestTCPTransportConstants:
    """Test transport constant values."""

    def test_length_prefix_size(self) -> None:
        """LENGTH_PREFIX_SIZE should be 4 bytes."""
        assert LENGTH_PREFIX_SIZE == 4

    def test_max_message_size(self) -> None:
        """MAX_MESSAGE_SIZE should be 16MB."""
        assert MAX_MESSAGE_SIZE == 16 * 1024 * 1024

    def test_default_read_size(self) -> None:
        """DEFAULT_READ_SIZE should be 64KB."""
        assert DEFAULT_READ_SIZE == 65536


# =============================================================================
# TCPTransport Init Tests
# =============================================================================


class TestTCPTransportInit:
    """Test TCPTransport initialization."""

    def test_init_stores_connection(
        self,
        mock_connection: MockQASPConnection,
    ) -> None:
        """TCPTransport should store the connection."""
        transport = TCPTransport(mock_connection)
        assert transport.connection is mock_connection

    def test_init_not_connected(
        self,
        mock_connection: MockQASPConnection,
    ) -> None:
        """TCPTransport should not be connected after init."""
        transport = TCPTransport(mock_connection)
        assert not transport.is_connected

    def test_connection_property(
        self,
        mock_connection: MockQASPConnection,
    ) -> None:
        """Connection property should return the stored connection."""
        transport = TCPTransport(mock_connection)
        assert transport.connection is mock_connection


# =============================================================================
# TCPTransport Connect Tests
# =============================================================================


class TestTCPTransportConnect:
    """Test TCPTransport connection."""

    @pytest.mark.asyncio
    async def test_connect_success(
        self,
        mock_connection: MockQASPConnection,
        echo_server: TCPServer,
    ) -> None:
        """connect() should establish a connection."""
        transport = TCPTransport(mock_connection)
        await transport.connect("127.0.0.1", echo_server.port)

        assert transport.is_connected
        await transport.close()

    @pytest.mark.asyncio
    async def test_connect_refused(
        self,
        mock_connection: MockQASPConnection,
        free_port: int,
    ) -> None:
        """connect() should raise ConnectionRefusedError when refused."""
        transport = TCPTransport(mock_connection)

        with pytest.raises(ConnectionRefusedError):
            await transport.connect("127.0.0.1", free_port)

    @pytest.mark.asyncio
    async def test_connect_timeout(
        self,
        mock_connection: MockQASPConnection,
    ) -> None:
        """connect() should raise ConnectionTimeoutError on timeout."""
        transport = TCPTransport(mock_connection)

        # Use a non-routable IP to trigger timeout
        with pytest.raises((ConnectionTimeoutError, TransportError)):
            await transport.connect("10.255.255.1", 12345, timeout=0.1)

    @pytest.mark.asyncio
    async def test_connect_already_connected(
        self,
        mock_connection: MockQASPConnection,
        echo_server: TCPServer,
    ) -> None:
        """connect() should raise TransportError if already connected."""
        transport = TCPTransport(mock_connection)
        await transport.connect("127.0.0.1", echo_server.port)

        with pytest.raises(TransportError, match="already connected"):
            await transport.connect("127.0.0.1", echo_server.port)

        await transport.close()


# =============================================================================
# TCPTransport Send/Receive Tests
# =============================================================================


class TestTCPTransportSendReceive:
    """Test TCPTransport send and receive operations."""

    @pytest.mark.asyncio
    async def test_send_receive_basic(
        self,
        mock_connection: MockQASPConnection,
        echo_server: TCPServer,
    ) -> None:
        """Basic send/receive should work."""
        transport = TCPTransport(mock_connection)
        await transport.connect("127.0.0.1", echo_server.port)

        test_data = b"hello, world!"
        await transport.send(test_data)
        received = await transport.receive()

        assert received == test_data
        await transport.close()

    @pytest.mark.asyncio
    async def test_send_receive_empty(
        self,
        mock_connection: MockQASPConnection,
        echo_server: TCPServer,
    ) -> None:
        """Empty message should work."""
        transport = TCPTransport(mock_connection)
        await transport.connect("127.0.0.1", echo_server.port)

        await transport.send(b"")
        received = await transport.receive()

        assert received == b""
        await transport.close()

    @pytest.mark.asyncio
    async def test_send_receive_binary(
        self,
        mock_connection: MockQASPConnection,
        echo_server: TCPServer,
    ) -> None:
        """Binary data should work."""
        transport = TCPTransport(mock_connection)
        await transport.connect("127.0.0.1", echo_server.port)

        test_data = bytes(range(256))
        await transport.send(test_data)
        received = await transport.receive()

        assert received == test_data
        await transport.close()

    @pytest.mark.asyncio
    async def test_send_receive_large(
        self,
        mock_connection: MockQASPConnection,
        echo_server: TCPServer,
    ) -> None:
        """Large message (1MB) should work."""
        transport = TCPTransport(mock_connection)
        await transport.connect("127.0.0.1", echo_server.port)

        # 1MB of data
        test_data = b"x" * (1024 * 1024)
        await transport.send(test_data)
        received = await transport.receive()

        assert received == test_data
        await transport.close()

    @pytest.mark.asyncio
    async def test_send_receive_multiple(
        self,
        mock_connection: MockQASPConnection,
        multi_echo_server: TCPServer,
    ) -> None:
        """Multiple messages in sequence should work."""
        transport = TCPTransport(mock_connection)
        await transport.connect("127.0.0.1", multi_echo_server.port)

        messages = [b"first", b"second", b"third", b"fourth"]
        for msg in messages:
            await transport.send(msg)
            received = await transport.receive()
            assert received == msg

        await transport.close()

    @pytest.mark.asyncio
    async def test_send_not_connected(
        self,
        mock_connection: MockQASPConnection,
    ) -> None:
        """send() should raise SendError when not connected."""
        transport = TCPTransport(mock_connection)

        with pytest.raises(SendError, match="Not connected"):
            await transport.send(b"test")

    @pytest.mark.asyncio
    async def test_receive_not_connected(
        self,
        mock_connection: MockQASPConnection,
    ) -> None:
        """receive() should raise ReceiveError when not connected."""
        transport = TCPTransport(mock_connection)

        with pytest.raises(ReceiveError, match="Not connected"):
            await transport.receive()

    @pytest.mark.asyncio
    async def test_send_message_too_large(
        self,
        mock_connection: MockQASPConnection,
        echo_server: TCPServer,
    ) -> None:
        """send() should raise FramingError for oversized messages."""
        transport = TCPTransport(mock_connection)
        await transport.connect("127.0.0.1", echo_server.port)

        oversized = b"x" * (MAX_MESSAGE_SIZE + 1)
        with pytest.raises(FramingError, match="exceeds maximum"):
            await transport.send(oversized)

        await transport.close()

    @pytest.mark.asyncio
    async def test_receive_timeout(
        self,
        mock_connection: MockQASPConnection,
        echo_server: TCPServer,
    ) -> None:
        """receive() should timeout when no data available."""
        transport = TCPTransport(mock_connection)
        await transport.connect("127.0.0.1", echo_server.port)

        with pytest.raises(ConnectionTimeoutError, match="timed out"):
            await transport.receive(timeout=0.1)

        await transport.close()


# =============================================================================
# TCPTransport Close Tests
# =============================================================================


class TestTCPTransportClose:
    """Test TCPTransport close behavior."""

    @pytest.mark.asyncio
    async def test_close_clears_connection_state(
        self,
        mock_connection: MockQASPConnection,
        echo_server: TCPServer,
    ) -> None:
        """close() should clear connection state."""
        transport = TCPTransport(mock_connection)
        await transport.connect("127.0.0.1", echo_server.port)
        assert transport.is_connected

        await transport.close()
        assert not transport.is_connected

    @pytest.mark.asyncio
    async def test_close_idempotent(
        self,
        mock_connection: MockQASPConnection,
        echo_server: TCPServer,
    ) -> None:
        """close() should be safe to call multiple times."""
        transport = TCPTransport(mock_connection)
        await transport.connect("127.0.0.1", echo_server.port)

        await transport.close()
        await transport.close()  # Should not raise
        await transport.close()  # Should not raise

    @pytest.mark.asyncio
    async def test_close_without_connect(
        self,
        mock_connection: MockQASPConnection,
    ) -> None:
        """close() should be safe to call without connecting."""
        transport = TCPTransport(mock_connection)
        await transport.close()  # Should not raise


# =============================================================================
# TCPServer Tests
# =============================================================================


class TestTCPServer:
    """Test TCPServer functionality."""

    @pytest.mark.asyncio
    async def test_server_start_stop(
        self,
        connection_factory: Callable[[], MockQASPConnection],
    ) -> None:
        """Server should start and stop cleanly."""
        async def handler(transport: TCPTransport) -> None:
            pass

        server = TCPServer(connection_factory, handler)
        await server.start("127.0.0.1", 0)

        assert server.is_serving
        assert server.host == "127.0.0.1"
        assert server.port is not None
        assert server.port > 0

        await server.stop()
        assert not server.is_serving
        assert server.host is None
        assert server.port is None

    @pytest.mark.asyncio
    async def test_server_context_manager(
        self,
        connection_factory: Callable[[], MockQASPConnection],
    ) -> None:
        """Server should work as async context manager."""
        async def handler(transport: TCPTransport) -> None:
            pass

        async with TCPServer(connection_factory, handler) as server:
            await server.start("127.0.0.1", 0)
            assert server.is_serving

        assert not server.is_serving

    @pytest.mark.asyncio
    async def test_server_start_twice(
        self,
        connection_factory: Callable[[], MockQASPConnection],
    ) -> None:
        """Server should raise error if started twice."""
        async def handler(transport: TCPTransport) -> None:
            pass

        server = TCPServer(connection_factory, handler)
        await server.start("127.0.0.1", 0)

        with pytest.raises(TransportError, match="already started"):
            await server.start("127.0.0.1", 0)

        await server.stop()

    @pytest.mark.asyncio
    async def test_server_serve_forever_not_started(
        self,
        connection_factory: Callable[[], MockQASPConnection],
    ) -> None:
        """serve_forever() should raise if not started."""
        async def handler(transport: TCPTransport) -> None:
            pass

        server = TCPServer(connection_factory, handler)

        with pytest.raises(TransportError, match="not started"):
            await server.serve_forever()

    @pytest.mark.asyncio
    async def test_server_accepts_connections(
        self,
        mock_connection: MockQASPConnection,
        echo_server: TCPServer,
    ) -> None:
        """Server should accept and handle connections."""
        transport = TCPTransport(mock_connection)
        await transport.connect("127.0.0.1", echo_server.port)

        await transport.send(b"test")
        received = await transport.receive()
        assert received == b"test"

        await transport.close()

    @pytest.mark.asyncio
    async def test_server_handles_multiple_clients(
        self,
        mock_keypair: MockKeypair,
        echo_server: TCPServer,
    ) -> None:
        """Server should handle multiple concurrent clients."""
        from .conftest import MockQASPConnection

        async def client_task(client_id: int) -> bytes:
            conn = MockQASPConnection(mock_keypair, is_client=True)
            transport = TCPTransport(conn)
            await transport.connect("127.0.0.1", echo_server.port)

            msg = f"client-{client_id}".encode()
            await transport.send(msg)
            received = await transport.receive()
            await transport.close()
            return received

        tasks = [asyncio.create_task(client_task(i)) for i in range(5)]
        results = await asyncio.gather(*tasks)

        for i, result in enumerate(results):
            assert result == f"client-{i}".encode()


# =============================================================================
# Convenience Functions Tests
# =============================================================================


class TestConvenienceFunctions:
    """Test module-level convenience functions."""

    @pytest.mark.asyncio
    async def test_connect_function(
        self,
        mock_connection: MockQASPConnection,
        echo_server: TCPServer,
    ) -> None:
        """connect() function should return connected transport."""
        transport = await connect(
            "127.0.0.1",
            echo_server.port,
            mock_connection,
        )

        assert transport.is_connected
        assert transport.connection is mock_connection
        await transport.close()

    @pytest.mark.asyncio
    async def test_listen_function(
        self,
        connection_factory: Callable[[], MockQASPConnection],
    ) -> None:
        """listen() function should return started server."""
        async def handler(transport: TCPTransport) -> None:
            pass

        server = await listen("127.0.0.1", 0, connection_factory, handler)

        assert server.is_serving
        assert server.port is not None
        await server.stop()


# =============================================================================
# Echo Server Integration Tests
# =============================================================================


class TestEchoServerIntegration:
    """End-to-end tests with echo server."""

    @pytest.mark.asyncio
    async def test_echo_basic(
        self,
        mock_connection: MockQASPConnection,
        echo_server: TCPServer,
    ) -> None:
        """Basic echo should work."""
        transport = TCPTransport(mock_connection)
        await transport.connect("127.0.0.1", echo_server.port)

        await transport.send(b"Hello, QASP!")
        response = await transport.receive()
        assert response == b"Hello, QASP!"

        await transport.close()

    @pytest.mark.asyncio
    async def test_echo_multiple_messages(
        self,
        mock_connection: MockQASPConnection,
        multi_echo_server: TCPServer,
    ) -> None:
        """Multiple echo messages should work."""
        transport = TCPTransport(mock_connection)
        await transport.connect("127.0.0.1", multi_echo_server.port)

        for i in range(10):
            msg = f"message-{i}".encode()
            await transport.send(msg)
            response = await transport.receive()
            assert response == msg

        await transport.close()

    @pytest.mark.asyncio
    async def test_echo_large_message(
        self,
        mock_connection: MockQASPConnection,
        echo_server: TCPServer,
    ) -> None:
        """Large message echo should work."""
        transport = TCPTransport(mock_connection)
        await transport.connect("127.0.0.1", echo_server.port)

        # 1MB message
        large_msg = b"A" * (1024 * 1024)
        await transport.send(large_msg)
        response = await transport.receive()
        assert response == large_msg

        await transport.close()

    @pytest.mark.asyncio
    async def test_echo_connection_close(
        self,
        mock_connection: MockQASPConnection,
        echo_server: TCPServer,
    ) -> None:
        """Connection should close cleanly after echo."""
        transport = TCPTransport(mock_connection)
        await transport.connect("127.0.0.1", echo_server.port)

        await transport.send(b"test")
        await transport.receive()
        await transport.close()

        assert not transport.is_connected


# =============================================================================
# Framing Tests
# =============================================================================


class TestFraming:
    """Test length-prefix framing implementation."""

    def test_write_length_prefixed(
        self,
        mock_connection: MockQASPConnection,
    ) -> None:
        """_write_length_prefixed should create correct frames."""
        transport = TCPTransport(mock_connection)

        # Test empty data
        frame = transport._write_length_prefixed(b"")
        assert frame == struct.pack(">I", 0)

        # Test small data
        frame = transport._write_length_prefixed(b"test")
        assert frame == struct.pack(">I", 4) + b"test"

        # Test larger data
        data = b"x" * 1000
        frame = transport._write_length_prefixed(data)
        assert frame == struct.pack(">I", 1000) + data

    @pytest.mark.asyncio
    async def test_framing_roundtrip(
        self,
        mock_connection: MockQASPConnection,
        echo_server: TCPServer,
    ) -> None:
        """Framing should handle various message sizes correctly."""
        transport = TCPTransport(mock_connection)
        await transport.connect("127.0.0.1", echo_server.port)

        # Test various sizes
        sizes = [0, 1, 100, 1000, 10000, 65536, 100000]
        for size in sizes:
            data = b"x" * size
            await transport.send(data)
            received = await transport.receive()
            assert len(received) == size
            assert received == data

        await transport.close()


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Test error handling in transport."""

    @pytest.mark.asyncio
    async def test_connection_closed_on_server_close(
        self,
        mock_connection: MockQASPConnection,
        connection_factory: Callable[[], MockQASPConnection],
    ) -> None:
        """Connection should handle server closing."""
        close_event = asyncio.Event()

        async def close_handler(transport: TCPTransport) -> None:
            # Immediately close the connection
            await transport.close()
            close_event.set()

        server = TCPServer(connection_factory, close_handler)
        await server.start("127.0.0.1", 0)

        transport = TCPTransport(mock_connection)
        await transport.connect("127.0.0.1", server.port)

        # Wait for server to close its side
        await asyncio.wait_for(close_event.wait(), timeout=5.0)
        await asyncio.sleep(0.1)  # Give time for close to propagate

        # Receiving should fail
        with pytest.raises((ConnectionClosedError, ReceiveError)):
            await transport.receive(timeout=1.0)

        await transport.close()
        await server.stop()
