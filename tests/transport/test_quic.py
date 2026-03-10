"""Tests for QUIC transport layer.

These tests verify the QUIC transport module's structure and behavior.
Full integration tests require aioquic and network access.
"""

from __future__ import annotations

import pytest

from qasp.transport.quic import (
    DEFAULT_QUIC_PORT,
    IDLE_TIMEOUT,
    MAX_DATAGRAM_SIZE,
    QASPQuicClient,
    QASPQuicServer,
    _check_aioquic,
)


def _aioquic_available_check() -> bool:
    """Check if aioquic is available for integration tests."""
    try:
        import aioquic  # noqa: F401

        return True
    except ImportError:
        return False


# =============================================================================
# Module-Level Tests
# =============================================================================


class TestQuicConstants:
    """Test module constants."""

    def test_default_port(self):
        assert DEFAULT_QUIC_PORT == 4443

    def test_max_datagram_size(self):
        assert MAX_DATAGRAM_SIZE == 65536

    def test_idle_timeout(self):
        assert IDLE_TIMEOUT == 30.0


class TestQuicAvailability:
    """Test aioquic availability checking."""

    def test_check_aioquic_import(self):
        """_check_aioquic should either succeed or raise ImportError."""
        try:
            _check_aioquic()
        except ImportError as e:
            assert "aioquic" in str(e)


# =============================================================================
# Client Tests
# =============================================================================


class TestQASPQuicClient:
    """Test QUIC client structure."""

    def test_client_init(self):
        """Client initializes with connection in disconnected state."""
        # Use a mock connection
        class MockConnection:
            pass

        client = QASPQuicClient(MockConnection())
        assert not client.connected

    @pytest.mark.asyncio
    async def test_send_without_connect_raises(self):
        """Sending without connection raises ConnectionClosedError."""
        from qasp.transport.exceptions import ConnectionClosedError

        class MockConnection:
            pass

        client = QASPQuicClient(MockConnection())
        with pytest.raises(ConnectionClosedError):
            await client.send(b"hello")

    @pytest.mark.asyncio
    async def test_receive_without_connect_raises(self):
        """Receiving without connection raises ConnectionClosedError."""
        from qasp.transport.exceptions import ConnectionClosedError

        class MockConnection:
            pass

        client = QASPQuicClient(MockConnection())
        with pytest.raises(ConnectionClosedError):
            await client.receive()

    @pytest.mark.asyncio
    async def test_close_without_connect(self):
        """Closing without connection should not raise."""
        class MockConnection:
            pass

        client = QASPQuicClient(MockConnection())
        await client.close()  # Should not raise

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Client supports async context manager."""
        class MockConnection:
            pass

        async with QASPQuicClient(MockConnection()) as client:
            assert not client.connected


# =============================================================================
# Server Tests
# =============================================================================


class TestQASPQuicServer:
    """Test QUIC server structure."""

    def test_server_init(self):
        """Server initializes in non-serving state."""

        async def handler():
            pass

        server = QASPQuicServer(handler)
        assert not server.serving

    @pytest.mark.asyncio
    async def test_close_without_serve(self):
        """Closing without starting should not raise."""

        async def handler():
            pass

        server = QASPQuicServer(handler)
        await server.close()

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Server supports async context manager."""

        async def handler():
            pass

        async with QASPQuicServer(handler) as server:
            assert not server.serving


# =============================================================================
# Integration Tests (require aioquic)
# =============================================================================


@pytest.mark.skipif(
    not _aioquic_available_check(),
    reason="aioquic not installed",
)
class TestQuicIntegration:
    """Integration tests requiring aioquic."""

    @pytest.mark.asyncio
    async def test_connect_to_invalid_host(self):
        """Connecting to invalid host raises appropriate error."""
        from qasp.transport.exceptions import ConnectionRefusedError, ConnectionTimeoutError

        client = QASPQuicClient(type("MockConn", (), {})())
        with pytest.raises((ConnectionRefusedError, ConnectionTimeoutError)):
            await client.connect("127.0.0.1", 19999, timeout=1.0)
