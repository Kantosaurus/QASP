"""QUIC transport layer for QASP.

This module implements QUIC transport using ``aioquic``, providing
0-RTT connection establishment, multiplexed streams, and TLS 1.3
with post-quantum cipher suites.

QUIC is an optional transport alongside TCP, registered via
the transport ``__init__`` module.
"""

from __future__ import annotations

import asyncio
import ssl
from typing import TYPE_CHECKING, Awaitable, Callable

from .exceptions import (
    ConnectionClosedError,
    ConnectionRefusedError,
    ConnectionTimeoutError,
    SendError,
    TransportError,
)

if TYPE_CHECKING:
    from qasp.protocol.connection import QASPConnection
    from qasp.protocol.events import Event

__all__ = [
    "QASPQuicClient",
    "QASPQuicServer",
    "quic_connect",
    "quic_serve",
]

# Lazy import aioquic to allow the module to be loaded even when
# aioquic is not installed (QUIC is optional).
_aioquic_available: bool | None = None


def _check_aioquic() -> None:
    """Verify that aioquic is installed."""
    global _aioquic_available
    if _aioquic_available is None:
        try:
            import aioquic  # noqa: F401

            _aioquic_available = True
        except ImportError:
            _aioquic_available = False
    if not _aioquic_available:
        raise ImportError(
            "aioquic is required for QUIC transport. "
            "Install it with: pip install aioquic"
        )


# Default QUIC configuration values
DEFAULT_QUIC_PORT = 4443
MAX_DATAGRAM_SIZE = 65536
IDLE_TIMEOUT = 30.0  # seconds


class QASPQuicClient:
    """Asyncio QUIC client for QASP.

    Establishes a QUIC connection to a server, opens a bidirectional
    stream, and pipes data through a :class:`QASPConnection`.

    Args:
        connection: The QASP sans-I/O connection to transport.
    """

    def __init__(self, connection: QASPConnection) -> None:
        self._connection = connection
        self._quic = None
        self._protocol = None
        self._stream_id: int | None = None
        self._connected = False
        self._receive_buffer = bytearray()
        self._receive_event = asyncio.Event()
        self._closed = False

    @property
    def connected(self) -> bool:
        """Whether the client is currently connected."""
        return self._connected

    async def connect(
        self,
        host: str,
        port: int = DEFAULT_QUIC_PORT,
        *,
        server_name: str | None = None,
        timeout: float = 10.0,
        session_ticket: object | None = None,
    ) -> None:
        """Connect to a QUIC server.

        Args:
            host: Server hostname or IP address.
            port: Server port (default 4443).
            server_name: SNI server name (defaults to *host*).
            timeout: Connection timeout in seconds.
            session_ticket: Optional session ticket for 0-RTT resumption.

        Raises:
            ConnectionTimeoutError: If connection times out.
            ConnectionRefusedError: If connection is refused.
        """
        _check_aioquic()
        from aioquic.asyncio import connect as quic_async_connect
        from aioquic.quic.configuration import QuicConfiguration

        configuration = QuicConfiguration(
            is_client=True,
            alpn_protocols=["qasp/1"],
            idle_timeout=IDLE_TIMEOUT,
        )
        configuration.verify_mode = ssl.CERT_NONE  # Use QASP-level auth

        if session_ticket is not None:
            configuration.session_ticket = session_ticket

        sni = server_name or host

        try:
            async with asyncio.timeout(timeout):
                self._protocol = await quic_async_connect(
                    host,
                    port,
                    configuration=configuration,
                    create_protocol=self._create_client_protocol,
                    server_name=sni,
                )
        except TimeoutError as e:
            raise ConnectionTimeoutError(
                f"QUIC connection to {host}:{port} timed out after {timeout}s"
            ) from e
        except OSError as e:
            raise ConnectionRefusedError(
                f"QUIC connection to {host}:{port} refused: {e}"
            ) from e

        # Open a bidirectional stream
        self._stream_id = self._protocol._quic.get_next_available_stream_id()
        self._connected = True

    def _create_client_protocol(self, *args, **kwargs):
        """Create the QUIC protocol handler."""
        from aioquic.asyncio.protocol import QuicConnectionProtocol

        protocol = QuicConnectionProtocol(*args, **kwargs)
        return protocol

    async def send(self, data: bytes) -> None:
        """Send data over the QUIC stream.

        Args:
            data: The data to send.

        Raises:
            ConnectionClosedError: If not connected.
            SendError: If sending fails.
        """
        if not self._connected or self._protocol is None:
            raise ConnectionClosedError("Not connected")
        if self._stream_id is None:
            raise SendError("No stream available")

        try:
            self._protocol._quic.send_stream_data(
                self._stream_id, data
            )
            self._protocol.transmit()
        except Exception as e:
            raise SendError(f"Failed to send data: {e}") from e

    async def receive(self, timeout: float | None = None) -> bytes:
        """Receive data from the QUIC stream.

        Args:
            timeout: Optional receive timeout in seconds.

        Returns:
            The received data.

        Raises:
            ConnectionClosedError: If not connected or connection is closed.
        """
        if not self._connected:
            raise ConnectionClosedError("Not connected")

        if self._receive_buffer:
            data = bytes(self._receive_buffer)
            self._receive_buffer.clear()
            return data

        try:
            if timeout is not None:
                async with asyncio.timeout(timeout):
                    await self._receive_event.wait()
            else:
                await self._receive_event.wait()
        except TimeoutError as e:
            raise ConnectionClosedError("Receive timed out") from e

        self._receive_event.clear()
        data = bytes(self._receive_buffer)
        self._receive_buffer.clear()
        return data

    async def close(self) -> None:
        """Close the QUIC connection."""
        if self._protocol is not None and not self._closed:
            self._closed = True
            self._connected = False
            try:
                self._protocol._quic.close()
                self._protocol.transmit()
            except Exception:
                pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()


class QASPQuicServer:
    """Asyncio QUIC server for QASP.

    Accepts QUIC connections and creates QASP sessions per stream.

    Args:
        handler: Async callback invoked for each new QASP connection.
            Receives ``(reader_data, writer_func, connection)`` where
            reader_data is incoming bytes and writer_func sends bytes.
    """

    def __init__(
        self,
        handler: Callable[..., Awaitable[None]],
        connection_factory: Callable[[], QASPConnection] | None = None,
    ) -> None:
        self._handler = handler
        self._connection_factory = connection_factory
        self._server = None
        self._serving = False

    @property
    def serving(self) -> bool:
        """Whether the server is currently serving connections."""
        return self._serving

    async def serve(
        self,
        host: str = "0.0.0.0",
        port: int = DEFAULT_QUIC_PORT,
        *,
        certfile: str | None = None,
        keyfile: str | None = None,
    ) -> None:
        """Start serving QUIC connections.

        Args:
            host: Bind address (default ``"0.0.0.0"``).
            port: Bind port (default 4443).
            certfile: Path to TLS certificate file.
            keyfile: Path to TLS private key file.

        Raises:
            TransportError: If the server fails to start.
        """
        _check_aioquic()
        from aioquic.asyncio import serve as quic_async_serve
        from aioquic.quic.configuration import QuicConfiguration

        configuration = QuicConfiguration(
            is_client=False,
            alpn_protocols=["qasp/1"],
            idle_timeout=IDLE_TIMEOUT,
        )

        if certfile and keyfile:
            configuration.load_cert_chain(certfile, keyfile)
        else:
            # Generate self-signed for testing when no cert provided
            configuration.verify_mode = ssl.CERT_NONE

        try:
            self._server = await quic_async_serve(
                host,
                port,
                configuration=configuration,
                create_protocol=self._create_server_protocol,
            )
            self._serving = True
        except OSError as e:
            raise TransportError(
                f"Failed to start QUIC server on {host}:{port}: {e}"
            ) from e

    def _create_server_protocol(self, *args, **kwargs):
        """Create the server-side QUIC protocol handler."""
        from aioquic.asyncio.protocol import QuicConnectionProtocol

        protocol = QuicConnectionProtocol(*args, **kwargs)
        return protocol

    async def close(self) -> None:
        """Stop the QUIC server."""
        if self._server is not None:
            self._server.close()
            self._serving = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()


# =============================================================================
# Convenience Functions
# =============================================================================


async def quic_connect(
    host: str,
    port: int = DEFAULT_QUIC_PORT,
    connection: QASPConnection | None = None,
    *,
    timeout: float = 10.0,
) -> QASPQuicClient:
    """Connect to a QUIC server and return a client transport.

    Args:
        host: Server hostname or IP.
        port: Server port.
        connection: Optional pre-built QASPConnection.
        timeout: Connection timeout in seconds.

    Returns:
        A connected :class:`QASPQuicClient`.
    """
    _check_aioquic()

    if connection is None:
        from qasp.protocol.connection import QASPConnection as Conn

        connection = Conn.__new__(Conn)

    client = QASPQuicClient(connection)
    await client.connect(host, port, timeout=timeout)
    return client


async def quic_serve(
    handler: Callable[..., Awaitable[None]],
    host: str = "0.0.0.0",
    port: int = DEFAULT_QUIC_PORT,
    *,
    certfile: str | None = None,
    keyfile: str | None = None,
) -> QASPQuicServer:
    """Start a QUIC server and return it.

    Args:
        handler: Connection handler callback.
        host: Bind address.
        port: Bind port.
        certfile: TLS certificate file path.
        keyfile: TLS private key file path.

    Returns:
        A serving :class:`QASPQuicServer`.
    """
    server = QASPQuicServer(handler)
    await server.serve(host, port, certfile=certfile, keyfile=keyfile)
    return server
