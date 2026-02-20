"""TCP transport layer.

This module implements TCP transport for QASP connections with
length-prefixed framing for message boundaries.
"""

from __future__ import annotations

import asyncio
import builtins
import struct
from typing import TYPE_CHECKING, Awaitable, Callable

from .exceptions import (
    ConnectionClosedError,
    ConnectionRefusedError,
    ConnectionTimeoutError,
    FramingError,
    ReceiveError,
    SendError,
    TransportError,
)

if TYPE_CHECKING:
    from qasp.protocol.connection import QASPConnection
    from qasp.protocol.events import Event

__all__ = [
    "LENGTH_PREFIX_SIZE",
    "MAX_MESSAGE_SIZE",
    "DEFAULT_READ_SIZE",
    "TCPTransport",
    "TCPServer",
    "connect",
    "listen",
    "serve",
]

# Constants
LENGTH_PREFIX_SIZE = 4  # 4-byte big-endian length prefix
MAX_MESSAGE_SIZE = 16 * 1024 * 1024  # 16MB maximum message size
DEFAULT_READ_SIZE = 65536  # 64KB read buffer size


class TCPTransport:
    """TCP transport for QASP.

    This class wraps a sans-I/O QASPConnection and provides asyncio-based
    TCP networking with length-prefixed framing for message boundaries.

    The transport can be used for both client and server connections:
    - Client: Create instance, call connect()
    - Server: Create instance with pre-populated reader/writer from accept

    Usage:
        # Client usage
        transport = TCPTransport(connection)
        await transport.connect("localhost", 8443)
        await transport.send(b"hello")
        response = await transport.receive()
        await transport.close()

        # Server usage (from TCPServer)
        transport = TCPTransport(connection)
        transport._reader = reader
        transport._writer = writer
        transport._connected = True
    """

    def __init__(self, connection: QASPConnection) -> None:
        """Initialize the transport.

        Args:
            connection: The QASP connection to transport.
        """
        self._connection = connection
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._connected = False
        self._receive_buffer = bytearray()

    @property
    def connection(self) -> QASPConnection:
        """Return the underlying QASP connection."""
        return self._connection

    @property
    def is_connected(self) -> bool:
        """Return True if the transport is connected."""
        return self._connected and self._writer is not None

    async def connect(
        self,
        host: str,
        port: int,
        timeout: float = 30.0,
    ) -> None:
        """Connect to a remote endpoint.

        This establishes the TCP connection only. The QASP handshake
        must be initiated separately via initiate_handshake().

        Args:
            host: The remote host.
            port: The remote port.
            timeout: Connection timeout in seconds.

        Raises:
            ConnectionRefusedError: If the connection is refused.
            ConnectionTimeoutError: If the connection times out.
            TransportError: If another connection error occurs.
        """
        if self._connected:
            raise TransportError("Transport is already connected")

        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
            self._connected = True
        except asyncio.TimeoutError as e:
            raise ConnectionTimeoutError(
                f"Connection to {host}:{port} timed out after {timeout}s"
            ) from e
        except builtins.ConnectionRefusedError as e:
            raise ConnectionRefusedError(
                f"Connection to {host}:{port} refused"
            ) from e
        except OSError as e:
            raise TransportError(f"Connection to {host}:{port} failed: {e}") from e

    async def send(self, data: bytes) -> None:
        """Send data over the connection with length-prefix framing.

        Args:
            data: The data to send.

        Raises:
            SendError: If the send operation fails.
            ConnectionClosedError: If the connection is closed.
            FramingError: If the message is too large.
        """
        if not self.is_connected:
            raise SendError("Not connected")

        if len(data) > MAX_MESSAGE_SIZE:
            raise FramingError(
                f"Message size {len(data)} exceeds maximum {MAX_MESSAGE_SIZE}"
            )

        assert self._writer is not None

        try:
            frame = self._write_length_prefixed(data)
            self._writer.write(frame)
            await self._writer.drain()
        except (ConnectionResetError, BrokenPipeError) as e:
            self._connected = False
            raise ConnectionClosedError("Connection closed by peer") from e
        except OSError as e:
            raise SendError(f"Send failed: {e}") from e

    async def receive(self, timeout: float | None = None) -> bytes:
        """Receive data from the connection with length-prefix framing.

        Args:
            timeout: Optional timeout in seconds. None means no timeout.

        Returns:
            The received data.

        Raises:
            ReceiveError: If the receive operation fails.
            ConnectionClosedError: If the connection is closed.
            ConnectionTimeoutError: If the receive times out.
            FramingError: If the frame format is invalid.
        """
        if not self.is_connected:
            raise ReceiveError("Not connected")

        try:
            if timeout is not None:
                return await asyncio.wait_for(
                    self._read_length_prefixed(),
                    timeout=timeout,
                )
            return await self._read_length_prefixed()
        except asyncio.TimeoutError as e:
            raise ConnectionTimeoutError("Receive timed out") from e
        except (ConnectionResetError, BrokenPipeError) as e:
            self._connected = False
            raise ConnectionClosedError("Connection closed by peer") from e
        except asyncio.IncompleteReadError as e:
            self._connected = False
            raise ConnectionClosedError("Connection closed unexpectedly") from e
        except (FramingError, ConnectionClosedError):
            raise
        except OSError as e:
            raise ReceiveError(f"Receive failed: {e}") from e

    async def close(self) -> None:
        """Close the transport.

        This closes the underlying TCP connection. The close operation
        is idempotent and will not raise an error if already closed.
        """
        if self._writer is not None:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass  # Ignore errors during close
            finally:
                self._writer = None
                self._reader = None
                self._connected = False
                self._receive_buffer.clear()

    async def send_protocol_data(self, app_data: bytes) -> list[Event]:
        """Send application data through the QASP protocol.

        This method queues data through the QASPConnection, then sends
        all pending protocol data over the transport.

        Args:
            app_data: Application data to send.

        Returns:
            List of events from the send operation.
        """
        events = self._connection.send_data(app_data)

        # Send any pending protocol data
        while data := self._connection.bytes_to_send():
            await self.send(data)

        return events

    async def receive_protocol_data(self) -> list[Event]:
        """Receive and process protocol data.

        This method receives a frame from the transport and passes it
        to the QASPConnection for processing.

        Returns:
            List of events from processing the received data.
        """
        data = await self.receive()
        return self._connection.receive_bytes(data)

    async def initiate_handshake(self) -> list[Event]:
        """Initiate the QASP handshake.

        This method initiates the handshake through the QASPConnection
        and sends the initial handshake message.

        Returns:
            List of events from initiating the handshake.
        """
        events = self._connection.initiate_handshake()

        # Send the handshake message
        while data := self._connection.bytes_to_send():
            await self.send(data)

        return events

    async def _read_exactly(self, n: int) -> bytes:
        """Read exactly n bytes from the connection.

        Args:
            n: Number of bytes to read.

        Returns:
            Exactly n bytes.

        Raises:
            asyncio.IncompleteReadError: If EOF before n bytes read.
        """
        assert self._reader is not None

        # Use buffer if we have data
        while len(self._receive_buffer) < n:
            chunk = await self._reader.read(DEFAULT_READ_SIZE)
            if not chunk:
                raise asyncio.IncompleteReadError(
                    bytes(self._receive_buffer),
                    n,
                )
            self._receive_buffer.extend(chunk)

        result = bytes(self._receive_buffer[:n])
        del self._receive_buffer[:n]
        return result

    async def _read_length_prefixed(self) -> bytes:
        """Read a length-prefixed message.

        Returns:
            The message payload.

        Raises:
            FramingError: If the length prefix is invalid.
            ConnectionClosedError: If connection closed before complete message.
        """
        # Read length prefix
        length_bytes = await self._read_exactly(LENGTH_PREFIX_SIZE)
        length = struct.unpack(">I", length_bytes)[0]

        # Validate length
        if length > MAX_MESSAGE_SIZE:
            raise FramingError(
                f"Message length {length} exceeds maximum {MAX_MESSAGE_SIZE}"
            )

        if length == 0:
            return b""

        # Read payload
        return await self._read_exactly(length)

    def _write_length_prefixed(self, data: bytes) -> bytes:
        """Create a length-prefixed frame.

        Args:
            data: The payload data.

        Returns:
            The framed data with length prefix.
        """
        length_prefix = struct.pack(">I", len(data))
        return length_prefix + data


class TCPServer:
    """TCP server for QASP connections.

    This class provides an asyncio-based TCP server that accepts
    connections and creates TCPTransport instances for each client.

    Usage:
        async def handle_connection(transport: TCPTransport) -> None:
            data = await transport.receive()
            await transport.send(data)
            await transport.close()

        server = TCPServer(
            connection_factory=lambda: QASPConnection(keypair, is_client=False),
            connection_handler=handle_connection,
        )
        await server.start("127.0.0.1", 8443)
        await server.serve_forever()
    """

    def __init__(
        self,
        connection_factory: Callable[[], QASPConnection],
        connection_handler: Callable[[TCPTransport], Awaitable[None]],
    ) -> None:
        """Initialize the server.

        Args:
            connection_factory: Factory function that creates a new
                QASPConnection for each accepted client.
            connection_handler: Async function that handles each client
                connection. Receives a TCPTransport instance.
        """
        self._connection_factory = connection_factory
        self._connection_handler = connection_handler
        self._server: asyncio.Server | None = None
        self._host: str | None = None
        self._port: int | None = None
        self._serving = False

    @property
    def host(self) -> str | None:
        """Return the bound host address, or None if not started."""
        return self._host

    @property
    def port(self) -> int | None:
        """Return the bound port, or None if not started."""
        return self._port

    @property
    def is_serving(self) -> bool:
        """Return True if the server is actively serving."""
        return self._serving and self._server is not None

    async def start(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        """Start the server.

        Args:
            host: The host address to bind.
            port: The port to bind. Use 0 for automatic port selection.

        Raises:
            TransportError: If the server fails to start.
        """
        if self._server is not None:
            raise TransportError("Server is already started")

        try:
            self._server = await asyncio.start_server(
                self._handle_client,
                host=host,
                port=port,
            )
            self._serving = True

            # Get the actual bound address
            sockets = self._server.sockets
            if sockets:
                addr = sockets[0].getsockname()
                self._host = addr[0]
                self._port = addr[1]
        except OSError as e:
            raise TransportError(f"Failed to start server: {e}") from e

    async def stop(self) -> None:
        """Stop the server.

        This closes the server and stops accepting new connections.
        Existing connections continue until they complete or are closed.
        """
        if self._server is not None:
            self._serving = False
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            self._host = None
            self._port = None

    async def serve_forever(self) -> None:
        """Serve connections until the server is stopped.

        This method blocks until stop() is called from another task.

        Raises:
            TransportError: If the server is not started.
        """
        if self._server is None:
            raise TransportError("Server is not started")

        await self._server.serve_forever()

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle an accepted client connection.

        This method creates a new QASPConnection and TCPTransport for
        the client, then calls the connection handler.

        Args:
            reader: The stream reader for the client.
            writer: The stream writer for the client.
        """
        # Create new connection and transport for this client
        connection = self._connection_factory()
        transport = TCPTransport(connection)
        transport._reader = reader
        transport._writer = writer
        transport._connected = True

        try:
            await self._connection_handler(transport)
        except Exception:
            pass  # Handler errors are silently ignored
        finally:
            await transport.close()

    async def __aenter__(self) -> TCPServer:
        """Enter async context manager."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit async context manager."""
        await self.stop()


async def connect(
    host: str,
    port: int,
    connection: QASPConnection,
    timeout: float = 30.0,
) -> TCPTransport:
    """Connect to a remote QASP endpoint.

    This is a convenience function that creates a TCPTransport and
    connects it to the specified host and port.

    Args:
        host: The remote host.
        port: The remote port.
        connection: The QASP connection.
        timeout: Connection timeout in seconds.

    Returns:
        A connected TCPTransport.

    Raises:
        ConnectionRefusedError: If the connection is refused.
        ConnectionTimeoutError: If the connection times out.
        TransportError: If another connection error occurs.
    """
    transport = TCPTransport(connection)
    await transport.connect(host, port, timeout)
    return transport


async def listen(
    host: str,
    port: int,
    connection_factory: Callable[[], QASPConnection],
    handler: Callable[[TCPTransport], Awaitable[None]],
) -> TCPServer:
    """Create and start a QASP TCP server.

    This is a convenience function that creates a TCPServer, starts it,
    and returns it. The server is started but not serving yet - call
    serve_forever() to start handling connections.

    Args:
        host: The host address to bind.
        port: The port to bind. Use 0 for automatic port selection.
        connection_factory: Factory for creating connections.
        handler: Handler function for each client connection.

    Returns:
        A started TCPServer.

    Raises:
        TransportError: If the server fails to start.
    """
    server = TCPServer(connection_factory, handler)
    await server.start(host, port)
    return server


async def serve(
    host: str,
    port: int,
    connection_factory: Callable[[], QASPConnection],
    handler: Callable[[TCPTransport], Awaitable[None]],
) -> None:
    """Create, start, and run a QASP TCP server forever.

    This is a convenience function that creates a TCPServer and runs
    it until cancelled or stopped.

    Args:
        host: The host address to bind.
        port: The port to bind. Use 0 for automatic port selection.
        connection_factory: Factory for creating connections.
        handler: Handler function for each client connection.

    Raises:
        TransportError: If the server fails to start.
    """
    server = await listen(host, port, connection_factory, handler)
    try:
        await server.serve_forever()
    finally:
        await server.stop()
