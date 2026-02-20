"""TCP transport layer.

This module implements TCP transport for QASP connections.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from qasp.protocol.connection import QASPConnection

__all__ = [
    "TCPTransport",
    "connect",
    "listen",
]


class TCPTransport:
    """TCP transport for QASP."""

    def __init__(self, connection: QASPConnection) -> None:
        """Initialize the transport.

        Args:
            connection: The QASP connection to transport.
        """
        self._connection = connection
        self._reader = None
        self._writer = None

    async def connect(self, host: str, port: int) -> None:
        """Connect to a remote endpoint.

        Args:
            host: The remote host.
            port: The remote port.
        """
        raise NotImplementedError("TCP transport implementation pending")

    async def send(self, data: bytes) -> None:
        """Send data over the connection.

        Args:
            data: The data to send.
        """
        raise NotImplementedError("TCP transport implementation pending")

    async def receive(self) -> bytes:
        """Receive data from the connection.

        Returns:
            The received data.
        """
        raise NotImplementedError("TCP transport implementation pending")

    async def close(self) -> None:
        """Close the transport."""
        raise NotImplementedError("TCP transport implementation pending")


async def connect(
    host: str,
    port: int,
    connection: QASPConnection,
) -> TCPTransport:
    """Connect to a remote QASP endpoint.

    Args:
        host: The remote host.
        port: The remote port.
        connection: The QASP connection.

    Returns:
        A connected TCPTransport.
    """
    raise NotImplementedError("TCP transport implementation pending")


async def listen(
    host: str,
    port: int,
    connection_factory: type[QASPConnection],
) -> None:
    """Listen for incoming QASP connections.

    Args:
        host: The local host to bind.
        port: The local port to bind.
        connection_factory: Factory for creating connections.
    """
    raise NotImplementedError("TCP transport implementation pending")
