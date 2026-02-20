"""QASP connection management.

This module implements the QASPConnection class using a sans-I/O design
pattern for protocol state management.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .states import ConnectionState

if TYPE_CHECKING:
    from qasp.crypto.hybrid import HybridKeypair

    from .events import Event

__all__ = [
    "QASPConnection",
]


class QASPConnection:
    """A sans-I/O QASP connection.

    This class manages protocol state and generates/processes protocol
    events without performing any I/O directly.
    """

    def __init__(self, keypair: HybridKeypair) -> None:
        """Initialize a QASP connection.

        Args:
            keypair: The local hybrid keypair for this connection.
        """
        self._keypair = keypair
        self._state = ConnectionState.IDLE
        self._peer_public_key: bytes | None = None

    @property
    def state(self) -> ConnectionState:
        """Return the current connection state."""
        return self._state

    def initiate_handshake(self) -> bytes:
        """Initiate the QASP-Shake handshake.

        Returns:
            The handshake initiation message to send.
        """
        raise NotImplementedError("Handshake implementation pending")

    def receive_data(self, data: bytes) -> list[Event]:
        """Process received data and return protocol events.

        Args:
            data: The received data bytes.

        Returns:
            A list of protocol events.
        """
        raise NotImplementedError("Connection implementation pending")

    def send_data(self, data: bytes) -> bytes:
        """Prepare data for sending.

        Args:
            data: The application data to send.

        Returns:
            The encrypted protocol message to send.
        """
        raise NotImplementedError("Connection implementation pending")

    def close(self) -> bytes:
        """Initiate connection close.

        Returns:
            The close message to send.
        """
        raise NotImplementedError("Connection implementation pending")
