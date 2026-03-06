"""Exception hierarchy for QASP transport operations.

This module defines specific exception types for different transport
failure modes, enabling precise error handling for network operations.
"""

from __future__ import annotations

__all__ = [
    "TransportError",
    "ConnectionError",
    "ConnectionRefusedError",
    "ConnectionTimeoutError",
    "ConnectionClosedError",
    "SendError",
    "ReceiveError",
    "FramingError",
    "DiscoveryError",
    "AdvertisementError",
    "DiscoveryTimeoutError",
]


class TransportError(Exception):
    """Base exception for all QASP transport errors.

    All transport-related exceptions inherit from this class, allowing
    callers to catch all transport errors with a single except clause.
    """


class ConnectionError(TransportError):
    """Raised when a connection-related error occurs.

    This is the base class for connection-specific errors such as
    refused connections, timeouts, and unexpected closures.
    """


class ConnectionRefusedError(ConnectionError):
    """Raised when a connection is refused by the remote host.

    This typically occurs when no server is listening on the target
    port, or when a firewall blocks the connection.
    """


class ConnectionTimeoutError(ConnectionError):
    """Raised when a connection or operation times out.

    This may occur during initial connection establishment, or during
    read/write operations with timeouts.
    """


class ConnectionClosedError(ConnectionError):
    """Raised when the connection is unexpectedly closed.

    This may occur when the remote peer closes the connection, or
    when the underlying socket is reset.
    """


class SendError(TransportError):
    """Raised when sending data fails.

    This may occur due to network errors, broken pipes, or when
    the connection is in an invalid state for sending.
    """


class ReceiveError(TransportError):
    """Raised when receiving data fails.

    This may occur due to network errors or when the connection
    is in an invalid state for receiving.
    """


class FramingError(TransportError):
    """Raised when frame format validation fails.

    This includes invalid length prefixes, oversized messages,
    or malformed frame data.
    """


class DiscoveryError(TransportError):
    """Base exception for discovery failures."""


class AdvertisementError(DiscoveryError):
    """Raised for invalid, expired, or forged advertisements."""


class DiscoveryTimeoutError(DiscoveryError):
    """Raised when a discovery operation times out."""
