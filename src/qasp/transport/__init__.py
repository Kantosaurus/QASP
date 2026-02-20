"""Network transport layer.

This module provides transport implementations:
- TCP transport with length-prefixed framing
- QASP-Discover for service discovery
"""

from .exceptions import (
    ConnectionClosedError,
    ConnectionError,
    ConnectionRefusedError,
    ConnectionTimeoutError,
    FramingError,
    ReceiveError,
    SendError,
    TransportError,
)
from .tcp import (
    DEFAULT_READ_SIZE,
    LENGTH_PREFIX_SIZE,
    MAX_MESSAGE_SIZE,
    TCPServer,
    TCPTransport,
    connect,
    listen,
    serve,
)

__all__ = [
    # Submodules
    "discover",
    "tcp",
    # Exceptions
    "TransportError",
    "ConnectionError",
    "ConnectionRefusedError",
    "ConnectionTimeoutError",
    "ConnectionClosedError",
    "SendError",
    "ReceiveError",
    "FramingError",
    # Constants
    "LENGTH_PREFIX_SIZE",
    "MAX_MESSAGE_SIZE",
    "DEFAULT_READ_SIZE",
    # Classes
    "TCPTransport",
    "TCPServer",
    # Functions
    "connect",
    "listen",
    "serve",
]
