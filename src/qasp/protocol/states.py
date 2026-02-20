"""Protocol state definitions.

This module defines the state machine for QASP connections.
"""

from __future__ import annotations

from enum import Enum, auto

__all__ = [
    "ConnectionState",
]


class ConnectionState(Enum):
    """QASP connection state."""

    IDLE = auto()
    HANDSHAKE_INITIATED = auto()
    HANDSHAKE_RECEIVED = auto()
    ESTABLISHED = auto()
    CLOSING = auto()
    CLOSED = auto()
    ERROR = auto()
