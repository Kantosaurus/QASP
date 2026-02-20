"""Protocol event definitions.

This module defines typed events emitted by the QASP protocol.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "ConnectionClosed",
    "ConnectionError",
    "DataReceived",
    "Event",
    "HandshakeComplete",
    "HandshakeInitiated",
]


@dataclass(frozen=True)
class Event:
    """Base class for protocol events."""


@dataclass(frozen=True)
class HandshakeInitiated(Event):
    """Handshake has been initiated."""

    initiator: bool


@dataclass(frozen=True)
class HandshakeComplete(Event):
    """Handshake completed successfully."""

    peer_public_key: bytes
    session_id: bytes


@dataclass(frozen=True)
class DataReceived(Event):
    """Application data received."""

    data: bytes


@dataclass(frozen=True)
class ConnectionClosed(Event):
    """Connection was closed."""

    reason: str | None = None


@dataclass(frozen=True)
class ConnectionError(Event):
    """Connection error occurred."""

    error: str
    fatal: bool = True
