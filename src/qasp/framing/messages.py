"""Protocol message definitions.

This module defines the message types used in QASP protocol.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

__all__ = [
    "Alert",
    "ApplicationData",
    "ClientHello",
    "CloseNotify",
    "Message",
    "MessageType",
    "ServerHello",
]


class MessageType(IntEnum):
    """QASP message types."""

    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    APPLICATION_DATA = 3
    ALERT = 4
    CLOSE_NOTIFY = 5
    CAPABILITY_REQUEST = 6
    CAPABILITY_GRANT = 7
    USAGE_REPORT = 8
    RECEIPT = 9


@dataclass(frozen=True)
class Message:
    """Base class for QASP messages."""

    message_type: MessageType


@dataclass(frozen=True)
class ClientHello(Message):
    """Client hello message for handshake initiation."""

    message_type: MessageType = MessageType.CLIENT_HELLO
    protocol_version: tuple[int, int] = (1, 0)
    client_random: bytes = b""
    public_key: bytes = b""
    cipher_suites: list[int] | None = None


@dataclass(frozen=True)
class ServerHello(Message):
    """Server hello message for handshake response."""

    message_type: MessageType = MessageType.SERVER_HELLO
    protocol_version: tuple[int, int] = (1, 0)
    server_random: bytes = b""
    public_key: bytes = b""
    ciphertext: bytes = b""
    selected_cipher_suite: int = 0


@dataclass(frozen=True)
class ApplicationData(Message):
    """Application data message."""

    message_type: MessageType = MessageType.APPLICATION_DATA
    encrypted_data: bytes = b""
    sequence_number: int = 0


@dataclass(frozen=True)
class Alert(Message):
    """Alert message for error reporting."""

    message_type: MessageType = MessageType.ALERT
    level: int = 0
    description: int = 0


@dataclass(frozen=True)
class CloseNotify(Message):
    """Close notification message."""

    message_type: MessageType = MessageType.CLOSE_NOTIFY
    reason: str = ""
