"""CBOR encoding and framing.

This module provides CBOR serialization for QASP protocol messages
with a framed binary format including integrity protection.

Frame structure (per spec):
  - Magic: 2 bytes (0x51, 0x41 = "QA")
  - Version: 1 byte
  - Type: 1 byte (MessageType value)
  - Length: 4 bytes (big-endian, payload length)
  - Payload: variable (CBOR-encoded message)
  - HMAC: 48 bytes (HMAC-SHA-384 over header + payload)
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass, fields
from typing import Any

import cbor2

from .messages import Message, MessageType

__all__ = [
    "FRAME_MAGIC",
    "FRAME_VERSION",
    "HEADER_SIZE",
    "HMAC_SIZE",
    "FrameHeader",
    "FramingError",
    "decode",
    "decode_frame",
    "encode",
    "encode_frame",
]

# Frame constants
FRAME_MAGIC = b"\x51\x41"  # "QA" in ASCII
FRAME_VERSION = 0x01
HEADER_SIZE = 8  # magic(2) + version(1) + type(1) + length(4)
HMAC_SIZE = 48  # HMAC-SHA-384 output size


class FramingError(Exception):
    """Exception raised for framing errors.

    This includes invalid magic bytes, unsupported versions,
    truncated frames, and HMAC verification failures.
    """

    pass


@dataclass(frozen=True)
class FrameHeader:
    """Parsed frame header.

    Attributes:
        magic: 2-byte magic value (should be FRAME_MAGIC).
        version: Protocol version byte.
        message_type: Message type from MessageType enum.
        payload_length: Length of the CBOR payload in bytes.
    """

    magic: bytes
    version: int
    message_type: MessageType
    payload_length: int

    @classmethod
    def from_bytes(cls, data: bytes) -> FrameHeader:
        """Parse a frame header from bytes.

        Args:
            data: At least HEADER_SIZE bytes of frame data.

        Returns:
            Parsed FrameHeader.

        Raises:
            FramingError: If data is too short or header is invalid.
        """
        if len(data) < HEADER_SIZE:
            raise FramingError(
                f"Insufficient data for header: need {HEADER_SIZE}, got {len(data)}"
            )

        magic = data[0:2]
        version = data[2]
        type_byte = data[3]
        payload_length = struct.unpack(">I", data[4:8])[0]

        if magic != FRAME_MAGIC:
            raise FramingError(
                f"Invalid magic bytes: expected {FRAME_MAGIC!r}, got {magic!r}"
            )

        if version != FRAME_VERSION:
            raise FramingError(
                f"Unsupported version: expected {FRAME_VERSION}, got {version}"
            )

        try:
            message_type = MessageType(type_byte)
        except ValueError as e:
            raise FramingError(f"Unknown message type: 0x{type_byte:02x}") from e

        return cls(
            magic=magic,
            version=version,
            message_type=message_type,
            payload_length=payload_length,
        )

    def to_bytes(self) -> bytes:
        """Serialize the header to bytes.

        Returns:
            HEADER_SIZE bytes representing the header.
        """
        return (
            self.magic
            + bytes([self.version, self.message_type])
            + struct.pack(">I", self.payload_length)
        )


def encode(obj: Any) -> bytes:
    """Encode an object to CBOR.

    Args:
        obj: The object to encode. Can be a Message dataclass or
             any CBOR-serializable type.

    Returns:
        The CBOR-encoded bytes.
    """
    if isinstance(obj, Message):
        # Convert dataclass to dict for CBOR encoding
        # Skip message_type as it's in the frame header
        data: dict[str, Any] = {}
        for f in fields(obj):
            if f.name == "message_type":
                continue
            value = getattr(obj, f.name)
            # Convert tuples to lists for CBOR compatibility
            if isinstance(value, tuple):
                value = list(value)
            data[f.name] = value
        return cbor2.dumps(data)
    return cbor2.dumps(obj)


def decode(data: bytes) -> Any:
    """Decode CBOR data to an object.

    Args:
        data: The CBOR-encoded bytes.

    Returns:
        The decoded object (typically a dict).

    Raises:
        FramingError: If CBOR decoding fails.
    """
    try:
        return cbor2.loads(data)
    except cbor2.CBORDecodeError as e:
        raise FramingError(f"CBOR decode error: {e}") from e


def _compute_hmac(key: bytes, data: bytes) -> bytes:
    """Compute HMAC-SHA-384 over data.

    Args:
        key: The HMAC key.
        data: The data to authenticate.

    Returns:
        48-byte HMAC digest.
    """
    return hmac.new(key, data, hashlib.sha384).digest()


def encode_frame(message: Message, hmac_key: bytes) -> bytes:
    """Encode a message to a framed binary format.

    Creates a complete frame with header, CBOR payload, and HMAC.

    Args:
        message: The message to encode.
        hmac_key: Key for HMAC-SHA-384 computation.

    Returns:
        Complete frame bytes (header + payload + HMAC).

    Raises:
        FramingError: If encoding fails.
    """
    # Encode payload
    payload = encode(message)

    # Build header
    header = FrameHeader(
        magic=FRAME_MAGIC,
        version=FRAME_VERSION,
        message_type=message.message_type,
        payload_length=len(payload),
    )
    header_bytes = header.to_bytes()

    # Compute HMAC over header + payload
    frame_data = header_bytes + payload
    mac = _compute_hmac(hmac_key, frame_data)

    return frame_data + mac


def decode_frame(
    data: bytes,
    hmac_key: bytes,
) -> tuple[Message, int]:
    """Decode a framed binary format to a message.

    Parses the frame header, verifies the HMAC, and decodes the payload.

    Args:
        data: Frame bytes (may contain extra data after frame).
        hmac_key: Key for HMAC-SHA-384 verification.

    Returns:
        Tuple of (decoded message, total bytes consumed).

    Raises:
        FramingError: If frame is invalid, truncated, or HMAC fails.
    """
    # Parse header
    header = FrameHeader.from_bytes(data)

    # Calculate total frame size
    total_size = HEADER_SIZE + header.payload_length + HMAC_SIZE

    if len(data) < total_size:
        raise FramingError(
            f"Incomplete frame: need {total_size}, got {len(data)}"
        )

    # Extract components
    header_bytes = data[:HEADER_SIZE]
    payload = data[HEADER_SIZE : HEADER_SIZE + header.payload_length]
    received_mac = data[
        HEADER_SIZE + header.payload_length : total_size
    ]

    # Verify HMAC
    expected_mac = _compute_hmac(hmac_key, header_bytes + payload)
    if not hmac.compare_digest(received_mac, expected_mac):
        raise FramingError("HMAC verification failed")

    # Decode payload
    payload_dict = decode(payload)

    # Reconstruct message object
    message = _dict_to_message(header.message_type, payload_dict)

    return message, total_size


def _dict_to_message(message_type: MessageType, data: dict[str, Any]) -> Message:
    """Convert a dictionary to the appropriate Message subclass.

    Args:
        message_type: The type of message to create.
        data: Dictionary of field values.

    Returns:
        The appropriate Message subclass instance.

    Raises:
        FramingError: If message type is unknown.
    """
    # Import message classes here to avoid circular import
    from . import messages

    # Map message types to classes
    type_to_class: dict[MessageType, type[Message]] = {
        MessageType.CLIENT_HELLO: messages.ClientHello,
        MessageType.SERVER_HELLO: messages.ServerHello,
        MessageType.CLIENT_AUTH: messages.ClientAuth,
        MessageType.APPLICATION_DATA: messages.ApplicationData,
        MessageType.TOKEN_REVOCATION: messages.TokenRevocation,
        MessageType.REVOCATION_NOTICE: messages.RevocationNotice,
        MessageType.RESOURCE_REQUEST: messages.ResourceRequest,
        MessageType.RESOURCE_GRANT: messages.ResourceGrant,
        MessageType.METER_ACK: messages.MeterAck,
        MessageType.RESOURCE_SUSPEND: messages.ResourceSuspend,
        MessageType.RESOURCE_DENY: messages.ResourceDeny,
        MessageType.RESOURCE_RELEASE: messages.ResourceRelease,
        MessageType.DISPUTE_OPEN: messages.DisputeOpen,
        MessageType.DISPUTE_EVIDENCE: messages.DisputeEvidence,
        MessageType.DISPUTE_VERDICT: messages.DisputeVerdict,
        MessageType.METER_REPORT: messages.MeterReport,
        MessageType.CHANNEL_OPEN: messages.ChannelOpen,
        MessageType.CHANNEL_CLOSE: messages.ChannelClose,
        MessageType.PRICE_REQUEST: messages.PriceRequest,
        MessageType.ALERT: messages.Alert,
        MessageType.PRICE_OFFER: messages.PriceOffer,
        MessageType.PRICE_ACCEPT: messages.PriceAccept,
        MessageType.DELEGATION_REQUEST: messages.DelegationRequest,
        MessageType.DELEGATION_GRANT: messages.DelegationGrant,
        MessageType.RECONCILIATION_REQUEST: messages.ReconciliationRequest,
        MessageType.RECONCILIATION_RESPONSE: messages.ReconciliationResponse,
        MessageType.OCSP_REQUEST: messages.OCSPRequestMessage,
        MessageType.OCSP_RESPONSE: messages.OCSPResponseMessage,
    }

    msg_class = type_to_class.get(message_type)
    if msg_class is None:
        raise FramingError(f"Unknown message type: {message_type}")

    # Convert lists back to tuples for tuple fields
    for f in fields(msg_class):
        if f.name in data:
            value = data[f.name]
            # Check if the field type annotation contains 'tuple'
            type_str = str(f.type)
            if "tuple" in type_str and isinstance(value, list):
                data[f.name] = tuple(value)

    # Filter to only known fields for this message type
    valid_fields = {f.name for f in fields(msg_class) if f.name != "message_type"}
    filtered_data = {k: v for k, v in data.items() if k in valid_fields}

    return msg_class(**filtered_data)
