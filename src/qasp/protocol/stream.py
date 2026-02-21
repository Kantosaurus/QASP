"""Stream multiplexing for QASP connections.

This module implements connection multiplexing, allowing multiple
concurrent capability streams over a single QASP connection.

Stream IDs follow HTTP/2 convention:
- Client-initiated streams use odd IDs (1, 3, 5, ...)
- Server-initiated streams use even IDs (2, 4, 6, ...)

Frame format (within encrypted ApplicationData payload):
    stream_id: 4 bytes (big-endian u32)
    flags: 1 byte (END_STREAM=0x01)
    payload_length: 4 bytes (big-endian u32)
    payload: variable
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntFlag
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .connection import QASPConnection

__all__ = [
    "Stream",
    "StreamFlags",
    "StreamFrame",
    "StreamManager",
    "StreamState",
]

# Frame header size: stream_id (4) + flags (1) + payload_length (4)
STREAM_FRAME_HEADER_SIZE = 9


class StreamFlags(IntFlag):
    """Flags for stream frames."""

    NONE = 0x00
    END_STREAM = 0x01  # Indicates stream is closing


class StreamState:
    """Stream state constants."""

    OPEN = "open"
    HALF_CLOSED_LOCAL = "half_closed_local"
    HALF_CLOSED_REMOTE = "half_closed_remote"
    CLOSED = "closed"


@dataclass
class StreamFrame:
    """A frame within a multiplexed stream.

    Attributes:
        stream_id: The stream identifier (4 bytes, big-endian).
        flags: Frame flags (1 byte).
        payload: The frame payload data.
    """

    stream_id: int
    flags: StreamFlags
    payload: bytes

    def serialize(self) -> bytes:
        """Serialize the frame to bytes.

        Returns:
            The serialized frame bytes.
        """
        return (
            self.stream_id.to_bytes(4, "big")
            + bytes([self.flags])
            + len(self.payload).to_bytes(4, "big")
            + self.payload
        )

    @classmethod
    def deserialize(cls, data: bytes) -> tuple[StreamFrame, int]:
        """Deserialize a frame from bytes.

        Args:
            data: The bytes to deserialize from.

        Returns:
            Tuple of (frame, bytes_consumed).

        Raises:
            ValueError: If the data is too short or malformed.
        """
        if len(data) < STREAM_FRAME_HEADER_SIZE:
            raise ValueError(
                f"Frame too short: need {STREAM_FRAME_HEADER_SIZE}, got {len(data)}"
            )

        stream_id = int.from_bytes(data[0:4], "big")
        flags = StreamFlags(data[4])
        payload_length = int.from_bytes(data[5:9], "big")

        total_length = STREAM_FRAME_HEADER_SIZE + payload_length
        if len(data) < total_length:
            raise ValueError(
                f"Incomplete frame: need {total_length}, got {len(data)}"
            )

        payload = data[9 : 9 + payload_length]
        return cls(stream_id=stream_id, flags=flags, payload=payload), total_length


@dataclass
class Stream:
    """A single multiplexed stream.

    Attributes:
        stream_id: The unique stream identifier.
        capability_token_id: Optional associated capability token.
        state: Current stream state.
    """

    stream_id: int
    capability_token_id: bytes | None = None
    state: str = StreamState.OPEN

    def is_open(self) -> bool:
        """Return True if the stream can send data."""
        return self.state in (StreamState.OPEN, StreamState.HALF_CLOSED_REMOTE)

    def is_readable(self) -> bool:
        """Return True if the stream can receive data."""
        return self.state in (StreamState.OPEN, StreamState.HALF_CLOSED_LOCAL)


@dataclass
class StreamManager:
    """Manages multiplexed streams over a QASP connection.

    Stream ID allocation:
    - Client uses odd IDs: 1, 3, 5, ...
    - Server uses even IDs: 2, 4, 6, ...

    Attributes:
        connection: The underlying QASP connection.
        is_client: True if this is the client side.
    """

    connection: QASPConnection
    is_client: bool
    _streams: dict[int, Stream] = field(default_factory=dict)
    _next_stream_id: int = field(init=False)
    _pending_frames: list[StreamFrame] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Initialize stream ID counter based on role."""
        # Client uses odd IDs starting at 1, server uses even IDs starting at 2
        self._next_stream_id = 1 if self.is_client else 2

    def open_stream(self, capability_token_id: bytes | None = None) -> int:
        """Open a new multiplexed stream.

        Args:
            capability_token_id: Optional capability token to associate.

        Returns:
            The new stream ID.
        """
        stream_id = self._next_stream_id
        self._next_stream_id += 2  # Increment by 2 to maintain odd/even

        stream = Stream(
            stream_id=stream_id,
            capability_token_id=capability_token_id,
            state=StreamState.OPEN,
        )
        self._streams[stream_id] = stream

        return stream_id

    def get_stream(self, stream_id: int) -> Stream | None:
        """Get a stream by ID.

        Args:
            stream_id: The stream ID.

        Returns:
            The stream, or None if not found.
        """
        return self._streams.get(stream_id)

    def send(self, stream_id: int, data: bytes, end_stream: bool = False) -> None:
        """Queue data to send on a stream.

        Args:
            stream_id: The stream to send on.
            data: The data to send.
            end_stream: If True, close the stream after sending.

        Raises:
            ValueError: If the stream doesn't exist or can't send.
        """
        stream = self._streams.get(stream_id)
        if stream is None:
            raise ValueError(f"Stream {stream_id} does not exist")

        if not stream.is_open():
            raise ValueError(f"Stream {stream_id} is not open for sending")

        flags = StreamFlags.END_STREAM if end_stream else StreamFlags.NONE
        frame = StreamFrame(stream_id=stream_id, flags=flags, payload=data)
        self._pending_frames.append(frame)

        if end_stream:
            if stream.state == StreamState.OPEN:
                stream.state = StreamState.HALF_CLOSED_LOCAL
            elif stream.state == StreamState.HALF_CLOSED_REMOTE:
                stream.state = StreamState.CLOSED

    def close_stream(self, stream_id: int) -> None:
        """Close a stream by sending END_STREAM.

        Args:
            stream_id: The stream to close.

        Raises:
            ValueError: If the stream doesn't exist.
        """
        stream = self._streams.get(stream_id)
        if stream is None:
            raise ValueError(f"Stream {stream_id} does not exist")

        if stream.is_open():
            self.send(stream_id, b"", end_stream=True)

    def get_pending_data(self) -> bytes:
        """Get all pending frame data for encryption.

        Returns:
            Serialized frames ready to be encrypted and sent.
        """
        if not self._pending_frames:
            return b""

        data = b"".join(frame.serialize() for frame in self._pending_frames)
        self._pending_frames.clear()
        return data

    def process_received_data(
        self, data: bytes
    ) -> list[tuple[int, bytes, bool]]:
        """Process received decrypted data into stream frames.

        Args:
            data: Decrypted data containing stream frames.

        Returns:
            List of (stream_id, payload, is_end_stream) tuples.
        """
        results: list[tuple[int, bytes, bool]] = []
        offset = 0

        while offset < len(data):
            try:
                frame, consumed = StreamFrame.deserialize(data[offset:])
                offset += consumed

                # Handle incoming frame
                is_end = bool(frame.flags & StreamFlags.END_STREAM)

                # Auto-create stream if it doesn't exist (peer-initiated)
                if frame.stream_id not in self._streams:
                    # Peer-initiated streams
                    stream = Stream(
                        stream_id=frame.stream_id,
                        state=StreamState.OPEN,
                    )
                    self._streams[frame.stream_id] = stream

                stream = self._streams[frame.stream_id]
                if stream.is_readable():
                    results.append((frame.stream_id, frame.payload, is_end))

                    if is_end:
                        if stream.state == StreamState.OPEN:
                            stream.state = StreamState.HALF_CLOSED_REMOTE
                        elif stream.state == StreamState.HALF_CLOSED_LOCAL:
                            stream.state = StreamState.CLOSED

            except ValueError:
                # Incomplete frame, break and wait for more data
                break

        return results

    @property
    def active_streams(self) -> list[int]:
        """Return list of active stream IDs."""
        return [
            sid
            for sid, stream in self._streams.items()
            if stream.state != StreamState.CLOSED
        ]

    @property
    def stream_count(self) -> int:
        """Return total number of streams (including closed)."""
        return len(self._streams)
