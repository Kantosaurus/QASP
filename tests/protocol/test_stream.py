"""Tests for stream multiplexing."""

from __future__ import annotations

import secrets
from unittest.mock import MagicMock

import pytest

from qasp.crypto import hybrid, signatures
from qasp.protocol import (
    QASPConnection,
    StreamClosed,
    StreamDataReceived,
    StreamOpened,
)
from qasp.protocol.stream import (
    Stream,
    StreamFlags,
    StreamFrame,
    StreamManager,
    StreamState,
)

# =============================================================================
# StreamFrame Tests
# =============================================================================


class TestStreamFrameRoundtrip:
    """Test StreamFrame serialization/deserialization."""

    def test_frame_roundtrip_basic(self) -> None:
        """Basic frame should serialize and deserialize correctly."""
        frame = StreamFrame(
            stream_id=123,
            flags=StreamFlags.NONE,
            payload=b"Hello, stream!",
        )

        serialized = frame.serialize()
        deserialized, consumed = StreamFrame.deserialize(serialized)

        assert deserialized.stream_id == frame.stream_id
        assert deserialized.flags == frame.flags
        assert deserialized.payload == frame.payload
        assert consumed == len(serialized)

    def test_frame_roundtrip_with_end_stream(self) -> None:
        """Frame with END_STREAM flag should roundtrip correctly."""
        frame = StreamFrame(
            stream_id=456,
            flags=StreamFlags.END_STREAM,
            payload=b"Final data",
        )

        serialized = frame.serialize()
        deserialized, consumed = StreamFrame.deserialize(serialized)

        assert deserialized.flags == StreamFlags.END_STREAM
        assert consumed == len(serialized)

    def test_frame_roundtrip_empty_payload(self) -> None:
        """Frame with empty payload should roundtrip correctly."""
        frame = StreamFrame(
            stream_id=789,
            flags=StreamFlags.NONE,
            payload=b"",
        )

        serialized = frame.serialize()
        deserialized, consumed = StreamFrame.deserialize(serialized)

        assert deserialized.payload == b""
        assert consumed == len(serialized)

    def test_frame_roundtrip_large_payload(self) -> None:
        """Frame with large payload should roundtrip correctly."""
        payload = bytes(range(256)) * 100  # 25.6KB
        frame = StreamFrame(
            stream_id=1,
            flags=StreamFlags.NONE,
            payload=payload,
        )

        serialized = frame.serialize()
        deserialized, consumed = StreamFrame.deserialize(serialized)

        assert deserialized.payload == payload
        assert consumed == len(serialized)

    def test_deserialize_incomplete_header_raises(self) -> None:
        """Deserializing incomplete header should raise ValueError."""
        with pytest.raises(ValueError, match="too short"):
            StreamFrame.deserialize(b"\x00\x00\x00")

    def test_deserialize_incomplete_payload_raises(self) -> None:
        """Deserializing incomplete payload should raise ValueError."""
        # Header says 100 bytes but only provide 5
        header = (
            b"\x00\x00\x00\x01"  # stream_id = 1
            + b"\x00"  # flags = NONE
            + b"\x00\x00\x00\x64"  # payload_length = 100
        )
        with pytest.raises(ValueError, match="Incomplete"):
            StreamFrame.deserialize(header + b"short")


class TestStreamFrameSerialization:
    """Test StreamFrame serialization format."""

    def test_serialization_format(self) -> None:
        """Frame should serialize to correct format."""
        frame = StreamFrame(
            stream_id=0x12345678,
            flags=StreamFlags.END_STREAM,
            payload=b"test",
        )

        serialized = frame.serialize()

        # Check stream_id (4 bytes big-endian)
        assert serialized[0:4] == b"\x12\x34\x56\x78"
        # Check flags (1 byte)
        assert serialized[4:5] == bytes([StreamFlags.END_STREAM])
        # Check payload_length (4 bytes big-endian)
        assert serialized[5:9] == b"\x00\x00\x00\x04"
        # Check payload
        assert serialized[9:] == b"test"


# =============================================================================
# Stream Tests
# =============================================================================


class TestStream:
    """Test Stream state management."""

    def test_stream_starts_open(self) -> None:
        """New stream should be in OPEN state."""
        stream = Stream(stream_id=1)
        assert stream.state == StreamState.OPEN
        assert stream.is_open()
        assert stream.is_readable()

    def test_half_closed_local(self) -> None:
        """HALF_CLOSED_LOCAL stream can receive but not send."""
        stream = Stream(stream_id=1, state=StreamState.HALF_CLOSED_LOCAL)
        assert not stream.is_open()
        assert stream.is_readable()

    def test_half_closed_remote(self) -> None:
        """HALF_CLOSED_REMOTE stream can send but not receive."""
        stream = Stream(stream_id=1, state=StreamState.HALF_CLOSED_REMOTE)
        assert stream.is_open()
        assert not stream.is_readable()

    def test_closed_stream(self) -> None:
        """CLOSED stream cannot send or receive."""
        stream = Stream(stream_id=1, state=StreamState.CLOSED)
        assert not stream.is_open()
        assert not stream.is_readable()


# =============================================================================
# StreamManager Tests
# =============================================================================


class TestOpenStream:
    """Test opening streams."""

    def test_open_stream_returns_id(self) -> None:
        """open_stream should return a stream ID."""
        mock_conn = MagicMock()
        manager = StreamManager(connection=mock_conn, is_client=True)

        stream_id = manager.open_stream()

        assert stream_id == 1

    def test_open_stream_with_capability_token(self) -> None:
        """open_stream should accept capability token ID."""
        mock_conn = MagicMock()
        manager = StreamManager(connection=mock_conn, is_client=True)

        token_id = b"token123"
        stream_id = manager.open_stream(capability_token_id=token_id)

        stream = manager.get_stream(stream_id)
        assert stream is not None
        assert stream.capability_token_id == token_id


class TestClientUsesOddIds:
    """Test that clients use odd stream IDs."""

    def test_client_first_stream_is_1(self) -> None:
        """Client's first stream should be ID 1."""
        mock_conn = MagicMock()
        manager = StreamManager(connection=mock_conn, is_client=True)

        stream_id = manager.open_stream()

        assert stream_id == 1

    def test_client_streams_increment_by_2(self) -> None:
        """Client stream IDs should increment by 2."""
        mock_conn = MagicMock()
        manager = StreamManager(connection=mock_conn, is_client=True)

        ids = [manager.open_stream() for _ in range(5)]

        assert ids == [1, 3, 5, 7, 9]

    def test_client_streams_are_all_odd(self) -> None:
        """All client stream IDs should be odd."""
        mock_conn = MagicMock()
        manager = StreamManager(connection=mock_conn, is_client=True)

        ids = [manager.open_stream() for _ in range(10)]

        assert all(id % 2 == 1 for id in ids)


class TestServerUsesEvenIds:
    """Test that servers use even stream IDs."""

    def test_server_first_stream_is_2(self) -> None:
        """Server's first stream should be ID 2."""
        mock_conn = MagicMock()
        manager = StreamManager(connection=mock_conn, is_client=False)

        stream_id = manager.open_stream()

        assert stream_id == 2

    def test_server_streams_increment_by_2(self) -> None:
        """Server stream IDs should increment by 2."""
        mock_conn = MagicMock()
        manager = StreamManager(connection=mock_conn, is_client=False)

        ids = [manager.open_stream() for _ in range(5)]

        assert ids == [2, 4, 6, 8, 10]

    def test_server_streams_are_all_even(self) -> None:
        """All server stream IDs should be even."""
        mock_conn = MagicMock()
        manager = StreamManager(connection=mock_conn, is_client=False)

        ids = [manager.open_stream() for _ in range(10)]

        assert all(id % 2 == 0 for id in ids)


class TestSendQueuesFrame:
    """Test sending data on streams."""

    def test_send_queues_frame(self) -> None:
        """send should queue a frame for sending."""
        mock_conn = MagicMock()
        manager = StreamManager(connection=mock_conn, is_client=True)

        stream_id = manager.open_stream()
        manager.send(stream_id, b"Hello")

        pending = manager.get_pending_data()
        assert len(pending) > 0

    def test_send_multiple_frames(self) -> None:
        """Multiple sends should queue multiple frames."""
        mock_conn = MagicMock()
        manager = StreamManager(connection=mock_conn, is_client=True)

        stream_id = manager.open_stream()
        manager.send(stream_id, b"First")
        manager.send(stream_id, b"Second")

        pending = manager.get_pending_data()

        # Deserialize and verify both frames
        frame1, offset1 = StreamFrame.deserialize(pending)
        frame2, _ = StreamFrame.deserialize(pending[offset1:])

        assert frame1.payload == b"First"
        assert frame2.payload == b"Second"

    def test_send_on_nonexistent_stream_raises(self) -> None:
        """Sending on nonexistent stream should raise ValueError."""
        mock_conn = MagicMock()
        manager = StreamManager(connection=mock_conn, is_client=True)

        with pytest.raises(ValueError, match="does not exist"):
            manager.send(999, b"data")

    def test_get_pending_data_clears_queue(self) -> None:
        """get_pending_data should clear the pending queue."""
        mock_conn = MagicMock()
        manager = StreamManager(connection=mock_conn, is_client=True)

        stream_id = manager.open_stream()
        manager.send(stream_id, b"Data")

        first_pending = manager.get_pending_data()
        second_pending = manager.get_pending_data()

        assert len(first_pending) > 0
        assert len(second_pending) == 0


class TestCloseStreamSendsEnd:
    """Test closing streams."""

    def test_close_stream_sends_end_stream(self) -> None:
        """close_stream should send END_STREAM flag."""
        mock_conn = MagicMock()
        manager = StreamManager(connection=mock_conn, is_client=True)

        stream_id = manager.open_stream()
        manager.close_stream(stream_id)

        pending = manager.get_pending_data()
        frame, _ = StreamFrame.deserialize(pending)

        assert frame.flags == StreamFlags.END_STREAM

    def test_close_stream_transitions_state(self) -> None:
        """close_stream should transition stream to HALF_CLOSED_LOCAL."""
        mock_conn = MagicMock()
        manager = StreamManager(connection=mock_conn, is_client=True)

        stream_id = manager.open_stream()
        manager.close_stream(stream_id)

        stream = manager.get_stream(stream_id)
        assert stream is not None
        assert stream.state == StreamState.HALF_CLOSED_LOCAL

    def test_send_with_end_stream(self) -> None:
        """send with end_stream=True should set END_STREAM flag."""
        mock_conn = MagicMock()
        manager = StreamManager(connection=mock_conn, is_client=True)

        stream_id = manager.open_stream()
        manager.send(stream_id, b"Final data", end_stream=True)

        pending = manager.get_pending_data()
        frame, _ = StreamFrame.deserialize(pending)

        assert frame.flags == StreamFlags.END_STREAM
        assert frame.payload == b"Final data"


class TestMultipleStreams:
    """Test multiple concurrent streams."""

    def test_multiple_streams_independent(self) -> None:
        """Multiple streams should be independent."""
        mock_conn = MagicMock()
        manager = StreamManager(connection=mock_conn, is_client=True)

        stream1 = manager.open_stream()
        stream2 = manager.open_stream()
        stream3 = manager.open_stream()

        manager.send(stream1, b"Stream 1 data")
        manager.send(stream2, b"Stream 2 data")
        manager.send(stream3, b"Stream 3 data")

        pending = manager.get_pending_data()

        # Parse all frames
        frames = []
        offset = 0
        while offset < len(pending):
            frame, consumed = StreamFrame.deserialize(pending[offset:])
            frames.append(frame)
            offset += consumed

        assert len(frames) == 3
        assert frames[0].stream_id == stream1
        assert frames[1].stream_id == stream2
        assert frames[2].stream_id == stream3

    def test_active_streams_property(self) -> None:
        """active_streams should list non-closed streams."""
        mock_conn = MagicMock()
        manager = StreamManager(connection=mock_conn, is_client=True)

        stream1 = manager.open_stream()
        stream2 = manager.open_stream()
        stream3 = manager.open_stream()

        # Close stream2 fully (both directions)
        manager.close_stream(stream2)
        stream2_obj = manager.get_stream(stream2)
        assert stream2_obj is not None
        stream2_obj.state = StreamState.CLOSED

        active = manager.active_streams
        assert stream1 in active
        assert stream2 not in active  # Closed
        assert stream3 in active


class TestProcessReceivedData:
    """Test processing received stream frames."""

    def test_process_single_frame(self) -> None:
        """Should process a single received frame."""
        mock_conn = MagicMock()
        manager = StreamManager(connection=mock_conn, is_client=True)

        # Create a frame
        frame = StreamFrame(stream_id=2, flags=StreamFlags.NONE, payload=b"Hello")
        data = frame.serialize()

        results = manager.process_received_data(data)

        assert len(results) == 1
        stream_id, payload, is_end = results[0]
        assert stream_id == 2
        assert payload == b"Hello"
        assert not is_end

    def test_process_multiple_frames(self) -> None:
        """Should process multiple frames in sequence."""
        mock_conn = MagicMock()
        manager = StreamManager(connection=mock_conn, is_client=True)

        frame1 = StreamFrame(stream_id=2, flags=StreamFlags.NONE, payload=b"First")
        frame2 = StreamFrame(stream_id=4, flags=StreamFlags.NONE, payload=b"Second")
        data = frame1.serialize() + frame2.serialize()

        results = manager.process_received_data(data)

        assert len(results) == 2
        assert results[0] == (2, b"First", False)
        assert results[1] == (4, b"Second", False)

    def test_process_end_stream_frame(self) -> None:
        """Should handle END_STREAM flag correctly."""
        mock_conn = MagicMock()
        manager = StreamManager(connection=mock_conn, is_client=True)

        frame = StreamFrame(
            stream_id=2, flags=StreamFlags.END_STREAM, payload=b"Final"
        )
        data = frame.serialize()

        results = manager.process_received_data(data)

        assert len(results) == 1
        _stream_id, _payload, is_end = results[0]
        assert is_end

        # Stream should be in HALF_CLOSED_REMOTE
        stream = manager.get_stream(2)
        assert stream is not None
        assert stream.state == StreamState.HALF_CLOSED_REMOTE

    def test_auto_creates_peer_streams(self) -> None:
        """Should auto-create streams initiated by peer."""
        mock_conn = MagicMock()
        manager = StreamManager(connection=mock_conn, is_client=True)

        # Peer (server) sends on stream 2 (even ID)
        frame = StreamFrame(stream_id=2, flags=StreamFlags.NONE, payload=b"Hello")
        data = frame.serialize()

        results = manager.process_received_data(data)

        assert len(results) == 1
        stream = manager.get_stream(2)
        assert stream is not None
        assert stream.state == StreamState.OPEN


# =============================================================================
# Connection Integration Tests
# =============================================================================


class TestConnectionStreamIntegration:
    """Test stream integration with QASPConnection."""

    @pytest.fixture
    def established_connections(self) -> tuple[QASPConnection, QASPConnection]:
        """Create established client and server connections."""
        shared_hmac_key = secrets.token_bytes(32)
        client = QASPConnection(
            kem_keypair=hybrid.generate_keypair(),
            sig_keypair=signatures.generate_keypair(),
            is_client=True,
            hmac_key=shared_hmac_key,
        )
        server = QASPConnection(
            kem_keypair=hybrid.generate_keypair(),
            sig_keypair=signatures.generate_keypair(),
            is_client=False,
            hmac_key=shared_hmac_key,
        )

        # Complete handshake
        client.initiate_handshake()
        server.receive_bytes(client.bytes_to_send())
        client.receive_bytes(server.bytes_to_send())
        server.receive_bytes(client.bytes_to_send())

        return client, server

    def test_stream_manager_initialized_after_handshake(
        self, established_connections: tuple[QASPConnection, QASPConnection]
    ) -> None:
        """Stream manager should be initialized after handshake."""
        client, server = established_connections

        assert client.stream_manager is not None
        assert server.stream_manager is not None

    def test_open_stream_returns_events(
        self, established_connections: tuple[QASPConnection, QASPConnection]
    ) -> None:
        """open_stream should return StreamOpened event."""
        client, _ = established_connections

        stream_id, events = client.open_stream()

        assert stream_id == 1  # Client uses odd IDs
        assert len(events) == 1
        assert isinstance(events[0], StreamOpened)
        assert events[0].stream_id == 1

    def test_close_stream_returns_events(
        self, established_connections: tuple[QASPConnection, QASPConnection]
    ) -> None:
        """close_stream should return StreamClosed event."""
        client, _ = established_connections

        stream_id, _ = client.open_stream()
        events = client.close_stream(stream_id)

        assert len(events) == 1
        assert isinstance(events[0], StreamClosed)
        assert events[0].stream_id == stream_id

    def test_process_stream_data_returns_events(
        self, established_connections: tuple[QASPConnection, QASPConnection]
    ) -> None:
        """process_stream_data should return StreamDataReceived events."""
        _, server = established_connections

        # Simulate receiving stream data
        frame = StreamFrame(stream_id=1, flags=StreamFlags.NONE, payload=b"Test data")
        events = server.process_stream_data(frame.serialize())

        assert len(events) == 1
        assert isinstance(events[0], StreamDataReceived)
        assert events[0].stream_id == 1
        assert events[0].data == b"Test data"

    def test_stream_manager_cleared_on_reset(
        self, established_connections: tuple[QASPConnection, QASPConnection]
    ) -> None:
        """Stream manager should be cleared on connection reset."""
        client, _ = established_connections

        assert client.stream_manager is not None

        client.reset()

        assert client.stream_manager is None
