"""QASP connection management.

This module implements the QASPConnection class using a sans-I/O design
pattern for protocol state management. The connection handles framing,
state transitions, and event generation without performing any I/O.
"""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING

from qasp.crypto.aead import decrypt, encrypt
from qasp.crypto.exceptions import DecryptionError
from qasp.crypto.kdf import derive_key
from qasp.framing.codec import (
    HEADER_SIZE,
    HMAC_SIZE,
    FrameHeader,
    FramingError,
    decode_frame,
    encode_frame,
)
from qasp.framing.messages import (
    Alert,
    ApplicationData,
    ClientAuth,
    ClientHello,
    Message,
    MessageType,
    ServerHello,
)

from .events import (
    AlertReceived,
    ConnectionClosed,
    ConnectionError,
    DataReceived,
    DataSent,
    Event,
    HandshakeComplete,
    HandshakeFailed,
    HandshakeInitiated,
    HandshakeTimeout,
    StreamClosed,
    StreamDataReceived,
    StreamOpened,
)
from .handshake import (
    Handshake,
    HandshakeConfig,
    HandshakeErrorType,
    HandshakeFailure,
    HandshakeKeys,
)
from .states import (
    ConnectionState,
    ProtocolError,
    StateTransitionError,
    is_valid_transition,
)

if TYPE_CHECKING:
    from qasp.crypto.hybrid import HybridKeypair

    from .stream import StreamManager

__all__ = [
    "QASPConnection",
]


class QASPConnection:
    """A sans-I/O QASP connection.

    This class manages protocol state and generates/processes protocol
    events without performing any I/O directly. It follows the sans-I/O
    pattern where:

    - `receive_bytes()` accepts incoming data and returns events
    - `bytes_to_send()` returns outgoing data to be sent
    - No blocking I/O is performed internally

    Usage:
        # Generate keypairs
        kem_keypair = hybrid.generate_keypair()
        sig_public, sig_secret = signatures.generate_keypair()

        conn = QASPConnection(
            kem_keypair=kem_keypair,
            sig_keypair=(sig_public, sig_secret),
            is_client=True,
        )

        # Client initiates handshake
        conn.initiate_handshake()

        # Get data to send
        while data := conn.bytes_to_send():
            socket.send(data)

        # Process incoming data
        events = conn.receive_bytes(socket.recv(4096))
        for event in events:
            if isinstance(event, HandshakeComplete):
                print("Connected!")
    """

    def __init__(
        self,
        kem_keypair: HybridKeypair,
        sig_keypair: tuple[bytes, bytes],
        is_client: bool = True,
        hmac_key: bytes | None = None,
        config: HandshakeConfig | None = None,
        certificate: bytes | None = None,
    ) -> None:
        """Initialize a QASP connection.

        Args:
            kem_keypair: The local hybrid keypair for key encapsulation.
            sig_keypair: The local signature keypair as (public_key, secret_key).
            is_client: True if this is a client connection, False for server.
            hmac_key: Optional HMAC key for frame integrity. If None, a
                temporary key is used until handshake establishes session key.
            config: Optional handshake configuration.
            certificate: Optional certificate for authentication.
        """
        self._kem_keypair = kem_keypair
        self._sig_keypair = sig_keypair
        self._is_client = is_client
        self._config = config or HandshakeConfig()
        self._certificate = certificate
        self._state = ConnectionState.IDLE
        self._peer_kem_public: bytes | None = None
        self._peer_sig_public: bytes | None = None
        self._session_id: bytes | None = None
        self._session_key: bytes | None = None
        self._nonce_iv: bytes | None = None

        # Frame integrity key (temporary until session established)
        self._hmac_key = hmac_key if hmac_key is not None else secrets.token_bytes(32)

        # Buffer management
        self._recv_buffer = bytearray()
        self._send_buffer = bytearray()

        # Sequence numbers
        self._send_seq = 0
        self._recv_seq = 0

        # Handshake state machine
        self._handshake: Handshake | None = None

        # Retry and timeout tracking
        self._retry_count = 0
        self._current_timeout_ms = self._config.initial_timeout_ms

        # Stream multiplexing manager
        self._stream_manager: StreamManager | None = None

    @property
    def state(self) -> ConnectionState:
        """Return the current connection state."""
        return self._state

    @property
    def is_established(self) -> bool:
        """Return True if the connection is established and ready for data."""
        return self._state == ConnectionState.ESTABLISHED

    @property
    def is_closed(self) -> bool:
        """Return True if the connection is closed."""
        return self._state in (ConnectionState.CLOSED, ConnectionState.ERROR)

    @property
    def retry_count(self) -> int:
        """Return the current retry count."""
        return self._retry_count

    def get_current_timeout(self) -> int:
        """Return the current timeout in milliseconds.

        Returns:
            Current timeout value, accounting for any backoff applied.
        """
        return self._current_timeout_ms

    def should_retry(self, error_type: HandshakeErrorType) -> bool:
        """Determine if a retry should be attempted for the given error.

        Args:
            error_type: The type of handshake error that occurred.

        Returns:
            True if a retry should be attempted, False otherwise.
        """
        # Auth failures should not be retried
        if error_type == HandshakeErrorType.AUTH_FAILED:
            return False

        # KEM failures should not be retried (cryptographic issue)
        if error_type == HandshakeErrorType.KEM_FAILED:
            return False

        # Check if we've exceeded max retries
        if self._retry_count >= self._config.max_retries:
            return False

        # Version mismatch and timeout are retryable
        return error_type in (
            HandshakeErrorType.VERSION_MISMATCH,
            HandshakeErrorType.TIMEOUT,
        )

    def prepare_retry(self) -> None:
        """Prepare for a retry attempt by incrementing count and applying backoff.

        Updates the retry count and calculates the new timeout using
        exponential backoff, capped at max_timeout_ms.
        """
        self._retry_count += 1

        # Calculate new timeout with exponential backoff
        new_timeout = int(
            self._current_timeout_ms * self._config.backoff_multiplier
        )

        # Cap at max timeout
        self._current_timeout_ms = min(new_timeout, self._config.max_timeout_ms)

    def handle_timeout(self) -> list[Event]:
        """Handle a handshake timeout.

        Returns:
            List of events including HandshakeTimeout.
        """
        will_retry = self.should_retry(HandshakeErrorType.TIMEOUT)

        events: list[Event] = [
            HandshakeTimeout(
                timeout_ms=self._current_timeout_ms,
                retry_count=self._retry_count,
                will_retry=will_retry,
            )
        ]

        if will_retry:
            self.prepare_retry()
        else:
            # Max retries exceeded, transition to error state
            try:
                self._transition_to(ConnectionState.ERROR)
            except StateTransitionError:
                self._state = ConnectionState.ERROR
            events.append(
                HandshakeFailed(
                    reason=f"Handshake timeout after {self._retry_count} retries",
                    fatal=True,
                )
            )

        return events

    @property
    def session_id(self) -> bytes | None:
        """Return the session ID if established, None otherwise."""
        return self._session_id

    @property
    def session_key(self) -> bytes | None:
        """Return the session key if established, None otherwise."""
        return self._session_key

    @property
    def peer_kem_public_key(self) -> bytes | None:
        """Return the peer's KEM public key if known, None otherwise."""
        return self._peer_kem_public

    @property
    def peer_sig_public_key(self) -> bytes | None:
        """Return the peer's signature public key if known, None otherwise."""
        return self._peer_sig_public

    def _transition_to(self, new_state: ConnectionState) -> None:
        """Transition to a new state.

        Args:
            new_state: The target state.

        Raises:
            StateTransitionError: If the transition is invalid.
        """
        if not is_valid_transition(self._state, new_state):
            raise StateTransitionError(self._state, new_state)
        self._state = new_state

    def _construct_nonce(self, sequence_number: int) -> bytes:
        """Construct AES-GCM nonce: 4-byte IV + 8-byte sequence.

        TLS 1.3 style counter-based nonce construction ensures unique
        nonces without additional per-message overhead.

        Args:
            sequence_number: The message sequence number.

        Returns:
            12-byte nonce suitable for AES-256-GCM.
        """
        assert self._nonce_iv is not None
        return self._nonce_iv + sequence_number.to_bytes(8, "big")

    def initiate_handshake(self) -> list[Event]:
        """Initiate the QASP-Shake handshake.

        Must be called by the client to start the handshake.

        Returns:
            List of events (HandshakeInitiated).

        Raises:
            ProtocolError: If not in IDLE state or not a client.
        """
        if self._state != ConnectionState.IDLE:
            raise ProtocolError(
                f"Cannot initiate handshake in state {self._state.name}"
            )

        if not self._is_client:
            raise ProtocolError("Only clients can initiate handshake")

        # Create handshake state machine
        self._handshake = Handshake(
            kem_keypair=self._kem_keypair,
            sig_keypair=self._sig_keypair,
            is_initiator=True,
            config=self._config,
            certificate=self._certificate,
        )

        # Generate ClientHello
        client_hello = self._handshake.create_client_hello()

        # Encode and queue for sending
        frame = encode_frame(client_hello, self._hmac_key)
        self._send_buffer.extend(frame)

        # Transition state
        self._transition_to(ConnectionState.HELLO_SENT)

        return [HandshakeInitiated(initiator=True)]

    def receive_bytes(self, data: bytes) -> list[Event]:
        """Process received data and return protocol events.

        This method buffers incoming data and attempts to parse
        complete frames. For each complete frame, it processes
        the message and may emit events.

        Args:
            data: The received data bytes.

        Returns:
            A list of protocol events.
        """
        events: list[Event] = []

        if not data:
            return events

        self._recv_buffer.extend(data)

        # Process all complete frames in buffer
        while True:
            # Check if we have enough data for a header
            if len(self._recv_buffer) < HEADER_SIZE:
                break

            # Peek at header to determine frame size
            try:
                header = FrameHeader.from_bytes(bytes(self._recv_buffer))
            except FramingError as e:
                # Invalid header - emit error and clear buffer
                events.append(ConnectionError(error=str(e), fatal=True))
                self._recv_buffer.clear()
                self._transition_to(ConnectionState.ERROR)
                break

            # Check if we have the complete frame
            frame_size = HEADER_SIZE + header.payload_length + HMAC_SIZE
            if len(self._recv_buffer) < frame_size:
                break

            # Extract and process the frame
            frame_data = bytes(self._recv_buffer[:frame_size])
            del self._recv_buffer[:frame_size]

            try:
                message, _ = decode_frame(frame_data, self._hmac_key)
                msg_events = self._process_message(message)
                events.extend(msg_events)
            except FramingError as e:
                events.append(ConnectionError(error=str(e), fatal=True))
                self._transition_to(ConnectionState.ERROR)
                break

        return events

    def _process_message(self, message: Message) -> list[Event]:
        """Handle a received message by type.

        Args:
            message: The decoded message.

        Returns:
            List of events generated from processing.
        """
        handlers = {
            MessageType.CLIENT_HELLO: self._handle_client_hello,
            MessageType.SERVER_HELLO: self._handle_server_hello,
            MessageType.CLIENT_AUTH: self._handle_client_auth,
            MessageType.APPLICATION_DATA: self._handle_application_data,
            MessageType.ALERT: self._handle_alert,
        }

        handler = handlers.get(message.message_type)
        if handler is not None:
            return handler(message)

        # Unknown or unhandled message type
        return []

    def _handle_client_hello(self, message: Message) -> list[Event]:
        """Handle ClientHello (server side)."""
        if self._is_client:
            return [HandshakeFailed(reason="Client received ClientHello", fatal=True)]

        if self._state != ConnectionState.IDLE:
            return [
                HandshakeFailed(
                    reason=f"ClientHello in wrong state: {self._state.name}",
                    fatal=True,
                )
            ]

        assert isinstance(message, ClientHello)

        # Create server handshake state machine
        self._handshake = Handshake(
            kem_keypair=self._kem_keypair,
            sig_keypair=self._sig_keypair,
            is_initiator=False,
            config=self._config,
            certificate=self._certificate,
        )

        # Process ClientHello and generate ServerHello
        result = self._handshake.process_client_hello(message)

        if isinstance(result, HandshakeFailure):
            return self._handle_handshake_failure(result)

        # result is ServerHello
        server_hello = result

        # Encode and queue for sending
        frame = encode_frame(server_hello, self._hmac_key)
        self._send_buffer.extend(frame)

        # Transition to HELLO_RECEIVED
        self._transition_to(ConnectionState.HELLO_RECEIVED)

        return [HandshakeInitiated(initiator=False)]

    def _handle_server_hello(self, message: Message) -> list[Event]:
        """Handle ServerHello (client side)."""
        if not self._is_client:
            return [HandshakeFailed(reason="Server received ServerHello", fatal=True)]

        if self._state != ConnectionState.HELLO_SENT:
            return [
                HandshakeFailed(
                    reason=f"ServerHello in wrong state: {self._state.name}",
                    fatal=True,
                )
            ]

        if self._handshake is None:
            return [
                HandshakeFailed(
                    reason="No handshake in progress",
                    fatal=True,
                )
            ]

        assert isinstance(message, ServerHello)

        # Process ServerHello and generate ClientAuth
        result = self._handshake.process_server_hello(message)

        if isinstance(result, HandshakeFailure):
            return self._handle_handshake_failure(result)

        # result is ClientAuth
        client_auth = result

        # Encode and queue for sending
        frame = encode_frame(client_auth, self._hmac_key)
        self._send_buffer.extend(frame)

        # Transition to AUTHENTICATED
        self._transition_to(ConnectionState.AUTHENTICATED)

        # Complete client handshake
        keys_result = self._handshake.complete_client_handshake()

        if isinstance(keys_result, HandshakeFailure):
            return self._handle_handshake_failure(keys_result)

        # keys_result is HandshakeKeys
        return self._complete_handshake(keys_result)

    def _handle_client_auth(self, message: Message) -> list[Event]:
        """Handle ClientAuth (server side)."""
        if self._is_client:
            return [HandshakeFailed(reason="Client received ClientAuth", fatal=True)]

        if self._state != ConnectionState.HELLO_RECEIVED:
            return [
                HandshakeFailed(
                    reason=f"ClientAuth in wrong state: {self._state.name}",
                    fatal=True,
                )
            ]

        if self._handshake is None:
            return [
                HandshakeFailed(
                    reason="No handshake in progress",
                    fatal=True,
                )
            ]

        assert isinstance(message, ClientAuth)

        # Process ClientAuth and complete handshake
        result = self._handshake.process_client_auth(message)

        if isinstance(result, HandshakeFailure):
            return self._handle_handshake_failure(result)

        # result is HandshakeKeys
        # Transition through AUTHENTICATED to ESTABLISHED
        self._transition_to(ConnectionState.AUTHENTICATED)

        return self._complete_handshake(result)

    def _complete_handshake(self, keys: HandshakeKeys) -> list[Event]:
        """Complete the handshake with derived keys.

        Args:
            keys: The derived handshake keys.

        Returns:
            List of events including HandshakeComplete.
        """
        # Store session data
        self._session_key = keys.session_key
        self._session_id = keys.session_id
        self._peer_kem_public = keys.peer_kem_public
        self._peer_sig_public = keys.peer_sig_public

        # Derive nonce IV for AES-GCM encryption
        # Uses HKDF to derive 4 bytes for the IV prefix from session key
        self._nonce_iv = derive_key(
            input_key_material=keys.session_key,
            info=b"qasp_nonce_iv",
            length=4,
        )

        # Switch to session key for HMAC
        self._hmac_key = keys.session_key

        # Transition to ESTABLISHED
        self._transition_to(ConnectionState.ESTABLISHED)

        # Clear handshake state machine
        self._handshake = None

        # Initialize stream manager for connection multiplexing
        from .stream import StreamManager

        self._stream_manager = StreamManager(
            connection=self,
            is_client=self._is_client,
        )

        return [
            HandshakeComplete(
                peer_public_key=keys.peer_kem_public,
                session_id=keys.session_id,
            )
        ]

    def _handle_handshake_failure(self, failure: HandshakeFailure) -> list[Event]:
        """Handle a handshake failure by sending alert.

        Args:
            failure: The handshake failure details.

        Returns:
            List of events including HandshakeFailed.
        """
        # Send alert to peer
        alert = Alert(
            level=2,  # Fatal
            description=failure.alert_code,
            message=failure.message,
            related_message_type=0,
        )

        try:
            frame = encode_frame(alert, self._hmac_key)
            self._send_buffer.extend(frame)
        except FramingError:
            # If encoding fails, just continue with failure
            pass

        # Transition to ERROR state
        try:
            self._transition_to(ConnectionState.ERROR)
        except StateTransitionError:
            self._state = ConnectionState.ERROR

        return [HandshakeFailed(reason=failure.message, fatal=True)]

    def _handle_application_data(self, message: Message) -> list[Event]:
        """Handle ApplicationData."""
        if self._state != ConnectionState.ESTABLISHED:
            return [
                ConnectionError(
                    error=f"Data received in state {self._state.name}",
                    fatal=False,
                )
            ]

        assert isinstance(message, ApplicationData)

        # Verify sequence number for replay protection
        if message.sequence_number < self._recv_seq:
            return [
                ConnectionError(
                    error="Replay detected: old sequence number",
                    fatal=False,
                )
            ]

        self._recv_seq = message.sequence_number + 1

        # Decrypt the payload using AES-256-GCM
        assert self._session_key is not None
        nonce = self._construct_nonce(message.sequence_number)
        aad = (
            bytes([MessageType.APPLICATION_DATA.value])
            + message.sequence_number.to_bytes(8, "big")
        )

        try:
            plaintext = decrypt(
                key=self._session_key,
                nonce=nonce,
                ciphertext=message.encrypted_data,
                associated_data=aad,
            )
        except DecryptionError as e:
            return [ConnectionError(error=f"Decryption failed: {e}", fatal=True)]

        return [
            DataReceived(
                data=plaintext,
                sequence_number=message.sequence_number,
            )
        ]

    def _handle_alert(self, message: Message) -> list[Event]:
        """Handle Alert messages."""
        assert isinstance(message, Alert)

        events: list[Event] = [
            AlertReceived(
                level=message.level,
                description=message.description,
                message=message.message,
            )
        ]

        # Fatal alerts close the connection
        if message.level == 2:  # Fatal
            self._transition_to(ConnectionState.ERROR)
            events.append(
                ConnectionClosed(
                    reason=f"Fatal alert: {message.description}",
                    graceful=False,
                )
            )

        return events

    def bytes_to_send(self) -> bytes:
        """Return pending outbound data.

        This method returns all queued outbound data and clears
        the send buffer. The caller is responsible for actually
        sending the data.

        Returns:
            Bytes to send (may be empty).
        """
        data = bytes(self._send_buffer)
        self._send_buffer.clear()
        return data

    def send_data(self, data: bytes) -> list[Event]:
        """Queue application data for sending.

        Args:
            data: The application data to send.

        Returns:
            List of events (DataSent on success, ConnectionError on failure).

        Raises:
            ProtocolError: If connection is not established.
        """
        if self._state != ConnectionState.ESTABLISHED:
            raise ProtocolError(
                f"Cannot send data in state {self._state.name}"
            )

        # Build ApplicationData message
        seq = self._send_seq
        self._send_seq += 1

        # Encrypt the payload using AES-256-GCM
        assert self._session_key is not None
        nonce = self._construct_nonce(seq)
        aad = bytes([MessageType.APPLICATION_DATA.value]) + seq.to_bytes(8, "big")
        _, ciphertext = encrypt(
            key=self._session_key,
            plaintext=data,
            associated_data=aad,
            nonce=nonce,
        )

        app_data = ApplicationData(
            encrypted_data=ciphertext,
            sequence_number=seq,
        )

        frame = encode_frame(app_data, self._hmac_key)
        self._send_buffer.extend(frame)

        return [DataSent(length=len(data), sequence_number=seq)]

    def open_stream(self, capability_token_id: bytes | None = None) -> tuple[int, list[Event]]:
        """Open a new multiplexed stream.

        Args:
            capability_token_id: Optional capability token to associate.

        Returns:
            Tuple of (stream_id, events).

        Raises:
            ProtocolError: If connection is not established.
        """
        if self._state != ConnectionState.ESTABLISHED:
            raise ProtocolError(
                f"Cannot open stream in state {self._state.name}"
            )

        if self._stream_manager is None:
            raise ProtocolError("Stream manager not initialized")

        stream_id = self._stream_manager.open_stream(capability_token_id)
        event = StreamOpened(stream_id=stream_id, capability_token_id=capability_token_id)
        return stream_id, [event]

    def send_stream_data(
        self, stream_id: int, data: bytes, end_stream: bool = False
    ) -> list[Event]:
        """Send data on a specific stream.

        This queues stream frame data for encryption and sending.

        Args:
            stream_id: The stream to send on.
            data: The data to send.
            end_stream: If True, close the stream after sending.

        Returns:
            List of events (StreamDataReceived for acknowledgment).

        Raises:
            ProtocolError: If connection is not established.
            ValueError: If stream doesn't exist or can't send.
        """
        if self._state != ConnectionState.ESTABLISHED:
            raise ProtocolError(
                f"Cannot send stream data in state {self._state.name}"
            )

        if self._stream_manager is None:
            raise ProtocolError("Stream manager not initialized")

        # Queue the data on the stream
        self._stream_manager.send(stream_id, data, end_stream)

        # Get pending stream data and send as encrypted ApplicationData
        pending_data = self._stream_manager.get_pending_data()
        if pending_data:
            self.send_data(pending_data)

        events: list[Event] = []
        if end_stream:
            events.append(StreamClosed(stream_id=stream_id, reason="local_close"))

        return events

    def close_stream(self, stream_id: int) -> list[Event]:
        """Close a specific stream.

        Args:
            stream_id: The stream to close.

        Returns:
            List of events.

        Raises:
            ProtocolError: If connection is not established.
            ValueError: If stream doesn't exist.
        """
        if self._state != ConnectionState.ESTABLISHED:
            raise ProtocolError(
                f"Cannot close stream in state {self._state.name}"
            )

        if self._stream_manager is None:
            raise ProtocolError("Stream manager not initialized")

        self._stream_manager.close_stream(stream_id)

        # Send pending stream data
        pending_data = self._stream_manager.get_pending_data()
        if pending_data:
            self.send_data(pending_data)

        return [StreamClosed(stream_id=stream_id, reason="local_close")]

    def process_stream_data(self, data: bytes) -> list[Event]:
        """Process received data as stream frames.

        This should be called with decrypted ApplicationData payload
        when using stream multiplexing.

        Args:
            data: Decrypted payload containing stream frames.

        Returns:
            List of StreamDataReceived events.
        """
        if self._stream_manager is None:
            return []

        events: list[Event] = []
        for stream_id, payload, is_end in self._stream_manager.process_received_data(data):
            events.append(
                StreamDataReceived(
                    stream_id=stream_id,
                    data=payload,
                    end_stream=is_end,
                )
            )
            if is_end:
                events.append(StreamClosed(stream_id=stream_id, reason="remote_close"))

        return events

    @property
    def stream_manager(self) -> StreamManager | None:
        """Return the stream manager if initialized."""
        return self._stream_manager

    def close(self, reason: str = "") -> list[Event]:
        """Initiate connection close.

        Args:
            reason: Optional reason for closing.

        Returns:
            List of events.
        """
        if self._state in (ConnectionState.CLOSED, ConnectionState.ERROR):
            return []

        if self._state == ConnectionState.CLOSING:
            # Already closing
            return []

        # Send close alert
        alert = Alert(
            level=1,  # Warning
            description=0,  # close_notify
            message=reason,
            related_message_type=0,
        )

        try:
            frame = encode_frame(alert, self._hmac_key)
            self._send_buffer.extend(frame)
        except FramingError:
            # If encoding fails, just close anyway - alert is best-effort
            pass

        # Transition to CLOSING then CLOSED
        if self._state not in (ConnectionState.CLOSED, ConnectionState.ERROR):
            try:
                self._transition_to(ConnectionState.CLOSING)
                self._transition_to(ConnectionState.CLOSED)
            except StateTransitionError:
                # Force close
                self._state = ConnectionState.CLOSED

        return [ConnectionClosed(reason=reason or None, graceful=True)]

    def reset(self) -> None:
        """Reset the connection to IDLE state.

        This allows reusing the connection object for a new session.
        """
        self._state = ConnectionState.IDLE
        self._peer_kem_public = None
        self._peer_sig_public = None
        self._session_id = None
        self._session_key = None
        self._nonce_iv = None
        self._recv_buffer.clear()
        self._send_buffer.clear()
        self._send_seq = 0
        self._recv_seq = 0
        self._handshake = None
        self._stream_manager = None
        self._hmac_key = secrets.token_bytes(32)
        self._retry_count = 0
        self._current_timeout_ms = self._config.initial_timeout_ms
