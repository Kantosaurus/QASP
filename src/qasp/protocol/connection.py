"""QASP connection management.

This module implements the QASPConnection class using a sans-I/O design
pattern for protocol state management. The connection handles framing,
state transitions, and event generation without performing any I/O.
"""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING

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
)
from .states import (
    ConnectionState,
    ProtocolError,
    StateTransitionError,
    is_valid_transition,
)

if TYPE_CHECKING:
    from qasp.crypto.hybrid import HybridKeypair

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
        conn = QASPConnection(keypair, is_client=True)

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
        keypair: HybridKeypair,
        is_client: bool = True,
        hmac_key: bytes | None = None,
    ) -> None:
        """Initialize a QASP connection.

        Args:
            keypair: The local hybrid keypair for this connection.
            is_client: True if this is a client connection, False for server.
            hmac_key: Optional HMAC key for frame integrity. If None, a
                temporary key is used until handshake establishes session key.
        """
        self._keypair = keypair
        self._is_client = is_client
        self._state = ConnectionState.IDLE
        self._peer_public_key: bytes | None = None
        self._session_id: bytes | None = None

        # Frame integrity key (temporary until session established)
        self._hmac_key = hmac_key if hmac_key is not None else secrets.token_bytes(32)

        # Buffer management
        self._recv_buffer = bytearray()
        self._send_buffer = bytearray()

        # Sequence numbers
        self._send_seq = 0
        self._recv_seq = 0

        # Handshake state
        self._client_random: bytes | None = None
        self._server_random: bytes | None = None

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
    def session_id(self) -> bytes | None:
        """Return the session ID if established, None otherwise."""
        return self._session_id

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

        # Generate client random
        self._client_random = secrets.token_bytes(32)

        # Build ClientHello message
        # Note: HybridKeypair contains KEM keys; signature keys would come
        # from a separate signing keypair in a full implementation
        client_hello = ClientHello(
            protocol_version=(1, 0),
            client_random=self._client_random,
            kem_public_key=self._keypair.public_key,  # Combined hybrid public key
            sig_public_key=b"",  # Signature key would come from separate keypair
            cipher_suites=(1,),  # Default cipher suite
            extensions=b"",
        )

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

        # Store client's data
        self._client_random = message.client_random
        self._peer_public_key = message.kem_public_key

        # Transition to HELLO_RECEIVED
        self._transition_to(ConnectionState.HELLO_RECEIVED)

        # Generate server random and response
        self._server_random = secrets.token_bytes(32)

        # Build ServerHello - simplified for skeleton
        # Full implementation would do KEM encapsulation here
        server_hello = ServerHello(
            protocol_version=(1, 0),
            server_random=self._server_random,
            kem_ciphertext=b"",  # Would be actual KEM ciphertext
            kem_public_key=self._keypair.public_key,  # Combined hybrid public key
            sig_public_key=b"",  # Signature key would come from separate keypair
            selected_cipher_suite=1,
            signature=b"",  # Would be actual signature
            extensions=b"",
        )

        frame = encode_frame(server_hello, self._hmac_key)
        self._send_buffer.extend(frame)

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

        assert isinstance(message, ServerHello)

        # Store server's data
        self._server_random = message.server_random
        self._peer_public_key = message.kem_public_key

        # Transition to AUTHENTICATED
        self._transition_to(ConnectionState.AUTHENTICATED)

        # Send ClientAuth
        client_auth = ClientAuth(
            kem_ciphertext=b"",  # Would be actual KEM ciphertext
            signature=b"",  # Would be actual signature
            certificate=b"",
        )

        frame = encode_frame(client_auth, self._hmac_key)
        self._send_buffer.extend(frame)

        # Generate session ID
        self._session_id = secrets.token_bytes(32)

        # Transition to ESTABLISHED
        self._transition_to(ConnectionState.ESTABLISHED)

        return [
            HandshakeComplete(
                peer_public_key=self._peer_public_key,
                session_id=self._session_id,
            )
        ]

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

        assert isinstance(message, ClientAuth)

        # Verify client auth - simplified for skeleton
        # Full implementation would verify signature

        # Transition through AUTHENTICATED to ESTABLISHED
        self._transition_to(ConnectionState.AUTHENTICATED)

        # Generate session ID
        self._session_id = secrets.token_bytes(32)

        self._transition_to(ConnectionState.ESTABLISHED)

        return [
            HandshakeComplete(
                peer_public_key=self._peer_public_key or b"",
                session_id=self._session_id,
            )
        ]

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

        # Verify sequence number
        if message.sequence_number < self._recv_seq:
            return [
                ConnectionError(
                    error="Replay detected: old sequence number",
                    fatal=False,
                )
            ]

        self._recv_seq = message.sequence_number + 1

        # In full implementation, would decrypt the data
        # For skeleton, pass through as-is
        return [
            DataReceived(
                data=message.encrypted_data,
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

        # In full implementation, would encrypt the data
        # For skeleton, pass through as-is
        app_data = ApplicationData(
            encrypted_data=data,
            sequence_number=seq,
        )

        frame = encode_frame(app_data, self._hmac_key)
        self._send_buffer.extend(frame)

        return [DataSent(length=len(data), sequence_number=seq)]

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
        self._peer_public_key = None
        self._session_id = None
        self._recv_buffer.clear()
        self._send_buffer.clear()
        self._send_seq = 0
        self._recv_seq = 0
        self._client_random = None
        self._server_random = None
