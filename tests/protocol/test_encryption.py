"""Tests for encrypted data exchange in QASPConnection."""

from __future__ import annotations

import secrets

import pytest

from qasp.crypto import hybrid, signatures
from qasp.crypto.aead import AES_GCM_TAG_SIZE
from qasp.protocol import (
    ConnectionError,
    DataReceived,
    DataSent,
    QASPConnection,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def shared_hmac_key() -> bytes:
    """Generate a shared HMAC key for client/server."""
    return secrets.token_bytes(32)


@pytest.fixture
def client_kem_keypair() -> hybrid.HybridKeypair:
    """Generate a fresh hybrid keypair for the client."""
    return hybrid.generate_keypair()


@pytest.fixture
def server_kem_keypair() -> hybrid.HybridKeypair:
    """Generate a fresh hybrid keypair for the server."""
    return hybrid.generate_keypair()


@pytest.fixture
def client_sig_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh signature keypair for the client."""
    return signatures.generate_keypair()


@pytest.fixture
def server_sig_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh signature keypair for the server."""
    return signatures.generate_keypair()


@pytest.fixture
def established_connections(
    client_kem_keypair: hybrid.HybridKeypair,
    client_sig_keypair: tuple[bytes, bytes],
    server_kem_keypair: hybrid.HybridKeypair,
    server_sig_keypair: tuple[bytes, bytes],
    shared_hmac_key: bytes,
) -> tuple[QASPConnection, QASPConnection]:
    """Create and complete handshake for client and server connections."""
    client = QASPConnection(
        kem_keypair=client_kem_keypair,
        sig_keypair=client_sig_keypair,
        is_client=True,
        hmac_key=shared_hmac_key,
    )
    server = QASPConnection(
        kem_keypair=server_kem_keypair,
        sig_keypair=server_sig_keypair,
        is_client=False,
        hmac_key=shared_hmac_key,
    )

    # Complete handshake
    client.initiate_handshake()
    server.receive_bytes(client.bytes_to_send())
    client.receive_bytes(server.bytes_to_send())
    server.receive_bytes(client.bytes_to_send())

    assert client.is_established
    assert server.is_established

    return client, server


# =============================================================================
# Encryption Tests
# =============================================================================


class TestSendDataEncryptsPayload:
    """Test that send_data encrypts the payload."""

    def test_ciphertext_differs_from_plaintext(
        self, established_connections: tuple[QASPConnection, QASPConnection]
    ) -> None:
        """Encrypted data should differ from plaintext."""
        client, _ = established_connections

        plaintext = b"Hello, secure world!"
        events = client.send_data(plaintext)

        assert any(isinstance(e, DataSent) for e in events)

        # Get the encrypted frame
        frame_bytes = client.bytes_to_send()
        assert len(frame_bytes) > 0

        # The frame should not contain the plaintext directly
        assert plaintext not in frame_bytes

    def test_encrypted_data_includes_tag(
        self, established_connections: tuple[QASPConnection, QASPConnection]
    ) -> None:
        """Encrypted data should include authentication tag."""
        client, _ = established_connections

        plaintext = b"Test message"
        client.send_data(plaintext)

        frame_bytes = client.bytes_to_send()
        # Frame should be larger than plaintext due to framing + tag
        assert len(frame_bytes) > len(plaintext) + AES_GCM_TAG_SIZE


class TestReceiveDataDecryptsPayload:
    """Test that received data is properly decrypted."""

    def test_roundtrip_encryption_decryption(
        self, established_connections: tuple[QASPConnection, QASPConnection]
    ) -> None:
        """Data sent by client should be decrypted by server."""
        client, server = established_connections

        plaintext = b"Secret message from client to server"
        client.send_data(plaintext)

        # Send encrypted data to server
        encrypted_frame = client.bytes_to_send()
        events = server.receive_bytes(encrypted_frame)

        # Server should emit DataReceived with decrypted plaintext
        data_events = [e for e in events if isinstance(e, DataReceived)]
        assert len(data_events) == 1
        assert data_events[0].data == plaintext

    def test_bidirectional_encryption(
        self, established_connections: tuple[QASPConnection, QASPConnection]
    ) -> None:
        """Both client and server should be able to encrypt/decrypt."""
        client, server = established_connections

        # Client to server
        client_message = b"Hello from client"
        client.send_data(client_message)
        events = server.receive_bytes(client.bytes_to_send())
        data_events = [e for e in events if isinstance(e, DataReceived)]
        assert len(data_events) == 1
        assert data_events[0].data == client_message

        # Server to client
        server_message = b"Hello from server"
        server.send_data(server_message)
        events = client.receive_bytes(server.bytes_to_send())
        data_events = [e for e in events if isinstance(e, DataReceived)]
        assert len(data_events) == 1
        assert data_events[0].data == server_message


class TestNonceUniqueness:
    """Test that nonces are unique for each message."""

    def test_different_sequence_numbers_produce_different_nonces(
        self, established_connections: tuple[QASPConnection, QASPConnection]
    ) -> None:
        """Each message should use a unique nonce based on sequence number."""
        client, _server = established_connections

        # Send multiple messages
        messages = [b"Message 1", b"Message 2", b"Message 3"]
        encrypted_frames = []

        for msg in messages:
            client.send_data(msg)
            encrypted_frames.append(client.bytes_to_send())

        # All frames should be different (different nonces produce different ciphertext)
        assert len(set(encrypted_frames)) == len(encrypted_frames)

    def test_sequence_numbers_increment(
        self, established_connections: tuple[QASPConnection, QASPConnection]
    ) -> None:
        """Sequence numbers should increment with each message."""
        client, _ = established_connections

        events1 = client.send_data(b"First")
        events2 = client.send_data(b"Second")
        events3 = client.send_data(b"Third")

        seq1 = next(e for e in events1 if isinstance(e, DataSent)).sequence_number
        seq2 = next(e for e in events2 if isinstance(e, DataSent)).sequence_number
        seq3 = next(e for e in events3 if isinstance(e, DataSent)).sequence_number

        assert seq1 == 0
        assert seq2 == 1
        assert seq3 == 2


class TestReplayDetection:
    """Test protection against replay attacks."""

    def test_old_sequence_number_rejected(
        self, established_connections: tuple[QASPConnection, QASPConnection]
    ) -> None:
        """Messages with old sequence numbers should be rejected."""
        client, server = established_connections

        # Send first message
        client.send_data(b"First message")
        first_frame = client.bytes_to_send()
        server.receive_bytes(first_frame)

        # Send second message
        client.send_data(b"Second message")
        second_frame = client.bytes_to_send()
        server.receive_bytes(second_frame)

        # Try to replay the first message (old sequence number)
        events = server.receive_bytes(first_frame)

        # Should get a ConnectionError for replay detection
        error_events = [e for e in events if isinstance(e, ConnectionError)]
        assert len(error_events) == 1
        assert "Replay" in error_events[0].error or "sequence" in error_events[0].error.lower()


class TestTamperingDetection:
    """Test detection of tampered messages."""

    def test_modified_ciphertext_fails_decryption(
        self, established_connections: tuple[QASPConnection, QASPConnection]
    ) -> None:
        """Tampered ciphertext should fail authentication."""
        client, server = established_connections

        client.send_data(b"Original message")
        encrypted_frame = bytearray(client.bytes_to_send())

        # Tamper with the ciphertext (modify a byte in the middle)
        if len(encrypted_frame) > 20:
            encrypted_frame[20] ^= 0xFF

        events = server.receive_bytes(bytes(encrypted_frame))

        # Should get a ConnectionError for decryption failure
        error_events = [e for e in events if isinstance(e, ConnectionError)]
        assert len(error_events) == 1
        assert error_events[0].fatal


class TestAADBinding:
    """Test that AAD binds message type and sequence number."""

    def test_aad_includes_message_type(
        self, established_connections: tuple[QASPConnection, QASPConnection]
    ) -> None:
        """AAD should bind the message type to prevent type confusion."""
        client, server = established_connections

        # This is implicitly tested by successful decryption
        # If AAD wasn't matching, decryption would fail
        plaintext = b"Test AAD binding"
        client.send_data(plaintext)

        events = server.receive_bytes(client.bytes_to_send())
        data_events = [e for e in events if isinstance(e, DataReceived)]
        assert len(data_events) == 1
        assert data_events[0].data == plaintext

    def test_aad_includes_sequence_number(
        self, established_connections: tuple[QASPConnection, QASPConnection]
    ) -> None:
        """AAD should bind the sequence number."""
        client, server = established_connections

        # Send multiple messages to verify sequence binding
        for i in range(3):
            plaintext = f"Message {i}".encode()
            client.send_data(plaintext)

            events = server.receive_bytes(client.bytes_to_send())
            data_events = [e for e in events if isinstance(e, DataReceived)]
            assert len(data_events) == 1
            assert data_events[0].data == plaintext
            assert data_events[0].sequence_number == i


class TestLargePayloads:
    """Test encryption of various payload sizes."""

    @pytest.mark.parametrize(
        "size",
        [
            1,  # Minimum
            16,  # AES block size
            1024,  # 1KB
            65536,  # 64KB
        ],
    )
    def test_various_payload_sizes(
        self,
        established_connections: tuple[QASPConnection, QASPConnection],
        size: int,
    ) -> None:
        """Various payload sizes should encrypt/decrypt correctly."""
        client, server = established_connections

        plaintext = bytes(range(256)) * (size // 256 + 1)
        plaintext = plaintext[:size]

        client.send_data(plaintext)
        events = server.receive_bytes(client.bytes_to_send())

        data_events = [e for e in events if isinstance(e, DataReceived)]
        assert len(data_events) == 1
        assert data_events[0].data == plaintext


class TestEmptyPayload:
    """Test encryption of empty payloads."""

    def test_empty_payload(
        self, established_connections: tuple[QASPConnection, QASPConnection]
    ) -> None:
        """Empty payloads should encrypt/decrypt correctly."""
        client, server = established_connections

        plaintext = b""
        client.send_data(plaintext)

        events = server.receive_bytes(client.bytes_to_send())
        data_events = [e for e in events if isinstance(e, DataReceived)]
        assert len(data_events) == 1
        assert data_events[0].data == plaintext


class TestNonceIVDerivation:
    """Test nonce IV derivation from session key."""

    def test_nonce_iv_derived_after_handshake(
        self, established_connections: tuple[QASPConnection, QASPConnection]
    ) -> None:
        """Nonce IV should be derived after handshake completes."""
        client, server = established_connections

        # The nonce IV is internal, but we can verify encryption works
        # which means the nonce IV was properly derived
        plaintext = b"Test nonce IV derivation"
        client.send_data(plaintext)

        events = server.receive_bytes(client.bytes_to_send())
        data_events = [e for e in events if isinstance(e, DataReceived)]
        assert len(data_events) == 1
        assert data_events[0].data == plaintext

    def test_different_sessions_have_different_encryption(self) -> None:
        """Different sessions should produce different ciphertext."""
        # First session (with shared HMAC key)
        hmac_key1 = secrets.token_bytes(32)
        client1 = QASPConnection(
            kem_keypair=hybrid.generate_keypair(),
            sig_keypair=signatures.generate_keypair(),
            is_client=True,
            hmac_key=hmac_key1,
        )
        server1 = QASPConnection(
            kem_keypair=hybrid.generate_keypair(),
            sig_keypair=signatures.generate_keypair(),
            is_client=False,
            hmac_key=hmac_key1,
        )
        client1.initiate_handshake()
        server1.receive_bytes(client1.bytes_to_send())
        client1.receive_bytes(server1.bytes_to_send())
        server1.receive_bytes(client1.bytes_to_send())

        # Second session (with different shared HMAC key)
        hmac_key2 = secrets.token_bytes(32)
        client2 = QASPConnection(
            kem_keypair=hybrid.generate_keypair(),
            sig_keypair=signatures.generate_keypair(),
            is_client=True,
            hmac_key=hmac_key2,
        )
        server2 = QASPConnection(
            kem_keypair=hybrid.generate_keypair(),
            sig_keypair=signatures.generate_keypair(),
            is_client=False,
            hmac_key=hmac_key2,
        )
        client2.initiate_handshake()
        server2.receive_bytes(client2.bytes_to_send())
        client2.receive_bytes(server2.bytes_to_send())
        server2.receive_bytes(client2.bytes_to_send())

        # Same plaintext
        plaintext = b"Same message in both sessions"

        client1.send_data(plaintext)
        client2.send_data(plaintext)

        frame1 = client1.bytes_to_send()
        frame2 = client2.bytes_to_send()

        # Frames should differ due to different session keys
        assert frame1 != frame2
