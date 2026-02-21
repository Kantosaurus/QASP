"""Unit tests for QASP-Shake handshake protocol."""

from __future__ import annotations

import pytest

from qasp.crypto import hybrid, signatures
from qasp.framing.messages import ClientAuth, ClientHello, ServerHello
from qasp.protocol.handshake import (
    DEFAULT_CIPHER_SUITE,
    DEFAULT_PROTOCOL_VERSION,
    NONCE_SIZE,
    SESSION_ID_SIZE,
    Handshake,
    HandshakeConfig,
    HandshakeErrorType,
    HandshakeFailure,
    HandshakeKeys,
    HandshakeState,
    TranscriptBuilder,
)


# =============================================================================
# Fixtures
# =============================================================================


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
def client_handshake(
    client_kem_keypair: hybrid.HybridKeypair,
    client_sig_keypair: tuple[bytes, bytes],
) -> Handshake:
    """Create a client handshake instance."""
    return Handshake(
        kem_keypair=client_kem_keypair,
        sig_keypair=client_sig_keypair,
        is_initiator=True,
    )


@pytest.fixture
def server_handshake(
    server_kem_keypair: hybrid.HybridKeypair,
    server_sig_keypair: tuple[bytes, bytes],
) -> Handshake:
    """Create a server handshake instance."""
    return Handshake(
        kem_keypair=server_kem_keypair,
        sig_keypair=server_sig_keypair,
        is_initiator=False,
    )


# =============================================================================
# TranscriptBuilder Tests
# =============================================================================


class TestTranscriptBuilder:
    """Test the TranscriptBuilder helper class."""

    def test_empty_transcript(self) -> None:
        """Empty transcript should produce empty bytes."""
        tb = TranscriptBuilder()
        assert tb.get_full_transcript() == b""

    def test_add_client_hello(self) -> None:
        """Adding ClientHello should update transcript."""
        tb = TranscriptBuilder()
        tb.add_client_hello(
            version=(1, 0),
            client_nonce=b"A" * 32,
            kem_public_key=b"K" * 100,
            sig_public_key=b"S" * 50,
            cipher_suites=(1, 2, 3),
        )

        transcript = tb.get_full_transcript()
        assert len(transcript) > 0
        assert b"A" * 32 in transcript

    def test_server_signing_transcript(self) -> None:
        """Server signing transcript includes ClientHello + ServerHello pre-sig."""
        tb = TranscriptBuilder()
        tb.add_client_hello(
            version=(1, 0),
            client_nonce=b"C" * 32,
            kem_public_key=b"CK",
            sig_public_key=b"CS",
            cipher_suites=(1,),
        )
        tb.add_server_hello_presig(
            version=(1, 0),
            server_nonce=b"S" * 32,
            kem_ciphertext=b"CT",
            kem_public_key=b"SK",
            sig_public_key=b"SS",
            selected_suite=1,
        )

        signing_transcript = tb.get_server_signing_transcript()
        assert b"C" * 32 in signing_transcript
        assert b"S" * 32 in signing_transcript

    def test_session_id_computation(self) -> None:
        """Session ID should be SHA-384(transcript)[:32]."""
        tb = TranscriptBuilder()
        tb.add_client_hello(
            version=(1, 0),
            client_nonce=b"N" * 32,
            kem_public_key=b"K",
            sig_public_key=b"S",
            cipher_suites=(1,),
        )

        session_id = tb.compute_session_id()
        assert len(session_id) == SESSION_ID_SIZE

    def test_same_input_produces_same_session_id(self) -> None:
        """Same transcript should produce same session ID."""
        tb1 = TranscriptBuilder()
        tb2 = TranscriptBuilder()

        for tb in [tb1, tb2]:
            tb.add_client_hello(
                version=(1, 0),
                client_nonce=b"X" * 32,
                kem_public_key=b"Y" * 100,
                sig_public_key=b"Z" * 50,
                cipher_suites=(1,),
            )

        assert tb1.compute_session_id() == tb2.compute_session_id()


# =============================================================================
# HandshakeConfig Tests
# =============================================================================


class TestHandshakeConfig:
    """Test HandshakeConfig dataclass."""

    def test_default_values(self) -> None:
        """Default config should have expected values."""
        config = HandshakeConfig()
        assert config.protocol_version == DEFAULT_PROTOCOL_VERSION
        assert config.supported_cipher_suites == (DEFAULT_CIPHER_SUITE,)
        assert config.enable_hybrid is True

    def test_custom_values(self) -> None:
        """Config should accept custom values."""
        config = HandshakeConfig(
            protocol_version=(2, 0),
            supported_cipher_suites=(1, 2, 3),
            enable_hybrid=False,
        )
        assert config.protocol_version == (2, 0)
        assert config.supported_cipher_suites == (1, 2, 3)
        assert config.enable_hybrid is False


# =============================================================================
# Client Handshake Tests
# =============================================================================


class TestCreateClientHello:
    """Test create_client_hello method."""

    def test_creates_client_hello(self, client_handshake: Handshake) -> None:
        """Should create a valid ClientHello message."""
        client_hello = client_handshake.create_client_hello()

        assert isinstance(client_hello, ClientHello)

    def test_client_hello_has_correct_version(
        self, client_handshake: Handshake
    ) -> None:
        """ClientHello should have correct protocol version."""
        client_hello = client_handshake.create_client_hello()
        assert client_hello.protocol_version == DEFAULT_PROTOCOL_VERSION

    def test_client_hello_has_nonce(self, client_handshake: Handshake) -> None:
        """ClientHello should have 32-byte nonce."""
        client_hello = client_handshake.create_client_hello()
        assert len(client_hello.client_random) == NONCE_SIZE

    def test_client_hello_has_kem_public_key(
        self, client_handshake: Handshake
    ) -> None:
        """ClientHello should have KEM public key."""
        client_hello = client_handshake.create_client_hello()
        assert len(client_hello.kem_public_key) == hybrid.HYBRID_PUBLIC_KEY_SIZE

    def test_client_hello_has_sig_public_key(
        self, client_handshake: Handshake
    ) -> None:
        """ClientHello should have signature public key."""
        client_hello = client_handshake.create_client_hello()
        assert len(client_hello.sig_public_key) == signatures.ML_DSA_65_PUBLIC_KEY_SIZE

    def test_client_hello_has_cipher_suites(
        self, client_handshake: Handshake
    ) -> None:
        """ClientHello should have cipher suites."""
        client_hello = client_handshake.create_client_hello()
        assert client_hello.cipher_suites == (DEFAULT_CIPHER_SUITE,)

    def test_transitions_to_sent_state(self, client_handshake: Handshake) -> None:
        """Should transition to SENT_CLIENT_HELLO state."""
        client_handshake.create_client_hello()
        assert client_handshake.state == HandshakeState.SENT_CLIENT_HELLO

    def test_unique_nonces(
        self,
        client_kem_keypair: hybrid.HybridKeypair,
        client_sig_keypair: tuple[bytes, bytes],
    ) -> None:
        """Each handshake should generate unique nonces."""
        hs1 = Handshake(
            kem_keypair=client_kem_keypair,
            sig_keypair=client_sig_keypair,
            is_initiator=True,
        )
        hs2 = Handshake(
            kem_keypair=client_kem_keypair,
            sig_keypair=client_sig_keypair,
            is_initiator=True,
        )

        hello1 = hs1.create_client_hello()
        hello2 = hs2.create_client_hello()

        assert hello1.client_random != hello2.client_random

    def test_server_cannot_create_client_hello(
        self, server_handshake: Handshake
    ) -> None:
        """Server should not be able to create ClientHello."""
        with pytest.raises(RuntimeError, match="Only initiator"):
            server_handshake.create_client_hello()

    def test_cannot_create_twice(self, client_handshake: Handshake) -> None:
        """Cannot create ClientHello twice."""
        client_handshake.create_client_hello()
        with pytest.raises(RuntimeError, match="Cannot create ClientHello"):
            client_handshake.create_client_hello()


# =============================================================================
# Server Handshake Tests
# =============================================================================


class TestProcessClientHello:
    """Test process_client_hello method."""

    def test_creates_server_hello(
        self,
        client_handshake: Handshake,
        server_handshake: Handshake,
    ) -> None:
        """Should create a valid ServerHello in response."""
        client_hello = client_handshake.create_client_hello()
        result = server_handshake.process_client_hello(client_hello)

        assert isinstance(result, ServerHello)

    def test_server_hello_has_correct_version(
        self,
        client_handshake: Handshake,
        server_handshake: Handshake,
    ) -> None:
        """ServerHello should have correct version."""
        client_hello = client_handshake.create_client_hello()
        server_hello = server_handshake.process_client_hello(client_hello)

        assert isinstance(server_hello, ServerHello)
        assert server_hello.protocol_version == DEFAULT_PROTOCOL_VERSION

    def test_server_hello_has_nonce(
        self,
        client_handshake: Handshake,
        server_handshake: Handshake,
    ) -> None:
        """ServerHello should have 32-byte nonce."""
        client_hello = client_handshake.create_client_hello()
        server_hello = server_handshake.process_client_hello(client_hello)

        assert isinstance(server_hello, ServerHello)
        assert len(server_hello.server_random) == NONCE_SIZE

    def test_server_hello_has_kem_ciphertext(
        self,
        client_handshake: Handshake,
        server_handshake: Handshake,
    ) -> None:
        """ServerHello should have KEM ciphertext."""
        client_hello = client_handshake.create_client_hello()
        server_hello = server_handshake.process_client_hello(client_hello)

        assert isinstance(server_hello, ServerHello)
        assert len(server_hello.kem_ciphertext) == hybrid.HYBRID_CIPHERTEXT_SIZE

    def test_server_hello_has_signature(
        self,
        client_handshake: Handshake,
        server_handshake: Handshake,
    ) -> None:
        """ServerHello should have signature."""
        client_hello = client_handshake.create_client_hello()
        server_hello = server_handshake.process_client_hello(client_hello)

        assert isinstance(server_hello, ServerHello)
        assert len(server_hello.signature) > 0

    def test_transitions_to_received_state(
        self,
        client_handshake: Handshake,
        server_handshake: Handshake,
    ) -> None:
        """Should transition to RECEIVED_CLIENT_HELLO state."""
        client_hello = client_handshake.create_client_hello()
        server_handshake.process_client_hello(client_hello)
        assert server_handshake.state == HandshakeState.RECEIVED_CLIENT_HELLO

    def test_client_cannot_process_client_hello(
        self, client_handshake: Handshake
    ) -> None:
        """Client should not be able to process ClientHello."""
        client_hello = client_handshake.create_client_hello()

        # Create another client instance
        other_client = Handshake(
            kem_keypair=hybrid.generate_keypair(),
            sig_keypair=signatures.generate_keypair(),
            is_initiator=True,
        )

        with pytest.raises(RuntimeError, match="Only responder"):
            other_client.process_client_hello(client_hello)


class TestVersionMismatch:
    """Test version mismatch handling."""

    def test_returns_failure_on_version_mismatch(
        self,
        server_kem_keypair: hybrid.HybridKeypair,
        server_sig_keypair: tuple[bytes, bytes],
    ) -> None:
        """Should return failure when versions don't match."""
        # Create client with different version
        client_config = HandshakeConfig(protocol_version=(2, 0))
        client = Handshake(
            kem_keypair=hybrid.generate_keypair(),
            sig_keypair=signatures.generate_keypair(),
            is_initiator=True,
            config=client_config,
        )

        # Server with default version (1, 0)
        server = Handshake(
            kem_keypair=server_kem_keypair,
            sig_keypair=server_sig_keypair,
            is_initiator=False,
        )

        client_hello = client.create_client_hello()
        result = server.process_client_hello(client_hello)

        assert isinstance(result, HandshakeFailure)
        assert result.error_type == HandshakeErrorType.VERSION_MISMATCH
        assert result.alert_code == 70


class TestSuiteMismatch:
    """Test cipher suite mismatch handling."""

    def test_returns_failure_on_suite_mismatch(
        self,
        server_kem_keypair: hybrid.HybridKeypair,
        server_sig_keypair: tuple[bytes, bytes],
    ) -> None:
        """Should return failure when no common cipher suites."""
        # Create client with unsupported suites
        client_config = HandshakeConfig(supported_cipher_suites=(99, 100))
        client = Handshake(
            kem_keypair=hybrid.generate_keypair(),
            sig_keypair=signatures.generate_keypair(),
            is_initiator=True,
            config=client_config,
        )

        # Server with default suite (1,)
        server = Handshake(
            kem_keypair=server_kem_keypair,
            sig_keypair=server_sig_keypair,
            is_initiator=False,
        )

        client_hello = client.create_client_hello()
        result = server.process_client_hello(client_hello)

        assert isinstance(result, HandshakeFailure)
        assert result.error_type == HandshakeErrorType.SUITE_MISMATCH
        assert result.alert_code == 71


# =============================================================================
# Client Processing ServerHello Tests
# =============================================================================


class TestProcessServerHello:
    """Test process_server_hello method."""

    def test_creates_client_auth(
        self,
        client_handshake: Handshake,
        server_handshake: Handshake,
    ) -> None:
        """Should create ClientAuth in response to valid ServerHello."""
        client_hello = client_handshake.create_client_hello()
        server_hello = server_handshake.process_client_hello(client_hello)

        assert isinstance(server_hello, ServerHello)
        result = client_handshake.process_server_hello(server_hello)

        assert isinstance(result, ClientAuth)

    def test_client_auth_has_signature(
        self,
        client_handshake: Handshake,
        server_handshake: Handshake,
    ) -> None:
        """ClientAuth should have signature."""
        client_hello = client_handshake.create_client_hello()
        server_hello = server_handshake.process_client_hello(client_hello)

        assert isinstance(server_hello, ServerHello)
        client_auth = client_handshake.process_server_hello(server_hello)

        assert isinstance(client_auth, ClientAuth)
        assert len(client_auth.signature) > 0

    def test_client_auth_has_kem_ciphertext(
        self,
        client_handshake: Handshake,
        server_handshake: Handshake,
    ) -> None:
        """ClientAuth should have KEM ciphertext."""
        client_hello = client_handshake.create_client_hello()
        server_hello = server_handshake.process_client_hello(client_hello)

        assert isinstance(server_hello, ServerHello)
        client_auth = client_handshake.process_server_hello(server_hello)

        assert isinstance(client_auth, ClientAuth)
        assert len(client_auth.kem_ciphertext) == hybrid.HYBRID_CIPHERTEXT_SIZE

    def test_transitions_to_received_server_hello(
        self,
        client_handshake: Handshake,
        server_handshake: Handshake,
    ) -> None:
        """Should transition to RECEIVED_SERVER_HELLO state."""
        client_hello = client_handshake.create_client_hello()
        server_hello = server_handshake.process_client_hello(client_hello)

        assert isinstance(server_hello, ServerHello)
        client_handshake.process_server_hello(server_hello)

        assert client_handshake.state == HandshakeState.RECEIVED_SERVER_HELLO


class TestInvalidSignature:
    """Test invalid signature handling."""

    def test_returns_auth_failed_on_invalid_signature(
        self,
        client_handshake: Handshake,
        server_handshake: Handshake,
    ) -> None:
        """Should return AUTH_FAILED when server signature is invalid."""
        client_hello = client_handshake.create_client_hello()
        server_hello = server_handshake.process_client_hello(client_hello)

        assert isinstance(server_hello, ServerHello)

        # Tamper with the signature
        tampered_hello = ServerHello(
            protocol_version=server_hello.protocol_version,
            server_random=server_hello.server_random,
            kem_ciphertext=server_hello.kem_ciphertext,
            kem_public_key=server_hello.kem_public_key,
            sig_public_key=server_hello.sig_public_key,
            selected_cipher_suite=server_hello.selected_cipher_suite,
            signature=b"\x00" * len(server_hello.signature),  # Invalid signature
            extensions=server_hello.extensions,
        )

        result = client_handshake.process_server_hello(tampered_hello)

        assert isinstance(result, HandshakeFailure)
        assert result.error_type == HandshakeErrorType.AUTH_FAILED
        assert result.alert_code == 51


# =============================================================================
# Server Processing ClientAuth Tests
# =============================================================================


class TestProcessClientAuth:
    """Test process_client_auth method."""

    def test_completes_handshake(
        self,
        client_handshake: Handshake,
        server_handshake: Handshake,
    ) -> None:
        """Should complete handshake and return keys."""
        client_hello = client_handshake.create_client_hello()
        server_hello = server_handshake.process_client_hello(client_hello)

        assert isinstance(server_hello, ServerHello)
        client_auth = client_handshake.process_server_hello(server_hello)

        assert isinstance(client_auth, ClientAuth)
        result = server_handshake.process_client_auth(client_auth)

        assert isinstance(result, HandshakeKeys)

    def test_server_state_is_complete(
        self,
        client_handshake: Handshake,
        server_handshake: Handshake,
    ) -> None:
        """Server should be in COMPLETE state after processing ClientAuth."""
        client_hello = client_handshake.create_client_hello()
        server_hello = server_handshake.process_client_hello(client_hello)

        assert isinstance(server_hello, ServerHello)
        client_auth = client_handshake.process_server_hello(server_hello)

        assert isinstance(client_auth, ClientAuth)
        server_handshake.process_client_auth(client_auth)

        assert server_handshake.state == HandshakeState.COMPLETE

    def test_returns_auth_failed_on_invalid_client_signature(
        self,
        client_handshake: Handshake,
        server_handshake: Handshake,
    ) -> None:
        """Should return AUTH_FAILED when client signature is invalid."""
        client_hello = client_handshake.create_client_hello()
        server_hello = server_handshake.process_client_hello(client_hello)

        assert isinstance(server_hello, ServerHello)
        client_auth = client_handshake.process_server_hello(server_hello)

        assert isinstance(client_auth, ClientAuth)

        # Tamper with the signature
        tampered_auth = ClientAuth(
            kem_ciphertext=client_auth.kem_ciphertext,
            signature=b"\x00" * len(client_auth.signature),  # Invalid signature
            certificate=client_auth.certificate,
        )

        result = server_handshake.process_client_auth(tampered_auth)

        assert isinstance(result, HandshakeFailure)
        assert result.error_type == HandshakeErrorType.AUTH_FAILED


# =============================================================================
# Complete Handshake Tests
# =============================================================================


class TestCompleteClientHandshake:
    """Test complete_client_handshake method."""

    def test_completes_handshake(
        self,
        client_handshake: Handshake,
        server_handshake: Handshake,
    ) -> None:
        """Should complete client handshake and return keys."""
        client_hello = client_handshake.create_client_hello()
        server_hello = server_handshake.process_client_hello(client_hello)

        assert isinstance(server_hello, ServerHello)
        client_handshake.process_server_hello(server_hello)

        result = client_handshake.complete_client_handshake()

        assert isinstance(result, HandshakeKeys)

    def test_client_state_is_complete(
        self,
        client_handshake: Handshake,
        server_handshake: Handshake,
    ) -> None:
        """Client should be in COMPLETE state after completing handshake."""
        client_hello = client_handshake.create_client_hello()
        server_hello = server_handshake.process_client_hello(client_hello)

        assert isinstance(server_hello, ServerHello)
        client_handshake.process_server_hello(server_hello)
        client_handshake.complete_client_handshake()

        assert client_handshake.state == HandshakeState.COMPLETE


class TestKeyDerivation:
    """Test that both sides derive the same keys."""

    def test_produces_consistent_keys(
        self,
        client_handshake: Handshake,
        server_handshake: Handshake,
    ) -> None:
        """Both sides should derive the same session key."""
        # Full handshake
        client_hello = client_handshake.create_client_hello()
        server_hello = server_handshake.process_client_hello(client_hello)

        assert isinstance(server_hello, ServerHello)
        client_auth = client_handshake.process_server_hello(server_hello)

        assert isinstance(client_auth, ClientAuth)
        server_keys = server_handshake.process_client_auth(client_auth)
        client_keys = client_handshake.complete_client_handshake()

        assert isinstance(server_keys, HandshakeKeys)
        assert isinstance(client_keys, HandshakeKeys)

        # Session keys should match
        assert client_keys.session_key == server_keys.session_key

    def test_produces_consistent_session_id(
        self,
        client_handshake: Handshake,
        server_handshake: Handshake,
    ) -> None:
        """Both sides should derive the same session ID."""
        # Full handshake
        client_hello = client_handshake.create_client_hello()
        server_hello = server_handshake.process_client_hello(client_hello)

        assert isinstance(server_hello, ServerHello)
        client_auth = client_handshake.process_server_hello(server_hello)

        assert isinstance(client_auth, ClientAuth)
        server_keys = server_handshake.process_client_auth(client_auth)
        client_keys = client_handshake.complete_client_handshake()

        assert isinstance(server_keys, HandshakeKeys)
        assert isinstance(client_keys, HandshakeKeys)

        # Session IDs should match
        assert client_keys.session_id == server_keys.session_id

    def test_session_key_correct_size(
        self,
        client_handshake: Handshake,
        server_handshake: Handshake,
    ) -> None:
        """Session key should be 32 bytes (AES-256)."""
        client_hello = client_handshake.create_client_hello()
        server_hello = server_handshake.process_client_hello(client_hello)

        assert isinstance(server_hello, ServerHello)
        client_auth = client_handshake.process_server_hello(server_hello)

        assert isinstance(client_auth, ClientAuth)
        server_keys = server_handshake.process_client_auth(client_auth)

        assert isinstance(server_keys, HandshakeKeys)
        assert len(server_keys.session_key) == 32

    def test_session_id_correct_size(
        self,
        client_handshake: Handshake,
        server_handshake: Handshake,
    ) -> None:
        """Session ID should be 32 bytes."""
        client_hello = client_handshake.create_client_hello()
        server_hello = server_handshake.process_client_hello(client_hello)

        assert isinstance(server_hello, ServerHello)
        client_auth = client_handshake.process_server_hello(server_hello)

        assert isinstance(client_auth, ClientAuth)
        server_keys = server_handshake.process_client_auth(client_auth)

        assert isinstance(server_keys, HandshakeKeys)
        assert len(server_keys.session_id) == SESSION_ID_SIZE

    def test_different_handshakes_produce_different_keys(self) -> None:
        """Different handshakes should produce different keys."""
        # First handshake
        client1 = Handshake(
            kem_keypair=hybrid.generate_keypair(),
            sig_keypair=signatures.generate_keypair(),
            is_initiator=True,
        )
        server1 = Handshake(
            kem_keypair=hybrid.generate_keypair(),
            sig_keypair=signatures.generate_keypair(),
            is_initiator=False,
        )

        client_hello1 = client1.create_client_hello()
        server_hello1 = server1.process_client_hello(client_hello1)
        assert isinstance(server_hello1, ServerHello)
        client_auth1 = client1.process_server_hello(server_hello1)
        assert isinstance(client_auth1, ClientAuth)
        keys1 = server1.process_client_auth(client_auth1)

        # Second handshake
        client2 = Handshake(
            kem_keypair=hybrid.generate_keypair(),
            sig_keypair=signatures.generate_keypair(),
            is_initiator=True,
        )
        server2 = Handshake(
            kem_keypair=hybrid.generate_keypair(),
            sig_keypair=signatures.generate_keypair(),
            is_initiator=False,
        )

        client_hello2 = client2.create_client_hello()
        server_hello2 = server2.process_client_hello(client_hello2)
        assert isinstance(server_hello2, ServerHello)
        client_auth2 = client2.process_server_hello(server_hello2)
        assert isinstance(client_auth2, ClientAuth)
        keys2 = server2.process_client_auth(client_auth2)

        assert isinstance(keys1, HandshakeKeys)
        assert isinstance(keys2, HandshakeKeys)

        # Keys should differ
        assert keys1.session_key != keys2.session_key
        assert keys1.session_id != keys2.session_id


# =============================================================================
# State Machine Tests
# =============================================================================


class TestStateMachine:
    """Test handshake state machine transitions."""

    def test_initial_state(
        self, client_handshake: Handshake, server_handshake: Handshake
    ) -> None:
        """Both handshakes should start in INITIAL state."""
        assert client_handshake.state == HandshakeState.INITIAL
        assert server_handshake.state == HandshakeState.INITIAL

    def test_failed_state_on_error(
        self,
        server_kem_keypair: hybrid.HybridKeypair,
        server_sig_keypair: tuple[bytes, bytes],
    ) -> None:
        """Handshake should enter FAILED state on error."""
        # Create mismatched version
        client_config = HandshakeConfig(protocol_version=(2, 0))
        client = Handshake(
            kem_keypair=hybrid.generate_keypair(),
            sig_keypair=signatures.generate_keypair(),
            is_initiator=True,
            config=client_config,
        )

        server = Handshake(
            kem_keypair=server_kem_keypair,
            sig_keypair=server_sig_keypair,
            is_initiator=False,
        )

        client_hello = client.create_client_hello()
        server.process_client_hello(client_hello)

        assert server.state == HandshakeState.FAILED
