"""Tests for downgrade resistance and 16-bit suite encoding."""

from __future__ import annotations

import pytest

from qasp.crypto import hybrid, signatures
from qasp.crypto.suites import (
    SUITE_CLASSICAL_COMPAT,
    SUITE_HYBRID_TRANSITION,
    SUITE_PQ_STRICT,
)
from qasp.framing.messages import ClientHello, ServerHello
from qasp.protocol.handshake import (
    Handshake,
    HandshakeConfig,
    HandshakeErrorType,
    HandshakeFailure,
    HandshakeKeys,
    TranscriptBuilder,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def client_kem_keypair() -> hybrid.HybridKeypair:
    return hybrid.generate_keypair()


@pytest.fixture
def server_kem_keypair() -> hybrid.HybridKeypair:
    return hybrid.generate_keypair()


@pytest.fixture
def client_sig_keypair() -> tuple[bytes, bytes]:
    return signatures.generate_keypair()


@pytest.fixture
def server_sig_keypair() -> tuple[bytes, bytes]:
    return signatures.generate_keypair()


# =============================================================================
# Downgrade Resistance Tests
# =============================================================================


class TestDowngradeResistance:
    """Test that PQ-capable servers reject classical-only clients."""

    def test_pq_server_rejects_classical_only_client(
        self,
        client_kem_keypair: hybrid.HybridKeypair,
        server_kem_keypair: hybrid.HybridKeypair,
        client_sig_keypair: tuple[bytes, bytes],
        server_sig_keypair: tuple[bytes, bytes],
    ) -> None:
        """PQ server should reject a client advertising only classical suites."""
        # Server supports PQ
        server = Handshake(
            kem_keypair=server_kem_keypair,
            sig_keypair=server_sig_keypair,
            is_initiator=False,
            config=HandshakeConfig(
                supported_cipher_suites=(SUITE_PQ_STRICT, SUITE_CLASSICAL_COMPAT),
            ),
        )

        # Client sends only classical suite
        client = Handshake(
            kem_keypair=client_kem_keypair,
            sig_keypair=client_sig_keypair,
            is_initiator=True,
            config=HandshakeConfig(
                supported_cipher_suites=(SUITE_CLASSICAL_COMPAT,),
                enable_hybrid=False,
            ),
        )
        client_hello = client.create_client_hello()

        result = server.process_client_hello(client_hello)
        assert isinstance(result, HandshakeFailure)
        assert result.error_type == HandshakeErrorType.UPGRADE_REQUIRED
        assert result.alert_code == 72

    def test_pq_server_accepts_hybrid_client(
        self,
        client_kem_keypair: hybrid.HybridKeypair,
        server_kem_keypair: hybrid.HybridKeypair,
        client_sig_keypair: tuple[bytes, bytes],
        server_sig_keypair: tuple[bytes, bytes],
    ) -> None:
        """PQ server should accept a client offering hybrid suite."""
        server = Handshake(
            kem_keypair=server_kem_keypair,
            sig_keypair=server_sig_keypair,
            is_initiator=False,
            config=HandshakeConfig(
                supported_cipher_suites=(SUITE_PQ_STRICT, SUITE_HYBRID_TRANSITION),
            ),
        )

        client = Handshake(
            kem_keypair=client_kem_keypair,
            sig_keypair=client_sig_keypair,
            is_initiator=True,
            config=HandshakeConfig(
                supported_cipher_suites=(SUITE_HYBRID_TRANSITION,),
                enable_hybrid=True,
            ),
        )
        client_hello = client.create_client_hello()

        result = server.process_client_hello(client_hello)
        assert isinstance(result, ServerHello)

    def test_classical_server_accepts_classical_client(
        self,
        client_kem_keypair: hybrid.HybridKeypair,
        server_kem_keypair: hybrid.HybridKeypair,
        client_sig_keypair: tuple[bytes, bytes],
        server_sig_keypair: tuple[bytes, bytes],
    ) -> None:
        """Classical-only server should accept classical-only client."""
        server = Handshake(
            kem_keypair=server_kem_keypair,
            sig_keypair=server_sig_keypair,
            is_initiator=False,
            config=HandshakeConfig(
                supported_cipher_suites=(SUITE_CLASSICAL_COMPAT,),
                enable_hybrid=False,
            ),
        )

        client = Handshake(
            kem_keypair=client_kem_keypair,
            sig_keypair=client_sig_keypair,
            is_initiator=True,
            config=HandshakeConfig(
                supported_cipher_suites=(SUITE_CLASSICAL_COMPAT,),
                enable_hybrid=False,
            ),
        )
        client_hello = client.create_client_hello()

        # Classical server has no PQ suites, so no downgrade check triggers
        result = server.process_client_hello(client_hello)
        assert isinstance(result, ServerHello)


# =============================================================================
# 16-bit Transcript Encoding Tests
# =============================================================================


class TestTranscript16BitEncoding:
    """Test that transcript uses 16-bit suite encoding."""

    def test_client_hello_suite_encoding(self) -> None:
        """Suite IDs should be encoded as 2-byte big-endian."""
        tb = TranscriptBuilder()
        tb.add_client_hello(
            version=(1, 0),
            client_nonce=b"\x00" * 32,
            kem_public_key=b"\x01" * 32,
            sig_public_key=b"\x02" * 32,
            cipher_suites=(SUITE_PQ_STRICT, SUITE_HYBRID_TRANSITION),
        )
        transcript = tb.get_full_transcript()
        # Suites should be at the end: 0x0001 0x0002 = 4 bytes
        assert transcript.endswith(b"\x00\x01\x00\x02")

    def test_server_hello_suite_encoding(self) -> None:
        """Selected suite should be encoded as 2-byte big-endian."""
        tb = TranscriptBuilder()
        tb.add_client_hello(
            version=(1, 0),
            client_nonce=b"\x00" * 32,
            kem_public_key=b"\x01" * 32,
            sig_public_key=b"\x02" * 32,
            cipher_suites=(SUITE_PQ_STRICT,),
        )
        tb.add_server_hello_presig(
            version=(1, 0),
            server_nonce=b"\x03" * 32,
            kem_ciphertext=b"\x04" * 64,
            kem_public_key=b"\x05" * 32,
            sig_public_key=b"\x06" * 32,
            selected_suite=SUITE_PQ_STRICT,
        )
        transcript = tb.get_server_signing_transcript()
        # Selected suite at end: 0x0001 = 2 bytes
        assert transcript.endswith(b"\x00\x01")

    def test_large_suite_id_encoding(self) -> None:
        """Suite IDs > 255 should encode correctly in 16-bit."""
        tb = TranscriptBuilder()
        tb.add_client_hello(
            version=(1, 0),
            client_nonce=b"\x00" * 32,
            kem_public_key=b"\x01" * 32,
            sig_public_key=b"\x02" * 32,
            cipher_suites=(0x0100, 0x0200),
        )
        transcript = tb.get_full_transcript()
        assert transcript.endswith(b"\x01\x00\x02\x00")


# =============================================================================
# Full Handshake with Hybrid Suite
# =============================================================================


class TestFullHandshakeWithHybridSuite:
    """Test full handshake with SUITE_HYBRID_TRANSITION."""

    def test_full_hybrid_handshake(
        self,
        client_kem_keypair: hybrid.HybridKeypair,
        server_kem_keypair: hybrid.HybridKeypair,
        client_sig_keypair: tuple[bytes, bytes],
        server_sig_keypair: tuple[bytes, bytes],
    ) -> None:
        """Full handshake with hybrid suite should produce matching keys."""
        config = HandshakeConfig(
            supported_cipher_suites=(SUITE_HYBRID_TRANSITION,),
            enable_hybrid=True,
        )

        client = Handshake(
            kem_keypair=client_kem_keypair,
            sig_keypair=client_sig_keypair,
            is_initiator=True,
            config=config,
        )
        server = Handshake(
            kem_keypair=server_kem_keypair,
            sig_keypair=server_sig_keypair,
            is_initiator=False,
            config=config,
        )

        # ClientHello
        client_hello = client.create_client_hello()
        assert isinstance(client_hello, ClientHello)

        # ServerHello
        server_hello = server.process_client_hello(client_hello)
        assert isinstance(server_hello, ServerHello)
        assert server_hello.selected_cipher_suite == SUITE_HYBRID_TRANSITION

        # ClientAuth
        client_auth = client.process_server_hello(server_hello)
        assert not isinstance(client_auth, HandshakeFailure)

        # Complete
        server_keys = server.process_client_auth(client_auth)
        assert isinstance(server_keys, HandshakeKeys)

        client_keys = client.complete_client_handshake()
        assert isinstance(client_keys, HandshakeKeys)

        # Keys must match
        assert client_keys.session_key == server_keys.session_key
        assert client_keys.session_id == server_keys.session_id


# =============================================================================
# Tampered Suite Detection
# =============================================================================


class TestTamperedSuiteDetection:
    """Test that tampered suite in ServerHello causes signature failure."""

    def test_tampered_suite_in_server_hello(
        self,
        client_kem_keypair: hybrid.HybridKeypair,
        server_kem_keypair: hybrid.HybridKeypair,
        client_sig_keypair: tuple[bytes, bytes],
        server_sig_keypair: tuple[bytes, bytes],
    ) -> None:
        """Changing the suite ID in ServerHello should fail signature verification."""
        # Both sides support both suites; client sends hybrid key
        client_config = HandshakeConfig(
            supported_cipher_suites=(SUITE_HYBRID_TRANSITION, SUITE_PQ_STRICT),
            enable_hybrid=True,
        )
        server_config = HandshakeConfig(
            supported_cipher_suites=(SUITE_HYBRID_TRANSITION, SUITE_PQ_STRICT),
            enable_hybrid=True,
        )

        client = Handshake(
            kem_keypair=client_kem_keypair,
            sig_keypair=client_sig_keypair,
            is_initiator=True,
            config=client_config,
        )
        server = Handshake(
            kem_keypair=server_kem_keypair,
            sig_keypair=server_sig_keypair,
            is_initiator=False,
            config=server_config,
        )

        client_hello = client.create_client_hello()
        server_hello = server.process_client_hello(client_hello)
        assert isinstance(server_hello, ServerHello)
        assert server_hello.selected_cipher_suite == SUITE_HYBRID_TRANSITION

        # Tamper: change selected suite from HYBRID to PQ_STRICT
        tampered_hello = ServerHello(
            protocol_version=server_hello.protocol_version,
            server_random=server_hello.server_random,
            kem_ciphertext=server_hello.kem_ciphertext,
            kem_public_key=server_hello.kem_public_key,
            sig_public_key=server_hello.sig_public_key,
            selected_cipher_suite=SUITE_PQ_STRICT,
            signature=server_hello.signature,  # signature won't match tampered suite
            extensions=server_hello.extensions,
        )

        result = client.process_server_hello(tampered_hello)
        assert isinstance(result, HandshakeFailure)
        assert result.error_type == HandshakeErrorType.AUTH_FAILED
