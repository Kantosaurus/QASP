"""Security tests for cipher suite downgrade resistance.

Security property: A MITM cannot force a weaker cipher suite.
Transcript hash divergence detects any modification to handshake messages.
"""

from __future__ import annotations

import os

import pytest

from qasp.crypto import hybrid, signatures
from qasp.framing.messages import ClientHello, ServerHello
from qasp.protocol.handshake import (
    DEFAULT_CIPHER_SUITE,
    DEFAULT_PROTOCOL_VERSION,
    Handshake,
    HandshakeConfig,
    HandshakeErrorType,
    HandshakeFailure,
)


@pytest.mark.security
class TestDowngradeResistance:
    """MITM cannot force a weaker cipher suite."""

    def test_stripped_cipher_suites_causes_suite_mismatch(
        self,
        server_kem_keypair: hybrid.HybridKeypair,
        server_sig_keypair: tuple[bytes, bytes],
    ) -> None:
        """Client sends suite (1,). MITM replaces with (99,). Server rejects."""
        # Client supports only suite 1
        client = Handshake(
            kem_keypair=hybrid.generate_keypair(),
            sig_keypair=signatures.generate_keypair(),
            is_initiator=True,
        )
        server = Handshake(
            kem_keypair=server_kem_keypair,
            sig_keypair=server_sig_keypair,
            is_initiator=False,
        )

        client_hello = client.create_client_hello()

        # MITM replaces cipher_suites with unsupported value
        tampered_hello = ClientHello(
            protocol_version=client_hello.protocol_version,
            client_random=client_hello.client_random,
            kem_public_key=client_hello.kem_public_key,
            sig_public_key=client_hello.sig_public_key,
            cipher_suites=(99,),
            extensions=client_hello.extensions,
        )

        result = server.process_client_hello(tampered_hello)

        assert isinstance(result, HandshakeFailure)
        assert result.error_type == HandshakeErrorType.SUITE_MISMATCH

    def test_tampered_cipher_suites_detected_by_transcript_signature(
        self,
        server_kem_keypair: hybrid.HybridKeypair,
        server_sig_keypair: tuple[bytes, bytes],
    ) -> None:
        """MITM adds extra suites. Transcript divergence causes AUTH_FAILED."""
        # Client supports only suite 2 (HYBRID_TRANSITION, the default)
        client = Handshake(
            kem_keypair=hybrid.generate_keypair(),
            sig_keypair=signatures.generate_keypair(),
            is_initiator=True,
        )
        # Server supports suites 2 and 1 (hybrid preferred)
        server_config = HandshakeConfig(supported_cipher_suites=(2, 1))
        server = Handshake(
            kem_keypair=server_kem_keypair,
            sig_keypair=server_sig_keypair,
            is_initiator=False,
            config=server_config,
        )

        client_hello = client.create_client_hello()

        # MITM adds extra cipher suites
        tampered_hello = ClientHello(
            protocol_version=client_hello.protocol_version,
            client_random=client_hello.client_random,
            kem_public_key=client_hello.kem_public_key,
            sig_public_key=client_hello.sig_public_key,
            cipher_suites=(2, 1),  # Modified from (2,)
            extensions=client_hello.extensions,
        )

        # Server processes tampered hello and signs over modified transcript
        server_hello = server.process_client_hello(tampered_hello)
        assert isinstance(server_hello, ServerHello)

        # Client's transcript has (2,) but server signed over (2, 1)
        result = client.process_server_hello(server_hello)

        assert isinstance(result, HandshakeFailure)
        assert result.error_type == HandshakeErrorType.AUTH_FAILED

    def test_version_downgrade_detected(
        self,
        server_kem_keypair: hybrid.HybridKeypair,
        server_sig_keypair: tuple[bytes, bytes],
    ) -> None:
        """MITM modifies protocol_version in transit. Server rejects."""
        client = Handshake(
            kem_keypair=hybrid.generate_keypair(),
            sig_keypair=signatures.generate_keypair(),
            is_initiator=True,
        )
        server = Handshake(
            kem_keypair=server_kem_keypair,
            sig_keypair=server_sig_keypair,
            is_initiator=False,
        )

        client_hello = client.create_client_hello()

        # MITM downgrades version
        tampered_hello = ClientHello(
            protocol_version=(0, 1),
            client_random=client_hello.client_random,
            kem_public_key=client_hello.kem_public_key,
            sig_public_key=client_hello.sig_public_key,
            cipher_suites=client_hello.cipher_suites,
            extensions=client_hello.extensions,
        )

        result = server.process_client_hello(tampered_hello)

        assert isinstance(result, HandshakeFailure)
        assert result.error_type == HandshakeErrorType.VERSION_MISMATCH

    def test_honest_handshake_succeeds(
        self,
        client_kem_keypair: hybrid.HybridKeypair,
        client_sig_keypair: tuple[bytes, bytes],
        server_kem_keypair: hybrid.HybridKeypair,
        server_sig_keypair: tuple[bytes, bytes],
    ) -> None:
        """Control test: unmodified handshake completes successfully."""
        client = Handshake(
            kem_keypair=client_kem_keypair,
            sig_keypair=client_sig_keypair,
            is_initiator=True,
        )
        server = Handshake(
            kem_keypair=server_kem_keypair,
            sig_keypair=server_sig_keypair,
            is_initiator=False,
        )

        client_hello = client.create_client_hello()
        server_hello = server.process_client_hello(client_hello)
        assert isinstance(server_hello, ServerHello)

        client_auth = client.process_server_hello(server_hello)
        assert not isinstance(client_auth, HandshakeFailure)

        server_keys = server.process_client_auth(client_auth)
        assert not isinstance(server_keys, HandshakeFailure)

        client_keys = client.complete_client_handshake()
        assert not isinstance(client_keys, HandshakeFailure)

        assert client_keys.session_key == server_keys.session_key
