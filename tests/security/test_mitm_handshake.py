"""Security tests for MITM handshake message tampering.

Security property: Modifying any handshake message in transit causes
transcript signature verification to fail.
"""

from __future__ import annotations

import os

import pytest

from qasp.crypto import hybrid, signatures
from qasp.framing.messages import ClientAuth, ClientHello, ServerHello
from qasp.protocol.handshake import (
    Handshake,
    HandshakeConfig,
    HandshakeErrorType,
    HandshakeFailure,
    HandshakeKeys,
)


def _complete_honest_handshake(
    client: Handshake, server: Handshake
) -> tuple[ClientHello, ServerHello, ClientAuth]:
    """Run a complete honest handshake and return all messages."""
    client_hello = client.create_client_hello()
    server_hello = server.process_client_hello(client_hello)
    assert isinstance(server_hello, ServerHello)
    client_auth = client.process_server_hello(server_hello)
    assert isinstance(client_auth, ClientAuth)
    return client_hello, server_hello, client_auth


# =============================================================================
# ClientHello Tampering
# =============================================================================


@pytest.mark.security
class TestMITMClientHelloTampering:
    """MITM tampers with ClientHello fields in transit."""

    def test_tampered_client_nonce(
        self,
        client_kem_keypair: hybrid.HybridKeypair,
        client_sig_keypair: tuple[bytes, bytes],
        server_kem_keypair: hybrid.HybridKeypair,
        server_sig_keypair: tuple[bytes, bytes],
    ) -> None:
        """Replacing client_random causes transcript divergence -> AUTH_FAILED."""
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

        # MITM replaces client nonce
        tampered_hello = ClientHello(
            protocol_version=client_hello.protocol_version,
            client_random=os.urandom(32),
            kem_public_key=client_hello.kem_public_key,
            sig_public_key=client_hello.sig_public_key,
            cipher_suites=client_hello.cipher_suites,
            extensions=client_hello.extensions,
        )

        server_hello = server.process_client_hello(tampered_hello)
        assert isinstance(server_hello, ServerHello)

        # Client transcript has original nonce, server signed over tampered nonce
        result = client.process_server_hello(server_hello)
        assert isinstance(result, HandshakeFailure)
        assert result.error_type == HandshakeErrorType.AUTH_FAILED

    def test_tampered_kem_public_key(
        self,
        client_kem_keypair: hybrid.HybridKeypair,
        client_sig_keypair: tuple[bytes, bytes],
        server_kem_keypair: hybrid.HybridKeypair,
        server_sig_keypair: tuple[bytes, bytes],
    ) -> None:
        """Replacing kem_public_key causes transcript divergence -> AUTH_FAILED or KEM_FAILED."""
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

        # MITM replaces KEM public key with random bytes
        attacker_kem = hybrid.generate_keypair()
        tampered_hello = ClientHello(
            protocol_version=client_hello.protocol_version,
            client_random=client_hello.client_random,
            kem_public_key=attacker_kem.public_key,
            sig_public_key=client_hello.sig_public_key,
            cipher_suites=client_hello.cipher_suites,
            extensions=client_hello.extensions,
        )

        result = server.process_client_hello(tampered_hello)
        # Server may succeed with encapsulation to attacker key, but transcript diverges
        if isinstance(result, ServerHello):
            client_result = client.process_server_hello(result)
            # Client cannot decrypt KEM ciphertext or transcript diverges
            assert isinstance(client_result, HandshakeFailure)
            assert client_result.error_type in (
                HandshakeErrorType.AUTH_FAILED,
                HandshakeErrorType.KEM_FAILED,
            )

    def test_tampered_sig_public_key(
        self,
        client_kem_keypair: hybrid.HybridKeypair,
        client_sig_keypair: tuple[bytes, bytes],
        server_kem_keypair: hybrid.HybridKeypair,
        server_sig_keypair: tuple[bytes, bytes],
        attacker_keypair: tuple[bytes, bytes],
    ) -> None:
        """Replacing sig_public_key causes transcript divergence -> AUTH_FAILED."""
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

        tampered_hello = ClientHello(
            protocol_version=client_hello.protocol_version,
            client_random=client_hello.client_random,
            kem_public_key=client_hello.kem_public_key,
            sig_public_key=attacker_keypair[0],
            cipher_suites=client_hello.cipher_suites,
            extensions=client_hello.extensions,
        )

        server_hello = server.process_client_hello(tampered_hello)
        assert isinstance(server_hello, ServerHello)

        # Transcript divergence: sig_public_key differs
        result = client.process_server_hello(server_hello)
        assert isinstance(result, HandshakeFailure)
        assert result.error_type == HandshakeErrorType.AUTH_FAILED


# =============================================================================
# ServerHello Tampering
# =============================================================================


@pytest.mark.security
class TestMITMServerHelloTampering:
    """MITM tampers with ServerHello fields in transit."""

    def test_tampered_server_nonce(
        self,
        client_kem_keypair: hybrid.HybridKeypair,
        client_sig_keypair: tuple[bytes, bytes],
        server_kem_keypair: hybrid.HybridKeypair,
        server_sig_keypair: tuple[bytes, bytes],
    ) -> None:
        """Modifying server_random causes signature verification failure."""
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

        tampered_hello = ServerHello(
            protocol_version=server_hello.protocol_version,
            server_random=os.urandom(32),
            kem_ciphertext=server_hello.kem_ciphertext,
            kem_public_key=server_hello.kem_public_key,
            sig_public_key=server_hello.sig_public_key,
            selected_cipher_suite=server_hello.selected_cipher_suite,
            signature=server_hello.signature,
            extensions=server_hello.extensions,
        )

        result = client.process_server_hello(tampered_hello)
        assert isinstance(result, HandshakeFailure)
        assert result.error_type == HandshakeErrorType.AUTH_FAILED

    def test_tampered_server_signature(
        self,
        client_kem_keypair: hybrid.HybridKeypair,
        client_sig_keypair: tuple[bytes, bytes],
        server_kem_keypair: hybrid.HybridKeypair,
        server_sig_keypair: tuple[bytes, bytes],
    ) -> None:
        """Replacing signature with random bytes causes direct verification failure."""
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

        tampered_hello = ServerHello(
            protocol_version=server_hello.protocol_version,
            server_random=server_hello.server_random,
            kem_ciphertext=server_hello.kem_ciphertext,
            kem_public_key=server_hello.kem_public_key,
            sig_public_key=server_hello.sig_public_key,
            selected_cipher_suite=server_hello.selected_cipher_suite,
            signature=b"\x00" * len(server_hello.signature),
            extensions=server_hello.extensions,
        )

        result = client.process_server_hello(tampered_hello)
        assert isinstance(result, HandshakeFailure)
        assert result.error_type == HandshakeErrorType.AUTH_FAILED

    def test_tampered_kem_ciphertext(
        self,
        client_kem_keypair: hybrid.HybridKeypair,
        client_sig_keypair: tuple[bytes, bytes],
        server_kem_keypair: hybrid.HybridKeypair,
        server_sig_keypair: tuple[bytes, bytes],
    ) -> None:
        """Replacing kem_ciphertext causes signature or KEM decapsulation failure."""
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

        tampered_hello = ServerHello(
            protocol_version=server_hello.protocol_version,
            server_random=server_hello.server_random,
            kem_ciphertext=os.urandom(len(server_hello.kem_ciphertext)),
            kem_public_key=server_hello.kem_public_key,
            sig_public_key=server_hello.sig_public_key,
            selected_cipher_suite=server_hello.selected_cipher_suite,
            signature=server_hello.signature,
            extensions=server_hello.extensions,
        )

        result = client.process_server_hello(tampered_hello)
        assert isinstance(result, HandshakeFailure)
        assert result.error_type in (
            HandshakeErrorType.AUTH_FAILED,
            HandshakeErrorType.KEM_FAILED,
        )

    def test_tampered_selected_suite(
        self,
        client_kem_keypair: hybrid.HybridKeypair,
        client_sig_keypair: tuple[bytes, bytes],
        server_kem_keypair: hybrid.HybridKeypair,
        server_sig_keypair: tuple[bytes, bytes],
    ) -> None:
        """Changing selected_cipher_suite causes transcript mismatch."""
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

        tampered_hello = ServerHello(
            protocol_version=server_hello.protocol_version,
            server_random=server_hello.server_random,
            kem_ciphertext=server_hello.kem_ciphertext,
            kem_public_key=server_hello.kem_public_key,
            sig_public_key=server_hello.sig_public_key,
            selected_cipher_suite=99,  # Invalid suite
            signature=server_hello.signature,
            extensions=server_hello.extensions,
        )

        result = client.process_server_hello(tampered_hello)
        assert isinstance(result, HandshakeFailure)
        assert result.error_type in (
            HandshakeErrorType.AUTH_FAILED,
            HandshakeErrorType.SUITE_MISMATCH,
        )


# =============================================================================
# ClientAuth Tampering
# =============================================================================


@pytest.mark.security
class TestMITMClientAuthTampering:
    """MITM tampers with ClientAuth fields in transit."""

    def test_tampered_client_auth_signature(
        self,
        client_kem_keypair: hybrid.HybridKeypair,
        client_sig_keypair: tuple[bytes, bytes],
        server_kem_keypair: hybrid.HybridKeypair,
        server_sig_keypair: tuple[bytes, bytes],
    ) -> None:
        """Replacing ClientAuth signature -> server's process_client_auth fails."""
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
        assert isinstance(client_auth, ClientAuth)

        tampered_auth = ClientAuth(
            kem_ciphertext=client_auth.kem_ciphertext,
            signature=b"\x00" * len(client_auth.signature),
            certificate=client_auth.certificate,
        )

        result = server.process_client_auth(tampered_auth)
        assert isinstance(result, HandshakeFailure)
        assert result.error_type == HandshakeErrorType.AUTH_FAILED

    def test_tampered_client_auth_kem_ciphertext(
        self,
        client_kem_keypair: hybrid.HybridKeypair,
        client_sig_keypair: tuple[bytes, bytes],
        server_kem_keypair: hybrid.HybridKeypair,
        server_sig_keypair: tuple[bytes, bytes],
    ) -> None:
        """Replacing ClientAuth KEM ciphertext -> keys diverge or handshake fails."""
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
        assert isinstance(client_auth, ClientAuth)

        tampered_auth = ClientAuth(
            kem_ciphertext=os.urandom(len(client_auth.kem_ciphertext)),
            signature=client_auth.signature,
            certificate=client_auth.certificate,
        )

        result = server.process_client_auth(tampered_auth)

        if isinstance(result, HandshakeFailure):
            # Server detected tampering directly
            assert result.error_type in (
                HandshakeErrorType.AUTH_FAILED,
                HandshakeErrorType.KEM_FAILED,
            )
        else:
            # Server completed but derived different keys — MITM prevented
            # because client and server will have mismatched session keys
            assert isinstance(result, HandshakeKeys)
            client_keys = client.complete_client_handshake()
            assert isinstance(client_keys, HandshakeKeys)
            assert client_keys.session_key != result.session_key
