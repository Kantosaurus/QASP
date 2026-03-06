"""Unit tests for Ed25519 digital signatures."""

from __future__ import annotations

import pytest

from qasp.crypto import ed25519
from qasp.crypto.exceptions import (
    InvalidKeyError,
    InvalidSignatureError,
)


class TestEd25519Constants:
    """Test Ed25519 size constants."""

    def test_public_key_size(self) -> None:
        assert ed25519.ED25519_PUBLIC_KEY_SIZE == 32

    def test_secret_key_size(self) -> None:
        assert ed25519.ED25519_SECRET_KEY_SIZE == 32

    def test_signature_size(self) -> None:
        assert ed25519.ED25519_SIGNATURE_SIZE == 64


class TestGenerateKeypair:
    """Test Ed25519 key generation."""

    def test_generates_keypair(self) -> None:
        public_key, secret_key = ed25519.generate_keypair()
        assert isinstance(public_key, bytes)
        assert isinstance(secret_key, bytes)

    def test_public_key_correct_size(self) -> None:
        public_key, _ = ed25519.generate_keypair()
        assert len(public_key) == ed25519.ED25519_PUBLIC_KEY_SIZE

    def test_secret_key_correct_size(self) -> None:
        _, secret_key = ed25519.generate_keypair()
        assert len(secret_key) == ed25519.ED25519_SECRET_KEY_SIZE

    def test_generates_unique_keys(self) -> None:
        pk1, sk1 = ed25519.generate_keypair()
        pk2, sk2 = ed25519.generate_keypair()
        assert pk1 != pk2
        assert sk1 != sk2


class TestSignVerifyRoundTrip:
    """Test Ed25519 sign/verify round-trip."""

    def test_sign_verify_success(self) -> None:
        pk, sk = ed25519.generate_keypair()
        message = b"hello world"
        signature = ed25519.sign(sk, message)
        assert len(signature) == ed25519.ED25519_SIGNATURE_SIZE
        assert ed25519.verify(pk, message, signature) is True

    def test_sign_verify_empty_message(self) -> None:
        pk, sk = ed25519.generate_keypair()
        signature = ed25519.sign(sk, b"")
        assert ed25519.verify(pk, b"", signature) is True

    def test_sign_verify_large_message(self) -> None:
        pk, sk = ed25519.generate_keypair()
        message = b"x" * 10000
        signature = ed25519.sign(sk, message)
        assert ed25519.verify(pk, message, signature) is True


class TestVerifyRejectsInvalid:
    """Test that verification rejects invalid inputs."""

    def test_wrong_public_key_rejects(self) -> None:
        pk1, sk1 = ed25519.generate_keypair()
        pk2, _ = ed25519.generate_keypair()
        message = b"test message"
        signature = ed25519.sign(sk1, message)
        with pytest.raises((InvalidSignatureError, Exception)):
            ed25519.verify(pk2, message, signature)

    def test_wrong_message_rejects(self) -> None:
        pk, sk = ed25519.generate_keypair()
        signature = ed25519.sign(sk, b"original")
        with pytest.raises((InvalidSignatureError, Exception)):
            ed25519.verify(pk, b"tampered", signature)

    def test_tampered_signature_rejects(self) -> None:
        pk, sk = ed25519.generate_keypair()
        message = b"test"
        signature = ed25519.sign(sk, message)
        tampered = bytearray(signature)
        tampered[0] ^= 0xFF
        with pytest.raises((InvalidSignatureError, Exception)):
            ed25519.verify(pk, message, bytes(tampered))


class TestKeySizeValidation:
    """Test key size validation."""

    def test_sign_rejects_wrong_key_size(self) -> None:
        with pytest.raises(InvalidKeyError):
            ed25519.sign(b"too_short", b"message")

    def test_verify_rejects_wrong_public_key_size(self) -> None:
        with pytest.raises(InvalidKeyError):
            ed25519.verify(b"short", b"message", b"\x00" * 64)

    def test_verify_rejects_wrong_signature_size(self) -> None:
        pk, _ = ed25519.generate_keypair()
        with pytest.raises(InvalidSignatureError):
            ed25519.verify(pk, b"message", b"short_sig")
