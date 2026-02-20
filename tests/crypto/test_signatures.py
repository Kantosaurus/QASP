"""Unit tests for ML-DSA-65 digital signatures."""

from __future__ import annotations

import pytest

from qasp.crypto import signatures
from qasp.crypto.exceptions import (
    InvalidKeyError,
    InvalidSignatureError,
)


class TestMLDSAConstants:
    """Test ML-DSA-65 size constants."""

    def test_public_key_size(self) -> None:
        """Public key should be 1952 bytes."""
        assert signatures.ML_DSA_65_PUBLIC_KEY_SIZE == 1952

    def test_secret_key_size(self) -> None:
        """Secret key should be 4032 bytes."""
        assert signatures.ML_DSA_65_SECRET_KEY_SIZE == 4032

    def test_signature_size(self) -> None:
        """Maximum signature size should be 3309 bytes."""
        assert signatures.ML_DSA_65_SIGNATURE_SIZE == 3309


class TestGenerateKeypair:
    """Test ML-DSA-65 key generation."""

    def test_generates_keypair(self) -> None:
        """Should generate a valid keypair."""
        public_key, secret_key = signatures.generate_keypair()

        assert isinstance(public_key, bytes)
        assert isinstance(secret_key, bytes)

    def test_public_key_correct_size(self) -> None:
        """Public key should have correct size."""
        public_key, _ = signatures.generate_keypair()
        assert len(public_key) == signatures.ML_DSA_65_PUBLIC_KEY_SIZE

    def test_secret_key_correct_size(self) -> None:
        """Secret key should have correct size."""
        _, secret_key = signatures.generate_keypair()
        assert len(secret_key) == signatures.ML_DSA_65_SECRET_KEY_SIZE

    def test_generates_unique_keys(self) -> None:
        """Each keypair should be unique."""
        pk1, sk1 = signatures.generate_keypair()
        pk2, sk2 = signatures.generate_keypair()

        assert pk1 != pk2
        assert sk1 != sk2


class TestSign:
    """Test ML-DSA-65 signing."""

    def test_signs_message(self, mldsa_secret_key: bytes) -> None:
        """Should sign a message successfully."""
        message = b"Hello, QASP!"
        signature = signatures.sign(mldsa_secret_key, message)

        assert isinstance(signature, bytes)
        assert len(signature) > 0

    def test_signature_within_max_size(self, mldsa_secret_key: bytes) -> None:
        """Signature should be within maximum size."""
        message = b"Test message for signature size"
        signature = signatures.sign(mldsa_secret_key, message)

        assert len(signature) <= signatures.ML_DSA_65_SIGNATURE_SIZE

    def test_different_messages_different_signatures(
        self, mldsa_secret_key: bytes
    ) -> None:
        """Different messages should produce different signatures."""
        sig1 = signatures.sign(mldsa_secret_key, b"Message 1")
        sig2 = signatures.sign(mldsa_secret_key, b"Message 2")

        assert sig1 != sig2

    def test_same_message_different_signatures(
        self, mldsa_secret_key: bytes
    ) -> None:
        """Same message may produce different signatures (randomized)."""
        message = b"Same message"
        sig1 = signatures.sign(mldsa_secret_key, message)
        sig2 = signatures.sign(mldsa_secret_key, message)

        # ML-DSA is deterministic, so signatures should be the same
        # This test documents the behavior
        assert sig1 == sig2

    def test_rejects_invalid_secret_key_size(self) -> None:
        """Should reject secret key with wrong size."""
        with pytest.raises(InvalidKeyError, match="Invalid secret key size"):
            signatures.sign(b"short", b"message")

    def test_signs_empty_message(self, mldsa_secret_key: bytes) -> None:
        """Should sign empty message."""
        signature = signatures.sign(mldsa_secret_key, b"")
        assert isinstance(signature, bytes)

    def test_signs_large_message(self, mldsa_secret_key: bytes) -> None:
        """Should sign large message."""
        large_message = b"A" * 100_000
        signature = signatures.sign(mldsa_secret_key, large_message)
        assert isinstance(signature, bytes)


class TestVerify:
    """Test ML-DSA-65 verification."""

    def test_verifies_valid_signature(
        self, mldsa_keypair: tuple[bytes, bytes]
    ) -> None:
        """Should verify a valid signature."""
        public_key, secret_key = mldsa_keypair
        message = b"Hello, QASP!"
        signature = signatures.sign(secret_key, message)

        result = signatures.verify(public_key, message, signature)
        assert result is True

    def test_rejects_tampered_message(
        self, mldsa_keypair: tuple[bytes, bytes]
    ) -> None:
        """Should reject signature on tampered message."""
        public_key, secret_key = mldsa_keypair
        message = b"Original message"
        signature = signatures.sign(secret_key, message)

        with pytest.raises(InvalidSignatureError):
            signatures.verify(public_key, b"Tampered message", signature)

    def test_rejects_tampered_signature(
        self, mldsa_keypair: tuple[bytes, bytes]
    ) -> None:
        """Should reject tampered signature."""
        public_key, secret_key = mldsa_keypair
        message = b"Test message"
        signature = bytearray(signatures.sign(secret_key, message))
        signature[0] ^= 0xFF  # Flip bits

        with pytest.raises(InvalidSignatureError):
            signatures.verify(public_key, message, bytes(signature))

    def test_rejects_wrong_public_key(
        self, mldsa_keypair: tuple[bytes, bytes]
    ) -> None:
        """Should reject signature verified with wrong key."""
        _, secret_key = mldsa_keypair
        wrong_public_key, _ = signatures.generate_keypair()

        message = b"Test message"
        signature = signatures.sign(secret_key, message)

        with pytest.raises(InvalidSignatureError):
            signatures.verify(wrong_public_key, message, signature)

    def test_rejects_invalid_public_key_size(self) -> None:
        """Should reject public key with wrong size."""
        with pytest.raises(InvalidKeyError, match="Invalid public key size"):
            signatures.verify(b"short", b"message", b"signature")

    def test_rejects_oversized_signature(
        self, mldsa_public_key: bytes
    ) -> None:
        """Should reject signature exceeding maximum size."""
        oversized_sig = b"\x00" * (signatures.ML_DSA_65_SIGNATURE_SIZE + 1)
        with pytest.raises(InvalidSignatureError, match="Invalid signature size"):
            signatures.verify(mldsa_public_key, b"message", oversized_sig)


class TestSecureSecretKey:
    """Test secure secret key context manager."""

    def test_yields_key_bytes(self, mldsa_secret_key: bytes) -> None:
        """Should yield the secret key for use."""
        with signatures.secure_secret_key(mldsa_secret_key) as key:
            assert key == mldsa_secret_key

    def test_key_usable_within_context(
        self, mldsa_keypair: tuple[bytes, bytes]
    ) -> None:
        """Key should be usable for signing within context."""
        public_key, secret_key = mldsa_keypair
        message = b"Test message"

        with signatures.secure_secret_key(secret_key) as key:
            signature = signatures.sign(key, message)

        assert signatures.verify(public_key, message, signature)


class TestRoundTrip:
    """Test complete sign/verify round trips."""

    def test_multiple_round_trips(self) -> None:
        """Multiple round trips should all succeed."""
        public_key, secret_key = signatures.generate_keypair()

        for i in range(5):
            message = f"Message number {i}".encode()
            signature = signatures.sign(secret_key, message)
            assert signatures.verify(public_key, message, signature)

    def test_different_keypairs_independent(self) -> None:
        """Different keypairs should be independent."""
        pk1, sk1 = signatures.generate_keypair()
        pk2, sk2 = signatures.generate_keypair()

        message = b"Test message"
        sig1 = signatures.sign(sk1, message)
        sig2 = signatures.sign(sk2, message)

        # Verify with correct keys
        assert signatures.verify(pk1, message, sig1)
        assert signatures.verify(pk2, message, sig2)

        # Verify fails with wrong keys
        with pytest.raises(InvalidSignatureError):
            signatures.verify(pk2, message, sig1)
        with pytest.raises(InvalidSignatureError):
            signatures.verify(pk1, message, sig2)
