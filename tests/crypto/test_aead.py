"""Unit tests for AES-256-GCM authenticated encryption."""

from __future__ import annotations

import os

import pytest

from qasp.crypto import aead
from qasp.crypto.exceptions import DecryptionError, EncryptionError, InvalidKeyError


class TestAEADConstants:
    """Test AES-256-GCM size constants."""

    def test_key_size(self) -> None:
        """Key should be 32 bytes."""
        assert aead.AES_256_KEY_SIZE == 32

    def test_nonce_size(self) -> None:
        """Nonce should be 12 bytes."""
        assert aead.AES_GCM_NONCE_SIZE == 12

    def test_tag_size(self) -> None:
        """Tag should be 16 bytes."""
        assert aead.AES_GCM_TAG_SIZE == 16


class TestGenerateNonce:
    """Test nonce generation."""

    def test_generates_correct_size(self) -> None:
        """Should generate 12-byte nonce."""
        nonce = aead.generate_nonce()
        assert len(nonce) == aead.AES_GCM_NONCE_SIZE

    def test_generates_unique_nonces(self) -> None:
        """Each nonce should be unique."""
        nonces = [aead.generate_nonce() for _ in range(100)]
        assert len(set(nonces)) == 100


class TestEncrypt:
    """Test AES-256-GCM encryption."""

    def test_encrypts_successfully(self, aes_key: bytes) -> None:
        """Should encrypt plaintext."""
        plaintext = b"Hello, QASP!"
        nonce, ciphertext = aead.encrypt(aes_key, plaintext)

        assert isinstance(nonce, bytes)
        assert isinstance(ciphertext, bytes)

    def test_nonce_correct_size(self, aes_key: bytes) -> None:
        """Returned nonce should be 12 bytes."""
        nonce, _ = aead.encrypt(aes_key, b"test")
        assert len(nonce) == aead.AES_GCM_NONCE_SIZE

    def test_ciphertext_includes_tag(self, aes_key: bytes) -> None:
        """Ciphertext should include 16-byte tag."""
        plaintext = b"test"
        _, ciphertext = aead.encrypt(aes_key, plaintext)
        # Ciphertext = encrypted data + 16-byte tag
        assert len(ciphertext) == len(plaintext) + aead.AES_GCM_TAG_SIZE

    def test_uses_provided_nonce(self, aes_key: bytes) -> None:
        """Should use provided nonce."""
        nonce = b"\x00" * aead.AES_GCM_NONCE_SIZE
        returned_nonce, _ = aead.encrypt(aes_key, b"test", nonce=nonce)
        assert returned_nonce == nonce

    def test_generates_nonce_if_not_provided(self, aes_key: bytes) -> None:
        """Should generate random nonce if not provided."""
        nonce1, _ = aead.encrypt(aes_key, b"test")
        nonce2, _ = aead.encrypt(aes_key, b"test")
        assert nonce1 != nonce2

    def test_rejects_invalid_key_size(self) -> None:
        """Should reject key with wrong size."""
        with pytest.raises(InvalidKeyError, match="Invalid key size"):
            aead.encrypt(b"short", b"test")

    def test_rejects_invalid_nonce_size(self, aes_key: bytes) -> None:
        """Should reject nonce with wrong size."""
        with pytest.raises(EncryptionError, match="Invalid nonce size"):
            aead.encrypt(aes_key, b"test", nonce=b"short")

    def test_encrypts_empty_plaintext(self, aes_key: bytes) -> None:
        """Should encrypt empty plaintext."""
        _nonce, ciphertext = aead.encrypt(aes_key, b"")
        assert len(ciphertext) == aead.AES_GCM_TAG_SIZE

    def test_encrypts_large_plaintext(self, aes_key: bytes) -> None:
        """Should encrypt large plaintext."""
        plaintext = b"A" * 1_000_000
        _nonce, ciphertext = aead.encrypt(aes_key, plaintext)
        assert len(ciphertext) == len(plaintext) + aead.AES_GCM_TAG_SIZE

    def test_same_plaintext_different_nonce_different_ciphertext(
        self, aes_key: bytes
    ) -> None:
        """Same plaintext with different nonces should produce different ciphertext."""
        plaintext = b"test"
        _, ct1 = aead.encrypt(aes_key, plaintext)
        _, ct2 = aead.encrypt(aes_key, plaintext)
        assert ct1 != ct2

    def test_associated_data_does_not_change_ciphertext_length(
        self, aes_key: bytes
    ) -> None:
        """Associated data should not change ciphertext length."""
        plaintext = b"test"
        nonce = aead.generate_nonce()
        _, ct1 = aead.encrypt(aes_key, plaintext, nonce=nonce)
        _, ct2 = aead.encrypt(
            aes_key, plaintext, associated_data=b"extra", nonce=nonce
        )
        # Different AAD produces different ciphertext
        assert ct1 != ct2
        # But same length
        assert len(ct1) == len(ct2)


class TestDecrypt:
    """Test AES-256-GCM decryption."""

    def test_decrypts_successfully(self, aes_key: bytes) -> None:
        """Should decrypt ciphertext."""
        plaintext = b"Hello, QASP!"
        nonce, ciphertext = aead.encrypt(aes_key, plaintext)

        decrypted = aead.decrypt(aes_key, nonce, ciphertext)
        assert decrypted == plaintext

    def test_rejects_invalid_key_size(self) -> None:
        """Should reject key with wrong size."""
        with pytest.raises(InvalidKeyError, match="Invalid key size"):
            aead.decrypt(b"short", b"\x00" * 12, b"\x00" * 32)

    def test_rejects_invalid_nonce_size(self, aes_key: bytes) -> None:
        """Should reject nonce with wrong size."""
        with pytest.raises(DecryptionError, match="Invalid nonce size"):
            aead.decrypt(aes_key, b"short", b"\x00" * 32)

    def test_rejects_short_ciphertext(self, aes_key: bytes) -> None:
        """Should reject ciphertext shorter than tag."""
        nonce = aead.generate_nonce()
        with pytest.raises(DecryptionError, match="Ciphertext too short"):
            aead.decrypt(aes_key, nonce, b"\x00" * 15)

    def test_rejects_tampered_ciphertext(self, aes_key: bytes) -> None:
        """Should reject tampered ciphertext."""
        nonce, ciphertext = aead.encrypt(aes_key, b"test")
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF

        with pytest.raises(DecryptionError):
            aead.decrypt(aes_key, nonce, bytes(tampered))

    def test_rejects_tampered_tag(self, aes_key: bytes) -> None:
        """Should reject tampered authentication tag."""
        nonce, ciphertext = aead.encrypt(aes_key, b"test")
        tampered = bytearray(ciphertext)
        tampered[-1] ^= 0xFF  # Modify last byte (part of tag)

        with pytest.raises(DecryptionError):
            aead.decrypt(aes_key, nonce, bytes(tampered))

    def test_rejects_wrong_key(self, aes_key: bytes) -> None:
        """Should reject ciphertext decrypted with wrong key."""
        nonce, ciphertext = aead.encrypt(aes_key, b"test")
        wrong_key = os.urandom(aead.AES_256_KEY_SIZE)

        with pytest.raises(DecryptionError):
            aead.decrypt(wrong_key, nonce, ciphertext)

    def test_rejects_wrong_nonce(self, aes_key: bytes) -> None:
        """Should reject ciphertext decrypted with wrong nonce."""
        _nonce, ciphertext = aead.encrypt(aes_key, b"test")
        wrong_nonce = os.urandom(aead.AES_GCM_NONCE_SIZE)

        with pytest.raises(DecryptionError):
            aead.decrypt(aes_key, wrong_nonce, ciphertext)

    def test_rejects_wrong_associated_data(self, aes_key: bytes) -> None:
        """Should reject ciphertext with wrong associated data."""
        aad = b"original-aad"
        nonce, ciphertext = aead.encrypt(aes_key, b"test", associated_data=aad)

        with pytest.raises(DecryptionError):
            aead.decrypt(aes_key, nonce, ciphertext, associated_data=b"wrong-aad")

    def test_decrypts_empty_plaintext(self, aes_key: bytes) -> None:
        """Should decrypt empty plaintext."""
        nonce, ciphertext = aead.encrypt(aes_key, b"")
        decrypted = aead.decrypt(aes_key, nonce, ciphertext)
        assert decrypted == b""


class TestRoundTrip:
    """Test complete encryption/decryption round trips."""

    def test_multiple_round_trips(self, aes_key: bytes) -> None:
        """Multiple round trips should all succeed."""
        for i in range(10):
            plaintext = f"Message number {i}".encode()
            nonce, ciphertext = aead.encrypt(aes_key, plaintext)
            decrypted = aead.decrypt(aes_key, nonce, ciphertext)
            assert decrypted == plaintext

    def test_round_trip_with_associated_data(self, aes_key: bytes) -> None:
        """Round trip should work with associated data."""
        plaintext = b"secret data"
        aad = b"authenticated but not encrypted"

        nonce, ciphertext = aead.encrypt(aes_key, plaintext, associated_data=aad)
        decrypted = aead.decrypt(aes_key, nonce, ciphertext, associated_data=aad)

        assert decrypted == plaintext

    def test_different_keys_produce_different_ciphertext(self) -> None:
        """Different keys should produce different ciphertext."""
        key1 = os.urandom(aead.AES_256_KEY_SIZE)
        key2 = os.urandom(aead.AES_256_KEY_SIZE)
        plaintext = b"test"
        nonce = aead.generate_nonce()

        _, ct1 = aead.encrypt(key1, plaintext, nonce=nonce)
        _, ct2 = aead.encrypt(key2, plaintext, nonce=nonce)

        assert ct1 != ct2
