"""Unit tests for HKDF-SHA-384 key derivation."""

from __future__ import annotations

import pytest

from qasp.crypto import aead, kdf
from qasp.crypto.exceptions import KeyDerivationError


class TestKDFConstants:
    """Test HKDF-SHA-384 constants."""

    def test_hash_size(self) -> None:
        """Hash output should be 48 bytes."""
        assert kdf.HKDF_SHA384_HASH_SIZE == 48

    def test_max_output(self) -> None:
        """Maximum output should be 255 * 48 bytes."""
        assert kdf.HKDF_SHA384_MAX_OUTPUT == 255 * 48

    def test_qasp_info_prefix(self) -> None:
        """QASP info prefix should be correct."""
        assert kdf.QASP_INFO_PREFIX == b"QASP-v1"

    def test_qasp_session_key_size(self) -> None:
        """Session key size should match AES-256."""
        assert kdf.QASP_SESSION_KEY_SIZE == 32


class TestDeriveKey:
    """Test HKDF-SHA-384 derive_key function."""

    def test_derives_key(self, sample_ikm: bytes) -> None:
        """Should derive a key from IKM."""
        key = kdf.derive_key(sample_ikm)
        assert isinstance(key, bytes)
        assert len(key) == kdf.HKDF_SHA384_HASH_SIZE

    def test_custom_length(self, sample_ikm: bytes) -> None:
        """Should derive key of custom length."""
        key = kdf.derive_key(sample_ikm, length=32)
        assert len(key) == 32

    def test_uses_salt(self, sample_ikm: bytes, sample_salt: bytes) -> None:
        """Different salts should produce different keys."""
        key1 = kdf.derive_key(sample_ikm, salt=sample_salt)
        key2 = kdf.derive_key(sample_ikm, salt=b"different-salt")
        assert key1 != key2

    def test_uses_info(self, sample_ikm: bytes, sample_info: bytes) -> None:
        """Different info should produce different keys."""
        key1 = kdf.derive_key(sample_ikm, info=sample_info)
        key2 = kdf.derive_key(sample_ikm, info=b"different-info")
        assert key1 != key2

    def test_deterministic(
        self, sample_ikm: bytes, sample_salt: bytes, sample_info: bytes
    ) -> None:
        """Same inputs should produce same output."""
        key1 = kdf.derive_key(sample_ikm, salt=sample_salt, info=sample_info)
        key2 = kdf.derive_key(sample_ikm, salt=sample_salt, info=sample_info)
        assert key1 == key2

    def test_rejects_zero_length(self, sample_ikm: bytes) -> None:
        """Should reject zero output length."""
        with pytest.raises(KeyDerivationError, match="Invalid output length"):
            kdf.derive_key(sample_ikm, length=0)

    def test_rejects_excessive_length(self, sample_ikm: bytes) -> None:
        """Should reject output length exceeding maximum."""
        with pytest.raises(KeyDerivationError, match="Invalid output length"):
            kdf.derive_key(sample_ikm, length=kdf.HKDF_SHA384_MAX_OUTPUT + 1)

    def test_max_length(self, sample_ikm: bytes) -> None:
        """Should allow maximum output length."""
        key = kdf.derive_key(sample_ikm, length=kdf.HKDF_SHA384_MAX_OUTPUT)
        assert len(key) == kdf.HKDF_SHA384_MAX_OUTPUT


class TestExtractKey:
    """Test HKDF-SHA-384 extract_key function."""

    def test_extracts_prk(self, sample_ikm: bytes) -> None:
        """Should extract a PRK from IKM."""
        prk = kdf.extract_key(sample_ikm)
        assert isinstance(prk, bytes)
        assert len(prk) == kdf.HKDF_SHA384_HASH_SIZE

    def test_uses_salt(self, sample_ikm: bytes, sample_salt: bytes) -> None:
        """Different salts should produce different PRKs."""
        prk1 = kdf.extract_key(sample_ikm, salt=sample_salt)
        prk2 = kdf.extract_key(sample_ikm, salt=b"different-salt")
        assert prk1 != prk2

    def test_deterministic(
        self, sample_ikm: bytes, sample_salt: bytes
    ) -> None:
        """Same inputs should produce same PRK."""
        prk1 = kdf.extract_key(sample_ikm, salt=sample_salt)
        prk2 = kdf.extract_key(sample_ikm, salt=sample_salt)
        assert prk1 == prk2


class TestExpandKey:
    """Test HKDF-SHA-384 expand_key function."""

    def test_expands_prk(self, sample_ikm: bytes) -> None:
        """Should expand a PRK."""
        prk = kdf.extract_key(sample_ikm)
        expanded = kdf.expand_key(prk)
        assert isinstance(expanded, bytes)
        assert len(expanded) == kdf.HKDF_SHA384_HASH_SIZE

    def test_custom_length(self, sample_ikm: bytes) -> None:
        """Should expand to custom length."""
        prk = kdf.extract_key(sample_ikm)
        expanded = kdf.expand_key(prk, length=64)
        assert len(expanded) == 64

    def test_uses_info(self, sample_ikm: bytes, sample_info: bytes) -> None:
        """Different info should produce different keys."""
        prk = kdf.extract_key(sample_ikm)
        key1 = kdf.expand_key(prk, info=sample_info)
        key2 = kdf.expand_key(prk, info=b"different-info")
        assert key1 != key2

    def test_rejects_short_prk(self) -> None:
        """Should reject PRK shorter than hash size."""
        with pytest.raises(KeyDerivationError, match="PRK too short"):
            kdf.expand_key(b"short-prk")

    def test_rejects_zero_length(self, sample_ikm: bytes) -> None:
        """Should reject zero output length."""
        prk = kdf.extract_key(sample_ikm)
        with pytest.raises(KeyDerivationError, match="Invalid output length"):
            kdf.expand_key(prk, length=0)

    def test_rejects_excessive_length(self, sample_ikm: bytes) -> None:
        """Should reject output length exceeding maximum."""
        prk = kdf.extract_key(sample_ikm)
        with pytest.raises(KeyDerivationError, match="Invalid output length"):
            kdf.expand_key(prk, length=kdf.HKDF_SHA384_MAX_OUTPUT + 1)


class TestDeriveQASPSessionKey:
    """Test QASP session key derivation."""

    def test_derives_session_key(self) -> None:
        """Should derive a session key from shared secrets."""
        mlkem_ss = b"\x00" * 32
        x25519_ss = b"\x11" * 32
        client_nonce = b"\x22" * 16
        server_nonce = b"\x33" * 16

        session_key = kdf.derive_qasp_session_key(
            mlkem_shared_secret=mlkem_ss,
            x25519_shared_secret=x25519_ss,
            client_nonce=client_nonce,
            server_nonce=server_nonce,
        )

        assert isinstance(session_key, bytes)
        assert len(session_key) == kdf.QASP_SESSION_KEY_SIZE

    def test_key_usable_for_aes(self) -> None:
        """Derived key should be usable for AES-256-GCM."""
        mlkem_ss = b"\x00" * 32
        x25519_ss = b"\x11" * 32
        client_nonce = b"\x22" * 16
        server_nonce = b"\x33" * 16

        session_key = kdf.derive_qasp_session_key(
            mlkem_shared_secret=mlkem_ss,
            x25519_shared_secret=x25519_ss,
            client_nonce=client_nonce,
            server_nonce=server_nonce,
        )

        # Should work with AES-256-GCM
        nonce, ciphertext = aead.encrypt(session_key, b"test message")
        plaintext = aead.decrypt(session_key, nonce, ciphertext)
        assert plaintext == b"test message"

    def test_custom_length(self) -> None:
        """Should derive key of custom length."""
        mlkem_ss = b"\x00" * 32
        x25519_ss = b"\x11" * 32
        client_nonce = b"\x22" * 16
        server_nonce = b"\x33" * 16

        session_key = kdf.derive_qasp_session_key(
            mlkem_shared_secret=mlkem_ss,
            x25519_shared_secret=x25519_ss,
            client_nonce=client_nonce,
            server_nonce=server_nonce,
            length=64,
        )

        assert len(session_key) == 64

    def test_different_mlkem_secret_different_key(self) -> None:
        """Different ML-KEM secrets should produce different keys."""
        x25519_ss = b"\x11" * 32
        client_nonce = b"\x22" * 16
        server_nonce = b"\x33" * 16

        key1 = kdf.derive_qasp_session_key(
            mlkem_shared_secret=b"\x00" * 32,
            x25519_shared_secret=x25519_ss,
            client_nonce=client_nonce,
            server_nonce=server_nonce,
        )
        key2 = kdf.derive_qasp_session_key(
            mlkem_shared_secret=b"\xFF" * 32,
            x25519_shared_secret=x25519_ss,
            client_nonce=client_nonce,
            server_nonce=server_nonce,
        )

        assert key1 != key2

    def test_different_x25519_secret_different_key(self) -> None:
        """Different X25519 secrets should produce different keys."""
        mlkem_ss = b"\x00" * 32
        client_nonce = b"\x22" * 16
        server_nonce = b"\x33" * 16

        key1 = kdf.derive_qasp_session_key(
            mlkem_shared_secret=mlkem_ss,
            x25519_shared_secret=b"\x11" * 32,
            client_nonce=client_nonce,
            server_nonce=server_nonce,
        )
        key2 = kdf.derive_qasp_session_key(
            mlkem_shared_secret=mlkem_ss,
            x25519_shared_secret=b"\xFF" * 32,
            client_nonce=client_nonce,
            server_nonce=server_nonce,
        )

        assert key1 != key2

    def test_different_nonces_different_key(self) -> None:
        """Different nonces should produce different keys."""
        mlkem_ss = b"\x00" * 32
        x25519_ss = b"\x11" * 32

        key1 = kdf.derive_qasp_session_key(
            mlkem_shared_secret=mlkem_ss,
            x25519_shared_secret=x25519_ss,
            client_nonce=b"\x22" * 16,
            server_nonce=b"\x33" * 16,
        )
        key2 = kdf.derive_qasp_session_key(
            mlkem_shared_secret=mlkem_ss,
            x25519_shared_secret=x25519_ss,
            client_nonce=b"\xFF" * 16,
            server_nonce=b"\x33" * 16,
        )

        assert key1 != key2

    def test_rejects_invalid_mlkem_size(self) -> None:
        """Should reject ML-KEM shared secret with wrong size."""
        with pytest.raises(KeyDerivationError, match="Invalid ML-KEM shared secret"):
            kdf.derive_qasp_session_key(
                mlkem_shared_secret=b"short",
                x25519_shared_secret=b"\x11" * 32,
                client_nonce=b"\x22" * 16,
                server_nonce=b"\x33" * 16,
            )

    def test_rejects_invalid_x25519_size(self) -> None:
        """Should reject X25519 shared secret with wrong size."""
        with pytest.raises(KeyDerivationError, match="Invalid X25519 shared secret"):
            kdf.derive_qasp_session_key(
                mlkem_shared_secret=b"\x00" * 32,
                x25519_shared_secret=b"short",
                client_nonce=b"\x22" * 16,
                server_nonce=b"\x33" * 16,
            )

    def test_deterministic(self) -> None:
        """Same inputs should produce same session key."""
        mlkem_ss = b"\x00" * 32
        x25519_ss = b"\x11" * 32
        client_nonce = b"\x22" * 16
        server_nonce = b"\x33" * 16

        key1 = kdf.derive_qasp_session_key(
            mlkem_shared_secret=mlkem_ss,
            x25519_shared_secret=x25519_ss,
            client_nonce=client_nonce,
            server_nonce=server_nonce,
        )
        key2 = kdf.derive_qasp_session_key(
            mlkem_shared_secret=mlkem_ss,
            x25519_shared_secret=x25519_ss,
            client_nonce=client_nonce,
            server_nonce=server_nonce,
        )

        assert key1 == key2
