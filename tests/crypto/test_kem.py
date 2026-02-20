"""Unit tests for ML-KEM-768 key encapsulation mechanism."""

from __future__ import annotations

import pytest

from qasp.crypto import kem
from qasp.crypto.exceptions import (
    DecapsulationError,
    InvalidKeyError,
)


class TestMLKEMConstants:
    """Test ML-KEM-768 size constants."""

    def test_public_key_size(self) -> None:
        """Public key should be 1184 bytes."""
        assert kem.ML_KEM_768_PUBLIC_KEY_SIZE == 1184

    def test_secret_key_size(self) -> None:
        """Secret key should be 2400 bytes."""
        assert kem.ML_KEM_768_SECRET_KEY_SIZE == 2400

    def test_ciphertext_size(self) -> None:
        """Ciphertext should be 1088 bytes."""
        assert kem.ML_KEM_768_CIPHERTEXT_SIZE == 1088

    def test_shared_secret_size(self) -> None:
        """Shared secret should be 32 bytes."""
        assert kem.ML_KEM_768_SHARED_SECRET_SIZE == 32


class TestGenerateKeypair:
    """Test ML-KEM-768 key generation."""

    def test_generates_keypair(self) -> None:
        """Should generate a valid keypair."""
        public_key, secret_key = kem.generate_keypair()

        assert isinstance(public_key, bytes)
        assert isinstance(secret_key, bytes)

    def test_public_key_correct_size(self) -> None:
        """Public key should have correct size."""
        public_key, _ = kem.generate_keypair()
        assert len(public_key) == kem.ML_KEM_768_PUBLIC_KEY_SIZE

    def test_secret_key_correct_size(self) -> None:
        """Secret key should have correct size."""
        _, secret_key = kem.generate_keypair()
        assert len(secret_key) == kem.ML_KEM_768_SECRET_KEY_SIZE

    def test_generates_unique_keys(self) -> None:
        """Each keypair should be unique."""
        pk1, sk1 = kem.generate_keypair()
        pk2, sk2 = kem.generate_keypair()

        assert pk1 != pk2
        assert sk1 != sk2


class TestEncapsulate:
    """Test ML-KEM-768 encapsulation."""

    def test_encapsulates_successfully(
        self, mlkem_public_key: bytes
    ) -> None:
        """Should encapsulate with valid public key."""
        ciphertext, shared_secret = kem.encapsulate(mlkem_public_key)

        assert isinstance(ciphertext, bytes)
        assert isinstance(shared_secret, bytes)

    def test_ciphertext_correct_size(
        self, mlkem_public_key: bytes
    ) -> None:
        """Ciphertext should have correct size."""
        ciphertext, _ = kem.encapsulate(mlkem_public_key)
        assert len(ciphertext) == kem.ML_KEM_768_CIPHERTEXT_SIZE

    def test_shared_secret_correct_size(
        self, mlkem_public_key: bytes
    ) -> None:
        """Shared secret should have correct size."""
        _, shared_secret = kem.encapsulate(mlkem_public_key)
        assert len(shared_secret) == kem.ML_KEM_768_SHARED_SECRET_SIZE

    def test_rejects_invalid_public_key_size(self) -> None:
        """Should reject public key with wrong size."""
        with pytest.raises(InvalidKeyError, match="Invalid public key size"):
            kem.encapsulate(b"short")

    def test_generates_unique_shared_secrets(
        self, mlkem_public_key: bytes
    ) -> None:
        """Each encapsulation should produce unique shared secret."""
        _, ss1 = kem.encapsulate(mlkem_public_key)
        _, ss2 = kem.encapsulate(mlkem_public_key)

        assert ss1 != ss2


class TestDecapsulate:
    """Test ML-KEM-768 decapsulation."""

    def test_decapsulates_successfully(
        self, mlkem_keypair: tuple[bytes, bytes]
    ) -> None:
        """Should decapsulate and recover shared secret."""
        public_key, secret_key = mlkem_keypair
        ciphertext, encap_secret = kem.encapsulate(public_key)

        decap_secret = kem.decapsulate(secret_key, ciphertext)

        assert decap_secret == encap_secret

    def test_shared_secret_correct_size(
        self, mlkem_keypair: tuple[bytes, bytes]
    ) -> None:
        """Decapsulated shared secret should have correct size."""
        public_key, secret_key = mlkem_keypair
        ciphertext, _ = kem.encapsulate(public_key)

        shared_secret = kem.decapsulate(secret_key, ciphertext)
        assert len(shared_secret) == kem.ML_KEM_768_SHARED_SECRET_SIZE

    def test_rejects_invalid_secret_key_size(self) -> None:
        """Should reject secret key with wrong size."""
        ciphertext = b"\x00" * kem.ML_KEM_768_CIPHERTEXT_SIZE
        with pytest.raises(InvalidKeyError, match="Invalid secret key size"):
            kem.decapsulate(b"short", ciphertext)

    def test_rejects_invalid_ciphertext_size(
        self, mlkem_secret_key: bytes
    ) -> None:
        """Should reject ciphertext with wrong size."""
        with pytest.raises(DecapsulationError, match="Invalid ciphertext size"):
            kem.decapsulate(mlkem_secret_key, b"short")

    def test_wrong_key_produces_different_secret(self) -> None:
        """Decapsulation with wrong key should produce different secret."""
        pk1, _sk1 = kem.generate_keypair()
        _, sk2 = kem.generate_keypair()

        ciphertext, original_secret = kem.encapsulate(pk1)

        # Decapsulate with wrong secret key
        wrong_secret = kem.decapsulate(sk2, ciphertext)

        assert wrong_secret != original_secret


class TestSecureSecretKey:
    """Test secure secret key context manager."""

    def test_yields_key_bytes(self, mlkem_secret_key: bytes) -> None:
        """Should yield the secret key for use."""
        with kem.secure_secret_key(mlkem_secret_key) as key:
            assert key == mlkem_secret_key

    def test_key_usable_within_context(
        self, mlkem_keypair: tuple[bytes, bytes]
    ) -> None:
        """Key should be usable for decapsulation within context."""
        public_key, secret_key = mlkem_keypair
        ciphertext, encap_secret = kem.encapsulate(public_key)

        with kem.secure_secret_key(secret_key) as key:
            decap_secret = kem.decapsulate(key, ciphertext)
            assert decap_secret == encap_secret


class TestRoundTrip:
    """Test complete encapsulation/decapsulation round trips."""

    def test_multiple_round_trips(self) -> None:
        """Multiple round trips should all succeed."""
        public_key, secret_key = kem.generate_keypair()

        for _ in range(5):
            ciphertext, encap_secret = kem.encapsulate(public_key)
            decap_secret = kem.decapsulate(secret_key, ciphertext)
            assert encap_secret == decap_secret

    def test_different_keypairs_independent(self) -> None:
        """Different keypairs should be independent."""
        pk1, sk1 = kem.generate_keypair()
        pk2, sk2 = kem.generate_keypair()

        ct1, ss1 = kem.encapsulate(pk1)
        ct2, ss2 = kem.encapsulate(pk2)

        assert kem.decapsulate(sk1, ct1) == ss1
        assert kem.decapsulate(sk2, ct2) == ss2
        assert ss1 != ss2
