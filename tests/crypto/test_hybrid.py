"""Unit tests for hybrid X25519 + ML-KEM-768 key exchange."""

from __future__ import annotations

import pytest

from qasp.crypto import hybrid, kem
from qasp.crypto.exceptions import (
    DecapsulationError,
    InvalidKeyError,
)


class TestHybridConstants:
    """Test hybrid KEM size constants."""

    def test_x25519_public_key_size(self) -> None:
        """X25519 public key should be 32 bytes."""
        assert hybrid.X25519_PUBLIC_KEY_SIZE == 32

    def test_x25519_private_key_size(self) -> None:
        """X25519 private key should be 32 bytes."""
        assert hybrid.X25519_PRIVATE_KEY_SIZE == 32

    def test_x25519_shared_secret_size(self) -> None:
        """X25519 shared secret should be 32 bytes."""
        assert hybrid.X25519_SHARED_SECRET_SIZE == 32

    def test_hybrid_public_key_size(self) -> None:
        """Hybrid public key should be 32 + 1184 = 1216 bytes."""
        assert hybrid.HYBRID_PUBLIC_KEY_SIZE == 1216

    def test_hybrid_private_key_size(self) -> None:
        """Hybrid private key should be 32 + 2400 = 2432 bytes."""
        assert hybrid.HYBRID_PRIVATE_KEY_SIZE == 2432

    def test_hybrid_ciphertext_size(self) -> None:
        """Hybrid ciphertext should be 32 + 1088 = 1120 bytes."""
        assert hybrid.HYBRID_CIPHERTEXT_SIZE == 1120

    def test_hybrid_shared_secret_size(self) -> None:
        """Hybrid shared secret should be 32 + 32 = 64 bytes."""
        assert hybrid.HYBRID_SHARED_SECRET_SIZE == 64


class TestHybridKeypair:
    """Test HybridKeypair dataclass."""

    def test_public_key_concatenation(
        self, hybrid_keypair: hybrid.HybridKeypair
    ) -> None:
        """Public key should be X25519 || ML-KEM-768."""
        expected = hybrid_keypair.x25519_public + hybrid_keypair.mlkem_public
        assert hybrid_keypair.public_key == expected

    def test_private_key_concatenation(
        self, hybrid_keypair: hybrid.HybridKeypair
    ) -> None:
        """Private key should be X25519 || ML-KEM-768."""
        expected = hybrid_keypair.x25519_private + hybrid_keypair.mlkem_private
        assert hybrid_keypair.private_key == expected

    def test_rejects_invalid_x25519_public(self) -> None:
        """Should reject invalid X25519 public key size."""
        with pytest.raises(InvalidKeyError, match="Invalid X25519 public key"):
            hybrid.HybridKeypair(
                x25519_public=b"short",
                x25519_private=b"\x00" * 32,
                mlkem_public=b"\x00" * kem.ML_KEM_768_PUBLIC_KEY_SIZE,
                mlkem_private=b"\x00" * kem.ML_KEM_768_SECRET_KEY_SIZE,
            )

    def test_rejects_invalid_x25519_private(self) -> None:
        """Should reject invalid X25519 private key size."""
        with pytest.raises(InvalidKeyError, match="Invalid X25519 private key"):
            hybrid.HybridKeypair(
                x25519_public=b"\x00" * 32,
                x25519_private=b"short",
                mlkem_public=b"\x00" * kem.ML_KEM_768_PUBLIC_KEY_SIZE,
                mlkem_private=b"\x00" * kem.ML_KEM_768_SECRET_KEY_SIZE,
            )

    def test_rejects_invalid_mlkem_public(self) -> None:
        """Should reject invalid ML-KEM public key size."""
        with pytest.raises(InvalidKeyError, match="Invalid ML-KEM-768 public key"):
            hybrid.HybridKeypair(
                x25519_public=b"\x00" * 32,
                x25519_private=b"\x00" * 32,
                mlkem_public=b"short",
                mlkem_private=b"\x00" * kem.ML_KEM_768_SECRET_KEY_SIZE,
            )

    def test_rejects_invalid_mlkem_private(self) -> None:
        """Should reject invalid ML-KEM secret key size."""
        with pytest.raises(InvalidKeyError, match="Invalid ML-KEM-768 secret key"):
            hybrid.HybridKeypair(
                x25519_public=b"\x00" * 32,
                x25519_private=b"\x00" * 32,
                mlkem_public=b"\x00" * kem.ML_KEM_768_PUBLIC_KEY_SIZE,
                mlkem_private=b"short",
            )


class TestGenerateKeypair:
    """Test hybrid keypair generation."""

    def test_generates_keypair(self) -> None:
        """Should generate a valid hybrid keypair."""
        keypair = hybrid.generate_keypair()

        assert isinstance(keypair, hybrid.HybridKeypair)

    def test_x25519_keys_correct_size(self) -> None:
        """X25519 keys should have correct sizes."""
        keypair = hybrid.generate_keypair()

        assert len(keypair.x25519_public) == hybrid.X25519_PUBLIC_KEY_SIZE
        assert len(keypair.x25519_private) == hybrid.X25519_PRIVATE_KEY_SIZE

    def test_mlkem_keys_correct_size(self) -> None:
        """ML-KEM-768 keys should have correct sizes."""
        keypair = hybrid.generate_keypair()

        assert len(keypair.mlkem_public) == kem.ML_KEM_768_PUBLIC_KEY_SIZE
        assert len(keypair.mlkem_private) == kem.ML_KEM_768_SECRET_KEY_SIZE

    def test_public_key_correct_size(self) -> None:
        """Combined public key should have correct size."""
        keypair = hybrid.generate_keypair()
        assert len(keypair.public_key) == hybrid.HYBRID_PUBLIC_KEY_SIZE

    def test_private_key_correct_size(self) -> None:
        """Combined private key should have correct size."""
        keypair = hybrid.generate_keypair()
        assert len(keypair.private_key) == hybrid.HYBRID_PRIVATE_KEY_SIZE

    def test_generates_unique_keypairs(self) -> None:
        """Each keypair should be unique."""
        kp1 = hybrid.generate_keypair()
        kp2 = hybrid.generate_keypair()

        assert kp1.public_key != kp2.public_key
        assert kp1.private_key != kp2.private_key


class TestEncapsulate:
    """Test hybrid encapsulation."""

    def test_encapsulates_successfully(
        self, hybrid_keypair: hybrid.HybridKeypair
    ) -> None:
        """Should encapsulate with valid public key."""
        ciphertext, shared_secret = hybrid.encapsulate(hybrid_keypair.public_key)

        assert isinstance(ciphertext, bytes)
        assert isinstance(shared_secret, bytes)

    def test_ciphertext_correct_size(
        self, hybrid_keypair: hybrid.HybridKeypair
    ) -> None:
        """Ciphertext should be 1120 bytes."""
        ciphertext, _ = hybrid.encapsulate(hybrid_keypair.public_key)
        assert len(ciphertext) == hybrid.HYBRID_CIPHERTEXT_SIZE

    def test_shared_secret_correct_size(
        self, hybrid_keypair: hybrid.HybridKeypair
    ) -> None:
        """Shared secret should be 64 bytes."""
        _, shared_secret = hybrid.encapsulate(hybrid_keypair.public_key)
        assert len(shared_secret) == hybrid.HYBRID_SHARED_SECRET_SIZE

    def test_rejects_invalid_public_key_size(self) -> None:
        """Should reject public key with wrong size."""
        with pytest.raises(InvalidKeyError, match="Invalid hybrid public key"):
            hybrid.encapsulate(b"short")

    def test_generates_unique_shared_secrets(
        self, hybrid_keypair: hybrid.HybridKeypair
    ) -> None:
        """Each encapsulation should produce unique shared secret."""
        _, ss1 = hybrid.encapsulate(hybrid_keypair.public_key)
        _, ss2 = hybrid.encapsulate(hybrid_keypair.public_key)

        assert ss1 != ss2

    def test_ciphertext_structure(
        self, hybrid_keypair: hybrid.HybridKeypair
    ) -> None:
        """Ciphertext should be ephemeral X25519 pk || ML-KEM ct."""
        ciphertext, _ = hybrid.encapsulate(hybrid_keypair.public_key)

        x25519_ct = ciphertext[:hybrid.X25519_PUBLIC_KEY_SIZE]
        mlkem_ct = ciphertext[hybrid.X25519_PUBLIC_KEY_SIZE:]

        assert len(x25519_ct) == hybrid.X25519_PUBLIC_KEY_SIZE
        assert len(mlkem_ct) == kem.ML_KEM_768_CIPHERTEXT_SIZE


class TestDecapsulate:
    """Test hybrid decapsulation."""

    def test_decapsulates_successfully(
        self, hybrid_keypair: hybrid.HybridKeypair
    ) -> None:
        """Should decapsulate and recover shared secret."""
        ciphertext, encap_secret = hybrid.encapsulate(hybrid_keypair.public_key)

        decap_secret = hybrid.decapsulate(hybrid_keypair, ciphertext)

        assert decap_secret == encap_secret

    def test_shared_secret_correct_size(
        self, hybrid_keypair: hybrid.HybridKeypair
    ) -> None:
        """Decapsulated shared secret should be 64 bytes."""
        ciphertext, _ = hybrid.encapsulate(hybrid_keypair.public_key)

        shared_secret = hybrid.decapsulate(hybrid_keypair, ciphertext)
        assert len(shared_secret) == hybrid.HYBRID_SHARED_SECRET_SIZE

    def test_rejects_invalid_ciphertext_size(
        self, hybrid_keypair: hybrid.HybridKeypair
    ) -> None:
        """Should reject ciphertext with wrong size."""
        with pytest.raises(DecapsulationError, match="Invalid hybrid ciphertext"):
            hybrid.decapsulate(hybrid_keypair, b"short")

    def test_shared_secret_structure(
        self, hybrid_keypair: hybrid.HybridKeypair
    ) -> None:
        """Shared secret should be X25519_ss || ML-KEM_ss."""
        _ciphertext, shared_secret = hybrid.encapsulate(hybrid_keypair.public_key)

        x25519_ss = shared_secret[:hybrid.X25519_SHARED_SECRET_SIZE]
        mlkem_ss = shared_secret[hybrid.X25519_SHARED_SECRET_SIZE:]

        assert len(x25519_ss) == hybrid.X25519_SHARED_SECRET_SIZE
        assert len(mlkem_ss) == kem.ML_KEM_768_SHARED_SECRET_SIZE


class TestSecureKeypair:
    """Test secure keypair context manager."""

    def test_yields_keypair(self, hybrid_keypair: hybrid.HybridKeypair) -> None:
        """Should yield the keypair for use."""
        with hybrid.secure_keypair(hybrid_keypair) as kp:
            assert kp.public_key == hybrid_keypair.public_key

    def test_keypair_usable_within_context(
        self, hybrid_keypair: hybrid.HybridKeypair
    ) -> None:
        """Keypair should be usable for decapsulation within context."""
        ciphertext, encap_secret = hybrid.encapsulate(hybrid_keypair.public_key)

        with hybrid.secure_keypair(hybrid_keypair) as kp:
            decap_secret = hybrid.decapsulate(kp, ciphertext)
            assert decap_secret == encap_secret


class TestRoundTrip:
    """Test complete encapsulation/decapsulation round trips."""

    def test_multiple_round_trips(self) -> None:
        """Multiple round trips should all succeed."""
        keypair = hybrid.generate_keypair()

        for _ in range(5):
            ciphertext, encap_secret = hybrid.encapsulate(keypair.public_key)
            decap_secret = hybrid.decapsulate(keypair, ciphertext)
            assert encap_secret == decap_secret

    def test_different_keypairs_independent(self) -> None:
        """Different keypairs should be independent."""
        kp1 = hybrid.generate_keypair()
        kp2 = hybrid.generate_keypair()

        ct1, ss1 = hybrid.encapsulate(kp1.public_key)
        ct2, ss2 = hybrid.encapsulate(kp2.public_key)

        assert hybrid.decapsulate(kp1, ct1) == ss1
        assert hybrid.decapsulate(kp2, ct2) == ss2
        assert ss1 != ss2

    def test_wrong_keypair_produces_different_secret(self) -> None:
        """Decapsulation with wrong keypair should produce different secret."""
        kp1 = hybrid.generate_keypair()
        kp2 = hybrid.generate_keypair()

        ciphertext, original_secret = hybrid.encapsulate(kp1.public_key)

        # The X25519 part will still work (any valid private key can compute DH)
        # but the ML-KEM part will produce a different (implicit reject) secret
        wrong_secret = hybrid.decapsulate(kp2, ciphertext)

        assert wrong_secret != original_secret


class TestIntegration:
    """Integration tests combining hybrid with other modules."""

    def test_full_key_exchange_and_encryption(self) -> None:
        """Full hybrid key exchange followed by encryption."""
        from qasp.crypto import aead, kdf

        # Generate keypairs for Alice and Bob
        bob = hybrid.generate_keypair()

        # Alice encapsulates to Bob
        ciphertext, alice_ss = hybrid.encapsulate(bob.public_key)

        # Bob decapsulates
        bob_ss = hybrid.decapsulate(bob, ciphertext)
        assert alice_ss == bob_ss

        # Derive session key
        session_key = kdf.derive_qasp_session_key(
            mlkem_shared_secret=alice_ss[32:],
            x25519_shared_secret=alice_ss[:32],
            client_nonce=b"client_nonce_16b",
            server_nonce=b"server_nonce_16b",
        )

        # Encrypt/decrypt message
        nonce, encrypted = aead.encrypt(session_key, b"Hello QASP!")
        plaintext = aead.decrypt(session_key, nonce, encrypted)
        assert plaintext == b"Hello QASP!"
