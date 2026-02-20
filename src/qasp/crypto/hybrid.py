"""Hybrid X25519 + ML-KEM-768 key exchange.

This module implements hybrid key exchange combining classical X25519
with post-quantum ML-KEM-768 for defense in depth.

The hybrid approach ensures that:
- If ML-KEM-768 is broken, X25519 still provides security
- If X25519 is broken (e.g., by quantum computers), ML-KEM-768 provides security

Key and ciphertext sizes:
    X25519:
        - Public key: 32 bytes
        - Private key: 32 bytes
    ML-KEM-768:
        - Public key: 1184 bytes
        - Secret key: 2400 bytes
        - Ciphertext: 1088 bytes
    Hybrid:
        - Public key: 1216 bytes (32 + 1184)
        - Private key: 2432 bytes (32 + 2400)
        - Ciphertext: 1120 bytes (32 + 1088)
        - Shared secret: 64 bytes (32 + 32)

Note on key zeroization:
    Python's memory model does not guarantee secure erasure. The secure_keypair
    context manager makes a best-effort attempt to overwrite key material, but
    copies may exist in Python's memory allocator or garbage collector.
"""

from __future__ import annotations

import ctypes
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from qasp.crypto import kem
from qasp.crypto.exceptions import (
    DecapsulationError,
    EncapsulationError,
    InvalidKeyError,
    KeyGenerationError,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

__all__ = [
    "HYBRID_CIPHERTEXT_SIZE",
    "HYBRID_PRIVATE_KEY_SIZE",
    "HYBRID_PUBLIC_KEY_SIZE",
    "HYBRID_SHARED_SECRET_SIZE",
    "X25519_PRIVATE_KEY_SIZE",
    "X25519_PUBLIC_KEY_SIZE",
    "X25519_SHARED_SECRET_SIZE",
    "HybridKeypair",
    "decapsulate",
    "encapsulate",
    "generate_keypair",
    "secure_keypair",
]

# X25519 size constants
X25519_PUBLIC_KEY_SIZE = 32
X25519_PRIVATE_KEY_SIZE = 32
X25519_SHARED_SECRET_SIZE = 32

# Hybrid size constants
HYBRID_PUBLIC_KEY_SIZE = X25519_PUBLIC_KEY_SIZE + kem.ML_KEM_768_PUBLIC_KEY_SIZE  # 1216
HYBRID_PRIVATE_KEY_SIZE = X25519_PRIVATE_KEY_SIZE + kem.ML_KEM_768_SECRET_KEY_SIZE  # 2432
HYBRID_CIPHERTEXT_SIZE = X25519_PUBLIC_KEY_SIZE + kem.ML_KEM_768_CIPHERTEXT_SIZE  # 1120
HYBRID_SHARED_SECRET_SIZE = X25519_SHARED_SECRET_SIZE + kem.ML_KEM_768_SHARED_SECRET_SIZE  # 64


@dataclass(frozen=True)
class HybridKeypair:
    """A hybrid keypair combining X25519 and ML-KEM-768.

    Attributes:
        x25519_public: X25519 public key (32 bytes)
        x25519_private: X25519 private key (32 bytes)
        mlkem_public: ML-KEM-768 public key (1184 bytes)
        mlkem_private: ML-KEM-768 secret key (2400 bytes)
    """

    x25519_public: bytes
    x25519_private: bytes
    mlkem_public: bytes
    mlkem_private: bytes

    def __post_init__(self) -> None:
        """Validate key sizes after initialization."""
        if len(self.x25519_public) != X25519_PUBLIC_KEY_SIZE:
            raise InvalidKeyError(
                f"Invalid X25519 public key size: expected {X25519_PUBLIC_KEY_SIZE}, "
                f"got {len(self.x25519_public)}"
            )
        if len(self.x25519_private) != X25519_PRIVATE_KEY_SIZE:
            raise InvalidKeyError(
                f"Invalid X25519 private key size: expected {X25519_PRIVATE_KEY_SIZE}, "
                f"got {len(self.x25519_private)}"
            )
        if len(self.mlkem_public) != kem.ML_KEM_768_PUBLIC_KEY_SIZE:
            raise InvalidKeyError(
                f"Invalid ML-KEM-768 public key size: expected {kem.ML_KEM_768_PUBLIC_KEY_SIZE}, "
                f"got {len(self.mlkem_public)}"
            )
        if len(self.mlkem_private) != kem.ML_KEM_768_SECRET_KEY_SIZE:
            raise InvalidKeyError(
                f"Invalid ML-KEM-768 secret key size: expected {kem.ML_KEM_768_SECRET_KEY_SIZE}, "
                f"got {len(self.mlkem_private)}"
            )

    @property
    def public_key(self) -> bytes:
        """Return the combined public key (X25519 || ML-KEM-768)."""
        return self.x25519_public + self.mlkem_public

    @property
    def private_key(self) -> bytes:
        """Return the combined private key (X25519 || ML-KEM-768)."""
        return self.x25519_private + self.mlkem_private


def generate_keypair() -> HybridKeypair:
    """Generate a hybrid X25519 + ML-KEM-768 keypair.

    Returns:
        A HybridKeypair instance containing both key components.

    Raises:
        KeyGenerationError: If key generation fails.
    """
    try:
        # Generate X25519 keypair
        x25519_private_key = X25519PrivateKey.generate()
        x25519_public_bytes = x25519_private_key.public_key().public_bytes_raw()
        x25519_private_bytes = x25519_private_key.private_bytes_raw()

        # Generate ML-KEM-768 keypair
        mlkem_public, mlkem_private = kem.generate_keypair()

        return HybridKeypair(
            x25519_public=x25519_public_bytes,
            x25519_private=x25519_private_bytes,
            mlkem_public=mlkem_public,
            mlkem_private=mlkem_private,
        )
    except InvalidKeyError:
        raise
    except Exception as e:
        raise KeyGenerationError(f"Hybrid key generation failed: {e}") from e


def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Encapsulate a shared secret using hybrid key exchange.

    Performs X25519 ECDH and ML-KEM-768 encapsulation, combining
    the results to produce a hybrid ciphertext and shared secret.

    Args:
        public_key: The recipient's combined public key (1216 bytes).
            Format: X25519_pk (32) || ML-KEM_pk (1184)

    Returns:
        Tuple of (ciphertext, shared_secret):
        - ciphertext: 1120 bytes = ephemeral X25519 pk (32) || ML-KEM ct (1088)
        - shared_secret: 64 bytes = X25519_ss (32) || ML-KEM_ss (32)

    Raises:
        InvalidKeyError: If the public key has invalid size.
        EncapsulationError: If encapsulation fails.
    """
    if len(public_key) != HYBRID_PUBLIC_KEY_SIZE:
        raise InvalidKeyError(
            f"Invalid hybrid public key size: expected {HYBRID_PUBLIC_KEY_SIZE}, "
            f"got {len(public_key)}"
        )

    # Split the combined public key
    x25519_peer_public = public_key[:X25519_PUBLIC_KEY_SIZE]
    mlkem_peer_public = public_key[X25519_PUBLIC_KEY_SIZE:]

    try:
        # Generate ephemeral X25519 keypair and perform ECDH
        ephemeral_private = X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key().public_bytes_raw()

        peer_public_key = X25519PublicKey.from_public_bytes(x25519_peer_public)
        x25519_shared_secret = ephemeral_private.exchange(peer_public_key)

        # Encapsulate using ML-KEM-768
        mlkem_ciphertext, mlkem_shared_secret = kem.encapsulate(mlkem_peer_public)

        # Combine results
        ciphertext = ephemeral_public + mlkem_ciphertext
        shared_secret = x25519_shared_secret + mlkem_shared_secret

        return ciphertext, shared_secret
    except (InvalidKeyError, EncapsulationError):
        raise
    except Exception as e:
        raise EncapsulationError(f"Hybrid encapsulation failed: {e}") from e


def decapsulate(keypair: HybridKeypair, ciphertext: bytes) -> bytes:
    """Decapsulate a shared secret using hybrid key exchange.

    Performs X25519 ECDH and ML-KEM-768 decapsulation to recover
    the hybrid shared secret.

    Args:
        keypair: The recipient's hybrid keypair.
        ciphertext: The ciphertext from encapsulation (1120 bytes).
            Format: ephemeral X25519 pk (32) || ML-KEM ct (1088)

    Returns:
        The shared secret (64 bytes): X25519_ss (32) || ML-KEM_ss (32)

    Raises:
        DecapsulationError: If the ciphertext has invalid size or decapsulation fails.
    """
    if len(ciphertext) != HYBRID_CIPHERTEXT_SIZE:
        raise DecapsulationError(
            f"Invalid hybrid ciphertext size: expected {HYBRID_CIPHERTEXT_SIZE}, "
            f"got {len(ciphertext)}"
        )

    # Split the ciphertext
    ephemeral_public = ciphertext[:X25519_PUBLIC_KEY_SIZE]
    mlkem_ciphertext = ciphertext[X25519_PUBLIC_KEY_SIZE:]

    try:
        # Perform X25519 ECDH
        private_key = X25519PrivateKey.from_private_bytes(keypair.x25519_private)
        peer_public_key = X25519PublicKey.from_public_bytes(ephemeral_public)
        x25519_shared_secret = private_key.exchange(peer_public_key)

        # Decapsulate using ML-KEM-768
        mlkem_shared_secret = kem.decapsulate(keypair.mlkem_private, mlkem_ciphertext)

        # Combine shared secrets
        return x25519_shared_secret + mlkem_shared_secret
    except (InvalidKeyError, DecapsulationError):
        raise
    except Exception as e:
        raise DecapsulationError(f"Hybrid decapsulation failed: {e}") from e


@contextmanager
def secure_keypair(keypair: HybridKeypair) -> Iterator[HybridKeypair]:
    """Context manager for secure handling of hybrid keypairs.

    Makes a best-effort attempt to zeroize the private key material when the
    context exits. Due to Python's memory model, this cannot guarantee
    that all copies of the keys are erased.

    Args:
        keypair: The hybrid keypair to protect.

    Yields:
        A copy of the keypair for use within the context.

    Example:
        with secure_keypair(kp) as safe_kp:
            shared_secret = decapsulate(safe_kp, ciphertext)
        # private key material has been zeroized (best effort)
    """
    # Create mutable copies of private keys
    x25519_mutable = bytearray(keypair.x25519_private)
    mlkem_mutable = bytearray(keypair.mlkem_private)

    try:
        # Yield a new keypair with the same values
        yield HybridKeypair(
            x25519_public=keypair.x25519_public,
            x25519_private=bytes(x25519_mutable),
            mlkem_public=keypair.mlkem_public,
            mlkem_private=bytes(mlkem_mutable),
        )
    finally:
        # Best-effort zeroization of both private keys
        for mutable in (x25519_mutable, mlkem_mutable):
            try:
                ctypes.memset(
                    ctypes.addressof(ctypes.c_char.from_buffer(mutable)),
                    0,
                    len(mutable),
                )
            except (ValueError, TypeError):
                # Fallback if ctypes fails
                for i in range(len(mutable)):
                    mutable[i] = 0
