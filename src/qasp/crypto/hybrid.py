"""Hybrid X25519 + ML-KEM-768 key exchange.

This module implements hybrid key exchange combining classical X25519
with post-quantum ML-KEM-768 for defense in depth.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "HybridKeypair",
    "decapsulate",
    "encapsulate",
    "generate_keypair",
]


@dataclass(frozen=True)
class HybridKeypair:
    """A hybrid keypair combining X25519 and ML-KEM-768."""

    x25519_public: bytes
    x25519_private: bytes
    mlkem_public: bytes
    mlkem_private: bytes

    @property
    def public_key(self) -> bytes:
        """Return the combined public key."""
        return self.x25519_public + self.mlkem_public

    @property
    def private_key(self) -> bytes:
        """Return the combined private key."""
        return self.x25519_private + self.mlkem_private


def generate_keypair() -> HybridKeypair:
    """Generate a hybrid X25519 + ML-KEM-768 keypair.

    Returns:
        A HybridKeypair instance.
    """
    raise NotImplementedError("Hybrid key exchange implementation pending")


def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Encapsulate a shared secret using hybrid key exchange.

    Args:
        public_key: The recipient's combined public key.

    Returns:
        Tuple of (ciphertext, shared_secret) as bytes.
    """
    raise NotImplementedError("Hybrid key exchange implementation pending")


def decapsulate(keypair: HybridKeypair, ciphertext: bytes) -> bytes:
    """Decapsulate a shared secret using hybrid key exchange.

    Args:
        keypair: The recipient's hybrid keypair.
        ciphertext: The ciphertext from encapsulation.

    Returns:
        The shared secret as bytes.
    """
    raise NotImplementedError("Hybrid key exchange implementation pending")
