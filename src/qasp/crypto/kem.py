"""ML-KEM-768 key encapsulation mechanism.

This module provides a wrapper around liboqs for ML-KEM-768 (FIPS 203).
"""

from __future__ import annotations

__all__ = [
    "decapsulate",
    "encapsulate",
    "generate_keypair",
]


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an ML-KEM-768 keypair.

    Returns:
        Tuple of (public_key, secret_key) as bytes.
    """
    raise NotImplementedError("ML-KEM-768 implementation pending")


def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Encapsulate a shared secret using the public key.

    Args:
        public_key: The recipient's public key.

    Returns:
        Tuple of (ciphertext, shared_secret) as bytes.
    """
    raise NotImplementedError("ML-KEM-768 implementation pending")


def decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """Decapsulate a shared secret using the secret key.

    Args:
        secret_key: The recipient's secret key.
        ciphertext: The ciphertext from encapsulation.

    Returns:
        The shared secret as bytes.
    """
    raise NotImplementedError("ML-KEM-768 implementation pending")
