"""ML-DSA-65 digital signatures.

This module provides a wrapper around liboqs for ML-DSA-65 (FIPS 204).
"""

from __future__ import annotations

__all__ = [
    "generate_keypair",
    "sign",
    "verify",
]


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an ML-DSA-65 keypair.

    Returns:
        Tuple of (public_key, secret_key) as bytes.
    """
    raise NotImplementedError("ML-DSA-65 implementation pending")


def sign(secret_key: bytes, message: bytes) -> bytes:
    """Sign a message using the secret key.

    Args:
        secret_key: The signer's secret key.
        message: The message to sign.

    Returns:
        The signature as bytes.
    """
    raise NotImplementedError("ML-DSA-65 implementation pending")


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a signature using the public key.

    Args:
        public_key: The signer's public key.
        message: The original message.
        signature: The signature to verify.

    Returns:
        True if the signature is valid, False otherwise.
    """
    raise NotImplementedError("ML-DSA-65 implementation pending")
