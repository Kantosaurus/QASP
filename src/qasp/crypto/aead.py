"""AES-256-GCM authenticated encryption.

This module provides AES-256-GCM for authenticated encryption
of protocol messages.
"""

from __future__ import annotations

__all__ = [
    "decrypt",
    "encrypt",
]


def encrypt(
    key: bytes,
    plaintext: bytes,
    associated_data: bytes = b"",
    nonce: bytes | None = None,
) -> tuple[bytes, bytes]:
    """Encrypt data using AES-256-GCM.

    Args:
        key: The 256-bit encryption key.
        plaintext: The data to encrypt.
        associated_data: Additional data to authenticate.
        nonce: Optional 96-bit nonce (generated if not provided).

    Returns:
        Tuple of (nonce, ciphertext_with_tag) as bytes.
    """
    raise NotImplementedError("AES-256-GCM implementation pending")


def decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    associated_data: bytes = b"",
) -> bytes:
    """Decrypt data using AES-256-GCM.

    Args:
        key: The 256-bit encryption key.
        nonce: The 96-bit nonce used for encryption.
        ciphertext: The ciphertext with authentication tag.
        associated_data: Additional data that was authenticated.

    Returns:
        The decrypted plaintext as bytes.

    Raises:
        ValueError: If authentication fails.
    """
    raise NotImplementedError("AES-256-GCM implementation pending")
