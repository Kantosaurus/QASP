"""AES-256-GCM authenticated encryption.

This module provides AES-256-GCM for authenticated encryption
of protocol messages using the cryptography library.

Parameters:
    - Key size: 32 bytes (256 bits)
    - Nonce size: 12 bytes (96 bits)
    - Tag size: 16 bytes (128 bits)
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from qasp.crypto.exceptions import DecryptionError, EncryptionError, InvalidKeyError

__all__ = [
    "AES_256_KEY_SIZE",
    "AES_GCM_NONCE_SIZE",
    "AES_GCM_TAG_SIZE",
    "decrypt",
    "encrypt",
    "generate_nonce",
]

# AES-256-GCM constants
AES_256_KEY_SIZE = 32  # 256 bits
AES_GCM_NONCE_SIZE = 12  # 96 bits (recommended for GCM)
AES_GCM_TAG_SIZE = 16  # 128 bits


def generate_nonce() -> bytes:
    """Generate a cryptographically random nonce for AES-GCM.

    Returns:
        A random 12-byte nonce.
    """
    return os.urandom(AES_GCM_NONCE_SIZE)


def encrypt(
    key: bytes,
    plaintext: bytes,
    associated_data: bytes = b"",
    nonce: bytes | None = None,
) -> tuple[bytes, bytes]:
    """Encrypt data using AES-256-GCM.

    Args:
        key: The 256-bit encryption key (32 bytes).
        plaintext: The data to encrypt.
        associated_data: Additional data to authenticate but not encrypt.
        nonce: Optional 96-bit nonce (12 bytes). Generated if not provided.

    Returns:
        Tuple of (nonce, ciphertext_with_tag) as bytes.
        The ciphertext includes a 16-byte authentication tag appended.

    Raises:
        InvalidKeyError: If the key has invalid size.
        EncryptionError: If encryption fails.
    """
    if len(key) != AES_256_KEY_SIZE:
        raise InvalidKeyError(
            f"Invalid key size: expected {AES_256_KEY_SIZE}, got {len(key)}"
        )

    if nonce is None:
        nonce = generate_nonce()
    elif len(nonce) != AES_GCM_NONCE_SIZE:
        raise EncryptionError(
            f"Invalid nonce size: expected {AES_GCM_NONCE_SIZE}, got {len(nonce)}"
        )

    try:
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext
    except Exception as e:
        raise EncryptionError(f"AES-256-GCM encryption failed: {e}") from e


def decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    associated_data: bytes = b"",
) -> bytes:
    """Decrypt data using AES-256-GCM.

    Args:
        key: The 256-bit encryption key (32 bytes).
        nonce: The 96-bit nonce used for encryption (12 bytes).
        ciphertext: The ciphertext with authentication tag appended.
        associated_data: Additional data that was authenticated.

    Returns:
        The decrypted plaintext as bytes.

    Raises:
        InvalidKeyError: If the key has invalid size.
        DecryptionError: If decryption fails or authentication fails.
    """
    if len(key) != AES_256_KEY_SIZE:
        raise InvalidKeyError(
            f"Invalid key size: expected {AES_256_KEY_SIZE}, got {len(key)}"
        )

    if len(nonce) != AES_GCM_NONCE_SIZE:
        raise DecryptionError(
            f"Invalid nonce size: expected {AES_GCM_NONCE_SIZE}, got {len(nonce)}"
        )

    if len(ciphertext) < AES_GCM_TAG_SIZE:
        raise DecryptionError(
            f"Ciphertext too short: minimum {AES_GCM_TAG_SIZE} bytes for tag, "
            f"got {len(ciphertext)}"
        )

    try:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
        return plaintext
    except Exception as e:
        raise DecryptionError(f"AES-256-GCM decryption failed: {e}") from e
