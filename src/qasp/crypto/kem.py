"""ML-KEM-768 key encapsulation mechanism.

This module provides a wrapper around liboqs for ML-KEM-768 (FIPS 203).
ML-KEM-768 provides NIST Security Level 3 (~192-bit classical security).

Key sizes:
    - Public key: 1184 bytes
    - Secret key: 2400 bytes
    - Ciphertext: 1088 bytes
    - Shared secret: 32 bytes

Note on key zeroization:
    Python's memory model does not guarantee secure erasure. The secure_secret_key
    context manager makes a best-effort attempt to overwrite key material, but
    copies may exist in Python's memory allocator or garbage collector.
"""

from __future__ import annotations

import ctypes
from contextlib import contextmanager
from typing import TYPE_CHECKING

import oqs

from qasp.crypto.exceptions import (
    DecapsulationError,
    EncapsulationError,
    InvalidKeyError,
    KeyGenerationError,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

__all__ = [
    "ML_KEM_768_CIPHERTEXT_SIZE",
    "ML_KEM_768_PUBLIC_KEY_SIZE",
    "ML_KEM_768_SECRET_KEY_SIZE",
    "ML_KEM_768_SHARED_SECRET_SIZE",
    "decapsulate",
    "encapsulate",
    "generate_keypair",
    "secure_secret_key",
]

# ML-KEM-768 size constants (FIPS 203)
ML_KEM_768_PUBLIC_KEY_SIZE = 1184
ML_KEM_768_SECRET_KEY_SIZE = 2400
ML_KEM_768_CIPHERTEXT_SIZE = 1088
ML_KEM_768_SHARED_SECRET_SIZE = 32

_ALGORITHM = "ML-KEM-768"


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an ML-KEM-768 keypair.

    Returns:
        Tuple of (public_key, secret_key) as bytes.
        - public_key: 1184 bytes
        - secret_key: 2400 bytes

    Raises:
        KeyGenerationError: If key generation fails.
    """
    try:
        kem = oqs.KeyEncapsulation(_ALGORITHM)
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
        return bytes(public_key), bytes(secret_key)
    except Exception as e:
        raise KeyGenerationError(f"ML-KEM-768 key generation failed: {e}") from e


def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Encapsulate a shared secret using the public key.

    Args:
        public_key: The recipient's public key (1184 bytes).

    Returns:
        Tuple of (ciphertext, shared_secret) as bytes.
        - ciphertext: 1088 bytes
        - shared_secret: 32 bytes

    Raises:
        InvalidKeyError: If the public key has invalid size.
        EncapsulationError: If encapsulation fails.
    """
    if len(public_key) != ML_KEM_768_PUBLIC_KEY_SIZE:
        raise InvalidKeyError(
            f"Invalid public key size: expected {ML_KEM_768_PUBLIC_KEY_SIZE}, "
            f"got {len(public_key)}"
        )

    try:
        kem = oqs.KeyEncapsulation(_ALGORITHM)
        ciphertext, shared_secret = kem.encap_secret(public_key)
        return bytes(ciphertext), bytes(shared_secret)
    except Exception as e:
        raise EncapsulationError(f"ML-KEM-768 encapsulation failed: {e}") from e


def decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """Decapsulate a shared secret using the secret key.

    Args:
        secret_key: The recipient's secret key (2400 bytes).
        ciphertext: The ciphertext from encapsulation (1088 bytes).

    Returns:
        The shared secret as bytes (32 bytes).

    Raises:
        InvalidKeyError: If the secret key has invalid size.
        DecapsulationError: If the ciphertext has invalid size or decapsulation fails.
    """
    if len(secret_key) != ML_KEM_768_SECRET_KEY_SIZE:
        raise InvalidKeyError(
            f"Invalid secret key size: expected {ML_KEM_768_SECRET_KEY_SIZE}, "
            f"got {len(secret_key)}"
        )

    if len(ciphertext) != ML_KEM_768_CIPHERTEXT_SIZE:
        raise DecapsulationError(
            f"Invalid ciphertext size: expected {ML_KEM_768_CIPHERTEXT_SIZE}, "
            f"got {len(ciphertext)}"
        )

    try:
        kem = oqs.KeyEncapsulation(_ALGORITHM, secret_key)
        shared_secret = kem.decap_secret(ciphertext)
        return bytes(shared_secret)
    except Exception as e:
        raise DecapsulationError(f"ML-KEM-768 decapsulation failed: {e}") from e


@contextmanager
def secure_secret_key(secret_key: bytes) -> Iterator[bytes]:
    """Context manager for secure handling of secret keys.

    Makes a best-effort attempt to zeroize the key material when the
    context exits. Due to Python's memory model, this cannot guarantee
    that all copies of the key are erased.

    Args:
        secret_key: The secret key to protect.

    Yields:
        The secret key bytes for use within the context.

    Example:
        with secure_secret_key(sk) as key:
            shared_secret = decapsulate(key, ciphertext)
        # key material has been zeroized (best effort)
    """
    mutable = bytearray(secret_key)
    try:
        yield bytes(mutable)
    finally:
        # Best-effort zeroization
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
