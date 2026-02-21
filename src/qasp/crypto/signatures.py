"""ML-DSA-65 digital signatures.

This module provides a wrapper around liboqs for ML-DSA-65 (FIPS 204).
ML-DSA-65 provides NIST Security Level 3 (~192-bit classical security).

Key and signature sizes:
    - Public key: 1952 bytes
    - Secret key: 4032 bytes
    - Signature: 3309 bytes (maximum)

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
    InvalidKeyError,
    InvalidSignatureError,
    KeyGenerationError,
    SignatureError,
    VerificationError,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

__all__ = [
    "ML_DSA_65_PUBLIC_KEY_SIZE",
    "ML_DSA_65_SECRET_KEY_SIZE",
    "ML_DSA_65_SIGNATURE_SIZE",
    "generate_keypair",
    "secure_secret_key",
    "sign",
    "verify",
]

# ML-DSA-65 size constants (FIPS 204)
ML_DSA_65_PUBLIC_KEY_SIZE = 1952
ML_DSA_65_SECRET_KEY_SIZE = 4032
ML_DSA_65_SIGNATURE_SIZE = 3309  # Maximum signature size

_ALGORITHM = "ML-DSA-65"


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an ML-DSA-65 keypair.

    Returns:
        Tuple of (public_key, secret_key) as bytes.
        - public_key: 1952 bytes
        - secret_key: 4032 bytes

    Raises:
        KeyGenerationError: If key generation fails.
    """
    try:
        sig = oqs.Signature(_ALGORITHM)
        public_key = sig.generate_keypair()
        secret_key = sig.export_secret_key()
        return bytes(public_key), bytes(secret_key)
    except Exception as e:
        raise KeyGenerationError(f"ML-DSA-65 key generation failed: {e}") from e


def sign(secret_key: bytes, message: bytes) -> bytes:
    """Sign a message using the secret key.

    Args:
        secret_key: The signer's secret key (4032 bytes).
        message: The message to sign (arbitrary length).

    Returns:
        The signature as bytes (up to 3309 bytes).

    Raises:
        InvalidKeyError: If the secret key has invalid size.
        SignatureError: If signing fails.
    """
    if len(secret_key) != ML_DSA_65_SECRET_KEY_SIZE:
        raise InvalidKeyError(
            f"Invalid secret key size: expected {ML_DSA_65_SECRET_KEY_SIZE}, "
            f"got {len(secret_key)}"
        )

    try:
        sig = oqs.Signature(_ALGORITHM, secret_key)
        signature = sig.sign(message)
        return bytes(signature)
    except Exception as e:
        raise SignatureError(f"ML-DSA-65 signing failed: {e}") from e


def verify(
    public_key: bytes,
    message: bytes,
    signature: bytes,
    context: bytes | None = None,
) -> bool:
    """Verify a signature using the public key.

    Args:
        public_key: The signer's public key (1952 bytes).
        message: The original message.
        signature: The signature to verify.
        context: Optional FIPS 204 context string for the external
            signing interface.  When *None* (the default), liboqs
            verifies with an empty context.

    Returns:
        True if the signature is valid.

    Raises:
        InvalidKeyError: If the public key has invalid size.
        InvalidSignatureError: If the signature is invalid.
        VerificationError: If verification fails due to an error.
    """
    if len(public_key) != ML_DSA_65_PUBLIC_KEY_SIZE:
        raise InvalidKeyError(
            f"Invalid public key size: expected {ML_DSA_65_PUBLIC_KEY_SIZE}, "
            f"got {len(public_key)}"
        )

    if len(signature) > ML_DSA_65_SIGNATURE_SIZE:
        raise InvalidSignatureError(
            f"Invalid signature size: maximum {ML_DSA_65_SIGNATURE_SIZE}, "
            f"got {len(signature)}"
        )

    try:
        sig = oqs.Signature(_ALGORITHM)
        if context is not None:
            is_valid = sig.verify_with_ctx_str(
                message, signature, context, public_key
            )
        else:
            is_valid = sig.verify(message, signature, public_key)
        if not is_valid:
            raise InvalidSignatureError("Signature verification failed")
        return True
    except InvalidSignatureError:
        raise
    except Exception as e:
        raise VerificationError(f"ML-DSA-65 verification error: {e}") from e


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
            signature = sign(key, message)
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
