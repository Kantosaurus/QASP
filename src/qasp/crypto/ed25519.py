"""Ed25519 digital signatures.

This module provides a wrapper around the cryptography library for Ed25519
signatures, used in the hybrid transition cipher suite alongside ML-DSA-65.

Key and signature sizes:
    - Public key: 32 bytes
    - Secret key: 32 bytes (seed)
    - Signature: 64 bytes
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from qasp.crypto.exceptions import (
    InvalidKeyError,
    InvalidSignatureError,
    KeyGenerationError,
    SignatureError,
    VerificationError,
)

__all__ = [
    "ED25519_PUBLIC_KEY_SIZE",
    "ED25519_SECRET_KEY_SIZE",
    "ED25519_SIGNATURE_SIZE",
    "generate_keypair",
    "sign",
    "verify",
]

ED25519_PUBLIC_KEY_SIZE = 32
ED25519_SECRET_KEY_SIZE = 32
ED25519_SIGNATURE_SIZE = 64


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an Ed25519 keypair.

    Returns:
        Tuple of (public_key, secret_key) as bytes.
        - public_key: 32 bytes
        - secret_key: 32 bytes (seed)

    Raises:
        KeyGenerationError: If key generation fails.
    """
    try:
        private_key = Ed25519PrivateKey.generate()
        public_bytes = private_key.public_key().public_bytes_raw()
        secret_bytes = private_key.private_bytes_raw()
        return bytes(public_bytes), bytes(secret_bytes)
    except Exception as e:
        raise KeyGenerationError(f"Ed25519 key generation failed: {e}") from e


def sign(secret_key: bytes, message: bytes) -> bytes:
    """Sign a message using the secret key.

    Args:
        secret_key: The signer's secret key (32 bytes seed).
        message: The message to sign (arbitrary length).

    Returns:
        The signature as bytes (64 bytes).

    Raises:
        InvalidKeyError: If the secret key has invalid size.
        SignatureError: If signing fails.
    """
    if len(secret_key) != ED25519_SECRET_KEY_SIZE:
        raise InvalidKeyError(
            f"Invalid secret key size: expected {ED25519_SECRET_KEY_SIZE}, "
            f"got {len(secret_key)}"
        )

    try:
        private_key = Ed25519PrivateKey.from_private_bytes(secret_key)
        signature = private_key.sign(message)
        return bytes(signature)
    except InvalidKeyError:
        raise
    except Exception as e:
        raise SignatureError(f"Ed25519 signing failed: {e}") from e


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a signature using the public key.

    Args:
        public_key: The signer's public key (32 bytes).
        message: The original message.
        signature: The signature to verify (64 bytes).

    Returns:
        True if the signature is valid.

    Raises:
        InvalidKeyError: If the public key has invalid size.
        InvalidSignatureError: If the signature is invalid.
        VerificationError: If verification fails due to an error.
    """
    if len(public_key) != ED25519_PUBLIC_KEY_SIZE:
        raise InvalidKeyError(
            f"Invalid public key size: expected {ED25519_PUBLIC_KEY_SIZE}, "
            f"got {len(public_key)}"
        )

    if len(signature) != ED25519_SIGNATURE_SIZE:
        raise InvalidSignatureError(
            f"Invalid signature size: expected {ED25519_SIGNATURE_SIZE}, "
            f"got {len(signature)}"
        )

    try:
        pub = Ed25519PublicKey.from_public_bytes(public_key)
        pub.verify(signature, message)
        return True
    except InvalidSignatureError:
        raise
    except Exception as e:
        if "invalid signature" in str(e).lower() or "signature" in str(e).lower():
            raise InvalidSignatureError("Ed25519 signature verification failed") from e
        raise VerificationError(f"Ed25519 verification error: {e}") from e
