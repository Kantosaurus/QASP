"""HKDF-SHA-384 key derivation.

This module provides HKDF-SHA-384 for deriving session keys
from shared secrets, using the cryptography library.

HKDF (HMAC-based Extract-and-Expand Key Derivation Function) is defined
in RFC 5869. SHA-384 provides 192-bit security.

Constants:
    - Hash output size: 48 bytes (384 bits)
    - Maximum output length: 255 * 48 = 12,240 bytes
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

from qasp.crypto.exceptions import KeyDerivationError

__all__ = [
    "HKDF_SHA384_HASH_SIZE",
    "HKDF_SHA384_MAX_OUTPUT",
    "QASP_INFO_PREFIX",
    "QASP_SESSION_KEY_SIZE",
    "derive_key",
    "derive_qasp_session_key",
    "expand_key",
    "extract_key",
]

# HKDF-SHA-384 constants
HKDF_SHA384_HASH_SIZE = 48  # SHA-384 output: 384 bits
HKDF_SHA384_MAX_OUTPUT = 255 * HKDF_SHA384_HASH_SIZE  # Maximum HKDF output

# QASP-specific constants
QASP_INFO_PREFIX = b"QASP-v1"
QASP_SESSION_KEY_SIZE = 32  # AES-256 key size


def derive_key(
    input_key_material: bytes,
    salt: bytes | None = None,
    info: bytes = b"",
    length: int = HKDF_SHA384_HASH_SIZE,
) -> bytes:
    """Derive a key using HKDF-SHA-384 (extract-then-expand).

    This performs both the extract and expand phases of HKDF.

    Args:
        input_key_material: The input keying material (arbitrary length).
        salt: Optional salt value. If None, uses a zero-filled salt.
        info: Optional context and application-specific info.
        length: Desired output length in bytes (max 12,240).

    Returns:
        The derived key as bytes.

    Raises:
        KeyDerivationError: If derivation fails or parameters are invalid.
    """
    if length < 1 or length > HKDF_SHA384_MAX_OUTPUT:
        raise KeyDerivationError(
            f"Invalid output length: must be 1-{HKDF_SHA384_MAX_OUTPUT}, got {length}"
        )

    try:
        hkdf = HKDF(
            algorithm=hashes.SHA384(),
            length=length,
            salt=salt,
            info=info,
        )
        return hkdf.derive(input_key_material)
    except Exception as e:
        raise KeyDerivationError(f"HKDF-SHA-384 derivation failed: {e}") from e


def extract_key(
    input_key_material: bytes,
    salt: bytes | None = None,
) -> bytes:
    """Extract a pseudorandom key using HKDF-SHA-384.

    This performs only the extract phase, producing a fixed-length PRK.

    Args:
        input_key_material: The input keying material.
        salt: Optional salt value. If None, uses a zero-filled salt.

    Returns:
        The pseudorandom key (48 bytes).

    Raises:
        KeyDerivationError: If extraction fails.
    """
    try:
        # Use HKDF with empty info and hash-length output for extract
        hkdf = HKDF(
            algorithm=hashes.SHA384(),
            length=HKDF_SHA384_HASH_SIZE,
            salt=salt,
            info=b"",
        )
        return hkdf.derive(input_key_material)
    except Exception as e:
        raise KeyDerivationError(f"HKDF-SHA-384 extract failed: {e}") from e


def expand_key(
    prk: bytes,
    info: bytes = b"",
    length: int = HKDF_SHA384_HASH_SIZE,
) -> bytes:
    """Expand a pseudorandom key using HKDF-SHA-384.

    This performs only the expand phase, producing output of the desired length.

    Args:
        prk: The pseudorandom key from extract (should be >= 48 bytes).
        info: Optional context and application-specific info.
        length: Desired output length in bytes (max 12,240).

    Returns:
        The expanded key as bytes.

    Raises:
        KeyDerivationError: If expansion fails or parameters are invalid.
    """
    if length < 1 or length > HKDF_SHA384_MAX_OUTPUT:
        raise KeyDerivationError(
            f"Invalid output length: must be 1-{HKDF_SHA384_MAX_OUTPUT}, got {length}"
        )

    if len(prk) < HKDF_SHA384_HASH_SIZE:
        raise KeyDerivationError(
            f"PRK too short: expected >= {HKDF_SHA384_HASH_SIZE}, got {len(prk)}"
        )

    try:
        hkdf_expand = HKDFExpand(
            algorithm=hashes.SHA384(),
            length=length,
            info=info,
        )
        return hkdf_expand.derive(prk)
    except Exception as e:
        raise KeyDerivationError(f"HKDF-SHA-384 expand failed: {e}") from e


def derive_qasp_session_key(
    mlkem_shared_secret: bytes,
    x25519_shared_secret: bytes,
    client_nonce: bytes,
    server_nonce: bytes,
    length: int = QASP_SESSION_KEY_SIZE,
) -> bytes:
    """Derive a QASP session key from hybrid shared secrets.

    Implements the QASP key derivation:
        SS = HKDF(ML-KEM_ss || X25519_ss, Nc || Ns, "QASP-v1")

    The shared secrets are concatenated as input keying material,
    the nonces form the salt, and "QASP-v1" is the info.

    Args:
        mlkem_shared_secret: The ML-KEM-768 shared secret (32 bytes).
        x25519_shared_secret: The X25519 shared secret (32 bytes).
        client_nonce: Client's random nonce (typically 16 bytes).
        server_nonce: Server's random nonce (typically 16 bytes).
        length: Desired session key length (default: 32 for AES-256).

    Returns:
        The derived session key.

    Raises:
        KeyDerivationError: If derivation fails or parameters are invalid.
    """
    if len(mlkem_shared_secret) != 32:
        raise KeyDerivationError(
            f"Invalid ML-KEM shared secret size: expected 32, got {len(mlkem_shared_secret)}"
        )

    if len(x25519_shared_secret) != 32:
        raise KeyDerivationError(
            f"Invalid X25519 shared secret size: expected 32, got {len(x25519_shared_secret)}"
        )

    # Concatenate shared secrets as IKM
    ikm = mlkem_shared_secret + x25519_shared_secret

    # Concatenate nonces as salt
    salt = client_nonce + server_nonce

    return derive_key(
        input_key_material=ikm,
        salt=salt,
        info=QASP_INFO_PREFIX,
        length=length,
    )
