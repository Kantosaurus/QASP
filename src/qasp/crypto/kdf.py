"""HKDF-SHA-384 key derivation.

This module provides HKDF-SHA-384 for deriving session keys
from shared secrets.
"""

from __future__ import annotations

__all__ = [
    "derive_key",
    "expand_key",
]


def derive_key(
    input_key_material: bytes,
    salt: bytes | None = None,
    info: bytes = b"",
    length: int = 48,
) -> bytes:
    """Derive a key using HKDF-SHA-384.

    Args:
        input_key_material: The input keying material.
        salt: Optional salt value.
        info: Optional context info.
        length: Desired output length in bytes.

    Returns:
        The derived key as bytes.
    """
    raise NotImplementedError("HKDF implementation pending")


def expand_key(
    prk: bytes,
    info: bytes = b"",
    length: int = 48,
) -> bytes:
    """Expand a pseudorandom key using HKDF-SHA-384.

    Args:
        prk: The pseudorandom key from extract.
        info: Optional context info.
        length: Desired output length in bytes.

    Returns:
        The expanded key as bytes.
    """
    raise NotImplementedError("HKDF implementation pending")
