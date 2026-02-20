"""CBOR encoding and decoding.

This module provides CBOR serialization for QASP protocol messages.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "decode",
    "encode",
]


def encode(obj: Any) -> bytes:
    """Encode an object to CBOR.

    Args:
        obj: The object to encode.

    Returns:
        The CBOR-encoded bytes.
    """
    raise NotImplementedError("CBOR encoding implementation pending")


def decode(data: bytes) -> Any:
    """Decode CBOR data to an object.

    Args:
        data: The CBOR-encoded bytes.

    Returns:
        The decoded object.
    """
    raise NotImplementedError("CBOR decoding implementation pending")
