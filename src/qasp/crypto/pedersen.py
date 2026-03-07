"""Pedersen commitments over Ed25519 for Bulletproofs.

Provides hiding and binding commitments: C = v*G + r*H
where G is the Ed25519 base point and H is an independent generator.
"""
from __future__ import annotations

import secrets

from qasp.crypto.ec import (
    BASE_POINT,
    IDENTITY,
    L,
    Point,
    hash_to_point,
    point_add,
    point_encode,
    point_eq,
    scalar_mult,
)

__all__ = [
    "G",
    "H",
    "commit",
    "open_commitment",
    "random_scalar",
    "vector_commit",
]

# Generators
G: Point = BASE_POINT
H: Point = hash_to_point(b"qasp-pedersen-H")


def random_scalar() -> int:
    """Generate a random scalar in [1, L-1]."""
    while True:
        r = int.from_bytes(secrets.token_bytes(32), "little") % L
        if r != 0:
            return r


def commit(value: int, blinding: int) -> bytes:
    """Create a Pedersen commitment C = value*G + blinding*H.

    Args:
        value: The value to commit to.
        blinding: The blinding factor.

    Returns:
        32-byte encoded commitment point.
    """
    c = point_add(scalar_mult(value, G), scalar_mult(blinding, H))
    return point_encode(c)


def open_commitment(commitment: bytes, value: int, blinding: int) -> bool:
    """Verify a Pedersen commitment opening.

    Args:
        commitment: The 32-byte commitment.
        value: The claimed value.
        blinding: The claimed blinding factor.

    Returns:
        True if the commitment opens correctly.
    """
    from qasp.crypto.ec import point_decode

    c_point = point_decode(commitment)
    expected = point_add(scalar_mult(value, G), scalar_mult(blinding, H))
    return point_eq(c_point, expected)


def vector_commit(
    values: list[int],
    blindings: list[int],
    g_vec: list[Point],
    h_vec: list[Point],
) -> Point:
    """Compute a vector Pedersen commitment.

    C = sum(values[i] * g_vec[i]) + sum(blindings[i] * h_vec[i])

    Args:
        values: Vector of values.
        blindings: Vector of blinding factors.
        g_vec: Generator vector for values.
        h_vec: Generator vector for blindings.

    Returns:
        Commitment point.
    """
    result = IDENTITY
    for v, g in zip(values, g_vec):
        result = point_add(result, scalar_mult(v % L, g))
    for b, h in zip(blindings, h_vec):
        result = point_add(result, scalar_mult(b % L, h))
    return result
