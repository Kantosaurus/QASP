"""Ed25519 elliptic curve arithmetic for Bulletproofs.

Pure-Python reference implementation of Ed25519 point operations
using extended coordinates (X, Y, Z, T) where x = X/Z, y = Y/Z, T = X*Y/Z.
"""
from __future__ import annotations

import hashlib
import struct

__all__ = [
    "BASE_POINT",
    "IDENTITY",
    "L",
    "P",
    "Point",
    "hash_to_point",
    "point_add",
    "point_decode",
    "point_double",
    "point_encode",
    "point_eq",
    "scalar_mult",
]

# Ed25519 constants
P = 2**255 - 19  # Field prime
D = -121665 * pow(121666, P - 2, P) % P  # Curve parameter d
L = 2**252 + 27742317777372353535851937790883648493  # Group order (subgroup)

# Type alias for extended coordinates (X, Y, Z, T)
Point = tuple[int, int, int, int]

# Identity point in extended coordinates
IDENTITY: Point = (0, 1, 1, 0)


def _mod_inv(a: int, p: int = P) -> int:
    """Modular inverse using Fermat's little theorem."""
    return pow(a, p - 2, p)


def point_add(p1: Point, p2: Point) -> Point:
    """Add two points in extended coordinates.

    Uses the unified addition formula for twisted Edwards curves.
    """
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2

    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * t2 * D % P
    d = 2 * z1 * z2 % P
    e = b - a
    f = d - c
    g = d + c
    h = b + a

    x3 = e * f % P
    y3 = g * h % P
    t3 = e * h % P
    z3 = f * g % P

    return (x3, y3, z3, t3)


def point_double(p: Point) -> Point:
    """Double a point in extended coordinates."""
    x1, y1, z1, _t1 = p

    a = x1 * x1 % P
    b = y1 * y1 % P
    c = 2 * z1 * z1 % P
    h = a + b
    e = h - (x1 + y1) * (x1 + y1) % P
    e = e % P
    g = a - b
    f = c + g

    x3 = e * f % P
    y3 = g * h % P
    t3 = e * h % P
    z3 = f * g % P

    return (x3, y3, z3, t3)


def scalar_mult(n: int, p: Point) -> Point:
    """Scalar multiplication using double-and-add."""
    n = n % L
    result = IDENTITY
    current = p
    while n > 0:
        if n & 1:
            result = point_add(result, current)
        current = point_double(current)
        n >>= 1
    return result


def point_encode(p: Point) -> bytes:
    """Encode a point to 32 bytes (RFC 8032 format)."""
    x, y, z, _t = p
    zi = _mod_inv(z)
    x_norm = x * zi % P
    y_norm = y * zi % P

    # Encode y coordinate in little-endian, set high bit of last byte if x is odd
    encoded = y_norm.to_bytes(32, "little")
    encoded_list = list(encoded)
    if x_norm & 1:
        encoded_list[31] |= 0x80
    return bytes(encoded_list)


def _recover_x(y: int, sign: int) -> int:
    """Recover x coordinate from y and sign bit."""
    y2 = y * y % P
    x2 = (y2 - 1) * _mod_inv(D * y2 + 1) % P

    if x2 == 0:
        if sign:
            raise ValueError("Invalid point: x=0 but sign bit set")
        return 0

    # Compute square root using Tonelli-Shanks for p == 5 (mod 8)
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        # Try the other root
        I = pow(2, (P - 1) // 4, P)  # sqrt(-1)
        x = x * I % P
    if (x * x - x2) % P != 0:
        raise ValueError("Invalid point: no square root exists")

    if x & 1 != sign:
        x = P - x

    return x


def point_decode(data: bytes) -> Point:
    """Decode 32 bytes to a point (RFC 8032 format)."""
    if len(data) != 32:
        raise ValueError(f"Point encoding must be 32 bytes, got {len(data)}")

    # Extract y and sign of x
    y = int.from_bytes(data, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1  # Clear high bit

    if y >= P:
        raise ValueError("Invalid point: y >= P")

    x = _recover_x(y, sign)

    return (x, y, 1, x * y % P)


def point_eq(p1: Point, p2: Point) -> bool:
    """Compare two points in projective coordinates."""
    x1, y1, z1, _t1 = p1
    x2, y2, z2, _t2 = p2

    # x1/z1 == x2/z2 => x1*z2 == x2*z1
    # y1/z1 == y2/z2 => y1*z2 == y2*z1
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def hash_to_point(domain_sep: bytes, *data: bytes | int) -> Point:
    """Hash to an independent Ed25519 point.

    Uses try-and-increment: hash domain_sep||data to get y candidates,
    try to lift to a valid point, and clear cofactor.
    """
    counter = 0
    while True:
        h = hashlib.sha512()
        h.update(domain_sep)
        for d in data:
            if isinstance(d, int):
                h.update(d.to_bytes(8, "little"))
            else:
                h.update(d)
        h.update(counter.to_bytes(4, "little"))
        digest = h.digest()

        # Use first 32 bytes as y candidate
        y = int.from_bytes(digest[:32], "little") % P

        # Try to recover x
        y2 = y * y % P
        x2 = (y2 - 1) * _mod_inv(D * y2 + 1) % P

        # Check if x2 is a quadratic residue
        x = pow(x2, (P + 3) // 8, P)
        if (x * x - x2) % P != 0:
            I = pow(2, (P - 1) // 4, P)
            x = x * I % P

        if (x * x - x2) % P == 0:
            # Valid point found, use even x
            if x & 1:
                x = P - x
            point = (x, y, 1, x * y % P)
            # Clear cofactor (multiply by 8 for Ed25519)
            result = scalar_mult(8, point)
            if not point_eq(result, IDENTITY):
                return result

        counter += 1
        if counter > 256:
            raise RuntimeError("hash_to_point failed after 256 attempts")


# Compute base point from RFC 8032
# The base point has y = 4/5 mod P
_BY = 4 * _mod_inv(5) % P
_BX = _recover_x(_BY, 0)
BASE_POINT: Point = (_BX, _BY, 1, _BX * _BY % P)
