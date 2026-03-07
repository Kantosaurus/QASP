"""Tests for Ed25519 curve arithmetic."""
from __future__ import annotations

from qasp.crypto.ec import (
    BASE_POINT,
    IDENTITY,
    L,
    P,
    hash_to_point,
    point_add,
    point_decode,
    point_double,
    point_encode,
    point_eq,
    scalar_mult,
)


class TestPointArithmetic:
    def test_identity(self) -> None:
        assert point_eq(point_add(BASE_POINT, IDENTITY), BASE_POINT)

    def test_double_equals_add(self) -> None:
        doubled = point_double(BASE_POINT)
        added = point_add(BASE_POINT, BASE_POINT)
        assert point_eq(doubled, added)

    def test_group_order(self) -> None:
        result = scalar_mult(L, BASE_POINT)
        assert point_eq(result, IDENTITY)

    def test_encode_decode_roundtrip(self) -> None:
        p = scalar_mult(42, BASE_POINT)
        encoded = point_encode(p)
        assert len(encoded) == 32
        decoded = point_decode(encoded)
        assert point_eq(p, decoded)

    def test_identity_encode_decode(self) -> None:
        encoded = point_encode(IDENTITY)
        decoded = point_decode(encoded)
        assert point_eq(decoded, IDENTITY)

    def test_scalar_mult_associative(self) -> None:
        p1 = scalar_mult(3 * 7, BASE_POINT)
        p2 = scalar_mult(7, scalar_mult(3, BASE_POINT))
        assert point_eq(p1, p2)

    def test_hash_to_point(self) -> None:
        p1 = hash_to_point(b"test-domain", b"data1")
        p2 = hash_to_point(b"test-domain", b"data2")
        assert not point_eq(p1, p2)
        assert not point_eq(p1, IDENTITY)

    def test_hash_to_point_deterministic(self) -> None:
        p1 = hash_to_point(b"domain", b"data")
        p2 = hash_to_point(b"domain", b"data")
        assert point_eq(p1, p2)
