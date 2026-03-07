"""Tests for Pedersen commitments."""
from __future__ import annotations

from qasp.crypto.ec import IDENTITY, L, point_add, point_decode, point_encode, point_eq
from qasp.crypto.pedersen import G, H, commit, open_commitment, random_scalar, vector_commit


class TestPedersenCommitment:
    def test_commit_and_open(self) -> None:
        v, r = 42, random_scalar()
        c = commit(v, r)
        assert open_commitment(c, v, r)

    def test_wrong_value_fails(self) -> None:
        v, r = 42, random_scalar()
        c = commit(v, r)
        assert not open_commitment(c, 43, r)

    def test_wrong_blinding_fails(self) -> None:
        v, r = 42, random_scalar()
        c = commit(v, r)
        assert not open_commitment(c, v, r + 1)

    def test_homomorphic_addition(self) -> None:
        v1, r1 = 10, random_scalar()
        v2, r2 = 20, random_scalar()
        c1 = point_decode(commit(v1, r1))
        c2 = point_decode(commit(v2, r2))
        c_sum = point_add(c1, c2)
        assert open_commitment(point_encode(c_sum), v1 + v2, (r1 + r2) % L)

    def test_random_scalar_in_range(self) -> None:
        for _ in range(10):
            s = random_scalar()
            assert 0 < s < L

    def test_vector_commit(self) -> None:
        from qasp.crypto.ec import hash_to_point

        g_vec = [hash_to_point(b"g", i) for i in range(4)]
        h_vec = [hash_to_point(b"h", i) for i in range(4)]
        values = [1, 2, 3, 4]
        blindings = [random_scalar() for _ in range(4)]
        result = vector_commit(values, blindings, g_vec, h_vec)
        assert not point_eq(result, IDENTITY)
