"""Tests for Shamir secret sharing over GF(q)."""

from __future__ import annotations

import secrets

import pytest

from qasp.crypto.dilithium import N, Q
from qasp.crypto.shamir import (
    PolyShare,
    PolyVecShare,
    reconstruct_poly,
    reconstruct_polyvec,
    reconstruct_scalar,
    share_poly,
    share_polyvec,
    share_scalar,
)


class TestScalarSharing:
    def test_roundtrip_2_of_3(self):
        secret = secrets.randbelow(Q)
        shares = share_scalar(secret, threshold=2, num_shares=3)
        assert len(shares) == 3
        # Any 2 shares should reconstruct
        for pair in [(0, 1), (0, 2), (1, 2)]:
            result = reconstruct_scalar([shares[pair[0]], shares[pair[1]]])
            assert result == secret

    def test_roundtrip_3_of_5(self):
        secret = secrets.randbelow(Q)
        shares = share_scalar(secret, threshold=3, num_shares=5)
        # Any 3 shares should reconstruct
        result = reconstruct_scalar([shares[0], shares[2], shares[4]])
        assert result == secret

    def test_threshold_property(self):
        """M-1 shares should NOT reconstruct the secret (with high probability)."""
        secret = 42
        shares = share_scalar(secret, threshold=3, num_shares=5)
        # 2 shares (below threshold) should almost certainly give wrong answer
        wrong = reconstruct_scalar([shares[0], shares[1]])
        # Probability of accidental match is 1/q ~ 10^{-7}
        assert wrong != secret

    def test_2_of_2(self):
        secret = 12345
        shares = share_scalar(secret, threshold=2, num_shares=2)
        result = reconstruct_scalar(shares)
        assert result == secret

    def test_m_equals_n(self):
        """M-of-N where M=N should work."""
        secret = 99999
        shares = share_scalar(secret, threshold=5, num_shares=5)
        result = reconstruct_scalar(shares)
        assert result == secret

    def test_different_subsets_same_result(self):
        secret = secrets.randbelow(Q)
        shares = share_scalar(secret, threshold=2, num_shares=4)
        r1 = reconstruct_scalar([shares[0], shares[1]])
        r2 = reconstruct_scalar([shares[2], shares[3]])
        r3 = reconstruct_scalar([shares[0], shares[3]])
        assert r1 == r2 == r3 == secret

    def test_zero_secret(self):
        shares = share_scalar(0, threshold=2, num_shares=3)
        result = reconstruct_scalar([shares[0], shares[2]])
        assert result == 0

    def test_max_secret(self):
        shares = share_scalar(Q - 1, threshold=2, num_shares=3)
        result = reconstruct_scalar([shares[0], shares[1]])
        assert result == Q - 1


class TestPolySharing:
    def test_poly_roundtrip(self):
        poly = [secrets.randbelow(Q) for _ in range(N)]
        shares = share_poly(poly, threshold=2, num_shares=3)
        assert len(shares) == 3
        assert all(isinstance(s, PolyShare) for s in shares)
        result = reconstruct_poly([shares[0], shares[2]])
        assert result == poly

    def test_poly_threshold_subset(self):
        poly = [secrets.randbelow(Q) for _ in range(N)]
        shares = share_poly(poly, threshold=3, num_shares=5)
        # Any 3 should work
        r1 = reconstruct_poly([shares[0], shares[1], shares[2]])
        r2 = reconstruct_poly([shares[2], shares[3], shares[4]])
        assert r1 == r2 == poly


class TestPolyVecSharing:
    def test_polyvec_roundtrip(self):
        dim = 3
        polyvec = [[secrets.randbelow(Q) for _ in range(N)] for _ in range(dim)]
        shares = share_polyvec(polyvec, threshold=2, num_shares=3)
        assert len(shares) == 3
        assert all(isinstance(s, PolyVecShare) for s in shares)
        result = reconstruct_polyvec([shares[0], shares[1]])
        for d in range(dim):
            assert result[d] == polyvec[d]

    def test_polyvec_different_subsets(self):
        dim = 2
        polyvec = [[secrets.randbelow(Q) for _ in range(N)] for _ in range(dim)]
        shares = share_polyvec(polyvec, threshold=2, num_shares=4)
        r1 = reconstruct_polyvec([shares[0], shares[1]])
        r2 = reconstruct_polyvec([shares[2], shares[3]])
        for d in range(dim):
            assert r1[d] == r2[d] == polyvec[d]
