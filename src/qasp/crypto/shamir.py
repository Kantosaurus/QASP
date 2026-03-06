"""Shamir secret sharing over GF(q) where q=8380417 (ML-DSA-65 modulus).

Provides polynomial-aware sharing for threshold operations on Dilithium
key material. Shares are created and reconstructed coefficient-wise.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from qasp.crypto.dilithium import N, Q

__all__ = [
    "PolyShare",
    "PolyVecShare",
    "Share",
    "lagrange_coefficient",
    "lagrange_coefficients_at_zero",
    "mod_inverse",
    "reconstruct_poly",
    "reconstruct_polyvec",
    "reconstruct_scalar",
    "share_poly",
    "share_polyvec",
    "share_scalar",
]


@dataclass(frozen=True)
class Share:
    """A single scalar share (index, value) over GF(q)."""

    index: int
    value: int


@dataclass(frozen=True)
class PolyShare:
    """Share of a polynomial: 256 coefficients, each a share value."""

    index: int
    coeffs: tuple[int, ...]

    def __post_init__(self) -> None:
        if len(self.coeffs) != N:
            object.__setattr__(self, "coeffs", tuple(self.coeffs)[:N])


@dataclass(frozen=True)
class PolyVecShare:
    """Share of a polynomial vector: list of PolyShare instances."""

    index: int
    poly_shares: tuple[PolyShare, ...]


# ============================================================================
# Field Arithmetic
# ============================================================================


def mod_inverse(a: int, p: int = Q) -> int:
    """Compute modular inverse via extended Euclidean algorithm."""
    return pow(a, -1, p)


# ============================================================================
# Lagrange Interpolation
# ============================================================================


def lagrange_coefficient(index: int, indices: list[int], at_point: int = 0) -> int:
    """Compute single Lagrange basis polynomial value at at_point.

    L_index(at_point) = prod_{j != index} (at_point - j) / (index - j)
    """
    num = 1
    den = 1
    for j in indices:
        if j == index:
            continue
        num = (num * (at_point - j)) % Q
        den = (den * (index - j)) % Q
    return (num * mod_inverse(den)) % Q


def lagrange_coefficients_at_zero(indices: list[int]) -> dict[int, int]:
    """Compute all Lagrange coefficients for interpolation at x=0."""
    return {i: lagrange_coefficient(i, indices, 0) for i in indices}


# ============================================================================
# Scalar Sharing
# ============================================================================


def share_scalar(secret: int, threshold: int, num_shares: int) -> list[Share]:
    """Create Shamir shares of a scalar secret.

    Generates a random polynomial f of degree threshold-1 with f(0)=secret,
    and evaluates it at points 1..num_shares.
    """
    secret = secret % Q
    # Random coefficients for degree 1..threshold-1
    coeffs = [secret] + [secrets.randbelow(Q) for _ in range(threshold - 1)]

    shares = []
    for i in range(1, num_shares + 1):
        # Evaluate polynomial at x=i using Horner's method
        val = 0
        for c in reversed(coeffs):
            val = (val * i + c) % Q
        shares.append(Share(index=i, value=val))
    return shares


def reconstruct_scalar(shares: list[Share]) -> int:
    """Reconstruct secret from shares via Lagrange interpolation at x=0."""
    indices = [s.index for s in shares]
    coeffs = lagrange_coefficients_at_zero(indices)
    result = 0
    for s in shares:
        result = (result + coeffs[s.index] * s.value) % Q
    return result


# ============================================================================
# Polynomial Sharing (coefficient-wise)
# ============================================================================


def share_poly(poly: list[int], threshold: int, num_shares: int) -> list[PolyShare]:
    """Create Shamir shares of a polynomial (coefficient-wise)."""
    # For each coefficient position, create shares
    all_coeff_shares: list[list[Share]] = []
    for c in range(N):
        all_coeff_shares.append(share_scalar(poly[c], threshold, num_shares))

    # Reorganize: per-participant PolyShare
    result = []
    for i in range(num_shares):
        coeffs = tuple(all_coeff_shares[c][i].value for c in range(N))
        result.append(PolyShare(index=i + 1, coeffs=coeffs))
    return result


def reconstruct_poly(shares: list[PolyShare]) -> list[int]:
    """Reconstruct polynomial from PolyShares."""
    indices = [s.index for s in shares]
    coeffs_map = lagrange_coefficients_at_zero(indices)
    result = [0] * N
    for s in shares:
        lc = coeffs_map[s.index]
        for c in range(N):
            result[c] = (result[c] + lc * s.coeffs[c]) % Q
    return result


# ============================================================================
# PolyVec Sharing (per-polynomial sharing)
# ============================================================================


def share_polyvec(
    polyvec: list[list[int]], threshold: int, num_shares: int
) -> list[PolyVecShare]:
    """Create Shamir shares of a polynomial vector."""
    dim = len(polyvec)
    # Share each polynomial
    all_poly_shares: list[list[PolyShare]] = []
    for d in range(dim):
        all_poly_shares.append(share_poly(polyvec[d], threshold, num_shares))

    # Reorganize: per-participant PolyVecShare
    result = []
    for i in range(num_shares):
        poly_shares = tuple(all_poly_shares[d][i] for d in range(dim))
        result.append(PolyVecShare(index=i + 1, poly_shares=poly_shares))
    return result


def reconstruct_polyvec(shares: list[PolyVecShare]) -> list[list[int]]:
    """Reconstruct polynomial vector from PolyVecShares."""
    dim = len(shares[0].poly_shares)
    result = []
    for d in range(dim):
        poly_shares = [PolyShare(index=s.index, coeffs=s.poly_shares[d].coeffs) for s in shares]
        result.append(reconstruct_poly(poly_shares))
    return result
