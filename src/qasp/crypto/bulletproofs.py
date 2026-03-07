"""Bulletproofs range proof protocol over Ed25519.

Pure-Python reference implementation of the Bulletproofs protocol
(Bunz et al., 2018) for zero-knowledge range proofs.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from qasp.crypto.ec import (
    IDENTITY,
    L as GROUP_ORDER,
    P,
    Point,
    hash_to_point,
    point_add,
    point_decode,
    point_encode,
    point_eq,
    scalar_mult,
)
from qasp.crypto.pedersen import G, H, random_scalar

__all__ = [
    "InnerProductProof",
    "RangeProof",
    "inner_product_prove",
    "inner_product_verify",
    "prove_range",
    "verify_range",
]


def _generators(prefix: bytes, n: int) -> list[Point]:
    """Generate n independent points using hash_to_point."""
    return [hash_to_point(prefix, i) for i in range(n)]


class Transcript:
    """Fiat-Shamir transcript for non-interactive proofs."""

    def __init__(self, label: bytes) -> None:
        self._hasher = hashlib.sha384(b"qasp-bulletproof-" + label)

    def append_point(self, label: bytes, point: Point) -> None:
        self._hasher.update(label)
        self._hasher.update(point_encode(point))

    def append_scalar(self, label: bytes, scalar: int) -> None:
        self._hasher.update(label)
        self._hasher.update(scalar.to_bytes(32, "little"))

    def challenge_scalar(self, label: bytes) -> int:
        self._hasher.update(label)
        digest = self._hasher.digest()
        return int.from_bytes(digest[:32], "little") % GROUP_ORDER


@dataclass(frozen=True)
class InnerProductProof:
    """Inner product argument proof."""

    l_vec: tuple[bytes, ...]  # log2(n) L points
    r_vec: tuple[bytes, ...]  # log2(n) R points
    a: int  # final scalar
    b: int  # final scalar


def _inner_product(a: list[int], b: list[int]) -> int:
    """Compute inner product <a, b> mod GROUP_ORDER."""
    return sum(ai * bi for ai, bi in zip(a, b)) % GROUP_ORDER


def inner_product_prove(
    g_vec: list[Point],
    h_vec: list[Point],
    u: Point,
    a_vec: list[int],
    b_vec: list[int],
    transcript: Transcript,
) -> InnerProductProof:
    """Create an inner product proof."""
    n = len(a_vec)
    assert n == len(b_vec) == len(g_vec) == len(h_vec)
    assert n > 0 and (n & (n - 1)) == 0, "n must be a power of 2"

    l_points: list[bytes] = []
    r_points: list[bytes] = []

    a = list(a_vec)
    b = list(b_vec)
    g = list(g_vec)
    h = list(h_vec)

    while len(a) > 1:
        n_half = len(a) // 2

        # Split vectors
        a_lo, a_hi = a[:n_half], a[n_half:]
        b_lo, b_hi = b[:n_half], b[n_half:]
        g_lo, g_hi = g[:n_half], g[n_half:]
        h_lo, h_hi = h[:n_half], h[n_half:]

        # Compute L and R
        cl = _inner_product(a_lo, b_hi)
        cr = _inner_product(a_hi, b_lo)

        L_point = IDENTITY
        for i in range(n_half):
            L_point = point_add(L_point, scalar_mult(a_lo[i] % GROUP_ORDER, g_hi[i]))
            L_point = point_add(L_point, scalar_mult(b_hi[i] % GROUP_ORDER, h_lo[i]))
        L_point = point_add(L_point, scalar_mult(cl, u))

        R_point = IDENTITY
        for i in range(n_half):
            R_point = point_add(R_point, scalar_mult(a_hi[i] % GROUP_ORDER, g_lo[i]))
            R_point = point_add(R_point, scalar_mult(b_lo[i] % GROUP_ORDER, h_hi[i]))
        R_point = point_add(R_point, scalar_mult(cr, u))

        l_points.append(point_encode(L_point))
        r_points.append(point_encode(R_point))

        # Fiat-Shamir challenge
        transcript.append_point(b"L", L_point)
        transcript.append_point(b"R", R_point)
        x = transcript.challenge_scalar(b"x")
        x_inv = pow(x, GROUP_ORDER - 2, GROUP_ORDER)

        # Fold
        a = [(a_lo[i] * x + a_hi[i] * x_inv) % GROUP_ORDER for i in range(n_half)]
        b = [(b_lo[i] * x_inv + b_hi[i] * x) % GROUP_ORDER for i in range(n_half)]
        g = [
            point_add(scalar_mult(x_inv, g_lo[i]), scalar_mult(x, g_hi[i]))
            for i in range(n_half)
        ]
        h = [
            point_add(scalar_mult(x, h_lo[i]), scalar_mult(x_inv, h_hi[i]))
            for i in range(n_half)
        ]

    return InnerProductProof(
        l_vec=tuple(l_points),
        r_vec=tuple(r_points),
        a=a[0],
        b=b[0],
    )


def inner_product_verify(
    g_vec: list[Point],
    h_vec: list[Point],
    u: Point,
    commitment: Point,
    expected_product: int,
    proof: InnerProductProof,
    transcript: Transcript,
) -> bool:
    """Verify an inner product proof."""
    n = len(g_vec)

    # Reconstruct challenges
    challenges: list[int] = []
    for i in range(len(proof.l_vec)):
        Li = point_decode(proof.l_vec[i])
        Ri = point_decode(proof.r_vec[i])
        transcript.append_point(b"L", Li)
        transcript.append_point(b"R", Ri)
        x = transcript.challenge_scalar(b"x")
        challenges.append(x)

    # Compute folded generators
    # For each index j in [0, n), compute the scalars s_j
    # s_j = product of x_i^(+1 if bit i of j is set, -1 otherwise)
    s = [1] * n
    for i, x in enumerate(challenges):
        x_inv = pow(x, GROUP_ORDER - 2, GROUP_ORDER)
        for j in range(n):
            if (j >> (len(challenges) - 1 - i)) & 1:
                s[j] = s[j] * x % GROUP_ORDER
            else:
                s[j] = s[j] * x_inv % GROUP_ORDER

    # Compute expected commitment
    # P' = sum(s_j * a * g_j) + sum(s_j^-1 * b * h_j) + (a*b)*u
    expected = IDENTITY
    for j in range(n):
        expected = point_add(
            expected, scalar_mult(s[j] * proof.a % GROUP_ORDER, g_vec[j])
        )
        s_inv = pow(s[j], GROUP_ORDER - 2, GROUP_ORDER)
        expected = point_add(
            expected, scalar_mult(s_inv * proof.b % GROUP_ORDER, h_vec[j])
        )
    expected = point_add(
        expected, scalar_mult(proof.a * proof.b % GROUP_ORDER, u)
    )

    # Adjust commitment with L and R points
    adjusted = commitment
    for i in range(len(challenges)):
        x = challenges[i]
        x_sq = x * x % GROUP_ORDER
        x_inv = pow(x, GROUP_ORDER - 2, GROUP_ORDER)
        x_inv_sq = x_inv * x_inv % GROUP_ORDER
        Li = point_decode(proof.l_vec[i])
        Ri = point_decode(proof.r_vec[i])
        adjusted = point_add(adjusted, scalar_mult(x_sq, Li))
        adjusted = point_add(adjusted, scalar_mult(x_inv_sq, Ri))

    return point_eq(adjusted, expected)


@dataclass(frozen=True)
class RangeProof:
    """Bulletproofs range proof: proves 0 <= v < 2^n."""

    cap_a: bytes  # Point A
    cap_s: bytes  # Point S
    cap_t1: bytes  # Point T1
    cap_t2: bytes  # Point T2
    tau_x: int
    mu: int
    t_hat: int
    inner_product: InnerProductProof
    n_bits: int


def prove_range(
    value: int,
    blinding: int,
    n_bits: int = 64,
) -> RangeProof:
    """Create a range proof proving 0 <= value < 2^n_bits.

    Args:
        value: The value to prove is in range.
        blinding: The blinding factor from the Pedersen commitment.
        n_bits: Number of bits for the range (default 64).

    Returns:
        A RangeProof.

    Raises:
        ValueError: If value is out of range.
    """
    if value < 0 or value >= (1 << n_bits):
        raise ValueError(f"Value {value} out of range [0, 2^{n_bits})")

    # Generators
    g_vec = _generators(b"qasp-bp-g", n_bits)
    h_vec = _generators(b"qasp-bp-h", n_bits)

    # Bit decomposition
    a_L = [(value >> i) & 1 for i in range(n_bits)]
    a_R = [(a_L[i] - 1) % GROUP_ORDER for i in range(n_bits)]

    # Blinding vectors
    alpha = random_scalar()
    rho = random_scalar()
    s_L = [random_scalar() for _ in range(n_bits)]
    s_R = [random_scalar() for _ in range(n_bits)]

    # A = alpha*H + sum(a_L[i]*g_i) + sum(a_R[i]*h_i)
    A = scalar_mult(alpha, H)
    for i in range(n_bits):
        A = point_add(A, scalar_mult(a_L[i], g_vec[i]))
        A = point_add(A, scalar_mult(a_R[i], h_vec[i]))

    # S = rho*H + sum(s_L[i]*g_i) + sum(s_R[i]*h_i)
    S = scalar_mult(rho, H)
    for i in range(n_bits):
        S = point_add(S, scalar_mult(s_L[i], g_vec[i]))
        S = point_add(S, scalar_mult(s_R[i], h_vec[i]))

    # Fiat-Shamir: y, z
    transcript = Transcript(b"range-proof")
    transcript.append_point(b"A", A)
    transcript.append_point(b"S", S)
    y = transcript.challenge_scalar(b"y")
    z = transcript.challenge_scalar(b"z")

    # Compute polynomial coefficients
    # t(x) = <l(x), r(x)> where:
    # l(x) = (a_L - z*1^n) + s_L*x
    # r(x) = y^n * (a_R + z*1^n + s_R*x) + z^2*2^n

    z_sq = z * z % GROUP_ORDER
    y_powers = [pow(y, i, GROUP_ORDER) for i in range(n_bits)]
    two_powers = [pow(2, i, GROUP_ORDER) for i in range(n_bits)]

    # t0 = <l(0), r(0)>
    l0 = [(a_L[i] - z) % GROUP_ORDER for i in range(n_bits)]
    r0 = [
        (y_powers[i] * ((a_R[i] + z) % GROUP_ORDER) + z_sq * two_powers[i])
        % GROUP_ORDER
        for i in range(n_bits)
    ]
    t0 = _inner_product(l0, r0)

    # t1 = <l(0), s_R*y^n> + <s_L, r(0)>
    t1 = 0
    for i in range(n_bits):
        t1 = (t1 + l0[i] * y_powers[i] * s_R[i]) % GROUP_ORDER
        t1 = (t1 + s_L[i] * r0[i]) % GROUP_ORDER

    # t2 = <s_L, s_R*y^n>
    t2 = 0
    for i in range(n_bits):
        t2 = (t2 + s_L[i] * y_powers[i] * s_R[i]) % GROUP_ORDER

    # Commit to t1, t2
    tau_1 = random_scalar()
    tau_2 = random_scalar()
    T1 = point_add(scalar_mult(t1, G), scalar_mult(tau_1, H))
    T2 = point_add(scalar_mult(t2, G), scalar_mult(tau_2, H))

    # Fiat-Shamir: x
    transcript.append_point(b"T1", T1)
    transcript.append_point(b"T2", T2)
    x = transcript.challenge_scalar(b"x")

    # Evaluate at x
    tau_x = (tau_1 * x + tau_2 * x * x + z_sq * blinding) % GROUP_ORDER
    mu = (alpha + rho * x) % GROUP_ORDER
    t_hat = (t0 + t1 * x + t2 * x * x) % GROUP_ORDER

    # Compute l_vec and r_vec at x
    l_vec = [(l0[i] + s_L[i] * x) % GROUP_ORDER for i in range(n_bits)]
    r_vec = [
        (r0[i] + y_powers[i] * s_R[i] * x) % GROUP_ORDER for i in range(n_bits)
    ]

    # Inner product proof
    # Need u for inner product: use hash_to_point
    u = hash_to_point(b"qasp-bp-u")

    # Scale h_vec by y^-i for the inner product proof
    y_inv = pow(y, GROUP_ORDER - 2, GROUP_ORDER)
    y_inv_powers = [pow(y_inv, i, GROUP_ORDER) for i in range(n_bits)]
    h_prime = [scalar_mult(y_inv_powers[i], h_vec[i]) for i in range(n_bits)]

    # Get challenge for inner product
    transcript.append_scalar(b"t_hat", t_hat)
    transcript.append_scalar(b"tau_x", tau_x)
    transcript.append_scalar(b"mu", mu)
    w = transcript.challenge_scalar(b"w")
    u_prime = scalar_mult(w, u)

    ip_proof = inner_product_prove(g_vec, h_prime, u_prime, l_vec, r_vec, transcript)

    return RangeProof(
        cap_a=point_encode(A),
        cap_s=point_encode(S),
        cap_t1=point_encode(T1),
        cap_t2=point_encode(T2),
        tau_x=tau_x,
        mu=mu,
        t_hat=t_hat,
        inner_product=ip_proof,
        n_bits=n_bits,
    )


def verify_range(
    commitment: bytes,
    proof: RangeProof,
) -> bool:
    """Verify a range proof.

    Args:
        commitment: 32-byte Pedersen commitment.
        proof: The range proof to verify.

    Returns:
        True if the proof is valid.
    """
    n_bits = proof.n_bits

    g_vec = _generators(b"qasp-bp-g", n_bits)
    h_vec = _generators(b"qasp-bp-h", n_bits)

    A = point_decode(proof.cap_a)
    S = point_decode(proof.cap_s)
    T1 = point_decode(proof.cap_t1)
    T2 = point_decode(proof.cap_t2)
    V = point_decode(commitment)

    # Reconstruct challenges
    transcript = Transcript(b"range-proof")
    transcript.append_point(b"A", A)
    transcript.append_point(b"S", S)
    y = transcript.challenge_scalar(b"y")
    z = transcript.challenge_scalar(b"z")

    transcript.append_point(b"T1", T1)
    transcript.append_point(b"T2", T2)
    x = transcript.challenge_scalar(b"x")

    z_sq = z * z % GROUP_ORDER

    # Check t_hat commitment
    # t_hat * G + tau_x * H == z^2 * V + delta(y,z) * G + x * T1 + x^2 * T2
    y_powers = [pow(y, i, GROUP_ORDER) for i in range(n_bits)]
    two_powers = [pow(2, i, GROUP_ORDER) for i in range(n_bits)]

    # delta(y,z) = (z - z^2) * <1^n, y^n> - z^3 * <1^n, 2^n>
    sum_y = sum(y_powers) % GROUP_ORDER
    sum_2 = sum(two_powers) % GROUP_ORDER
    delta = ((z - z_sq) * sum_y - z * z_sq * sum_2) % GROUP_ORDER

    lhs = point_add(scalar_mult(proof.t_hat, G), scalar_mult(proof.tau_x, H))
    rhs = point_add(scalar_mult(z_sq, V), scalar_mult(delta, G))
    rhs = point_add(rhs, scalar_mult(x, T1))
    rhs = point_add(rhs, scalar_mult(x * x % GROUP_ORDER, T2))

    if not point_eq(lhs, rhs):
        return False

    # Check inner product
    u = hash_to_point(b"qasp-bp-u")

    y_inv = pow(y, GROUP_ORDER - 2, GROUP_ORDER)
    y_inv_powers = [pow(y_inv, i, GROUP_ORDER) for i in range(n_bits)]
    h_prime = [scalar_mult(y_inv_powers[i], h_vec[i]) for i in range(n_bits)]

    # Compute P = A + x*S - z*sum(g_i) + sum((z*y^i + z^2*2^i)*h'_i) - mu*H
    P_point = A
    P_point = point_add(P_point, scalar_mult(x, S))
    for i in range(n_bits):
        # -z*g_i: negate by using (GROUP_ORDER - z)
        P_point = point_add(
            P_point, scalar_mult((GROUP_ORDER - z) % GROUP_ORDER, g_vec[i])
        )
        hi_scalar = (z * y_powers[i] + z_sq * two_powers[i]) % GROUP_ORDER
        P_point = point_add(P_point, scalar_mult(hi_scalar, h_prime[i]))
    # -mu*H
    P_point = point_add(
        P_point, scalar_mult((GROUP_ORDER - proof.mu) % GROUP_ORDER, H)
    )

    transcript.append_scalar(b"t_hat", proof.t_hat)
    transcript.append_scalar(b"tau_x", proof.tau_x)
    transcript.append_scalar(b"mu", proof.mu)
    w = transcript.challenge_scalar(b"w")
    u_prime = scalar_mult(w, u)

    # The inner product argument proves P = <a,g> + <b,h'> + <a,b>*u'
    # so the commitment must include the t_hat * u' term
    ip_commitment = point_add(P_point, scalar_mult(proof.t_hat, u_prime))

    return inner_product_verify(
        g_vec, h_prime, u_prime, ip_commitment, proof.t_hat,
        proof.inner_product, transcript
    )
