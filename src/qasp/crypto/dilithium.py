"""Pure Python ML-DSA-65 (Dilithium3) internals.

This module implements the core polynomial arithmetic, NTT, sampling,
rounding, and packing routines needed for threshold signing over ML-DSA-65.

Parameters (FIPS 204 / ML-DSA-65):
    q = 8380417, n = 256, k = 6, l = 5, eta = 4,
    gamma1 = 2**19, gamma2 = (q-1)//32, tau = 49,
    beta = tau * eta = 196, omega = 55, d = 13.

This is a reference implementation (~1000x slower than C).
Full sign/verify is handled by liboqs; this module provides the
internals needed for distributed key generation and threshold signing.
"""

from __future__ import annotations

import hashlib
import struct

__all__ = [
    "BETA",
    "D",
    "ETA",
    "GAMMA1",
    "GAMMA2",
    "K",
    "L",
    "N",
    "OMEGA",
    "Q",
    "TAU",
    "Poly",
    "PolyVec",
    "compute_mu",
    "compute_tr",
    "decompose",
    "expand_a",
    "hash_to_challenge",
    "high_bits",
    "low_bits",
    "make_hint",
    "mat_vec_mul",
    "mat_vec_ntt_mul",
    "poly_mul",
    "pack_polyvec_eta",
    "pack_polyvec_gamma1",
    "pack_polyvec_t0",
    "pack_polyvec_t1",
    "pack_public_key",
    "pack_signature",
    "pack_w1",
    "poly_add",
    "poly_inv_ntt",
    "poly_ntt",
    "poly_pointwise_mul",
    "poly_scalar_mul",
    "poly_sub",
    "polyvec_add",
    "polyvec_inv_ntt",
    "polyvec_ntt",
    "polyvec_sub",
    "power2round",
    "sample_in_ball",
    "sample_poly_eta",
    "sample_poly_gamma1",
    "unpack_public_key",
    "unpack_signature",
    "use_hint",
]

# ============================================================================
# ML-DSA-65 Parameters
# ============================================================================

Q = 8380417
N = 256
K = 6  # rows in matrix A
L = 5  # columns in matrix A
ETA = 4
GAMMA1 = 1 << 19  # 2^19 = 524288
GAMMA2 = (Q - 1) // 32  # 261888
TAU = 49
BETA = TAU * ETA  # 196
OMEGA = 55
D = 13

# Public key size: 32 (rho) + k*320 (t1 packed at 10 bits)
PK_SIZE = 32 + K * 320  # 1952
# Signature size (maximum)
SIG_SIZE = 48 + L * 640 + OMEGA + K  # 48 + 3200 + 61 = 3309

# Type aliases
Poly = list[int]  # 256 coefficients mod q
PolyVec = list[Poly]  # list of Poly


# ============================================================================
# NTT (Number Theoretic Transform) - FIPS 204 pure modular arithmetic
# ============================================================================

# Primitive 512th root of unity mod q
_ZETA = 1753

# Precompute: _ZETA_TABLE[k] = _ZETA^{bitrev8(k)} mod q
def _bitrev8(x: int) -> int:
    """8-bit reversal."""
    result = 0
    for _ in range(8):
        result = (result << 1) | (x & 1)
        x >>= 1
    return result


def _bitrev7(x: int) -> int:
    """7-bit reversal."""
    result = 0
    for _ in range(7):
        result = (result << 1) | (x & 1)
        x >>= 1
    return result


_ZETA_TABLE = [pow(_ZETA, _bitrev8(k), Q) for k in range(N)]

# 256^{-1} mod q for InvNTT final scaling (FIPS 204 Algorithm 42)
_N_INV = pow(N, -1, Q)


def poly_ntt(a: Poly) -> Poly:
    """Forward NTT per FIPS 204 Algorithm 41 (8 levels: len from 128 to 1)."""
    r = list(a)
    m = N
    k = 0
    while m >= 2:
        m //= 2
        for i in range(0, N, 2 * m):
            k += 1
            zeta = _ZETA_TABLE[k]
            for j in range(i, i + m):
                t = (zeta * r[j + m]) % Q
                r[j + m] = (r[j] - t) % Q
                r[j] = (r[j] + t) % Q
    return r


def poly_inv_ntt(a: Poly) -> Poly:
    """Inverse NTT per FIPS 204 Algorithm 42 (8 levels: len from 1 to 128)."""
    r = list(a)
    m = 1
    k = N  # 256
    while m <= N // 2:  # m <= 128, 8 levels
        for i in range(0, N, 2 * m):
            k -= 1
            zeta = (Q - _ZETA_TABLE[k]) % Q  # -ζ^{BitRev_8(k)}
            for j in range(i, i + m):
                t = r[j]
                r[j] = (t + r[j + m]) % Q
                r[j + m] = (zeta * (t - r[j + m])) % Q
        m *= 2
    for j in range(N):
        r[j] = (r[j] * _N_INV) % Q
    return r


def poly_pointwise_mul(a: Poly, b: Poly) -> Poly:
    """NTT-domain element-wise multiplication.

    With 8-level NTT, the output is 256 independent evaluations,
    so multiplication in NTT domain is simply element-wise.
    """
    return [(a[i] * b[i]) % Q for i in range(N)]


# ============================================================================
# Polynomial Arithmetic
# ============================================================================


def poly_add(a: Poly, b: Poly) -> Poly:
    """Add two polynomials coefficient-wise mod q."""
    return [(a[i] + b[i]) % Q for i in range(N)]


def poly_sub(a: Poly, b: Poly) -> Poly:
    """Subtract two polynomials coefficient-wise mod q."""
    return [(a[i] - b[i]) % Q for i in range(N)]


def poly_scalar_mul(c: int, a: Poly) -> Poly:
    """Multiply polynomial by scalar mod q."""
    return [(c * a[i]) % Q for i in range(N)]


def _reduce_coeffs(p: Poly) -> Poly:
    """Reduce all coefficients to [0, q)."""
    return [c % Q for c in p]


def poly_mul(a: Poly, b: Poly) -> Poly:
    """Polynomial multiplication mod (x^256 + 1) via NTT.

    Converts to NTT domain, does pointwise multiply, converts back.
    """
    a_ntt = poly_ntt(list(a))
    b_ntt = poly_ntt(list(b))
    c_ntt = poly_pointwise_mul(a_ntt, b_ntt)
    return poly_inv_ntt(c_ntt)


def polyvec_add(a: PolyVec, b: PolyVec) -> PolyVec:
    """Add two polynomial vectors."""
    return [poly_add(a[i], b[i]) for i in range(len(a))]


def polyvec_sub(a: PolyVec, b: PolyVec) -> PolyVec:
    """Subtract two polynomial vectors."""
    return [poly_sub(a[i], b[i]) for i in range(len(a))]


def polyvec_ntt(v: PolyVec) -> PolyVec:
    """Apply NTT to each polynomial in vector."""
    return [poly_ntt(p) for p in v]


def polyvec_inv_ntt(v: PolyVec) -> PolyVec:
    """Apply inverse NTT to each polynomial in vector."""
    return [poly_inv_ntt(p) for p in v]


def mat_vec_ntt_mul(mat_ntt: list[PolyVec], v_ntt: PolyVec) -> PolyVec:
    """Multiply NTT-domain matrix by NTT-domain vector.

    mat_ntt is k x l matrix of NTT-domain polynomials.
    v_ntt is l-vector of NTT-domain polynomials.
    Returns k-vector of NTT-domain polynomials.
    """
    result: PolyVec = []
    for i in range(len(mat_ntt)):
        acc = [0] * N
        for j in range(len(v_ntt)):
            t = poly_pointwise_mul(mat_ntt[i][j], v_ntt[j])
            acc = poly_add(acc, t)
        result.append(acc)
    return result


def mat_vec_mul(mat_ntt: list[PolyVec], v: PolyVec) -> PolyVec:
    """Multiply NTT-domain matrix A-hat by normal-domain vector.

    Converts v to NTT domain, multiplies, converts result back.
    mat_ntt is k x l matrix in NTT domain (from expand_a).
    v is l-vector in normal domain.
    Returns k-vector in normal domain.
    """
    v_ntt = polyvec_ntt(v)
    result_ntt = mat_vec_ntt_mul(mat_ntt, v_ntt)
    return [poly_inv_ntt(p) for p in result_ntt]


# ============================================================================
# Deterministic Expansion / Sampling
# ============================================================================


def _shake128(data: bytes, outlen: int) -> bytes:
    """SHAKE-128 XOF."""
    h = hashlib.shake_128(data)
    return h.digest(outlen)


def _shake256(data: bytes, outlen: int) -> bytes:
    """SHAKE-256 XOF."""
    h = hashlib.shake_256(data)
    return h.digest(outlen)


def _rejection_uniform(stream: bytes) -> Poly:
    """Sample polynomial with coefficients uniform in [0, q) via rejection.

    Per FIPS 204 Algorithm 14 (CoeffFromThreeBytes): extract one 23-bit value
    from each 3-byte group: z = (b0 + b1*256 + b2*65536) mod 2^23.
    Accept if z < q.
    """
    coeffs: list[int] = []
    pos = 0
    while len(coeffs) < N:
        if pos + 3 > len(stream):
            break
        b0 = stream[pos]
        b1 = stream[pos + 1]
        b2 = stream[pos + 2]
        pos += 3
        z = (b0 | (b1 << 8) | (b2 << 16)) & 0x7FFFFF
        if z < Q:
            coeffs.append(z)
    return coeffs


def expand_a(rho: bytes) -> list[PolyVec]:
    """Expand seed rho into k x l matrix A-hat via SHAKE-128.

    Returns matrix in NTT domain (matching FIPS 204 ExpandA / RejNTTPoly).
    The sampled coefficients ARE the NTT representation directly.
    """
    mat: list[PolyVec] = []
    for i in range(K):
        row: PolyVec = []
        for j in range(L):
            # Domain separator: rho || j || i (little-endian bytes)
            seed = rho + bytes([j, i])
            # 3 bytes per candidate, ~0.1% rejection rate, generous buffer
            stream = _shake128(seed, 3 * 256 + 256)
            poly = _rejection_uniform(stream)
            # Coefficients are already in NTT domain per FIPS 204
            row.append(poly)
        mat.append(row)
    return mat


def sample_poly_eta(seed: bytes, nonce: int) -> Poly:
    """Sample polynomial with coefficients in [-eta, eta].

    Uses SHAKE-256 with seed || nonce (2 bytes LE).
    For eta=4, each coefficient uses 4 bits.
    """
    data = seed + struct.pack("<H", nonce)
    # For eta=4: need 128 bytes (256 coefficients, 2 per byte via 4-bit halves)
    stream = _shake256(data, 128)
    coeffs: list[int] = []
    for byte in stream:
        # Each byte gives 2 coefficients
        d0 = byte & 0x0F
        d1 = byte >> 4
        # Map to [-eta, eta] via rejection
        if d0 <= 2 * ETA:
            coeffs.append(ETA - d0)
        if len(coeffs) < N and d1 <= 2 * ETA:
            coeffs.append(ETA - d1)
    # If we don't have enough (unlikely), extend
    extra_nonce = 1
    while len(coeffs) < N:
        extra_data = seed + struct.pack("<H", nonce + 0x8000 + extra_nonce)
        extra_stream = _shake256(extra_data, 128)
        for byte in extra_stream:
            d0 = byte & 0x0F
            d1 = byte >> 4
            if d0 <= 2 * ETA:
                coeffs.append(ETA - d0)
            if len(coeffs) < N and d1 <= 2 * ETA:
                coeffs.append(ETA - d1)
            if len(coeffs) >= N:
                break
        extra_nonce += 1
    return [c % Q for c in coeffs[:N]]


def sample_poly_gamma1(seed: bytes, nonce: int) -> Poly:
    """Sample polynomial with coefficients in [-gamma1+1, gamma1].

    Uses SHAKE-256 with seed || nonce (2 bytes LE).
    For gamma1=2^19, each coefficient uses 20 bits.
    """
    data = seed + struct.pack("<H", nonce)
    # 20 bits per coefficient, 256 coefficients = 640 bytes
    stream = _shake256(data, 640)
    coeffs: list[int] = []
    pos = 0
    for i in range(N // 4):
        # 4 coefficients from 10 bytes (4 * 20 bits = 80 bits = 10 bytes)
        if pos + 5 > len(stream):
            break
        b = stream[pos:pos + 5]
        pos += 5

        z0 = b[0] | ((b[1] & 0x0F) << 8)
        z0 |= ((b[1] >> 4) & 0x0F) << 12
        # Simpler: read 20-bit values
        # Actually, for gamma1 = 2^19, pack at 20 bits each
        # Let me use a cleaner approach
        pass

    # Cleaner: use 5 bytes for 2 coefficients (20 bits each)
    coeffs = []
    pos = 0
    for _ in range(N // 2):
        if pos + 5 > len(stream):
            break
        b0 = stream[pos]
        b1 = stream[pos + 1]
        b2 = stream[pos + 2]
        b3 = stream[pos + 3]
        b4 = stream[pos + 4]
        pos += 5

        z0 = b0 | (b1 << 8) | ((b2 & 0x0F) << 16)
        z1 = (b2 >> 4) | (b3 << 4) | (b4 << 12)

        z0 &= 0xFFFFF  # 20 bits
        z1 &= 0xFFFFF

        coeffs.append((GAMMA1 - z0) % Q)
        coeffs.append((GAMMA1 - z1) % Q)

    return coeffs[:N]


def sample_in_ball(c_tilde: bytes) -> Poly:
    """Sample challenge polynomial c with exactly tau +/-1 coefficients.

    Uses SHAKE-256 to derive positions and signs.
    """
    stream = _shake256(c_tilde, 256)
    c = [0] * N

    # First 8 bytes give sign bits (we need tau=49 sign bits)
    signs = int.from_bytes(stream[:8], "little")
    pos = 8

    for i in range(N - TAU, N):
        # Rejection sample j in [0, i]
        while True:
            if pos >= len(stream):
                stream = _shake256(c_tilde + stream, 256)
                pos = 0
            j = stream[pos]
            pos += 1
            if j <= i:
                break

        c[i] = c[j]
        sign_bit = signs & 1
        signs >>= 1
        c[j] = Q - 1 if sign_bit else 1

    return c


# ============================================================================
# Rounding (FIPS 204 Section 8.4)
# ============================================================================


def power2round(r: int) -> tuple[int, int]:
    """Decompose r into (r1, r0) such that r = r1 * 2^d + r0.

    Returns (r1, r0) where r0 in [-(2^(d-1)-1), 2^(d-1)].
    """
    r = r % Q
    r0 = _centered_mod(r, 1 << D)
    r1 = (r - r0) >> D
    return r1, r0


def _centered_mod(r: int, a: int) -> int:
    """Centered modular reduction: result in [-(a//2), a//2]."""
    r = r % a
    if r > a // 2:
        r -= a
    return r


def decompose(r: int) -> tuple[int, int]:
    """Decompose r into (r1, r0) per FIPS 204.

    Returns (r1, r0) where:
      r = r1 * 2*gamma2 + r0
      r0 in (-gamma2, gamma2]
    """
    r = r % Q
    r0 = _centered_mod(r, 2 * GAMMA2)
    if r - r0 == Q - 1:
        r1 = 0
        r0 = r0 - 1
    else:
        r1 = (r - r0) // (2 * GAMMA2)
    return r1, r0


def high_bits(r: int) -> int:
    """Extract high bits: r1 from decompose(r)."""
    r1, _ = decompose(r)
    return r1


def low_bits(r: int) -> int:
    """Extract low bits: r0 from decompose(r)."""
    _, r0 = decompose(r)
    return r0


def make_hint(z: int, r: int) -> int:
    """Compute hint bit: 1 if HighBits(r) != HighBits(r + z)."""
    r1_plain = high_bits(r)
    r1_sum = high_bits((r + z) % Q)
    return 0 if r1_plain == r1_sum else 1


def use_hint(h: int, r: int) -> int:
    """Use hint to recover correct high bits."""
    r1, r0 = decompose(r)
    if h == 0:
        return r1
    # Adjust r1 based on sign of r0
    if r0 > 0:
        return (r1 + 1) % ((Q - 1) // (2 * GAMMA2) + 1)
    else:
        return (r1 - 1) % ((Q - 1) // (2 * GAMMA2) + 1)


# ============================================================================
# Packing / Unpacking
# ============================================================================


def _pack_poly_t1(p: Poly) -> bytes:
    """Pack polynomial with coefficients in [0, 2^10) at 10 bits each.

    Output: 320 bytes.
    """
    out = bytearray(320)
    for i in range(N // 4):
        c0 = p[4 * i] & 0x3FF
        c1 = p[4 * i + 1] & 0x3FF
        c2 = p[4 * i + 2] & 0x3FF
        c3 = p[4 * i + 3] & 0x3FF
        out[5 * i + 0] = c0 & 0xFF
        out[5 * i + 1] = ((c0 >> 8) | (c1 << 2)) & 0xFF
        out[5 * i + 2] = ((c1 >> 6) | (c2 << 4)) & 0xFF
        out[5 * i + 3] = ((c2 >> 4) | (c3 << 6)) & 0xFF
        out[5 * i + 4] = (c3 >> 2) & 0xFF
    return bytes(out)


def _unpack_poly_t1(data: bytes) -> Poly:
    """Unpack polynomial from 320 bytes (10-bit coefficients)."""
    p: Poly = [0] * N
    for i in range(N // 4):
        b = data[5 * i:5 * i + 5]
        p[4 * i + 0] = (b[0] | (b[1] << 8)) & 0x3FF
        p[4 * i + 1] = ((b[1] >> 2) | (b[2] << 6)) & 0x3FF
        p[4 * i + 2] = ((b[2] >> 4) | (b[3] << 4)) & 0x3FF
        p[4 * i + 3] = ((b[3] >> 6) | (b[4] << 2)) & 0x3FF
    return p


def _pack_poly_t0(p: Poly) -> bytes:
    """Pack polynomial t0 coefficients.

    Coefficients are in [-(2^(d-1)-1), 2^(d-1)] = [-4095, 4096].
    Stored as 13-bit unsigned values after shifting.
    Output: 416 bytes (256 * 13 bits = 3328 bits).
    """
    out = bytearray(416)
    # Pack 8 coefficients into 13 bytes
    for i in range(N // 8):
        cs = []
        for j in range(8):
            c = p[8 * i + j]
            # Shift to unsigned: t0_unsigned = (1 << (d-1)) - t0
            c_unsigned = (1 << (D - 1)) - c
            cs.append(c_unsigned & 0x1FFF)
        # Pack 8 * 13 = 104 bits = 13 bytes
        bits = 0
        for j in range(8):
            bits |= cs[j] << (13 * j)
        for j in range(13):
            out[13 * i + j] = (bits >> (8 * j)) & 0xFF
    return bytes(out)


def _unpack_poly_t0(data: bytes) -> Poly:
    """Unpack polynomial t0 from 416 bytes."""
    p: Poly = [0] * N
    for i in range(N // 8):
        bits = 0
        for j in range(13):
            bits |= data[13 * i + j] << (8 * j)
        for j in range(8):
            c_unsigned = (bits >> (13 * j)) & 0x1FFF
            p[8 * i + j] = (1 << (D - 1)) - c_unsigned
    return p


def _to_centered(c: int) -> int:
    """Convert mod q value to centered representation in [-q//2, q//2]."""
    c = c % Q
    if c > Q // 2:
        return c - Q
    return c


def _pack_poly_eta(p: Poly) -> bytes:
    """Pack polynomial with coefficients in [-eta, eta] (mod q).

    For eta=4, each coefficient needs 4 bits. Output: 128 bytes.
    """
    out = bytearray(128)
    for i in range(N // 2):
        c0 = ETA - _to_centered(p[2 * i])
        c1 = ETA - _to_centered(p[2 * i + 1])
        out[i] = (c0 & 0x0F) | ((c1 & 0x0F) << 4)
    return bytes(out)


def _unpack_poly_eta(data: bytes) -> Poly:
    """Unpack polynomial from eta-packed bytes."""
    p: Poly = [0] * N
    for i in range(N // 2):
        b = data[i]
        p[2 * i] = (ETA - (b & 0x0F)) % Q
        p[2 * i + 1] = (ETA - (b >> 4)) % Q
    return p


def _pack_poly_gamma1(p: Poly) -> bytes:
    """Pack polynomial with coefficients in [-(gamma1-1), gamma1].

    For gamma1=2^19, each coefficient needs 20 bits. Output: 640 bytes.
    """
    out = bytearray(640)
    for i in range(N // 2):
        # Center coefficients to [-gamma1+1, gamma1]
        c0 = p[2 * i] % Q
        c1 = p[2 * i + 1] % Q
        if c0 > Q // 2:
            c0 -= Q
        if c1 > Q // 2:
            c1 -= Q
        # Map to unsigned: gamma1 - coefficient (always in [0, 2^20 - 1])
        z0 = GAMMA1 - c0
        z1 = GAMMA1 - c1
        out[5 * i + 0] = z0 & 0xFF
        out[5 * i + 1] = (z0 >> 8) & 0xFF
        out[5 * i + 2] = ((z0 >> 16) | (z1 << 4)) & 0xFF
        out[5 * i + 3] = (z1 >> 4) & 0xFF
        out[5 * i + 4] = (z1 >> 12) & 0xFF
    return bytes(out)


def _unpack_poly_gamma1(data: bytes) -> Poly:
    """Unpack polynomial from gamma1-packed bytes."""
    p: Poly = [0] * N
    for i in range(N // 2):
        b = data[5 * i:5 * i + 5]
        z0 = b[0] | (b[1] << 8) | ((b[2] & 0x0F) << 16)
        z1 = (b[2] >> 4) | (b[3] << 4) | (b[4] << 12)
        p[2 * i] = (GAMMA1 - z0) % Q
        p[2 * i + 1] = (GAMMA1 - z1) % Q
    return p


def pack_polyvec_t1(v: PolyVec) -> bytes:
    """Pack t1 vector."""
    return b"".join(_pack_poly_t1(p) for p in v)


def pack_polyvec_t0(v: PolyVec) -> bytes:
    """Pack t0 vector."""
    return b"".join(_pack_poly_t0(p) for p in v)


def pack_polyvec_eta(v: PolyVec) -> bytes:
    """Pack eta-bounded vector."""
    return b"".join(_pack_poly_eta(p) for p in v)


def pack_polyvec_gamma1(v: PolyVec) -> bytes:
    """Pack gamma1-bounded vector."""
    return b"".join(_pack_poly_gamma1(p) for p in v)


def pack_public_key(rho: bytes, t1: PolyVec) -> bytes:
    """Pack public key: rho (32 bytes) || t1 packed.

    Output: 1952 bytes.
    """
    return rho + pack_polyvec_t1(t1)


def unpack_public_key(pk: bytes) -> tuple[bytes, PolyVec]:
    """Unpack public key into (rho, t1)."""
    rho = pk[:32]
    t1: PolyVec = []
    for i in range(K):
        offset = 32 + i * 320
        t1.append(_unpack_poly_t1(pk[offset:offset + 320]))
    return rho, t1


def pack_w1(w1: PolyVec) -> bytes:
    """Pack w1 vector for hashing.

    w1 coefficients are in [0, (q-1)/(2*gamma2)].
    For gamma2=(q-1)/32, max value = 15, so 4 bits each.
    Output: k * 128 bytes = 768 bytes.
    """
    out = bytearray()
    for p in w1:
        poly_bytes = bytearray(128)
        for i in range(N // 2):
            c0 = p[2 * i] & 0x0F
            c1 = p[2 * i + 1] & 0x0F
            poly_bytes[i] = c0 | (c1 << 4)
        out.extend(poly_bytes)
    return bytes(out)


def pack_signature(c_tilde: bytes, z: PolyVec, h: list[Poly]) -> bytes:
    """Pack signature: c_tilde (48 bytes) || z packed || hint encoded.

    Output: 3309 bytes maximum.
    """
    sig = bytearray()
    # c_tilde: 48 bytes
    sig.extend(c_tilde[:48])
    # z: l polynomials packed with gamma1
    for p in z:
        sig.extend(_pack_poly_gamma1(p))
    # hints: omega + k bytes
    hint_bytes = bytearray(OMEGA + K)
    idx = 0
    for i in range(K):
        for j in range(N):
            if h[i][j] != 0:
                hint_bytes[idx] = j
                idx += 1
        hint_bytes[OMEGA + i] = idx
    sig.extend(hint_bytes)
    return bytes(sig)


def unpack_signature(sig: bytes) -> tuple[bytes, PolyVec, list[Poly]]:
    """Unpack signature into (c_tilde, z, h)."""
    # c_tilde
    c_tilde = sig[:48]
    # z
    z: PolyVec = []
    offset = 48
    for _ in range(L):
        z.append(_unpack_poly_gamma1(sig[offset:offset + 640]))
        offset += 640
    # hints
    h: list[Poly] = [[0] * N for _ in range(K)]
    hint_data = sig[offset:offset + OMEGA + K]
    idx = 0
    for i in range(K):
        end = hint_data[OMEGA + i]
        while idx < end:
            h[i][hint_data[idx]] = 1
            idx += 1
    return c_tilde, z, h


# ============================================================================
# Hashing
# ============================================================================


def compute_tr(pk_bytes: bytes) -> bytes:
    """Compute tr = SHAKE-256(pk, 64) -- public key hash."""
    return _shake256(pk_bytes, 64)


def compute_mu(tr: bytes, message: bytes) -> bytes:
    """Compute mu = SHAKE-256(tr || M', 64).

    Per FIPS 204 external interface, M' = 0x00 || 0x00 || message
    (empty context string).
    """
    m_prime = b"\x00\x00" + message
    return _shake256(tr + m_prime, 64)


def hash_to_challenge(mu: bytes, w1_bytes: bytes) -> bytes:
    """Compute c_tilde = SHAKE-256(mu || w1_encode, 48)."""
    return _shake256(mu + w1_bytes, 48)
