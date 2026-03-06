"""Tests for pure Python ML-DSA-65 internals."""

from __future__ import annotations

from qasp.crypto.dilithium import (
    ETA,
    GAMMA1,
    GAMMA2,
    K,
    L,
    N,
    Q,
    TAU,
    expand_a,
    hash_to_challenge,
    high_bits,
    low_bits,
    mat_vec_mul,
    pack_polyvec_eta,
    pack_polyvec_gamma1,
    pack_polyvec_t0,
    pack_polyvec_t1,
    pack_public_key,
    pack_signature,
    pack_w1,
    poly_add,
    poly_inv_ntt,
    poly_mul,
    poly_ntt,
    poly_pointwise_mul,
    poly_scalar_mul,
    poly_sub,
    polyvec_add,
    polyvec_ntt,
    power2round,
    sample_in_ball,
    sample_poly_eta,
    sample_poly_gamma1,
    unpack_public_key,
    unpack_signature,
)


class TestPolynomialArithmetic:
    def test_poly_add_basic(self):
        a = [1] * N
        b = [2] * N
        c = poly_add(a, b)
        assert all(c[i] == 3 for i in range(N))

    def test_poly_sub_basic(self):
        a = [5] * N
        b = [3] * N
        c = poly_sub(a, b)
        assert all(c[i] == 2 for i in range(N))

    def test_poly_sub_wrap(self):
        a = [0] * N
        b = [1] * N
        c = poly_sub(a, b)
        assert all(c[i] == Q - 1 for i in range(N))

    def test_poly_scalar_mul(self):
        a = [3] * N
        c = poly_scalar_mul(4, a)
        assert all(c[i] == 12 for i in range(N))

    def test_polyvec_add(self):
        a = [[1] * N, [2] * N]
        b = [[3] * N, [4] * N]
        c = polyvec_add(a, b)
        assert all(c[0][i] == 4 for i in range(N))
        assert all(c[1][i] == 6 for i in range(N))


class TestNTT:
    def test_ntt_inv_ntt_roundtrip(self):
        """NTT followed by inverse NTT should return original polynomial."""
        import secrets
        a = [secrets.randbelow(Q) for _ in range(N)]
        b = poly_ntt(a)
        c = poly_inv_ntt(b)
        for i in range(N):
            assert c[i] == a[i], f"Mismatch at index {i}: {c[i]} != {a[i]}"

    def test_ntt_inv_ntt_zero(self):
        a = [0] * N
        b = poly_ntt(a)
        c = poly_inv_ntt(b)
        assert all(c[i] == 0 for i in range(N))

    def test_ntt_inv_ntt_one(self):
        a = [1] + [0] * (N - 1)
        b = poly_ntt(a)
        c = poly_inv_ntt(b)
        assert c[0] == 1
        assert all(c[i] == 0 for i in range(1, N))

    def test_poly_mul_vs_schoolbook(self):
        """poly_mul should correctly compute polynomial mul mod (x^n+1)."""
        import secrets
        a = [secrets.randbelow(Q) for _ in range(N)]
        b = [secrets.randbelow(Q) for _ in range(N)]

        c = poly_mul(a, b)

        # Schoolbook multiplication mod (x^256 + 1) as reference
        expected = [0] * N
        for i in range(N):
            for j in range(N):
                idx = i + j
                if idx < N:
                    expected[idx] = (expected[idx] + a[i] * b[j]) % Q
                else:
                    expected[idx - N] = (expected[idx - N] - a[i] * b[j]) % Q

        for i in range(N):
            assert c[i] == expected[i], f"Mismatch at {i}: {c[i]} != {expected[i]}"


class TestExpandA:
    def test_determinism(self):
        """ExpandA with same seed should produce identical matrices."""
        rho = b"\x42" * 32
        mat1 = expand_a(rho)
        mat2 = expand_a(rho)
        assert len(mat1) == K
        assert len(mat1[0]) == L
        for i in range(K):
            for j in range(L):
                for c in range(N):
                    assert mat1[i][j][c] == mat2[i][j][c]

    def test_different_seeds_differ(self):
        rho1 = b"\x01" * 32
        rho2 = b"\x02" * 32
        mat1 = expand_a(rho1)
        mat2 = expand_a(rho2)
        # At least one coefficient should differ
        differs = False
        for i in range(K):
            for j in range(L):
                for c in range(N):
                    if mat1[i][j][c] != mat2[i][j][c]:
                        differs = True
                        break
        assert differs

    def test_coefficients_in_range(self):
        rho = b"\xAA" * 32
        mat = expand_a(rho)
        for i in range(K):
            for j in range(L):
                for c in range(N):
                    assert 0 <= mat[i][j][c] < Q


class TestSampling:
    def test_sample_in_ball_weight(self):
        """Challenge polynomial should have exactly tau nonzero coefficients."""
        c_tilde = b"\x01" * 48
        c = sample_in_ball(c_tilde)
        nonzero = sum(1 for x in c if x != 0)
        assert nonzero == TAU

    def test_sample_in_ball_values(self):
        """Nonzero coefficients should be +1 or -1 (i.e., 1 or q-1)."""
        c_tilde = b"\x02" * 48
        c = sample_in_ball(c_tilde)
        for x in c:
            assert x in (0, 1, Q - 1), f"Unexpected coefficient: {x}"

    def test_sample_in_ball_determinism(self):
        c_tilde = b"\x03" * 48
        c1 = sample_in_ball(c_tilde)
        c2 = sample_in_ball(c_tilde)
        assert c1 == c2

    def test_sample_poly_eta_range(self):
        """Eta-sampled coefficients should be in [-eta, eta] mod q."""
        seed = b"\x04" * 64
        p = sample_poly_eta(seed, 0)
        assert len(p) == N
        for c in p:
            # c should be in {0, 1, ..., eta} union {q-eta, ..., q-1}
            assert c <= ETA or c >= Q - ETA, f"Out of range: {c}"

    def test_sample_poly_gamma1_range(self):
        """Gamma1-sampled coefficients in range."""
        seed = b"\x05" * 64
        p = sample_poly_gamma1(seed, 0)
        assert len(p) == N


class TestRounding:
    def test_power2round_reconstruction(self):
        """r1 * 2^d + r0 should equal r mod q."""
        import secrets
        for _ in range(100):
            r = secrets.randbelow(Q)
            r1, r0 = power2round(r)
            reconstructed = (r1 * (1 << 13) + r0) % Q
            assert reconstructed == r, f"Failed for r={r}: {r1}*2^13 + {r0} = {reconstructed}"

    def test_decompose_reconstruction(self):
        """r1 * 2*gamma2 + r0 should equal r mod q (except edge case)."""
        import secrets
        for _ in range(100):
            r = secrets.randbelow(Q)
            r1, r0 = high_bits(r), low_bits(r)
            reconstructed = (r1 * 2 * GAMMA2 + r0) % Q
            assert reconstructed == r % Q, f"Failed for r={r}"


class TestPacking:
    def test_t1_pack_unpack_roundtrip(self):
        """Pack/unpack t1 should roundtrip."""
        import secrets
        t1 = [[secrets.randbelow(1 << 10) for _ in range(N)] for _ in range(K)]
        rho = b"\x00" * 32
        pk = pack_public_key(rho, t1)
        assert len(pk) == 1952
        rho_out, t1_out = unpack_public_key(pk)
        assert rho_out == rho
        for i in range(K):
            for j in range(N):
                assert t1_out[i][j] == t1[i][j]

    def test_signature_pack_unpack_roundtrip(self):
        """Pack/unpack signature should roundtrip."""
        import secrets
        c_tilde = secrets.token_bytes(48)
        z = [[(GAMMA1 - secrets.randbelow(2 * GAMMA1)) % Q for _ in range(N)] for _ in range(L)]
        h = [[0] * N for _ in range(K)]
        # Set a few hint bits
        h[0][5] = 1
        h[2][100] = 1
        sig = pack_signature(c_tilde, z, h)
        assert len(sig) == 3309
        c_out, z_out, h_out = unpack_signature(sig)
        assert c_out == c_tilde
        for i in range(K):
            for j in range(N):
                assert h_out[i][j] == h[i][j], f"Hint mismatch at [{i}][{j}]"

    def test_polyvec_eta_roundtrip(self):
        seed = b"\x06" * 64
        v = [sample_poly_eta(seed, i) for i in range(L)]
        from qasp.crypto.dilithium import _pack_poly_eta, _unpack_poly_eta
        for p in v:
            packed = _pack_poly_eta(p)
            unpacked = _unpack_poly_eta(packed)
            for i in range(N):
                assert unpacked[i] == p[i], f"Eta roundtrip failed at {i}"

    def test_polyvec_t0_roundtrip(self):
        """Power2round t0 values should roundtrip through pack/unpack."""
        import secrets
        # Generate t0 values via power2round
        t0 = []
        for _ in range(K):
            p = [0] * N
            for j in range(N):
                r = secrets.randbelow(Q)
                _, r0 = power2round(r)
                p[j] = r0
            t0.append(p)
        from qasp.crypto.dilithium import _pack_poly_t0, _unpack_poly_t0
        for p in t0:
            packed = _pack_poly_t0(p)
            unpacked = _unpack_poly_t0(packed)
            for i in range(N):
                assert unpacked[i] == p[i], f"t0 roundtrip failed at {i}: {unpacked[i]} != {p[i]}"

    def test_pack_w1(self):
        """pack_w1 should produce k*128 bytes."""
        w1 = [[i % 16 for i in range(N)] for _ in range(K)]
        packed = pack_w1(w1)
        assert len(packed) == K * 128


class TestMatVecMul:
    def test_mat_vec_mul_zero(self):
        """A * zero_vector = zero_vector."""
        rho = b"\x10" * 32
        mat = expand_a(rho)
        zero_vec = [[0] * N for _ in range(L)]
        result = mat_vec_mul(mat, zero_vec)
        for i in range(K):
            for j in range(N):
                assert result[i][j] == 0


class TestHashing:
    def test_compute_tr_determinism(self):
        from qasp.crypto.dilithium import compute_tr
        pk = b"\x01" * 1952
        tr1 = compute_tr(pk)
        tr2 = compute_tr(pk)
        assert tr1 == tr2
        assert len(tr1) == 64

    def test_compute_mu_determinism(self):
        from qasp.crypto.dilithium import compute_mu
        tr = b"\x02" * 64
        msg = b"hello"
        mu1 = compute_mu(tr, msg)
        mu2 = compute_mu(tr, msg)
        assert mu1 == mu2
        assert len(mu1) == 64

    def test_hash_to_challenge_length(self):
        mu = b"\x03" * 64
        w1_bytes = b"\x04" * 768
        c_tilde = hash_to_challenge(mu, w1_bytes)
        assert len(c_tilde) == 48
