"""Tests for Bulletproofs range proofs."""
from __future__ import annotations

import pytest

from qasp.crypto.pedersen import commit, random_scalar
from qasp.crypto.bulletproofs import prove_range, verify_range


class TestRangeProof:
    def test_valid_range_proof_small(self) -> None:
        """Test valid range proof with small n_bits for speed."""
        v = 42
        r = random_scalar()
        c = commit(v, r)
        proof = prove_range(v, r, n_bits=8)
        assert verify_range(c, proof)

    def test_valid_range_proof_zero(self) -> None:
        v = 0
        r = random_scalar()
        c = commit(v, r)
        proof = prove_range(v, r, n_bits=8)
        assert verify_range(c, proof)

    def test_valid_range_proof_max(self) -> None:
        v = 255  # 2^8 - 1
        r = random_scalar()
        c = commit(v, r)
        proof = prove_range(v, r, n_bits=8)
        assert verify_range(c, proof)

    def test_out_of_range_raises(self) -> None:
        r = random_scalar()
        with pytest.raises(ValueError):
            prove_range(256, r, n_bits=8)

    def test_negative_value_raises(self) -> None:
        r = random_scalar()
        with pytest.raises(ValueError):
            prove_range(-1, r, n_bits=8)

    def test_wrong_commitment_fails(self) -> None:
        v = 42
        r = random_scalar()
        c = commit(v, r)
        # Create proof for different value
        v2 = 43
        r2 = random_scalar()
        proof = prove_range(v2, r2, n_bits=8)
        # Verify with wrong commitment should fail
        assert not verify_range(c, proof)
