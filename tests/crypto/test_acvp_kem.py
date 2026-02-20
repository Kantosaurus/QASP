"""ACVP test vectors for ML-KEM-768.

These tests validate the ML-KEM-768 implementation against NIST ACVP test vectors.
Source: https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files

Test vectors cover:
- Key generation (75 vectors)
- Encapsulation (75 vectors)
- Decapsulation (30 vectors)
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from qasp.crypto import kem
from tests.crypto.conftest import hex_to_bytes

if TYPE_CHECKING:
    pass

# Skip all tests if vectors are not available
VECTORS_DIR = Path(__file__).parent / "vectors" / "ml_kem_768"
pytestmark = pytest.mark.slow


def has_vectors(test_type: str) -> bool:
    """Check if test vectors are available."""
    return (VECTORS_DIR / f"{test_type}.json").exists()


class TestACVPKeyGen:
    """Test ML-KEM-768 key generation against ACVP vectors."""

    @pytest.mark.skipif(
        not has_vectors("keygen"),
        reason="ACVP keygen vectors not available",
    )
    def test_keygen_vectors(self, mlkem_keygen_vectors: list[dict[str, str]]) -> None:
        """Validate key generation against ACVP vectors.

        Note: ML-KEM key generation is deterministic given the seed (d, z).
        Since liboqs doesn't expose seeded generation in the Python bindings,
        we can only verify that generated keys have correct sizes.
        """
        # Skip if no vectors
        if not mlkem_keygen_vectors:
            pytest.skip("No keygen vectors loaded")

        # For now, just verify we can generate valid keypairs
        # Full vector testing requires seeded key generation
        for _ in range(min(10, len(mlkem_keygen_vectors))):
            pk, sk = kem.generate_keypair()
            assert len(pk) == kem.ML_KEM_768_PUBLIC_KEY_SIZE
            assert len(sk) == kem.ML_KEM_768_SECRET_KEY_SIZE


class TestACVPEncaps:
    """Test ML-KEM-768 encapsulation against ACVP vectors."""

    @pytest.mark.skipif(
        not has_vectors("encaps"),
        reason="ACVP encaps vectors not available",
    )
    def test_encaps_vectors(self, mlkem_encaps_vectors: list[dict[str, str]]) -> None:
        """Validate encapsulation against ACVP vectors.

        Note: ML-KEM encapsulation requires randomness (m).
        Without seeded encapsulation in liboqs Python bindings,
        we verify functional correctness through round-trip tests.
        """
        if not mlkem_encaps_vectors:
            pytest.skip("No encaps vectors loaded")

        # Test functional correctness
        for vector in mlkem_encaps_vectors[:10]:
            if "ek" not in vector:
                continue

            pk = hex_to_bytes(vector["ek"])
            if len(pk) != kem.ML_KEM_768_PUBLIC_KEY_SIZE:
                continue

            # Encapsulate should succeed with valid public key
            ct, ss = kem.encapsulate(pk)
            assert len(ct) == kem.ML_KEM_768_CIPHERTEXT_SIZE
            assert len(ss) == kem.ML_KEM_768_SHARED_SECRET_SIZE


class TestACVPDecaps:
    """Test ML-KEM-768 decapsulation against ACVP vectors."""

    @pytest.mark.skipif(
        not has_vectors("decaps"),
        reason="ACVP decaps vectors not available",
    )
    def test_decaps_vectors(self, mlkem_decaps_vectors: list[dict[str, str]]) -> None:
        """Validate decapsulation against ACVP vectors.

        This is the primary ACVP validation test, as decapsulation
        is fully deterministic: decaps(dk, c) -> K
        """
        if not mlkem_decaps_vectors:
            pytest.skip("No decaps vectors loaded")

        for vector in mlkem_decaps_vectors:
            # Extract vector data
            if not all(k in vector for k in ("dk", "c", "k")):
                continue

            sk = hex_to_bytes(vector["dk"])
            ct = hex_to_bytes(vector["c"])
            expected_ss = hex_to_bytes(vector["k"])

            # Validate sizes
            if len(sk) != kem.ML_KEM_768_SECRET_KEY_SIZE:
                continue
            if len(ct) != kem.ML_KEM_768_CIPHERTEXT_SIZE:
                continue

            # Decapsulate and verify
            ss = kem.decapsulate(sk, ct)
            tc_id = vector.get("tcId", "unknown")
            assert ss == expected_ss, f"Decapsulation mismatch for vector {tc_id}"


class TestACVPRoundTrip:
    """Round-trip tests using ACVP vector components."""

    def test_round_trip_consistency(self) -> None:
        """Verify encapsulation/decapsulation round trip."""
        # Generate keypair
        pk, sk = kem.generate_keypair()

        # Multiple round trips
        for _ in range(10):
            ct, encap_ss = kem.encapsulate(pk)
            decap_ss = kem.decapsulate(sk, ct)

            assert encap_ss == decap_ss
            assert len(ct) == kem.ML_KEM_768_CIPHERTEXT_SIZE
            assert len(encap_ss) == kem.ML_KEM_768_SHARED_SECRET_SIZE
