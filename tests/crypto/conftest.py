"""Shared fixtures for crypto module tests."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

# Lazy imports to avoid loading liboqs when not needed
# These are imported inside fixtures that use them

if TYPE_CHECKING:
    from qasp.crypto import hybrid as hybrid_module


# Path to ACVP test vectors
VECTORS_DIR = Path(__file__).parent / "vectors"


# =============================================================================
# ML-KEM-768 Fixtures
# =============================================================================


@pytest.fixture
def mlkem_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh ML-KEM-768 keypair."""
    from qasp.crypto import kem

    return kem.generate_keypair()


@pytest.fixture
def mlkem_public_key(mlkem_keypair: tuple[bytes, bytes]) -> bytes:
    """Extract public key from ML-KEM-768 keypair."""
    return mlkem_keypair[0]


@pytest.fixture
def mlkem_secret_key(mlkem_keypair: tuple[bytes, bytes]) -> bytes:
    """Extract secret key from ML-KEM-768 keypair."""
    return mlkem_keypair[1]


# =============================================================================
# ML-DSA-65 Fixtures
# =============================================================================


@pytest.fixture
def mldsa_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh ML-DSA-65 keypair."""
    from qasp.crypto import signatures

    return signatures.generate_keypair()


@pytest.fixture
def mldsa_public_key(mldsa_keypair: tuple[bytes, bytes]) -> bytes:
    """Extract public key from ML-DSA-65 keypair."""
    return mldsa_keypair[0]


@pytest.fixture
def mldsa_secret_key(mldsa_keypair: tuple[bytes, bytes]) -> bytes:
    """Extract secret key from ML-DSA-65 keypair."""
    return mldsa_keypair[1]


# =============================================================================
# Hybrid KEM Fixtures
# =============================================================================


@pytest.fixture
def hybrid_keypair() -> hybrid_module.HybridKeypair:
    """Generate a fresh hybrid X25519+ML-KEM-768 keypair."""
    from qasp.crypto import hybrid

    return hybrid.generate_keypair()


# =============================================================================
# AEAD Fixtures
# =============================================================================


@pytest.fixture
def aes_key() -> bytes:
    """Generate a random AES-256 key."""
    from qasp.crypto import aead

    return os.urandom(aead.AES_256_KEY_SIZE)


@pytest.fixture
def aes_nonce() -> bytes:
    """Generate a random AES-GCM nonce."""
    from qasp.crypto import aead

    return aead.generate_nonce()


# =============================================================================
# KDF Fixtures
# =============================================================================


@pytest.fixture
def sample_ikm() -> bytes:
    """Sample input keying material for KDF tests."""
    return b"sample-input-keying-material-for-testing"


@pytest.fixture
def sample_salt() -> bytes:
    """Sample salt for KDF tests."""
    return b"sample-salt-value"


@pytest.fixture
def sample_info() -> bytes:
    """Sample info for KDF tests."""
    return b"sample-context-info"


# =============================================================================
# ACVP Test Vector Loaders
# =============================================================================


def load_acvp_vectors(algorithm: str, test_type: str) -> list[dict[str, Any]]:
    """Load ACVP test vectors from JSON files.

    Args:
        algorithm: Algorithm name (e.g., "ml_kem_768", "ml_dsa_65")
        test_type: Test type (e.g., "keygen", "encaps", "siggen")

    Returns:
        List of test vector dictionaries with hex-encoded values.
    """
    vector_file = VECTORS_DIR / algorithm / f"{test_type}.json"
    if not vector_file.exists():
        return []

    with open(vector_file) as f:
        data = json.load(f)

    # Handle ACVP format: vectors are in testGroups[].tests[]
    vectors: list[dict[str, Any]] = []
    for group in data.get("testGroups", []):
        for test in group.get("tests", []):
            vectors.append(test)

    return vectors


@pytest.fixture
def mlkem_keygen_vectors() -> list[dict[str, Any]]:
    """Load ML-KEM-768 key generation test vectors."""
    return load_acvp_vectors("ml_kem_768", "keygen")


@pytest.fixture
def mlkem_encaps_vectors() -> list[dict[str, Any]]:
    """Load ML-KEM-768 encapsulation test vectors."""
    return load_acvp_vectors("ml_kem_768", "encaps")


@pytest.fixture
def mlkem_decaps_vectors() -> list[dict[str, Any]]:
    """Load ML-KEM-768 decapsulation test vectors."""
    return load_acvp_vectors("ml_kem_768", "decaps")


@pytest.fixture
def mldsa_keygen_vectors() -> list[dict[str, Any]]:
    """Load ML-DSA-65 key generation test vectors."""
    return load_acvp_vectors("ml_dsa_65", "keygen")


@pytest.fixture
def mldsa_siggen_vectors() -> list[dict[str, Any]]:
    """Load ML-DSA-65 signature generation test vectors."""
    return load_acvp_vectors("ml_dsa_65", "siggen")


@pytest.fixture
def mldsa_sigver_vectors() -> list[dict[str, Any]]:
    """Load ML-DSA-65 signature verification test vectors."""
    return load_acvp_vectors("ml_dsa_65", "sigver")


# =============================================================================
# Utility Functions
# =============================================================================


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes."""
    return bytes.fromhex(hex_str)


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string."""
    return data.hex()
