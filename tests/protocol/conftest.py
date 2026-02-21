"""Shared fixtures for protocol module tests."""

from __future__ import annotations

import pytest

from qasp.crypto import signatures
from qasp.identity import DID, DIDDocument, DIDRegistry, create_did

# =============================================================================
# ML-DSA-65 Keypair Fixtures
# =============================================================================


@pytest.fixture
def issuer_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh ML-DSA-65 keypair for a token issuer."""
    return signatures.generate_keypair()


@pytest.fixture
def issuer_public_key(issuer_keypair: tuple[bytes, bytes]) -> bytes:
    """Extract issuer's public key."""
    return issuer_keypair[0]


@pytest.fixture
def issuer_secret_key(issuer_keypair: tuple[bytes, bytes]) -> bytes:
    """Extract issuer's secret key."""
    return issuer_keypair[1]


@pytest.fixture
def subject_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh ML-DSA-65 keypair for a token subject."""
    return signatures.generate_keypair()


@pytest.fixture
def subject_public_key(subject_keypair: tuple[bytes, bytes]) -> bytes:
    """Extract subject's public key."""
    return subject_keypair[0]


@pytest.fixture
def subject_secret_key(subject_keypair: tuple[bytes, bytes]) -> bytes:
    """Extract subject's secret key."""
    return subject_keypair[1]


@pytest.fixture
def delegate_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh ML-DSA-65 keypair for a delegate."""
    return signatures.generate_keypair()


@pytest.fixture
def delegate_public_key(delegate_keypair: tuple[bytes, bytes]) -> bytes:
    """Extract delegate's public key."""
    return delegate_keypair[0]


@pytest.fixture
def delegate_secret_key(delegate_keypair: tuple[bytes, bytes]) -> bytes:
    """Extract delegate's secret key."""
    return delegate_keypair[1]


@pytest.fixture
def third_party_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh ML-DSA-65 keypair for a third party."""
    return signatures.generate_keypair()


@pytest.fixture
def third_party_public_key(third_party_keypair: tuple[bytes, bytes]) -> bytes:
    """Extract third party's public key."""
    return third_party_keypair[0]


@pytest.fixture
def third_party_secret_key(third_party_keypair: tuple[bytes, bytes]) -> bytes:
    """Extract third party's secret key."""
    return third_party_keypair[1]


# =============================================================================
# DID Fixtures
# =============================================================================


@pytest.fixture
def issuer_did(issuer_public_key: bytes) -> DID:
    """Create a DID for the issuer."""
    did, _ = create_did(issuer_public_key)
    return did


@pytest.fixture
def issuer_did_document(issuer_public_key: bytes) -> DIDDocument:
    """Create a DID document for the issuer."""
    _, doc = create_did(issuer_public_key)
    return doc


@pytest.fixture
def subject_did(subject_public_key: bytes) -> DID:
    """Create a DID for the subject."""
    did, _ = create_did(subject_public_key)
    return did


@pytest.fixture
def subject_did_document(subject_public_key: bytes) -> DIDDocument:
    """Create a DID document for the subject."""
    _, doc = create_did(subject_public_key)
    return doc


@pytest.fixture
def delegate_did(delegate_public_key: bytes) -> DID:
    """Create a DID for the delegate."""
    did, _ = create_did(delegate_public_key)
    return did


@pytest.fixture
def delegate_did_document(delegate_public_key: bytes) -> DIDDocument:
    """Create a DID document for the delegate."""
    _, doc = create_did(delegate_public_key)
    return doc


@pytest.fixture
def third_party_did(third_party_public_key: bytes) -> DID:
    """Create a DID for the third party."""
    did, _ = create_did(third_party_public_key)
    return did


@pytest.fixture
def third_party_did_document(third_party_public_key: bytes) -> DIDDocument:
    """Create a DID document for the third party."""
    _, doc = create_did(third_party_public_key)
    return doc


@pytest.fixture
def audience_did(third_party_public_key: bytes) -> DID:
    """Create an audience DID (reuses third party keypair)."""
    did, _ = create_did(third_party_public_key)
    return did


# =============================================================================
# Registry Fixtures
# =============================================================================


@pytest.fixture
def did_registry(
    issuer_did_document: DIDDocument,
    subject_did_document: DIDDocument,
    delegate_did_document: DIDDocument,
    third_party_did_document: DIDDocument,
) -> DIDRegistry:
    """Create a DID registry with all test DIDs registered."""
    registry = DIDRegistry()
    registry.register(issuer_did_document)
    registry.register(subject_did_document)
    registry.register(delegate_did_document)
    registry.register(third_party_did_document)
    return registry
