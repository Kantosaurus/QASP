"""Shared fixtures for security test suite."""

from __future__ import annotations

import pytest

from qasp.crypto import hybrid, signatures
from qasp.identity import DID, DIDDocument, DIDRegistry, create_did
from qasp.protocol.capability import LocalDIDResolver
from qasp.protocol.revocation import CertificateRevocationList
from qasp.protocol.token_use_log import TokenUseLog

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
def attacker_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh ML-DSA-65 keypair for an attacker."""
    return signatures.generate_keypair()


@pytest.fixture
def attacker_public_key(attacker_keypair: tuple[bytes, bytes]) -> bytes:
    """Extract attacker's public key."""
    return attacker_keypair[0]


@pytest.fixture
def attacker_secret_key(attacker_keypair: tuple[bytes, bytes]) -> bytes:
    """Extract attacker's secret key."""
    return attacker_keypair[1]


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
def attacker_did(attacker_public_key: bytes) -> DID:
    """Create a DID for the attacker."""
    did, _ = create_did(attacker_public_key)
    return did


@pytest.fixture
def attacker_did_document(attacker_public_key: bytes) -> DIDDocument:
    """Create a DID document for the attacker."""
    _, doc = create_did(attacker_public_key)
    return doc


# =============================================================================
# Registry and Resolver Fixtures
# =============================================================================


@pytest.fixture
def did_registry(
    issuer_did_document: DIDDocument,
    subject_did_document: DIDDocument,
    delegate_did_document: DIDDocument,
    attacker_did_document: DIDDocument,
) -> DIDRegistry:
    """Create a DID registry with all test DIDs registered."""
    registry = DIDRegistry()
    registry.register(issuer_did_document)
    registry.register(subject_did_document)
    registry.register(delegate_did_document)
    registry.register(attacker_did_document)
    return registry


@pytest.fixture
def did_resolver(did_registry: DIDRegistry) -> LocalDIDResolver:
    """Create a DID resolver backed by the test registry."""
    return LocalDIDResolver(did_registry)


# =============================================================================
# Revocation and Replay Fixtures
# =============================================================================


@pytest.fixture
def crl() -> CertificateRevocationList:
    """Create an empty Certificate Revocation List."""
    return CertificateRevocationList()


@pytest.fixture
def token_use_log() -> TokenUseLog:
    """Create an empty TokenUseLog."""
    return TokenUseLog()


# =============================================================================
# Handshake Keypair Fixtures
# =============================================================================


@pytest.fixture
def client_kem_keypair() -> hybrid.HybridKeypair:
    """Generate a fresh hybrid keypair for the client."""
    return hybrid.generate_keypair()


@pytest.fixture
def server_kem_keypair() -> hybrid.HybridKeypair:
    """Generate a fresh hybrid keypair for the server."""
    return hybrid.generate_keypair()


@pytest.fixture
def client_sig_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh signature keypair for the client."""
    return signatures.generate_keypair()


@pytest.fixture
def server_sig_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh signature keypair for the server."""
    return signatures.generate_keypair()


@pytest.fixture
def meter_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh ML-DSA-65 keypair for metering tests."""
    return signatures.generate_keypair()
