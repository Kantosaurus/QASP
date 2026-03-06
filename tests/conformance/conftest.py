"""Shared fixtures for QASP conformance tests.

Provides reusable keypairs, DIDs, connections, tokens, and registries
for conformance testing of the QASP protocol.
"""

from __future__ import annotations

import pytest

from qasp.crypto import hybrid, signatures
from qasp.crypto.suites import (
    SUITE_CLASSICAL_COMPAT,
    SUITE_HYBRID_TRANSITION,
    SUITE_PQ_STRICT,
)
from qasp.identity.did import DID, DIDDocument, DIDRegistry, create_did
from qasp.protocol.capability import (
    CapabilityToken,
    Constraints,
    VerbSet,
    attenuate_token,
    create_token,
)
from qasp.protocol.connection import QASPConnection
from qasp.protocol.handshake import HandshakeConfig
from qasp.protocol.revocation import CertificateRevocationList


# =============================================================================
# Keypair Fixtures
# =============================================================================


@pytest.fixture
def alice_keypair() -> tuple[bytes, bytes]:
    """ML-DSA-65 keypair for Alice (owner)."""
    return signatures.generate_keypair()


@pytest.fixture
def alpha_keypair() -> tuple[bytes, bytes]:
    """ML-DSA-65 keypair for Agent Alpha."""
    return signatures.generate_keypair()


@pytest.fixture
def beta_keypair() -> tuple[bytes, bytes]:
    """ML-DSA-65 keypair for Server Beta."""
    return signatures.generate_keypair()


@pytest.fixture
def gamma_keypair() -> tuple[bytes, bytes]:
    """ML-DSA-65 keypair for delegate Gamma."""
    return signatures.generate_keypair()


# =============================================================================
# DID Fixtures
# =============================================================================


@pytest.fixture
def alice_did(alice_keypair: tuple[bytes, bytes]) -> tuple[DID, DIDDocument]:
    return create_did(alice_keypair[0])


@pytest.fixture
def alpha_did(alpha_keypair: tuple[bytes, bytes]) -> tuple[DID, DIDDocument]:
    return create_did(alpha_keypair[0])


@pytest.fixture
def beta_did(beta_keypair: tuple[bytes, bytes]) -> tuple[DID, DIDDocument]:
    return create_did(beta_keypair[0])


@pytest.fixture
def gamma_did(gamma_keypair: tuple[bytes, bytes]) -> tuple[DID, DIDDocument]:
    return create_did(gamma_keypair[0])


@pytest.fixture
def did_registry(
    alice_did: tuple[DID, DIDDocument],
    alpha_did: tuple[DID, DIDDocument],
    beta_did: tuple[DID, DIDDocument],
    gamma_did: tuple[DID, DIDDocument],
) -> DIDRegistry:
    """Registry with all test DIDs registered."""
    registry = DIDRegistry()
    for _, doc in [alice_did, alpha_did, beta_did, gamma_did]:
        registry.register(doc)
    return registry


# =============================================================================
# CRL Fixture
# =============================================================================


@pytest.fixture
def crl() -> CertificateRevocationList:
    return CertificateRevocationList()


# =============================================================================
# Connection Pair Fixtures
# =============================================================================


def _make_connection_pair(
    suite: int,
    hmac_key: bytes = b"\x00" * 32,
) -> tuple[QASPConnection, QASPConnection]:
    """Create a matching client/server QASPConnection pair."""
    client_kem = hybrid.generate_keypair()
    client_sig = signatures.generate_keypair()
    server_kem = hybrid.generate_keypair()
    server_sig = signatures.generate_keypair()

    enable_hybrid = suite == SUITE_HYBRID_TRANSITION
    config = HandshakeConfig(
        supported_cipher_suites=(suite,),
        enable_hybrid=enable_hybrid,
    )

    client = QASPConnection(
        kem_keypair=client_kem,
        sig_keypair=client_sig,
        is_client=True,
        hmac_key=hmac_key,
        config=config,
    )
    server = QASPConnection(
        kem_keypair=server_kem,
        sig_keypair=server_sig,
        is_client=False,
        hmac_key=hmac_key,
        config=config,
    )
    return client, server


def _complete_handshake(
    client: QASPConnection,
    server: QASPConnection,
) -> None:
    """Drive a full handshake between client and server via bytes exchange."""
    client.initiate_handshake()
    data = client.bytes_to_send()
    server.receive_bytes(data)
    data = server.bytes_to_send()
    client.receive_bytes(data)
    data = client.bytes_to_send()
    server.receive_bytes(data)


@pytest.fixture
def pq_strict_pair() -> tuple[QASPConnection, QASPConnection]:
    """Connected client/server pair using PQ-Strict suite."""
    return _make_connection_pair(SUITE_PQ_STRICT)


@pytest.fixture
def hybrid_pair() -> tuple[QASPConnection, QASPConnection]:
    """Connected client/server pair using Hybrid-Transition suite."""
    return _make_connection_pair(SUITE_HYBRID_TRANSITION)


@pytest.fixture
def classical_pair() -> tuple[QASPConnection, QASPConnection]:
    """Connected client/server pair using Classical-Compat suite."""
    return _make_connection_pair(SUITE_CLASSICAL_COMPAT)


# =============================================================================
# Token Fixtures
# =============================================================================


@pytest.fixture
def root_token(
    alice_keypair: tuple[bytes, bytes],
    alice_did: tuple[DID, DIDDocument],
    alpha_did: tuple[DID, DIDDocument],
) -> CapabilityToken:
    """A root capability token from Alice to Alpha."""
    return create_token(
        issuer_did=alice_did[0],
        issuer_secret_key=alice_keypair[1],
        subject_did=alpha_did[0],
        resource_uri="arm://test/compute/gpu",
        verbs={"read", "write", "execute"},
        max_delegation_depth=3,
        constraints=Constraints(quantity_limit=100),
    )


@pytest.fixture
def child_token(
    root_token: CapabilityToken,
    alpha_keypair: tuple[bytes, bytes],
    gamma_did: tuple[DID, DIDDocument],
) -> CapabilityToken:
    """An attenuated child token from Alpha to Gamma."""
    return attenuate_token(
        parent_token=root_token,
        delegator_secret_key=alpha_keypair[1],
        new_subject_did=gamma_did[0],
        reduced_verbs=VerbSet({"read", "execute"}),
        tightened_constraints=Constraints(quantity_limit=50),
    )
