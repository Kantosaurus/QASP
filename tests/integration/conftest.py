"""Shared fixtures for integration tests."""

from __future__ import annotations

import hashlib

import pytest

from qasp.crypto import signatures
from qasp.identity import DID, DIDRegistry, create_did
from qasp.protocol.capability import LocalDIDResolver
from qasp.trust.registry import TrustRegistry


@pytest.fixture
def agent_a_keypair() -> tuple[bytes, bytes]:
    return signatures.generate_keypair()


@pytest.fixture
def agent_a_public_key(agent_a_keypair: tuple[bytes, bytes]) -> bytes:
    return agent_a_keypair[0]


@pytest.fixture
def agent_a_secret_key(agent_a_keypair: tuple[bytes, bytes]) -> bytes:
    return agent_a_keypair[1]


@pytest.fixture
def agent_a_did(agent_a_public_key: bytes) -> DID:
    did, _ = create_did(agent_a_public_key)
    return did


@pytest.fixture
def agent_b_keypair() -> tuple[bytes, bytes]:
    return signatures.generate_keypair()


@pytest.fixture
def agent_b_public_key(agent_b_keypair: tuple[bytes, bytes]) -> bytes:
    return agent_b_keypair[0]


@pytest.fixture
def agent_b_secret_key(agent_b_keypair: tuple[bytes, bytes]) -> bytes:
    return agent_b_keypair[1]


@pytest.fixture
def agent_b_did(agent_b_public_key: bytes) -> DID:
    did, _ = create_did(agent_b_public_key)
    return did


@pytest.fixture
def auditor_keypair() -> tuple[bytes, bytes]:
    return signatures.generate_keypair()


@pytest.fixture
def auditor_public_key(auditor_keypair: tuple[bytes, bytes]) -> bytes:
    return auditor_keypair[0]


@pytest.fixture
def auditor_secret_key(auditor_keypair: tuple[bytes, bytes]) -> bytes:
    return auditor_keypair[1]


@pytest.fixture
def auditor_did(auditor_public_key: bytes) -> DID:
    did, _ = create_did(auditor_public_key)
    return did


@pytest.fixture
def sample_code_hash() -> bytes:
    return hashlib.sha384(b"sample_code_version_1.0.0").digest()


@pytest.fixture
def agent_c_keypair() -> tuple[bytes, bytes]:
    return signatures.generate_keypair()


@pytest.fixture
def agent_c_public_key(agent_c_keypair: tuple[bytes, bytes]) -> bytes:
    return agent_c_keypair[0]


@pytest.fixture
def agent_c_secret_key(agent_c_keypair: tuple[bytes, bytes]) -> bytes:
    return agent_c_keypair[1]


@pytest.fixture
def agent_c_did(agent_c_public_key: bytes) -> DID:
    did, _ = create_did(agent_c_public_key)
    return did


@pytest.fixture
def did_registry(
    agent_a_public_key: bytes,
    agent_b_public_key: bytes,
    agent_c_public_key: bytes,
) -> DIDRegistry:
    registry = DIDRegistry()
    for pk in (agent_a_public_key, agent_b_public_key, agent_c_public_key):
        _, doc = create_did(pk)
        registry.register(doc)
    return registry


@pytest.fixture
def did_resolver(did_registry: DIDRegistry) -> LocalDIDResolver:
    return LocalDIDResolver(did_registry)


@pytest.fixture
def trust_registry() -> TrustRegistry:
    return TrustRegistry()
