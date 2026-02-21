"""Shared fixtures for auditor tests."""

from __future__ import annotations

import pytest

from qasp.crypto.signatures import generate_keypair
from qasp.auditor.service import AuditorService
from qasp.identity.did import create_did


@pytest.fixture
def auditor_keypair() -> tuple[bytes, bytes]:
    """Generate ML-DSA-65 keypair for the auditor."""
    return generate_keypair()


@pytest.fixture
def auditor_public_key(auditor_keypair: tuple[bytes, bytes]) -> bytes:
    return auditor_keypair[0]


@pytest.fixture
def auditor_secret_key(auditor_keypair: tuple[bytes, bytes]) -> bytes:
    return auditor_keypair[1]


@pytest.fixture
def auditor_did(auditor_public_key: bytes) -> str:
    did, _ = create_did(auditor_public_key)
    return str(did)


@pytest.fixture
def auditor_service(
    auditor_did: str,
    auditor_secret_key: bytes,
    auditor_public_key: bytes,
) -> AuditorService:
    return AuditorService(
        auditor_did=auditor_did,
        secret_key=auditor_secret_key,
        public_key=auditor_public_key,
    )


@pytest.fixture
def claimant_keypair() -> tuple[bytes, bytes]:
    return generate_keypair()


@pytest.fixture
def claimant_public_key(claimant_keypair: tuple[bytes, bytes]) -> bytes:
    return claimant_keypair[0]


@pytest.fixture
def claimant_secret_key(claimant_keypair: tuple[bytes, bytes]) -> bytes:
    return claimant_keypair[1]


@pytest.fixture
def claimant_did(claimant_public_key: bytes) -> str:
    did, _ = create_did(claimant_public_key)
    return str(did)


@pytest.fixture
def respondent_keypair() -> tuple[bytes, bytes]:
    return generate_keypair()


@pytest.fixture
def respondent_public_key(respondent_keypair: tuple[bytes, bytes]) -> bytes:
    return respondent_keypair[0]


@pytest.fixture
def respondent_secret_key(respondent_keypair: tuple[bytes, bytes]) -> bytes:
    return respondent_keypair[1]


@pytest.fixture
def respondent_did(respondent_public_key: bytes) -> str:
    did, _ = create_did(respondent_public_key)
    return str(did)
