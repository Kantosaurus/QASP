"""Conformance tests for QASP-Discover service discovery.

Tests signed advertisement creation, verification, and discovery pipeline.
"""

from __future__ import annotations

import time

import pytest

from qasp.crypto import signatures
from qasp.identity.did import DIDRegistry, create_did
from qasp.transport.discover import (
    DEFAULT_AD_TTL,
    CapabilityAdvertisement,
    create_advertisement,
    verify_advertisement,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def advertiser_keypair() -> tuple[bytes, bytes]:
    return signatures.generate_keypair()


@pytest.fixture
def advertiser_did(
    advertiser_keypair: tuple[bytes, bytes],
) -> tuple[str, bytes]:
    """Create a DID and return (did_str, public_key)."""
    did, doc = create_did(advertiser_keypair[0])
    return str(did), advertiser_keypair[0]


# =============================================================================
# Advertisement Creation
# =============================================================================


class TestAdvertisementCreation:
    """Verify PQ-signed advertisement creation."""

    def test_create_advertisement(
        self,
        advertiser_keypair: tuple[bytes, bytes],
        advertiser_did: tuple[str, bytes],
    ) -> None:
        did_str, _ = advertiser_did

        ad = create_advertisement(
            did=did_str,
            secret_key=advertiser_keypair[1],
            endpoints=[("localhost", 8443)],
            capabilities={"compute:gpu", "storage:s3"},
        )

        assert ad.did == did_str
        assert len(ad.endpoints) == 1
        assert ad.endpoints[0] == ("localhost", 8443)
        assert "compute:gpu" in ad.capabilities
        assert "storage:s3" in ad.capabilities
        assert ad.ttl == DEFAULT_AD_TTL
        assert ad.signature != b""

    def test_custom_ttl(
        self,
        advertiser_keypair: tuple[bytes, bytes],
        advertiser_did: tuple[str, bytes],
    ) -> None:
        did_str, _ = advertiser_did

        ad = create_advertisement(
            did=did_str,
            secret_key=advertiser_keypair[1],
            endpoints=[("localhost", 8443)],
            capabilities={"compute:gpu"},
            ttl=600,
        )

        assert ad.ttl == 600


# =============================================================================
# Advertisement Verification
# =============================================================================


class TestAdvertisementVerification:
    """Verify PQ-signed advertisement verification."""

    def test_verify_valid_advertisement(
        self,
        advertiser_keypair: tuple[bytes, bytes],
        advertiser_did: tuple[str, bytes],
    ) -> None:
        did_str, pk = advertiser_did

        ad = create_advertisement(
            did=did_str,
            secret_key=advertiser_keypair[1],
            endpoints=[("localhost", 8443)],
            capabilities={"compute:gpu"},
        )

        result = verify_advertisement(ad, pk)
        assert result is True

    def test_verify_wrong_key_fails(
        self,
        advertiser_keypair: tuple[bytes, bytes],
        advertiser_did: tuple[str, bytes],
    ) -> None:
        did_str, _ = advertiser_did

        ad = create_advertisement(
            did=did_str,
            secret_key=advertiser_keypair[1],
            endpoints=[("localhost", 8443)],
            capabilities={"compute:gpu"},
        )

        wrong_pk, _ = signatures.generate_keypair()

        with pytest.raises(Exception):
            verify_advertisement(ad, wrong_pk)

    def test_tampered_advertisement_fails(
        self,
        advertiser_keypair: tuple[bytes, bytes],
        advertiser_did: tuple[str, bytes],
    ) -> None:
        did_str, pk = advertiser_did

        ad = create_advertisement(
            did=did_str,
            secret_key=advertiser_keypair[1],
            endpoints=[("localhost", 8443)],
            capabilities={"compute:gpu"},
        )

        # Tamper with capabilities
        tampered = CapabilityAdvertisement(
            did=ad.did,
            endpoints=ad.endpoints,
            capabilities=frozenset({"compute:gpu", "admin:root"}),
            ttl=ad.ttl,
            created_at=ad.created_at,
            signature=ad.signature,
        )

        with pytest.raises(Exception):
            verify_advertisement(tampered, pk)


# =============================================================================
# Discovery Pipeline
# =============================================================================


class TestDiscoveryPipeline:
    """Verify the discover -> verify -> extract DID -> check capabilities flow."""

    def test_full_pipeline(
        self,
        advertiser_keypair: tuple[bytes, bytes],
        advertiser_did: tuple[str, bytes],
    ) -> None:
        did_str, pk = advertiser_did

        # Step 1: Create advertisement
        ad = create_advertisement(
            did=did_str,
            secret_key=advertiser_keypair[1],
            endpoints=[("10.0.0.1", 8443), ("10.0.0.2", 8443)],
            capabilities={"compute:gpu", "storage:s3"},
        )

        # Step 2: Verify signature
        assert verify_advertisement(ad, pk) is True

        # Step 3: Check capabilities
        assert "compute:gpu" in ad.capabilities

        # Step 4: Extract endpoints
        assert len(ad.endpoints) == 2
        assert ad.endpoints[0] == ("10.0.0.1", 8443)

    def test_multiple_advertisers(
        self,
    ) -> None:
        """Verify multiple advertisers can be independently verified."""
        ads_with_keys: list[tuple[CapabilityAdvertisement, bytes]] = []

        for i in range(3):
            pk, sk = signatures.generate_keypair()
            did, doc = create_did(pk)

            ad = create_advertisement(
                did=str(did),
                secret_key=sk,
                endpoints=[("host-" + str(i), 8443 + i)],
                capabilities={f"service-{i}"},
            )
            ads_with_keys.append((ad, pk))

        # All verify with their respective public keys
        for ad, pk in ads_with_keys:
            assert verify_advertisement(ad, pk) is True
