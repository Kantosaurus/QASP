"""Tests for QASP-Discover service discovery."""

from __future__ import annotations

import time
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import cbor2
import pytest

from qasp.crypto.signatures import generate_keypair
from qasp.identity.did import DIDRegistry, create_did
from qasp.transport.discover import (
    DEFAULT_AD_TTL,
    WELL_KNOWN_PATH,
    CapabilityAdvertisement,
    DiscoveryClient,
    DiscoveryServer,
    ServiceEndpoint,
    create_advertisement,
    verify_advertisement,
)
from qasp.transport.exceptions import (
    AdvertisementError,
    DiscoveryError,
    DiscoveryTimeoutError,
)


def _mock_zeroconf_patches():
    """Return patch context managers for zeroconf lazy imports."""
    return (
        patch("zeroconf.Zeroconf"),
        patch("zeroconf.ServiceInfo"),
    )


class TestCapabilityAdvertisement:
    """Tests for the CapabilityAdvertisement dataclass."""

    def test_frozen_dataclass(self, sample_advertisement: CapabilityAdvertisement) -> None:
        with pytest.raises(AttributeError):
            sample_advertisement.did = "other"  # type: ignore[misc]

    def test_to_cbor_deterministic(self, mock_did: str) -> None:
        ad1 = CapabilityAdvertisement(
            did=mock_did,
            endpoints=(("127.0.0.1", 8443),),
            capabilities=frozenset({"b", "a", "c"}),
            ttl=300,
            created_at=1000.0,
            signature=b"",
        )
        ad2 = CapabilityAdvertisement(
            did=mock_did,
            endpoints=(("127.0.0.1", 8443),),
            capabilities=frozenset({"c", "a", "b"}),
            ttl=300,
            created_at=1000.0,
            signature=b"",
        )
        assert ad1.to_cbor() == ad2.to_cbor()

    def test_to_cbor_excludes_signature(self, mock_did: str) -> None:
        ad = CapabilityAdvertisement(
            did=mock_did,
            endpoints=(("127.0.0.1", 8443),),
            capabilities=frozenset({"invoke"}),
            ttl=300,
            created_at=1000.0,
            signature=b"some_signature_data",
        )
        payload = cbor2.loads(ad.to_cbor())
        assert "signature" not in payload

    def test_to_cbor_has_sorted_capabilities(self, mock_did: str) -> None:
        ad = CapabilityAdvertisement(
            did=mock_did,
            endpoints=(("127.0.0.1", 8443),),
            capabilities=frozenset({"z_cap", "a_cap", "m_cap"}),
            ttl=300,
            created_at=1000.0,
            signature=b"",
        )
        payload = cbor2.loads(ad.to_cbor())
        assert payload["capabilities"] == ["a_cap", "m_cap", "z_cap"]

    def test_is_expired_not_expired(self) -> None:
        ad = CapabilityAdvertisement(
            did="did:qasp:test",
            endpoints=(),
            capabilities=frozenset(),
            ttl=300,
            created_at=time.time(),
            signature=b"",
        )
        assert not ad.is_expired()

    def test_is_expired_expired(self) -> None:
        ad = CapabilityAdvertisement(
            did="did:qasp:test",
            endpoints=(),
            capabilities=frozenset(),
            ttl=300,
            created_at=time.time() - 600,
            signature=b"",
        )
        assert ad.is_expired()

    def test_is_expired_custom_now(self) -> None:
        created = 1000.0
        ad = CapabilityAdvertisement(
            did="did:qasp:test",
            endpoints=(),
            capabilities=frozenset(),
            ttl=300,
            created_at=created,
            signature=b"",
        )
        assert not ad.is_expired(now=1200.0)
        assert ad.is_expired(now=1400.0)

    def test_to_well_known_json(self, mock_did: str) -> None:
        ad = CapabilityAdvertisement(
            did=mock_did,
            endpoints=(("127.0.0.1", 8443), ("10.0.0.1", 9000)),
            capabilities=frozenset({"invoke", "delegate"}),
            ttl=300,
            created_at=1000.0,
            signature=b"\xab\xcd",
        )
        result = ad.to_well_known_json()
        assert result["did"] == mock_did
        assert result["endpoints"] == [
            {"host": "127.0.0.1", "port": 8443},
            {"host": "10.0.0.1", "port": 9000},
        ]
        assert result["capabilities"] == ["delegate", "invoke"]
        assert result["ttl"] == 300
        assert result["created_at"] == 1000.0
        assert result["signature"] == "abcd"


class TestAdvertisementSignVerify:
    """Tests for create_advertisement and verify_advertisement."""

    def test_roundtrip_create_verify(
        self, discovery_keypair: tuple[bytes, bytes]
    ) -> None:
        pk, sk = discovery_keypair
        did_obj, _ = create_did(pk)
        did_str = str(did_obj)

        ad = create_advertisement(
            did=did_str,
            secret_key=sk,
            endpoints=[("127.0.0.1", 8443)],
            capabilities={"invoke", "delegate"},
        )

        assert ad.did == did_str
        assert ad.signature != b""
        assert ad.ttl == DEFAULT_AD_TTL
        assert not ad.is_expired()

        result = verify_advertisement(ad, pk, check_expiry=True)
        assert result is True

    def test_wrong_key_fails(self, discovery_keypair: tuple[bytes, bytes]) -> None:
        pk, sk = discovery_keypair
        did_obj, _ = create_did(pk)

        ad = create_advertisement(
            did=str(did_obj),
            secret_key=sk,
            endpoints=[("127.0.0.1", 8443)],
            capabilities={"invoke"},
        )

        wrong_pk, _ = generate_keypair()
        with pytest.raises(AdvertisementError, match="verification failed"):
            verify_advertisement(ad, wrong_pk, check_expiry=False)

    def test_expired_check_raises(
        self, discovery_keypair: tuple[bytes, bytes]
    ) -> None:
        pk, sk = discovery_keypair
        did_obj, _ = create_did(pk)

        ad = create_advertisement(
            did=str(did_obj),
            secret_key=sk,
            endpoints=[("127.0.0.1", 8443)],
            capabilities={"invoke"},
            ttl=0,
        )
        time.sleep(0.01)

        with pytest.raises(AdvertisementError, match="expired"):
            verify_advertisement(ad, pk, check_expiry=True)

    def test_expired_check_skip(
        self, discovery_keypair: tuple[bytes, bytes]
    ) -> None:
        pk, sk = discovery_keypair
        did_obj, _ = create_did(pk)

        ad = create_advertisement(
            did=str(did_obj),
            secret_key=sk,
            endpoints=[("127.0.0.1", 8443)],
            capabilities={"invoke"},
            ttl=0,
        )
        time.sleep(0.01)

        result = verify_advertisement(ad, pk, check_expiry=False)
        assert result is True

    def test_tampered_payload_fails(
        self, discovery_keypair: tuple[bytes, bytes]
    ) -> None:
        pk, sk = discovery_keypair
        did_obj, _ = create_did(pk)

        ad = create_advertisement(
            did=str(did_obj),
            secret_key=sk,
            endpoints=[("127.0.0.1", 8443)],
            capabilities={"invoke"},
        )

        tampered = CapabilityAdvertisement(
            did=ad.did,
            endpoints=ad.endpoints,
            capabilities=frozenset({"invoke", "TAMPERED"}),
            ttl=ad.ttl,
            created_at=ad.created_at,
            signature=ad.signature,
        )

        with pytest.raises(AdvertisementError):
            verify_advertisement(tampered, pk, check_expiry=False)


class TestDiscoveryClientInit:
    """Tests for DiscoveryClient initialization."""

    def test_stores_did_and_key(
        self, discovery_keypair: tuple[bytes, bytes], mock_did: str
    ) -> None:
        _, sk = discovery_keypair
        client = DiscoveryClient(mock_did, sk)
        assert client._did == mock_did
        assert client._secret_key == sk

    def test_empty_cache(
        self, discovery_keypair: tuple[bytes, bytes], mock_did: str
    ) -> None:
        _, sk = discovery_keypair
        client = DiscoveryClient(mock_did, sk)
        assert len(client._known_endpoints) == 0
        assert len(client._advertisements) == 0

    def test_custom_registry(
        self, discovery_keypair: tuple[bytes, bytes], mock_did: str
    ) -> None:
        _, sk = discovery_keypair
        registry = DIDRegistry()
        client = DiscoveryClient(mock_did, sk, registry=registry)
        assert client._registry is registry


class TestDiscoveryClientDiscover:
    """Tests for DiscoveryClient.discover()."""

    async def test_returns_cached_endpoints(
        self, discovery_keypair: tuple[bytes, bytes], mock_did: str
    ) -> None:
        _, sk = discovery_keypair
        client = DiscoveryClient(mock_did, sk)

        ep = ServiceEndpoint(
            did="did:qasp:remote",
            host="10.0.0.1",
            port=8443,
            capabilities=frozenset({"invoke"}),
            last_seen=datetime.now(),
            trust_score=0.5,
        )
        client._known_endpoints["did:qasp:remote"] = ep

        results = await client.discover()
        assert len(results) == 1
        assert results[0].did == "did:qasp:remote"

    async def test_capability_filtering(
        self, discovery_keypair: tuple[bytes, bytes], mock_did: str
    ) -> None:
        _, sk = discovery_keypair
        client = DiscoveryClient(mock_did, sk)

        ep1 = ServiceEndpoint(
            did="did:qasp:a",
            host="10.0.0.1",
            port=8443,
            capabilities=frozenset({"invoke"}),
            last_seen=datetime.now(),
            trust_score=None,
        )
        ep2 = ServiceEndpoint(
            did="did:qasp:b",
            host="10.0.0.2",
            port=8443,
            capabilities=frozenset({"delegate"}),
            last_seen=datetime.now(),
            trust_score=None,
        )
        client._known_endpoints["did:qasp:a"] = ep1
        client._known_endpoints["did:qasp:b"] = ep2

        results = await client.discover(capability="invoke")
        assert len(results) == 1
        assert results[0].did == "did:qasp:a"

    async def test_trust_score_filtering(
        self, discovery_keypair: tuple[bytes, bytes], mock_did: str
    ) -> None:
        _, sk = discovery_keypair
        client = DiscoveryClient(mock_did, sk)

        ep_high = ServiceEndpoint(
            did="did:qasp:high",
            host="10.0.0.1",
            port=8443,
            capabilities=frozenset({"invoke"}),
            last_seen=datetime.now(),
            trust_score=0.9,
        )
        ep_low = ServiceEndpoint(
            did="did:qasp:low",
            host="10.0.0.2",
            port=8443,
            capabilities=frozenset({"invoke"}),
            last_seen=datetime.now(),
            trust_score=0.1,
        )
        client._known_endpoints["did:qasp:high"] = ep_high
        client._known_endpoints["did:qasp:low"] = ep_low

        results = await client.discover(min_trust_score=0.5)
        assert len(results) == 1
        assert results[0].did == "did:qasp:high"

    async def test_expired_eviction(
        self, discovery_keypair: tuple[bytes, bytes], mock_did: str
    ) -> None:
        _, sk = discovery_keypair
        client = DiscoveryClient(mock_did, sk)

        expired_ad = CapabilityAdvertisement(
            did="did:qasp:expired",
            endpoints=(("10.0.0.1", 8443),),
            capabilities=frozenset({"invoke"}),
            ttl=1,
            created_at=time.time() - 100,
            signature=b"fake",
        )
        client._advertisements["did:qasp:expired"] = expired_ad
        client._known_endpoints["did:qasp:expired"] = ServiceEndpoint(
            did="did:qasp:expired",
            host="10.0.0.1",
            port=8443,
            capabilities=frozenset({"invoke"}),
            last_seen=datetime.now(),
            trust_score=None,
        )

        results = await client.discover()
        assert len(results) == 0
        assert "did:qasp:expired" not in client._advertisements
        assert "did:qasp:expired" not in client._known_endpoints


class TestDiscoveryClientAnnounce:
    """Tests for DiscoveryClient.announce()."""

    async def test_creates_advertisement_and_caches(
        self, discovery_keypair: tuple[bytes, bytes], mock_did: str
    ) -> None:
        _, sk = discovery_keypair
        client = DiscoveryClient(mock_did, sk)

        p1, p2 = _mock_zeroconf_patches()
        with p1, p2:
            await client.announce("127.0.0.1", 8443, {"invoke", "delegate"})

        assert mock_did in client._advertisements
        assert mock_did in client._known_endpoints
        ad = client._advertisements[mock_did]
        assert ad.did == mock_did
        assert ad.signature != b""

        ep = client._known_endpoints[mock_did]
        assert ep.host == "127.0.0.1"
        assert ep.port == 8443
        assert ep.capabilities == frozenset({"invoke", "delegate"})


class TestDiscoveryClientFetchWellKnown:
    """Tests for DiscoveryClient.fetch_well_known()."""

    async def test_success_via_aiohttp(
        self, discovery_keypair: tuple[bytes, bytes]
    ) -> None:
        pk, sk = discovery_keypair
        did_obj, doc = create_did(pk)
        did_str = str(did_obj)

        registry = DIDRegistry()
        registry.register(doc)

        client = DiscoveryClient(did_str, sk, registry=registry)

        ad = create_advertisement(
            did=did_str,
            secret_key=sk,
            endpoints=[("127.0.0.1", 8443)],
            capabilities={"invoke"},
        )
        json_data = ad.to_well_known_json()

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(return_value=json_data)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=mock_resp),
            __aexit__=AsyncMock(return_value=False),
        ))
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await client.fetch_well_known("127.0.0.1", 8443)

        assert result.did == did_str
        assert result.signature == ad.signature
        assert did_str in client._advertisements

    async def test_error_on_bad_status(
        self, discovery_keypair: tuple[bytes, bytes], mock_did: str
    ) -> None:
        _, sk = discovery_keypair
        client = DiscoveryClient(mock_did, sk)

        mock_resp = AsyncMock()
        mock_resp.status = 404

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=mock_resp),
            __aexit__=AsyncMock(return_value=False),
        ))
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("aiohttp.ClientSession", return_value=mock_session),
            pytest.raises(DiscoveryError, match="status 404"),
        ):
            await client.fetch_well_known("127.0.0.1", 9999)


class TestDiscoveryServerInit:
    """Tests for DiscoveryServer initialization."""

    def test_stores_config(
        self, discovery_keypair: tuple[bytes, bytes], mock_did: str
    ) -> None:
        _, sk = discovery_keypair
        caps = {"invoke", "delegate"}
        server = DiscoveryServer(mock_did, sk, caps)
        assert server._did == mock_did
        assert server._secret_key == sk
        assert server._capabilities == caps
        assert server._advertisement is None

    def test_custom_registry(
        self, discovery_keypair: tuple[bytes, bytes], mock_did: str
    ) -> None:
        _, sk = discovery_keypair
        registry = DIDRegistry()
        server = DiscoveryServer(mock_did, sk, {"invoke"}, registry=registry)
        assert server._registry is registry


class TestDiscoveryServerStartStop:
    """Tests for DiscoveryServer start/stop lifecycle."""

    async def test_creates_advertisement_on_start(
        self, discovery_keypair: tuple[bytes, bytes], mock_did: str, free_port: int
    ) -> None:
        _, sk = discovery_keypair
        server = DiscoveryServer(mock_did, sk, {"invoke"})

        p1, p2 = _mock_zeroconf_patches()
        with p1, p2:
            await server.start("127.0.0.1", free_port)
            try:
                assert server.advertisement is not None
                assert server.advertisement.did == mock_did
                assert server.advertisement.signature != b""
                assert frozenset({"invoke"}) == server.advertisement.capabilities
            finally:
                await server.stop()

    async def test_stop_clears_state(
        self, discovery_keypair: tuple[bytes, bytes], mock_did: str, free_port: int
    ) -> None:
        _, sk = discovery_keypair
        server = DiscoveryServer(mock_did, sk, {"invoke"})

        p1, p2 = _mock_zeroconf_patches()
        with p1, p2:
            await server.start("127.0.0.1", free_port)
            await server.stop()

        assert server.advertisement is None
        assert server._app is None
        assert server._runner is None
        assert server._site is None

    async def test_well_known_serves_json(
        self, discovery_keypair: tuple[bytes, bytes], free_port: int
    ) -> None:
        """Integration test: start server and fetch well-known endpoint."""
        pk, sk = discovery_keypair
        did_obj, _ = create_did(pk)
        did_str = str(did_obj)

        server = DiscoveryServer(did_str, sk, {"invoke", "delegate"})

        p1, p2 = _mock_zeroconf_patches()
        with p1, p2:
            await server.start("127.0.0.1", free_port)

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                url = f"http://127.0.0.1:{free_port}{WELL_KNOWN_PATH}"
                async with session.get(url) as resp:
                    assert resp.status == 200
                    data = await resp.json()

            assert data["did"] == did_str
            assert "signature" in data
            assert len(data["signature"]) > 0
            assert set(data["capabilities"]) == {"invoke", "delegate"}
        finally:
            await server.stop()

    async def test_async_context_manager(
        self, discovery_keypair: tuple[bytes, bytes], mock_did: str, free_port: int
    ) -> None:
        _, sk = discovery_keypair
        server = DiscoveryServer(mock_did, sk, {"invoke"})

        p1, p2 = _mock_zeroconf_patches()
        with p1, p2:
            async with server:
                await server.start("127.0.0.1", free_port)
                assert server.advertisement is not None

        assert server.advertisement is None

    async def test_refresh_advertisement(
        self, discovery_keypair: tuple[bytes, bytes], mock_did: str, free_port: int
    ) -> None:
        _, sk = discovery_keypair
        server = DiscoveryServer(mock_did, sk, {"invoke"})

        p1, p2 = _mock_zeroconf_patches()
        with p1, p2:
            await server.start("127.0.0.1", free_port)

        try:
            assert server.advertisement is not None
            old_created = server.advertisement.created_at
            time.sleep(0.01)
            server.refresh_advertisement()
            assert server.advertisement is not None
            assert server.advertisement.created_at > old_created
        finally:
            await server.stop()


@pytest.mark.integration
class TestDiscoverAndConnect:
    """Integration test for the full discover-and-connect pipeline."""

    async def test_discover_and_connect_no_services(
        self, discovery_keypair: tuple[bytes, bytes], mock_did: str
    ) -> None:
        _, sk = discovery_keypair
        client = DiscoveryClient(mock_did, sk)

        with pytest.raises(DiscoveryTimeoutError, match="No services found"):
            await client.discover_and_connect(
                capability="invoke",
                connection_factory=lambda: MagicMock(),
            )
