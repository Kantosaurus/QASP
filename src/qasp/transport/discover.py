"""QASP-Discover service discovery.

This module implements service discovery for QASP agents with three
mechanisms: well-known HTTP endpoint, DNS-SD/mDNS, and PQ-signed
capability advertisements.
"""

from __future__ import annotations

import asyncio
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

import cbor2

from qasp.crypto.signatures import sign, verify
from qasp.identity.did import DIDRegistry, get_registry

from .exceptions import AdvertisementError, DiscoveryError, DiscoveryTimeoutError

if TYPE_CHECKING:
    from qasp.protocol.connection import QASPConnection
    from qasp.transport.tcp import TCPTransport

__all__ = [
    "DEFAULT_AD_TTL",
    "DEFAULT_DISCOVERY_TIMEOUT",
    "MDNS_SERVICE_TYPE",
    "WELL_KNOWN_PATH",
    "CapabilityAdvertisement",
    "DiscoveryClient",
    "DiscoveryServer",
    "ServiceEndpoint",
    "create_advertisement",
    "verify_advertisement",
]

# Constants
WELL_KNOWN_PATH = "/.well-known/qasp-agent.json"
MDNS_SERVICE_TYPE = "_qasp._tcp.local."
DEFAULT_AD_TTL = 300  # 5 minutes
DEFAULT_DISCOVERY_TIMEOUT = 10.0


@dataclass(frozen=True)
class CapabilityAdvertisement:
    """A PQ-signed capability advertisement.

    Attributes:
        did: The advertiser's DID string.
        endpoints: Tuple of (host, port) tuples.
        capabilities: Frozenset of capability strings.
        ttl: Time-to-live in seconds.
        created_at: Unix timestamp of creation.
        signature: ML-DSA-65 signature over the CBOR-encoded payload.
    """

    did: str
    endpoints: tuple[tuple[str, int], ...]
    capabilities: frozenset[str]
    ttl: int
    created_at: float
    signature: bytes

    def to_cbor(self) -> bytes:
        """CBOR-encode the payload fields (excluding signature) for signing.

        Uses sorted keys and sorted capabilities for determinism.
        """
        payload: dict[str, Any] = {
            "capabilities": sorted(self.capabilities),
            "created_at": self.created_at,
            "did": self.did,
            "endpoints": [list(ep) for ep in self.endpoints],
            "ttl": self.ttl,
        }
        return cbor2.dumps(payload, canonical=True)

    def is_expired(self, now: float | None = None) -> bool:
        """Check if this advertisement has expired."""
        if now is None:
            now = time.time()
        return self.created_at + self.ttl < now

    def to_well_known_json(self) -> dict[str, Any]:
        """Return JSON representation for the well-known HTTP endpoint."""
        return {
            "did": self.did,
            "endpoints": [{"host": h, "port": p} for h, p in self.endpoints],
            "capabilities": sorted(self.capabilities),
            "ttl": self.ttl,
            "created_at": self.created_at,
            "signature": self.signature.hex(),
        }


@dataclass(frozen=True)
class ServiceEndpoint:
    """A discovered service endpoint."""

    did: str
    host: str
    port: int
    capabilities: frozenset[str]
    last_seen: datetime
    trust_score: float | None


def create_advertisement(
    did: str,
    secret_key: bytes,
    endpoints: list[tuple[str, int]],
    capabilities: set[str],
    ttl: int = DEFAULT_AD_TTL,
) -> CapabilityAdvertisement:
    """Create a signed capability advertisement.

    Args:
        did: The advertiser's DID string.
        secret_key: ML-DSA-65 secret key for signing.
        endpoints: List of (host, port) tuples.
        capabilities: Set of capability strings.
        ttl: Time-to-live in seconds.

    Returns:
        A signed CapabilityAdvertisement.
    """
    created_at = time.time()

    # Build unsigned ad to get CBOR payload
    unsigned = CapabilityAdvertisement(
        did=did,
        endpoints=tuple(endpoints),
        capabilities=frozenset(capabilities),
        ttl=ttl,
        created_at=created_at,
        signature=b"",
    )

    payload = unsigned.to_cbor()
    signature = sign(secret_key, payload)

    return CapabilityAdvertisement(
        did=did,
        endpoints=tuple(endpoints),
        capabilities=frozenset(capabilities),
        ttl=ttl,
        created_at=created_at,
        signature=signature,
    )


def verify_advertisement(
    ad: CapabilityAdvertisement,
    public_key: bytes,
    check_expiry: bool = True,
) -> bool:
    """Verify a capability advertisement's signature and optionally its expiry.

    Args:
        ad: The advertisement to verify.
        public_key: ML-DSA-65 public key of the advertiser.
        check_expiry: Whether to check TTL expiry.

    Returns:
        True if valid.

    Raises:
        AdvertisementError: If verification fails.
    """
    if check_expiry and ad.is_expired():
        raise AdvertisementError("Advertisement has expired")

    # Re-create CBOR payload (excluding signature)
    unsigned = CapabilityAdvertisement(
        did=ad.did,
        endpoints=ad.endpoints,
        capabilities=ad.capabilities,
        ttl=ad.ttl,
        created_at=ad.created_at,
        signature=b"",
    )
    payload = unsigned.to_cbor()

    try:
        return verify(public_key, payload, ad.signature)
    except Exception as e:
        raise AdvertisementError(
            f"Advertisement signature verification failed: {e}"
        ) from e


class DiscoveryClient:
    """QASP-Discover client for finding services."""

    def __init__(
        self,
        local_did: str,
        secret_key: bytes,
        registry: DIDRegistry | None = None,
    ) -> None:
        self._did = local_did
        self._secret_key = secret_key
        self._registry = registry if registry is not None else get_registry()
        self._known_endpoints: dict[str, ServiceEndpoint] = {}
        self._advertisements: dict[str, CapabilityAdvertisement] = {}

        # mDNS state
        self._zeroconf: Any = None
        self._browser: Any = None
        self._mdns_discovered: asyncio.Queue[ServiceEndpoint] = asyncio.Queue()

    def start_browsing(self) -> None:
        """Start browsing for QASP services via mDNS."""
        from zeroconf import ServiceBrowser, ServiceStateChange, Zeroconf

        self._zeroconf = Zeroconf()

        def on_state_change(
            zeroconf: Zeroconf,
            service_type: str,
            name: str,
            state_change: ServiceStateChange,
        ) -> None:
            self._on_mdns_state_change(zeroconf, service_type, name, state_change)

        self._browser = ServiceBrowser(
            self._zeroconf,
            MDNS_SERVICE_TYPE,
            handlers=[on_state_change],
        )

    def stop_browsing(self) -> None:
        """Stop mDNS browsing."""
        if self._browser is not None:
            self._browser.cancel()
            self._browser = None
        if self._zeroconf is not None:
            self._zeroconf.close()
            self._zeroconf = None

    def _on_mdns_state_change(
        self,
        zeroconf: Any,
        service_type: str,
        name: str,
        state_change: Any,
    ) -> None:
        """Handle mDNS service state changes (called from background thread)."""
        from zeroconf import ServiceStateChange

        if state_change != ServiceStateChange.Added:
            return

        info = zeroconf.get_service_info(service_type, name)
        if info is None:
            return

        # Parse TXT records
        properties: dict[str, str] = {}
        if info.properties:
            for key_bytes, val_bytes in info.properties.items():
                key = (
                    key_bytes.decode("utf-8")
                    if isinstance(key_bytes, bytes)
                    else key_bytes
                )
                val = (
                    val_bytes.decode("utf-8")
                    if isinstance(val_bytes, bytes)
                    else str(val_bytes)
                )
                properties[key] = val

        did = properties.get("did", "")
        caps_str = properties.get("caps", "")
        caps = frozenset(c for c in caps_str.split(",") if c)

        addresses = info.parsed_addresses()
        host = addresses[0] if addresses else "127.0.0.1"
        port = info.port or 0

        endpoint = ServiceEndpoint(
            did=did,
            host=host,
            port=port,
            capabilities=caps,
            last_seen=datetime.now(),
            trust_score=None,
        )

        # Bridge into asyncio from background thread
        try:
            loop = asyncio.get_event_loop()
            loop.call_soon_threadsafe(self._mdns_discovered.put_nowait, endpoint)
        except RuntimeError:
            pass  # No event loop available

    async def discover(
        self,
        capability: str | None = None,
        min_trust_score: float = 0.0,
        timeout: float = DEFAULT_DISCOVERY_TIMEOUT,  # noqa: ARG002
    ) -> list[ServiceEndpoint]:
        """Discover available services.

        Evicts expired advertisements, drains the mDNS queue, then
        filters by capability and trust score.

        Args:
            capability: Optional required capability filter.
            min_trust_score: Minimum trust score filter.
            timeout: Not used for blocking; controls staleness window.

        Returns:
            List of matching service endpoints.
        """
        # Evict expired advertisements
        now = time.time()
        expired_dids = [
            did for did, ad in self._advertisements.items() if ad.is_expired(now)
        ]
        for did in expired_dids:
            del self._advertisements[did]
            self._known_endpoints.pop(did, None)

        # Drain mDNS queue
        while not self._mdns_discovered.empty():
            try:
                ep = self._mdns_discovered.get_nowait()
                self._known_endpoints[ep.did] = ep
            except asyncio.QueueEmpty:
                break

        # Filter
        results: list[ServiceEndpoint] = []
        for ep in self._known_endpoints.values():
            if capability and capability not in ep.capabilities:
                continue
            if ep.trust_score is not None and ep.trust_score < min_trust_score:
                continue
            results.append(ep)

        return results

    async def fetch_well_known(
        self,
        host: str,
        port: int = 80,
    ) -> CapabilityAdvertisement:
        """Fetch a capability advertisement from a well-known HTTP endpoint.

        Args:
            host: The host to fetch from.
            port: The HTTP port.

        Returns:
            The verified CapabilityAdvertisement.

        Raises:
            DiscoveryError: If the fetch or verification fails.
        """
        import aiohttp

        url = f"http://{host}:{port}{WELL_KNOWN_PATH}"
        try:
            async with aiohttp.ClientSession() as session, session.get(url) as resp:
                if resp.status != 200:
                    raise DiscoveryError(
                        f"Well-known endpoint returned status {resp.status}"
                    )
                data = await resp.json()
        except DiscoveryError:
            raise
        except Exception as e:
            raise DiscoveryError(
                f"Failed to fetch well-known endpoint: {e}"
            ) from e

        try:
            ad = CapabilityAdvertisement(
                did=data["did"],
                endpoints=tuple(
                    (ep["host"], ep["port"]) for ep in data["endpoints"]
                ),
                capabilities=frozenset(data["capabilities"]),
                ttl=data["ttl"],
                created_at=data["created_at"],
                signature=bytes.fromhex(data["signature"]),
            )
        except (KeyError, ValueError) as e:
            raise DiscoveryError(f"Invalid well-known response: {e}") from e

        # Resolve DID and verify signature
        try:
            doc = self._registry.lookup(ad.did)
            public_key = doc.get_public_key()
            verify_advertisement(ad, public_key)
        except AdvertisementError:
            raise
        except Exception as e:
            raise DiscoveryError(
                f"Advertisement verification failed: {e}"
            ) from e

        self._advertisements[ad.did] = ad
        return ad

    async def announce(
        self,
        host: str,
        port: int,
        capabilities: set[str],
    ) -> None:
        """Announce this agent's service endpoint via mDNS.

        Args:
            host: The service host.
            port: The service port.
            capabilities: Offered capabilities.
        """
        ad = create_advertisement(
            did=self._did,
            secret_key=self._secret_key,
            endpoints=[(host, port)],
            capabilities=capabilities,
        )
        self._advertisements[self._did] = ad

        # Cache the endpoint
        self._known_endpoints[self._did] = ServiceEndpoint(
            did=self._did,
            host=host,
            port=port,
            capabilities=frozenset(capabilities),
            last_seen=datetime.now(),
            trust_score=1.0,
        )

        # Register mDNS service
        from zeroconf import ServiceInfo, Zeroconf

        if self._zeroconf is None:
            self._zeroconf = Zeroconf()

        info = ServiceInfo(
            MDNS_SERVICE_TYPE,
            f"{self._did}.{MDNS_SERVICE_TYPE}",
            addresses=[socket.inet_aton(host)],
            port=port,
            properties={
                "did": self._did,
                "caps": ",".join(sorted(capabilities)),
            },
        )
        self._zeroconf.register_service(info)

    async def discover_and_connect(
        self,
        capability: str,
        connection_factory: Callable[[], QASPConnection],
        timeout: float = DEFAULT_DISCOVERY_TIMEOUT,
    ) -> TCPTransport:
        """Discover a service and connect to it.

        Full pipeline: discover -> verify ad -> resolve DID ->
        check capabilities -> create connection -> TCP connect -> handshake.

        Args:
            capability: Required capability.
            connection_factory: Factory for creating QASPConnection instances.
            timeout: Discovery timeout.

        Returns:
            A connected and handshaked TCPTransport.

        Raises:
            DiscoveryError: If no suitable service is found.
            DiscoveryTimeoutError: If discovery times out.
        """
        from qasp.transport.tcp import TCPTransport as TCPTransportClass

        endpoints = await self.discover(capability=capability, timeout=timeout)
        if not endpoints:
            raise DiscoveryTimeoutError(
                f"No services found with capability '{capability}'"
            )

        # Use the first matching endpoint
        ep = endpoints[0]

        # Verify advertisement if available
        ad = self._advertisements.get(ep.did)
        if ad is not None:
            try:
                doc = self._registry.lookup(ad.did)
                public_key = doc.get_public_key()
                verify_advertisement(ad, public_key)
            except Exception as e:
                raise DiscoveryError(
                    f"Advertisement verification failed for {ep.did}: {e}"
                ) from e

        # Create connection and transport
        connection = connection_factory()
        transport = TCPTransportClass(connection)
        try:
            await transport.connect(ep.host, ep.port, timeout=timeout)
            await transport.perform_handshake(timeout=timeout)
        except Exception as e:
            await transport.close()
            raise DiscoveryError(
                f"Failed to connect to {ep.host}:{ep.port}: {e}"
            ) from e

        return transport


class DiscoveryServer:
    """QASP-Discover server for coordinating discovery."""

    def __init__(
        self,
        did: str,
        secret_key: bytes,
        capabilities: set[str],
        registry: DIDRegistry | None = None,
    ) -> None:
        self._did = did
        self._secret_key = secret_key
        self._capabilities = capabilities
        self._registry = registry if registry is not None else get_registry()

        self._advertisement: CapabilityAdvertisement | None = None
        self._app: Any = None
        self._runner: Any = None
        self._site: Any = None
        self._zeroconf: Any = None
        self._service_info: Any = None

    @property
    def advertisement(self) -> CapabilityAdvertisement | None:
        """Return the current advertisement."""
        return self._advertisement

    async def start(self, host: str, port: int) -> None:
        """Start the discovery server.

        Creates a signed advertisement, starts the HTTP well-known
        endpoint, and registers an mDNS service.

        Args:
            host: The host to bind.
            port: The port to bind.
        """
        # Create signed advertisement
        self._advertisement = create_advertisement(
            did=self._did,
            secret_key=self._secret_key,
            endpoints=[(host, port)],
            capabilities=self._capabilities,
        )

        # Set up aiohttp app
        from aiohttp import web

        self._app = web.Application()
        self._app.router.add_get(WELL_KNOWN_PATH, self._handle_well_known)

        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, host, port)
        await self._site.start()

        # Register mDNS
        await self._register_mdns(host, port)

    async def stop(self) -> None:
        """Stop the discovery server."""
        await self._unregister_mdns()

        if self._site is not None:
            await self._site.stop()
            self._site = None
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None
        self._app = None
        self._advertisement = None

    async def _handle_well_known(self, request: Any) -> Any:  # noqa: ARG002
        """Handle GET requests to the well-known endpoint."""
        from aiohttp import web

        if self._advertisement is None:
            return web.json_response(
                {"error": "No advertisement available"}, status=503
            )
        return web.json_response(self._advertisement.to_well_known_json())

    async def _register_mdns(self, host: str, port: int) -> None:
        """Register mDNS service with TXT records."""
        from zeroconf import ServiceInfo, Zeroconf

        self._zeroconf = Zeroconf()
        self._service_info = ServiceInfo(
            MDNS_SERVICE_TYPE,
            f"{self._did}.{MDNS_SERVICE_TYPE}",
            addresses=[socket.inet_aton(host)],
            port=port,
            properties={
                "did": self._did,
                "caps": ",".join(sorted(self._capabilities)),
            },
        )
        self._zeroconf.register_service(self._service_info)

    async def _unregister_mdns(self) -> None:
        """Unregister mDNS service and close Zeroconf."""
        if self._zeroconf is not None and self._service_info is not None:
            self._zeroconf.unregister_service(self._service_info)
            self._service_info = None
        if self._zeroconf is not None:
            self._zeroconf.close()
            self._zeroconf = None

    def refresh_advertisement(self) -> None:
        """Re-sign the advertisement (e.g. on TTL expiry)."""
        self._advertisement = create_advertisement(
            did=self._did,
            secret_key=self._secret_key,
            endpoints=(
                list(self._advertisement.endpoints)
                if self._advertisement
                else []
            ),
            capabilities=self._capabilities,
        )

    async def __aenter__(self) -> DiscoveryServer:
        """Enter async context manager."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        """Exit async context manager."""
        await self.stop()
