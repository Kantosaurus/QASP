"""Network transport layer.

This module provides transport implementations:
- TCP transport with length-prefixed framing
- QASP-Discover for service discovery
"""

from .discover import (
    DEFAULT_AD_TTL,
    DEFAULT_DISCOVERY_TIMEOUT,
    MDNS_SERVICE_TYPE,
    WELL_KNOWN_PATH,
    CapabilityAdvertisement,
    DiscoveryClient,
    DiscoveryServer,
    ServiceEndpoint,
    create_advertisement,
    verify_advertisement,
)
from .exceptions import (
    AdvertisementError,
    ConnectionClosedError,
    ConnectionError,
    ConnectionRefusedError,
    ConnectionTimeoutError,
    DiscoveryError,
    DiscoveryTimeoutError,
    FramingError,
    ReceiveError,
    SendError,
    TransportError,
)
from .tcp import (
    DEFAULT_READ_SIZE,
    LENGTH_PREFIX_SIZE,
    MAX_MESSAGE_SIZE,
    TCPServer,
    TCPTransport,
    connect,
    listen,
    serve,
)

__all__ = [
    "DEFAULT_AD_TTL",
    "DEFAULT_DISCOVERY_TIMEOUT",
    "DEFAULT_READ_SIZE",
    "LENGTH_PREFIX_SIZE",
    "MAX_MESSAGE_SIZE",
    "MDNS_SERVICE_TYPE",
    "WELL_KNOWN_PATH",
    "AdvertisementError",
    "CapabilityAdvertisement",
    "ConnectionClosedError",
    "ConnectionError",
    "ConnectionRefusedError",
    "ConnectionTimeoutError",
    "DiscoveryClient",
    "DiscoveryError",
    "DiscoveryServer",
    "DiscoveryTimeoutError",
    "FramingError",
    "ReceiveError",
    "SendError",
    "ServiceEndpoint",
    "TCPServer",
    "TCPTransport",
    "TransportError",
    "connect",
    "create_advertisement",
    "discover",
    "listen",
    "serve",
    "tcp",
    "verify_advertisement",
]
