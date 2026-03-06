"""DID Resolver Network with DHT/VDR backend support.

This module implements a distributed DID resolution mechanism where DID Documents
are published to a persistent store (DHT/VDR), enabling offline resolution for
delegation chain verification, revocation cascades, and audit/forensics.

The resolver provides multi-tier resolution:
  L1: Local cache (fast, configurable TTL)
  L2: DIDRegistry (in-memory, direct exchange)
  L3: DHT backend (persistent, supports offline resolution)
"""

from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

import cbor2

from qasp.crypto.signatures import sign, verify
from qasp.identity.did import (
    DID,
    DIDDocument,
    DIDRegistry,
    VerificationMethod,
    decode_public_key_multibase,
)
from qasp.identity.exceptions import (
    DHTEntryError,
    DIDResolutionError,
    StaleEntryError,
)

if TYPE_CHECKING:
    pass

__all__ = [
    "DHTEntry",
    "DIDResolverNetwork",
    "InMemoryBackend",
    "ResolverBackend",
    "SQLiteBackend",
    "create_dht_entry",
    "get_resolver",
    "resolve_did_document",
    "verify_dht_entry",
]


# =============================================================================
# DHT Entry
# =============================================================================


@dataclass(frozen=True)
class DHTEntry:
    """A signed DHT entry containing a DID Document.

    Attributes:
        did: The DID string (e.g., "did:qasp:z6Mk...").
        did_document: The full DID Document.
        version: Monotonically increasing version number.
        timestamp: Unix epoch seconds when the entry was created.
        signature: ML-DSA-65 signature over the CBOR-encoded payload.
    """

    did: str
    did_document: DIDDocument
    version: int
    timestamp: int
    signature: bytes


def _encode_dht_payload(
    did: str,
    did_document: DIDDocument,
    version: int,
    timestamp: int,
) -> bytes:
    """CBOR-encode the signable DHT payload.

    Uses canonical CBOR encoding for deterministic signatures.
    """
    payload = {
        "did": did,
        "did_document": did_document.to_dict(),
        "version": version,
        "timestamp": timestamp,
    }
    return cbor2.dumps(payload, canonical=True)


def create_dht_entry(
    did_document: DIDDocument,
    secret_key: bytes,
    version: int = 1,
    timestamp: int | None = None,
) -> DHTEntry:
    """Create and sign a DHT entry for a DID Document.

    Args:
        did_document: The DID Document to publish.
        secret_key: The ML-DSA-65 secret key for signing.
        version: Entry version (monotonically increasing). Defaults to 1.
        timestamp: Unix epoch seconds. Auto-generated if None.

    Returns:
        A signed DHTEntry.
    """
    did_str = str(did_document.did)
    ts = timestamp if timestamp is not None else int(time.time())

    payload = _encode_dht_payload(did_str, did_document, version, ts)
    signature = sign(secret_key, payload)

    return DHTEntry(
        did=did_str,
        did_document=did_document,
        version=version,
        timestamp=ts,
        signature=signature,
    )


def verify_dht_entry(entry: DHTEntry) -> bool:
    """Verify the signature on a DHT entry.

    Extracts the public key from the entry's DID Document and verifies
    the ML-DSA-65 signature over the CBOR-encoded payload.

    Args:
        entry: The DHT entry to verify.

    Returns:
        True if the signature is valid.

    Raises:
        DHTEntryError: If signature verification fails.
    """
    try:
        public_key = entry.did_document.get_public_key()
    except Exception as e:
        raise DHTEntryError(f"Cannot extract public key from DHT entry: {e}") from e

    payload = _encode_dht_payload(
        entry.did, entry.did_document, entry.version, entry.timestamp
    )

    try:
        verify(public_key, payload, entry.signature)
    except Exception as e:
        raise DHTEntryError(f"DHT entry signature verification failed: {e}") from e

    return True


# =============================================================================
# Resolver Backend Protocol
# =============================================================================


@runtime_checkable
class ResolverBackend(Protocol):
    """Protocol for DHT/VDR backend storage."""

    def store(self, entry: DHTEntry) -> None:
        """Store a DHT entry. Reject if version <= existing version.

        Raises:
            StaleEntryError: If the entry version <= existing version.
        """
        ...

    def fetch(self, did: str) -> DHTEntry | None:
        """Fetch the latest DHT entry for a DID, or None if not found."""
        ...

    def remove(self, did: str) -> bool:
        """Remove a DHT entry. Return True if removed, False if not found."""
        ...


# =============================================================================
# In-Memory Backend
# =============================================================================


class InMemoryBackend:
    """Thread-safe in-memory DHT backend."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, DHTEntry] = {}

    def store(self, entry: DHTEntry) -> None:
        with self._lock:
            existing = self._entries.get(entry.did)
            if existing is not None and entry.version <= existing.version:
                raise StaleEntryError(
                    f"Entry version {entry.version} <= existing version {existing.version}"
                )
            self._entries[entry.did] = entry

    def fetch(self, did: str) -> DHTEntry | None:
        with self._lock:
            return self._entries.get(did)

    def remove(self, did: str) -> bool:
        with self._lock:
            if did in self._entries:
                del self._entries[did]
                return True
            return False


# =============================================================================
# SQLite Backend
# =============================================================================


def _reconstruct_did_document(doc_dict: dict) -> DIDDocument:
    """Reconstruct a DIDDocument from its dictionary representation.

    Parses the output of DIDDocument.to_dict() back into frozen dataclass hierarchy.
    """
    did_str = doc_dict["id"]
    did = DID.parse(did_str)

    verification_methods = tuple(
        VerificationMethod(
            id=vm["id"],
            type=vm["type"],
            controller=vm["controller"],
            public_key_multibase=vm["publicKeyMultibase"],
        )
        for vm in doc_dict.get("verificationMethod", [])
    )

    authentication = tuple(doc_dict.get("authentication", []))
    assertion_method = tuple(doc_dict.get("assertionMethod", []))

    service_endpoints: dict[str, str] = {}
    for svc in doc_dict.get("service", []):
        service_endpoints[svc["type"]] = svc["serviceEndpoint"]

    next_key_hash: bytes | None = None
    if "nextKeyHash" in doc_dict and doc_dict["nextKeyHash"] is not None:
        next_key_hash = bytes.fromhex(doc_dict["nextKeyHash"])

    key_version = doc_dict.get("keyVersion", 1)

    return DIDDocument(
        did=did,
        verification_methods=verification_methods,
        authentication=authentication,
        assertion_method=assertion_method,
        service_endpoints=service_endpoints,
        next_key_hash=next_key_hash,
        key_version=key_version,
    )


_SCHEMA = """\
CREATE TABLE IF NOT EXISTS dht_entries (
    did TEXT PRIMARY KEY,
    did_document_cbor BLOB NOT NULL,
    version INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    signature BLOB NOT NULL
)"""


class SQLiteBackend:
    """SQLite-backed DHT backend using stdlib sqlite3."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute(_SCHEMA)
        self._conn.commit()

    def store(self, entry: DHTEntry) -> None:
        doc_cbor = cbor2.dumps(entry.did_document.to_dict(), canonical=True)
        with self._lock:
            row = self._conn.execute(
                "SELECT version FROM dht_entries WHERE did = ?", (entry.did,)
            ).fetchone()
            if row is not None and entry.version <= row[0]:
                raise StaleEntryError(
                    f"Entry version {entry.version} <= existing version {row[0]}"
                )
            self._conn.execute(
                "INSERT OR REPLACE INTO dht_entries (did, did_document_cbor, version, timestamp, signature) "
                "VALUES (?, ?, ?, ?, ?)",
                (entry.did, doc_cbor, entry.version, entry.timestamp, entry.signature),
            )
            self._conn.commit()

    def fetch(self, did: str) -> DHTEntry | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT did_document_cbor, version, timestamp, signature FROM dht_entries WHERE did = ?",
                (did,),
            ).fetchone()
        if row is None:
            return None
        doc_cbor, version, timestamp, signature = row
        doc_dict = cbor2.loads(doc_cbor)
        did_document = _reconstruct_did_document(doc_dict)
        return DHTEntry(
            did=did,
            did_document=did_document,
            version=version,
            timestamp=timestamp,
            signature=bytes(signature),
        )

    def remove(self, did: str) -> bool:
        with self._lock:
            cursor = self._conn.execute("DELETE FROM dht_entries WHERE did = ?", (did,))
            self._conn.commit()
            return cursor.rowcount > 0

    def close(self) -> None:
        """Close the SQLite connection."""
        self._conn.close()


# =============================================================================
# Resolver Cache
# =============================================================================


@dataclass(frozen=True)
class _CacheEntry:
    """Internal cache entry for resolved DID Documents."""

    document: DIDDocument
    fetched_at: float
    version: int


class _ResolverCache:
    """Thread-safe TTL cache for DID resolution results."""

    def __init__(self, ttl: float = 300.0) -> None:
        self._ttl = ttl
        self._lock = threading.Lock()
        self._entries: dict[str, _CacheEntry] = {}

    def get(self, did: str) -> DIDDocument | None:
        with self._lock:
            entry = self._entries.get(did)
        if entry is None:
            return None
        if time.monotonic() - entry.fetched_at > self._ttl:
            self.invalidate(did)
            return None
        return entry.document

    def put(self, did: str, document: DIDDocument, version: int = 0) -> None:
        entry = _CacheEntry(
            document=document,
            fetched_at=time.monotonic(),
            version=version,
        )
        with self._lock:
            self._entries[did] = entry

    def invalidate(self, did: str) -> None:
        with self._lock:
            self._entries.pop(did, None)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


# =============================================================================
# DID Resolver Network
# =============================================================================


class DIDResolverNetwork:
    """Multi-tier DID resolver with cache, registry, and DHT backend.

    Resolution priority: L1 cache > L2 DIDRegistry > L3 DHT backend.

    This class satisfies the DIDResolver Protocol from capability.py,
    providing a resolve(did) -> bytes method for public key resolution.
    """

    def __init__(
        self,
        backend: ResolverBackend | None = None,
        registry: DIDRegistry | None = None,
        cache_ttl: float = 300.0,
        verify_signatures: bool = True,
    ) -> None:
        self._backend = backend if backend is not None else InMemoryBackend()
        self._registry = registry
        self._cache = _ResolverCache(ttl=cache_ttl)
        self._verify_signatures = verify_signatures

    def resolve(self, did: DID) -> bytes:
        """Resolve a DID to its public key bytes.

        Satisfies the DIDResolver Protocol from capability.py.

        Args:
            did: The DID to resolve.

        Returns:
            The public key bytes.

        Raises:
            DIDResolutionError: If resolution fails.
        """
        document = self.resolve_document(did)
        return document.get_public_key()

    def resolve_document(self, did: DID | str) -> DIDDocument:
        """Multi-tier DID Document resolution.

        Resolution order:
          1. L1: Local cache
          2. L2: DIDRegistry (if provided)
          3. L3: DHT backend

        Args:
            did: The DID to resolve (DID object or string).

        Returns:
            The resolved DIDDocument.

        Raises:
            DIDResolutionError: If the DID cannot be resolved at any tier.
        """
        did_str = str(did)

        # L1: Cache
        cached = self._cache.get(did_str)
        if cached is not None:
            return cached

        # L2: Registry
        if self._registry is not None:
            try:
                document = self._registry.lookup(did_str)
                self._cache.put(did_str, document)
                return document
            except DIDResolutionError:
                pass

        # L3: DHT backend
        entry = self._backend.fetch(did_str)
        if entry is not None:
            if self._verify_signatures:
                verify_dht_entry(entry)
            self._cache.put(did_str, entry.did_document, entry.version)
            return entry.did_document

        raise DIDResolutionError(f"DID not found: {did_str}")

    def publish(
        self,
        did_document: DIDDocument,
        secret_key: bytes,
        version: int | None = None,
    ) -> DHTEntry:
        """Publish a DID Document to the DHT backend.

        Creates a signed DHT entry and stores it. If version is None,
        auto-increments based on the existing entry version.

        Args:
            did_document: The DID Document to publish.
            secret_key: The ML-DSA-65 secret key for signing.
            version: Explicit version, or None to auto-increment.

        Returns:
            The created and stored DHTEntry.
        """
        did_str = str(did_document.did)

        if version is None:
            existing = self._backend.fetch(did_str)
            version = (existing.version + 1) if existing is not None else 1

        entry = create_dht_entry(did_document, secret_key, version=version)
        self._backend.store(entry)
        self._cache.put(did_str, did_document, version)
        return entry

    def publish_entry(self, entry: DHTEntry) -> None:
        """Store a pre-built DHT entry (e.g., received from a peer).

        Verifies the signature before storing.

        Args:
            entry: The DHT entry to store.

        Raises:
            DHTEntryError: If signature verification fails.
            StaleEntryError: If entry version <= existing version.
        """
        verify_dht_entry(entry)
        self._backend.store(entry)
        self._cache.put(entry.did, entry.did_document, entry.version)

    def invalidate_cache(self, did: DID | str) -> None:
        """Invalidate the cache entry for a DID.

        Args:
            did: The DID to invalidate.
        """
        self._cache.invalidate(str(did))


# =============================================================================
# Module-level Singleton
# =============================================================================

_resolver: DIDResolverNetwork | None = None
_resolver_lock = threading.Lock()


def get_resolver() -> DIDResolverNetwork:
    """Get the module-level DIDResolverNetwork singleton.

    Returns:
        The shared DIDResolverNetwork instance.
    """
    global _resolver
    if _resolver is None:
        with _resolver_lock:
            if _resolver is None:
                _resolver = DIDResolverNetwork()
    return _resolver


def resolve_did_document(did: DID | str) -> DIDDocument:
    """Resolve a DID Document using the module-level singleton.

    Convenience function wrapping get_resolver().resolve_document().

    Args:
        did: The DID to resolve.

    Returns:
        The resolved DIDDocument.

    Raises:
        DIDResolutionError: If resolution fails.
    """
    return get_resolver().resolve_document(did)
