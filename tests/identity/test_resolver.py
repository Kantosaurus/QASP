"""Tests for DID Resolver Network (DHT/VDR)."""

from __future__ import annotations

import dataclasses
import time
from unittest.mock import patch

import pytest

from qasp.crypto.signatures import generate_keypair, sign
from qasp.identity import DIDDocument, DIDRegistry, create_did
from qasp.identity.exceptions import DHTEntryError, DIDResolutionError, StaleEntryError
from qasp.identity.resolver import (
    DHTEntry,
    DIDResolverNetwork,
    InMemoryBackend,
    SQLiteBackend,
    _ResolverCache,
    _encode_dht_payload,
    create_dht_entry,
    verify_dht_entry,
)


# =============================================================================
# TestDHTEntry
# =============================================================================


class TestDHTEntry:
    """Tests for DHTEntry creation and structure."""

    def test_create_returns_frozen_dataclass(
        self, sample_did_document: DIDDocument, agent_secret_key: bytes
    ) -> None:
        entry = create_dht_entry(sample_did_document, agent_secret_key)
        assert isinstance(entry, DHTEntry)
        with pytest.raises(dataclasses.FrozenInstanceError):
            entry.version = 99  # type: ignore[misc]

    def test_create_has_correct_fields(
        self, sample_did_document: DIDDocument, agent_secret_key: bytes
    ) -> None:
        entry = create_dht_entry(sample_did_document, agent_secret_key)
        assert entry.did == str(sample_did_document.did)
        assert entry.did_document == sample_did_document
        assert entry.version == 1
        assert isinstance(entry.timestamp, int)
        assert isinstance(entry.signature, bytes)
        assert len(entry.signature) > 0

    def test_signs_with_ml_dsa_65(
        self, sample_did_document: DIDDocument, agent_secret_key: bytes
    ) -> None:
        entry = create_dht_entry(sample_did_document, agent_secret_key)
        # Signature should be verifiable
        assert verify_dht_entry(entry) is True

    def test_default_version_is_1(
        self, sample_did_document: DIDDocument, agent_secret_key: bytes
    ) -> None:
        entry = create_dht_entry(sample_did_document, agent_secret_key)
        assert entry.version == 1

    def test_custom_version(
        self, sample_did_document: DIDDocument, agent_secret_key: bytes
    ) -> None:
        entry = create_dht_entry(sample_did_document, agent_secret_key, version=42)
        assert entry.version == 42

    def test_auto_timestamp(
        self, sample_did_document: DIDDocument, agent_secret_key: bytes
    ) -> None:
        before = int(time.time())
        entry = create_dht_entry(sample_did_document, agent_secret_key)
        after = int(time.time())
        assert before <= entry.timestamp <= after

    def test_custom_timestamp(
        self, sample_did_document: DIDDocument, agent_secret_key: bytes
    ) -> None:
        ts = 1700000000
        entry = create_dht_entry(sample_did_document, agent_secret_key, timestamp=ts)
        assert entry.timestamp == ts

    def test_cbor_payload_is_deterministic(
        self, sample_did_document: DIDDocument
    ) -> None:
        payload1 = _encode_dht_payload(
            str(sample_did_document.did), sample_did_document, 1, 1000
        )
        payload2 = _encode_dht_payload(
            str(sample_did_document.did), sample_did_document, 1, 1000
        )
        assert payload1 == payload2

    def test_cbor_payload_excludes_signature(
        self, sample_did_document: DIDDocument, agent_secret_key: bytes
    ) -> None:
        entry = create_dht_entry(sample_did_document, agent_secret_key)
        payload = _encode_dht_payload(
            entry.did, entry.did_document, entry.version, entry.timestamp
        )
        assert entry.signature not in payload


# =============================================================================
# TestVerifyDHTEntry
# =============================================================================


class TestVerifyDHTEntry:
    """Tests for DHT entry signature verification."""

    def test_valid_entry_verifies(
        self, sample_did_document: DIDDocument, agent_secret_key: bytes
    ) -> None:
        entry = create_dht_entry(sample_did_document, agent_secret_key)
        assert verify_dht_entry(entry) is True

    def test_tampered_version_fails(
        self, sample_did_document: DIDDocument, agent_secret_key: bytes
    ) -> None:
        entry = create_dht_entry(sample_did_document, agent_secret_key)
        tampered = DHTEntry(
            did=entry.did,
            did_document=entry.did_document,
            version=entry.version + 1,
            timestamp=entry.timestamp,
            signature=entry.signature,
        )
        with pytest.raises(DHTEntryError, match="signature verification failed"):
            verify_dht_entry(tampered)

    def test_tampered_timestamp_fails(
        self, sample_did_document: DIDDocument, agent_secret_key: bytes
    ) -> None:
        entry = create_dht_entry(sample_did_document, agent_secret_key)
        tampered = DHTEntry(
            did=entry.did,
            did_document=entry.did_document,
            version=entry.version,
            timestamp=entry.timestamp + 1,
            signature=entry.signature,
        )
        with pytest.raises(DHTEntryError, match="signature verification failed"):
            verify_dht_entry(tampered)

    def test_tampered_signature_fails(
        self, sample_did_document: DIDDocument, agent_secret_key: bytes
    ) -> None:
        entry = create_dht_entry(sample_did_document, agent_secret_key)
        tampered = DHTEntry(
            did=entry.did,
            did_document=entry.did_document,
            version=entry.version,
            timestamp=entry.timestamp,
            signature=b"\x00" * len(entry.signature),
        )
        with pytest.raises(DHTEntryError, match="signature verification failed"):
            verify_dht_entry(tampered)

    def test_tampered_document_fails(
        self, agent_secret_key: bytes
    ) -> None:
        # Create entry with one document, then swap in a different document
        pk1, sk1 = generate_keypair()
        pk2, _ = generate_keypair()
        _, doc1 = create_did(pk1)
        _, doc2 = create_did(pk2)
        entry = create_dht_entry(doc1, sk1)
        tampered = DHTEntry(
            did=entry.did,
            did_document=doc2,
            version=entry.version,
            timestamp=entry.timestamp,
            signature=entry.signature,
        )
        with pytest.raises(DHTEntryError):
            verify_dht_entry(tampered)


# =============================================================================
# TestInMemoryBackend
# =============================================================================


class TestInMemoryBackend:
    """Tests for InMemoryBackend."""

    def test_store_and_fetch_roundtrip(
        self,
        in_memory_backend: InMemoryBackend,
        sample_did_document: DIDDocument,
        agent_secret_key: bytes,
    ) -> None:
        entry = create_dht_entry(sample_did_document, agent_secret_key)
        in_memory_backend.store(entry)
        fetched = in_memory_backend.fetch(entry.did)
        assert fetched is not None
        assert fetched.did == entry.did
        assert fetched.version == entry.version

    def test_fetch_nonexistent_returns_none(
        self, in_memory_backend: InMemoryBackend
    ) -> None:
        assert in_memory_backend.fetch("did:qasp:nonexistent") is None

    def test_higher_version_overwrites(
        self,
        in_memory_backend: InMemoryBackend,
        sample_did_document: DIDDocument,
        agent_secret_key: bytes,
    ) -> None:
        entry1 = create_dht_entry(sample_did_document, agent_secret_key, version=1)
        entry2 = create_dht_entry(sample_did_document, agent_secret_key, version=2)
        in_memory_backend.store(entry1)
        in_memory_backend.store(entry2)
        fetched = in_memory_backend.fetch(entry1.did)
        assert fetched is not None
        assert fetched.version == 2

    def test_same_version_raises_stale(
        self,
        in_memory_backend: InMemoryBackend,
        sample_did_document: DIDDocument,
        agent_secret_key: bytes,
    ) -> None:
        entry = create_dht_entry(sample_did_document, agent_secret_key, version=1)
        in_memory_backend.store(entry)
        with pytest.raises(StaleEntryError):
            in_memory_backend.store(entry)

    def test_lower_version_raises_stale(
        self,
        in_memory_backend: InMemoryBackend,
        sample_did_document: DIDDocument,
        agent_secret_key: bytes,
    ) -> None:
        entry2 = create_dht_entry(sample_did_document, agent_secret_key, version=2)
        entry1 = create_dht_entry(sample_did_document, agent_secret_key, version=1)
        in_memory_backend.store(entry2)
        with pytest.raises(StaleEntryError):
            in_memory_backend.store(entry1)

    def test_remove_existing(
        self,
        in_memory_backend: InMemoryBackend,
        sample_did_document: DIDDocument,
        agent_secret_key: bytes,
    ) -> None:
        entry = create_dht_entry(sample_did_document, agent_secret_key)
        in_memory_backend.store(entry)
        assert in_memory_backend.remove(entry.did) is True
        assert in_memory_backend.fetch(entry.did) is None

    def test_remove_nonexistent(self, in_memory_backend: InMemoryBackend) -> None:
        assert in_memory_backend.remove("did:qasp:nonexistent") is False


# =============================================================================
# TestSQLiteBackend
# =============================================================================


class TestSQLiteBackend:
    """Tests for SQLiteBackend."""

    def test_store_and_fetch_roundtrip(
        self,
        sqlite_backend: SQLiteBackend,
        sample_did_document: DIDDocument,
        agent_secret_key: bytes,
    ) -> None:
        entry = create_dht_entry(sample_did_document, agent_secret_key)
        sqlite_backend.store(entry)
        fetched = sqlite_backend.fetch(entry.did)
        assert fetched is not None
        assert fetched.did == entry.did
        assert fetched.version == entry.version
        assert fetched.did_document.did == entry.did_document.did

    def test_fetch_nonexistent_returns_none(
        self, sqlite_backend: SQLiteBackend
    ) -> None:
        assert sqlite_backend.fetch("did:qasp:nonexistent") is None

    def test_higher_version_overwrites(
        self,
        sqlite_backend: SQLiteBackend,
        sample_did_document: DIDDocument,
        agent_secret_key: bytes,
    ) -> None:
        entry1 = create_dht_entry(sample_did_document, agent_secret_key, version=1)
        entry2 = create_dht_entry(sample_did_document, agent_secret_key, version=2)
        sqlite_backend.store(entry1)
        sqlite_backend.store(entry2)
        fetched = sqlite_backend.fetch(entry1.did)
        assert fetched is not None
        assert fetched.version == 2

    def test_same_version_raises_stale(
        self,
        sqlite_backend: SQLiteBackend,
        sample_did_document: DIDDocument,
        agent_secret_key: bytes,
    ) -> None:
        entry = create_dht_entry(sample_did_document, agent_secret_key, version=1)
        sqlite_backend.store(entry)
        with pytest.raises(StaleEntryError):
            sqlite_backend.store(entry)

    def test_lower_version_raises_stale(
        self,
        sqlite_backend: SQLiteBackend,
        sample_did_document: DIDDocument,
        agent_secret_key: bytes,
    ) -> None:
        entry2 = create_dht_entry(sample_did_document, agent_secret_key, version=2)
        entry1 = create_dht_entry(sample_did_document, agent_secret_key, version=1)
        sqlite_backend.store(entry2)
        with pytest.raises(StaleEntryError):
            sqlite_backend.store(entry1)

    def test_remove_existing(
        self,
        sqlite_backend: SQLiteBackend,
        sample_did_document: DIDDocument,
        agent_secret_key: bytes,
    ) -> None:
        entry = create_dht_entry(sample_did_document, agent_secret_key)
        sqlite_backend.store(entry)
        assert sqlite_backend.remove(entry.did) is True
        assert sqlite_backend.fetch(entry.did) is None

    def test_remove_nonexistent(self, sqlite_backend: SQLiteBackend) -> None:
        assert sqlite_backend.remove("did:qasp:nonexistent") is False

    def test_persistence_across_reopen(self, tmp_path: object) -> None:
        import pathlib

        db_path = str(pathlib.Path(str(tmp_path)) / "persist.db")
        pk, sk = generate_keypair()
        _, doc = create_did(pk)
        entry = create_dht_entry(doc, sk)

        backend1 = SQLiteBackend(db_path)
        backend1.store(entry)
        backend1.close()

        backend2 = SQLiteBackend(db_path)
        fetched = backend2.fetch(entry.did)
        backend2.close()
        assert fetched is not None
        assert fetched.version == entry.version
        assert fetched.did == entry.did

    def test_memory_mode_works(self) -> None:
        pk, sk = generate_keypair()
        _, doc = create_did(pk)
        entry = create_dht_entry(doc, sk)

        backend = SQLiteBackend(":memory:")
        backend.store(entry)
        fetched = backend.fetch(entry.did)
        assert fetched is not None
        assert fetched.did == entry.did


# =============================================================================
# TestResolverCache
# =============================================================================


class TestResolverCache:
    """Tests for _ResolverCache."""

    def test_cache_hit(self, sample_did_document: DIDDocument) -> None:
        cache = _ResolverCache(ttl=300.0)
        did_str = str(sample_did_document.did)
        cache.put(did_str, sample_did_document)
        assert cache.get(did_str) == sample_did_document

    def test_cache_miss(self) -> None:
        cache = _ResolverCache(ttl=300.0)
        assert cache.get("did:qasp:nonexistent") is None

    def test_cache_expiry(self, sample_did_document: DIDDocument) -> None:
        cache = _ResolverCache(ttl=0.0)  # Immediate expiry
        did_str = str(sample_did_document.did)
        cache.put(did_str, sample_did_document)
        assert cache.get(did_str) is None

    def test_cache_invalidation(self, sample_did_document: DIDDocument) -> None:
        cache = _ResolverCache(ttl=300.0)
        did_str = str(sample_did_document.did)
        cache.put(did_str, sample_did_document)
        cache.invalidate(did_str)
        assert cache.get(did_str) is None

    def test_cache_clear(self, sample_did_document: DIDDocument) -> None:
        cache = _ResolverCache(ttl=300.0)
        did_str = str(sample_did_document.did)
        cache.put(did_str, sample_did_document)
        cache.clear()
        assert cache.get(did_str) is None


# =============================================================================
# TestDIDResolverNetwork
# =============================================================================


class TestDIDResolverNetwork:
    """Tests for the multi-tier DID Resolver Network."""

    def test_resolve_from_backend(
        self, sample_did_document: DIDDocument, agent_secret_key: bytes
    ) -> None:
        resolver = DIDResolverNetwork()
        resolver.publish(sample_did_document, agent_secret_key)
        result = resolver.resolve_document(sample_did_document.did)
        assert result.did == sample_did_document.did

    def test_resolve_from_registry(
        self, sample_did_document: DIDDocument
    ) -> None:
        registry = DIDRegistry()
        registry.register(sample_did_document)
        resolver = DIDResolverNetwork(registry=registry)
        result = resolver.resolve_document(sample_did_document.did)
        assert result.did == sample_did_document.did

    def test_resolve_from_cache(
        self, sample_did_document: DIDDocument, agent_secret_key: bytes
    ) -> None:
        resolver = DIDResolverNetwork()
        resolver.publish(sample_did_document, agent_secret_key)
        # First call populates cache
        resolver.resolve_document(sample_did_document.did)
        # Second call should hit cache (even if backend were removed)
        result = resolver.resolve_document(sample_did_document.did)
        assert result.did == sample_did_document.did

    def test_resolution_priority_cache_over_registry(
        self, agent_secret_key: bytes
    ) -> None:
        pk1, _ = generate_keypair()
        pk2, sk2 = generate_keypair()
        _, doc1 = create_did(pk1)
        _, doc2 = create_did(pk2)

        registry = DIDRegistry()
        registry.register(doc1)

        resolver = DIDResolverNetwork(registry=registry)
        # Manually populate cache with doc1
        resolver.resolve_document(doc1.did)
        # Registry lookup should hit cache first
        result = resolver.resolve_document(doc1.did)
        assert result.did == doc1.did

    def test_resolution_priority_registry_over_backend(
        self, agent_secret_key: bytes
    ) -> None:
        pk, sk = generate_keypair()
        _, doc = create_did(pk)

        registry = DIDRegistry()
        registry.register(doc)
        backend = InMemoryBackend()

        resolver = DIDResolverNetwork(backend=backend, registry=registry)
        result = resolver.resolve_document(doc.did)
        assert result.did == doc.did
        # Backend was never queried (no entry stored)
        assert backend.fetch(str(doc.did)) is None

    def test_not_found_raises(self) -> None:
        resolver = DIDResolverNetwork()
        with pytest.raises(DIDResolutionError, match="DID not found"):
            resolver.resolve_document("did:qasp:nonexistent")

    def test_publish_creates_entry(
        self, sample_did_document: DIDDocument, agent_secret_key: bytes
    ) -> None:
        resolver = DIDResolverNetwork()
        entry = resolver.publish(sample_did_document, agent_secret_key)
        assert entry.version == 1
        assert entry.did == str(sample_did_document.did)

    def test_publish_auto_increments_version(
        self, sample_did_document: DIDDocument, agent_secret_key: bytes
    ) -> None:
        resolver = DIDResolverNetwork()
        entry1 = resolver.publish(sample_did_document, agent_secret_key)
        assert entry1.version == 1
        entry2 = resolver.publish(sample_did_document, agent_secret_key)
        assert entry2.version == 2

    def test_publish_entry_verifies_signature(
        self, sample_did_document: DIDDocument, agent_secret_key: bytes
    ) -> None:
        entry = create_dht_entry(sample_did_document, agent_secret_key)
        resolver = DIDResolverNetwork()
        resolver.publish_entry(entry)  # Should not raise
        result = resolver.resolve_document(sample_did_document.did)
        assert result.did == sample_did_document.did

    def test_publish_entry_rejects_stale(
        self, sample_did_document: DIDDocument, agent_secret_key: bytes
    ) -> None:
        entry2 = create_dht_entry(sample_did_document, agent_secret_key, version=2)
        entry1 = create_dht_entry(sample_did_document, agent_secret_key, version=1)
        resolver = DIDResolverNetwork()
        resolver.publish_entry(entry2)
        with pytest.raises(StaleEntryError):
            resolver.publish_entry(entry1)

    def test_resolve_verifies_backend_signatures(
        self, sample_did_document: DIDDocument, agent_secret_key: bytes
    ) -> None:
        backend = InMemoryBackend()
        entry = create_dht_entry(sample_did_document, agent_secret_key)
        backend.store(entry)

        resolver = DIDResolverNetwork(backend=backend, verify_signatures=True)
        result = resolver.resolve_document(sample_did_document.did)
        assert result.did == sample_did_document.did

    def test_invalidate_cache_forces_refetch(
        self, sample_did_document: DIDDocument, agent_secret_key: bytes
    ) -> None:
        resolver = DIDResolverNetwork()
        resolver.publish(sample_did_document, agent_secret_key)
        resolver.resolve_document(sample_did_document.did)  # Populate cache
        resolver.invalidate_cache(sample_did_document.did)
        # Should still resolve from backend
        result = resolver.resolve_document(sample_did_document.did)
        assert result.did == sample_did_document.did


# =============================================================================
# TestProtocolCompliance
# =============================================================================


class TestProtocolCompliance:
    """Tests that DIDResolverNetwork satisfies the DIDResolver Protocol."""

    def test_satisfies_did_resolver_protocol(self) -> None:
        from qasp.protocol.capability import DIDResolver

        resolver = DIDResolverNetwork()
        assert isinstance(resolver, DIDResolver)

    def test_resolve_returns_public_key_bytes(
        self, sample_did_document: DIDDocument, agent_secret_key: bytes, agent_public_key: bytes
    ) -> None:
        resolver = DIDResolverNetwork()
        resolver.publish(sample_did_document, agent_secret_key)
        result = resolver.resolve(sample_did_document.did)
        assert isinstance(result, bytes)
        assert result == agent_public_key


# =============================================================================
# TestSingleton
# =============================================================================


class TestSingleton:
    """Tests for module-level singleton."""

    def test_get_resolver_returns_same_instance(self) -> None:
        import qasp.identity.resolver as mod

        # Reset singleton for test
        mod._resolver = None
        r1 = mod.get_resolver()
        r2 = mod.get_resolver()
        assert r1 is r2
        # Cleanup
        mod._resolver = None

    def test_resolve_did_document_uses_singleton(
        self, sample_did_document: DIDDocument, agent_secret_key: bytes
    ) -> None:
        import qasp.identity.resolver as mod

        # Reset and publish to singleton
        mod._resolver = None
        resolver = mod.get_resolver()
        resolver.publish(sample_did_document, agent_secret_key)
        result = mod.resolve_did_document(sample_did_document.did)
        assert result.did == sample_did_document.did
        # Cleanup
        mod._resolver = None
