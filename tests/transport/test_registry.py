"""Tests for registry-based agent discovery."""

from __future__ import annotations

import time

import cbor2
import pytest

from qasp.crypto.signatures import generate_keypair
from qasp.identity.did import DIDDocument, DIDRegistry, create_did
from qasp.transport.exceptions import (
    RegistryEntryError,
    RegistrySignatureError,
)
from qasp.transport.registry import (
    DEFAULT_REGISTRY_TTL,
    MAX_QUERY_RESULTS,
    AgentRegistry,
    CapEntry,
    RegistryEntry,
    RegistryQuery,
    RegistryResponse,
    create_registry_entry,
    get_agent_registry,
    match_capability,
    verify_registry_entry,
)


class TestCapEntry:
    """Tests for the CapEntry dataclass."""

    def test_frozen(self) -> None:
        cap = CapEntry(resource_uri="qasp://host/res", verbs=frozenset({"read"}))
        with pytest.raises(AttributeError):
            cap.resource_uri = "other"  # type: ignore[misc]

    def test_equality(self) -> None:
        a = CapEntry(resource_uri="qasp://host/res", verbs=frozenset({"read"}))
        b = CapEntry(resource_uri="qasp://host/res", verbs=frozenset({"read"}))
        assert a == b

    def test_default_verbs(self) -> None:
        cap = CapEntry(resource_uri="qasp://host/res")
        assert cap.verbs == frozenset()
        assert cap.description == ""


class TestRegistryEntry:
    """Tests for the RegistryEntry dataclass."""

    def test_frozen(self, sample_registry_entry: RegistryEntry) -> None:
        with pytest.raises(AttributeError):
            sample_registry_entry.agent_did = "other"  # type: ignore[misc]

    def test_to_cbor_deterministic(self, sample_registry_entry: RegistryEntry) -> None:
        assert sample_registry_entry.to_cbor() == sample_registry_entry.to_cbor()

    def test_to_cbor_excludes_signature(self, sample_registry_entry: RegistryEntry) -> None:
        payload = cbor2.loads(sample_registry_entry.to_cbor())
        assert "signature" not in payload

    def test_to_cbor_has_sorted_capability_verbs(
        self,
        discovery_keypair: tuple[bytes, bytes],
        did_registry_with_doc: tuple[DIDRegistry, DIDDocument, str],
    ) -> None:
        _pub, sec = discovery_keypair
        _reg, doc, did_str = did_registry_with_doc
        caps = (
            CapEntry(
                resource_uri="qasp://host/res",
                verbs=frozenset({"z_verb", "a_verb", "m_verb"}),
            ),
        )
        entry = create_registry_entry(
            agent_did=did_str,
            secret_key=sec,
            did_document=doc,
            capabilities=caps,
            trust_score=0.5,
            audit_vcs=(),
            endpoint=("127.0.0.1", 9000),
        )
        payload = cbor2.loads(entry.to_cbor())
        assert payload["capabilities"][0]["verbs"] == ["a_verb", "m_verb", "z_verb"]

    def test_is_expired_false(self, sample_registry_entry: RegistryEntry) -> None:
        assert not sample_registry_entry.is_expired()

    def test_is_expired_true(self, sample_registry_entry: RegistryEntry) -> None:
        future = sample_registry_entry.timestamp + sample_registry_entry.ttl + 1
        assert sample_registry_entry.is_expired(now=future)


class TestRegistryQuery:
    """Tests for the RegistryQuery dataclass."""

    def test_defaults(self) -> None:
        q = RegistryQuery()
        assert q.capability == ""
        assert q.min_trust == 0.0
        assert q.verbs == frozenset()
        assert q.max_results == MAX_QUERY_RESULTS

    def test_custom_values(self) -> None:
        q = RegistryQuery(
            capability="qasp://*/gpu/*",
            min_trust=0.7,
            verbs=frozenset({"invoke"}),
            max_results=10,
        )
        assert q.capability == "qasp://*/gpu/*"
        assert q.min_trust == 0.7
        assert q.verbs == frozenset({"invoke"})
        assert q.max_results == 10


class TestMatchCapability:
    """Tests for the match_capability helper."""

    def test_exact_match(self) -> None:
        assert match_capability("qasp://host/gpu/infer", "qasp://host/gpu/infer")

    def test_wildcard_host(self) -> None:
        assert match_capability("qasp://*/gpu/*", "qasp://myhost/gpu/infer")

    def test_wildcard_suffix(self) -> None:
        assert match_capability("qasp://host/storage/*", "qasp://host/storage/upload")

    def test_no_match(self) -> None:
        assert not match_capability("qasp://host/gpu/*", "qasp://host/storage/upload")

    def test_single_char_wildcard(self) -> None:
        assert match_capability("qasp://host/gpu/infe?", "qasp://host/gpu/infer")
        assert not match_capability("qasp://host/gpu/infe?", "qasp://host/gpu/inference")

    def test_case_sensitive(self) -> None:
        assert not match_capability("qasp://HOST/gpu/*", "qasp://host/gpu/infer")


class TestCreateVerifyRegistryEntry:
    """Tests for create_registry_entry and verify_registry_entry."""

    def test_roundtrip(
        self,
        discovery_keypair: tuple[bytes, bytes],
        sample_registry_entry: RegistryEntry,
    ) -> None:
        pub, _sec = discovery_keypair
        assert verify_registry_entry(sample_registry_entry, pub)

    def test_wrong_key_raises(self, sample_registry_entry: RegistryEntry) -> None:
        wrong_pub, _wrong_sec = generate_keypair()
        with pytest.raises(RegistrySignatureError):
            verify_registry_entry(sample_registry_entry, wrong_pub)

    def test_tampered_payload(
        self,
        discovery_keypair: tuple[bytes, bytes],
        did_registry_with_doc: tuple[DIDRegistry, DIDDocument, str],
        sample_cap_entries: tuple[CapEntry, ...],
    ) -> None:
        _pub, sec = discovery_keypair
        pub2, _sec2 = discovery_keypair
        _reg, doc, did_str = did_registry_with_doc

        entry = create_registry_entry(
            agent_did=did_str,
            secret_key=sec,
            did_document=doc,
            capabilities=sample_cap_entries,
            trust_score=0.5,
            audit_vcs=(),
            endpoint=("127.0.0.1", 9000),
        )
        # Tamper: change trust_score
        tampered = RegistryEntry(
            agent_did=entry.agent_did,
            did_document=entry.did_document,
            capabilities=entry.capabilities,
            trust_score=1.0,  # tampered
            audit_vcs=entry.audit_vcs,
            endpoint=entry.endpoint,
            timestamp=entry.timestamp,
            ttl=entry.ttl,
            signature=entry.signature,
        )
        with pytest.raises(RegistrySignatureError):
            verify_registry_entry(tampered, pub2)

    def test_expired_entry(
        self,
        discovery_keypair: tuple[bytes, bytes],
        did_registry_with_doc: tuple[DIDRegistry, DIDDocument, str],
    ) -> None:
        _pub, sec = discovery_keypair
        pub, _sec = discovery_keypair
        _reg, doc, did_str = did_registry_with_doc

        entry = create_registry_entry(
            agent_did=did_str,
            secret_key=sec,
            did_document=doc,
            capabilities=(),
            trust_score=0.5,
            audit_vcs=(),
            endpoint=("127.0.0.1", 9000),
            ttl=0,  # expires immediately
        )
        # Give it a moment to expire
        with pytest.raises(RegistryEntryError, match="expired"):
            verify_registry_entry(entry, pub)

    def test_skip_expiry_check(
        self,
        discovery_keypair: tuple[bytes, bytes],
        did_registry_with_doc: tuple[DIDRegistry, DIDDocument, str],
    ) -> None:
        _pub, sec = discovery_keypair
        pub, _sec = discovery_keypair
        _reg, doc, did_str = did_registry_with_doc

        entry = create_registry_entry(
            agent_did=did_str,
            secret_key=sec,
            did_document=doc,
            capabilities=(),
            trust_score=0.5,
            audit_vcs=(),
            endpoint=("127.0.0.1", 9000),
            ttl=0,
        )
        assert verify_registry_entry(entry, pub, check_expiry=False)


class TestAgentRegistry:
    """Tests for the AgentRegistry class."""

    def test_register_valid(
        self,
        agent_registry: AgentRegistry,
        sample_registry_entry: RegistryEntry,
    ) -> None:
        agent_registry.register(sample_registry_entry)
        assert sample_registry_entry.agent_did in agent_registry
        assert len(agent_registry) == 1

    def test_reject_invalid_signature(
        self,
        did_registry_with_doc: tuple[DIDRegistry, DIDDocument, str],
    ) -> None:
        _reg, doc, did_str = did_registry_with_doc
        did_registry = _reg
        # Create entry with wrong key
        wrong_pub, wrong_sec = generate_keypair()
        entry = create_registry_entry(
            agent_did=did_str,
            secret_key=wrong_sec,
            did_document=doc,
            capabilities=(),
            trust_score=0.5,
            audit_vcs=(),
            endpoint=("127.0.0.1", 9000),
        )
        registry = AgentRegistry(did_registry=did_registry)
        with pytest.raises(RegistrySignatureError):
            registry.register(entry)

    def test_reject_unresolvable_did(self) -> None:
        pub, sec = generate_keypair()
        did, doc = create_did(pub)
        empty_did_registry = DIDRegistry()
        entry = create_registry_entry(
            agent_did=str(did),
            secret_key=sec,
            did_document=doc,
            capabilities=(),
            trust_score=0.5,
            audit_vcs=(),
            endpoint=("127.0.0.1", 9000),
        )
        registry = AgentRegistry(did_registry=empty_did_registry)
        with pytest.raises(RegistryEntryError, match="Cannot resolve DID"):
            registry.register(entry)

    def test_lookup(
        self,
        agent_registry: AgentRegistry,
        sample_registry_entry: RegistryEntry,
    ) -> None:
        agent_registry.register(sample_registry_entry)
        found = agent_registry.lookup(sample_registry_entry.agent_did)
        assert found is not None
        assert found.agent_did == sample_registry_entry.agent_did

    def test_lookup_missing(self, agent_registry: AgentRegistry) -> None:
        assert agent_registry.lookup("did:qasp:nonexistent") is None

    def test_deregister(
        self,
        agent_registry: AgentRegistry,
        sample_registry_entry: RegistryEntry,
    ) -> None:
        agent_registry.register(sample_registry_entry)
        assert agent_registry.deregister(sample_registry_entry.agent_did)
        assert sample_registry_entry.agent_did not in agent_registry
        assert len(agent_registry) == 0

    def test_deregister_missing(self, agent_registry: AgentRegistry) -> None:
        assert not agent_registry.deregister("did:qasp:nonexistent")

    def test_query_by_capability(
        self,
        agent_registry: AgentRegistry,
        sample_registry_entry: RegistryEntry,
    ) -> None:
        agent_registry.register(sample_registry_entry)
        resp = agent_registry.query(
            RegistryQuery(capability="qasp://myhost/gpu/infer")
        )
        assert len(resp.entries) == 1
        assert resp.total_matches == 1

    def test_query_with_wildcards(
        self,
        agent_registry: AgentRegistry,
        sample_registry_entry: RegistryEntry,
    ) -> None:
        agent_registry.register(sample_registry_entry)
        resp = agent_registry.query(RegistryQuery(capability="qasp://*/gpu/*"))
        assert len(resp.entries) == 1

    def test_query_no_match(
        self,
        agent_registry: AgentRegistry,
        sample_registry_entry: RegistryEntry,
    ) -> None:
        agent_registry.register(sample_registry_entry)
        resp = agent_registry.query(
            RegistryQuery(capability="qasp://nonexistent/nothing")
        )
        assert len(resp.entries) == 0

    def test_query_by_verbs(
        self,
        agent_registry: AgentRegistry,
        sample_registry_entry: RegistryEntry,
    ) -> None:
        agent_registry.register(sample_registry_entry)
        # The gpu/infer cap has verbs {"invoke", "read"}
        resp = agent_registry.query(
            RegistryQuery(
                capability="qasp://*/gpu/*",
                verbs=frozenset({"invoke"}),
            )
        )
        assert len(resp.entries) == 1

    def test_query_by_verbs_no_match(
        self,
        agent_registry: AgentRegistry,
        sample_registry_entry: RegistryEntry,
    ) -> None:
        agent_registry.register(sample_registry_entry)
        # gpu/infer cap doesn't have "delete"
        resp = agent_registry.query(
            RegistryQuery(
                capability="qasp://*/gpu/*",
                verbs=frozenset({"delete"}),
            )
        )
        assert len(resp.entries) == 0

    def test_query_by_min_trust(
        self,
        agent_registry: AgentRegistry,
        sample_registry_entry: RegistryEntry,
    ) -> None:
        agent_registry.register(sample_registry_entry)
        # sample entry has trust_score=0.85
        resp = agent_registry.query(RegistryQuery(min_trust=0.8))
        assert len(resp.entries) == 1

        resp = agent_registry.query(RegistryQuery(min_trust=0.9))
        assert len(resp.entries) == 0

    def test_query_combined_filters(
        self,
        agent_registry: AgentRegistry,
        sample_registry_entry: RegistryEntry,
    ) -> None:
        agent_registry.register(sample_registry_entry)
        resp = agent_registry.query(
            RegistryQuery(
                capability="qasp://*/gpu/*",
                min_trust=0.5,
                verbs=frozenset({"invoke"}),
            )
        )
        assert len(resp.entries) == 1

    def test_query_sort_by_trust_desc(self) -> None:
        did_registry = DIDRegistry()
        entries = []
        for trust in [0.3, 0.9, 0.6]:
            pub, sec = generate_keypair()
            did, doc = create_did(pub)
            did_registry.register(doc)
            entry = create_registry_entry(
                agent_did=str(did),
                secret_key=sec,
                did_document=doc,
                capabilities=(
                    CapEntry(resource_uri="qasp://host/shared", verbs=frozenset({"read"})),
                ),
                trust_score=trust,
                audit_vcs=(),
                endpoint=("127.0.0.1", 9000),
            )
            entries.append(entry)

        registry = AgentRegistry(did_registry=did_registry)
        for e in entries:
            registry.register(e)

        resp = registry.query(RegistryQuery())
        scores = [e.trust_score for e in resp.entries]
        assert scores == [0.9, 0.6, 0.3]

    def test_query_max_results(self) -> None:
        did_registry = DIDRegistry()
        registry = AgentRegistry(did_registry=did_registry)
        for i in range(5):
            pub, sec = generate_keypair()
            did, doc = create_did(pub)
            did_registry.register(doc)
            entry = create_registry_entry(
                agent_did=str(did),
                secret_key=sec,
                did_document=doc,
                capabilities=(),
                trust_score=0.5,
                audit_vcs=(),
                endpoint=("127.0.0.1", 9000 + i),
            )
            registry.register(entry)

        resp = registry.query(RegistryQuery(max_results=2))
        assert len(resp.entries) == 2
        assert resp.total_matches == 5

    def test_cleanup_expired(self) -> None:
        did_registry = DIDRegistry()
        pub, sec = generate_keypair()
        did, doc = create_did(pub)
        did_registry.register(doc)

        entry = create_registry_entry(
            agent_did=str(did),
            secret_key=sec,
            did_document=doc,
            capabilities=(),
            trust_score=0.5,
            audit_vcs=(),
            endpoint=("127.0.0.1", 9000),
            ttl=0,  # expires immediately
        )
        registry = AgentRegistry(did_registry=did_registry)
        # Bypass signature check by inserting directly
        with registry._lock:
            registry._entries[entry.agent_did] = entry

        assert len(registry) == 1
        removed = registry.cleanup_expired()
        assert removed == 1
        assert len(registry) == 0

    def test_contains_and_len(
        self,
        agent_registry: AgentRegistry,
        sample_registry_entry: RegistryEntry,
    ) -> None:
        assert sample_registry_entry.agent_did not in agent_registry
        assert len(agent_registry) == 0

        agent_registry.register(sample_registry_entry)
        assert sample_registry_entry.agent_did in agent_registry
        assert len(agent_registry) == 1

    def test_re_registration_overwrites(
        self,
        agent_registry: AgentRegistry,
        discovery_keypair: tuple[bytes, bytes],
        did_registry_with_doc: tuple[DIDRegistry, DIDDocument, str],
    ) -> None:
        _pub, sec = discovery_keypair
        _reg, doc, did_str = did_registry_with_doc

        entry1 = create_registry_entry(
            agent_did=did_str,
            secret_key=sec,
            did_document=doc,
            capabilities=(),
            trust_score=0.5,
            audit_vcs=(),
            endpoint=("127.0.0.1", 9000),
        )
        entry2 = create_registry_entry(
            agent_did=did_str,
            secret_key=sec,
            did_document=doc,
            capabilities=(),
            trust_score=0.9,
            audit_vcs=(),
            endpoint=("127.0.0.1", 9001),
        )
        agent_registry.register(entry1)
        agent_registry.register(entry2)
        assert len(agent_registry) == 1

        found = agent_registry.lookup(did_str)
        assert found is not None
        assert found.trust_score == 0.9
        assert found.endpoint == ("127.0.0.1", 9001)

    def test_all_entries(
        self,
        agent_registry: AgentRegistry,
        sample_registry_entry: RegistryEntry,
    ) -> None:
        agent_registry.register(sample_registry_entry)
        entries = agent_registry.all_entries()
        assert len(entries) == 1
        assert entries[0].agent_did == sample_registry_entry.agent_did

    def test_query_skips_expired(self) -> None:
        did_registry = DIDRegistry()
        pub, sec = generate_keypair()
        did, doc = create_did(pub)
        did_registry.register(doc)

        entry = create_registry_entry(
            agent_did=str(did),
            secret_key=sec,
            did_document=doc,
            capabilities=(),
            trust_score=0.5,
            audit_vcs=(),
            endpoint=("127.0.0.1", 9000),
            ttl=0,
        )
        registry = AgentRegistry(did_registry=did_registry)
        with registry._lock:
            registry._entries[entry.agent_did] = entry

        resp = registry.query(RegistryQuery())
        assert len(resp.entries) == 0

    def test_query_verbs_without_capability(self) -> None:
        """When verbs are specified but no capability pattern, match any cap with those verbs."""
        did_registry = DIDRegistry()
        pub, sec = generate_keypair()
        did, doc = create_did(pub)
        did_registry.register(doc)

        entry = create_registry_entry(
            agent_did=str(did),
            secret_key=sec,
            did_document=doc,
            capabilities=(
                CapEntry(
                    resource_uri="qasp://host/res",
                    verbs=frozenset({"read", "write"}),
                ),
            ),
            trust_score=0.5,
            audit_vcs=(),
            endpoint=("127.0.0.1", 9000),
        )
        registry = AgentRegistry(did_registry=did_registry)
        registry.register(entry)

        resp = registry.query(RegistryQuery(verbs=frozenset({"read"})))
        assert len(resp.entries) == 1

        resp = registry.query(RegistryQuery(verbs=frozenset({"admin"})))
        assert len(resp.entries) == 0


class TestAgentRegistrySingleton:
    """Tests for the get_agent_registry singleton."""

    def test_singleton_identity(self) -> None:
        r1 = get_agent_registry()
        r2 = get_agent_registry()
        assert r1 is r2


class TestRegistryResponse:
    """Tests for the RegistryResponse dataclass."""

    def test_frozen(self) -> None:
        resp = RegistryResponse(
            entries=(), total_matches=0, query=RegistryQuery()
        )
        with pytest.raises(AttributeError):
            resp.total_matches = 5  # type: ignore[misc]

    def test_total_matches_vs_entries(self) -> None:
        resp = RegistryResponse(
            entries=(), total_matches=10, query=RegistryQuery()
        )
        assert resp.total_matches == 10
        assert len(resp.entries) == 0
