"""Integration tests for registry-based discovery via DiscoveryClient."""

from __future__ import annotations

import time
from datetime import datetime

import pytest

from qasp.crypto.signatures import generate_keypair
from qasp.identity.did import DIDRegistry, create_did
from qasp.transport.discover import DiscoveryClient, ServiceEndpoint
from qasp.transport.registry import (
    AgentRegistry,
    CapEntry,
    RegistryEntry,
    RegistryQuery,
    create_registry_entry,
)


@pytest.fixture
def multi_agent_setup() -> (
    tuple[DIDRegistry, AgentRegistry, list[tuple[str, bytes, RegistryEntry]]]
):
    """Set up 3 agents with real keypairs, DID documents, and registry entries."""
    did_registry = DIDRegistry()
    agent_registry = AgentRegistry(did_registry=did_registry)

    agents: list[tuple[str, bytes, RegistryEntry]] = []
    configs = [
        {
            "caps": (
                CapEntry(
                    resource_uri="qasp://agent-a/gpu/infer",
                    verbs=frozenset({"invoke", "read"}),
                    description="GPU inference",
                ),
            ),
            "trust": 0.9,
            "endpoint": ("10.0.0.1", 9001),
        },
        {
            "caps": (
                CapEntry(
                    resource_uri="qasp://agent-b/storage/upload",
                    verbs=frozenset({"write", "delete"}),
                    description="Storage",
                ),
                CapEntry(
                    resource_uri="qasp://agent-b/gpu/train",
                    verbs=frozenset({"invoke"}),
                    description="GPU training",
                ),
            ),
            "trust": 0.7,
            "endpoint": ("10.0.0.2", 9002),
        },
        {
            "caps": (
                CapEntry(
                    resource_uri="qasp://agent-c/api/v1/status",
                    verbs=frozenset({"read"}),
                    description="Status API",
                ),
            ),
            "trust": 0.4,
            "endpoint": ("10.0.0.3", 9003),
        },
    ]

    for cfg in configs:
        pub, sec = generate_keypair()
        did, doc = create_did(pub)
        did_str = str(did)
        did_registry.register(doc)
        entry = create_registry_entry(
            agent_did=did_str,
            secret_key=sec,
            did_document=doc,
            capabilities=cfg["caps"],
            trust_score=cfg["trust"],
            audit_vcs=(),
            endpoint=cfg["endpoint"],
        )
        agent_registry.register(entry)
        agents.append((did_str, sec, entry))

    return did_registry, agent_registry, agents


@pytest.mark.integration
class TestRegistryDiscoveryIntegration:
    """Integration tests for DiscoveryClient with registry as third mode."""

    def test_discover_from_registry_returns_endpoints(
        self, multi_agent_setup: tuple
    ) -> None:
        did_registry, agent_registry, agents = multi_agent_setup
        client_pub, client_sec = generate_keypair()
        client_did, client_doc = create_did(client_pub)
        did_registry.register(client_doc)

        client = DiscoveryClient(
            local_did=str(client_did),
            secret_key=client_sec,
            registry=did_registry,
            agent_registry=agent_registry,
        )
        results = client.discover_from_registry()
        assert len(results) == 3
        assert all(isinstance(ep, ServiceEndpoint) for ep in results)

    async def test_discover_merges_local_and_registry(
        self, multi_agent_setup: tuple
    ) -> None:
        """discover() merges local cache and registry, deduplicating by DID."""
        did_registry, agent_registry, agents = multi_agent_setup
        client_pub, client_sec = generate_keypair()
        client_did, client_doc = create_did(client_pub)
        did_registry.register(client_doc)

        client = DiscoveryClient(
            local_did=str(client_did),
            secret_key=client_sec,
            registry=did_registry,
            agent_registry=agent_registry,
        )

        # Manually add a local endpoint that overlaps with agent-a
        agent_a_did = agents[0][0]
        local_ep = ServiceEndpoint(
            did=agent_a_did,
            host="127.0.0.1",
            port=8888,
            capabilities=frozenset({"local-cap"}),
            last_seen=datetime.now(),
            trust_score=1.0,
        )
        client._known_endpoints[agent_a_did] = local_ep

        results = await client.discover()
        dids = [ep.did for ep in results]
        # Agent-a should appear only once (local wins due to dedup)
        assert dids.count(agent_a_did) == 1
        # All 3 agents + no duplicates
        assert len(set(dids)) == 3

    async def test_discover_deduplication_by_did(
        self, multi_agent_setup: tuple
    ) -> None:
        did_registry, agent_registry, agents = multi_agent_setup
        client_pub, client_sec = generate_keypair()
        client_did, client_doc = create_did(client_pub)
        did_registry.register(client_doc)

        client = DiscoveryClient(
            local_did=str(client_did),
            secret_key=client_sec,
            registry=did_registry,
            agent_registry=agent_registry,
        )

        results = await client.discover()
        dids = [ep.did for ep in results]
        assert len(dids) == len(set(dids)), "DIDs should be unique"

    def test_discover_wildcard_queries(
        self, multi_agent_setup: tuple
    ) -> None:
        did_registry, agent_registry, agents = multi_agent_setup
        client_pub, client_sec = generate_keypair()
        client_did, client_doc = create_did(client_pub)
        did_registry.register(client_doc)

        client = DiscoveryClient(
            local_did=str(client_did),
            secret_key=client_sec,
            registry=did_registry,
            agent_registry=agent_registry,
        )

        # Wildcard GPU query
        results = client.discover_from_registry(capability="qasp://*/gpu/*")
        assert len(results) == 2  # agent-a (gpu/infer) + agent-b (gpu/train)

    def test_discover_trust_score_filtering(
        self, multi_agent_setup: tuple
    ) -> None:
        did_registry, agent_registry, agents = multi_agent_setup
        client_pub, client_sec = generate_keypair()
        client_did, client_doc = create_did(client_pub)
        did_registry.register(client_doc)

        client = DiscoveryClient(
            local_did=str(client_did),
            secret_key=client_sec,
            registry=did_registry,
            agent_registry=agent_registry,
        )

        results = client.discover_from_registry(min_trust_score=0.5)
        assert len(results) == 2  # agent-a (0.9) and agent-b (0.7)

        results = client.discover_from_registry(min_trust_score=0.8)
        assert len(results) == 1  # only agent-a (0.9)

    def test_discover_expired_entry_excluded(self) -> None:
        did_registry = DIDRegistry()
        agent_registry = AgentRegistry(did_registry=did_registry)

        pub, sec = generate_keypair()
        did, doc = create_did(pub)
        did_registry.register(doc)

        entry = create_registry_entry(
            agent_did=str(did),
            secret_key=sec,
            did_document=doc,
            capabilities=(
                CapEntry(resource_uri="qasp://host/res", verbs=frozenset({"read"})),
            ),
            trust_score=0.8,
            audit_vcs=(),
            endpoint=("10.0.0.1", 9000),
            ttl=0,  # expires immediately
        )
        # Insert directly to bypass expiry check in register()
        with agent_registry._lock:
            agent_registry._entries[entry.agent_did] = entry

        client_pub, client_sec = generate_keypair()
        client_did, client_doc = create_did(client_pub)
        did_registry.register(client_doc)

        client = DiscoveryClient(
            local_did=str(client_did),
            secret_key=client_sec,
            registry=did_registry,
            agent_registry=agent_registry,
        )

        results = client.discover_from_registry()
        assert len(results) == 0

    def test_discover_without_registry_returns_empty(self) -> None:
        """DiscoveryClient without agent_registry returns empty from registry method."""
        pub, sec = generate_keypair()
        did, doc = create_did(pub)
        did_registry = DIDRegistry()
        did_registry.register(doc)

        client = DiscoveryClient(
            local_did=str(did),
            secret_key=sec,
            registry=did_registry,
        )
        results = client.discover_from_registry()
        assert results == []

    def test_discover_verbs_filtering(
        self, multi_agent_setup: tuple
    ) -> None:
        did_registry, agent_registry, agents = multi_agent_setup
        client_pub, client_sec = generate_keypair()
        client_did, client_doc = create_did(client_pub)
        did_registry.register(client_doc)

        client = DiscoveryClient(
            local_did=str(client_did),
            secret_key=client_sec,
            registry=did_registry,
            agent_registry=agent_registry,
        )

        results = client.discover_from_registry(
            capability="qasp://*/gpu/*",
            verbs=frozenset({"invoke", "read"}),
        )
        # Only agent-a's gpu/infer has both invoke+read
        assert len(results) == 1

    def test_registry_results_sorted_by_trust(
        self, multi_agent_setup: tuple
    ) -> None:
        did_registry, agent_registry, agents = multi_agent_setup
        client_pub, client_sec = generate_keypair()
        client_did, client_doc = create_did(client_pub)
        did_registry.register(client_doc)

        client = DiscoveryClient(
            local_did=str(client_did),
            secret_key=client_sec,
            registry=did_registry,
            agent_registry=agent_registry,
        )

        results = client.discover_from_registry()
        scores = [ep.trust_score for ep in results]
        assert scores == sorted(scores, reverse=True)
