"""Registry-based agent discovery for QASP.

This module implements an internet-scale, queryable directory service
where agents can register themselves and be discovered via structured
queries with wildcard matching and trust-score filtering.
"""

from __future__ import annotations

import fnmatch
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import cbor2

from qasp.crypto.signatures import sign, verify
from qasp.identity.did import DIDRegistry, get_registry

from .exceptions import RegistryEntryError, RegistrySignatureError

if TYPE_CHECKING:
    from qasp.identity.did import DIDDocument
    from qasp.trust.certification import AuditVC

__all__ = [
    "DEFAULT_REGISTRY_TTL",
    "MAX_QUERY_RESULTS",
    "AgentRegistry",
    "CapEntry",
    "RegistryEntry",
    "RegistryQuery",
    "RegistryResponse",
    "create_registry_entry",
    "get_agent_registry",
    "match_capability",
    "verify_registry_entry",
]

DEFAULT_REGISTRY_TTL = 600  # 10 minutes
MAX_QUERY_RESULTS = 100


@dataclass(frozen=True)
class CapEntry:
    """A single advertised capability with URI and permitted operations.

    Attributes:
        resource_uri: The capability resource URI (e.g. "qasp://host/gpu/infer").
        verbs: Permitted operations on this resource.
        description: Human-readable description of this capability.
    """

    resource_uri: str
    verbs: frozenset[str] = frozenset()
    description: str = ""


@dataclass(frozen=True)
class RegistryEntry:
    """A signed registry entry for an agent.

    Attributes:
        agent_did: The agent's DID string.
        did_document: The agent's DID document.
        capabilities: Tuple of advertised capabilities.
        trust_score: The agent's trust score (0.0-1.0).
        audit_vcs: Tuple of audit verifiable credentials.
        endpoint: The agent's (host, port) endpoint.
        timestamp: Unix timestamp of registration.
        ttl: Time-to-live in seconds.
        signature: ML-DSA-65 signature over the CBOR-encoded payload.
    """

    agent_did: str
    did_document: DIDDocument
    capabilities: tuple[CapEntry, ...]
    trust_score: float
    audit_vcs: tuple[AuditVC, ...]
    endpoint: tuple[str, int]
    timestamp: float
    ttl: int
    signature: bytes

    def to_cbor(self) -> bytes:
        """CBOR-encode the payload fields (excluding signature) for signing.

        Uses canonical CBOR with sorted keys for determinism.
        """
        payload: dict[str, Any] = {
            "agent_did": self.agent_did,
            "audit_vcs": [vc.id for vc in self.audit_vcs],
            "capabilities": [
                {
                    "description": cap.description,
                    "resource_uri": cap.resource_uri,
                    "verbs": sorted(cap.verbs),
                }
                for cap in self.capabilities
            ],
            "did_document": self.did_document.to_dict(),
            "endpoint": list(self.endpoint),
            "timestamp": self.timestamp,
            "trust_score": self.trust_score,
            "ttl": self.ttl,
        }
        return cbor2.dumps(payload, canonical=True)

    def is_expired(self, now: float | None = None) -> bool:
        """Check if this registry entry has expired."""
        if now is None:
            now = time.time()
        return self.timestamp + self.ttl < now


@dataclass(frozen=True)
class RegistryQuery:
    """A query against the agent registry.

    Attributes:
        capability: Capability URI pattern (supports fnmatch wildcards).
        min_trust: Minimum trust score threshold.
        verbs: Required verbs (all must be present on a matching CapEntry).
        max_results: Maximum number of results to return.
    """

    capability: str = ""
    min_trust: float = 0.0
    verbs: frozenset[str] = frozenset()
    max_results: int = MAX_QUERY_RESULTS


@dataclass(frozen=True)
class RegistryResponse:
    """Response from a registry query.

    Attributes:
        entries: Matching registry entries (truncated to max_results).
        total_matches: Total number of matches before truncation.
        query: The original query.
    """

    entries: tuple[RegistryEntry, ...]
    total_matches: int
    query: RegistryQuery


def match_capability(pattern: str, resource_uri: str) -> bool:
    """Match a capability URI against a wildcard pattern.

    Uses fnmatch.fnmatchcase() for case-sensitive, platform-independent matching.

    Args:
        pattern: The glob pattern (e.g. "qasp://*/gpu/*").
        resource_uri: The capability URI to match.

    Returns:
        True if the resource_uri matches the pattern.
    """
    return fnmatch.fnmatchcase(resource_uri, pattern)


def create_registry_entry(
    agent_did: str,
    secret_key: bytes,
    did_document: DIDDocument,
    capabilities: tuple[CapEntry, ...],
    trust_score: float,
    audit_vcs: tuple[AuditVC, ...],
    endpoint: tuple[str, int],
    ttl: int = DEFAULT_REGISTRY_TTL,
) -> RegistryEntry:
    """Create a signed registry entry.

    Args:
        agent_did: The agent's DID string.
        secret_key: ML-DSA-65 secret key for signing.
        did_document: The agent's DID document.
        capabilities: Tuple of advertised capabilities.
        trust_score: The agent's trust score.
        audit_vcs: Tuple of audit VCs.
        endpoint: The agent's (host, port) endpoint.
        ttl: Time-to-live in seconds.

    Returns:
        A signed RegistryEntry.
    """
    timestamp = time.time()

    unsigned = RegistryEntry(
        agent_did=agent_did,
        did_document=did_document,
        capabilities=capabilities,
        trust_score=trust_score,
        audit_vcs=audit_vcs,
        endpoint=endpoint,
        timestamp=timestamp,
        ttl=ttl,
        signature=b"",
    )

    payload = unsigned.to_cbor()
    signature = sign(secret_key, payload)

    return RegistryEntry(
        agent_did=agent_did,
        did_document=did_document,
        capabilities=capabilities,
        trust_score=trust_score,
        audit_vcs=audit_vcs,
        endpoint=endpoint,
        timestamp=timestamp,
        ttl=ttl,
        signature=signature,
    )


def verify_registry_entry(
    entry: RegistryEntry,
    public_key: bytes,
    check_expiry: bool = True,
) -> bool:
    """Verify a registry entry's signature and optionally its expiry.

    Args:
        entry: The registry entry to verify.
        public_key: ML-DSA-65 public key of the agent.
        check_expiry: Whether to check TTL expiry.

    Returns:
        True if valid.

    Raises:
        RegistrySignatureError: If signature verification fails.
        RegistryEntryError: If the entry has expired.
    """
    if check_expiry and entry.is_expired():
        raise RegistryEntryError("Registry entry has expired")

    unsigned = RegistryEntry(
        agent_did=entry.agent_did,
        did_document=entry.did_document,
        capabilities=entry.capabilities,
        trust_score=entry.trust_score,
        audit_vcs=entry.audit_vcs,
        endpoint=entry.endpoint,
        timestamp=entry.timestamp,
        ttl=entry.ttl,
        signature=b"",
    )
    payload = unsigned.to_cbor()

    try:
        return verify(public_key, payload, entry.signature)
    except Exception as e:
        raise RegistrySignatureError(
            f"Registry entry signature verification failed: {e}"
        ) from e


class AgentRegistry:
    """Thread-safe registry for agent discovery.

    Stores signed registry entries and supports structured queries
    with wildcard capability matching, verb filtering, and trust-score
    thresholds.
    """

    def __init__(self, did_registry: DIDRegistry | None = None) -> None:
        self._lock = threading.RLock()
        self._entries: dict[str, RegistryEntry] = {}
        self._did_registry = did_registry if did_registry is not None else get_registry()

    def register(self, entry: RegistryEntry) -> None:
        """Register an agent entry after verifying its signature.

        Resolves the agent's DID from the DID registry, extracts the
        public key, and verifies the entry signature. Re-registration
        for the same DID overwrites (last-write-wins).

        Args:
            entry: The signed registry entry.

        Raises:
            RegistryEntryError: If the DID cannot be resolved.
            RegistrySignatureError: If the signature is invalid.
        """
        try:
            doc = self._did_registry.lookup(entry.agent_did)
        except Exception as e:
            raise RegistryEntryError(
                f"Cannot resolve DID {entry.agent_did}: {e}"
            ) from e

        public_key = doc.get_public_key()
        verify_registry_entry(entry, public_key)

        with self._lock:
            self._entries[entry.agent_did] = entry

    def deregister(self, agent_did: str) -> bool:
        """Remove an agent entry.

        Args:
            agent_did: The agent's DID string.

        Returns:
            True if the entry was removed, False if not found.
        """
        with self._lock:
            if agent_did in self._entries:
                del self._entries[agent_did]
                return True
            return False

    def query(self, query: RegistryQuery) -> RegistryResponse:
        """Query the registry for matching agents.

        Filtering logic:
        1. Skip expired entries.
        2. If query.capability is non-empty, at least one CapEntry must match.
        3. If query.verbs is non-empty, the matching CapEntry must have all verbs.
        4. If query.min_trust > 0, entry.trust_score >= query.min_trust.
        5. Sort by trust_score descending.
        6. Truncate to query.max_results.

        Args:
            query: The registry query.

        Returns:
            A RegistryResponse with matching entries.
        """
        with self._lock:
            snapshot = list(self._entries.values())

        now = time.time()
        matches: list[RegistryEntry] = []

        for entry in snapshot:
            if entry.is_expired(now):
                continue

            if query.min_trust > 0 and entry.trust_score < query.min_trust:
                continue

            if query.capability:
                cap_matched = False
                for cap in entry.capabilities:
                    if match_capability(query.capability, cap.resource_uri):
                        if query.verbs and not query.verbs <= cap.verbs:
                            continue
                        cap_matched = True
                        break
                if not cap_matched:
                    continue
            elif query.verbs:
                # No capability pattern but verbs specified: any cap must have all verbs
                verb_matched = any(query.verbs <= cap.verbs for cap in entry.capabilities)
                if not verb_matched:
                    continue

            matches.append(entry)

        matches.sort(key=lambda e: e.trust_score, reverse=True)
        total = len(matches)
        truncated = matches[: query.max_results]

        return RegistryResponse(
            entries=tuple(truncated),
            total_matches=total,
            query=query,
        )

    def lookup(self, agent_did: str) -> RegistryEntry | None:
        """Look up an agent entry by DID.

        Args:
            agent_did: The agent's DID string.

        Returns:
            The registry entry, or None if not found.
        """
        with self._lock:
            return self._entries.get(agent_did)

    def cleanup_expired(self) -> int:
        """Remove all expired entries.

        Returns:
            The number of entries removed.
        """
        now = time.time()
        with self._lock:
            expired = [did for did, e in self._entries.items() if e.is_expired(now)]
            for did in expired:
                del self._entries[did]
            return len(expired)

    def all_entries(self) -> list[RegistryEntry]:
        """Return a snapshot of all non-expired entries."""
        now = time.time()
        with self._lock:
            return [e for e in self._entries.values() if not e.is_expired(now)]

    def __contains__(self, agent_did: str) -> bool:
        """Check if an agent DID is registered."""
        with self._lock:
            return agent_did in self._entries

    def __len__(self) -> int:
        """Return the number of registered entries."""
        with self._lock:
            return len(self._entries)


# Module-level singleton
_agent_registry: AgentRegistry | None = None
_agent_registry_lock = threading.Lock()


def get_agent_registry() -> AgentRegistry:
    """Get the module-level AgentRegistry singleton.

    Returns:
        The shared AgentRegistry instance.
    """
    global _agent_registry
    if _agent_registry is None:
        with _agent_registry_lock:
            if _agent_registry is None:
                _agent_registry = AgentRegistry()
    return _agent_registry
