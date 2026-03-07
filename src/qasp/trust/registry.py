"""Trust registry for agent trust information.

This module implements a thread-safe trust registry for tracking
agent trust information including Bayesian reputation scores, audit VCs,
and behavioral metrics.  Supports pluggable storage backends (in-memory
or SQLite).
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Protocol, runtime_checkable

import cbor2

from qasp.identity.did import DID
from qasp.trust.certification import AuditVC, _encode_vc_with_proof
from qasp.trust.exceptions import DuplicateEntryError, EntryNotFoundError, InvalidVCError

if TYPE_CHECKING:
    pass

__all__ = [
    "InMemoryRegistryBackend",
    "RegistryBackend",
    "SQLiteRegistryBackend",
    "TrustEntry",
    "TrustRegistry",
    "get_trust_registry",
]


@dataclass(frozen=True)
class TrustEntry:
    """A trust registry entry for an agent.

    Uses a Bayesian Beta distribution for reputation scoring:
    - reputation_alpha: Number of successful interactions + 1 (prior)
    - reputation_beta: Number of failed interactions + 1 (prior)
    - Expected value: alpha / (alpha + beta)

    Attributes:
        did: The agent's DID.
        reputation_alpha: Beta distribution alpha parameter (successes + 1).
        reputation_beta: Beta distribution beta parameter (failures + 1).
        audit_vcs: Tuple of audit VCs for this agent.
        behavioral_score: Behavioral verification score (0-1).
        total_interactions: Total number of interactions.
        successful_interactions: Number of successful interactions.
        last_interaction: Timestamp of last interaction.
        flags: Set of flags applied to this entry.
    """

    did: DID
    reputation_alpha: float = 1.0
    reputation_beta: float = 1.0
    audit_vcs: tuple[AuditVC, ...] = ()
    behavioral_score: float = 1.0
    total_interactions: int = 0
    successful_interactions: int = 0
    last_interaction: datetime | None = None
    flags: frozenset[str] = field(default_factory=frozenset)

    @property
    def reputation_score(self) -> float:
        """Compute the expected reputation score.

        Uses the expected value of the Beta distribution: alpha / (alpha + beta)

        Returns:
            The reputation score in the range [0, 1].
        """
        return self.reputation_alpha / (self.reputation_alpha + self.reputation_beta)

    @property
    def best_slsa_level(self) -> int | None:
        """Get the highest SLSA level from non-expired VCs.

        Returns:
            The highest SLSA level (1, 2, or 3), or None if no valid VCs.
        """
        now = datetime.now(UTC)
        valid_levels = [
            int(vc.credential_subject.slsa_level)
            for vc in self.audit_vcs
            if not vc.is_expired(now)
        ]
        return max(valid_levels) if valid_levels else None

    @property
    def audit_certified_score(self) -> float:
        """Compute the audit certification score normalized to [0, 1].

        Maps SLSA levels to scores:
        - Level 1: 0.33
        - Level 2: 0.67
        - Level 3: 1.0
        - No valid VC: 0.0

        Returns:
            The normalized audit certification score.
        """
        best_level = self.best_slsa_level
        if best_level is None:
            return 0.0
        return best_level / 3.0


# =============================================================================
# Registry Backend Protocol
# =============================================================================


@runtime_checkable
class RegistryBackend(Protocol):
    """Protocol for trust registry storage backends."""

    def store_entry(self, did_string: str, entry: TrustEntry) -> None: ...
    def fetch_entry(self, did_string: str) -> TrustEntry | None: ...
    def remove_entry(self, did_string: str) -> bool: ...
    def all_entries(self) -> list[TrustEntry]: ...
    def contains(self, did_string: str) -> bool: ...
    def count(self) -> int: ...
    def clear(self) -> None: ...
    def store_vc(self, vc_id: str, vc: AuditVC) -> None: ...
    def fetch_vc(self, vc_id: str) -> AuditVC | None: ...
    def remove_vc(self, vc_id: str) -> None: ...


# =============================================================================
# In-Memory Backend
# =============================================================================


class InMemoryRegistryBackend:
    """Thread-safe in-memory trust registry backend."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, TrustEntry] = {}
        self._vcs: dict[str, AuditVC] = {}

    def store_entry(self, did_string: str, entry: TrustEntry) -> None:
        with self._lock:
            self._entries[did_string] = entry

    def fetch_entry(self, did_string: str) -> TrustEntry | None:
        with self._lock:
            return self._entries.get(did_string)

    def remove_entry(self, did_string: str) -> bool:
        with self._lock:
            if did_string in self._entries:
                del self._entries[did_string]
                return True
            return False

    def all_entries(self) -> list[TrustEntry]:
        with self._lock:
            return list(self._entries.values())

    def contains(self, did_string: str) -> bool:
        with self._lock:
            return did_string in self._entries

    def count(self) -> int:
        with self._lock:
            return len(self._entries)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._vcs.clear()

    def store_vc(self, vc_id: str, vc: AuditVC) -> None:
        with self._lock:
            self._vcs[vc_id] = vc

    def fetch_vc(self, vc_id: str) -> AuditVC | None:
        with self._lock:
            return self._vcs.get(vc_id)

    def remove_vc(self, vc_id: str) -> None:
        with self._lock:
            self._vcs.pop(vc_id, None)


# =============================================================================
# SQLite Backend
# =============================================================================


_TRUST_SCHEMA = """\
CREATE TABLE IF NOT EXISTS trust_entries (
    did TEXT PRIMARY KEY,
    entry_cbor BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_vcs (
    vc_id TEXT PRIMARY KEY,
    vc_cbor BLOB NOT NULL
)"""


class SQLiteRegistryBackend:
    """SQLite-backed trust registry backend."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        for stmt in _TRUST_SCHEMA.split(";"):
            stmt = stmt.strip()
            if stmt:
                self._conn.execute(stmt)
        self._conn.commit()

    # -- serialization helpers ------------------------------------------------

    def _serialize_entry(self, entry: TrustEntry) -> bytes:
        """Serialize TrustEntry to CBOR, storing VC IDs as references."""
        data = {
            "did": str(entry.did),
            "reputation_alpha": entry.reputation_alpha,
            "reputation_beta": entry.reputation_beta,
            "audit_vc_ids": [vc.id for vc in entry.audit_vcs],
            "behavioral_score": entry.behavioral_score,
            "total_interactions": entry.total_interactions,
            "successful_interactions": entry.successful_interactions,
            "last_interaction": entry.last_interaction.isoformat() if entry.last_interaction else None,
            "flags": sorted(entry.flags),
        }
        return cbor2.dumps(data, canonical=True)

    def _deserialize_entry(self, raw: bytes) -> TrustEntry:
        """Deserialize TrustEntry from CBOR, loading VCs by reference."""
        data = cbor2.loads(raw)
        did = DID.parse(data["did"])
        # Load referenced VCs
        vcs: list[AuditVC] = []
        for vc_id in data.get("audit_vc_ids", []):
            vc = self.fetch_vc(vc_id)
            if vc is not None:
                vcs.append(vc)
        last_interaction = None
        if data["last_interaction"] is not None:
            last_interaction = datetime.fromisoformat(data["last_interaction"])
        return TrustEntry(
            did=did,
            reputation_alpha=data["reputation_alpha"],
            reputation_beta=data["reputation_beta"],
            audit_vcs=tuple(vcs),
            behavioral_score=data["behavioral_score"],
            total_interactions=data["total_interactions"],
            successful_interactions=data["successful_interactions"],
            last_interaction=last_interaction,
            flags=frozenset(data["flags"]),
        )

    def _serialize_vc(self, vc: AuditVC) -> bytes:
        """Serialize AuditVC to CBOR using the canonical wire format."""
        return _encode_vc_with_proof(vc)

    def _deserialize_vc(self, raw: bytes) -> AuditVC:
        """Deserialize AuditVC from CBOR."""
        return AuditVC.from_cbor(raw)

    # -- entry operations -----------------------------------------------------

    def store_entry(self, did_string: str, entry: TrustEntry) -> None:
        data = self._serialize_entry(entry)
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO trust_entries (did, entry_cbor) VALUES (?, ?)",
                (did_string, data),
            )
            self._conn.commit()

    def fetch_entry(self, did_string: str) -> TrustEntry | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT entry_cbor FROM trust_entries WHERE did = ?",
                (did_string,),
            ).fetchone()
        if row is None:
            return None
        return self._deserialize_entry(row[0])

    def remove_entry(self, did_string: str) -> bool:
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM trust_entries WHERE did = ?", (did_string,)
            )
            self._conn.commit()
            return cursor.rowcount > 0

    def all_entries(self) -> list[TrustEntry]:
        with self._lock:
            rows = self._conn.execute("SELECT entry_cbor FROM trust_entries").fetchall()
        return [self._deserialize_entry(row[0]) for row in rows]

    def contains(self, did_string: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM trust_entries WHERE did = ?", (did_string,)
            ).fetchone()
            return row is not None

    def count(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) FROM trust_entries").fetchone()
            return row[0]

    def clear(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM trust_entries")
            self._conn.execute("DELETE FROM audit_vcs")
            self._conn.commit()

    # -- VC operations --------------------------------------------------------

    def store_vc(self, vc_id: str, vc: AuditVC) -> None:
        data = self._serialize_vc(vc)
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO audit_vcs (vc_id, vc_cbor) VALUES (?, ?)",
                (vc_id, data),
            )
            self._conn.commit()

    def fetch_vc(self, vc_id: str) -> AuditVC | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT vc_cbor FROM audit_vcs WHERE vc_id = ?", (vc_id,)
            ).fetchone()
        if row is None:
            return None
        return self._deserialize_vc(row[0])

    def remove_vc(self, vc_id: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM audit_vcs WHERE vc_id = ?", (vc_id,))
            self._conn.commit()

    def close(self) -> None:
        """Close the SQLite connection."""
        self._conn.close()


# =============================================================================
# Trust Registry
# =============================================================================


class TrustRegistry:
    """Thread-safe registry for agent trust information.

    Supports pluggable storage backends via the ``RegistryBackend`` protocol.
    Defaults to ``InMemoryRegistryBackend`` when no backend is supplied.

    The registry-level ``RLock`` ensures atomic read-modify-write sequences,
    while the backend's own lock protects individual storage operations.
    """

    def __init__(self, backend: RegistryBackend | None = None) -> None:
        """Initialize the registry with the given backend.

        Args:
            backend: Storage backend. Defaults to ``InMemoryRegistryBackend()``.
        """
        self._lock = threading.RLock()
        self._backend: RegistryBackend = backend if backend is not None else InMemoryRegistryBackend()

    def register(self, did: DID) -> TrustEntry:
        """Register a new agent in the registry.

        Args:
            did: The agent's DID.

        Returns:
            The new trust entry.

        Raises:
            DuplicateEntryError: If an entry already exists for this DID.
        """
        did_string = str(did)
        with self._lock:
            if self._backend.contains(did_string):
                raise DuplicateEntryError(f"Entry already exists for DID: {did_string}")

            entry = TrustEntry(did=did)
            self._backend.store_entry(did_string, entry)
            return entry

    def lookup(self, did: DID | str) -> TrustEntry | None:
        """Look up an agent's trust entry.

        Args:
            did: The agent's DID (as DID object or string).

        Returns:
            The trust entry, or None if not found.
        """
        did_string = str(did) if isinstance(did, DID) else did
        with self._lock:
            return self._backend.fetch_entry(did_string)

    def get(self, did: DID | str) -> TrustEntry:
        """Get an agent's trust entry, raising if not found.

        Args:
            did: The agent's DID (as DID object or string).

        Returns:
            The trust entry.

        Raises:
            EntryNotFoundError: If no entry exists for this DID.
        """
        entry = self.lookup(did)
        if entry is None:
            raise EntryNotFoundError(f"No entry found for DID: {did}")
        return entry

    def update_reputation(self, did: DID | str, success: bool) -> TrustEntry:
        """Update an agent's reputation based on interaction outcome.

        Uses Bayesian updating on the Beta distribution:
        - Success: alpha += 1
        - Failure: beta += 1

        Args:
            did: The agent's DID.
            success: Whether the interaction was successful.

        Returns:
            The updated trust entry.

        Raises:
            EntryNotFoundError: If no entry exists for this DID.
        """
        did_string = str(did) if isinstance(did, DID) else did
        with self._lock:
            entry = self.get(did_string)

            # Update counts
            new_alpha = entry.reputation_alpha + (1.0 if success else 0.0)
            new_beta = entry.reputation_beta + (0.0 if success else 1.0)
            new_total = entry.total_interactions + 1
            new_successful = entry.successful_interactions + (1 if success else 0)

            # Create updated entry
            updated_entry = TrustEntry(
                did=entry.did,
                reputation_alpha=new_alpha,
                reputation_beta=new_beta,
                audit_vcs=entry.audit_vcs,
                behavioral_score=entry.behavioral_score,
                total_interactions=new_total,
                successful_interactions=new_successful,
                last_interaction=datetime.now(UTC),
                flags=entry.flags,
            )

            self._backend.store_entry(did_string, updated_entry)
            return updated_entry

    def add_audit_vc(self, did: DID | str, vc: AuditVC) -> TrustEntry:
        """Add an audit VC to an agent's entry.

        Args:
            did: The agent's DID.
            vc: The audit VC to add.

        Returns:
            The updated trust entry.

        Raises:
            EntryNotFoundError: If no entry exists for this DID.
            InvalidVCError: If the VC subject does not match the agent DID.
        """
        did_string = str(did) if isinstance(did, DID) else did
        with self._lock:
            entry = self.get(did_string)

            # Validate VC subject matches agent DID
            vc_subject_did = str(vc.credential_subject.agent_did)
            if vc_subject_did != did_string:
                raise InvalidVCError(
                    f"VC subject DID {vc_subject_did} does not match agent DID {did_string}"
                )

            # Add VC to lookup table
            self._backend.store_vc(vc.id, vc)

            # Create updated entry with new VC
            updated_entry = TrustEntry(
                did=entry.did,
                reputation_alpha=entry.reputation_alpha,
                reputation_beta=entry.reputation_beta,
                audit_vcs=(*entry.audit_vcs, vc),
                behavioral_score=entry.behavioral_score,
                total_interactions=entry.total_interactions,
                successful_interactions=entry.successful_interactions,
                last_interaction=entry.last_interaction,
                flags=entry.flags,
            )

            self._backend.store_entry(did_string, updated_entry)
            return updated_entry

    def add_flag(self, did: DID | str, flag: str) -> TrustEntry:
        """Add a flag to an agent's entry.

        Args:
            did: The agent's DID.
            flag: The flag to add.

        Returns:
            The updated trust entry.

        Raises:
            EntryNotFoundError: If no entry exists for this DID.
        """
        did_string = str(did) if isinstance(did, DID) else did
        with self._lock:
            entry = self.get(did_string)

            # Create updated entry with new flag
            updated_entry = TrustEntry(
                did=entry.did,
                reputation_alpha=entry.reputation_alpha,
                reputation_beta=entry.reputation_beta,
                audit_vcs=entry.audit_vcs,
                behavioral_score=entry.behavioral_score,
                total_interactions=entry.total_interactions,
                successful_interactions=entry.successful_interactions,
                last_interaction=entry.last_interaction,
                flags=entry.flags | frozenset([flag]),
            )

            self._backend.store_entry(did_string, updated_entry)
            return updated_entry

    def update_behavioral_score(self, did: DID | str, new_score: float) -> TrustEntry:
        """Replace the behavioral_score on a TrustEntry.

        Used by fault attribution to penalize parties found at fault.
        Creates a new frozen TrustEntry with the updated score.

        Args:
            did: The agent's DID.
            new_score: The new behavioral score (0-1).

        Returns:
            The updated trust entry.

        Raises:
            EntryNotFoundError: If no entry exists for this DID.
        """
        did_string = str(did) if isinstance(did, DID) else did
        with self._lock:
            entry = self.get(did_string)

            updated_entry = TrustEntry(
                did=entry.did,
                reputation_alpha=entry.reputation_alpha,
                reputation_beta=entry.reputation_beta,
                audit_vcs=entry.audit_vcs,
                behavioral_score=max(0.0, min(1.0, new_score)),
                total_interactions=entry.total_interactions,
                successful_interactions=entry.successful_interactions,
                last_interaction=entry.last_interaction,
                flags=entry.flags,
            )

            self._backend.store_entry(did_string, updated_entry)
            return updated_entry

    def remove_flag(self, did: DID | str, flag: str) -> TrustEntry:
        """Remove a flag from an agent's entry.

        Args:
            did: The agent's DID.
            flag: The flag to remove.

        Returns:
            The updated trust entry.

        Raises:
            EntryNotFoundError: If no entry exists for this DID.
        """
        did_string = str(did) if isinstance(did, DID) else did
        with self._lock:
            entry = self.get(did_string)

            # Create updated entry without the flag
            updated_entry = TrustEntry(
                did=entry.did,
                reputation_alpha=entry.reputation_alpha,
                reputation_beta=entry.reputation_beta,
                audit_vcs=entry.audit_vcs,
                behavioral_score=entry.behavioral_score,
                total_interactions=entry.total_interactions,
                successful_interactions=entry.successful_interactions,
                last_interaction=entry.last_interaction,
                flags=entry.flags - frozenset([flag]),
            )

            self._backend.store_entry(did_string, updated_entry)
            return updated_entry

    def lookup_vc(self, vc_id: str) -> AuditVC | None:
        """Look up a VC by its ID.

        Args:
            vc_id: The VC identifier (URN UUID).

        Returns:
            The AuditVC, or None if not found.
        """
        with self._lock:
            return self._backend.fetch_vc(vc_id)

    def remove(self, did: DID | str) -> bool:
        """Remove an entry and its associated VCs.

        Args:
            did: The agent's DID.

        Returns:
            True if the entry was removed, False if not found.
        """
        did_string = str(did) if isinstance(did, DID) else did
        with self._lock:
            entry = self._backend.fetch_entry(did_string)
            if entry is None:
                return False

            # Remove associated VCs
            for vc in entry.audit_vcs:
                self._backend.remove_vc(vc.id)

            # Remove entry
            self._backend.remove_entry(did_string)
            return True

    def clear(self) -> None:
        """Remove all entries and VCs from the registry."""
        with self._lock:
            self._backend.clear()

    def all_entries(self) -> list[TrustEntry]:
        """Return a snapshot list of all entries.

        Returns:
            A list of all trust entries.
        """
        with self._lock:
            return self._backend.all_entries()

    def __contains__(self, did: DID | str) -> bool:
        """Check if a DID is registered."""
        did_string = str(did) if isinstance(did, DID) else did
        with self._lock:
            return self._backend.contains(did_string)

    def __len__(self) -> int:
        """Return the number of registered entries."""
        with self._lock:
            return self._backend.count()


# Module-level singleton registry
_trust_registry: TrustRegistry | None = None
_registry_lock = threading.Lock()


def get_trust_registry() -> TrustRegistry:
    """Get the module-level trust registry singleton.

    Thread-safe initialization using double-checked locking.

    Returns:
        The shared TrustRegistry instance.
    """
    global _trust_registry
    if _trust_registry is None:
        with _registry_lock:
            if _trust_registry is None:
                _trust_registry = TrustRegistry()
    return _trust_registry
