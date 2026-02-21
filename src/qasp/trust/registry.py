"""Trust registry for agent trust information.

This module implements a thread-safe in-memory trust registry for tracking
agent trust information including Bayesian reputation scores, audit VCs,
and behavioral metrics.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from qasp.identity.did import DID
from qasp.trust.certification import AuditVC
from qasp.trust.exceptions import DuplicateEntryError, EntryNotFoundError, InvalidVCError

if TYPE_CHECKING:
    pass

__all__ = [
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


class TrustRegistry:
    """Thread-safe registry for agent trust information.

    Provides a simple in-memory registry for tracking trust entries.
    All operations are protected by a reentrant lock for thread safety.
    """

    def __init__(self) -> None:
        """Initialize an empty registry."""
        self._lock = threading.RLock()
        self._entries: dict[str, TrustEntry] = {}
        self._vcs: dict[str, AuditVC] = {}  # VC ID -> VC lookup

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
            if did_string in self._entries:
                raise DuplicateEntryError(f"Entry already exists for DID: {did_string}")

            entry = TrustEntry(did=did)
            self._entries[did_string] = entry
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
            return self._entries.get(did_string)

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

            self._entries[did_string] = updated_entry
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
            self._vcs[vc.id] = vc

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

            self._entries[did_string] = updated_entry
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

            self._entries[did_string] = updated_entry
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

            self._entries[did_string] = updated_entry
            return updated_entry

    def lookup_vc(self, vc_id: str) -> AuditVC | None:
        """Look up a VC by its ID.

        Args:
            vc_id: The VC identifier (URN UUID).

        Returns:
            The AuditVC, or None if not found.
        """
        with self._lock:
            return self._vcs.get(vc_id)

    def remove(self, did: DID | str) -> bool:
        """Remove an entry and its associated VCs.

        Args:
            did: The agent's DID.

        Returns:
            True if the entry was removed, False if not found.
        """
        did_string = str(did) if isinstance(did, DID) else did
        with self._lock:
            entry = self._entries.get(did_string)
            if entry is None:
                return False

            # Remove associated VCs
            for vc in entry.audit_vcs:
                self._vcs.pop(vc.id, None)

            # Remove entry
            del self._entries[did_string]
            return True

    def clear(self) -> None:
        """Remove all entries and VCs from the registry."""
        with self._lock:
            self._entries.clear()
            self._vcs.clear()

    def all_entries(self) -> list[TrustEntry]:
        """Return a snapshot list of all entries.

        Returns:
            A list of all trust entries.
        """
        with self._lock:
            return list(self._entries.values())

    def __contains__(self, did: DID | str) -> bool:
        """Check if a DID is registered."""
        did_string = str(did) if isinstance(did, DID) else did
        with self._lock:
            return did_string in self._entries

    def __len__(self) -> int:
        """Return the number of registered entries."""
        with self._lock:
            return len(self._entries)


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
