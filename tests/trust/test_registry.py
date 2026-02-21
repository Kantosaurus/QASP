"""Tests for trust registry module."""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta

import pytest

from qasp.identity import DID
from qasp.trust import (
    SLSALevel,
    TrustEntry,
    TrustRegistry,
    create_audit_vc,
    get_trust_registry,
)
from qasp.trust.exceptions import (
    DuplicateEntryError,
    EntryNotFoundError,
    InvalidVCError,
)

# =============================================================================
# TrustEntry Tests
# =============================================================================


class TestTrustEntry:
    """Tests for TrustEntry dataclass."""

    def test_default_values(self, agent_did: DID) -> None:
        """Test TrustEntry has correct default values."""
        entry = TrustEntry(did=agent_did)

        assert entry.did == agent_did
        assert entry.reputation_alpha == 1.0
        assert entry.reputation_beta == 1.0
        assert entry.audit_vcs == ()
        assert entry.behavioral_score == 1.0
        assert entry.total_interactions == 0
        assert entry.successful_interactions == 0
        assert entry.last_interaction is None
        assert entry.flags == frozenset()

    def test_reputation_score_initial(self, agent_did: DID) -> None:
        """Test initial reputation score is 0.5 (uniform prior)."""
        entry = TrustEntry(did=agent_did)

        # Beta(1,1) has expected value 1/(1+1) = 0.5
        assert entry.reputation_score == 0.5

    def test_reputation_score_after_successes(self, agent_did: DID) -> None:
        """Test reputation score increases with successes."""
        # After 9 successes and 0 failures: alpha=10, beta=1
        # Expected value = 10/11 ≈ 0.909
        entry = TrustEntry(
            did=agent_did,
            reputation_alpha=10.0,
            reputation_beta=1.0,
        )

        assert abs(entry.reputation_score - 10 / 11) < 0.001

    def test_reputation_score_after_failures(self, agent_did: DID) -> None:
        """Test reputation score decreases with failures."""
        # After 0 successes and 9 failures: alpha=1, beta=10
        # Expected value = 1/11 ≈ 0.091
        entry = TrustEntry(
            did=agent_did,
            reputation_alpha=1.0,
            reputation_beta=10.0,
        )

        assert abs(entry.reputation_score - 1 / 11) < 0.001

    def test_best_slsa_level_no_vcs(self, agent_did: DID) -> None:
        """Test best_slsa_level returns None with no VCs."""
        entry = TrustEntry(did=agent_did)
        assert entry.best_slsa_level is None

    def test_best_slsa_level_with_vc(
        self,
        auditor_did: DID,
        auditor_secret_key: bytes,
        agent_did: DID,
        sample_code_hash: bytes,
    ) -> None:
        """Test best_slsa_level returns highest level from valid VCs."""
        vc1 = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_did,
            audit_scope="Audit 1",
            code_version_hash=sample_code_hash,
            audit_result="PASSED",
            slsa_level=SLSALevel.LEVEL_1,
        )
        vc2 = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_did,
            audit_scope="Audit 2",
            code_version_hash=sample_code_hash,
            audit_result="PASSED",
            slsa_level=SLSALevel.LEVEL_3,
        )

        entry = TrustEntry(did=agent_did, audit_vcs=(vc1, vc2))

        assert entry.best_slsa_level == 3

    def test_best_slsa_level_ignores_expired(
        self,
        auditor_did: DID,
        auditor_secret_key: bytes,
        agent_did: DID,
        sample_code_hash: bytes,
    ) -> None:
        """Test best_slsa_level ignores expired VCs."""
        now = datetime.now(UTC)

        # Create expired SLSA 3 VC
        expired_vc = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_did,
            audit_scope="Expired audit",
            code_version_hash=sample_code_hash,
            audit_result="PASSED",
            slsa_level=SLSALevel.LEVEL_3,
            valid_from=now - timedelta(days=365),
            valid_until=now - timedelta(days=1),
        )

        # Create valid SLSA 1 VC
        valid_vc = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_did,
            audit_scope="Current audit",
            code_version_hash=sample_code_hash,
            audit_result="PASSED",
            slsa_level=SLSALevel.LEVEL_1,
        )

        entry = TrustEntry(did=agent_did, audit_vcs=(expired_vc, valid_vc))

        # Should return 1, not 3 (expired)
        assert entry.best_slsa_level == 1

    def test_audit_certified_score_no_vcs(self, agent_did: DID) -> None:
        """Test audit_certified_score is 0 with no VCs."""
        entry = TrustEntry(did=agent_did)
        assert entry.audit_certified_score == 0.0

    def test_audit_certified_score_level_1(
        self,
        auditor_did: DID,
        auditor_secret_key: bytes,
        agent_did: DID,
        sample_code_hash: bytes,
    ) -> None:
        """Test audit_certified_score for SLSA level 1."""
        vc = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_did,
            audit_scope="Audit",
            code_version_hash=sample_code_hash,
            audit_result="PASSED",
            slsa_level=SLSALevel.LEVEL_1,
        )
        entry = TrustEntry(did=agent_did, audit_vcs=(vc,))

        assert abs(entry.audit_certified_score - 1 / 3) < 0.001

    def test_audit_certified_score_level_3(
        self,
        auditor_did: DID,
        auditor_secret_key: bytes,
        agent_did: DID,
        sample_code_hash: bytes,
    ) -> None:
        """Test audit_certified_score for SLSA level 3."""
        vc = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_did,
            audit_scope="Audit",
            code_version_hash=sample_code_hash,
            audit_result="PASSED",
            slsa_level=SLSALevel.LEVEL_3,
        )
        entry = TrustEntry(did=agent_did, audit_vcs=(vc,))

        assert entry.audit_certified_score == 1.0

    def test_frozen_dataclass(self, agent_did: DID) -> None:
        """Test TrustEntry is immutable."""
        entry = TrustEntry(did=agent_did)

        with pytest.raises(AttributeError):
            entry.reputation_alpha = 5.0  # type: ignore[misc]


# =============================================================================
# TrustRegistry Registration Tests
# =============================================================================


class TestTrustRegistryRegistration:
    """Tests for TrustRegistry registration operations."""

    def test_register_new_agent(self, agent_did: DID) -> None:
        """Test registering a new agent."""
        registry = TrustRegistry()
        entry = registry.register(agent_did)

        assert entry.did == agent_did
        assert entry.reputation_score == 0.5
        assert len(registry) == 1

    def test_register_duplicate_raises(self, agent_did: DID) -> None:
        """Test registering duplicate DID raises error."""
        registry = TrustRegistry()
        registry.register(agent_did)

        with pytest.raises(DuplicateEntryError, match="Entry already exists"):
            registry.register(agent_did)

    def test_register_multiple_agents(
        self,
        agent_did: DID,
        second_agent_did: DID,
    ) -> None:
        """Test registering multiple agents."""
        registry = TrustRegistry()
        registry.register(agent_did)
        registry.register(second_agent_did)

        assert len(registry) == 2
        assert agent_did in registry
        assert second_agent_did in registry


# =============================================================================
# TrustRegistry Lookup Tests
# =============================================================================


class TestTrustRegistryLookup:
    """Tests for TrustRegistry lookup operations."""

    def test_lookup_found(self, agent_did: DID) -> None:
        """Test lookup returns entry when found."""
        registry = TrustRegistry()
        registry.register(agent_did)

        entry = registry.lookup(agent_did)
        assert entry is not None
        assert entry.did == agent_did

    def test_lookup_not_found(self, agent_did: DID) -> None:
        """Test lookup returns None when not found."""
        registry = TrustRegistry()

        entry = registry.lookup(agent_did)
        assert entry is None

    def test_lookup_with_string_did(self, agent_did: DID) -> None:
        """Test lookup works with string DID."""
        registry = TrustRegistry()
        registry.register(agent_did)

        entry = registry.lookup(str(agent_did))
        assert entry is not None
        assert entry.did == agent_did

    def test_get_found(self, agent_did: DID) -> None:
        """Test get returns entry when found."""
        registry = TrustRegistry()
        registry.register(agent_did)

        entry = registry.get(agent_did)
        assert entry.did == agent_did

    def test_get_not_found_raises(self, agent_did: DID) -> None:
        """Test get raises EntryNotFoundError when not found."""
        registry = TrustRegistry()

        with pytest.raises(EntryNotFoundError, match="No entry found"):
            registry.get(agent_did)


# =============================================================================
# TrustRegistry Reputation Tests
# =============================================================================


class TestTrustRegistryReputation:
    """Tests for TrustRegistry reputation operations."""

    def test_update_reputation_success(self, agent_did: DID) -> None:
        """Test updating reputation after successful interaction."""
        registry = TrustRegistry()
        registry.register(agent_did)

        entry = registry.update_reputation(agent_did, success=True)

        # After 1 success: alpha=2, beta=1
        # Expected value = 2/3 ≈ 0.667
        assert entry.reputation_alpha == 2.0
        assert entry.reputation_beta == 1.0
        assert abs(entry.reputation_score - 2 / 3) < 0.001
        assert entry.total_interactions == 1
        assert entry.successful_interactions == 1
        assert entry.last_interaction is not None

    def test_update_reputation_failure(self, agent_did: DID) -> None:
        """Test updating reputation after failed interaction."""
        registry = TrustRegistry()
        registry.register(agent_did)

        entry = registry.update_reputation(agent_did, success=False)

        # After 1 failure: alpha=1, beta=2
        # Expected value = 1/3 ≈ 0.333
        assert entry.reputation_alpha == 1.0
        assert entry.reputation_beta == 2.0
        assert abs(entry.reputation_score - 1 / 3) < 0.001
        assert entry.total_interactions == 1
        assert entry.successful_interactions == 0

    def test_update_reputation_multiple(self, agent_did: DID) -> None:
        """Test multiple reputation updates."""
        registry = TrustRegistry()
        registry.register(agent_did)

        # 3 successes, 1 failure
        registry.update_reputation(agent_did, success=True)
        registry.update_reputation(agent_did, success=True)
        registry.update_reputation(agent_did, success=True)
        entry = registry.update_reputation(agent_did, success=False)

        # alpha = 1 + 3 = 4, beta = 1 + 1 = 2
        assert entry.reputation_alpha == 4.0
        assert entry.reputation_beta == 2.0
        assert entry.total_interactions == 4
        assert entry.successful_interactions == 3

    def test_update_reputation_not_found(self, agent_did: DID) -> None:
        """Test updating reputation for non-existent DID raises."""
        registry = TrustRegistry()

        with pytest.raises(EntryNotFoundError):
            registry.update_reputation(agent_did, success=True)


# =============================================================================
# TrustRegistry Audit VC Tests
# =============================================================================


class TestTrustRegistryAuditVC:
    """Tests for TrustRegistry audit VC operations."""

    def test_add_audit_vc(
        self,
        auditor_did: DID,
        auditor_secret_key: bytes,
        agent_did: DID,
        sample_code_hash: bytes,
    ) -> None:
        """Test adding an audit VC to an entry."""
        registry = TrustRegistry()
        registry.register(agent_did)

        vc = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_did,
            audit_scope="Audit",
            code_version_hash=sample_code_hash,
            audit_result="PASSED",
            slsa_level=SLSALevel.LEVEL_2,
        )

        entry = registry.add_audit_vc(agent_did, vc)

        assert len(entry.audit_vcs) == 1
        assert entry.audit_vcs[0] == vc
        assert entry.best_slsa_level == 2

    def test_add_audit_vc_lookup(
        self,
        auditor_did: DID,
        auditor_secret_key: bytes,
        agent_did: DID,
        sample_code_hash: bytes,
    ) -> None:
        """Test VC can be looked up by ID after adding."""
        registry = TrustRegistry()
        registry.register(agent_did)

        vc = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_did,
            audit_scope="Audit",
            code_version_hash=sample_code_hash,
            audit_result="PASSED",
            slsa_level=SLSALevel.LEVEL_1,
        )

        registry.add_audit_vc(agent_did, vc)

        looked_up_vc = registry.lookup_vc(vc.id)
        assert looked_up_vc == vc

    def test_add_audit_vc_wrong_subject(
        self,
        auditor_did: DID,
        auditor_secret_key: bytes,
        agent_did: DID,
        second_agent_did: DID,
        sample_code_hash: bytes,
    ) -> None:
        """Test adding VC with wrong subject DID raises error."""
        registry = TrustRegistry()
        registry.register(agent_did)

        # Create VC for second_agent
        vc = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=second_agent_did,  # Different agent!
            audit_scope="Audit",
            code_version_hash=sample_code_hash,
            audit_result="PASSED",
            slsa_level=SLSALevel.LEVEL_1,
        )

        # Try to add to first agent's entry
        with pytest.raises(InvalidVCError, match="does not match"):
            registry.add_audit_vc(agent_did, vc)

    def test_add_audit_vc_not_found(
        self,
        auditor_did: DID,
        auditor_secret_key: bytes,
        agent_did: DID,
        sample_code_hash: bytes,
    ) -> None:
        """Test adding VC to non-existent entry raises."""
        registry = TrustRegistry()

        vc = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_did,
            audit_scope="Audit",
            code_version_hash=sample_code_hash,
            audit_result="PASSED",
            slsa_level=SLSALevel.LEVEL_1,
        )

        with pytest.raises(EntryNotFoundError):
            registry.add_audit_vc(agent_did, vc)


# =============================================================================
# TrustRegistry Flag Tests
# =============================================================================


class TestTrustRegistryFlags:
    """Tests for TrustRegistry flag operations."""

    def test_add_flag(self, agent_did: DID) -> None:
        """Test adding a flag to an entry."""
        registry = TrustRegistry()
        registry.register(agent_did)

        entry = registry.add_flag(agent_did, "suspicious_behavior")

        assert "suspicious_behavior" in entry.flags

    def test_add_multiple_flags(self, agent_did: DID) -> None:
        """Test adding multiple flags."""
        registry = TrustRegistry()
        registry.register(agent_did)

        registry.add_flag(agent_did, "flag_1")
        entry = registry.add_flag(agent_did, "flag_2")

        assert "flag_1" in entry.flags
        assert "flag_2" in entry.flags

    def test_remove_flag(self, agent_did: DID) -> None:
        """Test removing a flag from an entry."""
        registry = TrustRegistry()
        registry.register(agent_did)
        registry.add_flag(agent_did, "to_be_removed")

        entry = registry.remove_flag(agent_did, "to_be_removed")

        assert "to_be_removed" not in entry.flags

    def test_remove_nonexistent_flag(self, agent_did: DID) -> None:
        """Test removing a flag that doesn't exist is a no-op."""
        registry = TrustRegistry()
        registry.register(agent_did)

        entry = registry.remove_flag(agent_did, "nonexistent")

        assert "nonexistent" not in entry.flags


# =============================================================================
# TrustRegistry Removal Tests
# =============================================================================


class TestTrustRegistryRemoval:
    """Tests for TrustRegistry removal operations."""

    def test_remove_entry(self, agent_did: DID) -> None:
        """Test removing an entry."""
        registry = TrustRegistry()
        registry.register(agent_did)

        removed = registry.remove(agent_did)

        assert removed is True
        assert agent_did not in registry

    def test_remove_nonexistent(self, agent_did: DID) -> None:
        """Test removing non-existent entry returns False."""
        registry = TrustRegistry()

        removed = registry.remove(agent_did)

        assert removed is False

    def test_remove_clears_vcs(
        self,
        auditor_did: DID,
        auditor_secret_key: bytes,
        agent_did: DID,
        sample_code_hash: bytes,
    ) -> None:
        """Test removing entry also removes associated VCs."""
        registry = TrustRegistry()
        registry.register(agent_did)

        vc = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_did,
            audit_scope="Audit",
            code_version_hash=sample_code_hash,
            audit_result="PASSED",
            slsa_level=SLSALevel.LEVEL_1,
        )
        registry.add_audit_vc(agent_did, vc)

        # VC should be findable
        assert registry.lookup_vc(vc.id) is not None

        # Remove entry
        registry.remove(agent_did)

        # VC should no longer be findable
        assert registry.lookup_vc(vc.id) is None

    def test_clear_registry(
        self,
        agent_did: DID,
        second_agent_did: DID,
    ) -> None:
        """Test clearing the entire registry."""
        registry = TrustRegistry()
        registry.register(agent_did)
        registry.register(second_agent_did)

        registry.clear()

        assert len(registry) == 0
        assert agent_did not in registry
        assert second_agent_did not in registry


# =============================================================================
# TrustRegistry Collection Tests
# =============================================================================


class TestTrustRegistryCollection:
    """Tests for TrustRegistry collection operations."""

    def test_all_entries(
        self,
        agent_did: DID,
        second_agent_did: DID,
    ) -> None:
        """Test getting all entries."""
        registry = TrustRegistry()
        registry.register(agent_did)
        registry.register(second_agent_did)

        entries = registry.all_entries()

        assert len(entries) == 2
        dids = {entry.did for entry in entries}
        assert agent_did in dids
        assert second_agent_did in dids

    def test_contains(self, agent_did: DID) -> None:
        """Test __contains__ operator."""
        registry = TrustRegistry()

        assert agent_did not in registry

        registry.register(agent_did)

        assert agent_did in registry

    def test_len(
        self,
        agent_did: DID,
        second_agent_did: DID,
    ) -> None:
        """Test __len__ operator."""
        registry = TrustRegistry()

        assert len(registry) == 0

        registry.register(agent_did)
        assert len(registry) == 1

        registry.register(second_agent_did)
        assert len(registry) == 2


# =============================================================================
# Thread Safety Tests
# =============================================================================


class TestTrustRegistryThreadSafety:
    """Tests for TrustRegistry thread safety."""

    def test_concurrent_registration(self) -> None:
        """Test concurrent registration from multiple threads."""
        from qasp.crypto import signatures
        from qasp.identity import create_did

        registry = TrustRegistry()
        errors: list[Exception] = []
        success_count = [0]

        def register_agent(_i: int) -> None:
            try:
                pk, _ = signatures.generate_keypair()
                did, _ = create_did(pk)
                registry.register(did)
                success_count[0] += 1
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=register_agent, args=(i,))
            for i in range(10)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(registry) == 10

    def test_concurrent_reputation_updates(self, agent_did: DID) -> None:
        """Test concurrent reputation updates from multiple threads."""
        registry = TrustRegistry()
        registry.register(agent_did)

        def update_reputation(success: bool) -> None:
            for _ in range(100):
                registry.update_reputation(agent_did, success=success)

        # Half threads do successes, half do failures
        threads = [
            threading.Thread(target=update_reputation, args=(i % 2 == 0,))
            for i in range(4)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        entry = registry.get(agent_did)
        # 200 successes (2 threads * 100) + 200 failures
        assert entry.total_interactions == 400


# =============================================================================
# Singleton Tests
# =============================================================================


class TestGetTrustRegistry:
    """Tests for get_trust_registry singleton."""

    def test_same_instance(self) -> None:
        """Test get_trust_registry returns same instance."""
        registry1 = get_trust_registry()
        registry2 = get_trust_registry()

        assert registry1 is registry2

    def test_singleton_from_threads(self) -> None:
        """Test singleton is consistent across threads."""
        registries: list[TrustRegistry] = []

        def get_registry() -> None:
            registries.append(get_trust_registry())

        threads = [threading.Thread(target=get_registry) for _ in range(10)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All should be the same instance
        first = registries[0]
        assert all(r is first for r in registries)
