"""Tests for behavioral verification module."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from qasp.crypto.signatures import generate_keypair
from qasp.trust.behavioral import (
    BehaviorEvent,
    BehaviorState,
    BehaviorType,
    BehavioralVerifier,
    EVENT_STATE_MAP,
    PERMITTED_TRANSITIONS,
    CapabilityManifest,
    create_manifest,
    is_permitted_transition,
    verify_manifest,
)
from qasp.trust.exceptions import ManifestError


def _make_event(
    event_type: BehaviorType, **details: str
) -> BehaviorEvent:
    return BehaviorEvent(
        event_type=event_type,
        timestamp=datetime.now(UTC),
        details=details,
    )


# =============================================================================
# BehaviorState FSM Tests
# =============================================================================


class TestBehaviorStateFSM:
    """Tests for the behavioral FSM."""

    def test_all_states_have_transitions(self) -> None:
        """Every BehaviorState has an entry in PERMITTED_TRANSITIONS."""
        for state in BehaviorState:
            assert state in PERMITTED_TRANSITIONS

    def test_idle_to_requesting(self) -> None:
        assert is_permitted_transition(BehaviorState.IDLE, BehaviorState.REQUESTING)

    def test_requesting_to_responding(self) -> None:
        assert is_permitted_transition(
            BehaviorState.REQUESTING, BehaviorState.RESPONDING
        )

    def test_responding_to_idle(self) -> None:
        assert is_permitted_transition(BehaviorState.RESPONDING, BehaviorState.IDLE)

    def test_idle_to_processing_not_permitted(self) -> None:
        assert not is_permitted_transition(BehaviorState.IDLE, BehaviorState.PROCESSING)

    def test_suspended_only_to_idle(self) -> None:
        """Suspended can only transition to IDLE."""
        allowed = PERMITTED_TRANSITIONS[BehaviorState.SUSPENDED]
        assert allowed == frozenset({BehaviorState.IDLE})

    def test_all_events_mapped(self) -> None:
        """Every BehaviorType has an entry in EVENT_STATE_MAP."""
        for bt in BehaviorType:
            assert bt in EVENT_STATE_MAP


# =============================================================================
# Capability Manifest Tests
# =============================================================================


class TestCapabilityManifest:
    """Tests for manifest creation and verification."""

    def test_create_and_verify(self) -> None:
        """Created manifest verifies successfully."""
        pk, sk = generate_keypair()
        manifest = create_manifest(
            agent_did="did:test:agent1",
            declared_behaviors=(("IDLE", "REQUESTING"), ("REQUESTING", "RESPONDING")),
            permitted_event_types=(BehaviorType.REQUEST, BehaviorType.RESPONSE),
            public_key=pk,
            secret_key=sk,
        )
        assert isinstance(manifest, CapabilityManifest)
        assert verify_manifest(manifest) is True

    def test_wrong_key_raises(self) -> None:
        """Verification with wrong key raises ManifestError."""
        pk1, sk1 = generate_keypair()
        pk2, _ = generate_keypair()
        manifest = create_manifest(
            agent_did="did:test:agent2",
            declared_behaviors=(("IDLE", "REQUESTING"),),
            permitted_event_types=(BehaviorType.REQUEST,),
            public_key=pk1,
            secret_key=sk1,
        )
        # Tamper: replace public key
        tampered = CapabilityManifest(
            agent_did=manifest.agent_did,
            declared_behaviors=manifest.declared_behaviors,
            permitted_event_types=manifest.permitted_event_types,
            public_key=pk2,
            signature=manifest.signature,
            created=manifest.created,
        )
        with pytest.raises(ManifestError):
            verify_manifest(tampered)

    def test_manifest_fields(self) -> None:
        """Manifest has expected fields."""
        pk, sk = generate_keypair()
        manifest = create_manifest(
            agent_did="did:test:agent3",
            declared_behaviors=(("IDLE", "REQUESTING"),),
            permitted_event_types=(BehaviorType.REQUEST,),
            public_key=pk,
            secret_key=sk,
        )
        assert manifest.agent_did == "did:test:agent3"
        assert len(manifest.signature) > 0
        assert manifest.created is not None


# =============================================================================
# BehavioralVerifier Tests
# =============================================================================


class TestBehavioralVerifier:
    """Tests for BehavioralVerifier with FSM checking."""

    def test_normal_flow_no_violations(self) -> None:
        """Normal request-response flow has no violations."""
        v = BehavioralVerifier(did="did:test:v1")
        v.record_event(_make_event(BehaviorType.REQUEST))
        v.record_event(_make_event(BehaviorType.RESPONSE))
        assert v.current_state == BehaviorState.RESPONDING
        assert v.calculate_score() == pytest.approx(1.0)

    def test_fsm_violation_tracked(self) -> None:
        """Invalid FSM transition is tracked as violation."""
        v = BehavioralVerifier(did="did:test:v2")
        # IDLE -> RESPONDING is not permitted (needs REQUEST first)
        # But RESPONDING maps from RESPONSE event, and IDLE->RESPONDING is allowed
        # via IDLE->REQUESTING. Let's force an invalid one:
        # IDLE -> PROCESSING is not permitted
        # We need an event that maps to PROCESSING. PROCESSING isn't in EVENT_STATE_MAP,
        # so let's test with SUSPENDED from IDLE (which IS permitted via POLICY_VIOLATION)
        # Actually, let's test: IDLE->RESPONDING (RESPONSE event)
        # PERMITTED_TRANSITIONS[IDLE] = {REQUESTING, ERROR_HANDLING, SUSPENDED}
        # RESPONSE maps to RESPONDING, which is NOT in IDLE's permitted set
        v.record_event(_make_event(BehaviorType.RESPONSE))
        assert len(v._violation_indices) == 1
        assert v.calculate_score() < 1.0

    def test_policy_violation_severe_penalty(self) -> None:
        """Policy violations get severe_penalty weight."""
        v = BehavioralVerifier(did="did:test:v3", severe_penalty=10.0)
        # Normal events
        v.record_event(_make_event(BehaviorType.REQUEST))
        v.record_event(_make_event(BehaviorType.RESPONSE))
        # Back to IDLE-compatible state, then violation
        v.record_event(_make_event(BehaviorType.REQUEST))
        v.record_event(_make_event(BehaviorType.POLICY_VIOLATION))
        score = v.calculate_score()
        # 3 normal events (weight 1 each = 3) + 1 policy violation (weight 10)
        # violation_weight = 10, total_weight = 13
        # But POLICY_VIOLATION also maps to SUSPENDED, which may or may not be a
        # valid transition. From REQUESTING, SUSPENDED IS permitted.
        # So violation_weight = just the 10 for POLICY_VIOLATION type
        # score = 1 - 10/13 ≈ 0.23
        assert score < 0.5

    def test_sliding_window(self) -> None:
        """Sliding window considers only recent events."""
        v = BehavioralVerifier(did="did:test:v4", window_size=5)
        # Record 10 normal req/resp cycles
        for _ in range(10):
            v.record_event(_make_event(BehaviorType.REQUEST))
            v.record_event(_make_event(BehaviorType.RESPONSE))
        # Window only sees last 5 events, all normal
        assert v.calculate_score() == pytest.approx(1.0)

    def test_empty_events_score_one(self) -> None:
        """No events gives score 1.0."""
        v = BehavioralVerifier(did="did:test:v5")
        assert v.calculate_score() == 1.0

    def test_calculate_score_clamped(self) -> None:
        """Score is always in [0, 1]."""
        v = BehavioralVerifier(did="did:test:v6")
        for _ in range(10):
            v.record_event(_make_event(BehaviorType.POLICY_VIOLATION))
        score = v.calculate_score()
        assert 0.0 <= score <= 1.0


# =============================================================================
# Analysis Tests
# =============================================================================


class TestBehavioralVerifierAnalysis:
    """Tests for analyze_patterns and detect_anomalies."""

    def test_analyze_patterns_empty(self) -> None:
        """Empty verifier returns zero metrics."""
        v = BehavioralVerifier(did="did:test:a1")
        metrics = v.analyze_patterns()
        assert metrics["total_events"] == 0.0
        assert metrics["compliance_score"] == 1.0

    def test_analyze_patterns_with_events(self) -> None:
        """Patterns reflect actual event distribution."""
        v = BehavioralVerifier(did="did:test:a2")
        v.record_event(_make_event(BehaviorType.REQUEST))
        v.record_event(_make_event(BehaviorType.RESPONSE))
        v.record_event(_make_event(BehaviorType.ERROR))
        metrics = v.analyze_patterns()
        assert metrics["total_events"] == 3.0
        assert metrics["error_rate"] == pytest.approx(1 / 3)
        assert metrics["request_rate"] == pytest.approx(1 / 3)

    def test_detect_anomalies_returns_violations(self) -> None:
        """detect_anomalies returns FSM violations."""
        v = BehavioralVerifier(did="did:test:a3")
        # IDLE -> RESPONDING is an FSM violation
        v.record_event(_make_event(BehaviorType.RESPONSE))
        anomalies = v.detect_anomalies()
        assert len(anomalies) >= 1

    def test_detect_anomalies_returns_policy_violations(self) -> None:
        """detect_anomalies returns POLICY_VIOLATION events."""
        v = BehavioralVerifier(did="did:test:a4")
        v.record_event(_make_event(BehaviorType.POLICY_VIOLATION))
        anomalies = v.detect_anomalies()
        assert len(anomalies) == 1
        assert anomalies[0].event_type == BehaviorType.POLICY_VIOLATION

    def test_detect_anomalies_no_anomalies(self) -> None:
        """Normal flow produces no anomalies."""
        v = BehavioralVerifier(did="did:test:a5")
        v.record_event(_make_event(BehaviorType.REQUEST))
        v.record_event(_make_event(BehaviorType.RESPONSE))
        anomalies = v.detect_anomalies()
        assert len(anomalies) == 0
