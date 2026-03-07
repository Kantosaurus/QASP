"""Behavioral verification.

This module implements behavioral checks for verifying
agent behavior patterns, including FSM-based state tracking,
capability manifests, anomaly detection, and goal-conditioned
drift detection (KL-divergence + Wasserstein distance).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum, auto

import cbor2

from qasp.crypto.signatures import sign as mldsa_sign
from qasp.crypto.signatures import verify as mldsa_verify
from qasp.trust.exceptions import ManifestError

__all__ = [
    "EVENT_STATE_MAP",
    "PERMITTED_TRANSITIONS",
    "BehaviorDistribution",
    "BehaviorEvent",
    "BehaviorState",
    "BehaviorType",
    "BehavioralVerifier",
    "CapabilityManifest",
    "DriftDetector",
    "create_manifest",
    "is_permitted_transition",
    "verify_manifest",
]


class BehaviorType(Enum):
    """Types of behavioral events."""

    REQUEST = auto()
    RESPONSE = auto()
    ERROR = auto()
    TIMEOUT = auto()
    RATE_LIMIT = auto()
    POLICY_VIOLATION = auto()


@dataclass(frozen=True)
class BehaviorEvent:
    """A behavioral event record."""

    event_type: BehaviorType
    timestamp: datetime
    details: dict[str, str]


class BehaviorState(Enum):
    """Agent behavioral states for FSM tracking."""

    IDLE = auto()
    REQUESTING = auto()
    PROCESSING = auto()
    RESPONDING = auto()
    ERROR_HANDLING = auto()
    RATE_LIMITED = auto()
    SUSPENDED = auto()


EVENT_STATE_MAP: dict[BehaviorType, BehaviorState] = {
    BehaviorType.REQUEST: BehaviorState.REQUESTING,
    BehaviorType.RESPONSE: BehaviorState.RESPONDING,
    BehaviorType.ERROR: BehaviorState.ERROR_HANDLING,
    BehaviorType.TIMEOUT: BehaviorState.ERROR_HANDLING,
    BehaviorType.RATE_LIMIT: BehaviorState.RATE_LIMITED,
    BehaviorType.POLICY_VIOLATION: BehaviorState.SUSPENDED,
}


PERMITTED_TRANSITIONS: dict[BehaviorState, frozenset[BehaviorState]] = {
    BehaviorState.IDLE: frozenset({
        BehaviorState.REQUESTING,
        BehaviorState.ERROR_HANDLING,
        BehaviorState.SUSPENDED,
    }),
    BehaviorState.REQUESTING: frozenset({
        BehaviorState.PROCESSING,
        BehaviorState.RESPONDING,
        BehaviorState.ERROR_HANDLING,
        BehaviorState.RATE_LIMITED,
        BehaviorState.SUSPENDED,
    }),
    BehaviorState.PROCESSING: frozenset({
        BehaviorState.RESPONDING,
        BehaviorState.ERROR_HANDLING,
        BehaviorState.RATE_LIMITED,
        BehaviorState.SUSPENDED,
    }),
    BehaviorState.RESPONDING: frozenset({
        BehaviorState.IDLE,
        BehaviorState.REQUESTING,
        BehaviorState.ERROR_HANDLING,
        BehaviorState.SUSPENDED,
    }),
    BehaviorState.ERROR_HANDLING: frozenset({
        BehaviorState.IDLE,
        BehaviorState.REQUESTING,
        BehaviorState.SUSPENDED,
    }),
    BehaviorState.RATE_LIMITED: frozenset({
        BehaviorState.IDLE,
        BehaviorState.REQUESTING,
        BehaviorState.SUSPENDED,
    }),
    BehaviorState.SUSPENDED: frozenset({
        BehaviorState.IDLE,
    }),
}


def is_permitted_transition(
    from_state: BehaviorState,
    to_state: BehaviorState,
) -> bool:
    """Check if a behavioral state transition is permitted.

    Args:
        from_state: The current state.
        to_state: The proposed next state.

    Returns:
        True if the transition is permitted.
    """
    return to_state in PERMITTED_TRANSITIONS.get(from_state, frozenset())


@dataclass(frozen=True)
class CapabilityManifest:
    """A signed capability manifest declaring agent behaviors."""

    agent_did: str
    declared_behaviors: tuple[tuple[str, str], ...]
    permitted_event_types: tuple[BehaviorType, ...]
    public_key: bytes
    signature: bytes
    created: datetime


def _manifest_payload(
    agent_did: str,
    declared_behaviors: tuple[tuple[str, str], ...],
    permitted_event_types: tuple[BehaviorType, ...],
    public_key: bytes,
    created: datetime,
) -> bytes:
    """Build the CBOR-encoded manifest payload (without signature)."""
    data = {
        "agent_did": agent_did,
        "declared_behaviors": [list(pair) for pair in declared_behaviors],
        "permitted_event_types": [et.name for et in permitted_event_types],
        "public_key": public_key,
        "created": created.isoformat(),
    }
    return cbor2.dumps(data)


def create_manifest(
    agent_did: str,
    declared_behaviors: tuple[tuple[str, str], ...],
    permitted_event_types: tuple[BehaviorType, ...],
    public_key: bytes,
    secret_key: bytes,
) -> CapabilityManifest:
    """Create a signed capability manifest.

    Args:
        agent_did: The agent's DID.
        declared_behaviors: Pairs of (from_state_name, to_state_name).
        permitted_event_types: Event types the agent may emit.
        public_key: The agent's ML-DSA-65 public key.
        secret_key: The agent's ML-DSA-65 secret key.

    Returns:
        A signed CapabilityManifest.
    """
    created = datetime.now(UTC)
    payload = _manifest_payload(
        agent_did, declared_behaviors, permitted_event_types, public_key, created
    )
    signature = mldsa_sign(secret_key, payload)
    return CapabilityManifest(
        agent_did=agent_did,
        declared_behaviors=declared_behaviors,
        permitted_event_types=permitted_event_types,
        public_key=public_key,
        signature=signature,
        created=created,
    )


def verify_manifest(manifest: CapabilityManifest) -> bool:
    """Verify a capability manifest's signature.

    Args:
        manifest: The manifest to verify.

    Returns:
        True if the signature is valid.

    Raises:
        ManifestError: If signature verification fails.
    """
    payload = _manifest_payload(
        manifest.agent_did,
        manifest.declared_behaviors,
        manifest.permitted_event_types,
        manifest.public_key,
        manifest.created,
    )
    try:
        return mldsa_verify(manifest.public_key, payload, manifest.signature)
    except Exception as e:
        raise ManifestError(f"Manifest verification failed: {e}") from e


class BehavioralVerifier:
    """Behavioral verification for agents with FSM state tracking."""

    def __init__(
        self,
        did: str,
        manifest: CapabilityManifest | None = None,
        window_size: int = 100,
        severe_penalty: float = 10.0,
    ) -> None:
        """Initialize the verifier.

        Args:
            did: The agent's DID.
            manifest: Optional capability manifest for the agent.
            window_size: Sliding window size for score calculation.
            severe_penalty: Weight multiplier for policy violations.
        """
        self._did = did
        self._events: list[BehaviorEvent] = []
        self._manifest = manifest
        self._window_size = window_size
        self._severe_penalty = severe_penalty
        self._current_state = BehaviorState.IDLE
        self._violation_indices: set[int] = set()

    @property
    def current_state(self) -> BehaviorState:
        return self._current_state

    def record_event(self, event: BehaviorEvent) -> None:
        """Record a behavioral event with FSM transition checking.

        Args:
            event: The event to record.
        """
        target_state = EVENT_STATE_MAP.get(event.event_type, self._current_state)
        idx = len(self._events)

        if not is_permitted_transition(self._current_state, target_state):
            self._violation_indices.add(idx)

        self._current_state = target_state
        self._events.append(event)

    def analyze_patterns(self) -> dict[str, float]:
        """Analyze behavioral patterns.

        Returns:
            Dictionary of behavioral metrics.
        """
        total = len(self._events)
        if total == 0:
            return {
                "total_events": 0.0,
                "violation_count": 0.0,
                "violation_rate": 0.0,
                "request_rate": 0.0,
                "error_rate": 0.0,
                "timeout_rate": 0.0,
                "policy_violation_rate": 0.0,
                "compliance_score": 1.0,
            }

        counts: dict[BehaviorType, int] = {}
        for event in self._events:
            counts[event.event_type] = counts.get(event.event_type, 0) + 1

        violation_count = len(self._violation_indices)
        return {
            "total_events": float(total),
            "violation_count": float(violation_count),
            "violation_rate": violation_count / total,
            "request_rate": counts.get(BehaviorType.REQUEST, 0) / total,
            "error_rate": counts.get(BehaviorType.ERROR, 0) / total,
            "timeout_rate": counts.get(BehaviorType.TIMEOUT, 0) / total,
            "policy_violation_rate": counts.get(BehaviorType.POLICY_VIOLATION, 0)
            / total,
            "compliance_score": 1.0 - violation_count / total,
        }

    def detect_anomalies(self) -> list[BehaviorEvent]:
        """Detect anomalous behaviors.

        Returns FSM violations and POLICY_VIOLATION events.

        Returns:
            List of anomalous events.
        """
        anomalies: list[BehaviorEvent] = []
        for i, event in enumerate(self._events):
            if i in self._violation_indices or event.event_type == BehaviorType.POLICY_VIOLATION:
                anomalies.append(event)
        return anomalies

    def calculate_score(self) -> float:
        """Calculate a behavioral trust score using a sliding window.

        Uses the last `window_size` events. Policy violations receive
        a `severe_penalty` weight multiplier.

        Returns:
            Behavioral score from 0.0 to 1.0.
        """
        if not self._events:
            return 1.0

        window_events = self._events[-self._window_size :]
        window_start = len(self._events) - len(window_events)

        total_weight = 0.0
        violation_weight = 0.0

        for i, event in enumerate(window_events):
            global_idx = window_start + i
            is_policy = event.event_type == BehaviorType.POLICY_VIOLATION
            weight = self._severe_penalty if is_policy else 1.0
            total_weight += weight

            if global_idx in self._violation_indices or is_policy:
                violation_weight += weight

        if total_weight == 0.0:
            return 1.0

        score = 1.0 - (violation_weight / total_weight)
        return max(0.0, min(1.0, score))

    def detect_drift(self, baseline_events: list[BehaviorEvent] | None = None) -> float:
        """Detect behavioral drift from a baseline distribution.

        Uses the first half of recorded events as baseline if none provided.

        Args:
            baseline_events: Optional baseline event list. If None, uses
                first half of recorded events.

        Returns:
            Combined drift score in [0.0, 1.0].
        """
        if len(self._events) < 4:
            return 0.0

        if baseline_events is not None:
            baseline = DriftDetector.distribution_from_events(baseline_events)
        else:
            mid = len(self._events) // 2
            baseline = DriftDetector.distribution_from_events(self._events[:mid])

        current = DriftDetector.distribution_from_events(self._events[len(self._events) // 2 :])
        detector = DriftDetector(baseline=baseline)
        return detector.compute_drift_score(current)


# =============================================================================
# Drift Detection (Section 10.5.3)
# =============================================================================

# Canonical ordering of BehaviorType for Wasserstein distance
_BEHAVIOR_TYPE_ORDER: list[BehaviorType] = sorted(BehaviorType, key=lambda bt: bt.value)


@dataclass(frozen=True)
class BehaviorDistribution:
    """Probability distribution over BehaviorType values."""

    probs: dict[BehaviorType, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Normalize if needed
        total = sum(self.probs.values())
        if total > 0 and abs(total - 1.0) > 1e-9:
            normalized = {k: v / total for k, v in self.probs.items()}
            object.__setattr__(self, "probs", normalized)


class DriftDetector:
    """Goal-conditioned drift detection using KL-divergence and Wasserstein distance.

    Args:
        baseline: The reference (expected) behavior distribution.
        kl_threshold: Threshold for KL-divergence normalization (default 2.0).
        wasserstein_threshold: Threshold for Wasserstein normalization (default 1.0).
        kl_weight: Weight for KL component (default 0.6).
        wasserstein_weight: Weight for Wasserstein component (default 0.4).
    """

    def __init__(
        self,
        baseline: BehaviorDistribution,
        *,
        kl_threshold: float = 2.0,
        wasserstein_threshold: float = 1.0,
        kl_weight: float = 0.6,
        wasserstein_weight: float = 0.4,
    ) -> None:
        self._baseline = baseline
        self._kl_threshold = kl_threshold
        self._wasserstein_threshold = wasserstein_threshold
        self._kl_weight = kl_weight
        self._wasserstein_weight = wasserstein_weight

    @staticmethod
    def kl_divergence(p: BehaviorDistribution, q: BehaviorDistribution) -> float:
        """Compute KL(P || Q) with Laplace smoothing.

        Args:
            p: The observed distribution.
            q: The reference distribution.

        Returns:
            Non-negative KL divergence value.
        """
        epsilon = 1e-10
        types = _BEHAVIOR_TYPE_ORDER
        result = 0.0
        for bt in types:
            p_val = p.probs.get(bt, 0.0) + epsilon
            q_val = q.probs.get(bt, 0.0) + epsilon
            result += p_val * math.log(p_val / q_val)
        return max(0.0, result)

    @staticmethod
    def wasserstein_distance(
        p: BehaviorDistribution, q: BehaviorDistribution,
    ) -> float:
        """Compute Wasserstein-1 (earth mover's) distance over BehaviorType ordering.

        Args:
            p: First distribution.
            q: Second distribution.

        Returns:
            Non-negative Wasserstein-1 distance.
        """
        types = _BEHAVIOR_TYPE_ORDER
        cdf_diff = 0.0
        p_cum = 0.0
        q_cum = 0.0
        result = 0.0
        for bt in types:
            p_cum += p.probs.get(bt, 0.0)
            q_cum += q.probs.get(bt, 0.0)
            result += abs(p_cum - q_cum)
        return result

    def compute_drift_score(self, current: BehaviorDistribution) -> float:
        """Compute combined drift score from baseline.

        Args:
            current: The current observed behavior distribution.

        Returns:
            Drift score in [0.0, 1.0]. 0 means no drift, 1 means maximum drift.
        """
        kl = self.kl_divergence(current, self._baseline)
        w = self.wasserstein_distance(current, self._baseline)

        kl_norm = min(1.0, kl / self._kl_threshold) if self._kl_threshold > 0 else 0.0
        w_norm = min(1.0, w / self._wasserstein_threshold) if self._wasserstein_threshold > 0 else 0.0

        score = self._kl_weight * kl_norm + self._wasserstein_weight * w_norm
        return max(0.0, min(1.0, score))

    @staticmethod
    def distribution_from_events(events: list[BehaviorEvent]) -> BehaviorDistribution:
        """Build a BehaviorDistribution from a list of events.

        Args:
            events: List of behavior events.

        Returns:
            Normalized probability distribution.
        """
        if not events:
            return BehaviorDistribution()
        counts: dict[BehaviorType, float] = {}
        for e in events:
            counts[e.event_type] = counts.get(e.event_type, 0.0) + 1.0
        total = len(events)
        return BehaviorDistribution(probs={k: v / total for k, v in counts.items()})
