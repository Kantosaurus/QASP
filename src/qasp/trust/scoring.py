"""Composite trust scoring.

This module combines multiple trust signals into
a unified trust score with cold-start handling,
anti-gaming caps, and collusion detection.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "TrustScore",
    "TrustScorer",
    "detect_collusion",
]


@dataclass(frozen=True)
class TrustScore:
    """A composite trust score."""

    overall: float
    certification_component: float
    reputation_component: float
    behavioral_component: float
    witness_component: float
    confidence: float

    def meets_threshold(self, threshold: float) -> bool:
        """Check if score meets a threshold.

        Args:
            threshold: The minimum acceptable score.

        Returns:
            True if overall score meets threshold.
        """
        return self.overall >= threshold


def _trust_cap_for_interactions(count: int) -> float:
    """Return the anti-gaming trust cap based on interaction count."""
    if count < 10:
        return 0.7
    if count < 50:
        return 0.8
    if count < 200:
        return 0.9
    return 1.0


class TrustScorer:
    """Composite trust scorer.

    Combines interaction reputation, witness reputation,
    certification, and behavioral signals into a unified
    trust score.
    """

    def __init__(
        self,
        interaction_weight: float = 0.35,
        witness_weight: float = 0.25,
        certification_weight: float = 0.20,
        behavioral_weight: float = 0.20,
    ) -> None:
        """Initialize the scorer.

        Args:
            interaction_weight: Weight for interaction reputation.
            witness_weight: Weight for witness reputation.
            certification_weight: Weight for certification score.
            behavioral_weight: Weight for behavioral score.

        Raises:
            ValueError: If weights don't sum to 1.0.
        """
        total = (
            interaction_weight + witness_weight
            + certification_weight + behavioral_weight
        )
        if abs(total - 1.0) > 0.001:
            msg = "Weights must sum to 1.0"
            raise ValueError(msg)

        self._interaction_weight = interaction_weight
        self._witness_weight = witness_weight
        self._cert_weight = certification_weight
        self._behav_weight = behavioral_weight

    def calculate(
        self,
        certification_score: float | None,
        reputation_score: float,
        behavioral_score: float,
        reputation_confidence: float,
        witness_score: float | None = None,
        interaction_count: int = 0,
    ) -> TrustScore:
        """Calculate the composite trust score.

        Args:
            certification_score: Score from audit certification (0-1, or None).
            reputation_score: Score from interaction reputation model (0-1).
            behavioral_score: Score from behavioral analysis (0-1).
            reputation_confidence: Confidence in reputation score (0-1).
            witness_score: Score from witness aggregation (0-1, or None).
            interaction_count: Number of direct interactions observed.

        Returns:
            The composite TrustScore.
        """
        # Cold-start handling: boost reputation when confidence is low
        effective_reputation = reputation_score
        if reputation_confidence < 0.3 and certification_score is not None:
            if certification_score >= 0.9:  # SLSA Level 3
                effective_reputation = max(effective_reputation, 0.7)
            elif certification_score >= 0.6:  # SLSA Level 2
                effective_reputation = max(effective_reputation, 0.5)
            elif certification_score >= 0.3:  # SLSA Level 1
                effective_reputation = max(effective_reputation, 0.3)

        cert_value = certification_score if certification_score is not None else 0.0
        witness_value = witness_score if witness_score is not None else 0.0

        # Weighted combination
        raw = (
            self._interaction_weight * effective_reputation
            + self._witness_weight * witness_value
            + self._cert_weight * cert_value
            + self._behav_weight * behavioral_score
        )

        # Anti-gaming trust cap
        trust_cap = _trust_cap_for_interactions(interaction_count)
        capped = min(raw, trust_cap)

        # Confidence blend: pull toward 0.5 when confidence is low
        overall = reputation_confidence * capped + (1.0 - reputation_confidence) * 0.5

        return TrustScore(
            overall=overall,
            certification_component=cert_value,
            reputation_component=effective_reputation,
            behavioral_component=behavioral_score,
            witness_component=witness_value,
            confidence=reputation_confidence,
        )


def detect_collusion(
    witness_scores: dict[str, float],
    threshold: float = 0.95,
    min_cluster_size: int = 3,
) -> list[list[str]]:
    """Detect potential witness collusion by score clustering.

    Sorts witnesses by reported score and groups those whose
    scores differ by less than (1 - threshold).

    Args:
        witness_scores: Mapping of witness DID to reported score.
        threshold: Similarity threshold (higher = more sensitive).
        min_cluster_size: Minimum cluster size to flag.

    Returns:
        List of suspicious clusters (each a list of DIDs).
    """
    if len(witness_scores) < min_cluster_size:
        return []

    max_diff = 1.0 - threshold
    sorted_witnesses = sorted(witness_scores.items(), key=lambda x: x[1])

    clusters: list[list[str]] = []
    current_cluster: list[str] = [sorted_witnesses[0][0]]
    current_base_score = sorted_witnesses[0][1]

    for did, score in sorted_witnesses[1:]:
        if score - current_base_score <= max_diff:
            current_cluster.append(did)
        else:
            if len(current_cluster) >= min_cluster_size:
                clusters.append(current_cluster)
            current_cluster = [did]
            current_base_score = score

    if len(current_cluster) >= min_cluster_size:
        clusters.append(current_cluster)

    return clusters
