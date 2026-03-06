"""Tests for composite trust scoring."""

from __future__ import annotations

import pytest

from qasp.trust.scoring import (
    TrustScore,
    TrustScorer,
    detect_collusion,
)


# =============================================================================
# TrustScorer Init Tests
# =============================================================================


class TestTrustScorerInit:
    """Tests for TrustScorer initialization."""

    def test_default_weights_sum_to_one(self) -> None:
        """Default weights sum to 1.0."""
        scorer = TrustScorer()
        total = (
            scorer._interaction_weight + scorer._witness_weight
            + scorer._cert_weight + scorer._behav_weight
        )
        assert total == pytest.approx(1.0)

    def test_custom_weights(self) -> None:
        """Custom weights that sum to 1.0 are accepted."""
        scorer = TrustScorer(
            interaction_weight=0.4,
            witness_weight=0.3,
            certification_weight=0.2,
            behavioral_weight=0.1,
        )
        assert scorer._interaction_weight == 0.4

    def test_weights_not_summing_to_one_raises(self) -> None:
        """Weights not summing to 1.0 raise ValueError."""
        with pytest.raises(ValueError, match="Weights must sum to 1.0"):
            TrustScorer(
                interaction_weight=0.5,
                witness_weight=0.5,
                certification_weight=0.5,
                behavioral_weight=0.5,
            )


# =============================================================================
# TrustScorer Calculate Tests
# =============================================================================


class TestTrustScorerCalculate:
    """Tests for basic weighted combination."""

    def test_basic_weighted_combination(self) -> None:
        """All components contribute to overall score."""
        scorer = TrustScorer()
        result = scorer.calculate(
            certification_score=1.0,
            reputation_score=1.0,
            behavioral_score=1.0,
            reputation_confidence=1.0,
            witness_score=1.0,
            interaction_count=200,
        )
        assert result.overall == pytest.approx(1.0)

    def test_cert_none_handling(self) -> None:
        """certification_score=None uses 0.0."""
        scorer = TrustScorer()
        result = scorer.calculate(
            certification_score=None,
            reputation_score=0.8,
            behavioral_score=0.8,
            reputation_confidence=1.0,
            witness_score=0.8,
            interaction_count=200,
        )
        # cert_value = 0.0, so overall < all-1.0 case
        assert result.overall < 1.0
        assert result.certification_component == 0.0

    def test_witness_none_fallback(self) -> None:
        """witness_score=None uses 0.0."""
        scorer = TrustScorer()
        result = scorer.calculate(
            certification_score=0.8,
            reputation_score=0.8,
            behavioral_score=0.8,
            reputation_confidence=1.0,
            witness_score=None,
            interaction_count=200,
        )
        assert result.witness_component == 0.0

    def test_trust_score_fields(self) -> None:
        """TrustScore has all expected fields."""
        scorer = TrustScorer()
        result = scorer.calculate(
            certification_score=0.5,
            reputation_score=0.5,
            behavioral_score=0.5,
            reputation_confidence=0.5,
            witness_score=0.5,
            interaction_count=100,
        )
        assert hasattr(result, "overall")
        assert hasattr(result, "certification_component")
        assert hasattr(result, "reputation_component")
        assert hasattr(result, "behavioral_component")
        assert hasattr(result, "witness_component")
        assert hasattr(result, "confidence")

    def test_meets_threshold(self) -> None:
        """meets_threshold works correctly."""
        score = TrustScore(
            overall=0.8,
            certification_component=0.2,
            reputation_component=0.3,
            behavioral_component=0.2,
            witness_component=0.1,
            confidence=0.9,
        )
        assert score.meets_threshold(0.7)
        assert not score.meets_threshold(0.9)


# =============================================================================
# Cold Start Tests
# =============================================================================


class TestColdStart:
    """Tests for cold-start reputation boosting."""

    def test_slsa3_boost(self) -> None:
        """SLSA Level 3 cert boosts reputation to at least 0.7."""
        scorer = TrustScorer()
        result = scorer.calculate(
            certification_score=1.0,  # SLSA3
            reputation_score=0.5,
            behavioral_score=1.0,
            reputation_confidence=0.1,  # Low confidence triggers cold-start
            witness_score=0.5,
            interaction_count=200,
        )
        assert result.reputation_component >= 0.7

    def test_slsa2_boost(self) -> None:
        """SLSA Level 2 cert boosts reputation to at least 0.5."""
        scorer = TrustScorer()
        result = scorer.calculate(
            certification_score=0.7,  # SLSA2
            reputation_score=0.3,
            behavioral_score=1.0,
            reputation_confidence=0.1,
            witness_score=0.5,
            interaction_count=200,
        )
        assert result.reputation_component >= 0.5

    def test_no_cert_no_boost(self) -> None:
        """No certification means no cold-start boost."""
        scorer = TrustScorer()
        result = scorer.calculate(
            certification_score=None,
            reputation_score=0.3,
            behavioral_score=1.0,
            reputation_confidence=0.1,
            witness_score=0.5,
            interaction_count=200,
        )
        assert result.reputation_component == pytest.approx(0.3)

    def test_high_confidence_no_boost(self) -> None:
        """High confidence doesn't trigger cold-start even with cert."""
        scorer = TrustScorer()
        result = scorer.calculate(
            certification_score=1.0,
            reputation_score=0.3,
            behavioral_score=1.0,
            reputation_confidence=0.5,  # Above 0.3 threshold
            witness_score=0.5,
            interaction_count=200,
        )
        assert result.reputation_component == pytest.approx(0.3)


# =============================================================================
# Anti-Gaming Tests
# =============================================================================


class TestAntiGaming:
    """Tests for anti-gaming trust caps."""

    def test_new_agent_capped(self) -> None:
        """New agents (0-9 interactions) are capped at 0.7."""
        scorer = TrustScorer()
        result = scorer.calculate(
            certification_score=1.0,
            reputation_score=1.0,
            behavioral_score=1.0,
            reputation_confidence=1.0,
            witness_score=1.0,
            interaction_count=5,
        )
        # raw = 1.0, cap = 0.7, confidence=1.0
        # overall = 1.0 * 0.7 + 0.0 * 0.5 = 0.7
        assert result.overall == pytest.approx(0.7)

    def test_cap_increases_with_interactions(self) -> None:
        """Trust cap increases as interactions grow."""
        scorer = TrustScorer()
        scores = []
        for count in [5, 25, 100, 300]:
            result = scorer.calculate(
                certification_score=1.0,
                reputation_score=1.0,
                behavioral_score=1.0,
                reputation_confidence=1.0,
                witness_score=1.0,
                interaction_count=count,
            )
            scores.append(result.overall)
        # Each should be >= the previous
        for i in range(1, len(scores)):
            assert scores[i] >= scores[i - 1]

    def test_200_plus_uncapped(self) -> None:
        """200+ interactions have no cap."""
        scorer = TrustScorer()
        result = scorer.calculate(
            certification_score=1.0,
            reputation_score=1.0,
            behavioral_score=1.0,
            reputation_confidence=1.0,
            witness_score=1.0,
            interaction_count=200,
        )
        assert result.overall == pytest.approx(1.0)

    def test_confidence_blend_pulls_to_half(self) -> None:
        """Low confidence pulls overall toward 0.5."""
        scorer = TrustScorer()
        result = scorer.calculate(
            certification_score=1.0,
            reputation_score=1.0,
            behavioral_score=1.0,
            reputation_confidence=0.0,
            witness_score=1.0,
            interaction_count=200,
        )
        assert result.overall == pytest.approx(0.5)


# =============================================================================
# Collusion Detection Tests
# =============================================================================


class TestDetectCollusion:
    """Tests for detect_collusion."""

    def test_identical_scores_flagged(self) -> None:
        """Witnesses with identical scores are flagged."""
        scores = {f"did:test:w{i}": 0.95 for i in range(5)}
        clusters = detect_collusion(scores, threshold=0.95, min_cluster_size=3)
        assert len(clusters) == 1
        assert len(clusters[0]) == 5

    def test_diverse_scores_not_flagged(self) -> None:
        """Witnesses with diverse scores are not flagged."""
        scores = {
            "did:test:w1": 0.1,
            "did:test:w2": 0.3,
            "did:test:w3": 0.5,
            "did:test:w4": 0.7,
            "did:test:w5": 0.9,
        }
        clusters = detect_collusion(scores, threshold=0.95, min_cluster_size=3)
        assert len(clusters) == 0

    def test_too_few_witnesses(self) -> None:
        """Fewer witnesses than min_cluster_size returns empty."""
        scores = {"did:test:w1": 0.95, "did:test:w2": 0.95}
        clusters = detect_collusion(scores, threshold=0.95, min_cluster_size=3)
        assert len(clusters) == 0

    def test_two_clusters(self) -> None:
        """Can detect multiple collusion clusters."""
        scores = {
            "did:test:a1": 0.30,
            "did:test:a2": 0.30,
            "did:test:a3": 0.30,
            "did:test:b1": 0.90,
            "did:test:b2": 0.90,
            "did:test:b3": 0.90,
        }
        clusters = detect_collusion(scores, threshold=0.95, min_cluster_size=3)
        assert len(clusters) == 2
