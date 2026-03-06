"""Tests for Bayesian reputation scoring."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from qasp.trust.exceptions import ReputationError
from qasp.trust.reputation import (
    ReputationModel,
    ReputationScore,
    WitnessReport,
    aggregate_witness_reports,
)


# =============================================================================
# ReputationModel Basic Tests
# =============================================================================


class TestReputationModelBasic:
    """Tests for basic ReputationModel update/score."""

    def test_uniform_prior_score(self) -> None:
        """Uniform prior gives mean 0.5."""
        model = ReputationModel()
        s = model.score()
        assert s.mean == pytest.approx(0.5)
        assert s.sample_count == 0

    def test_update_returns_new_model(self) -> None:
        """Update returns a new model, doesn't mutate."""
        model = ReputationModel()
        updated = model.update(success=True)
        assert updated is not model
        assert model.score().mean == pytest.approx(0.5)
        assert updated.score().mean > 0.5

    def test_multiple_successes(self) -> None:
        """Multiple successes push mean toward 1."""
        model = ReputationModel()
        for _ in range(20):
            model = model.update(success=True)
        s = model.score()
        assert s.mean > 0.9
        assert s.sample_count == 20

    def test_multiple_failures(self) -> None:
        """Multiple failures push mean toward 0."""
        model = ReputationModel()
        for _ in range(20):
            model = model.update(success=False)
        s = model.score()
        assert s.mean < 0.1

    def test_mixed_observations(self) -> None:
        """Mixed observations give intermediate mean."""
        model = ReputationModel()
        for _ in range(10):
            model = model.update(success=True)
        for _ in range(10):
            model = model.update(success=False)
        s = model.score()
        assert 0.4 < s.mean < 0.6

    def test_score_bounded(self) -> None:
        """Score components are always in valid ranges."""
        model = ReputationModel()
        for _ in range(50):
            model = model.update(success=True)
        s = model.score()
        assert 0.0 <= s.mean <= 1.0
        assert s.variance >= 0.0
        assert 0.0 <= s.confidence <= 1.0
        assert s.sample_count >= 0

    def test_confidence_increases_with_evidence(self) -> None:
        """Confidence increases as more evidence is added."""
        low = ReputationModel(prior_alpha=2.0, prior_beta=2.0).score().confidence
        high = ReputationModel(prior_alpha=50.0, prior_beta=50.0).score().confidence
        assert high > low

    def test_lower_upper_bounds(self) -> None:
        """Lower and upper bounds bracket the mean."""
        model = ReputationModel()
        for _ in range(10):
            model = model.update(success=True)
        s = model.score()
        assert s.lower_bound <= s.mean <= s.upper_bound
        assert s.lower_bound >= 0.0
        assert s.upper_bound <= 1.0


# =============================================================================
# Time Decay Tests
# =============================================================================


class TestReputationModelTimeDecay:
    """Tests for time-based evidence decay."""

    def test_decay_reduces_evidence(self) -> None:
        """Decay pulls alpha/beta back toward prior."""
        t0 = datetime(2025, 1, 1, tzinfo=UTC)
        t1 = t0 + timedelta(days=30)
        model = ReputationModel(prior_alpha=10.0, prior_beta=2.0, decay_rate=0.1)
        updated = model.update(success=True, timestamp=t0)
        # After time passes, existing evidence decays
        decayed = updated.update(success=True, timestamp=t1)
        # The decayed model should have alpha closer to prior than raw accumulation
        no_decay_model = ReputationModel(prior_alpha=10.0, prior_beta=2.0, decay_rate=0.0)
        raw = no_decay_model.update(success=True).update(success=True)
        assert decayed.alpha < raw.alpha

    def test_no_decay_when_rate_zero(self) -> None:
        """No decay when decay_rate is 0."""
        t0 = datetime(2025, 1, 1, tzinfo=UTC)
        t1 = t0 + timedelta(days=365)
        model = ReputationModel(prior_alpha=5.0, prior_beta=2.0, decay_rate=0.0)
        updated = model.update(success=True, timestamp=t0)
        later = updated.update(success=True, timestamp=t1)
        # Without decay, alpha should just be +2 from two successes
        assert later.alpha == pytest.approx(7.0)

    def test_decay_preserves_prior(self) -> None:
        """Decay preserves the prior pseudo-observations."""
        t0 = datetime(2025, 1, 1, tzinfo=UTC)
        t1 = t0 + timedelta(days=1000)  # Very long time
        model = ReputationModel(prior_alpha=5.0, prior_beta=1.0, decay_rate=1.0)
        # After extreme decay, alpha should approach prior (1.0) + 1 success
        updated = model.update(success=True, timestamp=t0)
        decayed = updated.update(success=True, timestamp=t1)
        # Evidence should be almost fully decayed, so alpha ~ 1.0 + 1.0 = 2.0
        assert decayed.alpha < 3.0

    def test_no_decay_without_timestamps(self) -> None:
        """No decay when timestamps are not provided."""
        model = ReputationModel(prior_alpha=5.0, prior_beta=2.0, decay_rate=0.5)
        updated = model.update(success=True)
        assert updated.alpha == pytest.approx(6.0)


# =============================================================================
# Probability Above Tests
# =============================================================================


class TestReputationModelProbabilityAbove:
    """Tests for probability_above using incomplete beta."""

    def test_uniform_prior_half(self) -> None:
        """Uniform Beta(1,1) has ~50% probability above 0.5."""
        model = ReputationModel()
        p = model.probability_above(0.5)
        assert p == pytest.approx(0.5, abs=0.01)

    def test_strong_success_high_threshold(self) -> None:
        """Strong success history gives high probability above moderate threshold."""
        model = ReputationModel()
        for _ in range(50):
            model = model.update(success=True)
        p = model.probability_above(0.8)
        assert p > 0.9

    def test_boundary_zero(self) -> None:
        """Probability above 0 should be ~1.0."""
        model = ReputationModel()
        assert model.probability_above(0.0) == pytest.approx(1.0)

    def test_boundary_one(self) -> None:
        """Probability above 1 should be ~0.0."""
        model = ReputationModel()
        assert model.probability_above(1.0) == pytest.approx(0.0)

    def test_invalid_threshold_negative(self) -> None:
        """Negative threshold raises ReputationError."""
        model = ReputationModel()
        with pytest.raises(ReputationError):
            model.probability_above(-0.1)

    def test_invalid_threshold_above_one(self) -> None:
        """Threshold > 1 raises ReputationError."""
        model = ReputationModel()
        with pytest.raises(ReputationError):
            model.probability_above(1.5)

    def test_more_successes_higher_probability(self) -> None:
        """More successes give higher probability above threshold."""
        model_low = ReputationModel()
        model_high = ReputationModel()
        for _ in range(5):
            model_low = model_low.update(success=True)
        for _ in range(50):
            model_high = model_high.update(success=True)
        assert model_high.probability_above(0.7) > model_low.probability_above(0.7)


# =============================================================================
# Witness Aggregation Tests
# =============================================================================


class TestWitnessAggregation:
    """Tests for TRAVOS witness aggregation."""

    def test_credible_witness_shifts_score(self) -> None:
        """A credible witness report shifts the aggregated score."""
        own = ReputationModel(prior_alpha=5.0, prior_beta=5.0)
        # Witness with similar mean (credible)
        report = WitnessReport(
            reporter_did="did:test:witness1",
            subject_did="did:test:subject",
            alpha=10.0,
            beta=10.0,
            sample_count=18,
            timestamp=datetime.now(UTC),
        )
        agg = aggregate_witness_reports([report], own, credibility_threshold=0.3)
        # Aggregated model should have more evidence
        assert agg.alpha >= own.alpha
        assert agg.beta >= own.beta

    def test_incredible_witness_filtered(self) -> None:
        """An incredible witness (very different mean) is filtered out."""
        own = ReputationModel(prior_alpha=5.0, prior_beta=5.0)
        # Witness with very high mean (not credible from our perspective)
        report = WitnessReport(
            reporter_did="did:test:liar",
            subject_did="did:test:subject",
            alpha=100.0,
            beta=1.0,
            sample_count=99,
            timestamp=datetime.now(UTC),
        )
        agg = aggregate_witness_reports(
            [report], own, credibility_threshold=0.8, epsilon=0.1
        )
        # Should not change since witness is not credible
        assert agg.alpha == pytest.approx(own.alpha)
        assert agg.beta == pytest.approx(own.beta)

    def test_empty_reports_returns_own(self) -> None:
        """Empty reports list returns own model unchanged."""
        own = ReputationModel(prior_alpha=3.0, prior_beta=2.0)
        agg = aggregate_witness_reports([], own)
        assert agg.alpha == pytest.approx(own.alpha)
        assert agg.beta == pytest.approx(own.beta)

    def test_multiple_credible_witnesses(self) -> None:
        """Multiple credible witnesses accumulate evidence."""
        own = ReputationModel(prior_alpha=5.0, prior_beta=5.0)
        reports = [
            WitnessReport(
                reporter_did=f"did:test:w{i}",
                subject_did="did:test:subject",
                alpha=6.0,
                beta=6.0,
                sample_count=10,
                timestamp=datetime.now(UTC),
            )
            for i in range(3)
        ]
        agg = aggregate_witness_reports(reports, own, credibility_threshold=0.3)
        single_agg = aggregate_witness_reports(reports[:1], own, credibility_threshold=0.3)
        assert agg.alpha >= single_agg.alpha
