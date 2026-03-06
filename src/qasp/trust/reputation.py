"""Bayesian reputation scoring.

This module implements Bayesian reputation scoring for
agents based on interaction history, with time decay
and TRAVOS-style witness aggregation.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime

from qasp.trust.exceptions import ReputationError

__all__ = [
    "ReputationModel",
    "ReputationScore",
    "WitnessReport",
    "aggregate_witness_reports",
]


@dataclass
class ReputationScore:
    """A reputation score with uncertainty."""

    mean: float
    variance: float
    confidence: float
    sample_count: int

    @property
    def lower_bound(self) -> float:
        """Return the lower confidence bound."""
        bound = self.mean - 2 * (self.variance**0.5)
        return 0.0 if bound < 0.0 else bound

    @property
    def upper_bound(self) -> float:
        """Return the upper confidence bound."""
        bound = self.mean + 2 * (self.variance**0.5)
        return 1.0 if bound > 1.0 else bound


class ReputationModel:
    """Bayesian reputation model.

    Uses a Beta distribution to model agent reputation
    with proper uncertainty quantification and optional
    time-based evidence decay.
    """

    def __init__(
        self,
        prior_alpha: float = 1.0,
        prior_beta: float = 1.0,
        decay_rate: float = 0.0,
        last_update: datetime | None = None,
    ) -> None:
        """Initialize the reputation model.

        Args:
            prior_alpha: Alpha parameter (pseudo-successes).
            prior_beta: Beta parameter (pseudo-failures).
            decay_rate: Exponential decay rate per day. 0.0 = no decay.
            last_update: Timestamp of last observation.
        """
        self._alpha = prior_alpha
        self._beta = prior_beta
        self._decay_rate = decay_rate
        self._last_update = last_update

    @property
    def alpha(self) -> float:
        return self._alpha

    @property
    def beta(self) -> float:
        return self._beta

    def update(
        self,
        success: bool,
        timestamp: datetime | None = None,
    ) -> ReputationModel:
        """Update the model with a new observation.

        Args:
            success: Whether the interaction was successful.
            timestamp: When the observation occurred.

        Returns:
            A new ReputationModel with updated parameters.
        """
        alpha = self._alpha
        beta = self._beta

        if (
            timestamp is not None
            and self._last_update is not None
            and self._decay_rate > 0
        ):
            dt = (timestamp - self._last_update).total_seconds() / 86400.0
            decay = math.exp(-self._decay_rate * dt)
            alpha = 1.0 + (alpha - 1.0) * decay
            beta = 1.0 + (beta - 1.0) * decay

        if success:
            alpha += 1
        else:
            beta += 1

        return ReputationModel(
            prior_alpha=alpha,
            prior_beta=beta,
            decay_rate=self._decay_rate,
            last_update=timestamp if timestamp is not None else self._last_update,
        )

    def score(self) -> ReputationScore:
        """Calculate the current reputation score.

        Returns:
            The reputation score with uncertainty.
        """
        a, b = self._alpha, self._beta
        mean = a / (a + b)
        variance = (a * b) / ((a + b) ** 2 * (a + b + 1))
        confidence = 1.0 - 2.0 / (a + b)
        if confidence < 0.0:
            confidence = 0.0
        sample_count = max(0, int(a + b - 2))
        return ReputationScore(
            mean=mean,
            variance=variance,
            confidence=confidence,
            sample_count=sample_count,
        )

    def probability_above(self, threshold: float) -> float:
        """Calculate probability that true reputation exceeds threshold.

        Uses the regularized incomplete beta function via continued fraction
        (Lentz's algorithm).

        Args:
            threshold: The reputation threshold (must be in [0, 1]).

        Returns:
            Probability that true reputation is above threshold.

        Raises:
            ReputationError: If threshold is outside [0, 1].
        """
        if threshold < 0.0 or threshold > 1.0:
            msg = f"Threshold must be in [0, 1], got {threshold}"
            raise ReputationError(msg)
        return 1.0 - _regularized_beta(threshold, self._alpha, self._beta)


def _regularized_beta(x: float, a: float, b: float) -> float:
    """Compute the regularized incomplete beta function I_x(a, b)."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0

    # Use symmetry relation when x > (a+1)/(a+b+2) for better convergence
    if x > (a + 1.0) / (a + b + 2.0):
        return 1.0 - _regularized_beta(1.0 - x, b, a)

    # Log-beta function via log-gamma
    ln_beta = math.lgamma(a) + math.lgamma(b) - math.lgamma(a + b)
    front = math.exp(a * math.log(x) + b * math.log(1.0 - x) - ln_beta) / a

    # Continued fraction (modified Lentz's algorithm, Numerical Recipes)
    eps = 1e-30
    qab = a + b
    d = 1.0 - qab * x / (a + 1.0)
    if abs(d) < eps:
        d = eps
    d = 1.0 / d
    h = d
    c = 1.0

    for m in range(1, 201):
        m2 = 2 * m
        # Even step
        num = m * (b - m) * x / ((a + m2 - 1) * (a + m2))
        d = 1.0 + num * d
        if abs(d) < eps:
            d = eps
        d = 1.0 / d
        c = 1.0 + num / c
        if abs(c) < eps:
            c = eps
        h *= d * c

        # Odd step
        num = -(a + m) * (qab + m) * x / ((a + m2) * (a + m2 + 1))
        d = 1.0 + num * d
        if abs(d) < eps:
            d = eps
        d = 1.0 / d
        c = 1.0 + num / c
        if abs(c) < eps:
            c = eps
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-12:
            break

    return front * h


@dataclass(frozen=True)
class WitnessReport:
    """A witness reputation report from another agent."""

    reporter_did: str
    subject_did: str
    alpha: float
    beta: float
    sample_count: int
    timestamp: datetime


def aggregate_witness_reports(
    reports: list[WitnessReport],
    own_model: ReputationModel,
    credibility_threshold: float = 0.8,
    epsilon: float = 0.2,
) -> ReputationModel:
    """Aggregate witness reports using TRAVOS credibility filtering.

    For each witness report, compute the probability that the witness's
    mean lies within [own_mean - epsilon, own_mean + epsilon]. If this
    credibility exceeds the threshold, include the witness evidence
    weighted by credibility.

    Args:
        reports: Witness reports to aggregate.
        own_model: Our own reputation model for the subject.
        credibility_threshold: Minimum credibility to include a witness.
        epsilon: Tolerance window around own mean for credibility check.

    Returns:
        A new ReputationModel with aggregated alpha/beta.
    """
    if not reports:
        return ReputationModel(
            prior_alpha=own_model.alpha,
            prior_beta=own_model.beta,
            decay_rate=own_model._decay_rate,
            last_update=own_model._last_update,
        )

    own_mean = own_model.score().mean
    lo = max(0.0, own_mean - epsilon)
    hi = min(1.0, own_mean + epsilon)

    agg_alpha = own_model.alpha
    agg_beta = own_model.beta

    for report in reports:
        # Credibility = P(lo <= X <= hi) under the witness's Beta distribution
        cred = _regularized_beta(hi, report.alpha, report.beta) - _regularized_beta(
            lo, report.alpha, report.beta
        )
        if cred >= credibility_threshold:
            # Include witness evidence weighted by credibility
            witness_evidence_alpha = (report.alpha - 1.0) * cred
            witness_evidence_beta = (report.beta - 1.0) * cred
            agg_alpha += witness_evidence_alpha
            agg_beta += witness_evidence_beta

    return ReputationModel(
        prior_alpha=agg_alpha,
        prior_beta=agg_beta,
        decay_rate=own_model._decay_rate,
        last_update=own_model._last_update,
    )
