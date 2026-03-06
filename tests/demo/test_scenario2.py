"""Tests for Scenario 2: Delegation chain."""

from __future__ import annotations

import pytest

from examples.scenario2_delegation_chain import run_scenario2
from qasp.protocol.metering import ResourceState


@pytest.mark.integration
class TestScenario2DelegationChain:
    """End-to-end assertions on Scenario 2 results."""

    @pytest.fixture(scope="class")
    def results(self) -> dict:
        return run_scenario2()

    def test_delegation_chain_valid(self, results: dict) -> None:
        assert results["delegation_chain_valid"] is True

    def test_attenuation_monotonic(self, results: dict) -> None:
        t0, t1 = results["t0"], results["t1"]
        assert t1.constraints.is_tighter_than(t0.constraints)

    def test_verb_reduction(self, results: dict) -> None:
        t0, t1 = results["t0"], results["t1"]
        assert "execute" in t0.verbs.verbs
        assert "execute" not in t1.verbs.verbs
        assert "read" in t1.verbs.verbs

    def test_constraint_tightening(self, results: dict) -> None:
        t1 = results["t1"]
        assert t1.constraints.quantity_limit == 50
        assert t1.constraints.max_spend == 500

    def test_metering_within_bounds(self, results: dict) -> None:
        assert results["gamma_total_units"] == 20
        assert results["gamma_total_cost"] == 200
        # Both within T1 limits: qty<=50, spend<=500
        t1 = results["t1"]
        assert results["gamma_total_units"] <= t1.constraints.quantity_limit
        assert results["gamma_total_cost"] <= t1.constraints.max_spend

    def test_gamma_payment_settled(self, results: dict) -> None:
        assert results["gamma_final_balance"] == 300
        assert results["beta_final_balance"] == 200

    def test_receipt_chain_valid(self, results: dict) -> None:
        assert results["gamma_receipt_chain_valid"] is True
        assert len(results["gamma_receipt_chain"]) == 2

    def test_issuer_chain_correct(self, results: dict) -> None:
        t0, t1 = results["t0"], results["t1"]
        # T1.issuer == T0.subject (Alpha delegated to Gamma)
        assert t1.issuer_did == t0.subject_did
