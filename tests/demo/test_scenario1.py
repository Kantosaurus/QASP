"""Tests for Scenario 1: Direct resource request."""

from __future__ import annotations

import pytest

from examples.scenario1_direct_resource import run_scenario1
from qasp.protocol.metering import ResourceState


@pytest.mark.integration
class TestScenario1DirectResource:
    """End-to-end assertions on Scenario 1 results."""

    @pytest.fixture(scope="class")
    def results(self) -> dict:
        return run_scenario1()

    def test_token_issued(self, results: dict) -> None:
        t0 = results["t0"]
        assert t0 is not None
        assert t0.resource_uri == "qasp://beta/compute"
        assert len(t0.token_id) == 32

    def test_metering_complete(self, results: dict) -> None:
        assert results["total_units"] == 30
        assert results["total_cost"] == 300

    def test_payment_settled(self, results: dict) -> None:
        assert results["final_agent_balance"] == 700
        assert results["final_server_balance"] == 300

    def test_receipt_chain_valid(self, results: dict) -> None:
        assert results["receipt_chain_valid"] is True
        assert len(results["receipt_chain"]) == 3

    def test_resource_released(self, results: dict) -> None:
        assert results["resource_state"] == ResourceState.RELEASED

    def test_owner_binding_valid(self, results: dict) -> None:
        binding = results["owner_binding"]
        assert binding is not None
        assert not binding.is_expired()
        assert binding.max_delegation_depth == 2

    def test_discovery_verified(self, results: dict) -> None:
        assert results["advertisement_verified"] is True
        ad = results["advertisement"]
        assert "compute" in ad.capabilities
        assert "storage" in ad.capabilities

    def test_price_negotiation(self, results: dict) -> None:
        schedule = results["price_schedule"]
        assert schedule.unit_price == 10
        assert schedule.currency == "credits"
        assert schedule.resource_type == "compute"
