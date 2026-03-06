"""Scenario 2: Delegation chain — token attenuation for sub-agents.

Demonstrates: creating a sub-agent, attenuating tokens with
reduced verbs and tighter constraints, verifying delegation
chains, and metered usage against attenuated limits.

Run standalone:
    python -m examples.scenario2_delegation_chain
"""

from __future__ import annotations

import logging
import os
import time
from datetime import UTC, datetime, timedelta

from examples.demo_common import (
    create_agent,
    log_receipt_summary,
    log_token_summary,
    setup_did_resolver,
)
from examples.scenario1_direct_resource import run_scenario1
from qasp.identity.binding import Permission, attenuate_binding
from qasp.protocol.capability import (
    Constraints,
    VerbSet,
    attenuate_token,
    verify_delegation_chain,
)
from qasp.protocol.metering import ResourceManager
from qasp.protocol.settlement import PaymentChannel
from qasp.transport.discover import verify_advertisement

logger = logging.getLogger("qasp.demo.scenario2")


def run_scenario2(scenario1_results: dict | None = None) -> dict:
    """Execute Scenario 2 (delegation chain).

    Args:
        scenario1_results: Optional pre-computed Scenario 1 results.
            If None, Scenario 1 is run first.

    Returns a dict of results for test assertions.
    """
    # ------------------------------------------------------------------
    # Step 1: Setup — reuse or run Scenario 1
    # ------------------------------------------------------------------
    logger.info("=== Step 1: Setup ===")

    if scenario1_results is None:
        scenario1_results = run_scenario1()

    s1 = scenario1_results
    alpha = s1["alpha"]
    beta = s1["beta"]
    t0 = s1["t0"]
    registry = s1["registry"]
    beta_ad = s1["advertisement"]

    results: dict = {"scenario1": s1}

    # ------------------------------------------------------------------
    # Step 2: Create Gamma (sub-agent)
    # ------------------------------------------------------------------
    logger.info("=== Step 2: Create Gamma (sub-agent) ===")

    gamma = create_agent("Gamma")
    registry.register(gamma.did_document)
    resolver = setup_did_resolver(registry)
    results["gamma"] = gamma
    results["resolver"] = resolver

    # Alpha creates attenuated owner binding for Gamma
    attenuated_binding = attenuate_binding(
        parent_binding=s1["owner_binding"],
        agent_secret_key=alpha.secret_key,
        new_agent_did=gamma.did,
        reduced_permissions={
            Permission.RESOURCE_REQUEST,
            Permission.COMM_INITIATE,
        },
        reduced_validity_seconds=1800,  # 30 minutes
    )
    results["attenuated_binding"] = attenuated_binding
    logger.info(
        "Attenuated binding for Gamma: permissions=%s depth=%d",
        sorted(attenuated_binding.permissions),
        attenuated_binding.max_delegation_depth,
    )

    # ------------------------------------------------------------------
    # Step 3: Attenuate Token
    # ------------------------------------------------------------------
    logger.info("=== Step 3: Attenuate Token ===")

    tightened = Constraints(
        quantity_limit=50,
        max_spend=500,
        spend_currency="credits",
        not_after=datetime.now(UTC) + timedelta(minutes=30),
    )
    t1 = attenuate_token(
        parent_token=t0,
        delegator_secret_key=alpha.secret_key,
        new_subject_did=gamma.did,
        reduced_verbs=VerbSet({"read"}),
        tightened_constraints=tightened,
    )
    results["t0"] = t0
    results["t1"] = t1
    log_token_summary("T0 (parent)", t0)
    log_token_summary("T1 (attenuated)", t1)

    # ------------------------------------------------------------------
    # Step 4: Verify Delegation Chain
    # ------------------------------------------------------------------
    logger.info("=== Step 4: Verify Delegation Chain ===")

    chain_valid = verify_delegation_chain(
        tokens=[t0, t1],
        root_issuer_public_key=beta.public_key,
        did_resolver=resolver,
        check_expiry=True,
    )
    results["delegation_chain_valid"] = chain_valid
    logger.info("Delegation chain [T0, T1] verified: %s", chain_valid)

    # ------------------------------------------------------------------
    # Step 5: Discovery — Gamma verifies Beta's advertisement
    # ------------------------------------------------------------------
    logger.info("=== Step 5: Discovery ===")

    verify_advertisement(beta_ad, beta.public_key)
    results["gamma_discovery_verified"] = True
    logger.info("Gamma verified Beta's advertisement")

    # ------------------------------------------------------------------
    # Step 6: Resource Grant (Gamma <-> Beta)
    # ------------------------------------------------------------------
    logger.info("=== Step 6: Resource Grant ===")

    meter_id = os.urandom(16)
    gamma_constraints = Constraints(
        quantity_limit=50,
        max_spend=500,
        spend_currency="credits",
    )

    gamma_rm = ResourceManager(gamma.secret_key, gamma.public_key, is_server=False)
    gamma_rm.set_peer_public_key(beta.public_key)

    beta_rm = ResourceManager(beta.secret_key, beta.public_key, is_server=True)
    beta_rm.set_peer_public_key(gamma.public_key)

    request, _ = gamma_rm.create_resource_request(
        resource_type="compute",
        resource_id=b"beta-compute",
        permissions=0x01,  # read only
        duration=1800,
    )

    grant, _ = beta_rm.process_resource_request(
        request=request,
        token=t1.token_id,
        granted_permissions=0x01,
        expiration=int(time.time()) + 1800,
        meter_id=meter_id,
        constraints=gamma_constraints,
        unit_price=10,
    )
    gamma_rm.process_resource_grant(grant, constraints=gamma_constraints, unit_price=10)

    results["gamma_meter_id"] = meter_id
    results["gamma_rm"] = gamma_rm
    results["beta_rm"] = beta_rm
    logger.info("Resource granted to Gamma: meter_id=%s", meter_id.hex()[:16])

    # ------------------------------------------------------------------
    # Step 7: Payment Channel Open (Gamma <-> Beta)
    # ------------------------------------------------------------------
    logger.info("=== Step 7: Payment Channel Open ===")

    gamma_channel = PaymentChannel(
        agent_did=str(gamma.did),
        server_did=str(beta.did),
        agent_public_key=gamma.public_key,
        server_public_key=beta.public_key,
    )
    beta_channel = PaymentChannel(
        agent_did=str(gamma.did),
        server_did=str(beta.did),
        agent_public_key=gamma.public_key,
        server_public_key=beta.public_key,
    )

    open_msg, _ = gamma_channel.create_channel_open(initial_balance=500)
    response_msg, _ = beta_channel.process_channel_open(open_msg, server_balance=0)
    gamma_channel.accept_channel(response_msg)

    results["gamma_channel"] = gamma_channel
    results["beta_channel"] = beta_channel
    logger.info(
        "Channel open: gamma=%d beta=%d",
        gamma_channel.agent_balance,
        gamma_channel.server_balance,
    )

    # ------------------------------------------------------------------
    # Step 8: Metered Usage (2 cycles)
    # ------------------------------------------------------------------
    logger.info("=== Step 8: Metered Usage ===")

    for cycle in range(1, 3):
        beta_rm.record_usage(meter_id, units=10)
        report, receipt, _ = beta_rm.generate_meter_report(meter_id)

        ack, _ = gamma_rm.process_meter_report(report)
        beta_rm.process_meter_ack(ack)

        update, _ = gamma_channel.create_state_update(
            cost=100,
            signing_key=gamma.secret_key,
            from_agent_to_server=True,
        )
        signed_update, _ = beta_channel.countersign_state_update(
            update, signing_key=beta.secret_key,
        )
        gamma_channel.apply_state_update(signed_update)

        logger.info(
            "  Cycle %d: units=%d cost=%d | balances: gamma=%d beta=%d",
            cycle,
            report.usage_count,
            report.cost,
            gamma_channel.agent_balance,
            gamma_channel.server_balance,
        )

    results["gamma_total_units"] = 20
    results["gamma_total_cost"] = 200

    # ------------------------------------------------------------------
    # Step 9: Resource Release
    # ------------------------------------------------------------------
    logger.info("=== Step 9: Resource Release ===")

    release, _ = gamma_rm.create_resource_release(meter_id)
    beta_rm.process_resource_release(release)
    results["gamma_resource_state"] = gamma_rm._resources[meter_id].state
    logger.info("Resource released: final_usage=%d", release.final_usage)

    # ------------------------------------------------------------------
    # Step 10: Channel Close & Verification
    # ------------------------------------------------------------------
    logger.info("=== Step 10: Channel Close & Verification ===")

    close_msg, _ = gamma_channel.create_channel_close(signing_key=gamma.secret_key)
    signed_close, _ = beta_channel.countersign_close(close_msg, signing_key=beta.secret_key)
    results["gamma_final_balance"] = signed_close.final_balance_a
    results["beta_final_balance"] = signed_close.final_balance_b
    logger.info(
        "Channel closed: gamma=%d beta=%d",
        signed_close.final_balance_a,
        signed_close.final_balance_b,
    )

    receipt_chain = beta_rm._receipt_chains[meter_id]
    chain_verified = receipt_chain.verify(beta.public_key)
    results["gamma_receipt_chain"] = receipt_chain
    results["gamma_receipt_chain_valid"] = chain_verified
    log_receipt_summary("Scenario2", len(receipt_chain), chain_verified)

    logger.info("=== Scenario 2 Complete ===")
    return results


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(name)s | %(message)s",
    )
    results = run_scenario2()
    print()
    print("--- Scenario 2 Summary ---")
    t0 = results["t0"]
    t1 = results["t1"]
    print(f"  T0 verbs         : {sorted(t0.verbs.verbs)}")
    print(f"  T1 verbs         : {sorted(t1.verbs.verbs)}")
    print(f"  T0 depth         : {t0.max_delegation_depth}")
    print(f"  T1 depth         : {t1.max_delegation_depth}")
    print(f"  T0 qty limit     : {t0.constraints.quantity_limit}")
    print(f"  T1 qty limit     : {t1.constraints.quantity_limit}")
    print(f"  T0 max_spend     : {t0.constraints.max_spend}")
    print(f"  T1 max_spend     : {t1.constraints.max_spend}")
    print(f"  Delegation chain : valid={results['delegation_chain_valid']}")
    print(f"  Gamma units      : {results['gamma_total_units']}")
    print(f"  Gamma cost       : {results['gamma_total_cost']}")
    print(f"  Gamma balance    : {results['gamma_final_balance']}")
    print(f"  Beta balance     : {results['beta_final_balance']}")
    print(f"  Receipt chain    : {len(results['gamma_receipt_chain'])} receipts, valid={results['gamma_receipt_chain_valid']}")
