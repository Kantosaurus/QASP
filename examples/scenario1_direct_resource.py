"""Scenario 1: Direct resource request — full lifecycle.

Demonstrates: identity setup, discovery, price negotiation,
token issuance, metered resource usage with micropayments,
resource release, and channel close.

Run standalone:
    python -m examples.scenario1_direct_resource
"""

from __future__ import annotations

import logging
import os
import time

from examples.demo_common import (
    AgentIdentity,
    create_agent,
    log_receipt_summary,
    log_token_summary,
    setup_did_registry,
    setup_did_resolver,
)
from qasp.identity.binding import (
    Permission,
    create_owner_binding,
    verify_owner_binding,
)
from qasp.protocol.capability import (
    Constraints,
    VerbSet,
    create_token,
    verify_token,
)
from qasp.protocol.metering import ResourceManager, ResourceState
from qasp.protocol.settlement import PaymentChannel, PriceNegotiator
from qasp.transport.discover import create_advertisement, verify_advertisement

logger = logging.getLogger("qasp.demo.scenario1")


def run_scenario1() -> dict:
    """Execute the full Scenario 1 lifecycle.

    Returns a dict of results for test assertions and Scenario 2 reuse.
    """
    results: dict = {}

    # ------------------------------------------------------------------
    # Step 1: Identity Setup
    # ------------------------------------------------------------------
    logger.info("=== Step 1: Identity Setup ===")

    alice = create_agent("Alice")  # owner
    alpha = create_agent("Alpha")  # agent
    beta = create_agent("Beta")  # server

    results["alice"] = alice
    results["alpha"] = alpha
    results["beta"] = beta

    registry = setup_did_registry(alice, alpha, beta)
    resolver = setup_did_resolver(registry)
    results["registry"] = registry
    results["resolver"] = resolver

    # Alice signs owner-binding for Alpha
    owner_binding = create_owner_binding(
        agent_did=alpha.did,
        owner_did=alice.did,
        owner_secret_key=alice.secret_key,
        permissions={
            Permission.RESOURCE_REQUEST,
            Permission.COMM_INITIATE,
            Permission.TOKEN_ISSUE,
            Permission.TOKEN_ATTENUATE,
            Permission.IDENTITY_CREATE_SUB_AGENT,
        },
        max_delegation_depth=2,
    )
    verify_owner_binding(owner_binding, alice.public_key)
    results["owner_binding"] = owner_binding
    logger.info("Owner binding created and verified for Alpha")

    # ------------------------------------------------------------------
    # Step 2: Discovery
    # ------------------------------------------------------------------
    logger.info("=== Step 2: Discovery ===")

    beta_ad = create_advertisement(
        did=str(beta.did),
        secret_key=beta.secret_key,
        endpoints=[("127.0.0.1", 9090)],
        capabilities={"compute", "storage"},
    )
    verify_advertisement(beta_ad, beta.public_key)
    results["advertisement"] = beta_ad
    results["advertisement_verified"] = True
    logger.info("Beta advertisement created and verified: %s", sorted(beta_ad.capabilities))

    # ------------------------------------------------------------------
    # Step 3: Price Negotiation
    # ------------------------------------------------------------------
    logger.info("=== Step 3: Price Negotiation ===")

    alpha_negotiator = PriceNegotiator()
    beta_negotiator = PriceNegotiator()

    # Alpha requests pricing for compute
    price_request, _ = alpha_negotiator.create_price_request(
        resource_type="compute",
        resource_id=b"beta-compute",
        quantity=100,
        duration=3600,
    )

    # Beta offers unit_price=10, currency=credits
    price_offer, _ = beta_negotiator.create_price_offer(
        request=price_request,
        unit_price=10,
        currency="credits",
        signing_key=beta.secret_key,
    )

    # Alpha verifies and accepts
    alpha_negotiator.process_price_offer(price_offer, beta.public_key)
    price_accept, _ = alpha_negotiator.create_price_accept(
        offer=price_offer,
        signing_key=alpha.secret_key,
    )

    # Beta processes acceptance -> PriceSchedule
    schedule, _ = beta_negotiator.process_price_accept(price_accept, alpha.public_key)
    results["price_schedule"] = schedule
    logger.info(
        "Price negotiated: %s @ %d %s/unit",
        schedule.resource_type,
        schedule.unit_price,
        schedule.currency,
    )

    # ------------------------------------------------------------------
    # Step 4: Token Issuance
    # ------------------------------------------------------------------
    logger.info("=== Step 4: Token Issuance ===")

    token_constraints = Constraints(
        quantity_limit=100,
        max_spend=1000,
        spend_currency="credits",
    )
    t0 = create_token(
        issuer_did=beta.did,
        issuer_secret_key=beta.secret_key,
        subject_did=alpha.did,
        resource_uri="qasp://beta/compute",
        verbs={"read", "execute"},
        constraints=token_constraints,
        max_delegation_depth=2,
        validity_seconds=3600,
    )
    verify_token(t0, beta.public_key)
    results["t0"] = t0
    log_token_summary("T0", t0)

    # ------------------------------------------------------------------
    # Step 5: Resource Request / Grant
    # ------------------------------------------------------------------
    logger.info("=== Step 5: Resource Request / Grant ===")

    meter_id = os.urandom(16)
    agent_rm = ResourceManager(alpha.secret_key, alpha.public_key, is_server=False)
    agent_rm.set_peer_public_key(beta.public_key)

    server_rm = ResourceManager(beta.secret_key, beta.public_key, is_server=True)
    server_rm.set_peer_public_key(alpha.public_key)

    request, _ = agent_rm.create_resource_request(
        resource_type="compute",
        resource_id=b"beta-compute",
        permissions=0x03,
        duration=3600,
    )

    grant, _ = server_rm.process_resource_request(
        request=request,
        token=t0.token_id,
        granted_permissions=0x03,
        expiration=int(time.time()) + 3600,
        meter_id=meter_id,
        constraints=token_constraints,
        unit_price=10,
    )
    agent_rm.process_resource_grant(grant, constraints=token_constraints, unit_price=10)
    results["meter_id"] = meter_id
    results["agent_rm"] = agent_rm
    results["server_rm"] = server_rm
    logger.info("Resource granted: meter_id=%s", meter_id.hex()[:16])

    # ------------------------------------------------------------------
    # Step 6: Payment Channel Open
    # ------------------------------------------------------------------
    logger.info("=== Step 6: Payment Channel Open ===")

    alpha_channel = PaymentChannel(
        agent_did=str(alpha.did),
        server_did=str(beta.did),
        agent_public_key=alpha.public_key,
        server_public_key=beta.public_key,
    )
    beta_channel = PaymentChannel(
        agent_did=str(alpha.did),
        server_did=str(beta.did),
        agent_public_key=alpha.public_key,
        server_public_key=beta.public_key,
    )

    open_msg, _ = alpha_channel.create_channel_open(initial_balance=1000)
    response_msg, _ = beta_channel.process_channel_open(open_msg, server_balance=0)
    alpha_channel.accept_channel(response_msg)

    results["alpha_channel"] = alpha_channel
    results["beta_channel"] = beta_channel
    logger.info(
        "Channel open: agent=%d server=%d",
        alpha_channel.agent_balance,
        alpha_channel.server_balance,
    )

    # ------------------------------------------------------------------
    # Step 7: Metered Usage (3 cycles)
    # ------------------------------------------------------------------
    logger.info("=== Step 7: Metered Usage ===")

    for cycle in range(1, 4):
        # Server records 10 units
        server_rm.record_usage(meter_id, units=10)

        # Server generates meter report + receipt
        report, receipt, _ = server_rm.generate_meter_report(meter_id)

        # Agent processes report -> ack
        ack, _ = agent_rm.process_meter_report(report)

        # Server processes ack
        server_rm.process_meter_ack(ack)

        # Agent creates payment state update (cost = 10 units * 10 price = 100)
        update, _ = alpha_channel.create_state_update(
            cost=100,
            signing_key=alpha.secret_key,
            from_agent_to_server=True,
        )

        # Server countersigns
        signed_update, _ = beta_channel.countersign_state_update(
            update, signing_key=beta.secret_key,
        )

        # Agent applies the countersigned update
        alpha_channel.apply_state_update(signed_update)

        logger.info(
            "  Cycle %d: units=%d cost=%d | balances: agent=%d server=%d",
            cycle,
            report.usage_count,
            report.cost,
            alpha_channel.agent_balance,
            alpha_channel.server_balance,
        )

    results["total_units"] = 30
    results["total_cost"] = 300

    # ------------------------------------------------------------------
    # Step 8: Resource Release
    # ------------------------------------------------------------------
    logger.info("=== Step 8: Resource Release ===")

    release, _ = agent_rm.create_resource_release(meter_id)
    server_rm.process_resource_release(release)
    results["resource_state"] = agent_rm._resources[meter_id].state
    logger.info("Resource released: final_usage=%d", release.final_usage)

    # ------------------------------------------------------------------
    # Step 9: Channel Close
    # ------------------------------------------------------------------
    logger.info("=== Step 9: Channel Close ===")

    close_msg, _ = alpha_channel.create_channel_close(signing_key=alpha.secret_key)
    signed_close, _ = beta_channel.countersign_close(close_msg, signing_key=beta.secret_key)
    results["final_agent_balance"] = signed_close.final_balance_a
    results["final_server_balance"] = signed_close.final_balance_b
    logger.info(
        "Channel closed: agent=%d server=%d",
        signed_close.final_balance_a,
        signed_close.final_balance_b,
    )

    # ------------------------------------------------------------------
    # Step 10: Verification
    # ------------------------------------------------------------------
    logger.info("=== Step 10: Verification ===")

    receipt_chain = server_rm._receipt_chains[meter_id]
    chain_valid = receipt_chain.verify(beta.public_key)
    results["receipt_chain"] = receipt_chain
    results["receipt_chain_valid"] = chain_valid
    log_receipt_summary("Scenario1", len(receipt_chain), chain_valid)

    logger.info("=== Scenario 1 Complete ===")
    return results


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(name)s | %(message)s",
    )
    results = run_scenario1()
    print()
    print("--- Summary ---")
    print(f"  Token resource : {results['t0'].resource_uri}")
    print(f"  Total units    : {results['total_units']}")
    print(f"  Total cost     : {results['total_cost']}")
    print(f"  Agent balance  : {results['final_agent_balance']}")
    print(f"  Server balance : {results['final_server_balance']}")
    print(f"  Receipt chain  : {len(results['receipt_chain'])} receipts, valid={results['receipt_chain_valid']}")
    print(f"  Resource state : {results['resource_state'].value}")
