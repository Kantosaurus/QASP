"""Scenario 3: Tool-chain firebreaks — ordered capability boundaries.

Demonstrates how QASP capability tokens enforce tool-chain ordering,
preventing tokens from being reused outside the declared pipeline.

Three agents:
  - Alpha: orchestrator, creates root token
  - Beta: hosts ``data_fetch`` tool (tool class "data-fetch")
  - Gamma: hosts ``compute`` tool (tool class "compute")

Flow:
  1. Alpha creates root token with allowed_toolchain=("data-fetch", "compute")
  2. Alpha invokes data_fetch on Beta (position 0) — success
  3. Alpha mints sub-invocation token for Gamma — position advances to 1
  4. Alpha invokes compute on Gamma (position 1) — success
  5. Firebreak violation: root token used with wrong tool class — blocked
  6. Purpose binding violation: wrong declared purpose — blocked

Run standalone:
    python -m examples.scenario3_toolchain_firebreak
"""

from __future__ import annotations

import asyncio
import logging

from examples.demo_common import create_agent, setup_did_registry
from qasp.bridges.mcp_bridge import QASPToolProvider, inject_qasp_token
from qasp.protocol.capability import (
    Constraints,
    TokenConstraintViolation,
    TokenUsage,
    ToolchainViolationError,
    create_sub_invocation_token,
    create_token,
    verify_token,
)

logger = logging.getLogger("qasp.demo.scenario3")


async def _data_fetch_handler(_arguments: dict) -> dict:
    return {"status": "fetched", "rows": 100}


async def _compute_handler(_arguments: dict) -> dict:
    return {"status": "computed", "result": 42}


async def run_scenario3() -> dict:
    """Execute Scenario 3 (tool-chain firebreaks).

    Returns a dict of results for test assertions.
    """
    results: dict = {}

    # ------------------------------------------------------------------
    # Step 1: Identity Setup
    # ------------------------------------------------------------------
    logger.info("=== Step 1: Identity Setup ===")

    alpha = create_agent("Alpha")
    beta = create_agent("Beta")
    gamma = create_agent("Gamma")

    registry = setup_did_registry(alpha, beta, gamma)

    results["alpha"] = alpha
    results["beta"] = beta
    results["gamma"] = gamma
    logger.info(
        "Agents: Alpha=%s, Beta=%s, Gamma=%s",
        str(alpha.did)[:20], str(beta.did)[:20], str(gamma.did)[:20],
    )

    # ------------------------------------------------------------------
    # Step 2: Root Token with Tool-Chain Constraints
    # ------------------------------------------------------------------
    logger.info("=== Step 2: Root Token ===")

    root_token = create_token(
        issuer_did=alpha.did,
        issuer_secret_key=alpha.secret_key,
        subject_did=beta.did,
        resource_uri="qasp://pipeline/data-fetch",
        verbs={"execute"},
        constraints=Constraints(
            allowed_toolchain=("data-fetch", "compute"),
            purpose="data-analysis",
            quantity_limit=1000,
            max_spend=500,
        ),
        max_delegation_depth=3,
    )
    results["root_token"] = root_token
    logger.info(
        "Root token: toolchain=%s purpose=%s position=%d",
        root_token.constraints.allowed_toolchain,
        root_token.constraints.purpose,
        root_token.toolchain_position,
    )

    # ------------------------------------------------------------------
    # Step 3: Alpha Invokes Tool 1 on Beta (position 0)
    # ------------------------------------------------------------------
    logger.info("=== Step 3: Invoke data_fetch on Beta ===")

    beta_provider = QASPToolProvider("server-beta", registry)
    beta_provider.register_capability(
        resource_uri="qasp://pipeline/data-fetch",
        verbs={"execute"},
        tool_name="data_fetch",
        description="Fetch data from source",
        input_schema={"type": "object", "properties": {}},
        handler=_data_fetch_handler,
    )

    meta = inject_qasp_token(root_token)
    result = await beta_provider.handle_call_tool("data_fetch", {}, meta=meta)
    results["beta_result"] = result.content[0].text
    logger.info("Beta data_fetch result: %s", result.content[0].text)

    # ------------------------------------------------------------------
    # Step 4: Alpha Mints Sub-Invocation Token for Gamma
    # ------------------------------------------------------------------
    logger.info("=== Step 4: Sub-Invocation Token ===")

    sub_token = create_sub_invocation_token(
        parent_token=root_token,
        holder_secret_key=alpha.secret_key,
        target_tool_class="data-fetch",
        new_subject_did=gamma.did,
        tightened_constraints=Constraints(
            quantity_limit=100,
            max_spend=50,
        ),
    )
    results["sub_token"] = sub_token
    logger.info(
        "Sub-invocation token: position=%d qty_limit=%s max_spend=%s",
        sub_token.toolchain_position,
        sub_token.constraints.quantity_limit,
        sub_token.constraints.max_spend,
    )

    # ------------------------------------------------------------------
    # Step 5: Alpha Invokes Tool 2 on Gamma (position 1)
    # ------------------------------------------------------------------
    logger.info("=== Step 5: Invoke compute on Gamma ===")

    gamma_provider = QASPToolProvider("server-gamma", registry)
    gamma_provider.register_capability(
        resource_uri="qasp://pipeline/compute",
        verbs={"execute"},
        tool_name="compute",
        description="Run computation",
        input_schema={"type": "object", "properties": {}},
        handler=_compute_handler,
    )

    # Create a token scoped to Gamma's resource URI for the compute call
    compute_token = create_token(
        issuer_did=alpha.did,
        issuer_secret_key=alpha.secret_key,
        subject_did=gamma.did,
        resource_uri="qasp://pipeline/compute",
        verbs={"execute"},
        constraints=Constraints(
            allowed_toolchain=("data-fetch", "compute"),
            purpose="data-analysis",
        ),
        max_delegation_depth=3,
    )

    meta = inject_qasp_token(compute_token)
    result = await gamma_provider.handle_call_tool("compute", {}, meta=meta)
    results["gamma_result"] = result.content[0].text
    logger.info("Gamma compute result: %s", result.content[0].text)

    # ------------------------------------------------------------------
    # Step 6: Firebreak Violation (blocked)
    # ------------------------------------------------------------------
    logger.info("=== Step 6: Firebreak Violation ===")

    try:
        verify_token(
            root_token,
            alpha.public_key,
            usage=TokenUsage(current_tool_class="compute"),
        )
        results["firebreak_blocked"] = False
        logger.error("UNEXPECTED: Firebreak was NOT enforced!")
    except ToolchainViolationError as e:
        results["firebreak_blocked"] = True
        logger.info("Firebreak enforced: %s", e)

    # ------------------------------------------------------------------
    # Step 7: Purpose Binding Violation (blocked)
    # ------------------------------------------------------------------
    logger.info("=== Step 7: Purpose Binding Violation ===")

    try:
        verify_token(
            root_token,
            alpha.public_key,
            usage=TokenUsage(declared_purpose="model-training"),
        )
        results["purpose_blocked"] = False
        logger.error("UNEXPECTED: Purpose binding was NOT enforced!")
    except TokenConstraintViolation as e:
        results["purpose_blocked"] = True
        logger.info("Purpose binding enforced: %s", e)

    logger.info("=== Scenario 3 Complete ===")
    return results


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(name)s | %(message)s",
    )
    results = asyncio.run(run_scenario3())
    print()
    print("--- Scenario 3 Summary ---")
    print(f"  Root toolchain     : {results['root_token'].constraints.allowed_toolchain}")
    print(f"  Root purpose       : {results['root_token'].constraints.purpose}")
    print(f"  Root position      : {results['root_token'].toolchain_position}")
    print(f"  Sub-token position : {results['sub_token'].toolchain_position}")
    print(f"  Beta result        : {results['beta_result']}")
    print(f"  Gamma result       : {results['gamma_result']}")
    print(f"  Firebreak blocked  : {results['firebreak_blocked']}")
    print(f"  Purpose blocked    : {results['purpose_blocked']}")
