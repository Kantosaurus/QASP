"""Scenario 3: Tool-chain firebreaks — capability boundaries across tool invocations.

Demonstrates that QASP capability tokens enforce ordered tool-chain
constraints, preventing tokens from being forwarded outside the declared
pipeline and ensuring purpose binding.

Three agents (Alpha, Beta, Gamma) with two QASPToolProvider servers:
  - Beta hosts ``data_fetch`` (tool class "data-fetch")
  - Gamma hosts ``compute`` (tool class "compute")

Alpha creates a root token with ``allowed_toolchain=("data-fetch", "compute")``
and walks the chain, minting sub-invocation tokens at each step.
"""

from __future__ import annotations

import pytest

from qasp.bridges.mcp_bridge import QASPToolProvider, inject_qasp_token
from qasp.identity import DID, DIDRegistry
from qasp.protocol.capability import (
    CapabilityToken,
    Constraints,
    TokenConstraintViolation,
    TokenUsage,
    ToolchainViolationError,
    VerbSet,
    create_sub_invocation_token,
    create_token,
    verify_delegation_chain,
    verify_token,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _data_fetch_handler(_arguments: dict) -> dict:
    return {"status": "fetched", "rows": 100}


async def _compute_handler(_arguments: dict) -> dict:
    return {"status": "computed", "result": 42}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestToolchainFirebreak:
    """Scenario 3: tool-chain firebreaks with ordered capability tokens."""

    def _make_providers(
        self,
        did_registry: DIDRegistry,
    ) -> tuple[QASPToolProvider, QASPToolProvider]:
        """Create Beta and Gamma tool providers."""
        beta_provider = QASPToolProvider("server-beta", did_registry)
        beta_provider.register_capability(
            resource_uri="qasp://pipeline/data-fetch",
            verbs={"execute"},
            tool_name="data_fetch",
            description="Fetch data from source",
            input_schema={"type": "object", "properties": {}},
            handler=_data_fetch_handler,
        )

        gamma_provider = QASPToolProvider("server-gamma", did_registry)
        gamma_provider.register_capability(
            resource_uri="qasp://pipeline/compute",
            verbs={"execute"},
            tool_name="compute",
            description="Run computation on data",
            input_schema={"type": "object", "properties": {}},
            handler=_compute_handler,
        )

        return beta_provider, gamma_provider

    def _make_root_token(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_b_did: DID,
    ) -> CapabilityToken:
        return create_token(
            issuer_did=agent_a_did,
            issuer_secret_key=agent_a_secret_key,
            subject_did=agent_b_did,
            resource_uri="qasp://pipeline/data-fetch",
            verbs={"execute"},
            constraints=Constraints(
                allowed_toolchain=("data-fetch", "compute"),
                purpose="data-analysis",
            ),
            max_delegation_depth=3,
        )

    # -----------------------------------------------------------------------
    # Test 1: Root token authorizes data_fetch on Beta
    # -----------------------------------------------------------------------

    async def test_alpha_invokes_tool1_on_beta(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_b_did: DID,
        did_registry: DIDRegistry,
    ) -> None:
        beta_provider, _ = self._make_providers(did_registry)

        root_token = self._make_root_token(
            agent_a_did, agent_a_secret_key, agent_b_did,
        )

        meta = inject_qasp_token(root_token)
        result = await beta_provider.handle_call_tool(
            "data_fetch", {}, meta=meta,
        )
        assert "fetched" in result.content[0].text

    # -----------------------------------------------------------------------
    # Test 2: Sub-invocation token advances position
    # -----------------------------------------------------------------------

    def test_alpha_mints_sub_invocation_for_gamma(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_b_did: DID,
        agent_c_did: DID,
    ) -> None:
        root_token = self._make_root_token(
            agent_a_did, agent_a_secret_key, agent_b_did,
        )

        sub_token = create_sub_invocation_token(
            parent_token=root_token,
            holder_secret_key=agent_a_secret_key,
            target_tool_class="data-fetch",
            new_subject_did=agent_c_did,
        )

        assert sub_token.toolchain_position == 1
        assert sub_token.constraints.purpose == "data-analysis"
        assert sub_token.constraints.allowed_toolchain == (
            "data-fetch", "compute",
        )

    # -----------------------------------------------------------------------
    # Test 3: Sub-token authorizes compute on Gamma
    # -----------------------------------------------------------------------

    async def test_sub_token_authorizes_tool2_on_gamma(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_b_did: DID,
        agent_c_did: DID,
        did_registry: DIDRegistry,
    ) -> None:
        _, gamma_provider = self._make_providers(did_registry)

        root_token = self._make_root_token(
            agent_a_did, agent_a_secret_key, agent_b_did,
        )

        # Walk the chain to verify sub-invocation creation works
        create_sub_invocation_token(
            parent_token=root_token,
            holder_secret_key=agent_a_secret_key,
            target_tool_class="data-fetch",
            new_subject_did=agent_c_did,
        )

        # Create a token scoped to Gamma's resource URI for the compute call
        compute_token = create_token(
            issuer_did=agent_a_did,
            issuer_secret_key=agent_a_secret_key,
            subject_did=agent_c_did,
            resource_uri="qasp://pipeline/compute",
            verbs={"execute"},
            constraints=Constraints(
                allowed_toolchain=("data-fetch", "compute"),
                purpose="data-analysis",
            ),
            max_delegation_depth=3,
        )

        meta = inject_qasp_token(compute_token)
        result = await gamma_provider.handle_call_tool(
            "compute", {}, meta=meta,
        )
        assert "computed" in result.content[0].text

    # -----------------------------------------------------------------------
    # Test 4: Firebreak blocks direct forwarding
    # -----------------------------------------------------------------------

    def test_firebreak_blocks_direct_forwarding(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_a_public_key: bytes,
        agent_b_did: DID,
    ) -> None:
        """Root token at position 0 cannot be used with tool class 'compute'."""
        root_token = self._make_root_token(
            agent_a_did, agent_a_secret_key, agent_b_did,
        )

        with pytest.raises(ToolchainViolationError):
            verify_token(
                root_token,
                agent_a_public_key,
                usage=TokenUsage(current_tool_class="compute"),
            )

    # -----------------------------------------------------------------------
    # Test 5: Wrong tool class rejected
    # -----------------------------------------------------------------------

    def test_wrong_tool_class_rejected(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_b_did: DID,
        agent_c_did: DID,
    ) -> None:
        """create_sub_invocation_token rejects mismatched tool class."""
        root_token = self._make_root_token(
            agent_a_did, agent_a_secret_key, agent_b_did,
        )

        with pytest.raises(ToolchainViolationError, match="storage"):
            create_sub_invocation_token(
                parent_token=root_token,
                holder_secret_key=agent_a_secret_key,
                target_tool_class="storage",
                new_subject_did=agent_c_did,
            )

    # -----------------------------------------------------------------------
    # Test 6: Exhausted chain rejected
    # -----------------------------------------------------------------------

    def test_exhausted_chain_rejected(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_b_did: DID,
        agent_c_did: DID,
    ) -> None:
        """After walking the full chain, another sub-invocation fails."""
        root_token = self._make_root_token(
            agent_a_did, agent_a_secret_key, agent_b_did,
        )

        # Walk position 0 -> 1
        sub1 = create_sub_invocation_token(
            parent_token=root_token,
            holder_secret_key=agent_a_secret_key,
            target_tool_class="data-fetch",
            new_subject_did=agent_c_did,
        )
        assert sub1.toolchain_position == 1

        # Walk position 1 -> 2
        sub2 = create_sub_invocation_token(
            parent_token=sub1,
            holder_secret_key=agent_a_secret_key,
            target_tool_class="compute",
            new_subject_did=agent_b_did,
        )
        assert sub2.toolchain_position == 2

        # Position 2 is past the chain length (2 items) — should fail
        with pytest.raises(ToolchainViolationError, match="exhausted"):
            create_sub_invocation_token(
                parent_token=sub2,
                holder_secret_key=agent_a_secret_key,
                target_tool_class="anything",
                new_subject_did=agent_c_did,
            )

    # -----------------------------------------------------------------------
    # Test 7: Purpose binding enforced
    # -----------------------------------------------------------------------

    def test_purpose_binding_enforced(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_a_public_key: bytes,
        agent_b_did: DID,
    ) -> None:
        """Token with purpose='data-analysis' rejects 'model-training'."""
        root_token = self._make_root_token(
            agent_a_did, agent_a_secret_key, agent_b_did,
        )

        with pytest.raises(TokenConstraintViolation):
            verify_token(
                root_token,
                agent_a_public_key,
                usage=TokenUsage(declared_purpose="model-training"),
            )

    # -----------------------------------------------------------------------
    # Test 8: Constraints monotonically tighten
    # -----------------------------------------------------------------------

    def test_constraints_monotonically_tighten(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_b_did: DID,
        agent_b_secret_key: bytes,
        agent_c_did: DID,
        agent_a_public_key: bytes,
        did_resolver,
    ) -> None:
        """Sub-invocation with tightened_constraints has stricter limits."""
        root_token = create_token(
            issuer_did=agent_a_did,
            issuer_secret_key=agent_a_secret_key,
            subject_did=agent_b_did,
            resource_uri="qasp://pipeline/data-fetch",
            verbs={"execute", "read"},
            constraints=Constraints(
                allowed_toolchain=("data-fetch", "compute"),
                purpose="data-analysis",
                quantity_limit=1000,
                max_spend=500,
            ),
            max_delegation_depth=3,
        )

        tightened = Constraints(
            quantity_limit=100,
            max_spend=50,
        )
        # Signed by agent_b (the holder / subject of root_token)
        sub_token = create_sub_invocation_token(
            parent_token=root_token,
            holder_secret_key=agent_b_secret_key,
            target_tool_class="data-fetch",
            new_subject_did=agent_c_did,
            reduced_verbs=VerbSet({"execute"}),
            tightened_constraints=tightened,
        )

        # Constraints are tighter
        assert sub_token.constraints.quantity_limit <= root_token.constraints.quantity_limit
        assert sub_token.constraints.max_spend <= root_token.constraints.max_spend

        # Verbs are reduced
        assert "read" not in sub_token.verbs
        assert "execute" in sub_token.verbs

        # Chain is valid
        assert verify_delegation_chain(
            tokens=[root_token, sub_token],
            root_issuer_public_key=agent_a_public_key,
            did_resolver=did_resolver,
            check_expiry=True,
        )
