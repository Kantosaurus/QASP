"""Integration tests for protocol bridges (MCP, A2A) and payment channels."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from qasp.bridges.a2a_bridge import A2ABridge, A2ATaskState, QASPAgentCard
from qasp.bridges.mcp_bridge import MCPBridge, QASPToolProvider
from qasp.identity import DID, create_did
from qasp.protocol.accounting import Meter, ReceiptChain
from qasp.protocol.capability import (
    CapabilityError,
    CapabilityToken,
    Constraints,
    LocalDIDResolver,
    TokenExpiredError,
    TokenRevokedError,
    VerbSet,
    attenuate_token,
    create_token,
    verify_delegation_chain,
    verify_token,
)
from qasp.protocol.revocation import (
    CertificateRevocationList,
    RevocationReason,
    RevocationUrgency,
)
from qasp.protocol.settlement import ChannelState, PaymentChannel


# ============================================================================
# Test helpers
# ============================================================================


class FakeMCPBackend:
    """Fake MCP backend for testing."""

    def __init__(self) -> None:
        self._tools = [
            {"name": "calculator", "description": "A calculator tool"},
            {"name": "search", "description": "A search tool"},
        ]

    def list_tools(self) -> list[dict[str, Any]]:
        return list(self._tools)

    def execute_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        if name == "calculator":
            return {"result": arguments.get("a", 0) + arguments.get("b", 0)}
        return {"result": f"executed {name}"}

    def list_resources(self) -> list[dict[str, Any]]:
        return []

    def read_resource(self, uri: str) -> Any:
        return b""


class FakeA2ABackend:
    """Fake A2A task backend for testing."""

    def execute_task(self, task: dict[str, Any]) -> dict[str, Any]:
        return {"status": "completed", "output": "task done"}


def _make_token_meta(token: CapabilityToken) -> dict[str, Any]:
    """Create meta dict from a token for MCP bridge calls."""
    return QASPToolProvider.inject_token_meta(token)


# ============================================================================
# Class 1: TestMCPBridgeIntegration
# ============================================================================


@pytest.mark.integration
class TestMCPBridgeIntegration:
    def test_tool_call_with_valid_token(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_a_public_key: bytes,
        agent_b_did: DID,
    ) -> None:
        token = create_token(
            issuer_did=agent_a_did,
            issuer_secret_key=agent_a_secret_key,
            subject_did=agent_b_did,
            resource_uri="qasp://mcp/tools/calculator",
            verbs={"execute"},
        )
        backend = FakeMCPBackend()
        bridge = MCPBridge(
            backend=backend,
            issuer_public_key=agent_a_public_key,
        )
        meta = _make_token_meta(token)
        result = bridge.call_tool("calculator", {"a": 2, "b": 3}, meta=meta)
        assert result == {"result": 5}

    def test_tool_call_with_wrong_verb_rejected(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_a_public_key: bytes,
        agent_b_did: DID,
    ) -> None:
        token = create_token(
            issuer_did=agent_a_did,
            issuer_secret_key=agent_a_secret_key,
            subject_did=agent_b_did,
            resource_uri="qasp://mcp/tools/calculator",
            verbs={"read"},
        )
        backend = FakeMCPBackend()
        bridge = MCPBridge(
            backend=backend,
            issuer_public_key=agent_a_public_key,
        )
        meta = _make_token_meta(token)
        with pytest.raises(CapabilityError, match="execute"):
            bridge.call_tool("calculator", {"a": 1, "b": 2}, meta=meta)

    def test_tool_call_with_expired_token_rejected(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_a_public_key: bytes,
        agent_b_did: DID,
    ) -> None:
        expired = Constraints(
            not_after=datetime.now(UTC) - timedelta(seconds=10),
        )
        token = create_token(
            issuer_did=agent_a_did,
            issuer_secret_key=agent_a_secret_key,
            subject_did=agent_b_did,
            resource_uri="qasp://mcp/tools/calculator",
            verbs={"execute"},
            constraints=expired,
        )
        backend = FakeMCPBackend()
        bridge = MCPBridge(
            backend=backend,
            issuer_public_key=agent_a_public_key,
        )
        meta = _make_token_meta(token)
        with pytest.raises(TokenExpiredError):
            bridge.call_tool("calculator", {}, meta=meta)

    def test_tool_call_without_token_rejected(
        self,
        agent_a_public_key: bytes,
    ) -> None:
        backend = FakeMCPBackend()
        bridge = MCPBridge(
            backend=backend,
            issuer_public_key=agent_a_public_key,
        )
        with pytest.raises(CapabilityError, match="token required"):
            bridge.call_tool("calculator", {})

    def test_tool_call_with_wrong_resource_uri_rejected(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_a_public_key: bytes,
        agent_b_did: DID,
    ) -> None:
        token = create_token(
            issuer_did=agent_a_did,
            issuer_secret_key=agent_a_secret_key,
            subject_did=agent_b_did,
            resource_uri="qasp://mcp/tools/search",
            verbs={"execute"},
        )
        backend = FakeMCPBackend()
        bridge = MCPBridge(
            backend=backend,
            issuer_public_key=agent_a_public_key,
        )
        meta = _make_token_meta(token)
        with pytest.raises(CapabilityError, match="URI mismatch"):
            bridge.call_tool("calculator", {}, meta=meta)


# ============================================================================
# Class 2: TestA2ABridgeIntegration
# ============================================================================


@pytest.mark.integration
class TestA2ABridgeIntegration:
    def test_agent_card_contains_qasp_extension(
        self,
        agent_a_did: DID,
        agent_a_public_key: bytes,
    ) -> None:
        card = QASPAgentCard(
            name="agent-alpha",
            description="Test agent",
            did=agent_a_did,
            public_key=agent_a_public_key,
            capabilities=["compute"],
            skills=["math"],
        )
        card_dict = card.to_dict()
        assert "qasp" in card_dict
        qasp_ext = card_dict["qasp"]
        assert qasp_ext["did"] == str(agent_a_did)
        assert qasp_ext["sig_public_key"] == base64.b64encode(agent_a_public_key).decode()
        assert qasp_ext["qasp_version"] == "1.0"
        assert "compute" in qasp_ext["capabilities"]

    def test_agent_card_did_matches_keypair(
        self,
        agent_a_did: DID,
        agent_a_public_key: bytes,
    ) -> None:
        card = QASPAgentCard(
            name="agent-alpha",
            description="Test agent",
            did=agent_a_did,
            public_key=agent_a_public_key,
        )
        card_dict = card.to_dict()
        # Verify the DID matches the public key
        assert agent_a_did.verify_key(agent_a_public_key)
        assert card_dict["qasp"]["did"] == str(agent_a_did)

    def test_task_execution_lifecycle(self) -> None:
        backend = FakeA2ABackend()
        bridge = A2ABridge(backend=backend)

        card = {"name": "worker", "skills": ["compute"]}
        bridge.register_agent_card("http://agent.local", card)

        discovered = bridge.get_agent_card("http://agent.local")
        assert discovered["name"] == "worker"

        task_id = bridge.send_task("http://agent.local", {"action": "compute"})
        status = bridge.get_task_status("http://agent.local", task_id)

        assert status["state"] == A2ATaskState.COMPLETED
        assert status["result"]["output"] == "task done"

    def test_task_with_qasp_token_verification(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_a_public_key: bytes,
        agent_b_did: DID,
    ) -> None:
        token = create_token(
            issuer_did=agent_a_did,
            issuer_secret_key=agent_a_secret_key,
            subject_did=agent_b_did,
            resource_uri="qasp://a2a/tasks/compute",
            verbs={"execute"},
        )

        results = []

        def handler(task: dict[str, Any]) -> dict[str, Any]:
            results.append(task)
            return {"status": "completed"}

        card = QASPAgentCard(
            name="worker",
            description="Worker agent",
            did=agent_b_did,
            public_key=agent_a_public_key,
            handler=handler,
        )

        meta = QASPToolProvider.inject_token_meta(token)
        task = {"action": "compute", "metadata": meta}
        result = card.handle_task(task, issuer_public_key=agent_a_public_key)

        assert result["status"] == "completed"
        assert len(results) == 1


# ============================================================================
# Class 3: TestCrossProtocolDelegation
# ============================================================================


@pytest.mark.integration
class TestCrossProtocolDelegation:
    def test_a2a_delegates_to_mcp_tool_via_qasp(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_a_public_key: bytes,
        agent_b_did: DID,
        agent_b_secret_key: bytes,
        agent_b_public_key: bytes,
        agent_c_did: DID,
        did_resolver: LocalDIDResolver,
    ) -> None:
        # Agent A creates root token for agent B (A2A agent)
        root = create_token(
            issuer_did=agent_a_did,
            issuer_secret_key=agent_a_secret_key,
            subject_did=agent_b_did,
            resource_uri="qasp://mcp/tools/calculator",
            verbs={"execute", "read"},
            max_delegation_depth=2,
        )

        # Agent B delegates to agent C (MCP tool provider)
        delegated = attenuate_token(
            parent_token=root,
            delegator_secret_key=agent_b_secret_key,
            new_subject_did=agent_c_did,
            reduced_verbs=VerbSet({"execute"}),
        )

        # Agent C uses the delegated token to call MCP tool
        backend = FakeMCPBackend()
        bridge = MCPBridge(
            backend=backend,
            issuer_public_key=agent_b_public_key,
        )
        meta = _make_token_meta(delegated)
        result = bridge.call_tool("calculator", {"a": 10, "b": 20}, meta=meta)
        assert result == {"result": 30}

    def test_cross_protocol_delegation_chain_verified(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_a_public_key: bytes,
        agent_b_did: DID,
        agent_b_secret_key: bytes,
        agent_c_did: DID,
        did_resolver: LocalDIDResolver,
    ) -> None:
        root = create_token(
            issuer_did=agent_a_did,
            issuer_secret_key=agent_a_secret_key,
            subject_did=agent_b_did,
            resource_uri="qasp://mcp/tools/calculator",
            verbs={"execute", "read"},
            max_delegation_depth=2,
        )

        child = attenuate_token(
            parent_token=root,
            delegator_secret_key=agent_b_secret_key,
            new_subject_did=agent_c_did,
            reduced_verbs=VerbSet({"execute"}),
        )

        assert verify_delegation_chain(
            tokens=[root, child],
            root_issuer_public_key=agent_a_public_key,
            did_resolver=did_resolver,
            check_expiry=True,
        )

    def test_cross_protocol_revocation_blocks_delegated_call(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_a_public_key: bytes,
        agent_b_did: DID,
        agent_b_secret_key: bytes,
        agent_b_public_key: bytes,
        agent_c_did: DID,
    ) -> None:
        root = create_token(
            issuer_did=agent_a_did,
            issuer_secret_key=agent_a_secret_key,
            subject_did=agent_b_did,
            resource_uri="qasp://mcp/tools/calculator",
            verbs={"execute"},
            max_delegation_depth=2,
        )

        child = attenuate_token(
            parent_token=root,
            delegator_secret_key=agent_b_secret_key,
            new_subject_did=agent_c_did,
        )

        crl = CertificateRevocationList()
        crl.register_token(root)
        crl.register_token(child)

        # Revoke root -> cascades to child
        crl.revoke(
            token_id=root.token_id,
            reason=RevocationReason.KEY_COMPROMISE,
            urgency=RevocationUrgency.CRITICAL,
            revoker_did=str(agent_a_did),
            revoker_secret_key=agent_a_secret_key,
        )

        with pytest.raises(TokenRevokedError):
            verify_token(
                child,
                agent_b_public_key,
                check_expiry=False,
                crl=crl,
            )

    def test_attenuation_reduces_verbs_across_protocols(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_a_public_key: bytes,
        agent_b_did: DID,
        agent_b_secret_key: bytes,
        agent_b_public_key: bytes,
        agent_c_did: DID,
    ) -> None:
        root = create_token(
            issuer_did=agent_a_did,
            issuer_secret_key=agent_a_secret_key,
            subject_did=agent_b_did,
            resource_uri="qasp://mcp/tools/calculator",
            verbs={"execute", "read", "write"},
            max_delegation_depth=2,
        )

        # Agent B delegates to C with reduced verbs (read only)
        child = attenuate_token(
            parent_token=root,
            delegator_secret_key=agent_b_secret_key,
            new_subject_did=agent_c_did,
            reduced_verbs=VerbSet({"read"}),
        )

        assert "read" in child.verbs
        assert "execute" not in child.verbs
        assert "write" not in child.verbs

        # Verify token is valid but lacks execute verb
        verify_token(child, agent_b_public_key, check_expiry=True)

        # MCP bridge should reject because no "execute" verb
        backend = FakeMCPBackend()
        bridge = MCPBridge(
            backend=backend,
            issuer_public_key=agent_b_public_key,
        )
        meta = _make_token_meta(child)
        with pytest.raises(CapabilityError, match="execute"):
            bridge.call_tool("calculator", {}, meta=meta)


# ============================================================================
# Class 4: TestPaymentChannelIntegration
# ============================================================================


@pytest.mark.integration
class TestPaymentChannelIntegration:
    def test_payment_channel_open_transfer_close(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_a_public_key: bytes,
        agent_b_did: DID,
        agent_b_secret_key: bytes,
        agent_b_public_key: bytes,
    ) -> None:
        channel = PaymentChannel(
            party_a=str(agent_a_did),
            party_b=str(agent_b_did),
            initial_balance_a=1000,
            initial_balance_b=500,
        )

        assert channel.state == ChannelState.OPENING

        channel_id = channel.open(agent_a_secret_key, agent_b_secret_key)
        assert channel.state == ChannelState.OPEN
        assert len(channel_id) == 32

        channel.transfer(100, from_a_to_b=True, signing_key=agent_a_secret_key)
        assert channel.balance_a == 900
        assert channel.balance_b == 600

        channel.transfer(50, from_a_to_b=False, signing_key=agent_b_secret_key)
        assert channel.balance_a == 950
        assert channel.balance_b == 550

        settlement = channel.close(agent_a_secret_key, agent_b_secret_key)
        assert channel.state == ChannelState.CLOSED
        assert settlement.channel_id == channel_id
        assert settlement.amount == 50  # net: A lost 50
        assert settlement.payer == str(agent_a_did)
        assert settlement.payee == str(agent_b_did)

    def test_payment_channel_linked_to_receipt_chain(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_a_public_key: bytes,
        agent_b_did: DID,
        agent_b_secret_key: bytes,
    ) -> None:
        # Set up metering alongside payment channel
        meter = Meter(session_id=b"payment-session", issuer=str(agent_a_did))
        chain = ReceiptChain()

        channel = PaymentChannel(
            party_a=str(agent_a_did),
            party_b=str(agent_b_did),
            initial_balance_a=1000,
            initial_balance_b=0,
        )
        channel.open(agent_a_secret_key, agent_b_secret_key)

        # Record usage and transfer payment
        prev_hash = b""
        for i in range(3):
            meter.record("compute", "inference", units=10)
            receipt = meter.generate_receipt(agent_a_secret_key, prev_hash)
            chain.append(receipt)
            prev_hash = receipt.compute_hash()

            channel.transfer(10, from_a_to_b=True, signing_key=agent_a_secret_key)

        # Verify receipt chain matches payment transfers
        assert chain.verify(agent_a_public_key)
        assert len(chain) == 3
        assert channel.balance_a == 970
        assert channel.balance_b == 30

    def test_payment_channel_state_hash_chain(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_b_did: DID,
        agent_b_secret_key: bytes,
    ) -> None:
        channel = PaymentChannel(
            party_a=str(agent_a_did),
            party_b=str(agent_b_did),
            initial_balance_a=500,
            initial_balance_b=500,
        )
        channel.open(agent_a_secret_key, agent_b_secret_key)

        for i in range(5):
            channel.transfer(10, from_a_to_b=True, signing_key=agent_a_secret_key)

        states = channel.states
        assert len(states) == 6  # 1 open + 5 transfers

        # Verify hash chain: each state's prev_state_hash matches previous state's hash
        for i in range(1, len(states)):
            expected_hash = states[i - 1].compute_hash()
            assert states[i].prev_state_hash == expected_hash, (
                f"State {i} prev_state_hash mismatch"
            )

    def test_payment_channel_insufficient_balance_rejected(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_b_did: DID,
        agent_b_secret_key: bytes,
    ) -> None:
        channel = PaymentChannel(
            party_a=str(agent_a_did),
            party_b=str(agent_b_did),
            initial_balance_a=100,
            initial_balance_b=50,
        )
        channel.open(agent_a_secret_key, agent_b_secret_key)

        with pytest.raises(ValueError, match="Insufficient balance"):
            channel.transfer(200, from_a_to_b=True, signing_key=agent_a_secret_key)

        # Balance should be unchanged after failed transfer
        assert channel.balance_a == 100
        assert channel.balance_b == 50

    def test_payment_settlement_signatures_verifiable(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_a_public_key: bytes,
        agent_b_did: DID,
        agent_b_secret_key: bytes,
        agent_b_public_key: bytes,
    ) -> None:
        from qasp.crypto.signatures import verify

        channel = PaymentChannel(
            party_a=str(agent_a_did),
            party_b=str(agent_b_did),
            initial_balance_a=1000,
            initial_balance_b=0,
        )
        channel.open(agent_a_secret_key, agent_b_secret_key)
        channel.transfer(200, from_a_to_b=True, signing_key=agent_a_secret_key)

        settlement = channel.close(agent_a_secret_key, agent_b_secret_key)
        sig_a, sig_b = settlement.signatures

        # Both signatures should verify against the final state's signable bytes
        final_state = channel.states[-1]
        msg = final_state.signable_bytes()

        assert verify(agent_a_public_key, msg, sig_a)
        assert verify(agent_b_public_key, msg, sig_b)
