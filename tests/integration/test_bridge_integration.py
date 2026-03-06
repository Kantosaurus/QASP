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
        from qasp.protocol.settlement import (
            CLOSE_REASON_COOPERATIVE,
            InsufficientBalanceError,
        )

        agent_ch = PaymentChannel(
            str(agent_a_did), str(agent_b_did),
            agent_a_public_key, agent_b_public_key,
        )
        server_ch = PaymentChannel(
            str(agent_a_did), str(agent_b_did),
            agent_a_public_key, agent_b_public_key,
        )

        assert agent_ch.state == ChannelState.OPENING

        open_msg, _ = agent_ch.create_channel_open(1000)
        response, _ = server_ch.process_channel_open(open_msg, 500)
        agent_ch.accept_channel(response)

        assert agent_ch.state == ChannelState.OPEN
        assert len(agent_ch.channel_id) == 32

        # Transfer 100 from agent to server
        update, _ = agent_ch.create_state_update(
            100, agent_a_secret_key,
        )
        signed, _ = server_ch.countersign_state_update(
            update, agent_b_secret_key,
        )
        agent_ch.apply_state_update(signed)
        assert agent_ch.agent_balance == 900
        assert agent_ch.server_balance == 600

        # Transfer 50 from server to agent
        update, _ = server_ch.create_state_update(
            50, agent_b_secret_key, from_agent_to_server=False,
        )
        signed, _ = agent_ch.countersign_state_update(
            update, agent_a_secret_key,
        )
        server_ch.apply_state_update(signed)
        assert agent_ch.agent_balance == 950
        assert agent_ch.server_balance == 550

        # Cooperative close
        close_msg, _ = agent_ch.create_channel_close(agent_a_secret_key)
        assert close_msg.close_reason == CLOSE_REASON_COOPERATIVE
        signed_close, _ = server_ch.countersign_close(
            close_msg, agent_b_secret_key,
        )
        assert server_ch.state == ChannelState.CLOSED
        assert signed_close.final_balance_a == 950
        assert signed_close.final_balance_b == 550

    def test_payment_channel_linked_to_receipt_chain(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_a_public_key: bytes,
        agent_b_did: DID,
        agent_b_secret_key: bytes,
        agent_b_public_key: bytes,
    ) -> None:
        meter = Meter(session_id=b"payment-session", issuer=str(agent_a_did))
        chain = ReceiptChain()

        agent_ch = PaymentChannel(
            str(agent_a_did), str(agent_b_did),
            agent_a_public_key, agent_b_public_key,
        )
        server_ch = PaymentChannel(
            str(agent_a_did), str(agent_b_did),
            agent_a_public_key, agent_b_public_key,
        )
        open_msg, _ = agent_ch.create_channel_open(1000)
        response, _ = server_ch.process_channel_open(open_msg, 0)
        agent_ch.accept_channel(response)

        prev_hash = b""
        for i in range(3):
            meter.record("compute", "inference", units=10)
            receipt = meter.generate_receipt(agent_a_secret_key, prev_hash)
            chain.append(receipt)
            prev_hash = receipt.compute_hash()

            update, _ = agent_ch.create_state_update(
                10, agent_a_secret_key,
            )
            signed, _ = server_ch.countersign_state_update(
                update, agent_b_secret_key,
            )
            agent_ch.apply_state_update(signed)

        assert chain.verify(agent_a_public_key)
        assert len(chain) == 3
        assert agent_ch.agent_balance == 970
        assert agent_ch.server_balance == 30

    def test_payment_channel_state_hash_chain(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_a_public_key: bytes,
        agent_b_did: DID,
        agent_b_secret_key: bytes,
        agent_b_public_key: bytes,
    ) -> None:
        from qasp.protocol.settlement import ChannelStateUpdate

        agent_ch = PaymentChannel(
            str(agent_a_did), str(agent_b_did),
            agent_a_public_key, agent_b_public_key,
        )
        server_ch = PaymentChannel(
            str(agent_a_did), str(agent_b_did),
            agent_a_public_key, agent_b_public_key,
        )
        open_msg, _ = agent_ch.create_channel_open(500)
        response, _ = server_ch.process_channel_open(open_msg, 500)
        agent_ch.accept_channel(response)

        updates: list[ChannelStateUpdate] = []
        for i in range(5):
            update, _ = agent_ch.create_state_update(
                10, agent_a_secret_key,
            )
            signed, _ = server_ch.countersign_state_update(
                update, agent_b_secret_key,
            )
            agent_ch.apply_state_update(signed)
            updates.append(signed)

        assert len(updates) == 5

        # Verify hash chain
        for i in range(1, len(updates)):
            expected_hash = updates[i - 1].compute_hash()
            assert updates[i].prev_hash == expected_hash, (
                f"State {i} prev_hash mismatch"
            )

    def test_payment_channel_insufficient_balance_rejected(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_a_public_key: bytes,
        agent_b_did: DID,
        agent_b_secret_key: bytes,
        agent_b_public_key: bytes,
    ) -> None:
        from qasp.protocol.settlement import InsufficientBalanceError

        agent_ch = PaymentChannel(
            str(agent_a_did), str(agent_b_did),
            agent_a_public_key, agent_b_public_key,
        )
        server_ch = PaymentChannel(
            str(agent_a_did), str(agent_b_did),
            agent_a_public_key, agent_b_public_key,
        )
        open_msg, _ = agent_ch.create_channel_open(100)
        response, _ = server_ch.process_channel_open(open_msg, 50)
        agent_ch.accept_channel(response)

        with pytest.raises(InsufficientBalanceError):
            agent_ch.create_state_update(
                200, agent_a_secret_key,
            )

        assert agent_ch.agent_balance == 100
        assert agent_ch.server_balance == 50

    def test_payment_channel_signatures_verifiable(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_a_public_key: bytes,
        agent_b_did: DID,
        agent_b_secret_key: bytes,
        agent_b_public_key: bytes,
    ) -> None:
        from qasp.crypto.signatures import verify

        agent_ch = PaymentChannel(
            str(agent_a_did), str(agent_b_did),
            agent_a_public_key, agent_b_public_key,
        )
        server_ch = PaymentChannel(
            str(agent_a_did), str(agent_b_did),
            agent_a_public_key, agent_b_public_key,
        )
        open_msg, _ = agent_ch.create_channel_open(1000)
        response, _ = server_ch.process_channel_open(open_msg, 0)
        agent_ch.accept_channel(response)

        update, _ = agent_ch.create_state_update(
            200, agent_a_secret_key,
        )
        signed, _ = server_ch.countersign_state_update(
            update, agent_b_secret_key,
        )
        agent_ch.apply_state_update(signed)

        # Both signatures should verify against signable bytes
        msg = signed.signable_bytes()
        assert verify(agent_a_public_key, msg, signed.agent_signature)
        assert verify(agent_b_public_key, msg, signed.server_signature)
