"""Scenario 4: MCP-over-QASP — full session with handshake, token-gated tools, and metering.

Demonstrates:
  - QASP-Shake handshake (ClientHello -> ServerHello -> ClientAuth)
  - Per-tool-call capability token verification via QASPToolProvider
  - Resource metering with report/ack per call and receipt chain
  - PQ-encrypted token transport (AES-256-GCM via session key)
  - Token expiry and revocation rejection
  - Budget exhaustion triggering ResourceSuspend
"""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime, timedelta

import pytest

from qasp.bridges.mcp_bridge import (
    MCPAuthorizationError,
    QASPToolProvider,
    inject_qasp_token,
)
from qasp.crypto import aead, hybrid
from qasp.crypto.suites import SUITE_HYBRID_TRANSITION
from qasp.framing.messages import ResourceSuspend
from qasp.identity import DID, DIDRegistry
from qasp.protocol.capability import (
    CapabilityToken,
    Constraints,
    create_token,
    verify_token,
)
from qasp.protocol.handshake import (
    Handshake,
    HandshakeConfig,
    HandshakeFailure,
    HandshakeKeys,
)
from qasp.protocol.metering import MeterAck, ResourceManager, SuspendReason
from qasp.protocol.revocation import (
    CertificateRevocationList,
    RevocationReason,
    RevocationUrgency,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _analyze_handler(arguments: dict) -> dict:
    return {"status": "analyzed", "score": arguments.get("value", 0) * 2}


async def _summarize_handler(_arguments: dict) -> dict:
    return {"status": "summarized", "length": 42}


def _do_handshake(
    client_sig_keypair: tuple[bytes, bytes],
    server_sig_keypair: tuple[bytes, bytes],
) -> tuple[HandshakeKeys, HandshakeKeys]:
    """Run a full QASP-Shake handshake, returning (client_keys, server_keys)."""
    client_kem_kp = hybrid.generate_keypair()
    server_kem_kp = hybrid.generate_keypair()

    config = HandshakeConfig(
        supported_cipher_suites=(SUITE_HYBRID_TRANSITION,),
    )
    client_hs = Handshake(
        kem_keypair=client_kem_kp,
        sig_keypair=client_sig_keypair,
        is_initiator=True,
        config=config,
    )
    server_hs = Handshake(
        kem_keypair=server_kem_kp,
        sig_keypair=server_sig_keypair,
        is_initiator=False,
        config=config,
    )

    # 1. Client -> Server: ClientHello
    client_hello = client_hs.create_client_hello()

    # 2. Server -> Client: ServerHello
    server_hello = server_hs.process_client_hello(client_hello)
    assert not isinstance(server_hello, HandshakeFailure), server_hello

    # 3. Client -> Server: ClientAuth
    client_auth = client_hs.process_server_hello(server_hello)
    assert not isinstance(client_auth, HandshakeFailure), client_auth

    # 4. Server completes
    server_keys = server_hs.process_client_auth(client_auth)
    assert not isinstance(server_keys, HandshakeFailure), server_keys

    # 5. Client completes
    client_keys = client_hs.complete_client_handshake()
    assert not isinstance(client_keys, HandshakeFailure), client_keys

    return client_keys, server_keys


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestMCPOverQASP:
    """Scenario 4: MCP sessions protected by QASP handshake + tokens."""

    # -----------------------------------------------------------------------
    # Test 1: QASP-Shake establishes session
    # -----------------------------------------------------------------------

    def test_qasp_shake_establishes_session(
        self,
        agent_a_public_key: bytes,
        agent_a_secret_key: bytes,
        agent_b_public_key: bytes,
        agent_b_secret_key: bytes,
    ) -> None:
        """Full 3-message handshake produces identical session keys."""
        client_keys, server_keys = _do_handshake(
            client_sig_keypair=(agent_a_public_key, agent_a_secret_key),
            server_sig_keypair=(agent_b_public_key, agent_b_secret_key),
        )

        assert client_keys.session_key == server_keys.session_key
        assert len(client_keys.session_key) == 32  # AES-256
        assert client_keys.session_id == server_keys.session_id
        assert len(client_keys.session_id) == 32

    # -----------------------------------------------------------------------
    # Test 2: Each tools/call gated by token
    # -----------------------------------------------------------------------

    async def test_each_tools_call_gated_by_token(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_b_did: DID,
        did_registry: DIDRegistry,
    ) -> None:
        """Token for tool A cannot call tool B (resource_uri mismatch)."""
        provider = QASPToolProvider("mcp-server", did_registry)
        provider.register_capability(
            resource_uri="qasp://mcp/tools/analyze",
            verbs={"execute"},
            tool_name="analyze",
            description="Analyze data",
            input_schema={"type": "object"},
            handler=_analyze_handler,
        )
        provider.register_capability(
            resource_uri="qasp://mcp/tools/summarize",
            verbs={"execute"},
            tool_name="summarize",
            description="Summarize results",
            input_schema={"type": "object"},
            handler=_summarize_handler,
        )

        # Token scoped to "analyze"
        analyze_token = create_token(
            issuer_did=agent_a_did,
            issuer_secret_key=agent_a_secret_key,
            subject_did=agent_b_did,
            resource_uri="qasp://mcp/tools/analyze",
            verbs={"execute"},
        )

        # Calling analyze with analyze_token -> success
        meta = inject_qasp_token(analyze_token)
        result = await provider.handle_call_tool(
            "analyze", {"value": 5}, meta=meta,
        )
        assert "analyzed" in result.content[0].text

        # Calling summarize with analyze_token -> rejected (URI mismatch)
        with pytest.raises(MCPAuthorizationError, match="resource_uri"):
            await provider.handle_call_tool("summarize", {}, meta=meta)

    # -----------------------------------------------------------------------
    # Test 3: MCP session with full metering lifecycle
    # -----------------------------------------------------------------------

    async def test_mcp_session_with_metering(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_a_public_key: bytes,
        agent_b_did: DID,
        agent_b_secret_key: bytes,
        agent_b_public_key: bytes,
        did_registry: DIDRegistry,
    ) -> None:
        """Full lifecycle: request/grant, 3 tool calls with metering."""
        from qasp.protocol.metering import ResourceState

        # Setup provider
        provider = QASPToolProvider("mcp-server", did_registry)
        provider.register_capability(
            resource_uri="qasp://mcp/tools/analyze",
            verbs={"execute"},
            tool_name="analyze",
            description="Analyze data",
            input_schema={"type": "object"},
            handler=_analyze_handler,
        )

        # Setup metering
        meter_id = os.urandom(16)
        server_rm = ResourceManager(
            agent_b_secret_key, agent_b_public_key, is_server=True,
        )
        server_rm.set_peer_public_key(agent_a_public_key)

        agent_rm = ResourceManager(
            agent_a_secret_key, agent_a_public_key, is_server=False,
        )
        agent_rm.set_peer_public_key(agent_b_public_key)

        # Resource request/grant
        request, _ = agent_rm.create_resource_request(
            resource_type="compute",
            resource_id=b"mcp-analyze",
            permissions=0x03,
            duration=3600,
        )

        token_constraints = Constraints(
            quantity_limit=100,
            max_spend=1000,
            spend_currency="credits",
        )

        grant, _ = server_rm.process_resource_request(
            request=request,
            token=b"session-token-id",
            granted_permissions=0x03,
            expiration=int(time.time()) + 3600,
            meter_id=meter_id,
            constraints=token_constraints,
            unit_price=10,
        )
        agent_rm.process_resource_grant(
            grant, constraints=token_constraints, unit_price=10,
        )

        # 3 metered tool calls
        for cycle in range(3):
            call_token = create_token(
                issuer_did=agent_a_did,
                issuer_secret_key=agent_a_secret_key,
                subject_did=agent_b_did,
                resource_uri="qasp://mcp/tools/analyze",
                verbs={"execute"},
            )

            meta = inject_qasp_token(call_token)
            result = await provider.handle_call_tool(
                "analyze", {"value": cycle + 1}, meta=meta,
            )
            assert "analyzed" in result.content[0].text

            server_rm.record_usage(meter_id, units=10)
            report, _receipt, _ = server_rm.generate_meter_report(meter_id)
            ack, _ = agent_rm.process_meter_report(report)
            server_rm.process_meter_ack(ack)

        # Verify receipt chain
        receipt_chain = server_rm._receipt_chains[meter_id]
        assert len(receipt_chain) == 3
        assert receipt_chain.verify(agent_b_public_key)

        # Resource release
        release, _ = agent_rm.create_resource_release(meter_id)
        server_rm.process_resource_release(release)
        assert agent_rm._resources[meter_id].state == ResourceState.RELEASED

    # -----------------------------------------------------------------------
    # Test 4: PQ-encrypted token transport
    # -----------------------------------------------------------------------

    def test_pq_encrypted_token_transport(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_a_public_key: bytes,
        agent_b_did: DID,
        agent_b_secret_key: bytes,
        agent_b_public_key: bytes,
    ) -> None:
        """Session key encrypts QASP token via AES-256-GCM, round-trip."""
        client_keys, server_keys = _do_handshake(
            client_sig_keypair=(agent_a_public_key, agent_a_secret_key),
            server_sig_keypair=(agent_b_public_key, agent_b_secret_key),
        )
        session_key = client_keys.session_key

        token = create_token(
            issuer_did=agent_a_did,
            issuer_secret_key=agent_a_secret_key,
            subject_did=agent_b_did,
            resource_uri="qasp://mcp/tools/analyze",
            verbs={"execute"},
        )
        token_cbor = token.to_cbor_with_signature()

        # Encrypt with session key (client side)
        nonce, ciphertext = aead.encrypt(
            key=session_key,
            plaintext=token_cbor,
            associated_data=b"qasp-token-transport",
        )

        # Decrypt with same session key (server side)
        plaintext = aead.decrypt(
            key=server_keys.session_key,
            nonce=nonce,
            ciphertext=ciphertext,
            associated_data=b"qasp-token-transport",
        )

        assert plaintext == token_cbor

        recovered_token = CapabilityToken.from_cbor(plaintext)
        assert recovered_token.token_id == token.token_id
        assert recovered_token.resource_uri == token.resource_uri
        verify_token(recovered_token, agent_a_public_key)

    # -----------------------------------------------------------------------
    # Test 5: Expired token rejected
    # -----------------------------------------------------------------------

    async def test_expired_token_rejected(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_b_did: DID,
        did_registry: DIDRegistry,
    ) -> None:
        """Already-expired token causes MCPAuthorizationError."""
        provider = QASPToolProvider("mcp-server", did_registry)
        provider.register_capability(
            resource_uri="qasp://mcp/tools/analyze",
            verbs={"execute"},
            tool_name="analyze",
            description="Analyze data",
            input_schema={"type": "object"},
            handler=_analyze_handler,
        )

        expired_token = create_token(
            issuer_did=agent_a_did,
            issuer_secret_key=agent_a_secret_key,
            subject_did=agent_b_did,
            resource_uri="qasp://mcp/tools/analyze",
            verbs={"execute"},
            constraints=Constraints(
                not_after=datetime.now(UTC) - timedelta(seconds=10),
            ),
        )

        meta = inject_qasp_token(expired_token)
        with pytest.raises(MCPAuthorizationError):
            await provider.handle_call_tool("analyze", {}, meta=meta)

    # -----------------------------------------------------------------------
    # Test 6: Revoked token rejected
    # -----------------------------------------------------------------------

    async def test_revoked_token_rejected(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_b_did: DID,
        did_registry: DIDRegistry,
    ) -> None:
        """Token in CRL rejected by QASPToolProvider."""
        crl = CertificateRevocationList()
        provider = QASPToolProvider(
            "mcp-server", did_registry, revocation_checker=crl,
        )
        provider.register_capability(
            resource_uri="qasp://mcp/tools/analyze",
            verbs={"execute"},
            tool_name="analyze",
            description="Analyze data",
            input_schema={"type": "object"},
            handler=_analyze_handler,
        )

        token = create_token(
            issuer_did=agent_a_did,
            issuer_secret_key=agent_a_secret_key,
            subject_did=agent_b_did,
            resource_uri="qasp://mcp/tools/analyze",
            verbs={"execute"},
        )

        crl.register_token(token)
        crl.revoke(
            token_id=token.token_id,
            reason=RevocationReason.KEY_COMPROMISE,
            urgency=RevocationUrgency.CRITICAL,
            revoker_did=str(agent_a_did),
            revoker_secret_key=agent_a_secret_key,
        )

        meta = inject_qasp_token(token)
        with pytest.raises(MCPAuthorizationError):
            await provider.handle_call_tool("analyze", {}, meta=meta)

    # -----------------------------------------------------------------------
    # Test 7: Budget exhaustion suspends resource
    # -----------------------------------------------------------------------

    async def test_budget_exhaustion_suspends_resource(
        self,
        agent_a_secret_key: bytes,
        agent_a_public_key: bytes,
        agent_b_secret_key: bytes,
        agent_b_public_key: bytes,
    ) -> None:
        """Token with max_spend=50, cost accumulates past budget."""
        meter_id = os.urandom(16)
        budget_constraints = Constraints(
            max_spend=50, spend_currency="credits",
        )

        server_rm = ResourceManager(
            agent_b_secret_key, agent_b_public_key, is_server=True,
        )
        server_rm.set_peer_public_key(agent_a_public_key)

        agent_rm = ResourceManager(
            agent_a_secret_key, agent_a_public_key, is_server=False,
        )
        agent_rm.set_peer_public_key(agent_b_public_key)

        request, _ = agent_rm.create_resource_request(
            resource_type="compute",
            resource_id=b"mcp-analyze",
            permissions=0x03,
            duration=3600,
        )
        grant, _ = server_rm.process_resource_request(
            request=request,
            token=b"budget-token",
            granted_permissions=0x03,
            expiration=int(time.time()) + 3600,
            meter_id=meter_id,
            constraints=budget_constraints,
            unit_price=10,
        )
        agent_rm.process_resource_grant(
            grant, constraints=budget_constraints, unit_price=10,
        )

        # First 5 units (cost=50) -> OK
        server_rm.record_usage(meter_id, units=5)
        report, _, _ = server_rm.generate_meter_report(meter_id)
        response, _ = agent_rm.process_meter_report(report)
        assert isinstance(response, MeterAck)

        # Next 1 unit (cost=60 > max_spend=50) -> BUDGET_EXHAUSTED
        server_rm.record_usage(meter_id, units=1)
        report2, _, _ = server_rm.generate_meter_report(meter_id)
        response2, _ = agent_rm.process_meter_report(report2)

        assert isinstance(response2, ResourceSuspend)
        assert response2.reason == int(SuspendReason.BUDGET_EXHAUSTED)
