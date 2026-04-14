"""In-process end-to-end tests for RelayManager."""

import asyncio
from unittest.mock import MagicMock

import pytest

from qasp.protocol.relay.manager import RelayManager
from qasp.protocol.relay.messages import (
    RelayData,
    RelaySessionAccept,
    RelaySessionClose,
    RelaySessionDeny,
    RelaySessionGrant,
    RelaySessionNotify,
    RelaySessionParams,
    RelaySessionRequest,
    decode_relay_frame,
)


class _FakeTokenVerifier:
    """Replaces real ML-DSA-65 verification to avoid liboqs in tests."""

    def __init__(self, *, valid: bool = True):
        self.valid = valid
        self.attenuated_bytes = b"\xaa" * 32
        self.calls = 0

    def verify(self, cap_bytes: bytes, initiator_did: str):
        self.calls += 1
        if not self.valid:
            raise ValueError("token invalid")
        return MagicMock(
            owner_did=initiator_did,
            verbs=MagicMock(),
            constraints=MagicMock(quantity_limit=None, not_after=None),
        )

    def attenuate(self, cap_token, relay_did, session_id):
        return self.attenuated_bytes


@pytest.fixture
def manager(stub_ws):
    return RelayManager(
        relay_did="did:qasp:relay",
        relay_signing_key=b"sk" * 16,
        receipt_key=b"rk" * 16,
        ws_manager=stub_ws,
        token_verifier=_FakeTokenVerifier(),
        agent_is_connected=stub_ws.is_connected,
    )


def _request(target="did:qasp:bob", budget=5):
    return RelaySessionRequest(
        target_agent=target,
        capability_token=b"\xca" * 16,
        session_params=RelaySessionParams(
            max_messages=budget, max_bytes=10_000, max_rate=None,
            duration_sec=60, purpose=None,
        ),
        ephemeral_pk=None,
        nonce=b"\x00" * 32,
    )


async def _open_session(manager, stub_ws, budget=5):
    """Drive the handshake and return the Grant that Alice received."""
    await manager.handle_frame("did:qasp:alice", _request(budget=budget).to_cbor())
    bob_frames = [f for d, f in stub_ws.sent if d == "did:qasp:bob"]
    notify = decode_relay_frame(bob_frames[-1])
    assert isinstance(notify, RelaySessionNotify)
    await manager.handle_frame(
        "did:qasp:bob",
        RelaySessionAccept(session_id=notify.session_id, accepted=True).to_cbor(),
    )
    alice_grants = [
        decode_relay_frame(f)
        for d, f in stub_ws.sent
        if d == "did:qasp:alice" and decode_relay_frame(f).__class__.__name__ == "RelaySessionGrant"
    ]
    return alice_grants[-1]


class TestSessionEstablishment:
    @pytest.mark.asyncio
    async def test_happy_path_request_to_grant(self, manager, stub_ws):
        await manager.handle_frame("did:qasp:alice", _request().to_cbor())
        notify_frames = [f for did, f in stub_ws.sent if did == "did:qasp:bob"]
        assert len(notify_frames) == 1
        notify = decode_relay_frame(notify_frames[0])
        assert isinstance(notify, RelaySessionNotify)

        await manager.handle_frame(
            "did:qasp:bob",
            RelaySessionAccept(session_id=notify.session_id, accepted=True).to_cbor(),
        )
        grants = [decode_relay_frame(f) for did, f in stub_ws.sent if did == "did:qasp:alice"]
        assert any(isinstance(g, RelaySessionGrant) for g in grants)

    @pytest.mark.asyncio
    async def test_target_not_connected(self, manager, stub_ws):
        stub_ws.disconnect("did:qasp:bob")
        await manager.handle_frame("did:qasp:alice", _request().to_cbor())
        denies = [
            decode_relay_frame(f) for did, f in stub_ws.sent
            if did == "did:qasp:alice"
        ]
        assert any(
            isinstance(d, RelaySessionDeny) and d.error_code == 0x20
            for d in denies
        )

    @pytest.mark.asyncio
    async def test_target_rejects(self, manager, stub_ws):
        await manager.handle_frame("did:qasp:alice", _request().to_cbor())
        notify = decode_relay_frame(
            [f for d, f in stub_ws.sent if d == "did:qasp:bob"][-1]
        )
        stub_ws.sent.clear()
        await manager.handle_frame(
            "did:qasp:bob",
            RelaySessionAccept(session_id=notify.session_id, accepted=False).to_cbor(),
        )
        denies = [
            decode_relay_frame(f) for did, f in stub_ws.sent
            if did == "did:qasp:alice"
        ]
        assert any(
            isinstance(d, RelaySessionDeny) and d.error_code == 0x21
            for d in denies
        )


class TestDataPath:
    @pytest.mark.asyncio
    async def test_relay_data_forwarded_to_target(self, manager, stub_ws):
        grant = await _open_session(manager, stub_ws)
        stub_ws.sent.clear()
        data = RelayData(
            session_id=grant.session_id,
            scm=grant.scm,
            seq=1,
            payload=b"hello bob",
            receipt_ack=None,
        )
        await manager.handle_frame("did:qasp:alice", data.to_cbor())
        bob_frames = [decode_relay_frame(f) for d, f in stub_ws.sent if d == "did:qasp:bob"]
        assert any(
            isinstance(fr, RelayData) and fr.payload == b"hello bob"
            for fr in bob_frames
        )

    @pytest.mark.asyncio
    async def test_invalid_scm_drops_message(self, manager, stub_ws):
        grant = await _open_session(manager, stub_ws)
        stub_ws.sent.clear()
        bad = RelayData(
            session_id=grant.session_id,
            scm=b"\xff" * 32,
            seq=1,
            payload=b"hi",
            receipt_ack=None,
        )
        await manager.handle_frame("did:qasp:alice", bad.to_cbor())
        bob_frames = [d for d, _ in stub_ws.sent if d == "did:qasp:bob"]
        assert not bob_frames


class TestBudgetAndTimeout:
    @pytest.mark.asyncio
    async def test_budget_exhaustion_closes_session(self, manager, stub_ws):
        grant = await _open_session(manager, stub_ws, budget=5)
        # Deliver + ACK 5 messages
        for i in range(1, 6):
            await manager.handle_frame(
                "did:qasp:alice",
                RelayData(
                    session_id=grant.session_id, scm=grant.scm, seq=i,
                    payload=b"x", receipt_ack=None,
                ).to_cbor(),
            )
            await manager._on_delivery_ack(grant.session_id, i)
        stub_ws.sent.clear()
        # 6th message must trip budget and close session
        await manager.handle_frame(
            "did:qasp:alice",
            RelayData(
                session_id=grant.session_id, scm=grant.scm, seq=6,
                payload=b"x", receipt_ack=None,
            ).to_cbor(),
        )
        alice_frames = [decode_relay_frame(f) for d, f in stub_ws.sent if d == "did:qasp:alice"]
        assert any(
            isinstance(fr, RelaySessionClose) and fr.reason_code == 0x23
            for fr in alice_frames
        )

    @pytest.mark.asyncio
    async def test_delivery_timeout_rolls_back_debit(self, manager, stub_ws):
        grant = await _open_session(manager, stub_ws, budget=5)
        session = manager._sessions[grant.session_id]
        assert session.msg_remaining == 5
        await manager.handle_frame(
            "did:qasp:alice",
            RelayData(
                session_id=grant.session_id, scm=grant.scm, seq=1,
                payload=b"x", receipt_ack=None,
            ).to_cbor(),
        )
        assert session.msg_remaining == 4
        await manager._on_delivery_timeout(grant.session_id, seq=1)
        assert session.msg_remaining == 5
