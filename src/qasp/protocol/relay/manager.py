"""Server-side orchestrator for QASP-Relay sessions."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any, Protocol

from qasp.protocol.relay.errors import (
    RelayOverloadedError,
    SessionBudgetExhaustedError,
    TargetNotConnectedError,
    TargetRejectedError,
)
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
from qasp.protocol.relay.receipts import RelayReceipt, hash_payload
from qasp.protocol.relay.scm import (
    DIRECTION_A_TO_B,
    DIRECTION_B_TO_A,
    EpochKeyRing,
    derive_scm,
    validate_scm,
)
from qasp.protocol.relay.session import RelaySession

__all__ = ["RelayManager"]

logger = logging.getLogger(__name__)

DELIVERY_TIMEOUT_SEC = 2.0
MAX_CONCURRENT_SESSIONS = 10_000


class TokenVerifierProtocol(Protocol):
    def verify(self, cap_bytes: bytes, initiator_did: str) -> Any: ...
    def attenuate(self, cap_token: Any, relay_did: str, session_id: bytes) -> bytes: ...


class WSManagerProtocol(Protocol):
    async def send_bytes(self, did_str: str, payload: bytes) -> bool: ...


class RelayManager:
    """Owns the lifecycle of every relay session on this authority server."""

    def __init__(
        self,
        *,
        relay_did: str,
        relay_signing_key: bytes,
        receipt_key: bytes,
        ws_manager: WSManagerProtocol,
        token_verifier: TokenVerifierProtocol,
        agent_is_connected: Callable[[str], bool],
        key_ring: EpochKeyRing | None = None,
        on_receipt: Callable[[RelayReceipt], Awaitable[None]] | None = None,
    ) -> None:
        self.relay_did = relay_did
        self.relay_signing_key = relay_signing_key
        self.receipt_key = receipt_key
        self.ws = ws_manager
        self.verifier = token_verifier
        self.is_connected = agent_is_connected
        self.key_ring = key_ring or EpochKeyRing()
        self.on_receipt = on_receipt

        self._sessions: dict[bytes, RelaySession] = {}
        self._sessions_by_agent: dict[str, set[bytes]] = {}
        self._pending_notify: dict[bytes, RelaySession] = {}
        self._request_nonces: dict[bytes, bytes] = {}  # session_id -> Alice's nonce
        self._delivery_tasks: dict[tuple[bytes, int], asyncio.Task] = {}
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Entry point called from the WebSocket listen loop
    # ------------------------------------------------------------------

    async def handle_frame(self, sender_did: str, frame: bytes) -> None:
        try:
            msg = decode_relay_frame(frame)
        except ValueError as exc:
            logger.warning("relay: rejecting malformed frame from %s: %s", sender_did, exc)
            return

        if isinstance(msg, RelaySessionRequest):
            await self._handle_request(sender_did, msg)
        elif isinstance(msg, RelaySessionAccept):
            await self._handle_accept(sender_did, msg)
        elif isinstance(msg, RelayData):
            await self._handle_data(sender_did, msg)
        elif isinstance(msg, RelaySessionClose):
            await self._handle_close(sender_did, msg)
        else:
            logger.warning(
                "relay: unexpected message type from %s: %s",
                sender_did, type(msg).__name__,
            )

    async def close_all_for_agent(self, did_str: str) -> None:
        async with self._lock:
            ids = list(self._sessions_by_agent.get(did_str, set()))
        for sid in ids:
            await self._teardown_session(sid, reason_code=0x26, reason_text="peer disconnected")

    # ------------------------------------------------------------------
    # Request / accept
    # ------------------------------------------------------------------

    async def _handle_request(self, alice_did: str, req: RelaySessionRequest) -> None:
        if len(self._sessions) >= MAX_CONCURRENT_SESSIONS:
            await self._send_deny(alice_did, req.nonce, RelayOverloadedError("too many sessions"))
            return

        if not self.is_connected(req.target_agent):
            await self._send_deny(
                alice_did, req.nonce, TargetNotConnectedError("target offline"),
            )
            return

        try:
            cap_token = self.verifier.verify(req.capability_token, alice_did)
        except Exception as exc:
            await self._send_deny(
                alice_did, req.nonce,
                TargetRejectedError(f"capability verify failed: {exc}"),
            )
            return

        session_id = uuid.uuid4().bytes
        cap_hash = hashlib.sha384(req.capability_token).digest()
        now_ts = int(time.time())
        epoch = self.key_ring.current_epoch(now_ts)
        scm_a = derive_scm(
            self.key_ring.current_key, session_id, cap_hash, DIRECTION_A_TO_B, epoch,
        )
        scm_b = derive_scm(
            self.key_ring.current_key, session_id, cap_hash, DIRECTION_B_TO_A, epoch,
        )
        attenuated_bytes = self.verifier.attenuate(cap_token, self.relay_did, session_id)

        params = req.session_params
        expires_at = now_ts + params.duration_sec

        session = RelaySession(
            session_id=session_id,
            initiator_did=alice_did,
            target_did=req.target_agent,
            cap_token_hash=cap_hash,
            scm_a=scm_a,
            scm_b=scm_b,
            expires_at=expires_at,
            max_messages=params.max_messages,
            max_bytes=params.max_bytes,
            max_rate=params.max_rate,
            epoch_installed=epoch,
            attenuated_token_for_target=attenuated_bytes,
        )
        session.on_request()
        session.on_token_verified()
        self._pending_notify[session_id] = session
        self._request_nonces[session_id] = req.nonce

        await self.ws.send_bytes(
            req.target_agent,
            RelaySessionNotify(
                session_id=session_id,
                initiator_did=alice_did,
                attenuated_token=attenuated_bytes,
                negotiated_params=params,
            ).to_cbor(),
        )

    async def _handle_accept(self, bob_did: str, msg: RelaySessionAccept) -> None:
        session = self._pending_notify.pop(msg.session_id, None)
        nonce = self._request_nonces.pop(msg.session_id, b"\x00" * 32)
        if session is None:
            return
        if bob_did != session.target_did:
            return
        if not msg.accepted:
            await self._send_deny(
                session.initiator_did, nonce, TargetRejectedError("target declined"),
            )
            return
        session.on_accept()
        async with self._lock:
            self._sessions[session.session_id] = session
            self._sessions_by_agent.setdefault(session.initiator_did, set()).add(session.session_id)
            self._sessions_by_agent.setdefault(session.target_did, set()).add(session.session_id)

        remaining = session.expires_at - int(time.time())
        shared_params = RelaySessionParams(
            max_messages=session.max_messages,
            max_bytes=session.max_bytes,
            max_rate=session.max_rate,
            duration_sec=max(0, remaining),
            purpose=None,
        )
        await self.ws.send_bytes(
            session.initiator_did,
            RelaySessionGrant(
                session_id=session.session_id,
                scm=session.scm_a,
                negotiated_params=shared_params,
                attenuated_token_for_target=session.attenuated_token_for_target,
                epoch=session.epoch_installed,
                expires_at=session.expires_at,
            ).to_cbor(),
        )
        await self.ws.send_bytes(
            session.target_did,
            RelaySessionGrant(
                session_id=session.session_id,
                scm=session.scm_b,
                negotiated_params=shared_params,
                attenuated_token_for_target=b"",
                epoch=session.epoch_installed,
                expires_at=session.expires_at,
            ).to_cbor(),
        )

    # ------------------------------------------------------------------
    # Data forwarding
    # ------------------------------------------------------------------

    async def _handle_data(self, sender_did: str, msg: RelayData) -> None:
        session = self._sessions.get(msg.session_id)
        if session is None:
            return
        direction = DIRECTION_A_TO_B if sender_did == session.initiator_did else DIRECTION_B_TO_A
        other_did = session.target_did if direction == DIRECTION_A_TO_B else session.initiator_did

        if not validate_scm(
            msg.scm, self.key_ring, session.session_id, session.cap_token_hash, direction,
        ):
            return
        if session.is_expired(int(time.time())):
            await self._teardown_session(session.session_id, 0x26, "session expired")
            return

        try:
            seq = session.consume(payload_len=len(msg.payload), reserve_pending=True)
        except SessionBudgetExhaustedError:
            await self._teardown_session(session.session_id, 0x23, "budget exhausted")
            return

        ok = await self.ws.send_bytes(
            other_did,
            RelayData(
                session_id=msg.session_id,
                scm=b"\x00" * 32,
                seq=seq,
                payload=msg.payload,
                receipt_ack=None,
            ).to_cbor(),
        )
        if not ok:
            session.rollback_pending(seq)
            return

        task = asyncio.create_task(self._await_delivery(session.session_id, seq))
        self._delivery_tasks[(session.session_id, seq)] = task

        now_ts = int(time.time())
        cumulative_msgs = (
            (session.max_messages or 0)
            - (session.msg_remaining if session.msg_remaining is not None else 0)
        )
        cumulative_bytes = (
            (session.max_bytes or 0)
            - (session.bytes_remaining if session.bytes_remaining is not None else 0)
        )
        r = RelayReceipt.new(
            session_id=session.session_id,
            seq=seq,
            msg_hash=hash_payload(msg.payload),
            timestamp=now_ts,
            direction=direction,
            cumulative_msgs=cumulative_msgs,
            cumulative_bytes=cumulative_bytes,
            cumulative_cost=len(msg.payload),
            prev_hash=session.receipt_chain.tip,
            receipt_key=self.receipt_key,
        )
        session.receipt_chain.append(r)
        if self.on_receipt is not None:
            await self.on_receipt(r)

    async def _await_delivery(self, session_id: bytes, seq: int) -> None:
        try:
            await asyncio.sleep(DELIVERY_TIMEOUT_SEC)
            await self._on_delivery_timeout(session_id, seq)
        except asyncio.CancelledError:
            pass

    async def _on_delivery_ack(self, session_id: bytes, seq: int) -> None:
        task = self._delivery_tasks.pop((session_id, seq), None)
        if task is not None and not task.done():
            task.cancel()
        session = self._sessions.get(session_id)
        if session is not None:
            session.confirm_delivery(seq)

    async def _on_delivery_timeout(self, session_id: bytes, seq: int) -> None:
        self._delivery_tasks.pop((session_id, seq), None)
        session = self._sessions.get(session_id)
        if session is not None:
            session.rollback_pending(seq)

    # ------------------------------------------------------------------
    # Close / teardown
    # ------------------------------------------------------------------

    async def _handle_close(self, sender_did: str, msg: RelaySessionClose) -> None:
        await self._teardown_session(msg.session_id, msg.reason_code, msg.reason_text)

    async def _teardown_session(self, session_id: bytes, reason_code: int, reason_text: str) -> None:
        session = self._sessions.pop(session_id, None)
        if session is None:
            return
        async with self._lock:
            for did in (session.initiator_did, session.target_did):
                ids = self._sessions_by_agent.get(did)
                if ids:
                    ids.discard(session_id)
        session.on_close()
        close = RelaySessionClose(
            session_id=session_id, reason_code=reason_code, reason_text=reason_text,
        ).to_cbor()
        await self.ws.send_bytes(session.initiator_did, close)
        await self.ws.send_bytes(session.target_did, close)

    async def _send_deny(self, did: str, nonce: bytes, err: Exception) -> None:
        code = getattr(err, "code", 0x24)
        await self.ws.send_bytes(
            did,
            RelaySessionDeny(nonce=nonce, error_code=int(code), reason=str(err)).to_cbor(),
        )

    # ------------------------------------------------------------------
    # Epoch rotation
    # ------------------------------------------------------------------

    async def rotate_epoch(self) -> None:
        self.key_ring.rotate()
        now_ts = int(time.time())
        new_epoch = self.key_ring.current_epoch(now_ts)
        for session in list(self._sessions.values()):
            new_a = derive_scm(
                self.key_ring.current_key, session.session_id,
                session.cap_token_hash, DIRECTION_A_TO_B, new_epoch,
            )
            new_b = derive_scm(
                self.key_ring.current_key, session.session_id,
                session.cap_token_hash, DIRECTION_B_TO_A, new_epoch,
            )
            session.on_epoch_rotation(new_a, new_b, new_epoch)
