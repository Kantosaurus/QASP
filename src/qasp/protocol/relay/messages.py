"""CBOR-encoded wire messages for QASP-Relay (PRD §5)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

import cbor2

from qasp.framing.messages import MessageType

__all__ = [
    "RelayData",
    "RelayMessageType",
    "RelaySessionAccept",
    "RelaySessionClose",
    "RelaySessionDeny",
    "RelaySessionGrant",
    "RelaySessionNotify",
    "RelaySessionParams",
    "RelaySessionRequest",
    "decode_relay_frame",
]


class RelayMessageType(IntEnum):
    SESSION_REQUEST = MessageType.RELAY_SESSION_REQUEST
    SESSION_GRANT = MessageType.RELAY_SESSION_GRANT
    SESSION_DENY = MessageType.RELAY_SESSION_DENY
    SESSION_NOTIFY = MessageType.RELAY_SESSION_NOTIFY
    SESSION_ACCEPT = MessageType.RELAY_SESSION_ACCEPT
    DATA = MessageType.RELAY_DATA
    SESSION_CLOSE = MessageType.RELAY_SESSION_CLOSE


@dataclass(frozen=True)
class RelaySessionParams:
    max_messages: int | None
    max_bytes: int | None
    max_rate: tuple[int, int] | None  # (messages, per_seconds)
    duration_sec: int
    purpose: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_messages": self.max_messages,
            "max_bytes": self.max_bytes,
            "max_rate": list(self.max_rate) if self.max_rate is not None else None,
            "duration_sec": self.duration_sec,
            "purpose": self.purpose,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> RelaySessionParams:
        rate = d.get("max_rate")
        return cls(
            max_messages=d.get("max_messages"),
            max_bytes=d.get("max_bytes"),
            max_rate=tuple(rate) if rate is not None else None,  # type: ignore[arg-type]
            duration_sec=int(d["duration_sec"]),
            purpose=d.get("purpose"),
        )


def _dumps(payload: dict[str, Any]) -> bytes:
    return cbor2.dumps(payload)


def _loads(data: bytes) -> dict[str, Any]:
    value = cbor2.loads(data)
    if not isinstance(value, dict):
        raise ValueError("relay frame must be a CBOR map")
    return value


@dataclass(frozen=True)
class RelaySessionRequest:
    target_agent: str
    capability_token: bytes
    session_params: RelaySessionParams
    ephemeral_pk: bytes | None
    nonce: bytes
    msg_type: int = field(default=int(RelayMessageType.SESSION_REQUEST), init=False)

    def to_cbor(self) -> bytes:
        return _dumps({
            "msg_type": self.msg_type,
            "target_agent": self.target_agent,
            "capability_token": self.capability_token,
            "session_params": self.session_params.to_dict(),
            "ephemeral_pk": self.ephemeral_pk,
            "nonce": self.nonce,
        })

    @classmethod
    def from_cbor(cls, data: bytes) -> RelaySessionRequest:
        d = _loads(data)
        return cls(
            target_agent=str(d["target_agent"]),
            capability_token=bytes(d["capability_token"]),
            session_params=RelaySessionParams.from_dict(d["session_params"]),
            ephemeral_pk=bytes(d["ephemeral_pk"]) if d.get("ephemeral_pk") else None,
            nonce=bytes(d["nonce"]),
        )


@dataclass(frozen=True)
class RelaySessionGrant:
    session_id: bytes
    scm: bytes
    negotiated_params: RelaySessionParams
    attenuated_token_for_target: bytes
    epoch: int
    expires_at: int
    msg_type: int = field(default=int(RelayMessageType.SESSION_GRANT), init=False)

    def to_cbor(self) -> bytes:
        return _dumps({
            "msg_type": self.msg_type,
            "session_id": self.session_id,
            "scm": self.scm,
            "negotiated_params": self.negotiated_params.to_dict(),
            "attenuated_token_for_target": self.attenuated_token_for_target,
            "epoch": self.epoch,
            "expires_at": self.expires_at,
        })

    @classmethod
    def from_cbor(cls, data: bytes) -> RelaySessionGrant:
        d = _loads(data)
        return cls(
            session_id=bytes(d["session_id"]),
            scm=bytes(d["scm"]),
            negotiated_params=RelaySessionParams.from_dict(d["negotiated_params"]),
            attenuated_token_for_target=bytes(d["attenuated_token_for_target"]),
            epoch=int(d["epoch"]),
            expires_at=int(d["expires_at"]),
        )


@dataclass(frozen=True)
class RelaySessionDeny:
    nonce: bytes
    error_code: int
    reason: str
    msg_type: int = field(default=int(RelayMessageType.SESSION_DENY), init=False)

    def to_cbor(self) -> bytes:
        return _dumps({
            "msg_type": self.msg_type,
            "nonce": self.nonce,
            "error_code": self.error_code,
            "reason": self.reason,
        })

    @classmethod
    def from_cbor(cls, data: bytes) -> RelaySessionDeny:
        d = _loads(data)
        return cls(
            nonce=bytes(d["nonce"]),
            error_code=int(d["error_code"]),
            reason=str(d["reason"]),
        )


@dataclass(frozen=True)
class RelaySessionNotify:
    session_id: bytes
    initiator_did: str
    attenuated_token: bytes
    negotiated_params: RelaySessionParams
    msg_type: int = field(default=int(RelayMessageType.SESSION_NOTIFY), init=False)

    def to_cbor(self) -> bytes:
        return _dumps({
            "msg_type": self.msg_type,
            "session_id": self.session_id,
            "initiator_did": self.initiator_did,
            "attenuated_token": self.attenuated_token,
            "negotiated_params": self.negotiated_params.to_dict(),
        })

    @classmethod
    def from_cbor(cls, data: bytes) -> RelaySessionNotify:
        d = _loads(data)
        return cls(
            session_id=bytes(d["session_id"]),
            initiator_did=str(d["initiator_did"]),
            attenuated_token=bytes(d["attenuated_token"]),
            negotiated_params=RelaySessionParams.from_dict(d["negotiated_params"]),
        )


@dataclass(frozen=True)
class RelaySessionAccept:
    session_id: bytes
    accepted: bool
    msg_type: int = field(default=int(RelayMessageType.SESSION_ACCEPT), init=False)

    def to_cbor(self) -> bytes:
        return _dumps({
            "msg_type": self.msg_type,
            "session_id": self.session_id,
            "accepted": self.accepted,
        })

    @classmethod
    def from_cbor(cls, data: bytes) -> RelaySessionAccept:
        d = _loads(data)
        return cls(session_id=bytes(d["session_id"]), accepted=bool(d["accepted"]))


@dataclass(frozen=True)
class RelayData:
    session_id: bytes
    scm: bytes
    seq: int
    payload: bytes
    receipt_ack: bytes | None
    msg_type: int = field(default=int(RelayMessageType.DATA), init=False)

    def to_cbor(self) -> bytes:
        return _dumps({
            "msg_type": self.msg_type,
            "session_id": self.session_id,
            "scm": self.scm,
            "seq": self.seq,
            "payload": self.payload,
            "receipt_ack": self.receipt_ack,
        })

    @classmethod
    def from_cbor(cls, data: bytes) -> RelayData:
        d = _loads(data)
        return cls(
            session_id=bytes(d["session_id"]),
            scm=bytes(d["scm"]),
            seq=int(d["seq"]),
            payload=bytes(d["payload"]),
            receipt_ack=bytes(d["receipt_ack"]) if d.get("receipt_ack") else None,
        )


@dataclass(frozen=True)
class RelaySessionClose:
    session_id: bytes
    reason_code: int
    reason_text: str
    msg_type: int = field(default=int(RelayMessageType.SESSION_CLOSE), init=False)

    def to_cbor(self) -> bytes:
        return _dumps({
            "msg_type": self.msg_type,
            "session_id": self.session_id,
            "reason_code": self.reason_code,
            "reason_text": self.reason_text,
        })

    @classmethod
    def from_cbor(cls, data: bytes) -> RelaySessionClose:
        d = _loads(data)
        return cls(
            session_id=bytes(d["session_id"]),
            reason_code=int(d["reason_code"]),
            reason_text=str(d["reason_text"]),
        )


_DISPATCH: dict[int, Any] = {
    RelayMessageType.SESSION_REQUEST: RelaySessionRequest,
    RelayMessageType.SESSION_GRANT: RelaySessionGrant,
    RelayMessageType.SESSION_DENY: RelaySessionDeny,
    RelayMessageType.SESSION_NOTIFY: RelaySessionNotify,
    RelayMessageType.SESSION_ACCEPT: RelaySessionAccept,
    RelayMessageType.DATA: RelayData,
    RelayMessageType.SESSION_CLOSE: RelaySessionClose,
}


def decode_relay_frame(frame: bytes) -> Any:
    """Peek msg_type and dispatch to the matching dataclass."""
    try:
        outer = cbor2.loads(frame)
    except (cbor2.CBORDecodeError, ValueError) as exc:
        raise ValueError(f"malformed CBOR frame: {exc}") from exc
    if not isinstance(outer, dict):
        raise ValueError("relay frame must be a CBOR map")
    mt = outer.get("msg_type")
    if mt is None:
        raise ValueError("relay frame missing msg_type")
    cls = _DISPATCH.get(int(mt))
    if cls is None:
        raise ValueError(f"Unknown relay msg_type: {mt:#x}")
    return cls.from_cbor(frame)
