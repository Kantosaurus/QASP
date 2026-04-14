"""RelaySession FSM, metering counters, and token-bucket rate limiter (PRD §7.1, §12)."""

from __future__ import annotations

import hmac as _hmac
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable

from qasp.protocol.relay.errors import (
    InvalidScmError,
    SessionBudgetExhaustedError,
)
from qasp.protocol.relay.receipts import RelayReceiptChain

__all__ = [
    "RelaySession",
    "RelaySessionState",
    "TokenBucket",
]


class RelaySessionState(Enum):
    IDLE = auto()
    VERIFYING = auto()
    NOTIFYING = auto()
    ACTIVE = auto()
    SUSPENDED = auto()
    CLOSING = auto()


@dataclass
class TokenBucket:
    rate_per_sec: float
    burst: int
    now: Callable[[], float] = time.monotonic
    _tokens: float = field(init=False)
    _last: float = field(init=False)

    def __post_init__(self) -> None:
        self._tokens = float(self.burst)
        self._last = self.now()

    def allow(self, *, now: float | None = None) -> bool:
        t = now if now is not None else self.now()
        elapsed = max(0.0, t - self._last)
        self._tokens = min(self.burst, self._tokens + elapsed * self.rate_per_sec)
        self._last = t
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False


@dataclass
class RelaySession:
    session_id: bytes
    initiator_did: str
    target_did: str
    cap_token_hash: bytes
    scm_a: bytes
    scm_b: bytes
    expires_at: int
    max_messages: int | None
    max_bytes: int | None
    max_rate: tuple[int, int] | None
    epoch_installed: int
    attenuated_token_for_target: bytes

    state: RelaySessionState = RelaySessionState.IDLE
    msg_remaining: int | None = None
    bytes_remaining: int | None = None
    spend_accrued: int = 0
    next_seq: int = 1
    pending_debits: dict[int, tuple[int, int]] = field(default_factory=dict)
    receipt_chain: RelayReceiptChain = field(default_factory=RelayReceiptChain)
    _rate_bucket: TokenBucket | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        if self.msg_remaining is None:
            self.msg_remaining = self.max_messages
        if self.bytes_remaining is None:
            self.bytes_remaining = self.max_bytes
        if self.max_rate is not None:
            msgs, per_sec = self.max_rate
            self._rate_bucket = TokenBucket(
                rate_per_sec=msgs / per_sec, burst=msgs
            )

    # ---- FSM transitions ----------------------------------------------

    def on_request(self) -> None:
        if self.state != RelaySessionState.IDLE:
            raise RuntimeError(f"cannot request from state {self.state}")
        self.state = RelaySessionState.VERIFYING

    def on_token_verified(self) -> None:
        if self.state != RelaySessionState.VERIFYING:
            raise RuntimeError(f"cannot verify from state {self.state}")
        self.state = RelaySessionState.NOTIFYING

    def on_token_invalid(self) -> None:
        self.state = RelaySessionState.IDLE

    def on_accept(self) -> None:
        if self.state != RelaySessionState.NOTIFYING:
            raise RuntimeError(f"cannot accept from state {self.state}")
        self.state = RelaySessionState.ACTIVE

    def on_close(self) -> None:
        self.state = RelaySessionState.CLOSING

    def on_epoch_rotation(self, new_scm_a: bytes, new_scm_b: bytes, new_epoch: int) -> None:
        self.scm_a = new_scm_a
        self.scm_b = new_scm_b
        self.epoch_installed = new_epoch

    # ---- metering ------------------------------------------------------

    def is_expired(self, now_ts: int) -> bool:
        return now_ts >= self.expires_at

    def check_scm(self, candidate: bytes, direction: int) -> None:
        expected = self.scm_a if direction == 0x00 else self.scm_b
        if not _hmac.compare_digest(candidate, expected):
            raise InvalidScmError("SCM mismatch")

    def consume(
        self,
        *,
        payload_len: int,
        reserve_pending: bool = False,
        now: float | None = None,
    ) -> int:
        """Decrement counters for one message; return the assigned seq."""
        if self.state != RelaySessionState.ACTIVE:
            raise RuntimeError(f"cannot consume from state {self.state}")
        if self.msg_remaining is not None and self.msg_remaining <= 0:
            self.state = RelaySessionState.SUSPENDED
            raise SessionBudgetExhaustedError("msg budget exhausted")
        if self.bytes_remaining is not None and self.bytes_remaining < payload_len:
            self.state = RelaySessionState.SUSPENDED
            raise SessionBudgetExhaustedError("byte budget exhausted")
        if self._rate_bucket is not None and not self._rate_bucket.allow(now=now):
            raise SessionBudgetExhaustedError("rate limit exceeded")

        if self.msg_remaining is not None:
            self.msg_remaining -= 1
        if self.bytes_remaining is not None:
            self.bytes_remaining -= payload_len

        seq = self.next_seq
        self.next_seq += 1
        if reserve_pending:
            self.pending_debits[seq] = (1, payload_len)
        return seq

    def confirm_delivery(self, seq: int) -> None:
        self.pending_debits.pop(seq, None)

    def rollback_pending(self, seq: int) -> None:
        debit = self.pending_debits.pop(seq, None)
        if debit is None:
            return
        msgs, bytes_ = debit
        if self.msg_remaining is not None:
            self.msg_remaining += msgs
        if self.bytes_remaining is not None:
            self.bytes_remaining += bytes_
