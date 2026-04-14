"""FSM + metering counter tests for RelaySession (PRD §7.1, §12)."""

import time

import pytest

from qasp.protocol.relay.errors import (
    InvalidScmError,
    SessionBudgetExhaustedError,
)
from qasp.protocol.relay.session import (
    RelaySession,
    RelaySessionState,
    TokenBucket,
)


class TestTokenBucket:
    def test_initial_burst_allows(self):
        tb = TokenBucket(rate_per_sec=10.0, burst=5, now=lambda: 0.0)
        for _ in range(5):
            assert tb.allow(now=0.0) is True
        assert tb.allow(now=0.0) is False  # burst drained

    def test_refill_over_time(self):
        tb = TokenBucket(rate_per_sec=10.0, burst=5, now=lambda: 0.0)
        for _ in range(5):
            tb.allow(now=0.0)
        # 1 second later, burst refilled fully
        assert tb.allow(now=1.0) is True


class TestRelaySessionFSM:
    def _make(self, **overrides):
        defaults = dict(
            session_id=b"\x01" * 16,
            initiator_did="did:qasp:alice",
            target_did="did:qasp:bob",
            cap_token_hash=b"\x02" * 48,
            scm_a=b"\x03" * 32,
            scm_b=b"\x04" * 32,
            expires_at=int(time.time()) + 60,
            max_messages=10,
            max_bytes=1_000,
            max_rate=None,
            epoch_installed=1,
            attenuated_token_for_target=b"\xaa" * 32,
        )
        defaults.update(overrides)
        return RelaySession(**defaults)

    def test_initial_state_is_idle(self):
        s = self._make()
        assert s.state == RelaySessionState.IDLE

    def test_on_request_transitions_to_verifying(self):
        s = self._make()
        s.on_request()
        assert s.state == RelaySessionState.VERIFYING

    def test_on_token_verified_transitions_to_notifying(self):
        s = self._make()
        s.on_request()
        s.on_token_verified()
        assert s.state == RelaySessionState.NOTIFYING

    def test_on_accept_transitions_to_active(self):
        s = self._make()
        s.on_request(); s.on_token_verified(); s.on_accept()
        assert s.state == RelaySessionState.ACTIVE

    def test_on_data_decrements_counters(self):
        s = self._make(max_messages=5, max_bytes=100)
        s.on_request(); s.on_token_verified(); s.on_accept()
        s.consume(payload_len=10)
        assert s.msg_remaining == 4
        assert s.bytes_remaining == 90

    def test_budget_exhausted_transitions_to_suspended(self):
        s = self._make(max_messages=1, max_bytes=1_000)
        s.on_request(); s.on_token_verified(); s.on_accept()
        s.consume(payload_len=10)
        with pytest.raises(SessionBudgetExhaustedError):
            s.consume(payload_len=10)
        assert s.state == RelaySessionState.SUSPENDED

    def test_bytes_budget_rejects_oversized_payload(self):
        s = self._make(max_messages=10, max_bytes=5)
        s.on_request(); s.on_token_verified(); s.on_accept()
        with pytest.raises(SessionBudgetExhaustedError):
            s.consume(payload_len=10)

    def test_rate_limit_enforced(self):
        s = self._make(max_rate=(2, 1))  # 2 msgs / 1 sec
        s.on_request(); s.on_token_verified(); s.on_accept()
        s.consume(payload_len=1, now=0.0)
        s.consume(payload_len=1, now=0.0)
        with pytest.raises(SessionBudgetExhaustedError):
            s.consume(payload_len=1, now=0.0)

    def test_pending_debit_tracking(self):
        s = self._make(max_messages=5, max_bytes=100)
        s.on_request(); s.on_token_verified(); s.on_accept()
        seq = s.consume(payload_len=10, reserve_pending=True)
        assert seq in s.pending_debits
        # confirm: debit stays consumed
        s.confirm_delivery(seq)
        assert seq not in s.pending_debits
        assert s.msg_remaining == 4

    def test_pending_rollback_restores_budget(self):
        s = self._make(max_messages=5, max_bytes=100)
        s.on_request(); s.on_token_verified(); s.on_accept()
        seq = s.consume(payload_len=10, reserve_pending=True)
        assert s.msg_remaining == 4  # reserved debit
        s.rollback_pending(seq)
        assert s.msg_remaining == 5  # restored
        assert seq not in s.pending_debits

    def test_on_close_transitions_to_closing(self):
        s = self._make()
        s.on_request(); s.on_token_verified(); s.on_accept()
        s.on_close()
        assert s.state == RelaySessionState.CLOSING

    def test_expired_session_marked_on_tick(self):
        s = self._make(expires_at=int(time.time()) - 1)
        s.on_request(); s.on_token_verified(); s.on_accept()
        assert s.is_expired(now_ts=int(time.time())) is True

    def test_check_scm_accepts_matching(self):
        s = self._make()
        s.check_scm(s.scm_a, direction=0x00)  # no raise
        s.check_scm(s.scm_b, direction=0x01)

    def test_check_scm_rejects_mismatch(self):
        s = self._make()
        with pytest.raises(InvalidScmError):
            s.check_scm(b"\xff" * 32, direction=0x00)

    def test_epoch_rotation_updates_scms(self):
        s = self._make()
        s.on_request(); s.on_token_verified(); s.on_accept()
        new_a = b"\x77" * 32
        new_b = b"\x88" * 32
        s.on_epoch_rotation(new_a, new_b, 5)
        assert s.scm_a == new_a
        assert s.scm_b == new_b
        assert s.epoch_installed == 5
        assert s.state == RelaySessionState.ACTIVE  # unchanged
