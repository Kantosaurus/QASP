"""Tests for Session Capability MAC derivation and epoch key rotation (PRD §6)."""

import hmac
import hashlib
import time

import pytest

from qasp.protocol.relay.scm import (
    DIRECTION_A_TO_B,
    DIRECTION_B_TO_A,
    EPOCH_INTERVAL_SEC,
    EpochKeyRing,
    derive_scm,
    validate_scm,
)


class TestDeriveSCM:
    """SCM derivation is exactly HMAC-SHA-256 over the concatenation defined in PRD §6.1."""

    def test_scm_is_32_bytes(self):
        key = b"\x00" * 32
        sid = b"\x01" * 16
        cap_hash = b"\x02" * 48
        scm = derive_scm(key, sid, cap_hash, DIRECTION_A_TO_B, epoch=1)
        assert len(scm) == 32

    def test_scm_matches_hmac_reference(self):
        key = b"k" * 32
        sid = b"s" * 16
        cap_hash = b"c" * 48
        direction = DIRECTION_A_TO_B
        epoch = 42
        expected = hmac.new(
            key,
            sid + cap_hash + bytes([direction]) + epoch.to_bytes(8, "big"),
            hashlib.sha256,
        ).digest()
        assert derive_scm(key, sid, cap_hash, direction, epoch) == expected

    def test_scm_direction_bound(self):
        key = b"k" * 32
        sid = b"s" * 16
        cap_hash = b"c" * 48
        a_to_b = derive_scm(key, sid, cap_hash, DIRECTION_A_TO_B, epoch=1)
        b_to_a = derive_scm(key, sid, cap_hash, DIRECTION_B_TO_A, epoch=1)
        assert a_to_b != b_to_a

    def test_scm_epoch_bound(self):
        key = b"k" * 32
        sid = b"s" * 16
        cap_hash = b"c" * 48
        e1 = derive_scm(key, sid, cap_hash, DIRECTION_A_TO_B, epoch=1)
        e2 = derive_scm(key, sid, cap_hash, DIRECTION_A_TO_B, epoch=2)
        assert e1 != e2

    def test_scm_changes_with_key(self):
        sid = b"s" * 16
        cap_hash = b"c" * 48
        k1 = derive_scm(b"k1" * 16, sid, cap_hash, DIRECTION_A_TO_B, epoch=1)
        k2 = derive_scm(b"k2" * 16, sid, cap_hash, DIRECTION_A_TO_B, epoch=1)
        assert k1 != k2


class TestEpochKeyRing:
    """EpochKeyRing rotates K_server every epoch and keeps the previous key for a grace window."""

    def test_initial_state(self):
        ring = EpochKeyRing()
        assert len(ring.current_key) == 32
        assert ring.previous_key is None

    def test_rotation_shifts_current_to_previous(self):
        ring = EpochKeyRing()
        first = ring.current_key
        ring.rotate()
        assert ring.previous_key == first
        assert ring.current_key != first
        assert len(ring.current_key) == 32

    def test_current_epoch_uses_wall_clock(self):
        ring = EpochKeyRing()
        now = int(time.time())
        assert ring.current_epoch(now) == now // EPOCH_INTERVAL_SEC

    def test_epoch_interval_default_is_300_seconds(self):
        # PRD §6.1: default epoch is 5 minutes
        assert EPOCH_INTERVAL_SEC == 300


class TestValidateScm:
    """validate_scm accepts current-epoch SCMs, previous-epoch within grace, rejects otherwise."""

    def test_accepts_current_epoch(self):
        ring = EpochKeyRing()
        sid = b"s" * 16
        cap_hash = b"c" * 48
        epoch = ring.current_epoch(int(time.time()))
        scm = derive_scm(ring.current_key, sid, cap_hash, DIRECTION_A_TO_B, epoch)
        assert validate_scm(scm, ring, sid, cap_hash, DIRECTION_A_TO_B, now_ts=int(time.time()))

    def test_accepts_previous_epoch_within_grace(self):
        ring = EpochKeyRing()
        sid = b"s" * 16
        cap_hash = b"c" * 48
        now = int(time.time())
        prev_epoch = (now // EPOCH_INTERVAL_SEC) - 1
        old_key = ring.current_key
        ring.rotate()
        assert ring.previous_key == old_key
        scm = derive_scm(old_key, sid, cap_hash, DIRECTION_A_TO_B, prev_epoch)
        # Still within the 2-second grace window (we just rotated).
        assert validate_scm(scm, ring, sid, cap_hash, DIRECTION_A_TO_B, now_ts=now)

    def test_rejects_wrong_direction(self):
        ring = EpochKeyRing()
        sid = b"s" * 16
        cap_hash = b"c" * 48
        now = int(time.time())
        epoch = ring.current_epoch(now)
        scm = derive_scm(ring.current_key, sid, cap_hash, DIRECTION_A_TO_B, epoch)
        assert not validate_scm(scm, ring, sid, cap_hash, DIRECTION_B_TO_A, now_ts=now)

    def test_rejects_forged_scm(self):
        ring = EpochKeyRing()
        sid = b"s" * 16
        cap_hash = b"c" * 48
        now = int(time.time())
        forged = b"\xff" * 32
        assert not validate_scm(forged, ring, sid, cap_hash, DIRECTION_A_TO_B, now_ts=now)
