"""Session Capability MAC (SCM) derivation and epoch-based key rotation.

PRD §6: the SCM is a 256-bit HMAC-SHA-256 tag that the relay validates in O(1)
on every forwarded message, amortizing the cost of per-session ML-DSA-65
verification.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time

__all__ = [
    "DIRECTION_A_TO_B",
    "DIRECTION_B_TO_A",
    "EPOCH_INTERVAL_SEC",
    "GRACE_WINDOW_SEC",
    "EpochKeyRing",
    "derive_scm",
    "validate_scm",
]

DIRECTION_A_TO_B: int = 0x00
DIRECTION_B_TO_A: int = 0x01

EPOCH_INTERVAL_SEC: int = 300  # PRD §6.1 default: 5 minutes
GRACE_WINDOW_SEC: int = 2  # PRD §15 mitigation for epoch-rotation race

_KEY_SIZE = 32
_SCM_SIZE = 32


def derive_scm(
    key: bytes,
    session_id: bytes,
    cap_token_hash: bytes,
    direction: int,
    epoch: int,
) -> bytes:
    """Derive a Session Capability MAC per PRD §6.1.

    SCM = HMAC-SHA-256(
        key  = K_server,
        data = session_id || H(capability_token) || direction || epoch
    )
    """
    if len(session_id) != 16:
        raise ValueError("session_id must be 16 bytes (UUIDv7)")
    if len(cap_token_hash) != 48:
        raise ValueError("cap_token_hash must be 48 bytes (SHA-384)")
    if direction not in (DIRECTION_A_TO_B, DIRECTION_B_TO_A):
        raise ValueError(f"direction must be 0x00 or 0x01, got {direction:#x}")
    payload = (
        session_id
        + cap_token_hash
        + bytes([direction])
        + int(epoch).to_bytes(8, "big")
    )
    return hmac.new(key, payload, hashlib.sha256).digest()


class EpochKeyRing:
    """Holds the current and previous K_server for epoch rotation."""

    __slots__ = ("current_key", "previous_key", "_rotated_at")

    def __init__(self, seed: bytes | None = None) -> None:
        self.current_key: bytes = seed if seed is not None else os.urandom(_KEY_SIZE)
        if len(self.current_key) != _KEY_SIZE:
            raise ValueError("seed must be 32 bytes")
        self.previous_key: bytes | None = None
        self._rotated_at: float = time.monotonic()

    def rotate(self) -> None:
        self.previous_key = self.current_key
        self.current_key = os.urandom(_KEY_SIZE)
        self._rotated_at = time.monotonic()

    def current_epoch(self, now_ts: int | None = None) -> int:
        if now_ts is None:
            now_ts = int(time.time())
        return now_ts // EPOCH_INTERVAL_SEC

    @property
    def seconds_since_rotation(self) -> float:
        return time.monotonic() - self._rotated_at


def validate_scm(
    candidate: bytes,
    ring: EpochKeyRing,
    session_id: bytes,
    cap_token_hash: bytes,
    direction: int,
    now_ts: int | None = None,
) -> bool:
    """Constant-time validation against current epoch, falling back to previous
    epoch within the GRACE_WINDOW_SEC window (PRD §15)."""
    if len(candidate) != _SCM_SIZE:
        return False
    if now_ts is None:
        now_ts = int(time.time())
    current_epoch = ring.current_epoch(now_ts)
    current = derive_scm(
        ring.current_key, session_id, cap_token_hash, direction, current_epoch
    )
    if hmac.compare_digest(candidate, current):
        return True
    if ring.previous_key is not None and ring.seconds_since_rotation <= GRACE_WINDOW_SEC:
        previous = derive_scm(
            ring.previous_key,
            session_id,
            cap_token_hash,
            direction,
            current_epoch - 1,
        )
        if hmac.compare_digest(candidate, previous):
            return True
    return False
