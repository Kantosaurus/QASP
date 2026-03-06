"""Token replay prevention via in-memory use log.

Provides a thread-safe token-use log that tracks consumed token IDs
to prevent replay attacks. Follows the CertificateRevocationList
pattern from revocation.py.
"""

from __future__ import annotations

import threading

from qasp.protocol.capability import CapabilityError

__all__ = [
    "TokenReplayError",
    "TokenUseLog",
]


class TokenReplayError(CapabilityError):
    """Raised when a token has already been consumed."""

    alert_code: int = 54


class TokenUseLog:
    """Thread-safe in-memory log of consumed token IDs.

    Usage pattern: caller calls verify_token() first, then
    token_use_log.mark_used(token.token_id) to prevent replay.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._used: set[bytes] = set()

    def mark_used(self, token_id: bytes) -> None:
        """Mark a token as used. Raises TokenReplayError if already used."""
        with self._lock:
            if token_id in self._used:
                raise TokenReplayError(
                    f"Token {token_id.hex()[:16]}... has already been consumed"
                )
            self._used.add(token_id)

    def is_used(self, token_id: bytes) -> bool:
        """Check whether a token has been used."""
        with self._lock:
            return token_id in self._used

    def __contains__(self, token_id: bytes) -> bool:
        return self.is_used(token_id)

    def __len__(self) -> int:
        with self._lock:
            return len(self._used)
