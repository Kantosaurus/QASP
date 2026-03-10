"""Token bucket rate limiter for QASP capability constraint enforcement.

This module implements an active rate limiter that tracks consumption over
time windows and enforces the ``rate`` constraint on capability tokens.
The passive comparison in ``_verify_usage_constraints()`` is complemented
by this token bucket algorithm which provides smooth, time-aware enforcement.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

__all__ = [
    "RateLimitExceededError",
    "RateLimiterRegistry",
    "TokenBucketRateLimiter",
]


# =============================================================================
# Exceptions
# =============================================================================


class RateLimitExceededError(Exception):
    """Raised when a request exceeds the token bucket rate limit.

    Attributes:
        retry_after: Suggested number of seconds to wait before retrying.
    """

    def __init__(self, message: str, retry_after: float = 0.0) -> None:
        super().__init__(message)
        self.retry_after = retry_after


# =============================================================================
# Token Bucket Algorithm
# =============================================================================


class TokenBucketRateLimiter:
    """Standard token bucket rate limiter.

    The bucket starts full at *capacity* tokens. Tokens are consumed by
    requests and refilled at *refill_rate* tokens per second.

    Thread-safe: all mutations are protected by a lock.

    Args:
        capacity: Maximum number of tokens in the bucket.
        refill_rate: Tokens added per second.
    """

    def __init__(self, capacity: float, refill_rate: float) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        if refill_rate <= 0:
            raise ValueError("refill_rate must be positive")

        self._capacity = float(capacity)
        self._refill_rate = float(refill_rate)
        self._tokens = float(capacity)  # Start full
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    @property
    def capacity(self) -> float:
        """Maximum bucket capacity."""
        return self._capacity

    @property
    def refill_rate(self) -> float:
        """Tokens added per second."""
        return self._refill_rate

    @property
    def tokens_available(self) -> float:
        """Current number of tokens (after refill)."""
        with self._lock:
            self._refill()
            return self._tokens

    def consume(self, n: float = 1.0) -> bool:
        """Try to consume *n* tokens from the bucket.

        Args:
            n: Number of tokens to consume (default 1).

        Returns:
            ``True`` if tokens were consumed successfully, ``False`` if
            insufficient tokens are available.
        """
        if n <= 0:
            raise ValueError("n must be positive")

        with self._lock:
            self._refill()
            if self._tokens >= n:
                self._tokens -= n
                return True
            return False

    def consume_or_raise(self, n: float = 1.0) -> None:
        """Consume *n* tokens or raise :class:`RateLimitExceededError`.

        Args:
            n: Number of tokens to consume.

        Raises:
            RateLimitExceededError: If insufficient tokens. The ``retry_after``
                attribute indicates how long to wait.
        """
        if n <= 0:
            raise ValueError("n must be positive")

        with self._lock:
            self._refill()
            if self._tokens >= n:
                self._tokens -= n
                return

            # Compute how long until enough tokens are available
            deficit = n - self._tokens
            retry_after = deficit / self._refill_rate
            raise RateLimitExceededError(
                f"Rate limit exceeded: need {n} tokens, have {self._tokens:.2f}. "
                f"Retry after {retry_after:.2f}s",
                retry_after=retry_after,
            )

    def _refill(self) -> None:
        """Add tokens based on elapsed time since last refill.

        Must be called while holding ``self._lock``.
        """
        now = time.monotonic()
        elapsed = now - self._last_refill
        if elapsed > 0:
            self._tokens = min(
                self._capacity,
                self._tokens + elapsed * self._refill_rate,
            )
            self._last_refill = now


# =============================================================================
# Registry
# =============================================================================


@dataclass
class _LimiterEntry:
    """Internal tracking entry for a rate limiter."""

    limiter: TokenBucketRateLimiter
    created_at: float = field(default_factory=time.monotonic)
    rate_period_seconds: float = 3600.0


class RateLimiterRegistry:
    """Per-token-ID rate limiter tracking.

    Maintains one :class:`TokenBucketRateLimiter` per token ID, creating
    it on first access from the token's rate constraint.

    Thread-safe: all mutations are protected by a lock.
    """

    def __init__(self) -> None:
        self._limiters: dict[bytes, _LimiterEntry] = {}
        self._lock = threading.Lock()

    def get_or_create(
        self,
        token_id: bytes,
        rate_limit: int,
        rate_period_seconds: int = 3600,
    ) -> TokenBucketRateLimiter:
        """Get or create a rate limiter for a token.

        Args:
            token_id: The token's unique identifier.
            rate_limit: Maximum operations per period (bucket capacity).
            rate_period_seconds: Period duration in seconds (default 1 hour).

        Returns:
            The :class:`TokenBucketRateLimiter` for this token.
        """
        with self._lock:
            entry = self._limiters.get(token_id)
            if entry is not None:
                return entry.limiter

            refill_rate = rate_limit / rate_period_seconds
            limiter = TokenBucketRateLimiter(
                capacity=float(rate_limit),
                refill_rate=refill_rate,
            )
            self._limiters[token_id] = _LimiterEntry(
                limiter=limiter,
                rate_period_seconds=float(rate_period_seconds),
            )
            return limiter

    def remove(self, token_id: bytes) -> bool:
        """Remove a rate limiter for a token.

        Args:
            token_id: The token identifier to remove.

        Returns:
            ``True`` if a limiter was removed, ``False`` if not found.
        """
        with self._lock:
            return self._limiters.pop(token_id, None) is not None

    def cleanup_expired(self, max_age_seconds: float = 7200.0) -> int:
        """Remove rate limiters older than *max_age_seconds*.

        Args:
            max_age_seconds: Maximum age before removal (default 2 hours).

        Returns:
            Number of limiters removed.
        """
        now = time.monotonic()
        with self._lock:
            expired = [
                tid
                for tid, entry in self._limiters.items()
                if (now - entry.created_at) > max_age_seconds
            ]
            for tid in expired:
                del self._limiters[tid]
            return len(expired)

    def __len__(self) -> int:
        """Return the number of tracked limiters."""
        with self._lock:
            return len(self._limiters)

    def __contains__(self, token_id: bytes) -> bool:
        """Check if a limiter exists for a token."""
        with self._lock:
            return token_id in self._limiters


# Global registry instance
_global_registry: RateLimiterRegistry | None = None
_global_lock = threading.Lock()


def get_rate_limiter_registry() -> RateLimiterRegistry:
    """Get or create the global rate limiter registry."""
    global _global_registry
    if _global_registry is None:
        with _global_lock:
            if _global_registry is None:
                _global_registry = RateLimiterRegistry()
    return _global_registry
