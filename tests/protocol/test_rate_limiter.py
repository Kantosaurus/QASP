"""Tests for token bucket rate limiter."""

from __future__ import annotations

import threading
import time

import pytest

from qasp.protocol.rate_limiter import (
    RateLimitExceededError,
    RateLimiterRegistry,
    TokenBucketRateLimiter,
    get_rate_limiter_registry,
)


# =============================================================================
# TokenBucketRateLimiter Tests
# =============================================================================


class TestTokenBucketRateLimiter:
    """Test the token bucket algorithm."""

    def test_consume_within_capacity(self):
        limiter = TokenBucketRateLimiter(capacity=10, refill_rate=1.0)
        for _ in range(10):
            assert limiter.consume()

    def test_reject_when_empty(self):
        limiter = TokenBucketRateLimiter(capacity=3, refill_rate=0.001)
        assert limiter.consume()
        assert limiter.consume()
        assert limiter.consume()
        assert not limiter.consume()

    def test_consume_n(self):
        limiter = TokenBucketRateLimiter(capacity=10, refill_rate=1.0)
        assert limiter.consume(5)
        assert limiter.consume(5)
        assert not limiter.consume(1)

    def test_tokens_available_starts_full(self):
        limiter = TokenBucketRateLimiter(capacity=100, refill_rate=10.0)
        assert limiter.tokens_available == pytest.approx(100.0, abs=1.0)

    def test_tokens_decrease_after_consume(self):
        limiter = TokenBucketRateLimiter(capacity=10, refill_rate=0.001)
        limiter.consume(3)
        assert limiter.tokens_available == pytest.approx(7.0, abs=0.5)

    def test_refill_over_time(self):
        limiter = TokenBucketRateLimiter(capacity=10, refill_rate=1000.0)
        # Drain completely
        limiter.consume(10)
        assert not limiter.consume()
        # Wait for refill (1000 tokens/sec, need 1 token => ~1ms)
        time.sleep(0.05)
        assert limiter.consume()

    def test_refill_does_not_exceed_capacity(self):
        limiter = TokenBucketRateLimiter(capacity=5, refill_rate=1000.0)
        time.sleep(0.01)
        assert limiter.tokens_available <= 5.0

    def test_consume_or_raise_success(self):
        limiter = TokenBucketRateLimiter(capacity=10, refill_rate=1.0)
        limiter.consume_or_raise(5)  # Should not raise

    def test_consume_or_raise_failure(self):
        limiter = TokenBucketRateLimiter(capacity=2, refill_rate=0.001)
        limiter.consume(2)
        with pytest.raises(RateLimitExceededError) as exc_info:
            limiter.consume_or_raise(1)
        assert exc_info.value.retry_after > 0

    def test_capacity_property(self):
        limiter = TokenBucketRateLimiter(capacity=42, refill_rate=1.0)
        assert limiter.capacity == 42.0

    def test_refill_rate_property(self):
        limiter = TokenBucketRateLimiter(capacity=10, refill_rate=5.5)
        assert limiter.refill_rate == 5.5

    def test_invalid_capacity(self):
        with pytest.raises(ValueError, match="capacity"):
            TokenBucketRateLimiter(capacity=0, refill_rate=1.0)

    def test_invalid_refill_rate(self):
        with pytest.raises(ValueError, match="refill_rate"):
            TokenBucketRateLimiter(capacity=10, refill_rate=0)

    def test_invalid_consume_n(self):
        limiter = TokenBucketRateLimiter(capacity=10, refill_rate=1.0)
        with pytest.raises(ValueError, match="must be positive"):
            limiter.consume(0)

    def test_thread_safety(self):
        """Concurrent consume calls should not over-consume."""
        limiter = TokenBucketRateLimiter(capacity=100, refill_rate=0.001)
        successes = []
        barrier = threading.Barrier(10)

        def worker():
            barrier.wait()
            count = 0
            for _ in range(20):
                if limiter.consume():
                    count += 1
            successes.append(count)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Total successes should not exceed capacity (100)
        total = sum(successes)
        assert total <= 100, f"Over-consumed: {total} > 100"
        # Should consume close to all 100
        assert total >= 90, f"Under-consumed: {total} < 90"


# =============================================================================
# RateLimiterRegistry Tests
# =============================================================================


class TestRateLimiterRegistry:
    """Test the per-token rate limiter registry."""

    def test_get_or_create_new(self):
        registry = RateLimiterRegistry()
        token_id = b"\x01" * 32
        limiter = registry.get_or_create(token_id, rate_limit=100, rate_period_seconds=60)
        assert isinstance(limiter, TokenBucketRateLimiter)
        assert limiter.capacity == 100.0

    def test_get_or_create_existing(self):
        registry = RateLimiterRegistry()
        token_id = b"\x02" * 32
        limiter1 = registry.get_or_create(token_id, rate_limit=50)
        limiter2 = registry.get_or_create(token_id, rate_limit=50)
        assert limiter1 is limiter2

    def test_different_tokens_different_limiters(self):
        registry = RateLimiterRegistry()
        l1 = registry.get_or_create(b"\x01" * 32, rate_limit=10)
        l2 = registry.get_or_create(b"\x02" * 32, rate_limit=20)
        assert l1 is not l2
        assert l1.capacity == 10.0
        assert l2.capacity == 20.0

    def test_remove(self):
        registry = RateLimiterRegistry()
        token_id = b"\x03" * 32
        registry.get_or_create(token_id, rate_limit=10)
        assert registry.remove(token_id)
        assert not registry.remove(token_id)

    def test_contains(self):
        registry = RateLimiterRegistry()
        token_id = b"\x04" * 32
        assert token_id not in registry
        registry.get_or_create(token_id, rate_limit=10)
        assert token_id in registry

    def test_len(self):
        registry = RateLimiterRegistry()
        assert len(registry) == 0
        registry.get_or_create(b"\x01" * 32, rate_limit=10)
        registry.get_or_create(b"\x02" * 32, rate_limit=10)
        assert len(registry) == 2

    def test_cleanup_expired(self):
        registry = RateLimiterRegistry()
        registry.get_or_create(b"\x01" * 32, rate_limit=10)
        # Nothing should be expired with large max_age
        assert registry.cleanup_expired(max_age_seconds=99999) == 0
        # Everything should be expired with tiny max_age
        # (entries were just created, so they're ~0 seconds old)
        # We need to wait a tiny bit
        time.sleep(0.01)
        assert registry.cleanup_expired(max_age_seconds=0.001) == 1

    def test_refill_rate_calculation(self):
        registry = RateLimiterRegistry()
        limiter = registry.get_or_create(
            b"\x05" * 32, rate_limit=60, rate_period_seconds=60
        )
        # 60 ops / 60 seconds = 1 op/sec
        assert limiter.refill_rate == pytest.approx(1.0)


# =============================================================================
# Global Registry Tests
# =============================================================================


class TestGlobalRegistry:
    """Test the global singleton registry."""

    def test_get_registry_returns_same_instance(self):
        r1 = get_rate_limiter_registry()
        r2 = get_rate_limiter_registry()
        assert r1 is r2

    def test_get_registry_is_functional(self):
        registry = get_rate_limiter_registry()
        token_id = b"\xff" * 32
        limiter = registry.get_or_create(token_id, rate_limit=5)
        assert limiter.capacity == 5.0
        # Cleanup
        registry.remove(token_id)
