"""Integration tests for handshake timeout and retry behavior."""

from __future__ import annotations

import pytest

from qasp.crypto import hybrid, signatures
from qasp.protocol.connection import QASPConnection
from qasp.protocol.events import (
    HandshakeFailed,
    HandshakeTimeout,
)
from qasp.protocol.handshake import (
    HandshakeConfig,
    HandshakeErrorType,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def client_keypairs() -> tuple[hybrid.HybridKeypair, tuple[bytes, bytes]]:
    """Generate keypairs for a client."""
    kem_keypair = hybrid.generate_keypair()
    sig_keypair = signatures.generate_keypair()
    return kem_keypair, sig_keypair


@pytest.fixture
def server_keypairs() -> tuple[hybrid.HybridKeypair, tuple[bytes, bytes]]:
    """Generate keypairs for a server."""
    kem_keypair = hybrid.generate_keypair()
    sig_keypair = signatures.generate_keypair()
    return kem_keypair, sig_keypair


@pytest.fixture
def custom_timeout_config() -> HandshakeConfig:
    """Create a config with custom timeout settings for testing."""
    return HandshakeConfig(
        initial_timeout_ms=1000,
        max_timeout_ms=8000,
        backoff_multiplier=2.0,
        max_retries=3,
    )


@pytest.fixture
def client_connection(
    client_keypairs: tuple[hybrid.HybridKeypair, tuple[bytes, bytes]],
    custom_timeout_config: HandshakeConfig,
) -> QASPConnection:
    """Create a client connection with custom timeout config."""
    kem_keypair, sig_keypair = client_keypairs
    return QASPConnection(
        kem_keypair=kem_keypair,
        sig_keypair=sig_keypair,
        is_client=True,
        config=custom_timeout_config,
    )


# =============================================================================
# Timeout Configuration Tests
# =============================================================================


class TestTimeoutConfiguration:
    """Tests for timeout configuration in HandshakeConfig."""

    def test_default_timeout_values(self) -> None:
        """Default config has expected timeout values."""
        config = HandshakeConfig()
        assert config.initial_timeout_ms == 5000
        assert config.max_timeout_ms == 60000
        assert config.backoff_multiplier == 2.0
        assert config.max_retries == 3

    def test_custom_timeout_values(self) -> None:
        """Can create config with custom timeout values."""
        config = HandshakeConfig(
            initial_timeout_ms=2000,
            max_timeout_ms=30000,
            backoff_multiplier=1.5,
            max_retries=5,
        )
        assert config.initial_timeout_ms == 2000
        assert config.max_timeout_ms == 30000
        assert config.backoff_multiplier == 1.5
        assert config.max_retries == 5


# =============================================================================
# Timeout Handling Tests
# =============================================================================


class TestTimeoutHandling:
    """Tests for timeout handling in QASPConnection."""

    def test_get_current_timeout_returns_initial_value(
        self,
        client_connection: QASPConnection,
    ) -> None:
        """get_current_timeout returns initial timeout value."""
        assert client_connection.get_current_timeout() == 1000

    def test_prepare_retry_increases_timeout_exponentially(
        self,
        client_connection: QASPConnection,
    ) -> None:
        """prepare_retry applies exponential backoff to timeout."""
        # Initial timeout is 1000ms
        assert client_connection.get_current_timeout() == 1000

        # First retry: 1000 * 2 = 2000
        client_connection.prepare_retry()
        assert client_connection.get_current_timeout() == 2000
        assert client_connection.retry_count == 1

        # Second retry: 2000 * 2 = 4000
        client_connection.prepare_retry()
        assert client_connection.get_current_timeout() == 4000
        assert client_connection.retry_count == 2

        # Third retry: 4000 * 2 = 8000 (at max)
        client_connection.prepare_retry()
        assert client_connection.get_current_timeout() == 8000
        assert client_connection.retry_count == 3

    def test_timeout_capped_at_max_timeout_ms(
        self,
        client_connection: QASPConnection,
    ) -> None:
        """Timeout is capped at max_timeout_ms."""
        # Apply backoff multiple times
        for _ in range(5):
            client_connection.prepare_retry()

        # Should be capped at 8000 (max_timeout_ms)
        assert client_connection.get_current_timeout() == 8000

    def test_should_retry_returns_false_after_max_retries(
        self,
        client_connection: QASPConnection,
    ) -> None:
        """should_retry returns False after max retries exceeded."""
        # Initially should allow retries for timeout
        assert client_connection.should_retry(HandshakeErrorType.TIMEOUT)

        # Exhaust retries
        for _ in range(3):
            client_connection.prepare_retry()

        # Now should not allow retry
        assert client_connection.retry_count == 3
        assert not client_connection.should_retry(HandshakeErrorType.TIMEOUT)


# =============================================================================
# Version Mismatch Retry Tests
# =============================================================================


class TestVersionMismatchRetry:
    """Tests for version mismatch retry behavior."""

    def test_version_mismatch_is_retryable(
        self,
        client_connection: QASPConnection,
    ) -> None:
        """Version mismatch errors are retryable."""
        assert client_connection.should_retry(HandshakeErrorType.VERSION_MISMATCH)

    def test_retry_uses_exponential_backoff_timing(
        self,
        client_connection: QASPConnection,
    ) -> None:
        """Retries use exponential backoff for timeout values."""
        timeouts = [client_connection.get_current_timeout()]

        for _ in range(3):
            client_connection.prepare_retry()
            timeouts.append(client_connection.get_current_timeout())

        # Verify exponential growth: 1000, 2000, 4000, 8000
        assert timeouts == [1000, 2000, 4000, 8000]

    def test_max_retries_exceeded_closes_connection(
        self,
        client_connection: QASPConnection,
    ) -> None:
        """Exceeding max retries eventually fails."""
        # Start handshake to get into proper state
        client_connection.initiate_handshake()

        # Exhaust retries
        for _ in range(3):
            client_connection.prepare_retry()

        # Handle timeout should now fail permanently
        events = client_connection.handle_timeout()

        # Should have HandshakeTimeout with will_retry=False and HandshakeFailed
        timeout_events = [e for e in events if isinstance(e, HandshakeTimeout)]
        failed_events = [e for e in events if isinstance(e, HandshakeFailed)]

        assert len(timeout_events) == 1
        assert not timeout_events[0].will_retry
        assert len(failed_events) == 1
        assert "timeout" in failed_events[0].reason.lower()


# =============================================================================
# Auth Failed No Retry Tests
# =============================================================================


class TestAuthFailedNoRetry:
    """Tests for auth failed errors not being retried."""

    def test_auth_failed_does_not_retry(
        self,
        client_connection: QASPConnection,
    ) -> None:
        """AUTH_FAILED errors are not retryable."""
        assert not client_connection.should_retry(HandshakeErrorType.AUTH_FAILED)

    def test_should_retry_returns_false_for_auth_failed(
        self,
        client_connection: QASPConnection,
    ) -> None:
        """should_retry returns False for AUTH_FAILED even with retries remaining."""
        # Still have all retries available
        assert client_connection.retry_count == 0

        # But auth failed should not retry
        assert not client_connection.should_retry(HandshakeErrorType.AUTH_FAILED)

    def test_kem_failed_does_not_retry(
        self,
        client_connection: QASPConnection,
    ) -> None:
        """KEM_FAILED errors are not retryable."""
        assert not client_connection.should_retry(HandshakeErrorType.KEM_FAILED)


# =============================================================================
# Handle Timeout Tests
# =============================================================================


class TestHandleTimeout:
    """Tests for handle_timeout method."""

    def test_handle_timeout_emits_timeout_event(
        self,
        client_connection: QASPConnection,
    ) -> None:
        """handle_timeout emits HandshakeTimeout event."""
        client_connection.initiate_handshake()
        events = client_connection.handle_timeout()

        timeout_events = [e for e in events if isinstance(e, HandshakeTimeout)]
        assert len(timeout_events) == 1

        event = timeout_events[0]
        assert event.timeout_ms == 1000
        assert event.retry_count == 0
        assert event.will_retry is True

    def test_handle_timeout_prepares_retry(
        self,
        client_connection: QASPConnection,
    ) -> None:
        """handle_timeout prepares for retry when appropriate."""
        client_connection.initiate_handshake()
        client_connection.handle_timeout()

        # Retry count should be incremented
        assert client_connection.retry_count == 1
        # Timeout should be backed off
        assert client_connection.get_current_timeout() == 2000

    def test_handle_timeout_fails_after_max_retries(
        self,
        client_connection: QASPConnection,
    ) -> None:
        """handle_timeout emits failure after max retries."""
        client_connection.initiate_handshake()

        # Exhaust retries
        for _ in range(3):
            client_connection.prepare_retry()

        events = client_connection.handle_timeout()

        # Should include both timeout and failed events
        timeout_events = [e for e in events if isinstance(e, HandshakeTimeout)]
        failed_events = [e for e in events if isinstance(e, HandshakeFailed)]

        assert len(timeout_events) == 1
        assert timeout_events[0].will_retry is False
        assert len(failed_events) == 1


# =============================================================================
# Connection Reset Tests
# =============================================================================


class TestConnectionReset:
    """Tests for connection reset clearing retry state."""

    def test_reset_clears_retry_count(
        self,
        client_connection: QASPConnection,
    ) -> None:
        """reset() clears the retry count."""
        client_connection.prepare_retry()
        client_connection.prepare_retry()
        assert client_connection.retry_count == 2

        client_connection.reset()
        assert client_connection.retry_count == 0

    def test_reset_restores_initial_timeout(
        self,
        client_connection: QASPConnection,
    ) -> None:
        """reset() restores the initial timeout value."""
        # Apply backoff
        client_connection.prepare_retry()
        client_connection.prepare_retry()
        assert client_connection.get_current_timeout() == 4000

        client_connection.reset()
        assert client_connection.get_current_timeout() == 1000
