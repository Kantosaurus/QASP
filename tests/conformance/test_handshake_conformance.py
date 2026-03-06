"""Conformance tests for the QASP-Shake handshake protocol.

Tests handshake success/failure per cipher suite, version mismatch,
upgrade-required, and timeout recovery.
"""

from __future__ import annotations

import pytest

from qasp.crypto import hybrid, signatures
from qasp.crypto.suites import (
    SUITE_CLASSICAL_COMPAT,
    SUITE_HYBRID_TRANSITION,
    SUITE_PQ_STRICT,
)
from qasp.protocol.connection import QASPConnection
from qasp.protocol.events import HandshakeComplete, HandshakeFailed
from qasp.protocol.handshake import HandshakeConfig, HandshakeErrorType
from qasp.protocol.states import ConnectionState

from .conftest import _complete_handshake, _make_connection_pair


# =============================================================================
# Per-Suite Handshake Success
# =============================================================================


class TestHandshakePerSuite:
    """Verify handshake succeeds for each cipher suite profile."""

    @pytest.mark.parametrize(
        "suite_id",
        [SUITE_PQ_STRICT, SUITE_HYBRID_TRANSITION, SUITE_CLASSICAL_COMPAT],
        ids=["PQ-Strict", "Hybrid-Transition", "Classical-Compat"],
    )
    def test_handshake_success(self, suite_id: int) -> None:
        client, server = _make_connection_pair(suite_id)
        _complete_handshake(client, server)

        assert client.state == ConnectionState.ESTABLISHED
        assert server.state == ConnectionState.ESTABLISHED
        assert client.session_key is not None
        assert server.session_key is not None
        assert client.session_key == server.session_key
        assert client.session_id is not None
        assert client.session_id == server.session_id

    @pytest.mark.parametrize(
        "suite_id",
        [SUITE_PQ_STRICT, SUITE_HYBRID_TRANSITION, SUITE_CLASSICAL_COMPAT],
        ids=["PQ-Strict", "Hybrid-Transition", "Classical-Compat"],
    )
    def test_bidirectional_data_after_handshake(self, suite_id: int) -> None:
        client, server = _make_connection_pair(suite_id)
        _complete_handshake(client, server)

        # Client -> Server
        client.send_data(b"hello from client")
        data = client.bytes_to_send()
        events = server.receive_bytes(data)
        data_events = [e for e in events if hasattr(e, "data")]
        assert len(data_events) == 1
        assert data_events[0].data == b"hello from client"

        # Server -> Client
        server.send_data(b"hello from server")
        data = server.bytes_to_send()
        events = client.receive_bytes(data)
        data_events = [e for e in events if hasattr(e, "data")]
        assert len(data_events) == 1
        assert data_events[0].data == b"hello from server"


# =============================================================================
# Version Mismatch
# =============================================================================


class TestVersionMismatch:
    """Verify version mismatch handling."""

    def test_client_wrong_version(self) -> None:
        client_kem = hybrid.generate_keypair()
        client_sig = signatures.generate_keypair()
        server_kem = hybrid.generate_keypair()
        server_sig = signatures.generate_keypair()

        hmac_key = b"\x00" * 32

        client_config = HandshakeConfig(
            protocol_version=(2, 0),
            supported_cipher_suites=(SUITE_HYBRID_TRANSITION,),
        )
        server_config = HandshakeConfig(
            protocol_version=(1, 0),
            supported_cipher_suites=(SUITE_HYBRID_TRANSITION,),
        )

        client = QASPConnection(
            kem_keypair=client_kem,
            sig_keypair=client_sig,
            is_client=True,
            hmac_key=hmac_key,
            config=client_config,
        )
        server = QASPConnection(
            kem_keypair=server_kem,
            sig_keypair=server_sig,
            is_client=False,
            hmac_key=hmac_key,
            config=server_config,
        )

        client.initiate_handshake()
        data = client.bytes_to_send()
        events = server.receive_bytes(data)

        failed_events = [e for e in events if isinstance(e, HandshakeFailed)]
        assert len(failed_events) >= 1
        assert server.state == ConnectionState.ERROR


# =============================================================================
# Upgrade Required
# =============================================================================


class TestUpgradeRequired:
    """Verify PQ-capable server rejects classical-only client."""

    def test_upgrade_required(self) -> None:
        client_kem = hybrid.generate_keypair()
        client_sig = signatures.generate_keypair()
        server_kem = hybrid.generate_keypair()
        server_sig = signatures.generate_keypair()

        hmac_key = b"\x00" * 32

        # Client only supports classical
        client_config = HandshakeConfig(
            supported_cipher_suites=(SUITE_CLASSICAL_COMPAT,),
            enable_hybrid=False,
        )
        # Server supports PQ
        server_config = HandshakeConfig(
            supported_cipher_suites=(SUITE_PQ_STRICT, SUITE_HYBRID_TRANSITION),
        )

        client = QASPConnection(
            kem_keypair=client_kem,
            sig_keypair=client_sig,
            is_client=True,
            hmac_key=hmac_key,
            config=client_config,
        )
        server = QASPConnection(
            kem_keypair=server_kem,
            sig_keypair=server_sig,
            is_client=False,
            hmac_key=hmac_key,
            config=server_config,
        )

        client.initiate_handshake()
        data = client.bytes_to_send()
        events = server.receive_bytes(data)

        failed_events = [e for e in events if isinstance(e, HandshakeFailed)]
        assert len(failed_events) >= 1
        assert server.state == ConnectionState.ERROR


# =============================================================================
# Timeout Recovery
# =============================================================================


class TestTimeoutRecovery:
    """Verify timeout and exponential backoff."""

    def test_timeout_triggers_backoff(self) -> None:
        client, _ = _make_connection_pair(SUITE_HYBRID_TRANSITION)
        client.initiate_handshake()

        initial_timeout = client.get_current_timeout()
        assert initial_timeout == 5000

        events = client.handle_timeout()
        assert len(events) >= 1
        assert client.retry_count == 1
        assert client.get_current_timeout() == 10000  # 5000 * 2.0

    def test_max_retries_exceeded(self) -> None:
        config = HandshakeConfig(
            supported_cipher_suites=(SUITE_HYBRID_TRANSITION,),
            max_retries=2,
        )
        client_kem = hybrid.generate_keypair()
        client_sig = signatures.generate_keypair()
        client = QASPConnection(
            kem_keypair=client_kem,
            sig_keypair=client_sig,
            is_client=True,
            hmac_key=b"\x00" * 32,
            config=config,
        )
        client.initiate_handshake()

        # Exhaust retries
        client.handle_timeout()
        client.handle_timeout()
        events = client.handle_timeout()

        failed = [e for e in events if isinstance(e, HandshakeFailed)]
        assert len(failed) >= 1
        assert client.state == ConnectionState.ERROR


# =============================================================================
# Suite Mismatch
# =============================================================================


class TestSuiteMismatch:
    """Verify cipher suite mismatch handling."""

    def test_no_common_suites(self) -> None:
        client_kem = hybrid.generate_keypair()
        client_sig = signatures.generate_keypair()
        server_kem = hybrid.generate_keypair()
        server_sig = signatures.generate_keypair()

        hmac_key = b"\x00" * 32

        # Disjoint suite sets (both classical to avoid upgrade_required)
        client_config = HandshakeConfig(
            supported_cipher_suites=(SUITE_CLASSICAL_COMPAT,),
            enable_hybrid=False,
        )
        server_config = HandshakeConfig(
            supported_cipher_suites=(SUITE_CLASSICAL_COMPAT,),
            enable_hybrid=False,
        )
        # Use PQ-Strict for client to create true mismatch
        client_config_pq = HandshakeConfig(
            supported_cipher_suites=(SUITE_PQ_STRICT,),
            enable_hybrid=False,
        )
        server_config_classical = HandshakeConfig(
            supported_cipher_suites=(SUITE_CLASSICAL_COMPAT,),
            enable_hybrid=False,
        )

        client = QASPConnection(
            kem_keypair=client_kem,
            sig_keypair=client_sig,
            is_client=True,
            hmac_key=hmac_key,
            config=client_config_pq,
        )
        server = QASPConnection(
            kem_keypair=server_kem,
            sig_keypair=server_sig,
            is_client=False,
            hmac_key=hmac_key,
            config=server_config_classical,
        )

        client.initiate_handshake()
        data = client.bytes_to_send()
        events = server.receive_bytes(data)

        # Server should reject - either suite mismatch or upgrade required
        failed_events = [e for e in events if isinstance(e, HandshakeFailed)]
        assert len(failed_events) >= 1
        assert server.state == ConnectionState.ERROR


# =============================================================================
# Connection Close
# =============================================================================


class TestConnectionClose:
    """Verify graceful connection close."""

    def test_graceful_close(self) -> None:
        client, server = _make_connection_pair(SUITE_HYBRID_TRANSITION)
        _complete_handshake(client, server)

        events = client.close("done")
        assert client.state == ConnectionState.CLOSED
        assert any(hasattr(e, "graceful") and e.graceful for e in events)
