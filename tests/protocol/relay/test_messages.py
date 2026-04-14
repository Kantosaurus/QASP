"""CBOR round-trip tests for the seven CapFlow relay message types (PRD §5)."""

import pytest

from qasp.framing.messages import MessageType
from qasp.protocol.relay.messages import (
    RelayData,
    RelayMessageType,
    RelaySessionAccept,
    RelaySessionClose,
    RelaySessionDeny,
    RelaySessionGrant,
    RelaySessionNotify,
    RelaySessionParams,
    RelaySessionRequest,
    decode_relay_frame,
)


class TestMessageTypeRegistration:
    """Relay message type IDs match the top-level MessageType enum (PRD Table 2)."""

    def test_ids_match_framing_enum(self):
        assert RelayMessageType.SESSION_REQUEST == MessageType.RELAY_SESSION_REQUEST == 0x20
        assert RelayMessageType.SESSION_GRANT == MessageType.RELAY_SESSION_GRANT == 0x21
        assert RelayMessageType.SESSION_DENY == MessageType.RELAY_SESSION_DENY == 0x22
        assert RelayMessageType.SESSION_NOTIFY == MessageType.RELAY_SESSION_NOTIFY == 0x23
        assert RelayMessageType.SESSION_ACCEPT == MessageType.RELAY_SESSION_ACCEPT == 0x24
        assert RelayMessageType.DATA == MessageType.RELAY_DATA == 0x25
        assert RelayMessageType.SESSION_CLOSE == MessageType.RELAY_SESSION_CLOSE == 0x26


class TestSessionRequestRoundTrip:
    def test_full_fields(self):
        params = RelaySessionParams(
            max_messages=100,
            max_bytes=10_000,
            max_rate=(50, 1),
            duration_sec=60,
            purpose="translate",
        )
        msg = RelaySessionRequest(
            target_agent="did:qasp:bob",
            capability_token=b"\xca\xb0" * 32,
            session_params=params,
            ephemeral_pk=b"\xe0" * 32,
            nonce=b"\xaa" * 32,
        )
        decoded = RelaySessionRequest.from_cbor(msg.to_cbor())
        assert decoded == msg

    def test_optional_fields_null(self):
        params = RelaySessionParams(
            max_messages=None, max_bytes=None, max_rate=None, duration_sec=10, purpose=None,
        )
        msg = RelaySessionRequest(
            target_agent="did:qasp:bob",
            capability_token=b"x",
            session_params=params,
            ephemeral_pk=None,
            nonce=b"\x00" * 32,
        )
        decoded = RelaySessionRequest.from_cbor(msg.to_cbor())
        assert decoded == msg


class TestSessionGrantRoundTrip:
    def test_round_trip(self):
        msg = RelaySessionGrant(
            session_id=b"\x01" * 16,
            scm=b"\x02" * 32,
            negotiated_params=RelaySessionParams(100, 1000, (10, 1), 60, "p"),
            attenuated_token_for_target=b"\xaa" * 16,
            epoch=7,
            expires_at=1_800_000_000,
        )
        assert RelaySessionGrant.from_cbor(msg.to_cbor()) == msg


class TestSessionDenyRoundTrip:
    def test_round_trip(self):
        msg = RelaySessionDeny(
            nonce=b"\x00" * 32,
            error_code=0x20,
            reason="target offline",
        )
        assert RelaySessionDeny.from_cbor(msg.to_cbor()) == msg


class TestSessionNotifyRoundTrip:
    def test_round_trip(self):
        msg = RelaySessionNotify(
            session_id=b"\x01" * 16,
            initiator_did="did:qasp:alice",
            attenuated_token=b"\xaa" * 16,
            negotiated_params=RelaySessionParams(10, 100, None, 30, None),
        )
        assert RelaySessionNotify.from_cbor(msg.to_cbor()) == msg


class TestSessionAcceptRoundTrip:
    def test_round_trip(self):
        msg = RelaySessionAccept(session_id=b"\x01" * 16, accepted=True)
        assert RelaySessionAccept.from_cbor(msg.to_cbor()) == msg

    def test_reject(self):
        msg = RelaySessionAccept(session_id=b"\x01" * 16, accepted=False)
        assert RelaySessionAccept.from_cbor(msg.to_cbor()) == msg


class TestRelayDataRoundTrip:
    def test_round_trip(self):
        msg = RelayData(
            session_id=b"\x01" * 16,
            scm=b"\x02" * 32,
            seq=7,
            payload=b"hello world",
            receipt_ack=b"\xcc" * 48,
        )
        assert RelayData.from_cbor(msg.to_cbor()) == msg

    def test_no_piggyback_receipt(self):
        msg = RelayData(
            session_id=b"\x01" * 16,
            scm=b"\x02" * 32,
            seq=7,
            payload=b"hi",
            receipt_ack=None,
        )
        assert RelayData.from_cbor(msg.to_cbor()) == msg


class TestSessionCloseRoundTrip:
    def test_round_trip(self):
        msg = RelaySessionClose(
            session_id=b"\x01" * 16, reason_code=0x23, reason_text="budget exhausted",
        )
        assert RelaySessionClose.from_cbor(msg.to_cbor()) == msg


class TestDecodeRelayFrame:
    """decode_relay_frame peeks msg_type and dispatches to the right class."""

    def test_dispatches_request(self):
        msg = RelaySessionRequest(
            target_agent="did:qasp:bob",
            capability_token=b"c",
            session_params=RelaySessionParams(None, None, None, 10, None),
            ephemeral_pk=None,
            nonce=b"\x00" * 32,
        )
        decoded = decode_relay_frame(msg.to_cbor())
        assert isinstance(decoded, RelaySessionRequest)
        assert decoded == msg

    def test_dispatches_data(self):
        msg = RelayData(
            session_id=b"\x01" * 16, scm=b"\x02" * 32, seq=1, payload=b"x", receipt_ack=None,
        )
        decoded = decode_relay_frame(msg.to_cbor())
        assert isinstance(decoded, RelayData)
        assert decoded == msg

    def test_rejects_unknown_msg_type(self):
        import cbor2
        bogus = cbor2.dumps({"msg_type": 0x99})
        with pytest.raises(ValueError, match="Unknown relay msg_type"):
            decode_relay_frame(bogus)

    def test_rejects_malformed_frame(self):
        with pytest.raises(ValueError):
            decode_relay_frame(b"\xff\xff\xff")
