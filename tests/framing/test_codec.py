"""Property-based tests for CBOR encoding and framing.

This module uses Hypothesis to verify CBOR roundtrip properties
for all QASP message types.
"""

from __future__ import annotations

import struct

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from qasp.framing import (
    FRAME_MAGIC,
    FRAME_VERSION,
    HEADER_SIZE,
    HMAC_SIZE,
    FramingError,
    decode,
    decode_frame,
    encode,
    encode_frame,
)
from qasp.framing.messages import (
    Alert,
    ApplicationData,
    ChannelClose,
    ChannelOpen,
    ClientAuth,
    ClientHello,
    DisputeEvidence,
    DisputeOpen,
    DisputeVerdict,
    Message,
    MeterAck,
    MeterReport,
    PriceRequest,
    ResourceDeny,
    ResourceGrant,
    ResourceRelease,
    ResourceRequest,
    ResourceSuspend,
    RevocationNotice,
    ServerHello,
    TokenRevocation,
)

# =============================================================================
# Hypothesis Strategies for Message Types
# =============================================================================

# Basic strategies
safe_bytes = st.binary(max_size=1024)
safe_text = st.text(max_size=256, alphabet=st.characters(blacklist_categories=["Cs"]))
safe_int = st.integers(min_value=0, max_value=2**32 - 1)
protocol_version = st.tuples(st.integers(0, 255), st.integers(0, 255))
cipher_suites = st.tuples(st.integers(0, 255))


# Strategies for each message type
@st.composite
def client_hello_strategy(draw: st.DrawFn) -> ClientHello:
    """Generate arbitrary ClientHello messages."""
    return ClientHello(
        protocol_version=draw(protocol_version),
        client_random=draw(safe_bytes),
        kem_public_key=draw(safe_bytes),
        sig_public_key=draw(safe_bytes),
        cipher_suites=draw(cipher_suites),
        extensions=draw(safe_bytes),
    )


@st.composite
def server_hello_strategy(draw: st.DrawFn) -> ServerHello:
    """Generate arbitrary ServerHello messages."""
    return ServerHello(
        protocol_version=draw(protocol_version),
        server_random=draw(safe_bytes),
        kem_ciphertext=draw(safe_bytes),
        kem_public_key=draw(safe_bytes),
        sig_public_key=draw(safe_bytes),
        selected_cipher_suite=draw(st.integers(0, 255)),
        signature=draw(safe_bytes),
        extensions=draw(safe_bytes),
    )


@st.composite
def client_auth_strategy(draw: st.DrawFn) -> ClientAuth:
    """Generate arbitrary ClientAuth messages."""
    return ClientAuth(
        kem_ciphertext=draw(safe_bytes),
        signature=draw(safe_bytes),
        certificate=draw(safe_bytes),
    )


@st.composite
def application_data_strategy(draw: st.DrawFn) -> ApplicationData:
    """Generate arbitrary ApplicationData messages."""
    return ApplicationData(
        encrypted_data=draw(safe_bytes),
        sequence_number=draw(safe_int),
    )


@st.composite
def token_revocation_strategy(draw: st.DrawFn) -> TokenRevocation:
    """Generate arbitrary TokenRevocation messages."""
    return TokenRevocation(
        token_id=draw(safe_bytes),
        revocation_time=draw(safe_int),
        reason=draw(safe_int),
        signature=draw(safe_bytes),
    )


@st.composite
def revocation_notice_strategy(draw: st.DrawFn) -> RevocationNotice:
    """Generate arbitrary RevocationNotice messages."""
    return RevocationNotice(
        token_id=draw(safe_bytes),
        revocation_time=draw(safe_int),
        issuer_id=draw(safe_bytes),
        signature=draw(safe_bytes),
    )


@st.composite
def resource_request_strategy(draw: st.DrawFn) -> ResourceRequest:
    """Generate arbitrary ResourceRequest messages."""
    return ResourceRequest(
        request_id=draw(safe_bytes),
        resource_type=draw(safe_text),
        resource_id=draw(safe_bytes),
        permissions=draw(safe_int),
        duration=draw(safe_int),
        payment_offer=draw(safe_bytes),
    )


@st.composite
def resource_grant_strategy(draw: st.DrawFn) -> ResourceGrant:
    """Generate arbitrary ResourceGrant messages."""
    return ResourceGrant(
        request_id=draw(safe_bytes),
        token=draw(safe_bytes),
        granted_permissions=draw(safe_int),
        expiration=draw(safe_int),
        meter_id=draw(safe_bytes),
    )


@st.composite
def meter_ack_strategy(draw: st.DrawFn) -> MeterAck:
    """Generate arbitrary MeterAck messages."""
    return MeterAck(
        meter_id=draw(safe_bytes),
        acked_sequence=draw(safe_int),
        acked_usage=draw(safe_int),
        signature=draw(safe_bytes),
    )


@st.composite
def resource_suspend_strategy(draw: st.DrawFn) -> ResourceSuspend:
    """Generate arbitrary ResourceSuspend messages."""
    return ResourceSuspend(
        token_id=draw(safe_bytes),
        reason=draw(safe_int),
        resume_time=draw(safe_int),
    )


@st.composite
def resource_deny_strategy(draw: st.DrawFn) -> ResourceDeny:
    """Generate arbitrary ResourceDeny messages."""
    return ResourceDeny(
        request_id=draw(safe_bytes),
        reason=draw(safe_int),
        message=draw(safe_text),
        retry_after=draw(safe_int),
    )


@st.composite
def resource_release_strategy(draw: st.DrawFn) -> ResourceRelease:
    """Generate arbitrary ResourceRelease messages."""
    return ResourceRelease(
        token_id=draw(safe_bytes),
        final_usage=draw(safe_int),
        signature=draw(safe_bytes),
    )


@st.composite
def dispute_open_strategy(draw: st.DrawFn) -> DisputeOpen:
    """Generate arbitrary DisputeOpen messages."""
    return DisputeOpen(
        dispute_id=draw(safe_bytes),
        token_id=draw(safe_bytes),
        dispute_type=draw(safe_int),
        claimed_value=draw(safe_int),
        evidence_hash=draw(safe_bytes),
    )


@st.composite
def dispute_evidence_strategy(draw: st.DrawFn) -> DisputeEvidence:
    """Generate arbitrary DisputeEvidence messages."""
    return DisputeEvidence(
        dispute_id=draw(safe_bytes),
        evidence_type=draw(safe_int),
        evidence_data=draw(safe_bytes),
        signature=draw(safe_bytes),
    )


@st.composite
def dispute_verdict_strategy(draw: st.DrawFn) -> DisputeVerdict:
    """Generate arbitrary DisputeVerdict messages."""
    return DisputeVerdict(
        dispute_id=draw(safe_bytes),
        verdict=draw(safe_int),
        awarded_value=draw(safe_int),
        arbiter_id=draw(safe_bytes),
        signature=draw(safe_bytes),
    )


@st.composite
def meter_report_strategy(draw: st.DrawFn) -> MeterReport:
    """Generate arbitrary MeterReport messages."""
    return MeterReport(
        meter_id=draw(safe_bytes),
        sequence_number=draw(safe_int),
        usage_count=draw(safe_int),
        usage_bytes=draw(safe_int),
        timestamp=draw(safe_int),
        signature=draw(safe_bytes),
    )


@st.composite
def channel_open_strategy(draw: st.DrawFn) -> ChannelOpen:
    """Generate arbitrary ChannelOpen messages."""
    return ChannelOpen(
        channel_id=draw(safe_bytes),
        channel_type=draw(safe_int),
        initial_balance=draw(safe_int),
        peer_id=draw(safe_bytes),
        timeout=draw(safe_int),
    )


@st.composite
def channel_close_strategy(draw: st.DrawFn) -> ChannelClose:
    """Generate arbitrary ChannelClose messages."""
    return ChannelClose(
        channel_id=draw(safe_bytes),
        final_balance_a=draw(safe_int),
        final_balance_b=draw(safe_int),
        close_reason=draw(safe_int),
        signatures=draw(st.tuples(safe_bytes, safe_bytes)),
    )


@st.composite
def price_request_strategy(draw: st.DrawFn) -> PriceRequest:
    """Generate arbitrary PriceRequest messages."""
    return PriceRequest(
        resource_type=draw(safe_text),
        resource_id=draw(safe_bytes),
        quantity=draw(safe_int),
        duration=draw(safe_int),
    )


@st.composite
def alert_strategy(draw: st.DrawFn) -> Alert:
    """Generate arbitrary Alert messages."""
    return Alert(
        level=draw(st.integers(0, 2)),
        description=draw(safe_int),
        message=draw(safe_text),
        related_message_type=draw(st.integers(0, 255)),
    )


# Combined strategy for any message
any_message = st.one_of(
    client_hello_strategy(),
    server_hello_strategy(),
    client_auth_strategy(),
    application_data_strategy(),
    token_revocation_strategy(),
    revocation_notice_strategy(),
    resource_request_strategy(),
    resource_grant_strategy(),
    meter_ack_strategy(),
    resource_suspend_strategy(),
    resource_deny_strategy(),
    resource_release_strategy(),
    dispute_open_strategy(),
    dispute_evidence_strategy(),
    dispute_verdict_strategy(),
    meter_report_strategy(),
    channel_open_strategy(),
    channel_close_strategy(),
    price_request_strategy(),
    alert_strategy(),
)


# =============================================================================
# CBOR Encode/Decode Roundtrip Tests (without framing)
# =============================================================================


class TestCBORRoundtrip:
    """Property tests for raw CBOR encode/decode."""

    @given(msg=client_hello_strategy())
    def test_client_hello_roundtrip(self, msg: ClientHello) -> None:
        """ClientHello encodes and decodes correctly."""
        encoded = encode(msg)
        decoded = decode(encoded)
        assert isinstance(decoded, dict)
        assert decoded["client_random"] == msg.client_random
        assert decoded["kem_public_key"] == msg.kem_public_key
        assert decoded["sig_public_key"] == msg.sig_public_key
        assert tuple(decoded["protocol_version"]) == msg.protocol_version
        assert tuple(decoded["cipher_suites"]) == msg.cipher_suites
        assert decoded["extensions"] == msg.extensions

    @given(msg=server_hello_strategy())
    def test_server_hello_roundtrip(self, msg: ServerHello) -> None:
        """ServerHello encodes and decodes correctly."""
        encoded = encode(msg)
        decoded = decode(encoded)
        assert isinstance(decoded, dict)
        assert decoded["server_random"] == msg.server_random
        assert tuple(decoded["protocol_version"]) == msg.protocol_version

    @given(msg=client_auth_strategy())
    def test_client_auth_roundtrip(self, msg: ClientAuth) -> None:
        """ClientAuth encodes and decodes correctly."""
        encoded = encode(msg)
        decoded = decode(encoded)
        assert isinstance(decoded, dict)
        assert decoded["kem_ciphertext"] == msg.kem_ciphertext
        assert decoded["signature"] == msg.signature
        assert decoded["certificate"] == msg.certificate

    @given(msg=application_data_strategy())
    def test_application_data_roundtrip(self, msg: ApplicationData) -> None:
        """ApplicationData encodes and decodes correctly."""
        encoded = encode(msg)
        decoded = decode(encoded)
        assert isinstance(decoded, dict)
        assert decoded["encrypted_data"] == msg.encrypted_data
        assert decoded["sequence_number"] == msg.sequence_number

    @given(msg=alert_strategy())
    def test_alert_roundtrip(self, msg: Alert) -> None:
        """Alert encodes and decodes correctly."""
        encoded = encode(msg)
        decoded = decode(encoded)
        assert isinstance(decoded, dict)
        assert decoded["level"] == msg.level
        assert decoded["description"] == msg.description
        assert decoded["message"] == msg.message
        assert decoded["related_message_type"] == msg.related_message_type


# =============================================================================
# Frame Encode/Decode Roundtrip Tests (with HMAC)
# =============================================================================


# HMAC key strategy
hmac_key = st.binary(min_size=32, max_size=64)


class TestFrameRoundtrip:
    """Property tests for framed encode/decode with HMAC."""

    @given(msg=client_hello_strategy(), key=hmac_key)
    def test_client_hello_frame_roundtrip(self, msg: ClientHello, key: bytes) -> None:
        """ClientHello frame encodes and decodes correctly."""
        frame = encode_frame(msg, key)
        decoded, consumed = decode_frame(frame, key)
        assert consumed == len(frame)
        assert isinstance(decoded, ClientHello)
        assert decoded == msg

    @given(msg=server_hello_strategy(), key=hmac_key)
    def test_server_hello_frame_roundtrip(self, msg: ServerHello, key: bytes) -> None:
        """ServerHello frame encodes and decodes correctly."""
        frame = encode_frame(msg, key)
        decoded, consumed = decode_frame(frame, key)
        assert consumed == len(frame)
        assert isinstance(decoded, ServerHello)
        assert decoded == msg

    @given(msg=client_auth_strategy(), key=hmac_key)
    def test_client_auth_frame_roundtrip(self, msg: ClientAuth, key: bytes) -> None:
        """ClientAuth frame encodes and decodes correctly."""
        frame = encode_frame(msg, key)
        decoded, consumed = decode_frame(frame, key)
        assert consumed == len(frame)
        assert isinstance(decoded, ClientAuth)
        assert decoded == msg

    @given(msg=application_data_strategy(), key=hmac_key)
    def test_application_data_frame_roundtrip(
        self, msg: ApplicationData, key: bytes
    ) -> None:
        """ApplicationData frame encodes and decodes correctly."""
        frame = encode_frame(msg, key)
        decoded, consumed = decode_frame(frame, key)
        assert consumed == len(frame)
        assert isinstance(decoded, ApplicationData)
        assert decoded == msg

    @given(msg=token_revocation_strategy(), key=hmac_key)
    def test_token_revocation_frame_roundtrip(
        self, msg: TokenRevocation, key: bytes
    ) -> None:
        """TokenRevocation frame encodes and decodes correctly."""
        frame = encode_frame(msg, key)
        decoded, consumed = decode_frame(frame, key)
        assert consumed == len(frame)
        assert isinstance(decoded, TokenRevocation)
        assert decoded == msg

    @given(msg=revocation_notice_strategy(), key=hmac_key)
    def test_revocation_notice_frame_roundtrip(
        self, msg: RevocationNotice, key: bytes
    ) -> None:
        """RevocationNotice frame encodes and decodes correctly."""
        frame = encode_frame(msg, key)
        decoded, consumed = decode_frame(frame, key)
        assert consumed == len(frame)
        assert isinstance(decoded, RevocationNotice)
        assert decoded == msg

    @given(msg=resource_request_strategy(), key=hmac_key)
    def test_resource_request_frame_roundtrip(
        self, msg: ResourceRequest, key: bytes
    ) -> None:
        """ResourceRequest frame encodes and decodes correctly."""
        frame = encode_frame(msg, key)
        decoded, consumed = decode_frame(frame, key)
        assert consumed == len(frame)
        assert isinstance(decoded, ResourceRequest)
        assert decoded == msg

    @given(msg=resource_grant_strategy(), key=hmac_key)
    def test_resource_grant_frame_roundtrip(
        self, msg: ResourceGrant, key: bytes
    ) -> None:
        """ResourceGrant frame encodes and decodes correctly."""
        frame = encode_frame(msg, key)
        decoded, consumed = decode_frame(frame, key)
        assert consumed == len(frame)
        assert isinstance(decoded, ResourceGrant)
        assert decoded == msg

    @given(msg=meter_ack_strategy(), key=hmac_key)
    def test_meter_ack_frame_roundtrip(self, msg: MeterAck, key: bytes) -> None:
        """MeterAck frame encodes and decodes correctly."""
        frame = encode_frame(msg, key)
        decoded, consumed = decode_frame(frame, key)
        assert consumed == len(frame)
        assert isinstance(decoded, MeterAck)
        assert decoded == msg

    @given(msg=resource_suspend_strategy(), key=hmac_key)
    def test_resource_suspend_frame_roundtrip(
        self, msg: ResourceSuspend, key: bytes
    ) -> None:
        """ResourceSuspend frame encodes and decodes correctly."""
        frame = encode_frame(msg, key)
        decoded, consumed = decode_frame(frame, key)
        assert consumed == len(frame)
        assert isinstance(decoded, ResourceSuspend)
        assert decoded == msg

    @given(msg=resource_deny_strategy(), key=hmac_key)
    def test_resource_deny_frame_roundtrip(
        self, msg: ResourceDeny, key: bytes
    ) -> None:
        """ResourceDeny frame encodes and decodes correctly."""
        frame = encode_frame(msg, key)
        decoded, consumed = decode_frame(frame, key)
        assert consumed == len(frame)
        assert isinstance(decoded, ResourceDeny)
        assert decoded == msg

    @given(msg=resource_release_strategy(), key=hmac_key)
    def test_resource_release_frame_roundtrip(
        self, msg: ResourceRelease, key: bytes
    ) -> None:
        """ResourceRelease frame encodes and decodes correctly."""
        frame = encode_frame(msg, key)
        decoded, consumed = decode_frame(frame, key)
        assert consumed == len(frame)
        assert isinstance(decoded, ResourceRelease)
        assert decoded == msg

    @given(msg=dispute_open_strategy(), key=hmac_key)
    def test_dispute_open_frame_roundtrip(
        self, msg: DisputeOpen, key: bytes
    ) -> None:
        """DisputeOpen frame encodes and decodes correctly."""
        frame = encode_frame(msg, key)
        decoded, consumed = decode_frame(frame, key)
        assert consumed == len(frame)
        assert isinstance(decoded, DisputeOpen)
        assert decoded == msg

    @given(msg=dispute_evidence_strategy(), key=hmac_key)
    def test_dispute_evidence_frame_roundtrip(
        self, msg: DisputeEvidence, key: bytes
    ) -> None:
        """DisputeEvidence frame encodes and decodes correctly."""
        frame = encode_frame(msg, key)
        decoded, consumed = decode_frame(frame, key)
        assert consumed == len(frame)
        assert isinstance(decoded, DisputeEvidence)
        assert decoded == msg

    @given(msg=dispute_verdict_strategy(), key=hmac_key)
    def test_dispute_verdict_frame_roundtrip(
        self, msg: DisputeVerdict, key: bytes
    ) -> None:
        """DisputeVerdict frame encodes and decodes correctly."""
        frame = encode_frame(msg, key)
        decoded, consumed = decode_frame(frame, key)
        assert consumed == len(frame)
        assert isinstance(decoded, DisputeVerdict)
        assert decoded == msg

    @given(msg=meter_report_strategy(), key=hmac_key)
    def test_meter_report_frame_roundtrip(
        self, msg: MeterReport, key: bytes
    ) -> None:
        """MeterReport frame encodes and decodes correctly."""
        frame = encode_frame(msg, key)
        decoded, consumed = decode_frame(frame, key)
        assert consumed == len(frame)
        assert isinstance(decoded, MeterReport)
        assert decoded == msg

    @given(msg=channel_open_strategy(), key=hmac_key)
    def test_channel_open_frame_roundtrip(
        self, msg: ChannelOpen, key: bytes
    ) -> None:
        """ChannelOpen frame encodes and decodes correctly."""
        frame = encode_frame(msg, key)
        decoded, consumed = decode_frame(frame, key)
        assert consumed == len(frame)
        assert isinstance(decoded, ChannelOpen)
        assert decoded == msg

    @given(msg=channel_close_strategy(), key=hmac_key)
    def test_channel_close_frame_roundtrip(
        self, msg: ChannelClose, key: bytes
    ) -> None:
        """ChannelClose frame encodes and decodes correctly."""
        frame = encode_frame(msg, key)
        decoded, consumed = decode_frame(frame, key)
        assert consumed == len(frame)
        assert isinstance(decoded, ChannelClose)
        assert decoded == msg

    @given(msg=price_request_strategy(), key=hmac_key)
    def test_price_request_frame_roundtrip(
        self, msg: PriceRequest, key: bytes
    ) -> None:
        """PriceRequest frame encodes and decodes correctly."""
        frame = encode_frame(msg, key)
        decoded, consumed = decode_frame(frame, key)
        assert consumed == len(frame)
        assert isinstance(decoded, PriceRequest)
        assert decoded == msg

    @given(msg=alert_strategy(), key=hmac_key)
    def test_alert_frame_roundtrip(self, msg: Alert, key: bytes) -> None:
        """Alert frame encodes and decodes correctly."""
        frame = encode_frame(msg, key)
        decoded, consumed = decode_frame(frame, key)
        assert consumed == len(frame)
        assert isinstance(decoded, Alert)
        assert decoded == msg

    @given(msg=any_message, key=hmac_key)
    def test_any_message_frame_roundtrip(self, msg: Message, key: bytes) -> None:
        """Any message type frame encodes and decodes correctly."""
        frame = encode_frame(msg, key)
        decoded, consumed = decode_frame(frame, key)
        assert consumed == len(frame)
        assert type(decoded) is type(msg)
        assert decoded == msg


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestFrameErrors:
    """Tests for frame error handling."""

    def test_invalid_cbor_raises(self) -> None:
        """Invalid CBOR data raises FramingError."""
        # 0x9f is an indefinite array start that requires a break marker
        # Without more data, cbor2 raises a decode error
        with pytest.raises(FramingError, match="CBOR decode error"):
            decode(b"\x9f")

    def test_truncated_header_raises(self) -> None:
        """Truncated header raises FramingError."""
        key = b"x" * 32
        with pytest.raises(FramingError, match="Insufficient data"):
            decode_frame(b"QA\x01", key)

    def test_invalid_magic_raises(self) -> None:
        """Invalid magic bytes raise FramingError."""
        key = b"x" * 32
        # Wrong magic bytes
        bad_frame = b"XX\x01\x01\x00\x00\x00\x00"
        with pytest.raises(FramingError, match="Invalid magic"):
            decode_frame(bad_frame, key)

    def test_invalid_version_raises(self) -> None:
        """Unsupported version raises FramingError."""
        key = b"x" * 32
        # Wrong version (0x99)
        bad_frame = FRAME_MAGIC + b"\x99\x01\x00\x00\x00\x00"
        with pytest.raises(FramingError, match="Unsupported version"):
            decode_frame(bad_frame, key)

    def test_unknown_message_type_raises(self) -> None:
        """Unknown message type raises FramingError."""
        key = b"x" * 32
        # Message type 0xFF doesn't exist
        bad_frame = FRAME_MAGIC + b"\x01\xff\x00\x00\x00\x00"
        with pytest.raises(FramingError, match="Unknown message type"):
            decode_frame(bad_frame, key)

    def test_truncated_frame_raises(self) -> None:
        """Truncated frame (missing payload/HMAC) raises FramingError."""
        key = b"x" * 32
        # Valid header but claims 100 bytes payload that doesn't exist
        header = FRAME_MAGIC + b"\x01\x01" + struct.pack(">I", 100)
        with pytest.raises(FramingError, match="Incomplete frame"):
            decode_frame(header, key)

    @given(msg=any_message, key=hmac_key)
    def test_corrupted_hmac_raises(self, msg: Message, key: bytes) -> None:
        """Corrupted HMAC raises FramingError."""
        frame = encode_frame(msg, key)
        # Corrupt the last byte of the HMAC
        corrupted = frame[:-1] + bytes([frame[-1] ^ 0xFF])
        with pytest.raises(FramingError, match="HMAC verification failed"):
            decode_frame(corrupted, key)

    @given(msg=any_message, key=hmac_key, wrong_key=hmac_key)
    def test_wrong_key_raises(
        self, msg: Message, key: bytes, wrong_key: bytes
    ) -> None:
        """Wrong HMAC key raises FramingError."""
        assume(key != wrong_key)
        frame = encode_frame(msg, key)
        with pytest.raises(FramingError, match="HMAC verification failed"):
            decode_frame(frame, wrong_key)

    @given(msg=any_message, key=hmac_key, extra=st.binary(min_size=1, max_size=100))
    def test_extra_data_after_frame(
        self, msg: Message, key: bytes, extra: bytes
    ) -> None:
        """Extra data after frame is handled correctly."""
        frame = encode_frame(msg, key)
        frame_with_extra = frame + extra
        decoded, consumed = decode_frame(frame_with_extra, key)
        assert consumed == len(frame)
        assert decoded == msg


# =============================================================================
# Frame Structure Tests
# =============================================================================


class TestFrameStructure:
    """Tests for frame structure properties."""

    @given(msg=any_message, key=hmac_key)
    def test_frame_has_correct_header(self, msg: Message, key: bytes) -> None:
        """Frame has correct header structure."""
        frame = encode_frame(msg, key)
        assert frame[:2] == FRAME_MAGIC
        assert frame[2] == FRAME_VERSION
        assert frame[3] == msg.message_type

    @given(msg=any_message, key=hmac_key)
    def test_frame_has_correct_length(self, msg: Message, key: bytes) -> None:
        """Frame length field matches actual payload length."""
        frame = encode_frame(msg, key)
        length_field = struct.unpack(">I", frame[4:8])[0]
        expected_payload_len = len(frame) - HEADER_SIZE - HMAC_SIZE
        assert length_field == expected_payload_len

    @given(msg=any_message, key=hmac_key)
    def test_frame_minimum_size(self, msg: Message, key: bytes) -> None:
        """Frame is at least header + HMAC size."""
        frame = encode_frame(msg, key)
        assert len(frame) >= HEADER_SIZE + HMAC_SIZE
