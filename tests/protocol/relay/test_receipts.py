"""Tests for RelayReceipt and RelayReceiptChain (PRD §7.2)."""

import hmac
import hashlib

import pytest

from qasp.protocol.relay.receipts import (
    RelayReceipt,
    RelayReceiptChain,
    RelayReceiptChainError,
    build_session_summary,
    hash_payload,
)


def _make_receipt(
    seq: int,
    prev_hash: bytes,
    key: bytes,
    *,
    session_id: bytes = b"\x01" * 16,
    direction: int = 0x00,
    msg_hash: bytes | None = None,
    timestamp: int = 1_800_000_000,
    cumulative_msgs: int | None = None,
    cumulative_bytes: int = 100,
    cumulative_cost: int = 0,
) -> RelayReceipt:
    return RelayReceipt.new(
        session_id=session_id,
        seq=seq,
        msg_hash=msg_hash if msg_hash is not None else hashlib.sha384(f"msg{seq}".encode()).digest(),
        timestamp=timestamp,
        direction=direction,
        cumulative_msgs=cumulative_msgs if cumulative_msgs is not None else seq,
        cumulative_bytes=cumulative_bytes,
        cumulative_cost=cumulative_cost,
        prev_hash=prev_hash,
        receipt_key=key,
    )


class TestHashPayload:
    def test_returns_sha384_digest(self):
        out = hash_payload(b"hello")
        assert out == hashlib.sha384(b"hello").digest()
        assert len(out) == 48


class TestRelayReceiptSigning:
    def test_relay_sig_is_hmac_sha256_over_signable_bytes(self):
        key = b"k" * 32
        r = _make_receipt(1, b"\x00" * 48, key)
        expected = hmac.new(key, r.signable_bytes(), hashlib.sha256).digest()
        assert r.relay_sig == expected

    def test_compute_hash_is_sha384(self):
        r = _make_receipt(1, b"\x00" * 48, b"k" * 32)
        assert r.compute_hash() == hashlib.sha384(r.to_cbor()).digest()

    def test_round_trip_cbor(self):
        r = _make_receipt(1, b"\x00" * 48, b"k" * 32)
        r2 = RelayReceipt.from_cbor(r.to_cbor())
        assert r2 == r


class TestRelayReceiptChain:
    def test_first_receipt_requires_empty_prev_hash(self):
        chain = RelayReceiptChain()
        bad = _make_receipt(1, b"\xff" * 48, b"k" * 32)
        with pytest.raises(RelayReceiptChainError):
            chain.append(bad)

    def test_valid_chain_accepts_receipts(self):
        key = b"k" * 32
        chain = RelayReceiptChain()
        r1 = _make_receipt(1, b"", key)
        chain.append(r1)
        r2 = _make_receipt(2, r1.compute_hash(), key)
        chain.append(r2)
        assert len(chain) == 2

    def test_broken_chain_rejected(self):
        key = b"k" * 32
        chain = RelayReceiptChain()
        chain.append(_make_receipt(1, b"", key))
        bad = _make_receipt(2, b"\xde\xad" * 24, key)
        with pytest.raises(RelayReceiptChainError):
            chain.append(bad)

    def test_tip_returns_last_hash(self):
        key = b"k" * 32
        chain = RelayReceiptChain()
        assert chain.tip == b""
        r1 = _make_receipt(1, b"", key)
        chain.append(r1)
        assert chain.tip == r1.compute_hash()

    def test_verify_detects_bad_hmac(self):
        key = b"k" * 32
        chain = RelayReceiptChain()
        chain.append(_make_receipt(1, b"", key))
        assert chain.verify(key) is True
        assert chain.verify(b"wrong" * 7) is False


class TestSessionSummary:
    def test_summary_captures_chain_tip_and_counts(self):
        key = b"k" * 32
        chain = RelayReceiptChain()
        r1 = _make_receipt(1, b"", key)
        chain.append(r1)
        r2 = _make_receipt(2, r1.compute_hash(), key)
        chain.append(r2)

        # Use a dummy signer for the test — ML-DSA-65 path is exercised in integration.
        captured = {}

        def dummy_sign(private_key: bytes, data: bytes) -> bytes:
            captured["key"] = private_key
            captured["data"] = data
            return b"sig-" + hashlib.sha256(data).digest()

        summary = build_session_summary(
            chain=chain,
            session_id=b"\x01" * 16,
            signing_key=b"pk" * 16,
            issuer="did:qasp:relay",
            signer=dummy_sign,
        )
        assert summary.sequence_number == 2
        assert summary.total_units == 2  # one per receipt
        assert summary.issuer == "did:qasp:relay"
        assert summary.signature.startswith(b"sig-")
        assert captured["key"] == b"pk" * 16
