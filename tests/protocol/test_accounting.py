"""Tests for usage metering and receipt chains."""

from __future__ import annotations

import pytest

from qasp.crypto.signatures import generate_keypair, verify
from qasp.protocol.accounting import (
    Meter,
    Receipt,
    ReceiptChain,
    ReceiptChainError,
)


# =============================================================================
# ML-DSA-65 Keypair Fixtures
# =============================================================================


@pytest.fixture
def signing_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh ML-DSA-65 keypair for receipt signing."""
    return generate_keypair()


@pytest.fixture
def signing_public_key(signing_keypair: tuple[bytes, bytes]) -> bytes:
    return signing_keypair[0]


@pytest.fixture
def signing_secret_key(signing_keypair: tuple[bytes, bytes]) -> bytes:
    return signing_keypair[1]


@pytest.fixture
def session_id() -> bytes:
    return b"test_session_id_"


@pytest.fixture
def meter(session_id: bytes) -> Meter:
    return Meter(
        session_id=session_id,
        meter_id=b"meter_001",
        issuer="did:qasp:provider",
    )


# =============================================================================
# TestUsageRecording
# =============================================================================


class TestUsageRecording:
    """Tests for Meter.record()."""

    def test_record_creates_usage_record(self, meter: Meter) -> None:
        """record() returns a UsageRecord."""
        rec = meter.record("compute", "execute", units=5)
        assert rec.resource == "compute"
        assert rec.operation == "execute"
        assert rec.units == 5

    def test_multiple_records(self, meter: Meter) -> None:
        """Multiple records accumulate."""
        meter.record("compute", "execute", units=3)
        meter.record("storage", "write", units=7)
        assert meter.total_units == 10

    def test_total_units_default(self, meter: Meter) -> None:
        """Default units is 1."""
        meter.record("compute", "execute")
        assert meter.total_units == 1

    def test_record_preserves_session_id(
        self, meter: Meter, session_id: bytes
    ) -> None:
        """Records have correct session_id."""
        rec = meter.record("compute", "execute")
        assert rec.session_id == session_id


# =============================================================================
# TestReceiptGeneration
# =============================================================================


class TestReceiptGeneration:
    """Tests for Meter.generate_receipt()."""

    def test_generate_receipt(
        self,
        meter: Meter,
        signing_secret_key: bytes,
    ) -> None:
        """generate_receipt() returns a signed Receipt."""
        meter.record("compute", "execute", units=10)
        receipt = meter.generate_receipt(signing_secret_key)
        assert isinstance(receipt, Receipt)
        assert receipt.total_units == 10
        assert receipt.sequence_number == 1
        assert len(receipt.signature) > 0

    def test_receipt_signature_verifies(
        self,
        meter: Meter,
        signing_secret_key: bytes,
        signing_public_key: bytes,
    ) -> None:
        """Receipt signature is verifiable with the public key."""
        meter.record("compute", "execute", units=5)
        receipt = meter.generate_receipt(signing_secret_key)
        assert verify(
            signing_public_key,
            receipt.signable_bytes(),
            receipt.signature,
        )

    def test_generate_clears_records(
        self,
        meter: Meter,
        signing_secret_key: bytes,
    ) -> None:
        """generate_receipt() clears internal records."""
        meter.record("compute", "execute", units=5)
        meter.generate_receipt(signing_secret_key)
        assert meter.total_units == 0

    def test_sequential_receipts_increment_sequence(
        self,
        meter: Meter,
        signing_secret_key: bytes,
    ) -> None:
        """Sequential receipts have incrementing sequence numbers."""
        meter.record("compute", "execute", units=1)
        r1 = meter.generate_receipt(signing_secret_key)
        meter.record("compute", "execute", units=2)
        r2 = meter.generate_receipt(signing_secret_key, prev_hash=r1.compute_hash())
        assert r1.sequence_number == 1
        assert r2.sequence_number == 2


# =============================================================================
# TestReceiptChain
# =============================================================================


class TestReceiptChain:
    """Tests for ReceiptChain."""

    def _build_chain(
        self,
        meter: Meter,
        secret_key: bytes,
        count: int = 3,
    ) -> ReceiptChain:
        """Helper to build a valid receipt chain."""
        chain = ReceiptChain()
        prev_hash = b""
        for i in range(count):
            meter.record("compute", "execute", units=i + 1)
            receipt = meter.generate_receipt(secret_key, prev_hash=prev_hash)
            chain.append(receipt)
            prev_hash = receipt.compute_hash()
        return chain

    def test_append_valid_chain(
        self,
        meter: Meter,
        signing_secret_key: bytes,
    ) -> None:
        """Can append receipts to form a valid chain."""
        chain = self._build_chain(meter, signing_secret_key)
        assert len(chain) == 3

    def test_verify_integrity(
        self,
        meter: Meter,
        signing_secret_key: bytes,
        signing_public_key: bytes,
    ) -> None:
        """verify() passes for a valid chain."""
        chain = self._build_chain(meter, signing_secret_key)
        assert chain.verify(signing_public_key)

    def test_detect_tampering(
        self,
        meter: Meter,
        signing_secret_key: bytes,
        signing_public_key: bytes,
    ) -> None:
        """verify() detects a tampered receipt."""
        chain = self._build_chain(meter, signing_secret_key)
        # Tamper with the second receipt's total_units
        original = chain.receipts[1]
        tampered = Receipt(
            records=original.records,
            total_units=999,  # tampered
            total_cost=original.total_cost,
            issued_at=original.issued_at,
            issuer=original.issuer,
            signature=original.signature,
            sequence_number=original.sequence_number,
            prev_hash=original.prev_hash,
            meter_id=original.meter_id,
        )
        chain._receipts[1] = tampered
        with pytest.raises(Exception):
            chain.verify(signing_public_key)

    def test_broken_hash_chain_rejected(
        self,
        meter: Meter,
        signing_secret_key: bytes,
    ) -> None:
        """append() rejects a receipt with wrong prev_hash."""
        chain = ReceiptChain()
        meter.record("compute", "execute", units=1)
        r1 = meter.generate_receipt(signing_secret_key, prev_hash=b"")
        chain.append(r1)

        # Create receipt with wrong prev_hash
        meter.record("compute", "execute", units=2)
        r2 = meter.generate_receipt(signing_secret_key, prev_hash=b"wrong_hash")
        with pytest.raises(ReceiptChainError, match="prev_hash mismatch"):
            chain.append(r2)

    def test_first_receipt_must_have_empty_prev_hash(
        self,
        meter: Meter,
        signing_secret_key: bytes,
    ) -> None:
        """First receipt must have empty prev_hash."""
        chain = ReceiptChain()
        meter.record("compute", "execute", units=1)
        r = meter.generate_receipt(signing_secret_key, prev_hash=b"notempty")
        with pytest.raises(ReceiptChainError, match="empty prev_hash"):
            chain.append(r)

    def test_get_range(
        self,
        meter: Meter,
        signing_secret_key: bytes,
    ) -> None:
        """get_range() returns receipts in the requested range."""
        chain = self._build_chain(meter, signing_secret_key, count=5)
        sub = chain.get_range(2, 4)
        assert len(sub) == 3
        assert all(2 <= r.sequence_number <= 4 for r in sub)

    def test_cbor_roundtrip(
        self,
        meter: Meter,
        signing_secret_key: bytes,
    ) -> None:
        """Chain survives CBOR serialization roundtrip."""
        chain = self._build_chain(meter, signing_secret_key)
        data = chain.to_cbor()
        restored = ReceiptChain.from_cbor(data)
        assert len(restored) == len(chain)
        for orig, rest in zip(chain.receipts, restored.receipts):
            assert orig.sequence_number == rest.sequence_number
            assert orig.total_units == rest.total_units
            assert orig.signature == rest.signature
            assert orig.prev_hash == rest.prev_hash

    def test_empty_chain_verify_raises(self) -> None:
        """verify() raises on empty chain."""
        chain = ReceiptChain()
        with pytest.raises(ReceiptChainError, match="Empty chain"):
            chain.verify(b"k" * 1952)
