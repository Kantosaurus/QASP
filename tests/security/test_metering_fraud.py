"""Security tests for metering fraud resistance.

Security property: Receipt chain integrity is protected by
SHA-384 hash chain + ML-DSA-65 signatures.
"""

from __future__ import annotations

import pytest

from qasp.crypto import signatures
from qasp.crypto.exceptions import InvalidSignatureError
from qasp.framing.messages import MeterAck, MeterReport
from qasp.protocol.accounting import (
    Meter,
    Receipt,
    ReceiptChain,
    ReceiptChainError,
)
from qasp.protocol.metering import (
    InvalidMeterReportError,
    MeterReportHandler,
)


# =============================================================================
# Helpers
# =============================================================================


def build_receipt_chain(
    signing_key: bytes,
    n: int = 3,
) -> tuple[ReceiptChain, bytes]:
    """Build a receipt chain with n receipts.

    Returns (chain, public_key).
    """
    public_key, _ = signatures.generate_keypair()
    # We need the public key from the same keypair as the signing key
    # The signing_key IS the secret key; get the matching public key
    # Actually, we receive the keypair from fixtures, so we need to
    # accept both. Let's just build from scratch with a known keypair.
    pk, sk = signatures.generate_keypair()
    meter = Meter(session_id=b"session_001", meter_id=b"meter_001", issuer="test_issuer")
    chain = ReceiptChain()
    prev_hash = b""

    for i in range(n):
        meter.record(resource="res/compute", operation="invoke", units=i + 1)
        receipt = meter.generate_receipt(sk, prev_hash=prev_hash)
        chain.append(receipt)
        prev_hash = receipt.compute_hash()

    return chain, pk


def _build_chain_with_key(
    n: int = 3,
) -> tuple[ReceiptChain, bytes, bytes]:
    """Build a receipt chain, returning (chain, public_key, secret_key)."""
    pk, sk = signatures.generate_keypair()
    meter = Meter(session_id=b"session_001", meter_id=b"meter_001", issuer="test_issuer")
    chain = ReceiptChain()
    prev_hash = b""

    for i in range(n):
        meter.record(resource="res/compute", operation="invoke", units=i + 1)
        receipt = meter.generate_receipt(sk, prev_hash=prev_hash)
        chain.append(receipt)
        prev_hash = receipt.compute_hash()

    return chain, pk, sk


# =============================================================================
# Receipt Tampering
# =============================================================================


@pytest.mark.security
class TestReceiptTampering:
    """Detect tampering with individual receipt fields."""

    def test_modified_total_units_detected(self) -> None:
        """Changing total_units invalidates signature."""
        chain, pk, sk = _build_chain_with_key(3)
        original = chain._receipts[1]

        tampered = Receipt(
            records=original.records,
            total_units=original.total_units + 999,  # Tampered
            total_cost=original.total_cost,
            issued_at=original.issued_at,
            issuer=original.issuer,
            signature=original.signature,
            sequence_number=original.sequence_number,
            prev_hash=original.prev_hash,
            meter_id=original.meter_id,
        )
        chain._receipts[1] = tampered

        with pytest.raises((ReceiptChainError, InvalidSignatureError)):
            chain.verify(pk)

    def test_modified_total_cost_detected(self) -> None:
        """Changing total_cost invalidates signature."""
        chain, pk, sk = _build_chain_with_key(3)
        original = chain._receipts[1]

        tampered = Receipt(
            records=original.records,
            total_units=original.total_units,
            total_cost=original.total_cost + 50000,  # Tampered
            issued_at=original.issued_at,
            issuer=original.issuer,
            signature=original.signature,
            sequence_number=original.sequence_number,
            prev_hash=original.prev_hash,
            meter_id=original.meter_id,
        )
        chain._receipts[1] = tampered

        with pytest.raises((ReceiptChainError, InvalidSignatureError)):
            chain.verify(pk)

    def test_modified_issuer_detected(self) -> None:
        """Changing issuer field invalidates signature."""
        chain, pk, sk = _build_chain_with_key(3)
        original = chain._receipts[1]

        tampered = Receipt(
            records=original.records,
            total_units=original.total_units,
            total_cost=original.total_cost,
            issued_at=original.issued_at,
            issuer="evil_issuer",  # Tampered
            signature=original.signature,
            sequence_number=original.sequence_number,
            prev_hash=original.prev_hash,
            meter_id=original.meter_id,
        )
        chain._receipts[1] = tampered

        with pytest.raises((ReceiptChainError, InvalidSignatureError)):
            chain.verify(pk)

    def test_zeroed_signature_detected(self) -> None:
        """Replacing signature with zeros is detected."""
        chain, pk, sk = _build_chain_with_key(3)
        original = chain._receipts[1]

        tampered = Receipt(
            records=original.records,
            total_units=original.total_units,
            total_cost=original.total_cost,
            issued_at=original.issued_at,
            issuer=original.issuer,
            signature=b"\x00" * len(original.signature),  # Zeroed
            sequence_number=original.sequence_number,
            prev_hash=original.prev_hash,
            meter_id=original.meter_id,
        )
        chain._receipts[1] = tampered

        with pytest.raises((ReceiptChainError, InvalidSignatureError)):
            chain.verify(pk)


# =============================================================================
# Receipt Order Tampering
# =============================================================================


@pytest.mark.security
class TestReceiptOrderTampering:
    """Detect tampering with receipt ordering."""

    def test_swapped_receipt_order_detected(self) -> None:
        """Swapping two receipts breaks hash chain."""
        chain, pk, sk = _build_chain_with_key(3)

        # Swap receipt 1 and 2
        chain._receipts[1], chain._receipts[2] = (
            chain._receipts[2],
            chain._receipts[1],
        )

        with pytest.raises((ReceiptChainError, InvalidSignatureError)):
            chain.verify(pk)

    def test_reversed_chain_detected(self) -> None:
        """Reversing entire chain is detected: first receipt has non-empty prev_hash."""
        chain, pk, sk = _build_chain_with_key(3)

        chain._receipts.reverse()

        with pytest.raises((ReceiptChainError, InvalidSignatureError)):
            chain.verify(pk)


# =============================================================================
# Fake Receipt Insertion
# =============================================================================


@pytest.mark.security
class TestFakeReceiptInsertion:
    """Detect insertion of receipts signed by different keys."""

    def test_inserted_receipt_breaks_chain(self) -> None:
        """A receipt signed with a different key fails chain verification."""
        chain, pk, sk = _build_chain_with_key(2)

        # Create a receipt with a different key
        _, evil_sk = signatures.generate_keypair()
        evil_meter = Meter(
            session_id=b"evil_session",
            meter_id=b"meter_001",
            issuer="evil",
        )
        evil_meter.record(resource="res/stolen", operation="exfil", units=100)
        fake_receipt = evil_meter.generate_receipt(evil_sk, prev_hash=b"")

        # Insert between existing receipts
        chain._receipts.insert(1, fake_receipt)

        with pytest.raises((ReceiptChainError, InvalidSignatureError)):
            chain.verify(pk)

    def test_appended_receipt_with_wrong_prev_hash(self) -> None:
        """Appending a receipt with wrong prev_hash raises ReceiptChainError."""
        chain, pk, sk = _build_chain_with_key(2)

        meter = Meter(
            session_id=b"session_001",
            meter_id=b"meter_001",
            issuer="test_issuer",
        )
        meter.record(resource="res/compute", operation="invoke", units=1)
        bad_receipt = meter.generate_receipt(sk, prev_hash=b"wrong_hash")

        with pytest.raises(ReceiptChainError):
            chain.append(bad_receipt)


# =============================================================================
# MeterReport Tampering
# =============================================================================


@pytest.mark.security
class TestMeterReportTampering:
    """Detect tampering with MeterReport messages."""

    def test_modified_usage_count_detected(self) -> None:
        """Changing usage_count after signing invalidates the report."""
        pk, sk = signatures.generate_keypair()
        report = MeterReportHandler.create_meter_report(
            meter_id=b"meter_001",
            seq=1,
            usage_count=10,
            usage_bytes=1024,
            cost=100,
            signing_key=sk,
        )

        tampered = MeterReport(
            meter_id=report.meter_id,
            sequence_number=report.sequence_number,
            usage_count=9999,  # Tampered
            usage_bytes=report.usage_bytes,
            cost=report.cost,
            timestamp=report.timestamp,
            signature=report.signature,
        )

        with pytest.raises(InvalidMeterReportError):
            MeterReportHandler.verify_meter_report(tampered, pk)

    def test_modified_cost_detected(self) -> None:
        """Changing cost after signing invalidates the report."""
        pk, sk = signatures.generate_keypair()
        report = MeterReportHandler.create_meter_report(
            meter_id=b"meter_001",
            seq=1,
            usage_count=10,
            usage_bytes=1024,
            cost=100,
            signing_key=sk,
        )

        tampered = MeterReport(
            meter_id=report.meter_id,
            sequence_number=report.sequence_number,
            usage_count=report.usage_count,
            usage_bytes=report.usage_bytes,
            cost=0,  # Tampered
            timestamp=report.timestamp,
            signature=report.signature,
        )

        with pytest.raises(InvalidMeterReportError):
            MeterReportHandler.verify_meter_report(tampered, pk)

    def test_modified_ack_detected(self) -> None:
        """Changing acked_sequence after signing invalidates the ack."""
        pk, sk = signatures.generate_keypair()
        ack = MeterReportHandler.create_meter_ack(
            meter_id=b"meter_001",
            acked_seq=5,
            acked_usage=50,
            signing_key=sk,
        )

        tampered = MeterAck(
            meter_id=ack.meter_id,
            acked_sequence=999,  # Tampered
            acked_usage=ack.acked_usage,
            signature=ack.signature,
        )

        with pytest.raises(InvalidMeterReportError):
            MeterReportHandler.verify_meter_ack(tampered, pk)
