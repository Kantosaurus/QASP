"""Conformance tests for receipt chains and metering.

Tests chain creation, validation, tamper detection, and dispute replay.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from qasp.crypto import signatures
from qasp.protocol.accounting import (
    Meter,
    Receipt,
    ReceiptChain,
    ReceiptChainError,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def meter_keypair() -> tuple[bytes, bytes]:
    return signatures.generate_keypair()


@pytest.fixture
def meter(meter_keypair: tuple[bytes, bytes]) -> Meter:
    return Meter(
        session_id=b"\x01" * 32,
        meter_id=b"\x02" * 16,
        issuer="did:qasp:test-issuer",
    )


# =============================================================================
# Receipt Chain Creation
# =============================================================================


class TestReceiptChainCreation:
    """Verify receipt chain construction and hash linking."""

    def test_single_receipt_chain(
        self,
        meter: Meter,
        meter_keypair: tuple[bytes, bytes],
    ) -> None:
        meter.record("gpu", "inference", units=10)
        receipt = meter.generate_receipt(meter_keypair[1])

        chain = ReceiptChain()
        chain.append(receipt)

        assert len(chain) == 1
        assert receipt.prev_hash == b""
        assert receipt.sequence_number == 1

    def test_multi_receipt_chain(
        self,
        meter_keypair: tuple[bytes, bytes],
    ) -> None:
        meter = Meter(
            session_id=b"\x01" * 32,
            meter_id=b"\x02" * 16,
            issuer="did:qasp:test-issuer",
        )
        chain = ReceiptChain()

        # Receipt 1
        meter.record("gpu", "inference", units=10)
        r1 = meter.generate_receipt(meter_keypair[1])
        chain.append(r1)

        # Receipt 2 - linked to r1
        meter.record("gpu", "inference", units=20)
        r2 = meter.generate_receipt(meter_keypair[1], prev_hash=r1.compute_hash())
        chain.append(r2)

        # Receipt 3 - linked to r2
        meter.record("gpu", "training", units=5)
        r3 = meter.generate_receipt(meter_keypair[1], prev_hash=r2.compute_hash())
        chain.append(r3)

        assert len(chain) == 3
        assert r2.prev_hash == r1.compute_hash()
        assert r3.prev_hash == r2.compute_hash()


# =============================================================================
# Receipt Chain Validation
# =============================================================================


class TestReceiptChainValidation:
    """Verify receipt chain signature and hash validation."""

    def test_valid_chain_verifies(
        self,
        meter_keypair: tuple[bytes, bytes],
    ) -> None:
        meter = Meter(
            session_id=b"\x01" * 32,
            meter_id=b"\x02" * 16,
            issuer="did:qasp:test-issuer",
        )
        chain = ReceiptChain()

        meter.record("gpu", "inference", units=10)
        r1 = meter.generate_receipt(meter_keypair[1])
        chain.append(r1)

        meter.record("gpu", "inference", units=20)
        r2 = meter.generate_receipt(meter_keypair[1], prev_hash=r1.compute_hash())
        chain.append(r2)

        assert chain.verify(meter_keypair[0]) is True

    def test_wrong_key_fails_verification(
        self,
        meter: Meter,
        meter_keypair: tuple[bytes, bytes],
    ) -> None:
        meter.record("gpu", "inference", units=10)
        receipt = meter.generate_receipt(meter_keypair[1])

        chain = ReceiptChain()
        chain.append(receipt)

        wrong_pk, _ = signatures.generate_keypair()
        with pytest.raises(Exception):
            chain.verify(wrong_pk)


# =============================================================================
# Tamper Detection
# =============================================================================


class TestTamperDetection:
    """Verify that tampering with receipts breaks chain validation."""

    def test_tampered_receipt_detected(
        self,
        meter_keypair: tuple[bytes, bytes],
    ) -> None:
        meter = Meter(
            session_id=b"\x01" * 32,
            meter_id=b"\x02" * 16,
            issuer="did:qasp:test-issuer",
        )

        meter.record("gpu", "inference", units=10)
        r1 = meter.generate_receipt(meter_keypair[1])

        meter.record("gpu", "inference", units=20)
        r2 = meter.generate_receipt(meter_keypair[1], prev_hash=r1.compute_hash())

        # Tamper with r2's total_units
        tampered = Receipt(
            records=r2.records,
            total_units=999,  # Tampered!
            total_cost=r2.total_cost,
            issued_at=r2.issued_at,
            issuer=r2.issuer,
            signature=r2.signature,
            sequence_number=r2.sequence_number,
            prev_hash=r2.prev_hash,
            meter_id=r2.meter_id,
        )

        chain = ReceiptChain()
        chain.append(r1)
        chain._receipts.append(tampered)  # Bypass append validation

        with pytest.raises(Exception):
            chain.verify(meter_keypair[0])

    def test_broken_hash_chain_detected(
        self,
        meter_keypair: tuple[bytes, bytes],
    ) -> None:
        meter = Meter(
            session_id=b"\x01" * 32,
            meter_id=b"\x02" * 16,
            issuer="did:qasp:test-issuer",
        )

        meter.record("gpu", "inference", units=10)
        r1 = meter.generate_receipt(meter_keypair[1])

        # Create r2 with wrong prev_hash
        meter.record("gpu", "inference", units=20)
        r2 = meter.generate_receipt(meter_keypair[1], prev_hash=b"\x00" * 48)

        chain = ReceiptChain()
        chain.append(r1)

        with pytest.raises(ReceiptChainError):
            chain.append(r2)


# =============================================================================
# Dispute Replay
# =============================================================================


class TestDisputeReplay:
    """Verify receipt chain can be used for dispute replay."""

    def test_receipt_range_extraction(
        self,
        meter_keypair: tuple[bytes, bytes],
    ) -> None:
        meter = Meter(
            session_id=b"\x01" * 32,
            meter_id=b"\x02" * 16,
            issuer="did:qasp:test-issuer",
        )
        chain = ReceiptChain()

        prev = b""
        for i in range(5):
            meter.record("gpu", "inference", units=10 * (i + 1))
            r = meter.generate_receipt(meter_keypair[1], prev_hash=prev)
            chain.append(r)
            prev = r.compute_hash()

        # Extract range [2, 4]
        sub = chain.get_range(2, 4)
        assert len(sub) == 3
        assert sub[0].sequence_number == 2
        assert sub[-1].sequence_number == 4

    def test_receipt_cbor_roundtrip(
        self,
        meter: Meter,
        meter_keypair: tuple[bytes, bytes],
    ) -> None:
        meter.record("gpu", "inference", units=10)
        r1 = meter.generate_receipt(meter_keypair[1])

        meter.record("gpu", "training", units=5)
        r2 = meter.generate_receipt(meter_keypair[1], prev_hash=r1.compute_hash())

        chain = ReceiptChain()
        chain.append(r1)
        chain.append(r2)

        # Serialize and deserialize
        cbor_data = chain.to_cbor()
        restored = ReceiptChain.from_cbor(cbor_data)

        assert len(restored) == 2
        assert restored.receipts[0].sequence_number == 1
        assert restored.receipts[1].sequence_number == 2


# =============================================================================
# Empty Chain
# =============================================================================


class TestEmptyChain:
    """Verify empty chain edge cases."""

    def test_verify_empty_chain_fails(
        self,
        meter_keypair: tuple[bytes, bytes],
    ) -> None:
        chain = ReceiptChain()
        with pytest.raises(ReceiptChainError):
            chain.verify(meter_keypair[0])

    def test_first_receipt_must_have_empty_prev_hash(
        self,
        meter: Meter,
        meter_keypair: tuple[bytes, bytes],
    ) -> None:
        meter.record("gpu", "inference", units=10)
        receipt = meter.generate_receipt(meter_keypair[1], prev_hash=b"\xff" * 48)

        chain = ReceiptChain()
        with pytest.raises(ReceiptChainError):
            chain.append(receipt)
