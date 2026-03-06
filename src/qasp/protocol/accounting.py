"""Usage metering and accounting.

This module implements usage tracking, receipt generation, and
hash-chained receipt verification for QASP connections.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import cbor2

from qasp.crypto.signatures import sign, verify

__all__ = [
    "Meter",
    "Receipt",
    "ReceiptChain",
    "ReceiptChainError",
    "UsageRecord",
]


class ReceiptChainError(Exception):
    """Raised when receipt chain validation fails."""


@dataclass(frozen=True)
class UsageRecord:
    """A record of resource usage."""

    resource: str
    operation: str
    units: int
    timestamp: datetime
    session_id: bytes


@dataclass(frozen=True)
class Receipt:
    """A signed usage receipt with hash-chain linkage."""

    records: list[UsageRecord]
    total_units: int
    total_cost: int
    issued_at: datetime
    issuer: str
    signature: bytes
    sequence_number: int = 0
    prev_hash: bytes = b""
    meter_id: bytes = b""

    def to_cbor(self) -> bytes:
        """Serialize the receipt to CBOR."""
        return cbor2.dumps(self._to_dict())

    def _to_dict(self) -> dict[str, Any]:
        return {
            "records": [
                {
                    "resource": r.resource,
                    "operation": r.operation,
                    "units": r.units,
                    "timestamp": r.timestamp.isoformat(),
                    "session_id": r.session_id,
                }
                for r in self.records
            ],
            "total_units": self.total_units,
            "total_cost": self.total_cost,
            "issued_at": self.issued_at.isoformat(),
            "issuer": self.issuer,
            "signature": self.signature,
            "sequence_number": self.sequence_number,
            "prev_hash": self.prev_hash,
            "meter_id": self.meter_id,
        }

    @classmethod
    def from_cbor(cls, data: bytes) -> Receipt:
        """Deserialize a receipt from CBOR."""
        d = cbor2.loads(data)
        records = [
            UsageRecord(
                resource=r["resource"],
                operation=r["operation"],
                units=r["units"],
                timestamp=datetime.fromisoformat(r["timestamp"]),
                session_id=bytes(r["session_id"]),
            )
            for r in d["records"]
        ]
        return cls(
            records=records,
            total_units=d["total_units"],
            total_cost=d.get("total_cost", 0),
            issued_at=datetime.fromisoformat(d["issued_at"]),
            issuer=d["issuer"],
            signature=bytes(d["signature"]),
            sequence_number=d["sequence_number"],
            prev_hash=bytes(d["prev_hash"]),
            meter_id=bytes(d["meter_id"]),
        )

    def signable_bytes(self) -> bytes:
        """Return the canonical bytes used for signing (excludes signature)."""
        d = self._to_dict()
        d.pop("signature")
        return cbor2.dumps(d)

    def compute_hash(self) -> bytes:
        """Compute SHA-384 hash of the full receipt (including signature)."""
        return hashlib.sha384(self.to_cbor()).digest()


class Meter:
    """Usage metering for a QASP session."""

    def __init__(self, session_id: bytes, meter_id: bytes = b"", issuer: str = "") -> None:
        """Initialize the meter.

        Args:
            session_id: The session identifier.
            meter_id: Optional meter identifier.
            issuer: Issuer identifier for receipts.
        """
        self._session_id = session_id
        self._meter_id = meter_id
        self._issuer = issuer
        self._records: list[UsageRecord] = []
        self._sequence: int = 0

    def record(
        self,
        resource: str,
        operation: str,
        units: int = 1,
    ) -> UsageRecord:
        """Record usage of a resource.

        Args:
            resource: The resource being used.
            operation: The operation performed.
            units: The number of units consumed.

        Returns:
            The usage record.
        """
        usage = UsageRecord(
            resource=resource,
            operation=operation,
            units=units,
            timestamp=datetime.now(UTC),
            session_id=self._session_id,
        )
        self._records.append(usage)
        return usage

    def generate_receipt(
        self,
        signing_key: bytes,
        prev_hash: bytes = b"",
    ) -> Receipt:
        """Generate a signed receipt for all recorded usage.

        Args:
            signing_key: The ML-DSA-65 secret key to sign the receipt.
            prev_hash: Hash of the previous receipt in the chain.

        Returns:
            A signed Receipt.
        """
        self._sequence += 1
        receipt = Receipt(
            records=list(self._records),
            total_units=self.total_units,
            total_cost=0,
            issued_at=datetime.now(UTC),
            issuer=self._issuer,
            signature=b"",  # placeholder
            sequence_number=self._sequence,
            prev_hash=prev_hash,
            meter_id=self._meter_id,
        )
        sig = sign(signing_key, receipt.signable_bytes())
        receipt = Receipt(
            records=receipt.records,
            total_units=receipt.total_units,
            total_cost=receipt.total_cost,
            issued_at=receipt.issued_at,
            issuer=receipt.issuer,
            signature=sig,
            sequence_number=receipt.sequence_number,
            prev_hash=receipt.prev_hash,
            meter_id=receipt.meter_id,
        )
        self._records.clear()
        return receipt

    @property
    def total_units(self) -> int:
        """Return the total units recorded."""
        return sum(r.units for r in self._records)


class ReceiptChain:
    """An ordered, hash-chained list of receipts."""

    def __init__(self) -> None:
        self._receipts: list[Receipt] = []

    def __len__(self) -> int:
        return len(self._receipts)

    @property
    def receipts(self) -> list[Receipt]:
        return list(self._receipts)

    def append(self, receipt: Receipt) -> None:
        """Append a receipt, validating hash chain continuity.

        Args:
            receipt: The receipt to append.

        Raises:
            ReceiptChainError: If the prev_hash doesn't match.
        """
        if self._receipts:
            expected = self._receipts[-1].compute_hash()
            if receipt.prev_hash != expected:
                raise ReceiptChainError(
                    f"Hash chain broken at sequence {receipt.sequence_number}: "
                    f"prev_hash mismatch"
                )
        else:
            if receipt.prev_hash != b"":
                raise ReceiptChainError(
                    "First receipt in chain must have empty prev_hash"
                )
        self._receipts.append(receipt)

    def verify(self, issuer_public_key: bytes) -> bool:
        """Walk the chain, verify every prev_hash and signature.

        Args:
            issuer_public_key: The public key to verify signatures against.

        Returns:
            True if the entire chain is valid.

        Raises:
            ReceiptChainError: If verification fails.
        """
        if not self._receipts:
            raise ReceiptChainError("Empty chain")

        for i, receipt in enumerate(self._receipts):
            # Verify hash chain
            if i == 0:
                if receipt.prev_hash != b"":
                    raise ReceiptChainError("First receipt must have empty prev_hash")
            else:
                expected = self._receipts[i - 1].compute_hash()
                if receipt.prev_hash != expected:
                    raise ReceiptChainError(
                        f"Hash chain broken at sequence {receipt.sequence_number}"
                    )

            # Verify signature
            verify(issuer_public_key, receipt.signable_bytes(), receipt.signature)

        return True

    def get_range(self, start_seq: int, end_seq: int) -> list[Receipt]:
        """Extract a sub-range of receipts by sequence number.

        Args:
            start_seq: Start sequence number (inclusive).
            end_seq: End sequence number (inclusive).

        Returns:
            List of receipts in the range.
        """
        return [
            r
            for r in self._receipts
            if start_seq <= r.sequence_number <= end_seq
        ]

    def to_cbor(self) -> bytes:
        """Serialize the entire chain to CBOR."""
        return cbor2.dumps([r.to_cbor() for r in self._receipts])

    @classmethod
    def from_cbor(cls, data: bytes) -> ReceiptChain:
        """Deserialize a receipt chain from CBOR."""
        chain = cls()
        receipt_blobs: list[bytes] = cbor2.loads(data)
        for blob in receipt_blobs:
            receipt = Receipt.from_cbor(blob)
            chain._receipts.append(receipt)
        return chain
