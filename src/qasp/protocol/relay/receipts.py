"""Hash-chain relay receipts (PRD §7.2) and ML-DSA-65 session summaries.

Each forwarded message produces a RelayReceipt. Receipts form a SHA-384 hash
chain. At session close, build_session_summary emits a standard QASP-Meter
Receipt (src/qasp/protocol/accounting.py) signed with the relay's ML-DSA-65
key that covers the final chain tip — this is what agents archive for
QASP-Meter / QASP-Settle reconciliation.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import cbor2

from qasp.crypto.signatures import sign as mldsa_sign
from qasp.protocol.accounting import Receipt, UsageRecord

__all__ = [
    "RelayReceipt",
    "RelayReceiptChain",
    "RelayReceiptChainError",
    "build_session_summary",
    "hash_payload",
]


class RelayReceiptChainError(Exception):
    """Raised when a RelayReceiptChain invariant is violated."""


def hash_payload(payload: bytes) -> bytes:
    """Return SHA-384(payload) — the 48-byte message hash used by PRD §7.2."""
    return hashlib.sha384(payload).digest()


@dataclass(frozen=True)
class RelayReceipt:
    session_id: bytes
    seq: int
    msg_hash: bytes
    timestamp: int
    direction: int
    cumulative_msgs: int
    cumulative_bytes: int
    cumulative_cost: int
    prev_hash: bytes
    relay_sig: bytes

    # ---- construction --------------------------------------------------

    @classmethod
    def new(
        cls,
        *,
        session_id: bytes,
        seq: int,
        msg_hash: bytes,
        timestamp: int,
        direction: int,
        cumulative_msgs: int,
        cumulative_bytes: int,
        cumulative_cost: int,
        prev_hash: bytes,
        receipt_key: bytes,
    ) -> RelayReceipt:
        """Build a signed RelayReceipt using the K_receipt HMAC key."""
        if len(session_id) != 16:
            raise ValueError("session_id must be 16 bytes")
        if len(msg_hash) != 48:
            raise ValueError("msg_hash must be 48 bytes (SHA-384)")
        if direction not in (0x00, 0x01):
            raise ValueError(f"direction must be 0x00 or 0x01, got {direction:#x}")
        if prev_hash and len(prev_hash) != 48:
            raise ValueError("prev_hash must be 0 bytes (first) or 48 bytes")

        unsigned = cls(
            session_id=session_id,
            seq=seq,
            msg_hash=msg_hash,
            timestamp=timestamp,
            direction=direction,
            cumulative_msgs=cumulative_msgs,
            cumulative_bytes=cumulative_bytes,
            cumulative_cost=cumulative_cost,
            prev_hash=prev_hash,
            relay_sig=b"",
        )
        sig = hmac.new(receipt_key, unsigned.signable_bytes(), hashlib.sha256).digest()
        return cls(
            session_id=session_id,
            seq=seq,
            msg_hash=msg_hash,
            timestamp=timestamp,
            direction=direction,
            cumulative_msgs=cumulative_msgs,
            cumulative_bytes=cumulative_bytes,
            cumulative_cost=cumulative_cost,
            prev_hash=prev_hash,
            relay_sig=sig,
        )

    # ---- serialization -------------------------------------------------

    def _to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "seq": self.seq,
            "msg_hash": self.msg_hash,
            "timestamp": self.timestamp,
            "direction": self.direction,
            "cumulative_msgs": self.cumulative_msgs,
            "cumulative_bytes": self.cumulative_bytes,
            "cumulative_cost": self.cumulative_cost,
            "prev_hash": self.prev_hash,
            "relay_sig": self.relay_sig,
        }

    def to_cbor(self) -> bytes:
        return cbor2.dumps(self._to_dict())

    @classmethod
    def from_cbor(cls, data: bytes) -> RelayReceipt:
        d = cbor2.loads(data)
        return cls(
            session_id=bytes(d["session_id"]),
            seq=int(d["seq"]),
            msg_hash=bytes(d["msg_hash"]),
            timestamp=int(d["timestamp"]),
            direction=int(d["direction"]),
            cumulative_msgs=int(d["cumulative_msgs"]),
            cumulative_bytes=int(d["cumulative_bytes"]),
            cumulative_cost=int(d["cumulative_cost"]),
            prev_hash=bytes(d["prev_hash"]),
            relay_sig=bytes(d["relay_sig"]),
        )

    def signable_bytes(self) -> bytes:
        """Canonical bytes fed to HMAC-SHA-256 (excludes relay_sig)."""
        d = self._to_dict()
        d.pop("relay_sig")
        return cbor2.dumps(d)

    def compute_hash(self) -> bytes:
        """SHA-384 over the full signed receipt CBOR — used as prev_hash."""
        return hashlib.sha384(self.to_cbor()).digest()


class RelayReceiptChain:
    def __init__(self) -> None:
        self._receipts: list[RelayReceipt] = []

    def __len__(self) -> int:
        return len(self._receipts)

    @property
    def tip(self) -> bytes:
        return self._receipts[-1].compute_hash() if self._receipts else b""

    @property
    def receipts(self) -> list[RelayReceipt]:
        return list(self._receipts)

    def append(self, receipt: RelayReceipt) -> None:
        if self._receipts:
            expected = self._receipts[-1].compute_hash()
            if receipt.prev_hash != expected:
                raise RelayReceiptChainError(
                    f"chain broken at seq {receipt.seq}: prev_hash mismatch"
                )
        else:
            if receipt.prev_hash != b"":
                raise RelayReceiptChainError(
                    "first receipt in chain must have empty prev_hash"
                )
        self._receipts.append(receipt)

    def verify(self, receipt_key: bytes) -> bool:
        prev = b""
        for r in self._receipts:
            if r.prev_hash != prev:
                return False
            expected_sig = hmac.new(
                receipt_key, r.signable_bytes(), hashlib.sha256
            ).digest()
            if not hmac.compare_digest(expected_sig, r.relay_sig):
                return False
            prev = r.compute_hash()
        return True


def build_session_summary(
    *,
    chain: RelayReceiptChain,
    session_id: bytes,
    signing_key: bytes,
    issuer: str,
    signer: Callable[[bytes, bytes], bytes] | None = None,
) -> Receipt:
    """Produce an ML-DSA-65-signed QASP-Meter Receipt covering the chain tip.

    Reuses src/qasp/protocol/accounting.py::Receipt so downstream QASP-Meter
    and QASP-Settle components see a familiar object.
    """
    sign_fn = signer or mldsa_sign
    total_units = len(chain)
    total_bytes = chain.receipts[-1].cumulative_bytes if chain.receipts else 0
    records = [
        UsageRecord(
            resource=f"qasp://relay/session/{session_id.hex()}",
            operation="relay",
            units=1,
            timestamp=datetime.fromtimestamp(r.timestamp, tz=UTC),
            session_id=session_id,
        )
        for r in chain.receipts
    ]
    draft = Receipt(
        records=records,
        total_units=total_units,
        total_cost=0,
        issued_at=datetime.now(UTC),
        issuer=issuer,
        signature=b"",
        sequence_number=total_units,
        prev_hash=chain.tip,
        meter_id=session_id,
    )
    sig = sign_fn(signing_key, draft.signable_bytes())
    return Receipt(
        records=draft.records,
        total_units=total_units,
        total_cost=total_bytes,  # PoC: cost equals total bytes relayed
        issued_at=draft.issued_at,
        issuer=issuer,
        signature=sig,
        sequence_number=total_units,
        prev_hash=chain.tip,
        meter_id=session_id,
    )
