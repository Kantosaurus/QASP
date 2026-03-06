"""Payment channel settlement.

This module implements payment channels for settling
usage receipts in QASP.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum, auto

import cbor2

from qasp.crypto.signatures import sign, verify

__all__ = [
    "CHALLENGE_PERIOD_SECONDS",
    "CLOSE_REASON_COOPERATIVE",
    "CLOSE_REASON_TIMEOUT",
    "CLOSE_REASON_UNILATERAL",
    "ChallengeError",
    "ChannelNotOpenError",
    "ChannelState",
    "ChannelStateUpdate",
    "ChannelTimeoutError",
    "CloseReason",
    "InsufficientBalanceError",
    "InvalidPriceError",
    "InvalidStateUpdateError",
    "PaymentChannel",
    "PriceNegotiator",
    "PriceSchedule",
    "Settlement",
    "SettlementError",
]

# Constants
CHALLENGE_PERIOD_SECONDS = 300
CLOSE_REASON_COOPERATIVE = "cooperative"
CLOSE_REASON_TIMEOUT = "timeout"
CLOSE_REASON_UNILATERAL = "unilateral"


# Exceptions
class SettlementError(Exception):
    """Base exception for settlement errors."""


class ChannelNotOpenError(SettlementError):
    """Raised when operating on a channel that is not open."""


class InsufficientBalanceError(SettlementError):
    """Raised when a transfer exceeds available balance."""


class InvalidStateUpdateError(SettlementError):
    """Raised when a state update is invalid."""


class ChallengeError(SettlementError):
    """Raised when a channel challenge fails."""


class ChannelTimeoutError(SettlementError):
    """Raised when a channel operation times out."""


class InvalidPriceError(SettlementError):
    """Raised when a price is invalid."""


class CloseReason(Enum):
    """Reason for closing a payment channel."""
    COOPERATIVE = auto()
    UNILATERAL = auto()
    TIMEOUT = auto()


class PriceSchedule:
    """Price schedule for metered usage."""

    def __init__(self, price_per_unit: int = 1, currency: str = "credits") -> None:
        self.price_per_unit = price_per_unit
        self.currency = currency

    def compute_cost(self, units: int) -> int:
        return units * self.price_per_unit


class PriceNegotiator:
    """Negotiates pricing between channel parties."""

    def __init__(self, schedule: PriceSchedule | None = None) -> None:
        self._schedule = schedule or PriceSchedule()

    @property
    def schedule(self) -> PriceSchedule:
        return self._schedule


class ChannelState(Enum):
    """Payment channel state."""

    OPENING = auto()
    OPEN = auto()
    CLOSING = auto()
    CLOSED = auto()
    DISPUTED = auto()


@dataclass(frozen=True)
class ChannelStateUpdate:
    """A signed state update for a payment channel."""

    channel_id: bytes
    sequence: int
    balance_a: int
    balance_b: int
    prev_state_hash: bytes
    timestamp: datetime
    signature_a: bytes
    signature_b: bytes

    def signable_bytes(self) -> bytes:
        """Return CBOR-encoded bytes for signing (excludes signatures)."""
        return cbor2.dumps({
            "channel_id": self.channel_id,
            "sequence": self.sequence,
            "balance_a": self.balance_a,
            "balance_b": self.balance_b,
            "prev_state_hash": self.prev_state_hash,
            "timestamp": self.timestamp.isoformat(),
        })

    def compute_hash(self) -> bytes:
        """Compute SHA-384 hash of the full state (including signatures)."""
        return hashlib.sha384(self.to_cbor()).digest()

    def to_cbor(self) -> bytes:
        """Serialize the full state update to CBOR."""
        return cbor2.dumps({
            "channel_id": self.channel_id,
            "sequence": self.sequence,
            "balance_a": self.balance_a,
            "balance_b": self.balance_b,
            "prev_state_hash": self.prev_state_hash,
            "timestamp": self.timestamp.isoformat(),
            "signature_a": self.signature_a,
            "signature_b": self.signature_b,
        })


@dataclass(frozen=True)
class Settlement:
    """A settlement record."""

    channel_id: bytes
    amount: int
    payer: str
    payee: str
    timestamp: datetime
    receipt_hash: bytes
    signatures: tuple[bytes, bytes]


class PaymentChannel:
    """A bidirectional payment channel."""

    def __init__(
        self,
        party_a: str,
        party_b: str,
        initial_balance_a: int,
        initial_balance_b: int,
    ) -> None:
        """Initialize a payment channel.

        Args:
            party_a: Identifier for party A.
            party_b: Identifier for party B.
            initial_balance_a: Initial balance for party A.
            initial_balance_b: Initial balance for party B.
        """
        self._party_a = party_a
        self._party_b = party_b
        self._balance_a = initial_balance_a
        self._balance_b = initial_balance_b
        self._state = ChannelState.OPENING
        self._channel_id: bytes | None = None
        self._states: list[ChannelStateUpdate] = []
        self._sequence = 0

    @property
    def state(self) -> ChannelState:
        """Return the current channel state."""
        return self._state

    @property
    def channel_id(self) -> bytes | None:
        """Return the channel ID."""
        return self._channel_id

    @property
    def balance_a(self) -> int:
        """Return party A's current balance."""
        return self._balance_a

    @property
    def balance_b(self) -> int:
        """Return party B's current balance."""
        return self._balance_b

    @property
    def states(self) -> list[ChannelStateUpdate]:
        """Return all state updates."""
        return list(self._states)

    def open(self, signing_key_a: bytes, signing_key_b: bytes) -> bytes:
        """Open the payment channel.

        Args:
            signing_key_a: Party A's signing key.
            signing_key_b: Party B's signing key.

        Returns:
            The channel ID.
        """
        self._channel_id = os.urandom(32)
        now = datetime.now(UTC)

        msg = cbor2.dumps({
            "channel_id": self._channel_id,
            "sequence": 0,
            "balance_a": self._balance_a,
            "balance_b": self._balance_b,
            "prev_state_hash": b"",
            "timestamp": now.isoformat(),
        })
        sig_a = sign(signing_key_a, msg)
        sig_b = sign(signing_key_b, msg)

        initial_state = ChannelStateUpdate(
            channel_id=self._channel_id,
            sequence=0,
            balance_a=self._balance_a,
            balance_b=self._balance_b,
            prev_state_hash=b"",
            timestamp=now,
            signature_a=sig_a,
            signature_b=sig_b,
        )
        self._states.append(initial_state)
        self._state = ChannelState.OPEN
        return self._channel_id

    def transfer(
        self,
        amount: int,
        from_a_to_b: bool,
        signing_key: bytes,
    ) -> bytes:
        """Transfer funds within the channel.

        Args:
            amount: The amount to transfer.
            from_a_to_b: True to transfer from A to B.
            signing_key: The sender's signing key.

        Returns:
            The signed state update as CBOR.

        Raises:
            ValueError: If channel is not open or balance insufficient.
        """
        if self._state != ChannelState.OPEN:
            raise ValueError("Channel is not open")

        if from_a_to_b:
            new_a = self._balance_a - amount
            new_b = self._balance_b + amount
        else:
            new_a = self._balance_a + amount
            new_b = self._balance_b - amount

        if new_a < 0 or new_b < 0:
            raise ValueError("Insufficient balance for transfer")

        self._sequence += 1
        prev_hash = self._states[-1].compute_hash()
        now = datetime.now(UTC)

        msg = cbor2.dumps({
            "channel_id": self._channel_id,
            "sequence": self._sequence,
            "balance_a": new_a,
            "balance_b": new_b,
            "prev_state_hash": prev_hash,
            "timestamp": now.isoformat(),
        })
        sender_sig = sign(signing_key, msg)

        # Sender signs; the other signature slot is empty until countersigned
        if from_a_to_b:
            sig_a, sig_b = sender_sig, b""
        else:
            sig_a, sig_b = b"", sender_sig

        state_update = ChannelStateUpdate(
            channel_id=self._channel_id,
            sequence=self._sequence,
            balance_a=new_a,
            balance_b=new_b,
            prev_state_hash=prev_hash,
            timestamp=now,
            signature_a=sig_a,
            signature_b=sig_b,
        )
        self._states.append(state_update)
        self._balance_a = new_a
        self._balance_b = new_b
        return state_update.to_cbor()

    def close(
        self,
        signing_key_a: bytes,
        signing_key_b: bytes,
    ) -> Settlement:
        """Close the channel and settle.

        Args:
            signing_key_a: Party A's signing key.
            signing_key_b: Party B's signing key.

        Returns:
            The settlement record.

        Raises:
            ValueError: If channel is not open.
        """
        if self._state != ChannelState.OPEN:
            raise ValueError("Channel is not open")

        self._sequence += 1
        prev_hash = self._states[-1].compute_hash()
        now = datetime.now(UTC)

        msg = cbor2.dumps({
            "channel_id": self._channel_id,
            "sequence": self._sequence,
            "balance_a": self._balance_a,
            "balance_b": self._balance_b,
            "prev_state_hash": prev_hash,
            "timestamp": now.isoformat(),
        })
        sig_a = sign(signing_key_a, msg)
        sig_b = sign(signing_key_b, msg)

        final_state = ChannelStateUpdate(
            channel_id=self._channel_id,
            sequence=self._sequence,
            balance_a=self._balance_a,
            balance_b=self._balance_b,
            prev_state_hash=prev_hash,
            timestamp=now,
            signature_a=sig_a,
            signature_b=sig_b,
        )
        self._states.append(final_state)
        self._state = ChannelState.CLOSED

        # Determine net transfer direction
        initial = self._states[0]
        net_a = initial.balance_a - self._balance_a
        if net_a >= 0:
            payer, payee, amount = self._party_a, self._party_b, net_a
        else:
            payer, payee, amount = self._party_b, self._party_a, -net_a

        return Settlement(
            channel_id=self._channel_id,
            amount=amount,
            payer=payer,
            payee=payee,
            timestamp=now,
            receipt_hash=final_state.compute_hash(),
            signatures=(sig_a, sig_b),
        )
