"""Payment channel settlement.

This module implements payment channels for settling
usage receipts in QASP.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum, auto

__all__ = [
    "ChannelState",
    "PaymentChannel",
    "Settlement",
]


class ChannelState(Enum):
    """Payment channel state."""

    OPENING = auto()
    OPEN = auto()
    CLOSING = auto()
    CLOSED = auto()
    DISPUTED = auto()


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

    @property
    def state(self) -> ChannelState:
        """Return the current channel state."""
        return self._state

    def open(self, signing_key_a: bytes, signing_key_b: bytes) -> bytes:
        """Open the payment channel.

        Args:
            signing_key_a: Party A's signing key.
            signing_key_b: Party B's signing key.

        Returns:
            The channel opening transaction.
        """
        raise NotImplementedError("Payment channel implementation pending")

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
            The signed transfer message.
        """
        raise NotImplementedError("Payment channel implementation pending")

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
        """
        raise NotImplementedError("Payment channel implementation pending")
