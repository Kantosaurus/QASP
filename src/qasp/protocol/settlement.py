"""Payment channel settlement.

This module implements payment channels for settling
usage receipts in QASP.
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass
from enum import Enum, auto

import cbor2

from qasp.crypto.signatures import sign, verify
from qasp.framing.messages import (
    ChannelClose,
    ChannelOpen,
    PriceAccept,
    PriceOffer,
    PriceRequest,
)
from qasp.protocol.accounting import ReceiptChain
from qasp.protocol.events import (
    ChannelChallengeExpired,
    ChannelClosed,
    ChannelClosing,
    ChannelDisputed,
    ChannelOpened,
    ChannelOpening,
    ChannelStateUpdated,
    PriceAccepted,
    PriceOfferReceived,
    VerdictEnforced,
)

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


@dataclass(frozen=True)
class PriceSchedule:
    """Negotiated price schedule for metered usage."""

    resource_type: str
    unit_price: int
    currency: str
    valid_from: int
    valid_until: int
    offerer_signature: bytes
    accepter_signature: bytes

    def to_cbor(self) -> bytes:
        return cbor2.dumps({
            "resource_type": self.resource_type,
            "unit_price": self.unit_price,
            "currency": self.currency,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "offerer_signature": self.offerer_signature,
            "accepter_signature": self.accepter_signature,
        })

    @classmethod
    def from_cbor(cls, data: bytes) -> PriceSchedule:
        d = cbor2.loads(data)
        return cls(
            resource_type=d["resource_type"],
            unit_price=d["unit_price"],
            currency=d["currency"],
            valid_from=d["valid_from"],
            valid_until=d["valid_until"],
            offerer_signature=bytes(d["offerer_signature"]),
            accepter_signature=bytes(d["accepter_signature"]),
        )


def _offer_signable(offer: PriceOffer) -> bytes:
    """Return canonical bytes for signing a price offer."""
    return cbor2.dumps({
        "request_id": offer.request_id,
        "resource_type": offer.resource_type,
        "unit_price": offer.unit_price,
        "currency": offer.currency,
        "valid_from": offer.valid_from,
        "valid_until": offer.valid_until,
    })


def _accept_signable(accept: PriceAccept) -> bytes:
    """Return canonical bytes for signing a price accept."""
    return cbor2.dumps({
        "request_id": accept.request_id,
        "offer_signature": accept.offer_signature,
        "resource_type": accept.resource_type,
        "unit_price": accept.unit_price,
        "currency": accept.currency,
        "valid_from": accept.valid_from,
        "valid_until": accept.valid_until,
    })


class PriceNegotiator:
    """Negotiates pricing between channel parties."""

    def __init__(self) -> None:
        self._offers: dict[bytes, PriceOffer] = {}

    def create_price_request(
        self,
        resource_type: str,
        resource_id: bytes,
        quantity: int,
        duration: int,
    ) -> tuple[PriceRequest, list]:
        request = PriceRequest(
            request_id=os.urandom(16),
            resource_type=resource_type,
            resource_id=resource_id,
            quantity=quantity,
            duration=duration,
        )
        return request, []

    def create_price_offer(
        self,
        request: PriceRequest,
        unit_price: int,
        currency: str,
        signing_key: bytes,
    ) -> tuple[PriceOffer, list]:
        now = int(time.time())
        offer = PriceOffer(
            request_id=request.request_id,
            resource_type=request.resource_type,
            unit_price=unit_price,
            currency=currency,
            valid_from=now,
            valid_until=now + request.duration,
            signature=b"",
        )
        sig = sign(signing_key, _offer_signable(offer))
        offer = PriceOffer(
            request_id=offer.request_id,
            resource_type=offer.resource_type,
            unit_price=offer.unit_price,
            currency=offer.currency,
            valid_from=offer.valid_from,
            valid_until=offer.valid_until,
            signature=sig,
        )
        self._offers[request.request_id] = offer
        return offer, []

    def process_price_offer(
        self,
        offer: PriceOffer,
        public_key: bytes,
    ) -> list:
        signable = _offer_signable(PriceOffer(
            request_id=offer.request_id,
            resource_type=offer.resource_type,
            unit_price=offer.unit_price,
            currency=offer.currency,
            valid_from=offer.valid_from,
            valid_until=offer.valid_until,
            signature=b"",
        ))
        try:
            verify(public_key, signable, offer.signature)
        except Exception as e:
            raise InvalidPriceError(
                f"Invalid price offer signature: {e}"
            ) from e

        self._offers[offer.request_id] = offer
        return [PriceOfferReceived(
            resource_type=offer.resource_type,
            unit_price=offer.unit_price,
            currency=offer.currency,
            valid_until=offer.valid_until,
        )]

    def create_price_accept(
        self,
        offer: PriceOffer,
        signing_key: bytes,
    ) -> tuple[PriceAccept, list]:
        accept = PriceAccept(
            request_id=offer.request_id,
            offer_signature=offer.signature,
            resource_type=offer.resource_type,
            unit_price=offer.unit_price,
            currency=offer.currency,
            valid_from=offer.valid_from,
            valid_until=offer.valid_until,
            signature=b"",
        )
        sig = sign(signing_key, _accept_signable(accept))
        accept = PriceAccept(
            request_id=accept.request_id,
            offer_signature=accept.offer_signature,
            resource_type=accept.resource_type,
            unit_price=accept.unit_price,
            currency=accept.currency,
            valid_from=accept.valid_from,
            valid_until=accept.valid_until,
            signature=sig,
        )
        return accept, []

    def process_price_accept(
        self,
        accept: PriceAccept,
        public_key: bytes,
    ) -> tuple[PriceSchedule, list]:
        signable = _accept_signable(PriceAccept(
            request_id=accept.request_id,
            offer_signature=accept.offer_signature,
            resource_type=accept.resource_type,
            unit_price=accept.unit_price,
            currency=accept.currency,
            valid_from=accept.valid_from,
            valid_until=accept.valid_until,
            signature=b"",
        ))
        try:
            verify(public_key, signable, accept.signature)
        except Exception as e:
            raise InvalidPriceError(
                f"Invalid price accept signature: {e}"
            ) from e

        offer = self._offers.get(accept.request_id)
        offerer_sig = offer.signature if offer else b""

        schedule = PriceSchedule(
            resource_type=accept.resource_type,
            unit_price=accept.unit_price,
            currency=accept.currency,
            valid_from=accept.valid_from,
            valid_until=accept.valid_until,
            offerer_signature=offerer_sig,
            accepter_signature=accept.signature,
        )
        return schedule, [PriceAccepted(
            resource_type=accept.resource_type,
            unit_price=accept.unit_price,
            currency=accept.currency,
        )]


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
    sequence_number: int
    agent_balance: int
    server_balance: int
    prev_hash: bytes
    timestamp: int
    agent_signature: bytes
    server_signature: bytes

    def signable_bytes(self) -> bytes:
        """Return CBOR-encoded bytes for signing (excludes signatures)."""
        return cbor2.dumps({
            "channel_id": self.channel_id,
            "sequence_number": self.sequence_number,
            "agent_balance": self.agent_balance,
            "server_balance": self.server_balance,
            "prev_hash": self.prev_hash,
            "timestamp": self.timestamp,
        })

    def compute_hash(self) -> bytes:
        """Compute SHA-384 hash of the full state (including signatures)."""
        return hashlib.sha384(self.to_cbor()).digest()

    def to_cbor(self) -> bytes:
        """Serialize the full state update to CBOR."""
        return cbor2.dumps({
            "channel_id": self.channel_id,
            "sequence_number": self.sequence_number,
            "agent_balance": self.agent_balance,
            "server_balance": self.server_balance,
            "prev_hash": self.prev_hash,
            "timestamp": self.timestamp,
            "agent_signature": self.agent_signature,
            "server_signature": self.server_signature,
        })

    @classmethod
    def from_cbor(cls, data: bytes) -> ChannelStateUpdate:
        """Deserialize a state update from CBOR."""
        d = cbor2.loads(data)
        return cls(
            channel_id=bytes(d["channel_id"]),
            sequence_number=d["sequence_number"],
            agent_balance=d["agent_balance"],
            server_balance=d["server_balance"],
            prev_hash=bytes(d["prev_hash"]),
            timestamp=d["timestamp"],
            agent_signature=bytes(d["agent_signature"]),
            server_signature=bytes(d["server_signature"]),
        )


@dataclass(frozen=True)
class Settlement:
    """A settlement record."""

    channel_id: bytes
    final_balance_a: int
    final_balance_b: int
    payer: str
    payee: str
    timestamp: int
    receipt_hash: bytes
    signatures: tuple[bytes, bytes]


class PaymentChannel:
    """A bidirectional payment channel."""

    def __init__(
        self,
        agent_did: str,
        server_did: str,
        agent_public_key: bytes,
        server_public_key: bytes,
    ) -> None:
        self._agent_did = agent_did
        self._server_did = server_did
        self._agent_public_key = agent_public_key
        self._server_public_key = server_public_key
        self._agent_balance = 0
        self._server_balance = 0
        self._channel_id: bytes | None = None
        self._state = ChannelState.OPENING
        self._sequence = 0
        self._states: list[ChannelStateUpdate] = []
        self._challenge_deadline: int = 0
        self._receipt_chain_hash: bytes | None = None

    @property
    def agent_balance(self) -> int:
        return self._agent_balance

    @property
    def server_balance(self) -> int:
        return self._server_balance

    @property
    def channel_id(self) -> bytes | None:
        return self._channel_id

    @property
    def state(self) -> ChannelState:
        return self._state

    @property
    def sequence_number(self) -> int:
        return self._sequence

    # ------------------------------------------------------------------
    # Channel open handshake
    # ------------------------------------------------------------------

    def create_channel_open(
        self, initial_balance: int,
    ) -> tuple[ChannelOpen, list]:
        if self._state != ChannelState.OPENING:
            raise ChannelNotOpenError("Channel already opened")

        self._channel_id = os.urandom(32)
        self._agent_balance = initial_balance

        open_msg = ChannelOpen(
            channel_id=self._channel_id,
            initial_balance=initial_balance,
        )
        return open_msg, [ChannelOpening(
            channel_id=self._channel_id,
            peer_id=self._server_did.encode(),
            initial_balance=initial_balance,
        )]

    def process_channel_open(
        self, open_msg: ChannelOpen, server_balance: int,
    ) -> tuple[ChannelOpen, list]:
        self._channel_id = open_msg.channel_id
        self._agent_balance = open_msg.initial_balance
        self._server_balance = server_balance
        self._state = ChannelState.OPEN

        response = ChannelOpen(
            channel_id=self._channel_id,
            initial_balance=server_balance,
        )
        return response, [ChannelOpened(
            channel_id=self._channel_id,
            agent_balance=self._agent_balance,
            server_balance=self._server_balance,
        )]

    def accept_channel(self, response: ChannelOpen) -> list:
        self._server_balance = response.initial_balance
        self._state = ChannelState.OPEN

        return [ChannelOpened(
            channel_id=self._channel_id,
            agent_balance=self._agent_balance,
            server_balance=self._server_balance,
        )]

    # ------------------------------------------------------------------
    # Off-chain state updates
    # ------------------------------------------------------------------

    def create_state_update(
        self,
        cost: int,
        signing_key: bytes,
        from_agent_to_server: bool = True,
    ) -> tuple[ChannelStateUpdate, list]:
        if self._state != ChannelState.OPEN:
            raise ChannelNotOpenError("Channel is not open")

        if from_agent_to_server:
            new_agent = self._agent_balance - cost
            new_server = self._server_balance + cost
        else:
            new_agent = self._agent_balance + cost
            new_server = self._server_balance - cost

        if new_agent < 0 or new_server < 0:
            raise InsufficientBalanceError("Insufficient balance")

        self._sequence += 1

        if self._receipt_chain_hash is not None:
            prev_hash = self._receipt_chain_hash
            self._receipt_chain_hash = None
        elif self._states:
            prev_hash = self._states[-1].compute_hash()
        else:
            prev_hash = b""

        update = ChannelStateUpdate(
            channel_id=self._channel_id,
            sequence_number=self._sequence,
            agent_balance=new_agent,
            server_balance=new_server,
            prev_hash=prev_hash,
            timestamp=int(time.time()),
            agent_signature=b"",
            server_signature=b"",
        )
        sig = sign(signing_key, update.signable_bytes())

        if from_agent_to_server:
            update = ChannelStateUpdate(
                channel_id=update.channel_id,
                sequence_number=update.sequence_number,
                agent_balance=update.agent_balance,
                server_balance=update.server_balance,
                prev_hash=update.prev_hash,
                timestamp=update.timestamp,
                agent_signature=sig,
                server_signature=b"",
            )
        else:
            update = ChannelStateUpdate(
                channel_id=update.channel_id,
                sequence_number=update.sequence_number,
                agent_balance=update.agent_balance,
                server_balance=update.server_balance,
                prev_hash=update.prev_hash,
                timestamp=update.timestamp,
                agent_signature=b"",
                server_signature=sig,
            )

        return update, []

    def countersign_state_update(
        self,
        update: ChannelStateUpdate,
        signing_key: bytes,
    ) -> tuple[ChannelStateUpdate, list]:
        expected_seq = self._sequence + 1
        if update.sequence_number != expected_seq:
            raise InvalidStateUpdateError(
                f"Expected sequence {expected_seq}, "
                f"got {update.sequence_number}"
            )

        sig = sign(signing_key, update.signable_bytes())

        if update.agent_signature == b"":
            signed = ChannelStateUpdate(
                channel_id=update.channel_id,
                sequence_number=update.sequence_number,
                agent_balance=update.agent_balance,
                server_balance=update.server_balance,
                prev_hash=update.prev_hash,
                timestamp=update.timestamp,
                agent_signature=sig,
                server_signature=update.server_signature,
            )
        else:
            signed = ChannelStateUpdate(
                channel_id=update.channel_id,
                sequence_number=update.sequence_number,
                agent_balance=update.agent_balance,
                server_balance=update.server_balance,
                prev_hash=update.prev_hash,
                timestamp=update.timestamp,
                agent_signature=update.agent_signature,
                server_signature=sig,
            )

        self._sequence = signed.sequence_number
        self._agent_balance = signed.agent_balance
        self._server_balance = signed.server_balance
        self._states.append(signed)

        return signed, [ChannelStateUpdated(
            channel_id=signed.channel_id,
            sequence_number=signed.sequence_number,
            agent_balance=signed.agent_balance,
            server_balance=signed.server_balance,
        )]

    def apply_state_update(self, signed: ChannelStateUpdate) -> None:
        self._sequence = signed.sequence_number
        self._agent_balance = signed.agent_balance
        self._server_balance = signed.server_balance
        self._states.append(signed)

    # ------------------------------------------------------------------
    # Cooperative close
    # ------------------------------------------------------------------

    def create_channel_close(
        self, signing_key: bytes,
    ) -> tuple[ChannelClose, list]:
        signable = cbor2.dumps({
            "channel_id": self._channel_id,
            "final_balance_a": self._agent_balance,
            "final_balance_b": self._server_balance,
            "close_reason": CLOSE_REASON_COOPERATIVE,
        })
        sig = sign(signing_key, signable)

        close_msg = ChannelClose(
            channel_id=self._channel_id,
            final_balance_a=self._agent_balance,
            final_balance_b=self._server_balance,
            close_reason=CLOSE_REASON_COOPERATIVE,
            signatures=(sig, b""),
        )
        return close_msg, [ChannelClosing(
            channel_id=self._channel_id,
            close_reason=0,
            unilateral=False,
        )]

    def countersign_close(
        self,
        close_msg: ChannelClose,
        signing_key: bytes,
    ) -> tuple[ChannelClose, list]:
        signable = cbor2.dumps({
            "channel_id": close_msg.channel_id,
            "final_balance_a": close_msg.final_balance_a,
            "final_balance_b": close_msg.final_balance_b,
            "close_reason": close_msg.close_reason,
        })
        sig = sign(signing_key, signable)

        signed_close = ChannelClose(
            channel_id=close_msg.channel_id,
            final_balance_a=close_msg.final_balance_a,
            final_balance_b=close_msg.final_balance_b,
            close_reason=close_msg.close_reason,
            signatures=(close_msg.signatures[0], sig),
        )
        self._state = ChannelState.CLOSED

        return signed_close, [ChannelClosed(
            channel_id=close_msg.channel_id,
            final_balance_a=close_msg.final_balance_a,
            final_balance_b=close_msg.final_balance_b,
        )]

    # ------------------------------------------------------------------
    # Unilateral close & dispute
    # ------------------------------------------------------------------

    def create_unilateral_close(
        self,
        signing_key: bytes,
        current_time: int,
    ) -> tuple[ChannelClose, list]:
        self._state = ChannelState.CLOSING
        self._challenge_deadline = current_time + CHALLENGE_PERIOD_SECONDS

        signable = cbor2.dumps({
            "channel_id": self._channel_id,
            "final_balance_a": self._agent_balance,
            "final_balance_b": self._server_balance,
            "close_reason": CLOSE_REASON_UNILATERAL,
        })
        sig = sign(signing_key, signable)

        close_msg = ChannelClose(
            channel_id=self._channel_id,
            final_balance_a=self._agent_balance,
            final_balance_b=self._server_balance,
            close_reason=CLOSE_REASON_UNILATERAL,
            signatures=(sig, b""),
        )
        return close_msg, [ChannelClosing(
            channel_id=self._channel_id,
            close_reason=1,
            unilateral=True,
        )]

    def finalize_close(
        self, current_time: int,
    ) -> tuple[Settlement, list]:
        if current_time < self._challenge_deadline:
            raise ChannelTimeoutError("Challenge period has not expired")

        self._state = ChannelState.CLOSED

        settlement = Settlement(
            channel_id=self._channel_id,
            final_balance_a=self._agent_balance,
            final_balance_b=self._server_balance,
            payer=self._agent_did,
            payee=self._server_did,
            timestamp=current_time,
            receipt_hash=b"",
            signatures=(b"", b""),
        )
        return settlement, [
            ChannelChallengeExpired(channel_id=self._channel_id),
            ChannelClosed(
                channel_id=self._channel_id,
                final_balance_a=self._agent_balance,
                final_balance_b=self._server_balance,
            ),
        ]

    def challenge(
        self,
        state_update: ChannelStateUpdate,
        current_time: int,
    ) -> list:
        if current_time >= self._challenge_deadline:
            raise ChallengeError("Challenge period has expired")

        if state_update.sequence_number <= self._sequence:
            raise ChallengeError(
                "Submitted state is not newer than current state"
            )

        old_sequence = self._sequence
        self._state = ChannelState.DISPUTED
        self._sequence = state_update.sequence_number
        self._agent_balance = state_update.agent_balance
        self._server_balance = state_update.server_balance

        return [ChannelDisputed(
            channel_id=self._channel_id,
            challenged_sequence=old_sequence,
            newer_sequence=state_update.sequence_number,
        )]

    # ------------------------------------------------------------------
    # Receipt chain linkage
    # ------------------------------------------------------------------

    def link_to_receipt_chain(self, chain: ReceiptChain) -> None:
        receipts = chain.receipts
        if receipts:
            self._receipt_chain_hash = receipts[-1].compute_hash()

    # ------------------------------------------------------------------
    # Verdict enforcement
    # ------------------------------------------------------------------

    def apply_verdict(
        self,
        verdict: object,
        signing_key: bytes,
        auditor_public_key: bytes,
    ) -> tuple[ChannelStateUpdate, list]:
        """Apply an auditor's binding verdict to the channel.

        Verifies the verdict signature, computes a balance adjustment,
        creates a new state update, and transitions from DISPUTED to OPEN.

        Args:
            verdict: A DisputeVerdict message from the auditor.
            signing_key: Local party's signing key for the new state update.
            auditor_public_key: Auditor's public key for verdict verification.

        Returns:
            (state_update, events) — the new state and enforcement events.

        Raises:
            SettlementError: If the channel is not in DISPUTED state.
            SettlementError: If the verdict signature is invalid.
        """
        if self._state != ChannelState.DISPUTED:
            raise SettlementError(
                f"Cannot apply verdict: channel is {self._state.name}, "
                f"expected DISPUTED"
            )

        # Verify auditor's verdict signature
        from qasp.protocol.dispute import VerdictCode

        verdict_data = (
            verdict.dispute_id
            + int(verdict.verdict).to_bytes(4, "big")
            + verdict.awarded_value.to_bytes(8, "big", signed=True)
        )
        try:
            verify(auditor_public_key, verdict_data, verdict.signature)
        except Exception as e:
            raise SettlementError(
                f"Verdict signature verification failed: {e}"
            ) from e

        # Compute adjustment based on verdict
        verdict_code = VerdictCode(verdict.verdict)
        adjustment = 0
        if verdict_code == VerdictCode.CLAIMANT_WINS:
            adjustment = verdict.awarded_value
        elif verdict_code == VerdictCode.SPLIT:
            adjustment = verdict.awarded_value

        # Apply adjustment: transfer from server to agent
        new_agent = self._agent_balance + adjustment
        new_server = self._server_balance - adjustment

        # Clamp to non-negative
        if new_server < 0:
            adjustment = self._server_balance
            new_agent = self._agent_balance + adjustment
            new_server = 0

        self._agent_balance = new_agent
        self._server_balance = new_server
        self._state = ChannelState.OPEN

        # Create a new state update reflecting the adjustment
        self._sequence += 1
        prev_hash = self._states[-1].compute_hash() if self._states else b""

        update = ChannelStateUpdate(
            channel_id=self._channel_id,
            sequence_number=self._sequence,
            agent_balance=new_agent,
            server_balance=new_server,
            prev_hash=prev_hash,
            timestamp=int(time.time()),
            agent_signature=b"",
            server_signature=b"",
        )
        sig = sign(signing_key, update.signable_bytes())
        update = ChannelStateUpdate(
            channel_id=update.channel_id,
            sequence_number=update.sequence_number,
            agent_balance=update.agent_balance,
            server_balance=update.server_balance,
            prev_hash=update.prev_hash,
            timestamp=update.timestamp,
            agent_signature=sig,
            server_signature=b"",
        )
        self._states.append(update)

        events = [VerdictEnforced(
            channel_id=self._channel_id,
            dispute_id=verdict.dispute_id,
            adjustment=adjustment,
            new_agent_balance=new_agent,
            new_server_balance=new_server,
        )]
        return update, events
