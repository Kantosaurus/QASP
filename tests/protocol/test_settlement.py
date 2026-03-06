"""Tests for payment channel settlement."""

from __future__ import annotations

import pytest

from qasp.crypto.signatures import generate_keypair
from qasp.framing.messages import ChannelClose, ChannelOpen, PriceAccept, PriceOffer
from qasp.protocol.accounting import Receipt, ReceiptChain
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
)
from qasp.protocol.settlement import (
    CHALLENGE_PERIOD_SECONDS,
    CLOSE_REASON_COOPERATIVE,
    CLOSE_REASON_UNILATERAL,
    ChannelNotOpenError,
    ChannelState,
    ChannelStateUpdate,
    ChannelTimeoutError,
    ChallengeError,
    InsufficientBalanceError,
    InvalidPriceError,
    InvalidStateUpdateError,
    PaymentChannel,
    PriceNegotiator,
    PriceSchedule,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def agent_keypair() -> tuple[bytes, bytes]:
    return generate_keypair()


@pytest.fixture
def agent_public_key(agent_keypair: tuple[bytes, bytes]) -> bytes:
    return agent_keypair[0]


@pytest.fixture
def agent_secret_key(agent_keypair: tuple[bytes, bytes]) -> bytes:
    return agent_keypair[1]


@pytest.fixture
def server_keypair() -> tuple[bytes, bytes]:
    return generate_keypair()


@pytest.fixture
def server_public_key(server_keypair: tuple[bytes, bytes]) -> bytes:
    return server_keypair[0]


@pytest.fixture
def server_secret_key(server_keypair: tuple[bytes, bytes]) -> bytes:
    return server_keypair[1]


@pytest.fixture
def agent_did() -> str:
    return "did:qasp:agent001"


@pytest.fixture
def server_did() -> str:
    return "did:qasp:server001"


@pytest.fixture
def agent_channel(
    agent_did: str,
    server_did: str,
    agent_public_key: bytes,
    server_public_key: bytes,
) -> PaymentChannel:
    return PaymentChannel(agent_did, server_did, agent_public_key, server_public_key)


@pytest.fixture
def server_channel(
    agent_did: str,
    server_did: str,
    agent_public_key: bytes,
    server_public_key: bytes,
) -> PaymentChannel:
    return PaymentChannel(agent_did, server_did, agent_public_key, server_public_key)


def _open_channel(
    agent_ch: PaymentChannel,
    server_ch: PaymentChannel,
    agent_balance: int = 1000,
    server_balance: int = 500,
) -> None:
    """Helper: complete channel open handshake."""
    open_msg, _ = agent_ch.create_channel_open(agent_balance)
    response, _ = server_ch.process_channel_open(open_msg, server_balance)
    agent_ch.accept_channel(response)


def _do_transfer(
    initiator: PaymentChannel,
    countersigner: PaymentChannel,
    cost: int,
    initiator_sk: bytes,
    countersigner_sk: bytes,
    from_agent_to_server: bool = True,
) -> ChannelStateUpdate:
    """Helper: create, countersign, and apply a state update."""
    update, _ = initiator.create_state_update(
        cost=cost,
        signing_key=initiator_sk,
        from_agent_to_server=from_agent_to_server,
    )
    signed, _ = countersigner.countersign_state_update(update, countersigner_sk)
    initiator.apply_state_update(signed)
    return signed


# =============================================================================
# TestPriceNegotiation
# =============================================================================


class TestPriceNegotiation:
    """Tests for price negotiation flow."""

    def test_full_price_negotiation_flow(
        self,
        agent_secret_key: bytes,
        agent_public_key: bytes,
        server_secret_key: bytes,
        server_public_key: bytes,
    ) -> None:
        negotiator = PriceNegotiator()

        # Agent creates request
        request, _ = negotiator.create_price_request(
            resource_type="compute",
            resource_id=b"res_001",
            quantity=100,
            duration=3600,
        )
        assert request.resource_type == "compute"
        assert len(request.request_id) > 0

        # Server creates offer
        offer, _ = negotiator.create_price_offer(
            request, unit_price=10, currency="credits",
            signing_key=server_secret_key,
        )
        assert isinstance(offer, PriceOffer)
        assert offer.unit_price == 10
        assert offer.currency == "credits"
        assert len(offer.signature) > 0

        # Agent verifies and processes offer
        events = negotiator.process_price_offer(offer, server_public_key)
        assert len(events) == 1
        assert isinstance(events[0], PriceOfferReceived)
        assert events[0].unit_price == 10

        # Agent accepts
        accept, _ = negotiator.create_price_accept(offer, agent_secret_key)
        assert isinstance(accept, PriceAccept)
        assert accept.offer_signature == offer.signature

        # Server processes accept
        schedule, events = negotiator.process_price_accept(accept, agent_public_key)
        assert isinstance(schedule, PriceSchedule)
        assert schedule.unit_price == 10
        assert schedule.currency == "credits"
        assert len(events) == 1
        assert isinstance(events[0], PriceAccepted)

    def test_price_offer_signature_verification(
        self,
        server_secret_key: bytes,
        agent_public_key: bytes,
    ) -> None:
        """Verifying offer with wrong key should fail."""
        negotiator = PriceNegotiator()
        request, _ = negotiator.create_price_request(
            "compute", b"res", 1, 60,
        )
        offer, _ = negotiator.create_price_offer(
            request, 5, "credits", server_secret_key,
        )
        # Verify with wrong key
        with pytest.raises(InvalidPriceError):
            negotiator.process_price_offer(offer, agent_public_key)

    def test_price_accept_signature_verification(
        self,
        agent_secret_key: bytes,
        server_secret_key: bytes,
        server_public_key: bytes,
    ) -> None:
        """Verifying accept with wrong key should fail."""
        negotiator = PriceNegotiator()
        request, _ = negotiator.create_price_request(
            "compute", b"res", 1, 60,
        )
        offer, _ = negotiator.create_price_offer(
            request, 5, "credits", server_secret_key,
        )
        negotiator.process_price_offer(offer, server_public_key)
        accept, _ = negotiator.create_price_accept(offer, agent_secret_key)

        # Verify with wrong key (server key instead of agent key)
        with pytest.raises(InvalidPriceError):
            negotiator.process_price_accept(accept, server_public_key)


# =============================================================================
# TestChannelOpen
# =============================================================================


class TestChannelOpen:
    """Tests for channel open flow."""

    def test_create_process_accept(
        self,
        agent_channel: PaymentChannel,
        server_channel: PaymentChannel,
    ) -> None:
        open_msg, events = agent_channel.create_channel_open(1000)
        assert isinstance(open_msg, ChannelOpen)
        assert open_msg.initial_balance == 1000
        assert len(events) == 1
        assert isinstance(events[0], ChannelOpening)
        assert agent_channel.state == ChannelState.OPENING

        response, events = server_channel.process_channel_open(open_msg, 500)
        assert isinstance(response, ChannelOpen)
        assert response.initial_balance == 500
        assert server_channel.state == ChannelState.OPEN
        assert len(events) == 1
        assert isinstance(events[0], ChannelOpened)
        assert events[0].agent_balance == 1000
        assert events[0].server_balance == 500

        events = agent_channel.accept_channel(response)
        assert agent_channel.state == ChannelState.OPEN
        assert agent_channel.agent_balance == 1000
        assert agent_channel.server_balance == 500
        assert len(events) == 1
        assert isinstance(events[0], ChannelOpened)

    def test_state_transitions(
        self,
        agent_channel: PaymentChannel,
        server_channel: PaymentChannel,
    ) -> None:
        assert agent_channel.state == ChannelState.OPENING
        _open_channel(agent_channel, server_channel)
        assert agent_channel.state == ChannelState.OPEN
        assert server_channel.state == ChannelState.OPEN

    def test_double_open_guard(
        self,
        agent_channel: PaymentChannel,
        server_channel: PaymentChannel,
    ) -> None:
        _open_channel(agent_channel, server_channel)
        with pytest.raises(ChannelNotOpenError):
            agent_channel.create_channel_open(500)


# =============================================================================
# TestStateUpdates
# =============================================================================


class TestStateUpdates:
    """Tests for off-chain state updates."""

    def test_basic_transfer(
        self,
        agent_channel: PaymentChannel,
        server_channel: PaymentChannel,
        agent_secret_key: bytes,
        server_secret_key: bytes,
    ) -> None:
        _open_channel(agent_channel, server_channel)

        update, _ = agent_channel.create_state_update(
            cost=100, signing_key=agent_secret_key,
        )
        assert update.agent_balance == 900
        assert update.server_balance == 600
        assert update.sequence_number == 1
        assert len(update.agent_signature) > 0
        assert update.server_signature == b""

        signed, events = server_channel.countersign_state_update(
            update, server_secret_key,
        )
        assert len(signed.server_signature) > 0
        assert len(signed.agent_signature) > 0
        assert len(events) == 1
        assert isinstance(events[0], ChannelStateUpdated)
        assert events[0].agent_balance == 900
        assert events[0].server_balance == 600

        # Apply to initiator
        agent_channel.apply_state_update(signed)

    def test_conservation_invariant(
        self,
        agent_channel: PaymentChannel,
        server_channel: PaymentChannel,
        agent_secret_key: bytes,
        server_secret_key: bytes,
    ) -> None:
        _open_channel(agent_channel, server_channel, 1000, 500)
        total = 1500

        for cost in [100, 200, 50]:
            signed = _do_transfer(
                agent_channel, server_channel, cost,
                agent_secret_key, server_secret_key,
            )
            assert signed.agent_balance + signed.server_balance == total

    def test_hash_chain(
        self,
        agent_channel: PaymentChannel,
        server_channel: PaymentChannel,
        agent_secret_key: bytes,
        server_secret_key: bytes,
    ) -> None:
        _open_channel(agent_channel, server_channel)

        updates: list[ChannelStateUpdate] = []
        for cost in [50, 30, 20]:
            signed = _do_transfer(
                agent_channel, server_channel, cost,
                agent_secret_key, server_secret_key,
            )
            updates.append(signed)

        # Each update's prev_hash should match the previous update's hash
        for i in range(1, len(updates)):
            assert updates[i].prev_hash == updates[i - 1].compute_hash()

    def test_insufficient_balance(
        self,
        agent_channel: PaymentChannel,
        server_channel: PaymentChannel,
        agent_secret_key: bytes,
    ) -> None:
        _open_channel(agent_channel, server_channel, 100, 50)

        with pytest.raises(InsufficientBalanceError):
            agent_channel.create_state_update(
                cost=200, signing_key=agent_secret_key,
            )

    def test_server_to_agent_transfer(
        self,
        agent_channel: PaymentChannel,
        server_channel: PaymentChannel,
        agent_secret_key: bytes,
        server_secret_key: bytes,
    ) -> None:
        _open_channel(agent_channel, server_channel, 1000, 500)

        update, _ = server_channel.create_state_update(
            cost=100, signing_key=server_secret_key,
            from_agent_to_server=False,
        )
        assert update.agent_balance == 1100
        assert update.server_balance == 400
        assert len(update.server_signature) > 0
        assert update.agent_signature == b""

        signed, events = agent_channel.countersign_state_update(
            update, agent_secret_key,
        )
        assert signed.agent_balance == 1100
        assert signed.server_balance == 400
        server_channel.apply_state_update(signed)

    def test_countersign_validates_sequence(
        self,
        agent_channel: PaymentChannel,
        server_channel: PaymentChannel,
        agent_secret_key: bytes,
        server_secret_key: bytes,
    ) -> None:
        _open_channel(agent_channel, server_channel)

        # Do one normal update first
        _do_transfer(
            agent_channel, server_channel, 50,
            agent_secret_key, server_secret_key,
        )

        # Create another update from agent (seq=2)
        update2, _ = agent_channel.create_state_update(
            cost=50, signing_key=agent_secret_key,
        )

        # Tamper with sequence
        bad_update = ChannelStateUpdate(
            channel_id=update2.channel_id,
            sequence_number=99,  # Wrong sequence
            agent_balance=update2.agent_balance,
            server_balance=update2.server_balance,
            prev_hash=update2.prev_hash,
            timestamp=update2.timestamp,
            agent_signature=update2.agent_signature,
            server_signature=update2.server_signature,
        )
        with pytest.raises(InvalidStateUpdateError):
            server_channel.countersign_state_update(bad_update, server_secret_key)


# =============================================================================
# TestCooperativeClose
# =============================================================================


class TestCooperativeClose:
    """Tests for cooperative channel close."""

    def test_cooperative_close_flow(
        self,
        agent_channel: PaymentChannel,
        server_channel: PaymentChannel,
        agent_secret_key: bytes,
        server_secret_key: bytes,
    ) -> None:
        _open_channel(agent_channel, server_channel, 1000, 500)

        # Do a transfer first
        _do_transfer(
            agent_channel, server_channel, 200,
            agent_secret_key, server_secret_key,
        )

        # Agent initiates close
        close_msg, events = agent_channel.create_channel_close(agent_secret_key)
        assert isinstance(close_msg, ChannelClose)
        assert close_msg.final_balance_a == 800
        assert close_msg.final_balance_b == 700
        assert close_msg.close_reason == CLOSE_REASON_COOPERATIVE
        assert len(events) == 1
        assert isinstance(events[0], ChannelClosing)
        assert events[0].unilateral is False

        # Server countersigns
        signed_close, events = server_channel.countersign_close(
            close_msg, server_secret_key,
        )
        assert server_channel.state == ChannelState.CLOSED
        assert len(signed_close.signatures[0]) > 0
        assert len(signed_close.signatures[1]) > 0
        assert len(events) == 1
        assert isinstance(events[0], ChannelClosed)
        assert events[0].final_balance_a == 800
        assert events[0].final_balance_b == 700


# =============================================================================
# TestUnilateralClose
# =============================================================================


class TestUnilateralClose:
    """Tests for unilateral close with challenge period."""

    def test_unilateral_close_and_finalize(
        self,
        agent_channel: PaymentChannel,
        server_channel: PaymentChannel,
        agent_secret_key: bytes,
        server_secret_key: bytes,
    ) -> None:
        _open_channel(agent_channel, server_channel, 1000, 500)
        now = 1_000_000

        close_msg, events = agent_channel.create_unilateral_close(
            agent_secret_key, current_time=now,
        )
        assert agent_channel.state == ChannelState.CLOSING
        assert isinstance(close_msg, ChannelClose)
        assert close_msg.close_reason == CLOSE_REASON_UNILATERAL
        assert len(events) == 1
        assert isinstance(events[0], ChannelClosing)
        assert events[0].unilateral is True

        # Cannot finalize before challenge expires
        with pytest.raises(ChannelTimeoutError):
            agent_channel.finalize_close(current_time=now + 100)

        # Finalize after challenge
        settlement, events = agent_channel.finalize_close(
            current_time=now + CHALLENGE_PERIOD_SECONDS,
        )
        assert agent_channel.state == ChannelState.CLOSED
        assert settlement.final_balance_a == 1000
        assert settlement.final_balance_b == 500
        assert len(events) == 2
        assert isinstance(events[0], ChannelChallengeExpired)
        assert isinstance(events[1], ChannelClosed)

    def test_challenge_with_newer_state(
        self,
        agent_channel: PaymentChannel,
        server_channel: PaymentChannel,
        agent_secret_key: bytes,
        server_secret_key: bytes,
    ) -> None:
        _open_channel(agent_channel, server_channel, 1000, 500)

        # Create two state updates
        _do_transfer(
            agent_channel, server_channel, 100,
            agent_secret_key, server_secret_key,
        )
        _do_transfer(
            agent_channel, server_channel, 200,
            agent_secret_key, server_secret_key,
        )

        # Create a third update (seq=3) — server refunds 50
        signed3 = _do_transfer(
            server_channel, agent_channel, 50,
            server_secret_key, agent_secret_key,
            from_agent_to_server=False,
        )

        # Set up a "challenger" channel simulating unilateral close at seq=2
        now = 1_000_000
        challenger = PaymentChannel(
            agent_channel._agent_did,
            agent_channel._server_did,
            agent_channel._agent_public_key,
            agent_channel._server_public_key,
        )
        challenger._channel_id = agent_channel._channel_id
        challenger._state = ChannelState.CLOSING
        challenger._sequence = 2
        challenger._challenge_deadline = now + CHALLENGE_PERIOD_SECONDS
        challenger._agent_balance = 700
        challenger._server_balance = 800

        events = challenger.challenge(signed3, current_time=now + 100)
        assert challenger._state == ChannelState.DISPUTED
        assert len(events) == 1
        assert isinstance(events[0], ChannelDisputed)
        assert events[0].challenged_sequence == 2
        assert events[0].newer_sequence == 3
        assert challenger._agent_balance == signed3.agent_balance
        assert challenger._server_balance == signed3.server_balance

    def test_challenge_with_older_state_rejected(
        self,
        agent_channel: PaymentChannel,
        server_channel: PaymentChannel,
        agent_secret_key: bytes,
        server_secret_key: bytes,
    ) -> None:
        _open_channel(agent_channel, server_channel, 1000, 500)

        signed1 = _do_transfer(
            agent_channel, server_channel, 100,
            agent_secret_key, server_secret_key,
        )
        _do_transfer(
            agent_channel, server_channel, 200,
            agent_secret_key, server_secret_key,
        )

        now = 1_000_000
        agent_channel.create_unilateral_close(
            agent_secret_key, current_time=now,
        )

        # Try challenging with older state (seq=1)
        with pytest.raises(ChallengeError, match="not newer"):
            agent_channel.challenge(signed1, current_time=now + 100)

    def test_challenge_after_expiry_rejected(
        self,
        agent_channel: PaymentChannel,
        server_channel: PaymentChannel,
        agent_secret_key: bytes,
        server_secret_key: bytes,
    ) -> None:
        _open_channel(agent_channel, server_channel, 1000, 500)

        now = 1_000_000
        agent_channel.create_unilateral_close(
            agent_secret_key, current_time=now,
        )

        # Create a fully signed state update on the server side to use as challenge
        # Server needs to create and agent countersign — but agent is CLOSING.
        # Build the update manually for the test.
        signed = _build_fully_signed_update(
            agent_channel, server_channel,
            agent_secret_key, server_secret_key,
            cost=100, from_agent_to_server=False,
        )

        with pytest.raises(ChallengeError, match="expired"):
            agent_channel.challenge(
                signed,
                current_time=now + CHALLENGE_PERIOD_SECONDS + 1,
            )

    def test_finalize_disputed_channel(
        self,
        agent_channel: PaymentChannel,
        server_channel: PaymentChannel,
        agent_secret_key: bytes,
        server_secret_key: bytes,
    ) -> None:
        """After dispute, finalize should use the disputed balances."""
        _open_channel(agent_channel, server_channel, 1000, 500)

        signed1 = _do_transfer(
            agent_channel, server_channel, 100,
            agent_secret_key, server_secret_key,
        )

        now = 1_000_000
        agent_channel.create_unilateral_close(
            agent_secret_key, current_time=now,
        )

        # Build a newer fully signed state update for challenge
        signed2 = _build_fully_signed_update(
            agent_channel, server_channel,
            agent_secret_key, server_secret_key,
            cost=50, from_agent_to_server=False,
        )

        agent_channel._state = ChannelState.CLOSING
        agent_channel._sequence = 1
        agent_channel.challenge(signed2, current_time=now + 100)
        assert agent_channel._state == ChannelState.DISPUTED

        # Finalize after deadline
        settlement, events = agent_channel.finalize_close(
            current_time=now + CHALLENGE_PERIOD_SECONDS,
        )
        assert agent_channel.state == ChannelState.CLOSED
        assert settlement.final_balance_a == signed2.agent_balance
        assert settlement.final_balance_b == signed2.server_balance


def _build_fully_signed_update(
    agent_ch: PaymentChannel,
    server_ch: PaymentChannel,
    agent_sk: bytes,
    server_sk: bytes,
    cost: int,
    from_agent_to_server: bool = True,
) -> ChannelStateUpdate:
    """Build a fully-signed state update without modifying channel state.

    Used in tests where the channel is in CLOSING state but we need
    a valid co-signed update for challenge testing.
    """
    import cbor2

    from qasp.crypto.signatures import sign as _sign

    seq = max(agent_ch.sequence_number, server_ch.sequence_number) + 1
    if from_agent_to_server:
        new_agent = agent_ch.agent_balance - cost
        new_server = agent_ch.server_balance + cost
    else:
        new_agent = agent_ch.agent_balance + cost
        new_server = agent_ch.server_balance - cost

    update = ChannelStateUpdate(
        channel_id=agent_ch.channel_id,
        sequence_number=seq,
        agent_balance=new_agent,
        server_balance=new_server,
        prev_hash=b"",  # don't validate chain in challenge tests
        timestamp=1_000_000,
        agent_signature=b"",
        server_signature=b"",
    )
    signable = update.signable_bytes()
    agent_sig = _sign(agent_sk, signable)
    server_sig = _sign(server_sk, signable)

    return ChannelStateUpdate(
        channel_id=update.channel_id,
        sequence_number=update.sequence_number,
        agent_balance=update.agent_balance,
        server_balance=update.server_balance,
        prev_hash=update.prev_hash,
        timestamp=update.timestamp,
        agent_signature=agent_sig,
        server_signature=server_sig,
    )


# =============================================================================
# TestReceiptChainIntegration
# =============================================================================


class TestReceiptChainIntegration:
    """Tests for linking channel state updates to receipt chain."""

    def test_first_update_chains_from_receipt_hash(
        self,
        agent_channel: PaymentChannel,
        server_channel: PaymentChannel,
        agent_secret_key: bytes,
        server_secret_key: bytes,
    ) -> None:
        _open_channel(agent_channel, server_channel, 1000, 500)

        # Create a mock receipt chain
        from datetime import UTC, datetime

        chain = ReceiptChain()
        receipt = Receipt(
            records=[],
            total_units=10,
            total_cost=100,
            issued_at=datetime.now(UTC),
            issuer="server",
            signature=b"fakesig",
            sequence_number=1,
            prev_hash=b"",
            meter_id=b"meter_01",
        )
        chain._receipts.append(receipt)

        expected_hash = receipt.compute_hash()

        # Link both channels
        agent_channel.link_to_receipt_chain(chain)
        server_channel.link_to_receipt_chain(chain)

        # First state update should have receipt hash as prev_hash
        update, _ = agent_channel.create_state_update(
            cost=100, signing_key=agent_secret_key,
        )
        assert update.prev_hash == expected_hash


# =============================================================================
# TestCBORRoundtrip
# =============================================================================


class TestCBORRoundtrip:
    """Tests for CBOR serialization roundtrips."""

    def test_channel_state_update_roundtrip(
        self,
        agent_channel: PaymentChannel,
        server_channel: PaymentChannel,
        agent_secret_key: bytes,
        server_secret_key: bytes,
    ) -> None:
        _open_channel(agent_channel, server_channel, 1000, 500)

        signed = _do_transfer(
            agent_channel, server_channel, 100,
            agent_secret_key, server_secret_key,
        )

        # Roundtrip
        cbor_data = signed.to_cbor()
        restored = ChannelStateUpdate.from_cbor(cbor_data)
        assert restored.channel_id == signed.channel_id
        assert restored.sequence_number == signed.sequence_number
        assert restored.agent_balance == signed.agent_balance
        assert restored.server_balance == signed.server_balance
        assert restored.prev_hash == signed.prev_hash
        assert restored.timestamp == signed.timestamp
        assert restored.agent_signature == signed.agent_signature
        assert restored.server_signature == signed.server_signature

    def test_price_schedule_roundtrip(self) -> None:
        schedule = PriceSchedule(
            resource_type="compute",
            unit_price=10,
            currency="credits",
            valid_from=1000,
            valid_until=2000,
            offerer_signature=b"sig_offer",
            accepter_signature=b"sig_accept",
        )
        cbor_data = schedule.to_cbor()
        restored = PriceSchedule.from_cbor(cbor_data)
        assert restored.resource_type == schedule.resource_type
        assert restored.unit_price == schedule.unit_price
        assert restored.currency == schedule.currency
        assert restored.valid_from == schedule.valid_from
        assert restored.valid_until == schedule.valid_until
        assert restored.offerer_signature == schedule.offerer_signature
        assert restored.accepter_signature == schedule.accepter_signature

    def test_state_update_hash_consistency(
        self,
        agent_channel: PaymentChannel,
        server_channel: PaymentChannel,
        agent_secret_key: bytes,
        server_secret_key: bytes,
    ) -> None:
        """Hash should be consistent across serialization."""
        _open_channel(agent_channel, server_channel, 1000, 500)

        signed = _do_transfer(
            agent_channel, server_channel, 100,
            agent_secret_key, server_secret_key,
        )

        hash1 = signed.compute_hash()
        restored = ChannelStateUpdate.from_cbor(signed.to_cbor())
        hash2 = restored.compute_hash()
        assert hash1 == hash2
