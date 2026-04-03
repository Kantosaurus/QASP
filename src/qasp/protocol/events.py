"""Protocol event definitions.

This module defines typed events emitted by the QASP protocol.
Events are immutable dataclasses used to communicate protocol
state changes and received data to the application layer.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "AlertReceived",
    "ChannelChallengeExpired",
    "ChannelClosed",
    "ChannelClosing",
    "ChannelDisputed",
    "ChannelOpened",
    "ChannelOpening",
    "ChannelStateUpdated",
    "ConnectionClosed",
    "ConnectionError",
    "ConversationClosed",
    "ConversationOpened",
    "CrossDomainDelegationGranted",
    "CrossDomainDelegationRejected",
    "CrossDomainDelegationRequested",
    "CrossDomainDelegationRevoked",
    "DataReceived",
    "DataSent",
    "DisputeEvidenceReceived",
    "DisputeOpened",
    "DisputeResolved",
    "DivergenceDetected",
    "Event",
    "FaultAttributed",
    "HandshakeComplete",
    "HandshakeFailed",
    "HandshakeInitiated",
    "HandshakeTimeout",
    "MessageDelivered",
    "MessageReceived",
    "MessageRejected",
    "MessageSent",
    "MeterAckSent",
    "MeterReportReceived",
    "OCSPRequestReceived",
    "OCSPResponseGenerated",
    "PriceAccepted",
    "PriceOfferReceived",
    "ReconciliationFailed",
    "ReconciliationStarted",
    "ReconciliationSucceeded",
    "ResourceDenied",
    "ResourceGranted",
    "ResourceReleased",
    "ResourceRequested",
    "ResourceSuspended",
    "RevocationCascadeComplete",
    "RevocationGracePeriodStarted",
    "StreamClosed",
    "StreamDataReceived",
    "StreamOpened",
    "TokenIssued",
    "TokenRevoked",
    "TokenVerified",
    "VerdictEnforced",
]


@dataclass(frozen=True)
class Event:
    """Base class for protocol events.

    All protocol events inherit from this class, enabling
    type-based dispatching in event handlers.
    """


# =============================================================================
# Handshake Events
# =============================================================================


@dataclass(frozen=True)
class HandshakeInitiated(Event):
    """Handshake has been initiated.

    Attributes:
        initiator: True if this side initiated the handshake (client),
                   False if responding (server).
    """

    initiator: bool


@dataclass(frozen=True)
class HandshakeComplete(Event):
    """Handshake completed successfully.

    Attributes:
        peer_public_key: The peer's public key from the handshake.
        session_id: Unique identifier for this session.
    """

    peer_public_key: bytes
    session_id: bytes


@dataclass(frozen=True)
class HandshakeFailed(Event):
    """Handshake failed.

    Attributes:
        reason: Description of why the handshake failed.
        fatal: Whether this is a fatal error requiring connection close.
    """

    reason: str
    fatal: bool = True


@dataclass(frozen=True)
class HandshakeTimeout(Event):
    """Handshake timed out waiting for peer response.

    Attributes:
        timeout_ms: The timeout duration in milliseconds.
        retry_count: Number of retries attempted so far.
        will_retry: Whether the connection will attempt a retry.
    """

    timeout_ms: int
    retry_count: int
    will_retry: bool


# =============================================================================
# Data Events
# =============================================================================


@dataclass(frozen=True)
class DataReceived(Event):
    """Application data received from peer.

    Attributes:
        data: The decrypted application data.
        sequence_number: The message sequence number.
    """

    data: bytes
    sequence_number: int = 0


@dataclass(frozen=True)
class DataSent(Event):
    """Application data successfully queued for sending.

    Attributes:
        length: Number of bytes queued.
        sequence_number: The assigned sequence number.
    """

    length: int
    sequence_number: int


# =============================================================================
# Capability/Token Events
# =============================================================================


@dataclass(frozen=True)
class TokenIssued(Event):
    """A capability token was issued.

    Attributes:
        token_id: Unique identifier for the token.
        resource_type: Type of resource the token grants access to.
        permissions: Bitmask of granted permissions.
    """

    token_id: bytes
    resource_type: str
    permissions: int


@dataclass(frozen=True)
class TokenRevoked(Event):
    """A capability token was revoked.

    Attributes:
        token_id: Unique identifier of the revoked token.
        reason: Optional reason for revocation.
    """

    token_id: bytes
    reason: str = ""


@dataclass(frozen=True)
class RevocationCascadeComplete(Event):
    """A revocation cascade completed.

    Attributes:
        root_token_id: Token ID that initiated the cascade.
        revoked_token_ids: All token IDs revoked in the cascade.
        urgency: Urgency level of the revocation.
    """

    root_token_id: bytes
    revoked_token_ids: tuple[bytes, ...]
    urgency: int


@dataclass(frozen=True)
class RevocationGracePeriodStarted(Event):
    """A non-critical revocation grace period has started.

    Attributes:
        token_id: Token ID entering grace period.
        effective_time: Unix timestamp when revocation becomes effective.
        urgency: Urgency level of the revocation.
    """

    token_id: bytes
    effective_time: int
    urgency: int


@dataclass(frozen=True)
class TokenVerified(Event):
    """A capability token was successfully verified.

    Attributes:
        token_id: Unique identifier of the verified token.
        resource_type: Type of resource the token grants access to.
        permissions: Bitmask of granted permissions.
    """

    token_id: bytes
    resource_type: str
    permissions: int


# =============================================================================
# Resource Events
# =============================================================================


@dataclass(frozen=True)
class ResourceRequested(Event):
    """A resource access was requested.

    Attributes:
        resource_id: Identifier of the requested resource.
        resource_type: Type of resource requested.
        requested_permissions: Bitmask of requested permissions.
    """

    resource_id: bytes
    resource_type: str
    requested_permissions: int


@dataclass(frozen=True)
class ResourceGranted(Event):
    """Resource access was granted.

    Attributes:
        resource_id: Identifier of the granted resource.
        token_id: Token granting access to the resource.
        granted_permissions: Bitmask of granted permissions.
    """

    resource_id: bytes
    token_id: bytes
    granted_permissions: int


@dataclass(frozen=True)
class ResourceDenied(Event):
    """Resource access was denied.

    Attributes:
        resource_id: Identifier of the denied resource.
        reason: Reason for denial.
    """

    resource_id: bytes
    reason: str


@dataclass(frozen=True)
class ResourceReleased(Event):
    """Resource access was released.

    Attributes:
        resource_id: Identifier of the released resource.
        token_id: Token that was released.
    """

    resource_id: bytes
    token_id: bytes


@dataclass(frozen=True)
class ResourceSuspended(Event):
    """Resource access was suspended.

    Attributes:
        resource_id: Identifier of the suspended resource.
        token_id: Token of the suspended resource.
        reason: Suspension reason code.
        resume_time: Expected resume timestamp (0 = indefinite).
    """

    resource_id: bytes
    token_id: bytes
    reason: int
    resume_time: int = 0


# =============================================================================
# Metering Events
# =============================================================================


@dataclass(frozen=True)
class MeterReportReceived(Event):
    """A metering report was received.

    Attributes:
        meter_id: Identifier of the meter.
        usage_count: Number of usage units reported.
        usage_bytes: Number of bytes used.
        timestamp: Unix timestamp of the report.
    """

    meter_id: bytes
    usage_count: int
    usage_bytes: int
    timestamp: int


@dataclass(frozen=True)
class MeterAckSent(Event):
    """A metering acknowledgment was sent.

    Attributes:
        meter_id: Identifier of the acknowledged meter.
        acked_count: Count value that was acknowledged.
    """

    meter_id: bytes
    acked_count: int


# =============================================================================
# Dispute Events
# =============================================================================


@dataclass(frozen=True)
class DisputeOpened(Event):
    """A dispute was opened.

    Attributes:
        dispute_id: Unique identifier for the dispute.
        token_id: Token related to the dispute.
        dispute_type: Type of dispute (maps to DisputeType IntEnum).
    """

    dispute_id: bytes
    token_id: bytes
    dispute_type: int


@dataclass(frozen=True)
class DisputeEvidenceReceived(Event):
    """Evidence was submitted for a dispute.

    Attributes:
        dispute_id: Identifier of the dispute.
        evidence_type: Type of evidence submitted.
        submitter: DID of the evidence submitter.
    """

    dispute_id: bytes
    evidence_type: int
    submitter: str


@dataclass(frozen=True)
class DisputeResolved(Event):
    """A dispute was resolved with a verdict.

    Attributes:
        dispute_id: Identifier of the resolved dispute.
        verdict: Verdict code (maps to VerdictCode IntEnum).
        awarded_value: Value awarded to the winner.
    """

    dispute_id: bytes
    verdict: int
    awarded_value: int


# =============================================================================
# Connection Events
# =============================================================================


@dataclass(frozen=True)
class ConnectionClosed(Event):
    """Connection was closed.

    Attributes:
        reason: Optional reason for the close.
        graceful: True if this was a graceful close, False if abrupt.
    """

    reason: str | None = None
    graceful: bool = True


@dataclass(frozen=True)
class ConnectionError(Event):
    """Connection error occurred.

    Attributes:
        error: Description of the error.
        fatal: Whether this is a fatal error requiring connection close.
    """

    error: str
    fatal: bool = True


@dataclass(frozen=True)
class AlertReceived(Event):
    """An alert message was received.

    Attributes:
        level: Alert severity level (1=warning, 2=fatal).
        description: Alert description code.
        message: Optional human-readable message.
    """

    level: int
    description: int
    message: str = ""


# =============================================================================
# Stream Multiplexing Events
# =============================================================================


@dataclass(frozen=True)
class StreamOpened(Event):
    """A new multiplexed stream was opened.

    Attributes:
        stream_id: The unique stream identifier.
        capability_token_id: Optional associated capability token.
    """

    stream_id: int
    capability_token_id: bytes | None = None


@dataclass(frozen=True)
class StreamDataReceived(Event):
    """Data was received on a multiplexed stream.

    Attributes:
        stream_id: The stream the data was received on.
        data: The received data.
        end_stream: True if this is the last data on the stream.
    """

    stream_id: int
    data: bytes
    end_stream: bool = False


@dataclass(frozen=True)
class StreamClosed(Event):
    """A multiplexed stream was closed.

    Attributes:
        stream_id: The closed stream's identifier.
        reason: Optional reason for closure.
    """

    stream_id: int
    reason: str = ""


# =============================================================================
# Settlement / Channel Events
# =============================================================================


@dataclass(frozen=True)
class PriceOfferReceived(Event):
    """A price offer was received.

    Attributes:
        resource_type: Type of resource being priced.
        unit_price: Price per unit offered.
        currency: Currency identifier.
        valid_until: Unix timestamp for end of offer validity.
    """

    resource_type: str
    unit_price: int
    currency: str
    valid_until: int


@dataclass(frozen=True)
class PriceAccepted(Event):
    """A price offer was accepted.

    Attributes:
        resource_type: Type of resource priced.
        unit_price: Agreed price per unit.
        currency: Currency identifier.
    """

    resource_type: str
    unit_price: int
    currency: str


@dataclass(frozen=True)
class ChannelOpening(Event):
    """A payment channel is being opened.

    Attributes:
        channel_id: Unique channel identifier.
        peer_id: Identifier of the channel peer.
        initial_balance: Initial balance proposed.
    """

    channel_id: bytes
    peer_id: bytes
    initial_balance: int


@dataclass(frozen=True)
class ChannelOpened(Event):
    """A payment channel was successfully opened.

    Attributes:
        channel_id: Unique channel identifier.
        agent_balance: Agent's starting balance.
        server_balance: Server's starting balance.
    """

    channel_id: bytes
    agent_balance: int
    server_balance: int


@dataclass(frozen=True)
class ChannelStateUpdated(Event):
    """A payment channel state was updated off-chain.

    Attributes:
        channel_id: Channel identifier.
        sequence_number: Sequence number of the update.
        agent_balance: Agent's balance after update.
        server_balance: Server's balance after update.
    """

    channel_id: bytes
    sequence_number: int
    agent_balance: int
    server_balance: int


@dataclass(frozen=True)
class ChannelClosing(Event):
    """A payment channel close was initiated.

    Attributes:
        channel_id: Channel identifier.
        close_reason: Reason for closing.
        unilateral: Whether the close is unilateral.
    """

    channel_id: bytes
    close_reason: int
    unilateral: bool


@dataclass(frozen=True)
class ChannelClosed(Event):
    """A payment channel was closed.

    Attributes:
        channel_id: Channel identifier.
        final_balance_a: Final balance for party A (agent).
        final_balance_b: Final balance for party B (server).
    """

    channel_id: bytes
    final_balance_a: int
    final_balance_b: int


@dataclass(frozen=True)
class ChannelDisputed(Event):
    """A payment channel close was disputed with newer state.

    Attributes:
        channel_id: Channel identifier.
        challenged_sequence: Sequence number that was challenged.
        newer_sequence: Sequence number of the newer state submitted.
    """

    channel_id: bytes
    challenged_sequence: int
    newer_sequence: int


@dataclass(frozen=True)
class ChannelChallengeExpired(Event):
    """A payment channel challenge period has expired.

    Attributes:
        channel_id: Channel identifier.
    """

    channel_id: bytes


# =============================================================================
# Cross-Domain Delegation Events
# =============================================================================


@dataclass(frozen=True)
class CrossDomainDelegationRequested(Event):
    """A cross-domain delegation was requested.

    Attributes:
        request_id: Unique request identifier.
        source_agent_did: DID of the source agent.
        target_agent_did: DID of the target agent.
        resource_uri: Resource being delegated.
    """

    request_id: bytes
    source_agent_did: str
    target_agent_did: str
    resource_uri: str


@dataclass(frozen=True)
class CrossDomainDelegationGranted(Event):
    """A cross-domain delegation was granted.

    Attributes:
        delegation_id: Unique delegation identifier.
        source_owner_did: DID of the source owner.
        target_owner_did: DID of the target owner.
        resource_uri: Resource being delegated.
    """

    delegation_id: bytes
    source_owner_did: str
    target_owner_did: str
    resource_uri: str


@dataclass(frozen=True)
class CrossDomainDelegationRejected(Event):
    """A cross-domain delegation was rejected.

    Attributes:
        request_id: The request that was rejected.
        reason: Reason for rejection.
    """

    request_id: bytes
    reason: str


@dataclass(frozen=True)
class CrossDomainDelegationRevoked(Event):
    """A cross-domain delegation was revoked.

    Attributes:
        delegation_id: The delegation that was revoked.
        revoked_by: DID of the revoker.
        reason: Revocation reason.
        cascade_token_ids: Token IDs revoked in the cascade.
    """

    delegation_id: bytes
    revoked_by: str
    reason: str
    cascade_token_ids: tuple[bytes, ...]


# =============================================================================
# Reconciliation / Arbitration Events
# =============================================================================


@dataclass(frozen=True)
class DivergenceDetected(Event):
    """A metering divergence was detected between agent and server.

    Attributes:
        meter_id: The meter with divergent readings.
        reported_cost: Cost reported by the server.
        local_cost: Cost tracked locally by the agent.
        difference: Absolute difference between the two.
        tolerance: The tolerance threshold that was exceeded.
    """

    meter_id: bytes
    reported_cost: int
    local_cost: int
    difference: int
    tolerance: int


@dataclass(frozen=True)
class ReconciliationStarted(Event):
    """A reconciliation session was started for a meter.

    Attributes:
        meter_id: The meter being reconciled.
        start_seq: Start sequence number of the receipt range.
        end_seq: End sequence number of the receipt range.
    """

    meter_id: bytes
    start_seq: int
    end_seq: int


@dataclass(frozen=True)
class ReconciliationSucceeded(Event):
    """Reconciliation succeeded with an auto-resolution.

    Attributes:
        meter_id: The meter that was reconciled.
        resolution_method: The method used (0=agreed, 1=higher_seq, 2=average).
        agreed_cost: The agreed-upon cost after reconciliation.
    """

    meter_id: bytes
    resolution_method: int
    agreed_cost: int


@dataclass(frozen=True)
class ReconciliationFailed(Event):
    """Reconciliation failed, escalation to formal dispute needed.

    Attributes:
        meter_id: The meter that failed reconciliation.
        reason: Reason for failure.
    """

    meter_id: bytes
    reason: str


@dataclass(frozen=True)
class FaultAttributed(Event):
    """Fault was attributed to a party during dispute resolution.

    Attributes:
        dispute_id: The dispute identifier.
        faulty_party_did: DID of the party found at fault.
        fault_type: Type of fault (maps to FaultType IntEnum).
        severity: Fault severity (0.0 to 1.0).
    """

    dispute_id: bytes
    faulty_party_did: str
    fault_type: int
    severity: float


@dataclass(frozen=True)
class VerdictEnforced(Event):
    """An auditor verdict was enforced on a payment channel.

    Attributes:
        channel_id: The payment channel identifier.
        dispute_id: The dispute that triggered enforcement.
        adjustment: The balance adjustment applied.
        new_agent_balance: Agent's balance after enforcement.
        new_server_balance: Server's balance after enforcement.
    """

    channel_id: bytes
    dispute_id: bytes
    adjustment: int
    new_agent_balance: int
    new_server_balance: int


# =============================================================================
# OCSP Events
# =============================================================================


@dataclass(frozen=True)
class OCSPRequestReceived(Event):
    """An OCSP status request was received.

    Attributes:
        token_id: Token whose status was queried.
        requester_nonce: Nonce from the requester for replay protection.
    """

    token_id: bytes
    requester_nonce: bytes


@dataclass(frozen=True)
class OCSPResponseGenerated(Event):
    """An OCSP response was generated.

    Attributes:
        token_id: Token whose status was returned.
        status: OCSP status code (0=good, 1=revoked, 2=unknown).
        cached: Whether the status was served from cache.
    """

    token_id: bytes
    status: int
    cached: bool


# =============================================================================
# Agent-to-Agent Messaging Events
# =============================================================================


@dataclass(frozen=True)
class MessageSent(Event):
    """An agent-to-agent message was sent.

    Attributes:
        message_id: Unique message identifier.
        conversation_id: Conversation identifier.
        sender_did: DID of the sender.
        recipient_did: DID of the recipient.
        content_length: Length of the message content in bytes.
    """

    message_id: str
    conversation_id: str
    sender_did: str
    recipient_did: str
    content_length: int


@dataclass(frozen=True)
class MessageReceived(Event):
    """An agent-to-agent message was received.

    Attributes:
        message_id: Unique message identifier.
        conversation_id: Conversation identifier.
        sender_did: DID of the sender.
        content_length: Length of the message content in bytes.
    """

    message_id: str
    conversation_id: str
    sender_did: str
    content_length: int


@dataclass(frozen=True)
class MessageDelivered(Event):
    """An agent message was confirmed delivered.

    Attributes:
        message_id: The delivered message's identifier.
        conversation_id: Conversation identifier.
    """

    message_id: str
    conversation_id: str


@dataclass(frozen=True)
class MessageRejected(Event):
    """An agent message was rejected by the recipient.

    Attributes:
        message_id: The rejected message's identifier.
        conversation_id: Conversation identifier.
        reason: Rejection reason.
    """

    message_id: str
    conversation_id: str
    reason: str


@dataclass(frozen=True)
class ConversationOpened(Event):
    """A new conversation thread was opened.

    Attributes:
        conversation_id: The new conversation's identifier.
        initiator_did: DID of the agent that started the conversation.
        participant_did: DID of the other agent.
    """

    conversation_id: str
    initiator_did: str
    participant_did: str


@dataclass(frozen=True)
class ConversationClosed(Event):
    """A conversation was closed.

    Attributes:
        conversation_id: The closed conversation's identifier.
        closed_by: DID of the agent that closed it.
        message_count: Total messages exchanged.
    """

    conversation_id: str
    closed_by: str
    message_count: int
