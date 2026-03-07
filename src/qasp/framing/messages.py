"""Protocol message definitions.

This module defines the 22 QASP message types per Table IV of the
QASP protocol specification (0x01-0x16).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

__all__ = [
    "Alert",
    "ApplicationData",
    "ChannelClose",
    "ChannelOpen",
    "ClientAuth",
    "ClientHello",
    "DelegationGrant",
    "DelegationRequest",
    "DisputeEvidence",
    "DisputeOpen",
    "DisputeVerdict",
    "Message",
    "MessageType",
    "MeterAck",
    "MeterReport",
    "OCSPRequestMessage",
    "OCSPResponseMessage",
    "PriceAccept",
    "PriceOffer",
    "PriceRequest",
    "ReconciliationRequest",
    "ReconciliationResponse",
    "ResourceDeny",
    "ResourceGrant",
    "ResourceRelease",
    "ResourceRequest",
    "ResourceSuspend",
    "RevocationNotice",
    "ServerHello",
    "TokenRevocation",
]


class MessageType(IntEnum):
    """QASP message types per Table IV.

    Message types are organized into functional groups:
    - 0x01-0x03: Handshake
    - 0x04: Application data
    - 0x05-0x06: Token revocation
    - 0x07-0x0C: Resource management
    - 0x0D-0x0F: Dispute resolution
    - 0x10: Metering
    - 0x11-0x12: Channel management
    - 0x13-0x14: Pricing and alerts
    - 0x1B-0x1C: OCSP
    """

    # Handshake messages
    CLIENT_HELLO = 0x01
    SERVER_HELLO = 0x02
    CLIENT_AUTH = 0x03

    # Application data
    APPLICATION_DATA = 0x04

    # Token revocation
    TOKEN_REVOCATION = 0x05
    REVOCATION_NOTICE = 0x06

    # Resource management
    RESOURCE_REQUEST = 0x07
    RESOURCE_GRANT = 0x08
    METER_ACK = 0x09
    RESOURCE_SUSPEND = 0x0A
    RESOURCE_DENY = 0x0B
    RESOURCE_RELEASE = 0x0C

    # Dispute resolution
    DISPUTE_OPEN = 0x0D
    DISPUTE_EVIDENCE = 0x0E
    DISPUTE_VERDICT = 0x0F

    # Metering
    METER_REPORT = 0x10

    # Channel management
    CHANNEL_OPEN = 0x11
    CHANNEL_CLOSE = 0x12

    # Pricing and alerts
    PRICE_REQUEST = 0x13
    ALERT = 0x14
    PRICE_OFFER = 0x15
    PRICE_ACCEPT = 0x16

    # Cross-domain delegation
    DELEGATION_REQUEST = 0x17
    DELEGATION_GRANT = 0x18

    # Reconciliation
    RECONCILIATION_REQUEST = 0x19
    RECONCILIATION_RESPONSE = 0x1A

    # OCSP
    OCSP_REQUEST = 0x1B
    OCSP_RESPONSE = 0x1C


@dataclass(frozen=True)
class Message:
    """Base class for all QASP messages.

    All message types inherit from this class and include
    the message_type field for dispatching.
    """

    message_type: MessageType


# =============================================================================
# Handshake Messages (0x01-0x03)
# =============================================================================


@dataclass(frozen=True)
class ClientHello(Message):
    """Client hello message for handshake initiation (0x01).

    Sent by the client to initiate the QASP-Shake handshake.

    Attributes:
        protocol_version: Protocol version (major, minor).
        client_random: 32-byte random nonce.
        kem_public_key: Client's ML-KEM-1024 public key.
        sig_public_key: Client's ML-DSA-65 public key.
        cipher_suites: Supported cipher suite identifiers.
        extensions: Optional protocol extensions.
    """

    message_type: MessageType = field(default=MessageType.CLIENT_HELLO, init=False)
    protocol_version: tuple[int, int] = (1, 0)
    client_random: bytes = b""
    kem_public_key: bytes = b""
    sig_public_key: bytes = b""
    cipher_suites: tuple[int, ...] = ()
    extensions: bytes = b""


@dataclass(frozen=True)
class ServerHello(Message):
    """Server hello message for handshake response (0x02).

    Sent by the server in response to ClientHello.

    Attributes:
        protocol_version: Selected protocol version.
        server_random: 32-byte random nonce.
        kem_ciphertext: ML-KEM-1024 ciphertext encapsulating shared secret.
        kem_public_key: Server's ML-KEM-1024 public key.
        sig_public_key: Server's ML-DSA-65 public key.
        selected_cipher_suite: Selected cipher suite identifier.
        signature: ML-DSA-65 signature over handshake transcript.
        extensions: Optional protocol extensions.
    """

    message_type: MessageType = field(default=MessageType.SERVER_HELLO, init=False)
    protocol_version: tuple[int, int] = (1, 0)
    server_random: bytes = b""
    kem_ciphertext: bytes = b""
    kem_public_key: bytes = b""
    sig_public_key: bytes = b""
    selected_cipher_suite: int = 0
    signature: bytes = b""
    extensions: bytes = b""
    certificate_chain: bytes = b""


@dataclass(frozen=True)
class ClientAuth(Message):
    """Client authentication message (0x03).

    Sent by the client to complete mutual authentication.

    Attributes:
        kem_ciphertext: ML-KEM-1024 ciphertext for server's public key.
        signature: ML-DSA-65 signature over handshake transcript.
        certificate: Optional client certificate.
    """

    message_type: MessageType = field(default=MessageType.CLIENT_AUTH, init=False)
    kem_ciphertext: bytes = b""
    signature: bytes = b""
    certificate: bytes = b""


# =============================================================================
# Application Data (0x04)
# =============================================================================


@dataclass(frozen=True)
class ApplicationData(Message):
    """Application data message (0x04).

    Carries encrypted application data.

    Attributes:
        encrypted_data: AES-256-GCM encrypted payload.
        sequence_number: Message sequence number for replay protection.
    """

    message_type: MessageType = field(default=MessageType.APPLICATION_DATA, init=False)
    encrypted_data: bytes = b""
    sequence_number: int = 0


# =============================================================================
# Token Revocation Messages (0x05-0x06)
# =============================================================================


@dataclass(frozen=True)
class TokenRevocation(Message):
    """Token revocation message (0x05).

    Sent to revoke a previously issued capability token.

    Attributes:
        token_id: Identifier of the token to revoke.
        revocation_time: Unix timestamp of revocation.
        reason: Revocation reason code.
        signature: Signature from token issuer.
        urgency: Revocation urgency (0=critical, 1=normal, 2=planned).
        scheduled_time: Unix timestamp for planned revocations.
        issuer_did: DID of the revoker.
    """

    message_type: MessageType = field(default=MessageType.TOKEN_REVOCATION, init=False)
    token_id: bytes = b""
    revocation_time: int = 0
    reason: int = 0
    signature: bytes = b""
    urgency: int = 1
    scheduled_time: int = 0
    issuer_did: str = ""


@dataclass(frozen=True)
class RevocationNotice(Message):
    """Revocation notice message (0x06).

    Broadcast to notify peers of a token revocation.

    Attributes:
        token_id: Identifier of the revoked token.
        revocation_time: Unix timestamp of revocation.
        issuer_id: Identifier of the original token issuer.
        signature: Signature from revocation authority.
        urgency: Revocation urgency (0=critical, 1=normal, 2=planned).
        cascade_token_ids: Descendant token IDs also revoked.
    """

    message_type: MessageType = field(default=MessageType.REVOCATION_NOTICE, init=False)
    token_id: bytes = b""
    revocation_time: int = 0
    issuer_id: bytes = b""
    signature: bytes = b""
    urgency: int = 1
    cascade_token_ids: tuple[bytes, ...] = ()


# =============================================================================
# Resource Management Messages (0x07-0x0C)
# =============================================================================


@dataclass(frozen=True)
class ResourceRequest(Message):
    """Resource request message (0x07).

    Sent to request access to a resource.

    Attributes:
        request_id: Unique request identifier.
        resource_type: Type of resource requested.
        resource_id: Specific resource identifier.
        permissions: Requested permission bitmask.
        duration: Requested access duration in seconds.
        payment_offer: Optional payment offer for the resource.
        capability_tokens: CBOR-encoded capability tokens to aggregate
            for computing effective permissions. Empty by default.
    """

    message_type: MessageType = field(default=MessageType.RESOURCE_REQUEST, init=False)
    request_id: bytes = b""
    resource_type: str = ""
    resource_id: bytes = b""
    permissions: int = 0
    duration: int = 0
    payment_offer: bytes = b""
    capability_tokens: tuple[bytes, ...] = ()
    disclosure_mode: str = "full"
    selective_proof: bytes = b""


@dataclass(frozen=True)
class ResourceGrant(Message):
    """Resource grant message (0x08).

    Sent to grant access to a requested resource.

    Attributes:
        request_id: Matching request identifier.
        token: Capability token granting access.
        granted_permissions: Granted permission bitmask.
        expiration: Token expiration timestamp.
        meter_id: Meter identifier for usage tracking.
    """

    message_type: MessageType = field(default=MessageType.RESOURCE_GRANT, init=False)
    request_id: bytes = b""
    token: bytes = b""
    granted_permissions: int = 0
    expiration: int = 0
    meter_id: bytes = b""


@dataclass(frozen=True)
class MeterAck(Message):
    """Meter acknowledgment message (0x09).

    Sent to acknowledge a meter report.

    Attributes:
        meter_id: Meter identifier being acknowledged.
        acked_sequence: Acknowledged sequence number.
        acked_usage: Acknowledged usage value.
        signature: Provider signature for receipt.
    """

    message_type: MessageType = field(default=MessageType.METER_ACK, init=False)
    meter_id: bytes = b""
    acked_sequence: int = 0
    acked_usage: int = 0
    signature: bytes = b""


@dataclass(frozen=True)
class ResourceSuspend(Message):
    """Resource suspend message (0x0A).

    Sent to temporarily suspend resource access.

    Attributes:
        token_id: Token of the suspended resource.
        reason: Suspension reason code.
        resume_time: Expected resume timestamp (0 = indefinite).
    """

    message_type: MessageType = field(default=MessageType.RESOURCE_SUSPEND, init=False)
    token_id: bytes = b""
    reason: int = 0
    resume_time: int = 0


@dataclass(frozen=True)
class ResourceDeny(Message):
    """Resource deny message (0x0B).

    Sent to deny a resource request.

    Attributes:
        request_id: Matching request identifier.
        reason: Denial reason code.
        message: Optional human-readable explanation.
        retry_after: Seconds before retrying (0 = don't retry).
    """

    message_type: MessageType = field(default=MessageType.RESOURCE_DENY, init=False)
    request_id: bytes = b""
    reason: int = 0
    message: str = ""
    retry_after: int = 0


@dataclass(frozen=True)
class ResourceRelease(Message):
    """Resource release message (0x0C).

    Sent to release a held resource.

    Attributes:
        token_id: Token of the released resource.
        final_usage: Final usage count for settlement.
        signature: Signature confirming release.
    """

    message_type: MessageType = field(default=MessageType.RESOURCE_RELEASE, init=False)
    token_id: bytes = b""
    final_usage: int = 0
    signature: bytes = b""


# =============================================================================
# Dispute Resolution Messages (0x0D-0x0F)
# =============================================================================


@dataclass(frozen=True)
class DisputeOpen(Message):
    """Dispute open message (0x0D).

    Sent to initiate a dispute.

    Attributes:
        dispute_id: Unique dispute identifier.
        token_id: Token related to the dispute.
        dispute_type: Type of dispute.
        claimed_value: Value claimed by disputant.
        evidence_hash: Hash of initial evidence.
    """

    message_type: MessageType = field(default=MessageType.DISPUTE_OPEN, init=False)
    dispute_id: bytes = b""
    token_id: bytes = b""
    dispute_type: int = 0
    claimed_value: int = 0
    evidence_hash: bytes = b""


@dataclass(frozen=True)
class DisputeEvidence(Message):
    """Dispute evidence message (0x0E).

    Sent to submit evidence for a dispute.

    Attributes:
        dispute_id: Matching dispute identifier.
        evidence_type: Type of evidence being submitted.
        evidence_data: Serialized evidence.
        signature: Signature over the evidence.
    """

    message_type: MessageType = field(default=MessageType.DISPUTE_EVIDENCE, init=False)
    dispute_id: bytes = b""
    evidence_type: int = 0
    evidence_data: bytes = b""
    signature: bytes = b""


@dataclass(frozen=True)
class DisputeVerdict(Message):
    """Dispute verdict message (0x0F).

    Sent by arbiter to resolve a dispute.

    Attributes:
        dispute_id: Matching dispute identifier.
        verdict: Verdict code.
        awarded_value: Value awarded to winner.
        arbiter_id: Identifier of the arbiter.
        signature: Arbiter's signature.
    """

    message_type: MessageType = field(default=MessageType.DISPUTE_VERDICT, init=False)
    dispute_id: bytes = b""
    verdict: int = 0
    awarded_value: int = 0
    arbiter_id: bytes = b""
    signature: bytes = b""


# =============================================================================
# Metering Message (0x10)
# =============================================================================


@dataclass(frozen=True)
class MeterReport(Message):
    """Meter report message (0x10).

    Sent to report resource usage.

    Attributes:
        meter_id: Meter identifier.
        sequence_number: Report sequence number.
        usage_count: Number of usage units.
        usage_bytes: Number of bytes used.
        cost: Cumulative cost in smallest currency units.
        timestamp: Report timestamp.
        signature: Client signature for non-repudiation.
    """

    message_type: MessageType = field(default=MessageType.METER_REPORT, init=False)
    meter_id: bytes = b""
    sequence_number: int = 0
    usage_count: int = 0
    usage_bytes: int = 0
    cost: int = 0
    timestamp: int = 0
    signature: bytes = b""


# =============================================================================
# Channel Management Messages (0x11-0x12)
# =============================================================================


@dataclass(frozen=True)
class ChannelOpen(Message):
    """Channel open message (0x11).

    Sent to open a payment/data channel.

    Attributes:
        channel_id: Unique channel identifier.
        channel_type: Type of channel.
        initial_balance: Initial channel balance.
        peer_id: Identifier of channel peer.
        timeout: Channel timeout in seconds.
    """

    message_type: MessageType = field(default=MessageType.CHANNEL_OPEN, init=False)
    channel_id: bytes = b""
    channel_type: int = 0
    initial_balance: int = 0
    peer_id: bytes = b""
    timeout: int = 0


@dataclass(frozen=True)
class ChannelClose(Message):
    """Channel close message (0x12).

    Sent to close a channel.

    Attributes:
        channel_id: Channel identifier to close.
        final_balance_a: Final balance for party A.
        final_balance_b: Final balance for party B.
        close_reason: Reason for closing.
        signatures: Both parties' signatures.
    """

    message_type: MessageType = field(default=MessageType.CHANNEL_CLOSE, init=False)
    channel_id: bytes = b""
    final_balance_a: int = 0
    final_balance_b: int = 0
    close_reason: int = 0
    signatures: tuple[bytes, bytes] = (b"", b"")


# =============================================================================
# Pricing and Alert Messages (0x13-0x14)
# =============================================================================


@dataclass(frozen=True)
class PriceRequest(Message):
    """Price request message (0x13).

    Sent to query pricing for a resource.

    Attributes:
        request_id: Unique request identifier for correlation.
        resource_type: Type of resource to price.
        resource_id: Specific resource identifier.
        quantity: Quantity to price.
        duration: Duration to price in seconds.
    """

    message_type: MessageType = field(default=MessageType.PRICE_REQUEST, init=False)
    request_id: bytes = b""
    resource_type: str = ""
    resource_id: bytes = b""
    quantity: int = 0
    duration: int = 0


@dataclass(frozen=True)
class Alert(Message):
    """Alert message (0x14).

    Sent to signal errors or warnings.

    Attributes:
        level: Alert level (1=warning, 2=fatal).
        description: Alert description code.
        message: Human-readable message.
        related_message_type: Message type that triggered the alert.
    """

    message_type: MessageType = field(default=MessageType.ALERT, init=False)
    level: int = 0
    description: int = 0
    message: str = ""
    related_message_type: int = 0


# =============================================================================
# Price Negotiation Messages (0x15-0x16)
# =============================================================================


@dataclass(frozen=True)
class PriceOffer(Message):
    """Price offer message (0x15).

    Sent in response to a PriceRequest with pricing terms.

    Attributes:
        request_id: Correlates to the PriceRequest.
        resource_type: Type of resource being priced.
        unit_price: Price per unit in smallest currency denomination.
        currency: Currency identifier (e.g. "credits").
        valid_from: Unix timestamp for start of validity.
        valid_until: Unix timestamp for end of validity.
        signature: ML-DSA-65 signature over CBOR(fields - signature).
    """

    message_type: MessageType = field(default=MessageType.PRICE_OFFER, init=False)
    request_id: bytes = b""
    resource_type: str = ""
    unit_price: int = 0
    currency: str = ""
    valid_from: int = 0
    valid_until: int = 0
    signature: bytes = b""


@dataclass(frozen=True)
class PriceAccept(Message):
    """Price accept message (0x16).

    Sent to accept a PriceOffer and lock in pricing terms.

    Attributes:
        request_id: Correlates to the original PriceRequest.
        offer_signature: Echoes the PriceOffer.signature being accepted.
        resource_type: Type of resource being priced.
        unit_price: Accepted price per unit.
        currency: Currency identifier.
        valid_from: Unix timestamp for start of validity.
        valid_until: Unix timestamp for end of validity.
        signature: ML-DSA-65 signature from the accepter.
    """

    message_type: MessageType = field(default=MessageType.PRICE_ACCEPT, init=False)
    request_id: bytes = b""
    offer_signature: bytes = b""
    resource_type: str = ""
    unit_price: int = 0
    currency: str = ""
    valid_from: int = 0
    valid_until: int = 0
    signature: bytes = b""


# =============================================================================
# Cross-Domain Delegation Messages (0x17-0x18)
# =============================================================================


@dataclass(frozen=True)
class DelegationRequest(Message):
    """Delegation request message (0x17).

    Sent to request cross-domain delegation of a capability.

    Attributes:
        request_id: Unique request identifier.
        attenuated_token: CBOR-encoded attenuated capability token.
        delegation_chain: CBOR-encoded delegation chain.
        source_binding: CBOR-encoded source owner binding.
        endorsement: CBOR-encoded owner endorsement.
        target_owner_did: DID of the target owner.
        target_agent_did: DID of the target agent.
    """

    message_type: MessageType = field(default=MessageType.DELEGATION_REQUEST, init=False)
    request_id: bytes = b""
    attenuated_token: bytes = b""
    delegation_chain: bytes = b""
    source_binding: bytes = b""
    endorsement: bytes = b""
    target_owner_did: str = ""
    target_agent_did: str = ""


@dataclass(frozen=True)
class DelegationGrant(Message):
    """Delegation grant message (0x18).

    Sent in response to a DelegationRequest.

    Attributes:
        request_id: Matching request identifier.
        acceptance: CBOR-encoded owner acceptance.
        target_binding: CBOR-encoded target owner binding.
        delegation_id: Unique delegation identifier.
        status: 0 for accepted, 1 for rejected.
        rejection_reason: Reason for rejection (if status=1).
    """

    message_type: MessageType = field(default=MessageType.DELEGATION_GRANT, init=False)
    request_id: bytes = b""
    acceptance: bytes = b""
    target_binding: bytes = b""
    delegation_id: bytes = b""
    status: int = 0
    rejection_reason: str = ""


# =============================================================================
# Reconciliation Messages (0x19-0x1A)
# =============================================================================


@dataclass(frozen=True)
class ReconciliationRequest(Message):
    """Reconciliation request message (0x19).

    Sent to initiate pre-dispute reconciliation when a metering
    divergence is detected between agent and server.

    Attributes:
        meter_id: Meter identifier for the divergent resource.
        start_seq: Start sequence number of the receipt range.
        end_seq: End sequence number of the receipt range.
        chain_cbor: CBOR-encoded bounded receipt chain.
        detected_cost_diff: Detected cost difference (absolute).
        timestamp: Request timestamp.
        signature: ML-DSA-65 signature over request fields.
    """

    message_type: MessageType = field(
        default=MessageType.RECONCILIATION_REQUEST, init=False,
    )
    meter_id: bytes = b""
    start_seq: int = 0
    end_seq: int = 0
    chain_cbor: bytes = b""
    detected_cost_diff: int = 0
    timestamp: int = 0
    signature: bytes = b""


@dataclass(frozen=True)
class ReconciliationResponse(Message):
    """Reconciliation response message (0x1A).

    Sent in response to a ReconciliationRequest with the resolution outcome.

    Attributes:
        meter_id: Meter identifier for the divergent resource.
        start_seq: Start sequence number of the receipt range.
        end_seq: End sequence number of the receipt range.
        chain_cbor: CBOR-encoded bounded receipt chain (responder's view).
        resolution: Resolution method (0=agreed, 1=higher_seq_wins,
            2=use_average, 3=failed).
        agreed_cost: Agreed cost after resolution.
        timestamp: Response timestamp.
        signature: ML-DSA-65 signature over response fields.
    """

    message_type: MessageType = field(
        default=MessageType.RECONCILIATION_RESPONSE, init=False,
    )
    meter_id: bytes = b""
    start_seq: int = 0
    end_seq: int = 0
    chain_cbor: bytes = b""
    resolution: int = 0
    agreed_cost: int = 0
    timestamp: int = 0
    signature: bytes = b""


# =============================================================================
# OCSP Messages (0x1B-0x1C)
# =============================================================================


@dataclass(frozen=True)
class OCSPRequestMessage(Message):
    """OCSP request message (0x1B).

    Sent to query real-time revocation status of a capability token.

    Attributes:
        token_id: Identifier of the token to check.
        nonce: Random nonce for replay protection.
    """

    message_type: MessageType = field(default=MessageType.OCSP_REQUEST, init=False)
    token_id: bytes = b""
    nonce: bytes = b""


@dataclass(frozen=True)
class OCSPResponseMessage(Message):
    """OCSP response message (0x1C).

    Returns real-time revocation status with a signed proof.

    Attributes:
        status: OCSP status (0=good, 1=revoked, 2=unknown).
        token_id: Identifier of the queried token.
        this_update: Unix timestamp when status was determined.
        next_update: Unix timestamp when status expires.
        responder_id: DID of the OCSP responder.
        nonce: Echoed nonce from the request.
        signature: ML-DSA-65 signature over response data.
        revocation_reason: Revocation reason code (if revoked).
        revocation_time: Unix timestamp of revocation (if revoked).
    """

    message_type: MessageType = field(default=MessageType.OCSP_RESPONSE, init=False)
    status: int = 0
    token_id: bytes = b""
    this_update: int = 0
    next_update: int = 0
    responder_id: str = ""
    nonce: bytes = b""
    signature: bytes = b""
    revocation_reason: int | None = None
    revocation_time: int | None = None
