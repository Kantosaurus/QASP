"""Protocol message definitions.

This module defines the 20 QASP message types per Table IV of the
QASP protocol specification (0x01-0x14).
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
    "DisputeEvidence",
    "DisputeOpen",
    "DisputeVerdict",
    "Message",
    "MessageType",
    "MeterAck",
    "MeterReport",
    "PriceRequest",
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
    """

    message_type: MessageType = field(default=MessageType.TOKEN_REVOCATION, init=False)
    token_id: bytes = b""
    revocation_time: int = 0
    reason: int = 0
    signature: bytes = b""


@dataclass(frozen=True)
class RevocationNotice(Message):
    """Revocation notice message (0x06).

    Broadcast to notify peers of a token revocation.

    Attributes:
        token_id: Identifier of the revoked token.
        revocation_time: Unix timestamp of revocation.
        issuer_id: Identifier of the original token issuer.
        signature: Signature from revocation authority.
    """

    message_type: MessageType = field(default=MessageType.REVOCATION_NOTICE, init=False)
    token_id: bytes = b""
    revocation_time: int = 0
    issuer_id: bytes = b""
    signature: bytes = b""


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
    """

    message_type: MessageType = field(default=MessageType.RESOURCE_REQUEST, init=False)
    request_id: bytes = b""
    resource_type: str = ""
    resource_id: bytes = b""
    permissions: int = 0
    duration: int = 0
    payment_offer: bytes = b""


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
        timestamp: Report timestamp.
        signature: Client signature for non-repudiation.
    """

    message_type: MessageType = field(default=MessageType.METER_REPORT, init=False)
    meter_id: bytes = b""
    sequence_number: int = 0
    usage_count: int = 0
    usage_bytes: int = 0
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
        resource_type: Type of resource to price.
        resource_id: Specific resource identifier.
        quantity: Quantity to price.
        duration: Duration to price in seconds.
    """

    message_type: MessageType = field(default=MessageType.PRICE_REQUEST, init=False)
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
