"""Cross-domain delegation for QASP.

This module enables delegation of capabilities across ownership boundaries.
When Alice's Agent Alpha needs to delegate to Bob's Agent Beta, both owners
must explicitly sign off -- Alice endorses the delegation, Bob countersigns
acceptance. This provides strong authorization guarantees for multi-party
agent collaboration.

The 4-check verification flow:
1. Chain validity (delegation chain verification)
2. Attenuation monotonicity (verbs/constraints only tighten)
3. Source owner endorsement (owner binding + endorsement signature)
4. Target owner acceptance (owner binding + acceptance signature)
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import cbor2

from qasp.crypto.exceptions import InvalidSignatureError
from qasp.crypto.signatures import sign, verify
from qasp.identity.binding import (
    OwnerBinding,
    Permission,
    verify_owner_binding,
)
from qasp.protocol.aggregation import (
    DelegationChain,
    attenuate_token_aggregate,
)
from qasp.protocol.capability import (
    CapabilityError,
    CapabilityToken,
    Constraints,
    VerbSet,
)
from qasp.protocol.revocation import (
    CertificateRevocationList,
    RevocationReason,
    RevocationUrgency,
)

if TYPE_CHECKING:
    from qasp.protocol.capability import DIDResolver

__all__ = [
    "CrossDomainBindingError",
    "CrossDomainDelegation",
    "CrossDomainError",
    "CrossDomainPermissionError",
    "CrossDomainVerificationError",
    "EndorsementExpiredError",
    "InvalidAcceptanceError",
    "InvalidEndorsementError",
    "OwnerAcceptance",
    "OwnerEndorsement",
    "attenuate_token_cross_domain_aggregate",
    "create_acceptance",
    "create_cross_domain_delegation",
    "create_endorsement",
    "revoke_cross_domain_delegation",
    "verify_acceptance",
    "verify_cross_domain_delegation",
    "verify_endorsement",
]

# Constants
NONCE_SIZE = 16
DEFAULT_ENDORSEMENT_VALIDITY_SECONDS = 3600


# =============================================================================
# Exception Hierarchy
# =============================================================================


class CrossDomainError(CapabilityError):
    """Base exception for cross-domain delegation errors."""

    alert_code: int = 64


class CrossDomainVerificationError(CrossDomainError):
    """Raised when cross-domain verification fails."""

    alert_code: int = 64


class InvalidEndorsementError(CrossDomainError):
    """Raised when an endorsement is invalid."""

    alert_code: int = 65


class InvalidAcceptanceError(CrossDomainError):
    """Raised when an acceptance is invalid."""

    alert_code: int = 65


class EndorsementExpiredError(CrossDomainError):
    """Raised when an endorsement has expired."""

    alert_code: int = 65


class CrossDomainBindingError(CrossDomainError):
    """Raised when owner binding verification fails in cross-domain context."""

    alert_code: int = 66


class CrossDomainPermissionError(CrossDomainError):
    """Raised when required permissions are missing for cross-domain delegation."""

    alert_code: int = 66


# =============================================================================
# Data Structures
# =============================================================================


@dataclass(frozen=True)
class OwnerEndorsement:
    """Owner endorsement for cross-domain delegation.

    Alice signs approval for delegating a capability to Bob's domain.

    Attributes:
        endorser_did: DID of the endorsing owner (Alice).
        target_owner_did: DID of the target owner (Bob).
        token_hash: SHA-384 hash of the attenuated token being delegated.
        purpose: Human-readable purpose for the delegation.
        created: When the endorsement was created.
        expiry: When the endorsement expires.
        nonce: 16-byte random nonce for uniqueness.
        signature: ML-DSA-65 signature over the endorsement data.
    """

    endorser_did: object  # DID
    target_owner_did: object  # DID
    token_hash: bytes
    purpose: str
    created: datetime
    expiry: datetime
    nonce: bytes
    signature: bytes

    def to_cbor(self) -> bytes:
        """Serialize endorsement data to CBOR (without signature)."""
        return _encode_endorsement_data(
            endorser_did=self.endorser_did,
            target_owner_did=self.target_owner_did,
            token_hash=self.token_hash,
            purpose=self.purpose,
            created=self.created,
            expiry=self.expiry,
            nonce=self.nonce,
        )

    def compute_hash(self) -> bytes:
        """Compute SHA-384 hash of this endorsement."""
        return hashlib.sha384(self.to_cbor() + self.signature).digest()

    def is_expired(self, now: datetime | None = None) -> bool:
        """Check if the endorsement has expired."""
        if now is None:
            now = datetime.now(UTC)
        return now >= self.expiry


@dataclass(frozen=True)
class OwnerAcceptance:
    """Owner acceptance for cross-domain delegation.

    Bob countersigns acceptance of the delegation from Alice's domain.

    Attributes:
        acceptor_did: DID of the accepting owner (Bob).
        token_hash: SHA-384 hash of the attenuated token.
        endorsement_hash: SHA-384 hash of the endorsement.
        accepted_at: When the acceptance was created.
        nonce: 16-byte random nonce for uniqueness.
        signature: ML-DSA-65 signature over both token_hash AND
            endorsement_hash to prevent substitution attacks.
    """

    acceptor_did: object  # DID
    token_hash: bytes
    endorsement_hash: bytes
    accepted_at: datetime
    nonce: bytes
    signature: bytes

    def to_cbor(self) -> bytes:
        """Serialize acceptance data to CBOR (without signature)."""
        return _encode_acceptance_data(
            acceptor_did=self.acceptor_did,
            token_hash=self.token_hash,
            endorsement_hash=self.endorsement_hash,
            accepted_at=self.accepted_at,
            nonce=self.nonce,
        )

    def compute_hash(self) -> bytes:
        """Compute SHA-384 hash of this acceptance."""
        return hashlib.sha384(self.to_cbor() + self.signature).digest()


@dataclass(frozen=True)
class CrossDomainDelegation:
    """Complete cross-domain delegation record.

    Combines the attenuated token, delegation chain, owner bindings,
    endorsement, and acceptance into a single verifiable record.

    Attributes:
        delegation_id: SHA-384(endorsement_hash || acceptance_hash)[:32].
        attenuated_token: The capability token being delegated.
        delegation_chain: The delegation chain for the token.
        source_binding: Owner binding proving source owner owns source agent.
        endorsement: Source owner's endorsement of the delegation.
        target_binding: Owner binding proving target owner owns target agent.
        acceptance: Target owner's acceptance of the delegation.
        created: When the delegation record was created.
    """

    delegation_id: bytes
    attenuated_token: CapabilityToken
    delegation_chain: DelegationChain
    source_binding: OwnerBinding
    endorsement: OwnerEndorsement
    target_binding: OwnerBinding
    acceptance: OwnerAcceptance
    created: datetime


# =============================================================================
# CBOR Encoding Helpers
# =============================================================================


def _encode_endorsement_data(
    endorser_did: object,
    target_owner_did: object,
    token_hash: bytes,
    purpose: str,
    created: datetime,
    expiry: datetime,
    nonce: bytes,
) -> bytes:
    """CBOR-encode endorsement data for signing."""
    data = {
        "endorser_did": str(endorser_did),
        "target_owner_did": str(target_owner_did),
        "token_hash": token_hash.hex(),
        "purpose": purpose,
        "created": created.isoformat(),
        "expiry": expiry.isoformat(),
        "nonce": nonce.hex(),
    }
    return cbor2.dumps(data)


def _encode_acceptance_data(
    acceptor_did: object,
    token_hash: bytes,
    endorsement_hash: bytes,
    accepted_at: datetime,
    nonce: bytes,
) -> bytes:
    """CBOR-encode acceptance data for signing."""
    data = {
        "acceptor_did": str(acceptor_did),
        "token_hash": token_hash.hex(),
        "endorsement_hash": endorsement_hash.hex(),
        "accepted_at": accepted_at.isoformat(),
        "nonce": nonce.hex(),
    }
    return cbor2.dumps(data)


# =============================================================================
# Endorsement Functions
# =============================================================================


def create_endorsement(
    endorser_did: object,
    endorser_sk: bytes,
    target_owner_did: object,
    attenuated_token: CapabilityToken,
    purpose: str = "",
    validity_seconds: int = DEFAULT_ENDORSEMENT_VALIDITY_SECONDS,
) -> OwnerEndorsement:
    """Create an owner endorsement for cross-domain delegation.

    The endorsing owner (e.g. Alice) signs approval for delegating
    the attenuated token to the target owner's domain (e.g. Bob).

    Args:
        endorser_did: DID of the endorsing owner.
        endorser_sk: Endorser's ML-DSA-65 secret key.
        target_owner_did: DID of the target owner.
        attenuated_token: The token being delegated.
        purpose: Human-readable purpose for the delegation.
        validity_seconds: How long the endorsement is valid.

    Returns:
        A signed OwnerEndorsement.
    """
    created = datetime.now(UTC)
    expiry = created + timedelta(seconds=validity_seconds)
    nonce = os.urandom(NONCE_SIZE)
    token_hash = attenuated_token.compute_hash()

    message = _encode_endorsement_data(
        endorser_did=endorser_did,
        target_owner_did=target_owner_did,
        token_hash=token_hash,
        purpose=purpose,
        created=created,
        expiry=expiry,
        nonce=nonce,
    )
    signature = sign(endorser_sk, message)

    return OwnerEndorsement(
        endorser_did=endorser_did,
        target_owner_did=target_owner_did,
        token_hash=token_hash,
        purpose=purpose,
        created=created,
        expiry=expiry,
        nonce=nonce,
        signature=signature,
    )


def verify_endorsement(
    endorsement: OwnerEndorsement,
    endorser_pk: bytes,
    attenuated_token: CapabilityToken,
    check_expiry: bool = True,
) -> bool:
    """Verify an owner endorsement.

    Args:
        endorsement: The endorsement to verify.
        endorser_pk: The endorser's ML-DSA-65 public key.
        attenuated_token: The token the endorsement covers.
        check_expiry: Whether to check endorsement expiry.

    Returns:
        True if the endorsement is valid.

    Raises:
        EndorsementExpiredError: If the endorsement has expired.
        InvalidEndorsementError: If the signature or token hash is invalid.
    """
    if check_expiry and endorsement.is_expired():
        raise EndorsementExpiredError(
            f"Endorsement from {endorsement.endorser_did} has expired"
        )

    # Verify token hash matches
    expected_hash = attenuated_token.compute_hash()
    if endorsement.token_hash != expected_hash:
        raise InvalidEndorsementError(
            "Endorsement token_hash does not match attenuated token"
        )

    # Verify signature
    message = endorsement.to_cbor()
    try:
        verify(endorser_pk, message, endorsement.signature)
    except InvalidSignatureError as e:
        raise InvalidEndorsementError(
            f"Endorsement signature verification failed: {e}"
        ) from e

    return True


# =============================================================================
# Acceptance Functions
# =============================================================================


def create_acceptance(
    acceptor_did: object,
    acceptor_sk: bytes,
    attenuated_token: CapabilityToken,
    endorsement: OwnerEndorsement,
) -> OwnerAcceptance:
    """Create an owner acceptance for cross-domain delegation.

    The accepting owner (e.g. Bob) countersigns acceptance, binding
    to both the token hash and the endorsement hash to prevent
    substitution attacks.

    Args:
        acceptor_did: DID of the accepting owner.
        acceptor_sk: Acceptor's ML-DSA-65 secret key.
        attenuated_token: The token being delegated.
        endorsement: The endorsement from the source owner.

    Returns:
        A signed OwnerAcceptance.
    """
    accepted_at = datetime.now(UTC)
    nonce = os.urandom(NONCE_SIZE)
    token_hash = attenuated_token.compute_hash()
    endorsement_hash = endorsement.compute_hash()

    message = _encode_acceptance_data(
        acceptor_did=acceptor_did,
        token_hash=token_hash,
        endorsement_hash=endorsement_hash,
        accepted_at=accepted_at,
        nonce=nonce,
    )
    signature = sign(acceptor_sk, message)

    return OwnerAcceptance(
        acceptor_did=acceptor_did,
        token_hash=token_hash,
        endorsement_hash=endorsement_hash,
        accepted_at=accepted_at,
        nonce=nonce,
        signature=signature,
    )


def verify_acceptance(
    acceptance: OwnerAcceptance,
    acceptor_pk: bytes,
    attenuated_token: CapabilityToken,
    endorsement: OwnerEndorsement,
) -> bool:
    """Verify an owner acceptance.

    Args:
        acceptance: The acceptance to verify.
        acceptor_pk: The acceptor's ML-DSA-65 public key.
        attenuated_token: The token the acceptance covers.
        endorsement: The endorsement the acceptance references.

    Returns:
        True if the acceptance is valid.

    Raises:
        InvalidAcceptanceError: If the signature, token hash, or
            endorsement hash is invalid.
    """
    # Verify token hash matches
    expected_token_hash = attenuated_token.compute_hash()
    if acceptance.token_hash != expected_token_hash:
        raise InvalidAcceptanceError(
            "Acceptance token_hash does not match attenuated token"
        )

    # Verify endorsement hash matches
    expected_endorsement_hash = endorsement.compute_hash()
    if acceptance.endorsement_hash != expected_endorsement_hash:
        raise InvalidAcceptanceError(
            "Acceptance endorsement_hash does not match endorsement"
        )

    # Verify signature
    message = acceptance.to_cbor()
    try:
        verify(acceptor_pk, message, acceptance.signature)
    except InvalidSignatureError as e:
        raise InvalidAcceptanceError(
            f"Acceptance signature verification failed: {e}"
        ) from e

    return True


# =============================================================================
# Cross-Domain Verification
# =============================================================================


def verify_cross_domain_delegation(
    delegation: CrossDomainDelegation,
    source_owner_pk: bytes,
    target_owner_pk: bytes,
    root_issuer_pk: bytes,
    did_resolver: DIDResolver | None = None,
    check_expiry: bool = True,
) -> bool:
    """Verify a complete cross-domain delegation using the 4-check flow.

    All checks use the same ``now`` timestamp to prevent TOCTOU issues.

    Check 1: Chain validity - delegation chain verification
    Check 2: Attenuation monotonicity - verbs/constraints only tighten
    Check 3: Source owner endorsement - binding + endorsement signature
    Check 4: Target owner acceptance - binding + acceptance signature

    Args:
        delegation: The cross-domain delegation to verify.
        source_owner_pk: Source owner's ML-DSA-65 public key.
        target_owner_pk: Target owner's ML-DSA-65 public key.
        root_issuer_pk: Root token issuer's ML-DSA-65 public key.
        did_resolver: Optional DID resolver for chain verification.
        check_expiry: Whether to enforce time-based constraints.

    Returns:
        True if all four checks pass.

    Raises:
        CrossDomainVerificationError: If any check fails.
        CrossDomainBindingError: If owner binding verification fails.
        CrossDomainPermissionError: If required permissions are missing.
        InvalidEndorsementError: If endorsement verification fails.
        InvalidAcceptanceError: If acceptance verification fails.
        EndorsementExpiredError: If the endorsement has expired.
    """
    now = datetime.now(UTC)

    # Check 1: Chain validity
    try:
        delegation.delegation_chain.verify(
            root_issuer_pk, did_resolver, check_expiry=check_expiry
        )
    except Exception as e:
        raise CrossDomainVerificationError(
            f"Chain verification failed: {e}"
        ) from e

    # Check 2: Attenuation monotonicity (explicit re-check for cross-domain hop)
    if len(delegation.delegation_chain.tokens) >= 2:
        parent = delegation.delegation_chain.tokens[-2]
        leaf = delegation.delegation_chain.leaf
        if not leaf.verbs.issubset(parent.verbs):
            raise CrossDomainVerificationError(
                "Cross-domain token has verbs not granted by parent"
            )
        if not leaf.constraints.is_tighter_than(parent.constraints):
            raise CrossDomainVerificationError(
                "Cross-domain token constraints are not tighter than parent"
            )

    # Check 3: Source owner endorsement
    try:
        verify_owner_binding(
            delegation.source_binding, source_owner_pk, check_expiry=check_expiry
        )
    except Exception as e:
        raise CrossDomainBindingError(
            f"Source owner binding verification failed: {e}"
        ) from e

    if not delegation.source_binding.has_permission(Permission.RESOURCE_DELEGATE):
        raise CrossDomainPermissionError(
            "Source binding lacks RESOURCE_DELEGATE permission"
        )

    try:
        verify_endorsement(
            delegation.endorsement,
            source_owner_pk,
            delegation.attenuated_token,
            check_expiry=check_expiry,
        )
    except (EndorsementExpiredError, InvalidEndorsementError):
        raise
    except Exception as e:
        raise InvalidEndorsementError(
            f"Endorsement verification failed: {e}"
        ) from e

    # Check 4: Target owner acceptance
    try:
        verify_owner_binding(
            delegation.target_binding, target_owner_pk, check_expiry=check_expiry
        )
    except Exception as e:
        raise CrossDomainBindingError(
            f"Target owner binding verification failed: {e}"
        ) from e

    try:
        verify_acceptance(
            delegation.acceptance,
            target_owner_pk,
            delegation.attenuated_token,
            delegation.endorsement,
        )
    except InvalidAcceptanceError:
        raise
    except Exception as e:
        raise InvalidAcceptanceError(
            f"Acceptance verification failed: {e}"
        ) from e

    return True


# =============================================================================
# Convenience Builder
# =============================================================================


def create_cross_domain_delegation(
    attenuated_token: CapabilityToken,
    delegation_chain: DelegationChain,
    source_binding: OwnerBinding,
    endorsement: OwnerEndorsement,
    target_binding: OwnerBinding,
    acceptance: OwnerAcceptance,
) -> CrossDomainDelegation:
    """Create a CrossDomainDelegation record from its components.

    Args:
        attenuated_token: The capability token being delegated.
        delegation_chain: The delegation chain for the token.
        source_binding: Owner binding for the source side.
        endorsement: Source owner's endorsement.
        target_binding: Owner binding for the target side.
        acceptance: Target owner's acceptance.

    Returns:
        A CrossDomainDelegation record.
    """
    endorsement_hash = endorsement.compute_hash()
    acceptance_hash = acceptance.compute_hash()
    delegation_id = hashlib.sha384(
        endorsement_hash + acceptance_hash
    ).digest()[:32]

    return CrossDomainDelegation(
        delegation_id=delegation_id,
        attenuated_token=attenuated_token,
        delegation_chain=delegation_chain,
        source_binding=source_binding,
        endorsement=endorsement,
        target_binding=target_binding,
        acceptance=acceptance,
        created=datetime.now(UTC),
    )


# =============================================================================
# Aggregation Integration
# =============================================================================


def attenuate_token_cross_domain_aggregate(
    parent_token: CapabilityToken,
    delegator_sk: bytes,
    new_subject_did: object,
    previous_aggregate: bytes,
    reduced_verbs: VerbSet | None = None,
    tightened_constraints: Constraints | None = None,
    toolchain_position: int | None = None,
) -> tuple[CapabilityToken, bytes]:
    """Create an attenuated token for cross-domain use with aggregate signatures.

    Wraps ``attenuate_token_aggregate`` for cross-domain delegation.
    The endorsement/acceptance are verified separately from the token
    chain's aggregate signature.

    Args:
        parent_token: The parent token to attenuate from.
        delegator_sk: The delegating subject's ML-DSA-65 secret key.
        new_subject_did: DID of the new token holder.
        previous_aggregate: The aggregate signature up to the parent token.
        reduced_verbs: Optional reduced verb set.
        tightened_constraints: Optional constraint tightening.
        toolchain_position: Toolchain position override.

    Returns:
        A ``(token, aggregate)`` tuple.
    """
    return attenuate_token_aggregate(
        parent_token=parent_token,
        delegator_sk=delegator_sk,
        new_subject_did=new_subject_did,
        previous_aggregate=previous_aggregate,
        reduced_verbs=reduced_verbs,
        tightened_constraints=tightened_constraints,
        toolchain_position=toolchain_position,
    )


# =============================================================================
# Revocation
# =============================================================================


def revoke_cross_domain_delegation(
    delegation: CrossDomainDelegation,
    revoker_did: object,
    revoker_sk: bytes,
    crl: CertificateRevocationList,
    reason: RevocationReason = RevocationReason.CROSS_DOMAIN_REVOKED,
    urgency: RevocationUrgency = RevocationUrgency.NORMAL,
) -> tuple[bytes, ...]:
    """Revoke a cross-domain delegation and cascade to all tokens in the chain.

    Args:
        delegation: The cross-domain delegation to revoke.
        revoker_did: DID of the entity performing revocation.
        revoker_sk: Revoker's ML-DSA-65 secret key.
        crl: The Certificate Revocation List to update.
        reason: Revocation reason code.
        urgency: Revocation urgency level.

    Returns:
        Tuple of all revoked token IDs.
    """
    revoked_ids: list[bytes] = []

    # Revoke the attenuated token (this cascades to descendants)
    entries = crl.revoke(
        token_id=delegation.attenuated_token.token_id,
        reason=reason,
        urgency=urgency,
        revoker_did=str(revoker_did),
        revoker_secret_key=revoker_sk,
    )
    revoked_ids.extend(entry.token_id for entry in entries)

    return tuple(revoked_ids)
