"""SPIFFE platform attestation for composite multi-owner tokens.

This module extends QASP's multi-owner capability system with SPIFFE SVID
platform attestations. A CompositeMultiOwnerToken wraps an existing
MultiOwnerCapabilityToken plus optional platform attestations, providing
enterprise-grade workload identity alongside capability authorization.

Zero attestations = identical behavior to existing MultiOwnerCapabilityToken.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime

import cbor2

from qasp.identity.exceptions import (
    ExpiredSVIDError,
    SVIDVerificationError,
    TrustBundleError,
)
from qasp.identity.spiffe import (
    SPIFFEID,
    SVIDCertificate,
    TrustBundleRegistry,
    parse_spiffe_id,
    parse_svid_from_x509,
    verify_svid_with_registry,
)
from qasp.protocol.capability import (
    CapabilityError,
    Constraints,
    DIDResolver,
    MultiOwnerCapabilityToken,
    VerbSet,
    verify_multi_owner_token,
)

__all__ = [
    "AttestationExpiredError",
    "CompositeMultiOwnerToken",
    "InvalidAttestationError",
    "PlatformAttestationEntry",
    "SPIFFEAttestationError",
    "attestation_from_cbor",
    "attestation_to_cbor",
    "composite_token_to_cbor",
    "composite_token_from_cbor",
    "create_composite_token",
    "verify_composite_token",
]

ATTESTATION_NONCE_SIZE = 16


# =============================================================================
# Exception Hierarchy
# =============================================================================


class SPIFFEAttestationError(CapabilityError):
    """Base exception for SPIFFE attestation errors."""

    alert_code: int = 70


class InvalidAttestationError(SPIFFEAttestationError):
    """Raised when a platform attestation is invalid."""

    alert_code: int = 71


class AttestationExpiredError(SPIFFEAttestationError):
    """Raised when a platform attestation has expired."""

    alert_code: int = 72


# =============================================================================
# Data Structures
# =============================================================================


@dataclass(frozen=True)
class PlatformAttestationEntry:
    """A platform attestation binding a SPIFFE SVID to a token.

    Attributes:
        role: The attestation role (always "platform").
        spiffe_id: The SPIFFE identity of the attesting workload.
        svid: The X.509 SVID certificate.
        attested_at: Timestamp when attestation was created.
        attestation_nonce: 16-byte freshness nonce.
    """

    role: str
    spiffe_id: SPIFFEID
    svid: SVIDCertificate
    attested_at: datetime
    attestation_nonce: bytes


@dataclass(frozen=True)
class CompositeMultiOwnerToken:
    """A multi-owner token with optional platform attestations.

    Wraps an existing MultiOwnerCapabilityToken and adds SPIFFE SVID
    attestations for enterprise workload identity. When platform_attestations
    is empty, behavior is identical to the wrapped token.

    Attributes:
        token: The underlying multi-owner capability token.
        platform_attestations: Tuple of platform attestation entries.
        composition: Composition mode ("all" = all attestations must pass).
    """

    token: MultiOwnerCapabilityToken
    platform_attestations: tuple[PlatformAttestationEntry, ...]
    composition: str = "all"

    def effective_verbs(self) -> VerbSet:
        """Delegates to the wrapped token."""
        return self.token.effective_verbs()

    def effective_constraints(self) -> Constraints:
        """Delegates to the wrapped token."""
        return self.token.effective_constraints()


# =============================================================================
# Token Creation
# =============================================================================


def create_composite_token(
    token: MultiOwnerCapabilityToken,
    platform_attestations: list[PlatformAttestationEntry] | None = None,
    composition: str = "all",
) -> CompositeMultiOwnerToken:
    """Create a composite multi-owner token with optional attestations.

    Args:
        token: The underlying multi-owner capability token.
        platform_attestations: Optional list of platform attestations.
        composition: Composition mode (default "all").

    Returns:
        A CompositeMultiOwnerToken.
    """
    attestations = tuple(platform_attestations) if platform_attestations else ()
    return CompositeMultiOwnerToken(
        token=token,
        platform_attestations=attestations,
        composition=composition,
    )


def create_platform_attestation(
    spiffe_id: SPIFFEID,
    svid: SVIDCertificate,
    now: datetime | None = None,
) -> PlatformAttestationEntry:
    """Create a platform attestation entry.

    Args:
        spiffe_id: The SPIFFE identity.
        svid: The X.509 SVID.
        now: Attestation timestamp (defaults to UTC now).

    Returns:
        A PlatformAttestationEntry with a fresh nonce.
    """
    if now is None:
        now = datetime.now(UTC)
    return PlatformAttestationEntry(
        role="platform",
        spiffe_id=spiffe_id,
        svid=svid,
        attested_at=now,
        attestation_nonce=os.urandom(ATTESTATION_NONCE_SIZE),
    )


# =============================================================================
# Verification
# =============================================================================


def verify_composite_token(
    composite: CompositeMultiOwnerToken,
    did_resolver: DIDResolver | None = None,
    trust_bundle_registry: TrustBundleRegistry | None = None,
    check_expiry: bool = True,
    now: datetime | None = None,
) -> bool:
    """Verify a composite multi-owner token.

    Step 1: Verify the inner multi-owner token (existing, unchanged).
    Step 2: For each attestation, verify SVID against trust bundle registry.
    Step 3: composition="all" means all must pass.

    Args:
        composite: The composite token to verify.
        did_resolver: Optional DID resolver for chain verification.
        trust_bundle_registry: Registry for SVID trust bundle lookup.
        check_expiry: Whether to check time-based constraints.
        now: Current time for validity checks.

    Returns:
        True if all verifications pass.

    Raises:
        SPIFFEAttestationError: If attestation verification fails.
    """
    # Step 1: Verify inner token
    verify_multi_owner_token(
        composite.token,
        did_resolver=did_resolver,
        check_expiry=check_expiry,
    )

    # Step 2: Verify attestations
    if not composite.platform_attestations:
        return True

    if now is None:
        now = datetime.now(UTC)

    for i, attestation in enumerate(composite.platform_attestations):
        _verify_single_attestation(attestation, trust_bundle_registry, now, i)

    return True


def _verify_single_attestation(
    attestation: PlatformAttestationEntry,
    registry: TrustBundleRegistry | None,
    now: datetime,
    index: int,
) -> None:
    """Verify a single platform attestation.

    Raises:
        InvalidAttestationError: If the attestation is structurally invalid.
        AttestationExpiredError: If the SVID has expired.
        SPIFFEAttestationError: If SVID verification fails.
    """
    if attestation.role != "platform":
        raise InvalidAttestationError(
            f"Attestation {index}: expected role 'platform', "
            f"got '{attestation.role}'"
        )

    if len(attestation.attestation_nonce) != ATTESTATION_NONCE_SIZE:
        raise InvalidAttestationError(
            f"Attestation {index}: invalid nonce size "
            f"(expected {ATTESTATION_NONCE_SIZE}, "
            f"got {len(attestation.attestation_nonce)})"
        )

    try:
        verify_svid_with_registry(attestation.svid, registry=registry, now=now)
    except ExpiredSVIDError as e:
        raise AttestationExpiredError(
            f"Attestation {index}: SVID expired: {e}"
        ) from e
    except (SVIDVerificationError, TrustBundleError) as e:
        raise SPIFFEAttestationError(
            f"Attestation {index}: SVID verification failed: {e}"
        ) from e


# =============================================================================
# CBOR Serialization
# =============================================================================


def attestation_to_cbor(attestation: PlatformAttestationEntry) -> bytes:
    """Serialize a PlatformAttestationEntry to CBOR.

    Returns:
        CBOR-encoded bytes.
    """
    data = {
        "role": attestation.role,
        "spiffe_id": str(attestation.spiffe_id),
        "svid_chain": list(attestation.svid.certificate_chain),
        "attested_at": attestation.attested_at.timestamp(),
        "attestation_nonce": attestation.attestation_nonce,
    }
    return cbor2.dumps(data)


def attestation_from_cbor(data: bytes) -> PlatformAttestationEntry:
    """Deserialize a PlatformAttestationEntry from CBOR.

    Args:
        data: CBOR-encoded bytes.

    Returns:
        A PlatformAttestationEntry.

    Raises:
        InvalidAttestationError: If the CBOR data is malformed.
    """
    try:
        decoded = cbor2.loads(data)
    except Exception as e:
        raise InvalidAttestationError(f"Invalid CBOR data: {e}") from e

    if not isinstance(decoded, dict):
        raise InvalidAttestationError("Attestation CBOR must be a map")

    try:
        spiffe_id = parse_spiffe_id(decoded["spiffe_id"])
        svid_chain = [bytes(c) for c in decoded["svid_chain"]]
        svid = parse_svid_from_x509(svid_chain)
        attested_at = datetime.fromtimestamp(decoded["attested_at"], tz=UTC)
        nonce = bytes(decoded["attestation_nonce"])

        return PlatformAttestationEntry(
            role=decoded["role"],
            spiffe_id=spiffe_id,
            svid=svid,
            attested_at=attested_at,
            attestation_nonce=nonce,
        )
    except (KeyError, TypeError, ValueError) as e:
        raise InvalidAttestationError(
            f"Missing or invalid field in attestation CBOR: {e}"
        ) from e


def composite_token_to_cbor(
    composite: CompositeMultiOwnerToken,
    token_serializer: bytes,
) -> bytes:
    """Serialize a CompositeMultiOwnerToken to CBOR.

    The inner MultiOwnerCapabilityToken must be pre-serialized by the caller,
    since its serialization depends on the full capability token CBOR format.

    Args:
        composite: The composite token.
        token_serializer: Pre-serialized inner token bytes.

    Returns:
        CBOR-encoded bytes.
    """
    attestation_cbor_list = [
        attestation_to_cbor(a) for a in composite.platform_attestations
    ]
    data = {
        "token": token_serializer,
        "platform_attestations": attestation_cbor_list,
        "composition": composite.composition,
    }
    return cbor2.dumps(data)


def composite_token_from_cbor(
    data: bytes,
    token_deserializer: MultiOwnerCapabilityToken,
) -> CompositeMultiOwnerToken:
    """Deserialize a CompositeMultiOwnerToken from CBOR.

    The inner MultiOwnerCapabilityToken must be pre-deserialized by the caller.

    Args:
        data: CBOR-encoded bytes.
        token_deserializer: Pre-deserialized inner token.

    Returns:
        A CompositeMultiOwnerToken.

    Raises:
        InvalidAttestationError: If the CBOR data is malformed.
    """
    try:
        decoded = cbor2.loads(data)
    except Exception as e:
        raise InvalidAttestationError(f"Invalid CBOR data: {e}") from e

    if not isinstance(decoded, dict):
        raise InvalidAttestationError("Composite token CBOR must be a map")

    try:
        attestations = [
            attestation_from_cbor(a_bytes)
            for a_bytes in decoded.get("platform_attestations", [])
        ]
        composition = decoded.get("composition", "all")
    except (KeyError, TypeError) as e:
        raise InvalidAttestationError(
            f"Invalid composite token CBOR: {e}"
        ) from e

    return CompositeMultiOwnerToken(
        token=token_deserializer,
        platform_attestations=tuple(attestations),
        composition=composition,
    )
