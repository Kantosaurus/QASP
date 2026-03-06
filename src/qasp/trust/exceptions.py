"""Exception hierarchy for QASP trust operations.

This module defines specific exception types for different trust-related
failure modes, enabling precise error handling.
"""

from __future__ import annotations

__all__ = [
    "BehavioralError",
    "CertificationError",
    "DuplicateEntryError",
    "EntryNotFoundError",
    "InvalidProofError",
    "InvalidSLSALevelError",
    "InvalidTransitionError",
    "InvalidVCError",
    "ManifestError",
    "RegistryError",
    "ReputationError",
    "TrustError",
    "VCExpiredError",
    "VCNotYetValidError",
]


class TrustError(Exception):
    """Base exception for all QASP trust errors.

    All trust-related exceptions inherit from this class, allowing
    callers to catch all trust errors with a single except clause.
    """


class CertificationError(TrustError):
    """Base exception for Verifiable Credential errors.

    This includes VC creation, verification, and validation failures.
    """


class VCExpiredError(CertificationError):
    """Raised when a Verifiable Credential has expired.

    This indicates the VC's valid_until time has passed and it
    should no longer be accepted.
    """


class VCNotYetValidError(CertificationError):
    """Raised when a Verifiable Credential is not yet valid.

    This indicates the VC's valid_from time has not yet arrived.
    """


class InvalidVCError(CertificationError):
    """Raised when a Verifiable Credential is malformed or invalid.

    This includes missing required fields, invalid structure,
    or CBOR deserialization failures.
    """


class InvalidSLSALevelError(CertificationError):
    """Raised when an invalid SLSA level is specified.

    Valid SLSA levels are 1, 2, or 3.
    """


class InvalidProofError(CertificationError):
    """Raised when a proof is invalid or verification fails.

    This includes signature verification failures, invalid proof types,
    or missing proof fields.
    """


class RegistryError(TrustError):
    """Base exception for trust registry errors.

    This includes registration, lookup, and update failures.
    """


class EntryNotFoundError(RegistryError):
    """Raised when a trust registry entry is not found.

    This indicates the requested DID is not registered in the registry.
    """


class DuplicateEntryError(RegistryError):
    """Raised when attempting to register a duplicate entry.

    This indicates a trust entry already exists for the given DID.
    """


class ReputationError(TrustError):
    """Raised on reputation model failures."""


class BehavioralError(TrustError):
    """Raised on behavioral verification failures."""


class ManifestError(BehavioralError):
    """Raised on manifest signing or verification failures."""


class InvalidTransitionError(BehavioralError):
    """Raised on unpermitted FSM transitions."""
