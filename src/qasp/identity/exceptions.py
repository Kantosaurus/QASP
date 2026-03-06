"""Exception hierarchy for QASP identity operations.

This module defines specific exception types for different identity-related
failure modes, enabling precise error handling without exposing key material.
"""

from __future__ import annotations

__all__ = [
    "BindingError",
    "BindingExpiredError",
    "BindingPermissionError",
    "DHTEntryError",
    "DIDError",
    "DIDResolutionError",
    "ExpiredSVIDError",
    "IdentityError",
    "InvalidBindingError",
    "InvalidDIDError",
    "InvalidSPIFFEIDError",
    "KeyRotationError",
    "SPIFFEError",
    "SVIDVerificationError",
    "StaleEntryError",
    "ThresholdGroupError",
    "TrustBundleError",
]


class IdentityError(Exception):
    """Base exception for all QASP identity errors.

    All identity-related exceptions inherit from this class, allowing
    callers to catch all identity errors with a single except clause.
    """


class DIDError(IdentityError):
    """Base exception for DID-related errors.

    This includes DID creation, parsing, and resolution failures.
    """


class InvalidDIDError(DIDError):
    """Raised when a DID is malformed or invalid.

    This includes incorrect format, invalid method, or identifier
    that doesn't match the expected pattern.
    """


class DIDResolutionError(DIDError):
    """Raised when DID resolution fails.

    This may occur when the DID cannot be found in a registry or
    the resolution process encounters an error.
    """


class BindingError(IdentityError):
    """Base exception for binding-related errors.

    This includes binding creation, verification, and chain validation failures.
    """


class InvalidBindingError(BindingError):
    """Raised when a binding is malformed or invalid.

    This includes signature verification failures, invalid structure,
    or missing required fields.
    """


class BindingExpiredError(BindingError):
    """Raised when a binding has expired.

    This indicates the binding's expiry time has passed and it
    should no longer be accepted.
    """


class BindingPermissionError(BindingError):
    """Raised when a binding permission check fails.

    This indicates the binding does not grant the required permission
    for the requested operation.
    """


class DHTEntryError(DIDError):
    """Raised when a DHT entry is invalid (signature failure, bad structure)."""


class StaleEntryError(DHTEntryError):
    """Raised when a DHT entry version <= currently stored version (replay prevention)."""


class KeyRotationError(DIDError):
    """Raised when DID key rotation fails.

    This includes pre-commitment mismatches, invalid rotation proofs,
    or version increment violations.
    """


class SPIFFEError(IdentityError):
    """Base exception for SPIFFE-related errors."""


class InvalidSPIFFEIDError(SPIFFEError):
    """Raised when a SPIFFE ID is malformed or invalid."""


class SVIDVerificationError(SPIFFEError):
    """Raised when SVID certificate verification fails."""


class ExpiredSVIDError(SVIDVerificationError):
    """Raised when an SVID certificate has expired."""


class ThresholdGroupError(IdentityError):
    """Raised when threshold group creation or validation fails."""


class TrustBundleError(SPIFFEError):
    """Raised when a trust bundle operation fails."""
