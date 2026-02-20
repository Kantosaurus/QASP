"""Exception hierarchy for QASP identity operations.

This module defines specific exception types for different identity-related
failure modes, enabling precise error handling without exposing key material.
"""

from __future__ import annotations

__all__ = [
    "BindingError",
    "BindingExpiredError",
    "BindingPermissionError",
    "DIDError",
    "DIDResolutionError",
    "IdentityError",
    "InvalidBindingError",
    "InvalidDIDError",
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
