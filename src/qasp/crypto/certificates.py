"""X.509-PQ certificates.

This module provides support for X.509 certificates with
post-quantum signature algorithms.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

__all__ = [
    "Certificate",
    "create_self_signed",
    "parse_certificate",
    "verify_certificate",
]


@dataclass(frozen=True)
class Certificate:
    """An X.509-PQ certificate."""

    subject: str
    issuer: str
    public_key: bytes
    signature_algorithm: str
    signature: bytes
    not_before: datetime
    not_after: datetime
    serial_number: int
    raw: bytes


def create_self_signed(
    subject: str,
    keypair: tuple[bytes, bytes],
    validity_days: int = 365,
) -> Certificate:
    """Create a self-signed X.509-PQ certificate.

    Args:
        subject: The certificate subject (DN).
        keypair: Tuple of (public_key, private_key).
        validity_days: Certificate validity period.

    Returns:
        A Certificate instance.
    """
    raise NotImplementedError("X.509-PQ implementation pending")


def verify_certificate(
    certificate: Certificate,
    issuer_public_key: bytes | None = None,
) -> bool:
    """Verify a certificate's signature.

    Args:
        certificate: The certificate to verify.
        issuer_public_key: The issuer's public key (None for self-signed).

    Returns:
        True if the signature is valid.
    """
    raise NotImplementedError("X.509-PQ implementation pending")


def parse_certificate(data: bytes) -> Certificate:
    """Parse a DER-encoded X.509-PQ certificate.

    Args:
        data: The DER-encoded certificate data.

    Returns:
        A Certificate instance.
    """
    raise NotImplementedError("X.509-PQ implementation pending")
