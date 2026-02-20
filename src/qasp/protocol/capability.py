"""Capability-based access control.

This module implements capability tokens for fine-grained
access control in QASP.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Flag, auto

__all__ = [
    "CapabilityToken",
    "Permission",
    "attenuate_token",
    "create_token",
    "verify_token",
]


class Permission(Flag):
    """Permission flags for capability tokens."""

    NONE = 0
    READ = auto()
    WRITE = auto()
    EXECUTE = auto()
    DELEGATE = auto()
    ADMIN = auto()

    READ_WRITE = READ | WRITE
    ALL = READ | WRITE | EXECUTE | DELEGATE | ADMIN


@dataclass(frozen=True)
class CapabilityToken:
    """A capability token for access control."""

    resource: str
    permissions: Permission
    issuer: str
    subject: str
    issued_at: datetime
    expires_at: datetime
    signature: bytes
    constraints: dict[str, str] = field(default_factory=dict)


def create_token(
    resource: str,
    permissions: Permission,
    subject: str,
    signing_key: bytes,
    validity_seconds: int = 3600,
    constraints: dict[str, str] | None = None,
) -> CapabilityToken:
    """Create a new capability token.

    Args:
        resource: The resource this token grants access to.
        permissions: The permissions granted.
        subject: The token subject (recipient).
        signing_key: The issuer's signing key.
        validity_seconds: Token validity duration.
        constraints: Optional additional constraints.

    Returns:
        A signed CapabilityToken.
    """
    raise NotImplementedError("Capability tokens implementation pending")


def verify_token(
    token: CapabilityToken,
    issuer_public_key: bytes,
) -> bool:
    """Verify a capability token's signature.

    Args:
        token: The token to verify.
        issuer_public_key: The issuer's public key.

    Returns:
        True if the token is valid.
    """
    raise NotImplementedError("Capability tokens implementation pending")


def attenuate_token(
    token: CapabilityToken,
    new_permissions: Permission,
    signing_key: bytes,
) -> CapabilityToken:
    """Create a delegated token with reduced permissions.

    Args:
        token: The original token.
        new_permissions: The new (reduced) permissions.
        signing_key: The delegator's signing key.

    Returns:
        A new token with attenuated permissions.
    """
    raise NotImplementedError("Capability tokens implementation pending")
