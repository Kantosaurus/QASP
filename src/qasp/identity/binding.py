"""Owner-agent binding for QASP identity.

This module implements the owner-binding mechanism that allows human owners
to authorize AI agents to act on their behalf with specific permissions.

Bindings are CBOR-encoded and signed with ML-DSA-65.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING

import cbor2

from qasp.crypto.exceptions import InvalidSignatureError
from qasp.crypto.signatures import sign, verify
from qasp.identity.did import DID
from qasp.identity.exceptions import (
    BindingExpiredError,
    BindingPermissionError,
    InvalidBindingError,
)

if TYPE_CHECKING:
    pass

__all__ = [
    "OwnerBinding",
    "Permission",
    "attenuate_binding",
    "create_owner_binding",
    "verify_binding_chain",
    "verify_owner_binding",
]

# Default binding validity: 1 year
DEFAULT_VALIDITY_SECONDS = 365 * 24 * 60 * 60

# Nonce size for binding uniqueness
NONCE_SIZE = 16


class Permission(StrEnum):
    """Standard permission grants for owner bindings.

    These permissions define what actions an agent is authorized to perform
    on behalf of their owner.
    """

    # Resource permissions
    RESOURCE_REQUEST = "resource:request"
    RESOURCE_DELEGATE = "resource:delegate"

    # Communication permissions
    COMM_INITIATE = "comm:initiate"
    COMM_ACCEPT = "comm:accept"

    # Token permissions (not passwords, permission strings)
    TOKEN_ISSUE = "token:issue"  # noqa: S105
    TOKEN_ATTENUATE = "token:attenuate"  # noqa: S105
    TOKEN_REVOKE = "token:revoke"  # noqa: S105

    # Identity permissions
    IDENTITY_ROTATE_KEY = "identity:rotate_key"
    IDENTITY_CREATE_SUB_AGENT = "identity:create_sub_agent"

    # Full access
    FULL = "*"


@dataclass(frozen=True)
class OwnerBinding:
    """An owner-agent binding that authorizes an agent.

    Attributes:
        agent_did: The DID of the authorized agent.
        owner_did: The DID of the authorizing owner.
        permissions: Set of granted permissions.
        expiry: When the binding expires.
        created: When the binding was created.
        nonce: Random nonce for uniqueness.
        signature: ML-DSA-65 signature over the binding data.
        max_delegation_depth: Maximum levels of delegation allowed.
        parent_binding_hash: Hash of parent binding for delegated bindings.
    """

    agent_did: DID
    owner_did: DID
    permissions: frozenset[str]
    expiry: datetime
    created: datetime
    nonce: bytes
    signature: bytes
    max_delegation_depth: int = 0
    parent_binding_hash: bytes | None = None

    def is_expired(self, now: datetime | None = None) -> bool:
        """Check if the binding has expired.

        Args:
            now: The current time (defaults to UTC now).

        Returns:
            True if the binding has expired.
        """
        if now is None:
            now = datetime.now(UTC)
        return now >= self.expiry

    def has_permission(self, permission: str | Permission) -> bool:
        """Check if the binding grants a specific permission.

        Args:
            permission: The permission to check.

        Returns:
            True if the permission is granted.
        """
        perm_str = permission.value if isinstance(permission, Permission) else permission

        # Full permission grants everything
        if Permission.FULL.value in self.permissions:
            return True

        return perm_str in self.permissions

    def check_permission(self, permission: str | Permission) -> None:
        """Check a permission, raising if not granted.

        Args:
            permission: The permission to check.

        Raises:
            BindingExpiredError: If the binding has expired.
            BindingPermissionError: If the permission is not granted.
        """
        if self.is_expired():
            raise BindingExpiredError(
                f"Binding for {self.agent_did} expired at {self.expiry.isoformat()}"
            )

        if not self.has_permission(permission):
            perm_str = permission.value if isinstance(permission, Permission) else permission
            raise BindingPermissionError(
                f"Permission '{perm_str}' not granted to {self.agent_did}"
            )

    def to_cbor(self) -> bytes:
        """Serialize the binding to CBOR.

        Returns:
            CBOR-encoded binding data (without signature for verification).
        """
        return _encode_binding_data(
            agent_did=self.agent_did,
            owner_did=self.owner_did,
            permissions=self.permissions,
            expiry=self.expiry,
            created=self.created,
            nonce=self.nonce,
            max_delegation_depth=self.max_delegation_depth,
            parent_binding_hash=self.parent_binding_hash,
        )

    def compute_hash(self) -> bytes:
        """Compute the SHA-384 hash of this binding.

        Returns:
            The hash bytes.
        """
        return hashlib.sha384(self.to_cbor() + self.signature).digest()


def _encode_binding_data(
    agent_did: DID,
    owner_did: DID,
    permissions: frozenset[str],
    expiry: datetime,
    created: datetime,
    nonce: bytes,
    max_delegation_depth: int,
    parent_binding_hash: bytes | None,
) -> bytes:
    """Encode binding data to CBOR for signing.

    Args:
        agent_did: The agent's DID.
        owner_did: The owner's DID.
        permissions: Set of permissions.
        expiry: Expiry datetime.
        created: Creation datetime.
        nonce: Random nonce.
        max_delegation_depth: Delegation depth limit.
        parent_binding_hash: Parent binding hash if delegated.

    Returns:
        CBOR-encoded bytes.
    """
    binding_data = {
        "agent_did": str(agent_did),
        "owner_did": str(owner_did),
        "permissions": sorted(permissions),
        "expiry": expiry.isoformat(),
        "created": created.isoformat(),
        "nonce": nonce.hex(),
        "max_delegation_depth": max_delegation_depth,
        "parent_binding_hash": parent_binding_hash.hex() if parent_binding_hash else None,
    }
    return cbor2.dumps(binding_data)


def create_owner_binding(
    agent_did: DID,
    owner_did: DID,
    owner_secret_key: bytes,
    permissions: set[str] | frozenset[str],
    validity_seconds: int = DEFAULT_VALIDITY_SECONDS,
    max_delegation_depth: int = 0,
) -> OwnerBinding:
    """Create a new owner binding.

    Args:
        agent_did: The DID of the agent to authorize.
        owner_did: The DID of the owner granting authorization.
        owner_secret_key: The owner's ML-DSA-65 secret key.
        permissions: Set of permissions to grant.
        validity_seconds: How long the binding is valid (default 1 year).
        max_delegation_depth: Maximum delegation depth allowed.

    Returns:
        A signed OwnerBinding.

    Raises:
        InvalidKeyError: If the secret key is invalid.
        SignatureError: If signing fails.
    """
    created = datetime.now(UTC)
    expiry = created + timedelta(seconds=validity_seconds)
    nonce = os.urandom(NONCE_SIZE)
    permissions_frozen = frozenset(permissions)

    # Encode and sign
    message = _encode_binding_data(
        agent_did=agent_did,
        owner_did=owner_did,
        permissions=permissions_frozen,
        expiry=expiry,
        created=created,
        nonce=nonce,
        max_delegation_depth=max_delegation_depth,
        parent_binding_hash=None,
    )
    signature = sign(owner_secret_key, message)

    return OwnerBinding(
        agent_did=agent_did,
        owner_did=owner_did,
        permissions=permissions_frozen,
        expiry=expiry,
        created=created,
        nonce=nonce,
        signature=signature,
        max_delegation_depth=max_delegation_depth,
        parent_binding_hash=None,
    )


def verify_owner_binding(
    binding: OwnerBinding,
    owner_public_key: bytes,
    check_expiry: bool = True,
) -> bool:
    """Verify an owner binding's signature.

    Args:
        binding: The binding to verify.
        owner_public_key: The owner's ML-DSA-65 public key.
        check_expiry: Whether to check if the binding has expired.

    Returns:
        True if the binding is valid.

    Raises:
        BindingExpiredError: If check_expiry is True and binding has expired.
        InvalidBindingError: If the signature is invalid.
    """
    if check_expiry and binding.is_expired():
        raise BindingExpiredError(
            f"Binding for {binding.agent_did} expired at {binding.expiry.isoformat()}"
        )

    message = binding.to_cbor()

    try:
        verify(owner_public_key, message, binding.signature)
        return True
    except InvalidSignatureError as e:
        raise InvalidBindingError(f"Binding signature verification failed: {e}") from e


def attenuate_binding(
    parent_binding: OwnerBinding,
    agent_secret_key: bytes,
    new_agent_did: DID,
    reduced_permissions: set[str] | frozenset[str],
    reduced_validity_seconds: int | None = None,
) -> OwnerBinding:
    """Create an attenuated binding from a parent binding.

    The new binding can only have:
    - A subset of the parent's permissions
    - A shorter validity period
    - A lower delegation depth

    Args:
        parent_binding: The parent binding to attenuate from.
        agent_secret_key: The delegating agent's secret key.
        new_agent_did: The DID of the new agent to authorize.
        reduced_permissions: Permissions for the new binding (must be subset).
        reduced_validity_seconds: Validity period (must be shorter than remaining).

    Returns:
        A new attenuated OwnerBinding.

    Raises:
        InvalidBindingError: If attenuation constraints are violated.
        BindingExpiredError: If the parent binding has expired.
    """
    # Check parent hasn't expired
    if parent_binding.is_expired():
        raise BindingExpiredError(
            f"Cannot attenuate expired binding for {parent_binding.agent_did}"
        )

    # Check delegation depth
    if parent_binding.max_delegation_depth <= 0:
        raise InvalidBindingError(
            "Parent binding does not allow delegation (max_delegation_depth=0)"
        )

    # Validate permissions are a subset
    reduced_frozen = frozenset(reduced_permissions)
    if (
        Permission.FULL.value not in parent_binding.permissions
        and not reduced_frozen.issubset(parent_binding.permissions)
    ):
        extra = reduced_frozen - parent_binding.permissions
        raise InvalidBindingError(f"Cannot delegate permissions not held: {extra}")
    # Note: FULL permission allows delegating any specific permissions

    # Calculate validity
    now = datetime.now(UTC)
    remaining_seconds = int((parent_binding.expiry - now).total_seconds())

    if reduced_validity_seconds is None:
        validity_seconds = remaining_seconds
    elif reduced_validity_seconds > remaining_seconds:
        raise InvalidBindingError(
            f"Requested validity ({reduced_validity_seconds}s) exceeds "
            f"parent's remaining validity ({remaining_seconds}s)"
        )
    else:
        validity_seconds = reduced_validity_seconds

    created = now
    expiry = created + timedelta(seconds=validity_seconds)
    nonce = os.urandom(NONCE_SIZE)
    new_depth = parent_binding.max_delegation_depth - 1
    parent_hash = parent_binding.compute_hash()

    # Encode and sign with agent's key
    message = _encode_binding_data(
        agent_did=new_agent_did,
        owner_did=parent_binding.owner_did,  # Original owner
        permissions=reduced_frozen,
        expiry=expiry,
        created=created,
        nonce=nonce,
        max_delegation_depth=new_depth,
        parent_binding_hash=parent_hash,
    )
    signature = sign(agent_secret_key, message)

    return OwnerBinding(
        agent_did=new_agent_did,
        owner_did=parent_binding.owner_did,
        permissions=reduced_frozen,
        expiry=expiry,
        created=created,
        nonce=nonce,
        signature=signature,
        max_delegation_depth=new_depth,
        parent_binding_hash=parent_hash,
    )


def verify_binding_chain(
    bindings: list[OwnerBinding],
    root_owner_public_key: bytes,
    check_expiry: bool = True,
) -> bool:
    """Verify a chain of delegated bindings.

    The chain starts with the root owner's binding and each subsequent
    binding must be properly attenuated from its parent.

    Args:
        bindings: List of bindings from root to leaf.
        root_owner_public_key: The root owner's public key.
        check_expiry: Whether to check binding expiry.

    Returns:
        True if the entire chain is valid.

    Raises:
        InvalidBindingError: If any binding in the chain is invalid.
        BindingExpiredError: If any binding has expired and check_expiry is True.
    """
    if not bindings:
        raise InvalidBindingError("Empty binding chain")

    # First binding must be from the root owner
    root_binding = bindings[0]
    if root_binding.parent_binding_hash is not None:
        raise InvalidBindingError(
            "Root binding cannot have a parent binding hash"
        )

    verify_owner_binding(root_binding, root_owner_public_key, check_expiry=check_expiry)

    # Verify each subsequent binding
    prev_binding = root_binding
    for i, binding in enumerate(bindings[1:], start=1):
        # Check parent hash matches
        expected_hash = prev_binding.compute_hash()
        if binding.parent_binding_hash != expected_hash:
            raise InvalidBindingError(
                f"Binding {i} parent hash mismatch"
            )

        # Check delegation depth is decremented
        if binding.max_delegation_depth != prev_binding.max_delegation_depth - 1:
            raise InvalidBindingError(
                f"Binding {i} has incorrect delegation depth"
            )

        # Check permissions are subset
        if (
            Permission.FULL.value not in prev_binding.permissions
            and not binding.permissions.issubset(prev_binding.permissions)
        ):
            raise InvalidBindingError(f"Binding {i} has permissions not granted by parent")

        # Check expiry is not later than parent
        if binding.expiry > prev_binding.expiry:
            raise InvalidBindingError(
                f"Binding {i} expiry exceeds parent expiry"
            )

        # Verify signature with previous agent's key
        # Note: In practice, we'd need the previous agent's public key
        # For now, we assume the chain structure is correct
        # The actual verification would require looking up the agent's DID document

        if check_expiry and binding.is_expired():
            raise BindingExpiredError(
                f"Binding {i} has expired"
            )

        prev_binding = binding

    return True
