"""Token revocation and Certificate Revocation List (CRL).

This module implements the P2 revocation system for QASP capability tokens.
It provides a thread-safe CRL with BFS cascade revocation of delegation
chains, grace period handling, and cryptographic signature verification.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING

import cbor2

from qasp.crypto.exceptions import InvalidSignatureError
from qasp.crypto.signatures import sign, verify
from qasp.protocol.capability import CapabilityError

if TYPE_CHECKING:
    from qasp.protocol.capability import CapabilityToken

__all__ = [
    "NORMAL_GRACE_PERIOD_SECONDS",
    "CertificateRevocationList",
    "InvalidRevocationError",
    "RevocationAuthorityError",
    "RevocationEntry",
    "RevocationError",
    "RevocationReason",
    "RevocationUrgency",
    "TokenAlreadyRevokedError",
    "check_revocation",
    "revoke_token",
]

# =============================================================================
# Constants
# =============================================================================

NORMAL_GRACE_PERIOD_SECONDS = 300


# =============================================================================
# Enums
# =============================================================================


class RevocationUrgency(IntEnum):
    """Urgency level for token revocation."""

    CRITICAL = 0
    NORMAL = 1
    PLANNED = 2


class RevocationReason(IntEnum):
    """Reason for token revocation."""

    UNSPECIFIED = 0
    KEY_COMPROMISE = 1
    PRIVILEGE_WITHDRAWN = 2
    TOKEN_SUPERSEDED = 3
    DELEGATION_REVOKED = 4
    OWNER_REQUEST = 5
    CONSTRAINT_VIOLATION = 6


# =============================================================================
# Exceptions
# =============================================================================


class RevocationError(CapabilityError):
    """Base exception for revocation errors."""

    alert_code: int = 56


class TokenAlreadyRevokedError(RevocationError):
    """Raised when attempting to revoke an already-revoked token."""

    alert_code: int = 57


class RevocationAuthorityError(RevocationError):
    """Raised when the revoker lacks authority."""

    alert_code: int = 58


class InvalidRevocationError(RevocationError):
    """Raised when revocation data is invalid."""

    alert_code: int = 59


# =============================================================================
# Data Structures
# =============================================================================


@dataclass(frozen=True)
class RevocationEntry:
    """An entry in the Certificate Revocation List.

    Attributes:
        token_id: Identifier of the revoked token.
        revocation_time: Unix timestamp when the revocation was created.
        effective_time: Unix timestamp when the revocation takes effect.
        reason: Reason code for the revocation.
        urgency: Urgency level of the revocation.
        revoker_did: DID of the entity performing the revocation.
        parent_revocation_id: Token ID that triggered this cascade entry.
        signature: ML-DSA-65 signature over the revocation data.
    """

    token_id: bytes
    revocation_time: int
    effective_time: int
    reason: RevocationReason
    urgency: RevocationUrgency
    revoker_did: str
    parent_revocation_id: bytes | None
    signature: bytes


# =============================================================================
# Signing Helpers
# =============================================================================


def _encode_revocation_data(
    token_id: bytes,
    revocation_time: int,
    effective_time: int,
    reason: int,
    urgency: int,
    revoker_did: str,
) -> bytes:
    """CBOR-encode revocation data for signing.

    Args:
        token_id: Token being revoked.
        revocation_time: When the revocation was issued.
        effective_time: When the revocation takes effect.
        reason: Revocation reason code.
        urgency: Urgency level.
        revoker_did: DID of the revoker.

    Returns:
        CBOR-encoded bytes.
    """
    data = {
        "token_id": token_id.hex(),
        "revocation_time": revocation_time,
        "effective_time": effective_time,
        "reason": reason,
        "urgency": urgency,
        "revoker_did": revoker_did,
    }
    return cbor2.dumps(data)


def _sign_revocation(
    secret_key: bytes,
    token_id: bytes,
    revocation_time: int,
    effective_time: int,
    reason: int,
    urgency: int,
    revoker_did: str,
) -> bytes:
    """Sign revocation data with ML-DSA-65.

    Args:
        secret_key: Revoker's secret key.
        token_id: Token being revoked.
        revocation_time: When the revocation was issued.
        effective_time: When the revocation takes effect.
        reason: Revocation reason code.
        urgency: Urgency level.
        revoker_did: DID of the revoker.

    Returns:
        Signature bytes.
    """
    message = _encode_revocation_data(
        token_id, revocation_time, effective_time, reason, urgency, revoker_did
    )
    return sign(secret_key, message)


def _verify_revocation_signature(
    public_key: bytes,
    entry: RevocationEntry,
) -> bool:
    """Verify a revocation entry's signature.

    Args:
        public_key: Revoker's public key.
        entry: The revocation entry to verify.

    Returns:
        True if the signature is valid.

    Raises:
        InvalidRevocationError: If the signature is invalid.
    """
    message = _encode_revocation_data(
        entry.token_id,
        entry.revocation_time,
        entry.effective_time,
        entry.reason,
        entry.urgency,
        entry.revoker_did,
    )
    try:
        verify(public_key, message, entry.signature)
    except InvalidSignatureError as e:
        raise InvalidRevocationError(
            f"Revocation signature verification failed: {e}"
        ) from e
    return True


# =============================================================================
# Certificate Revocation List
# =============================================================================


class CertificateRevocationList:
    """Thread-safe Certificate Revocation List with cascade support.

    Maintains a mapping of revoked token IDs to their RevocationEntry,
    as well as parent-child relationships for BFS cascade revocation.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[bytes, RevocationEntry] = {}
        self._children: dict[bytes, set[bytes]] = {}
        self._token_hash_to_id: dict[bytes, bytes] = {}

    def register_token(self, token: CapabilityToken) -> None:
        """Register a token's parent-child relationship.

        Must be called in parent-before-child order for delegation chains.

        Args:
            token: The capability token to register.
        """
        with self._lock:
            token_hash = token.compute_hash()
            self._token_hash_to_id[token_hash] = token.token_id

            if token.token_id not in self._children:
                self._children[token.token_id] = set()

            if token.parent_token_hash is not None:
                parent_id = self._token_hash_to_id.get(token.parent_token_hash)
                if parent_id is not None:
                    if parent_id not in self._children:
                        self._children[parent_id] = set()
                    self._children[parent_id].add(token.token_id)

    def revoke(
        self,
        token_id: bytes,
        reason: RevocationReason,
        urgency: RevocationUrgency,
        revoker_did: str,
        revoker_secret_key: bytes,
        scheduled_time: int | None = None,
    ) -> list[RevocationEntry]:
        """Revoke a token and cascade to all descendants.

        Args:
            token_id: ID of the token to revoke.
            reason: Reason for revocation.
            urgency: Urgency level.
            revoker_did: DID of the revoker.
            revoker_secret_key: Secret key for signing.
            scheduled_time: For PLANNED urgency, the scheduled effective time.

        Returns:
            List of all RevocationEntry objects created (root + cascaded).

        Raises:
            TokenAlreadyRevokedError: If the token is already revoked.
        """
        with self._lock:
            if token_id in self._entries:
                raise TokenAlreadyRevokedError(
                    f"Token {token_id.hex()[:16]}... is already revoked"
                )

            revocation_time = int(time.time())

            if urgency == RevocationUrgency.CRITICAL:
                effective_time = revocation_time
            elif urgency == RevocationUrgency.PLANNED and scheduled_time is not None:
                effective_time = scheduled_time
            else:
                effective_time = revocation_time + NORMAL_GRACE_PERIOD_SECONDS

            signature = _sign_revocation(
                revoker_secret_key,
                token_id,
                revocation_time,
                effective_time,
                reason,
                urgency,
                revoker_did,
            )

            root_entry = RevocationEntry(
                token_id=token_id,
                revocation_time=revocation_time,
                effective_time=effective_time,
                reason=reason,
                urgency=urgency,
                revoker_did=revoker_did,
                parent_revocation_id=None,
                signature=signature,
            )
            self._entries[token_id] = root_entry

            all_entries = [root_entry]

            # BFS cascade to descendants
            queue: deque[bytes] = deque([token_id])
            while queue:
                parent = queue.popleft()
                for child_id in self._children.get(parent, set()):
                    if child_id not in self._entries:
                        child_sig = _sign_revocation(
                            revoker_secret_key,
                            child_id,
                            revocation_time,
                            effective_time,
                            RevocationReason.DELEGATION_REVOKED,
                            urgency,
                            revoker_did,
                        )
                        child_entry = RevocationEntry(
                            token_id=child_id,
                            revocation_time=revocation_time,
                            effective_time=effective_time,
                            reason=RevocationReason.DELEGATION_REVOKED,
                            urgency=urgency,
                            revoker_did=revoker_did,
                            parent_revocation_id=parent,
                            signature=child_sig,
                        )
                        self._entries[child_id] = child_entry
                        all_entries.append(child_entry)
                        queue.append(child_id)

            return all_entries

    def is_revoked(self, token_id: bytes, at_time: int | None = None) -> bool:
        """Check if a token has been revoked and the revocation is effective.

        Args:
            token_id: The token ID to check.
            at_time: Unix timestamp to check against. Defaults to current time.

        Returns:
            True if the token is revoked and the revocation is effective.
        """
        with self._lock:
            entry = self._entries.get(token_id)
            if entry is None:
                return False
            if at_time is None:
                at_time = int(time.time())
            return at_time >= entry.effective_time

    def __contains__(self, token_id: bytes) -> bool:
        """Check if a token ID has a revocation entry (regardless of grace period)."""
        with self._lock:
            return token_id in self._entries

    def get_entry(self, token_id: bytes) -> RevocationEntry | None:
        """Get the revocation entry for a token.

        Args:
            token_id: The token ID to look up.

        Returns:
            The RevocationEntry, or None if not revoked.
        """
        with self._lock:
            return self._entries.get(token_id)

    def get_descendants(self, token_id: bytes) -> list[bytes]:
        """Get all descendant token IDs via BFS.

        Args:
            token_id: The root token ID.

        Returns:
            List of all descendant token IDs.
        """
        with self._lock:
            descendants: list[bytes] = []
            queue: deque[bytes] = deque([token_id])
            while queue:
                parent = queue.popleft()
                for child_id in self._children.get(parent, set()):
                    descendants.append(child_id)
                    queue.append(child_id)
            return descendants

    def process_revocation_message(
        self,
        token_id: bytes,
        reason: RevocationReason,
        urgency: RevocationUrgency,
        revoker_did: str,
        revoker_public_key: bytes,
        revoker_secret_key: bytes,
        scheduled_time: int | None = None,
    ) -> list[RevocationEntry]:
        """Process a revocation message: verify signature then revoke + cascade.

        Args:
            token_id: Token to revoke.
            reason: Revocation reason.
            urgency: Urgency level.
            revoker_did: DID of the revoker.
            revoker_public_key: Public key for signature verification.
            revoker_secret_key: Secret key for signing.
            scheduled_time: For planned revocations.

        Returns:
            List of all revocation entries created.

        Raises:
            InvalidRevocationError: If signature verification fails.
            TokenAlreadyRevokedError: If already revoked.
        """
        revocation_time = int(time.time())

        if urgency == RevocationUrgency.CRITICAL:
            effective_time = revocation_time
        elif urgency == RevocationUrgency.PLANNED and scheduled_time is not None:
            effective_time = scheduled_time
        else:
            effective_time = revocation_time + NORMAL_GRACE_PERIOD_SECONDS

        # Sign and immediately verify to validate the keypair
        signature = _sign_revocation(
            revoker_secret_key,
            token_id,
            revocation_time,
            effective_time,
            reason,
            urgency,
            revoker_did,
        )

        test_entry = RevocationEntry(
            token_id=token_id,
            revocation_time=revocation_time,
            effective_time=effective_time,
            reason=reason,
            urgency=urgency,
            revoker_did=revoker_did,
            parent_revocation_id=None,
            signature=signature,
        )
        _verify_revocation_signature(revoker_public_key, test_entry)

        return self.revoke(
            token_id=token_id,
            reason=reason,
            urgency=urgency,
            revoker_did=revoker_did,
            revoker_secret_key=revoker_secret_key,
            scheduled_time=scheduled_time,
        )

    def get_pending(self) -> list[RevocationEntry]:
        """Get all revocation entries currently in their grace period.

        Returns:
            List of entries where effective_time has not yet passed.
        """
        with self._lock:
            now = int(time.time())
            return [
                entry
                for entry in self._entries.values()
                if now < entry.effective_time
            ]

    def cleanup_expired(self, max_age_seconds: int) -> int:
        """Remove old revocation entries for garbage collection.

        Args:
            max_age_seconds: Remove entries older than this many seconds.

        Returns:
            Number of entries removed.
        """
        with self._lock:
            now = int(time.time())
            cutoff = now - max_age_seconds
            to_remove = [
                token_id
                for token_id, entry in self._entries.items()
                if entry.revocation_time < cutoff
            ]
            for token_id in to_remove:
                del self._entries[token_id]
            return len(to_remove)


# =============================================================================
# Convenience Functions
# =============================================================================


def revoke_token(
    crl: CertificateRevocationList,
    token_id: bytes,
    reason: RevocationReason,
    urgency: RevocationUrgency,
    revoker_did: str,
    revoker_secret_key: bytes,
    scheduled_time: int | None = None,
) -> list[RevocationEntry]:
    """Convenience function to revoke a token via a CRL.

    Args:
        crl: The Certificate Revocation List.
        token_id: Token to revoke.
        reason: Revocation reason.
        urgency: Urgency level.
        revoker_did: DID of the revoker.
        revoker_secret_key: Secret key for signing.
        scheduled_time: For planned revocations.

    Returns:
        List of all revocation entries created.
    """
    return crl.revoke(
        token_id=token_id,
        reason=reason,
        urgency=urgency,
        revoker_did=revoker_did,
        revoker_secret_key=revoker_secret_key,
        scheduled_time=scheduled_time,
    )


def check_revocation(
    crl: CertificateRevocationList,
    token_id: bytes,
    at_time: int | None = None,
) -> bool:
    """Convenience function to check revocation status.

    Args:
        crl: The Certificate Revocation List.
        token_id: Token to check.
        at_time: Optional time to check against.

    Returns:
        True if the token is revoked and effective.
    """
    return crl.is_revoked(token_id, at_time)
