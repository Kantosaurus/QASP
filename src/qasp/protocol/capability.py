"""Capability-based access control.

This module implements CBOR-encoded, ML-DSA-65 signed capability tokens
for fine-grained access control in QASP. Supports attenuation, splitting,
and delegation chain verification.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

import cbor2

from qasp.crypto.exceptions import InvalidSignatureError
from qasp.crypto.signatures import sign, verify
from qasp.identity.did import DID, DIDRegistry
from qasp.protocol.states import ProtocolError

if TYPE_CHECKING:
    pass

__all__ = [
    "ARM_ATTENUATE",
    "ARM_CHARGE",
    "ARM_DELEGATE",
    "ARM_EXEC",
    "ARM_READ",
    "ARM_RELAY",
    "ARM_REVOKE",
    "ARM_MESSAGE",
    "ARM_VERBS",
    "ARM_WRITE",
    "AttenuationError",
    "AuthorityChainEntry",
    "CapabilityError",
    "CapabilityToken",
    "Constraints",
    "DIDResolver",
    "DelegationDepthExceeded",
    "InvalidDelegationChainError",
    "InvalidTokenError",
    "LocalDIDResolver",
    "MultiOwnerCapabilityToken",
    "MultiOwnerValidationError",
    "RevocationChecker",
    "TemporalSchedule",
    "TemporalScheduleError",
    "TemporalThreshold",
    "TokenConstraintViolation",
    "TokenExpiredError",
    "TokenNotYetValidError",
    "TokenRevokedError",
    "TokenUsage",
    "ToolchainViolationError",
    "VerbSet",
    "attenuate_token",
    "create_multi_owner_token",
    "create_sub_invocation_token",
    "create_token",
    "evaluate_temporal_constraints",
    "exponential_decay_schedule",
    "intersect_constraints",
    "linear_decay_schedule",
    "split_token",
    "step_schedule",
    "verify_delegation_chain",
    "verify_multi_owner_token",
    "verify_token",
]

# Constants
NONCE_SIZE = 16
DEFAULT_VALIDITY_SECONDS = 3600

# Canonical ARM verb constants (Section 5.2)
ARM_READ = "read"
ARM_WRITE = "write"
ARM_EXEC = "exec"
ARM_DELEGATE = "delegate"
ARM_CHARGE = "charge"
ARM_ATTENUATE = "attenuate"
ARM_REVOKE = "revoke"
ARM_MESSAGE = "message"
ARM_RELAY = "relay"
ARM_VERBS: frozenset[str] = frozenset({
    ARM_READ, ARM_WRITE, ARM_EXEC, ARM_DELEGATE,
    ARM_CHARGE, ARM_ATTENUATE, ARM_REVOKE, ARM_MESSAGE, ARM_RELAY,
})


# =============================================================================
# Exception Hierarchy
# =============================================================================


class CapabilityError(ProtocolError):
    """Base exception for capability token errors."""

    alert_code: int = 0

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class TokenExpiredError(CapabilityError):
    """Raised when a token has expired (not_after constraint violated)."""

    alert_code: int = 45


class TokenNotYetValidError(CapabilityError):
    """Raised when a token is not yet valid (not_before constraint violated)."""

    alert_code: int = 46


class InvalidTokenError(CapabilityError):
    """Raised when a token signature is invalid or token is malformed."""

    alert_code: int = 51


class TokenConstraintViolation(CapabilityError):
    """Raised when token usage violates constraints."""

    alert_code: int = 49


class AttenuationError(CapabilityError):
    """Raised when token attenuation fails (e.g., verbs not subset)."""

    alert_code: int = 48


class DelegationDepthExceeded(CapabilityError):
    """Raised when delegation depth limit is exceeded."""

    alert_code: int = 47


class InvalidDelegationChainError(CapabilityError):
    """Raised when delegation chain verification fails."""

    alert_code: int = 44


class ToolchainViolationError(CapabilityError):
    """Raised when a capability crosses a tool boundary it is not allowed to."""

    alert_code: int = 52


class MultiOwnerValidationError(CapabilityError):
    """Raised when multi-owner token validation fails."""

    alert_code: int = 53


class TokenRevokedError(CapabilityError):
    """Raised when a revoked token is used."""

    alert_code: int = 56


class TemporalScheduleError(CapabilityError):
    """Raised when a temporal attenuation schedule is invalid."""

    alert_code: int = 57


# =============================================================================
# Protocols
# =============================================================================


@runtime_checkable
class RevocationChecker(Protocol):
    """Protocol for checking token revocation status."""

    def is_revoked(self, token_id: bytes, at_time: int | None = None) -> bool:
        """Check if a token has been revoked.

        Args:
            token_id: The token identifier to check.
            at_time: Optional Unix timestamp to check against
                     (for grace period handling).

        Returns:
            True if the token is revoked and the revocation is effective.
        """
        ...


# =============================================================================
# Core Data Structures
# =============================================================================


@dataclass(frozen=True)
class VerbSet:
    """Immutable set of permitted operations.

    Attributes:
        verbs: Frozenset of verb strings (e.g., "read", "write", "execute").
    """

    verbs: frozenset[str]

    def __init__(self, verbs: frozenset[str] | set[str] | list[str]) -> None:
        object.__setattr__(self, "verbs", frozenset(verbs))

    def issubset(self, other: VerbSet) -> bool:
        """Check if this verb set is a subset of another.

        Args:
            other: The other VerbSet to compare against.

        Returns:
            True if all verbs in this set are in the other set.
        """
        return self.verbs.issubset(other.verbs)

    def intersection(self, other: VerbSet) -> VerbSet:
        """Return the intersection of this verb set with another.

        Args:
            other: The other VerbSet to intersect with.

        Returns:
            A new VerbSet containing only verbs in both sets.
        """
        return VerbSet(self.verbs.intersection(other.verbs))

    def union(self, other: VerbSet) -> VerbSet:
        """Return the union of this verb set with another.

        Args:
            other: The other VerbSet to union with.

        Returns:
            A new VerbSet containing verbs from both sets.
        """
        return VerbSet(self.verbs.union(other.verbs))

    def __contains__(self, verb: str) -> bool:
        return verb in self.verbs

    def __len__(self) -> int:
        return len(self.verbs)

    def __iter__(self) -> Iterator[str]:
        return iter(self.verbs)


@dataclass(frozen=True)
class Constraints:
    """Token usage constraints.

    All constraints are optional. When checking if constraints are tighter,
    None values are considered unbounded (most permissive).

    Attributes:
        not_before: Token is not valid before this time.
        not_after: Token is not valid after this time (expiry).
        quantity_limit: Maximum quantity that can be consumed.
        quantity_unit: Unit for the quantity (e.g., "vCPU-h", "GB").
        rate_limit: Maximum operations per rate_period_seconds.
        rate_period_seconds: Period for rate limiting (default 1 hour).
        max_spend: Maximum spend allowed.
        spend_currency: Currency for max_spend (e.g., "USD", "credits").
        data_scope: Set of data scope identifiers this token can access.
        purpose: Purpose string describing intended use.
    """

    not_before: datetime | None = None
    not_after: datetime | None = None
    quantity_limit: int | None = None
    quantity_unit: str = ""
    rate_limit: int | None = None
    rate_period_seconds: int = 3600
    max_spend: int | None = None
    spend_currency: str = ""
    data_scope: frozenset[str] = field(default_factory=frozenset)
    purpose: str = ""
    allowed_toolchain: tuple[str, ...] = ()

    def is_tighter_than(self, other: Constraints) -> bool:
        """Check if these constraints are tighter than (or equal to) another.

        A constraint is tighter if it is more restrictive. For each field:
        - not_before: tighter if >= other.not_before
        - not_after: tighter if <= other.not_after
        - quantity_limit: tighter if <= other.quantity_limit
        - rate_limit: tighter if <= other.rate_limit
        - max_spend: tighter if <= other.max_spend
        - data_scope: tighter if subset of other.data_scope
        - purpose: must match if other has a purpose

        Args:
            other: The parent constraints to compare against.

        Returns:
            True if all constraints are tighter or equal.
        """
        # not_before: must be same or later
        if other.not_before is not None and (
            self.not_before is None or self.not_before < other.not_before
        ):
            return False

        # not_after: must be same or earlier
        if other.not_after is not None and (
            self.not_after is None or self.not_after > other.not_after
        ):
            return False

        # quantity_limit: must be same or less
        if other.quantity_limit is not None and (
            self.quantity_limit is None or self.quantity_limit > other.quantity_limit
        ):
            return False

        # rate_limit: must be same or less (with same or longer period)
        if other.rate_limit is not None and (
            self.rate_limit is None or self.rate_limit > other.rate_limit
        ):
            return False

        # max_spend: must be same or less
        if other.max_spend is not None and (
            self.max_spend is None or self.max_spend > other.max_spend
        ):
            return False

        # data_scope: must be subset
        if other.data_scope and not self.data_scope.issubset(other.data_scope):
            return False

        # purpose: must match if parent has one
        if other.purpose and self.purpose != other.purpose:
            return False

        # allowed_toolchain: child must be a contiguous ordered sublist of parent
        return not other.allowed_toolchain or _is_contiguous_sublist(
            self.allowed_toolchain, other.allowed_toolchain
        )

    def tighten(self, delta: Constraints) -> Constraints:
        """Create new constraints that are tighter by applying delta.

        For each field, takes the more restrictive value between self and delta.

        Args:
            delta: Constraints to apply for tightening.

        Returns:
            A new Constraints instance with tightened values.
        """
        # not_before: take later
        new_not_before = self.not_before
        if delta.not_before is not None and (
            new_not_before is None or delta.not_before > new_not_before
        ):
            new_not_before = delta.not_before

        # not_after: take earlier
        new_not_after = self.not_after
        if delta.not_after is not None and (
            new_not_after is None or delta.not_after < new_not_after
        ):
            new_not_after = delta.not_after

        # quantity_limit: take smaller
        new_quantity_limit = self.quantity_limit
        if delta.quantity_limit is not None and (
            new_quantity_limit is None or delta.quantity_limit < new_quantity_limit
        ):
            new_quantity_limit = delta.quantity_limit

        # quantity_unit: prefer delta if set
        new_quantity_unit = delta.quantity_unit if delta.quantity_unit else self.quantity_unit

        # rate_limit: take smaller
        new_rate_limit = self.rate_limit
        if delta.rate_limit is not None and (
            new_rate_limit is None or delta.rate_limit < new_rate_limit
        ):
            new_rate_limit = delta.rate_limit

        # rate_period_seconds: prefer delta if rate_limit was updated
        new_rate_period = self.rate_period_seconds
        if delta.rate_limit is not None:
            new_rate_period = delta.rate_period_seconds

        # max_spend: take smaller
        new_max_spend = self.max_spend
        if delta.max_spend is not None and (
            new_max_spend is None or delta.max_spend < new_max_spend
        ):
            new_max_spend = delta.max_spend

        # spend_currency: prefer delta if set
        new_spend_currency = delta.spend_currency if delta.spend_currency else self.spend_currency

        # data_scope: intersection
        new_data_scope = self.data_scope
        if delta.data_scope and new_data_scope:
            new_data_scope = new_data_scope.intersection(delta.data_scope)
        elif delta.data_scope:
            new_data_scope = delta.data_scope

        # purpose: prefer delta if set
        new_purpose = delta.purpose if delta.purpose else self.purpose

        # allowed_toolchain: intersect preserving order of self, or adopt delta's if self is empty
        if self.allowed_toolchain and delta.allowed_toolchain:
            new_toolchain = tuple(
                t for t in self.allowed_toolchain if t in delta.allowed_toolchain
            )
        elif delta.allowed_toolchain:
            new_toolchain = delta.allowed_toolchain
        else:
            new_toolchain = self.allowed_toolchain

        return Constraints(
            not_before=new_not_before,
            not_after=new_not_after,
            quantity_limit=new_quantity_limit,
            quantity_unit=new_quantity_unit,
            rate_limit=new_rate_limit,
            rate_period_seconds=new_rate_period,
            max_spend=new_max_spend,
            spend_currency=new_spend_currency,
            data_scope=new_data_scope,
            purpose=new_purpose,
            allowed_toolchain=new_toolchain,
        )


def _is_contiguous_sublist(child: tuple[str, ...], parent: tuple[str, ...]) -> bool:
    """Check if child is a contiguous ordered sublist of parent.

    Empty child is always a valid sublist.
    """
    if not child:
        return True
    if len(child) > len(parent):
        return False
    for start in range(len(parent) - len(child) + 1):
        if parent[start : start + len(child)] == child:
            return True
    return False


@dataclass(frozen=True)
class TemporalThreshold:
    """A single point in a temporal decay schedule.

    Attributes:
        at_seconds: Seconds after token issued_at when this threshold applies.
        max_spend: Override for max_spend at this time point (None = no override).
        quantity_limit: Override for quantity_limit at this time point.
        rate_limit: Override for rate_limit at this time point.
    """

    at_seconds: int
    max_spend: int | None = None
    quantity_limit: int | None = None
    rate_limit: int | None = None


@dataclass(frozen=True)
class TemporalSchedule:
    """A temporal attenuation schedule for capability tokens.

    Thresholds must be sorted by at_seconds ascending. Each threshold
    specifies reduced numeric constraints that take effect at that time offset.

    Attributes:
        thresholds: Ordered tuple of temporal thresholds.
        policy: Label describing the generation policy (informational only).
    """

    thresholds: tuple[TemporalThreshold, ...]
    policy: str = ""

    def __post_init__(self) -> None:
        if len(self.thresholds) > 1:
            for i in range(1, len(self.thresholds)):
                if self.thresholds[i].at_seconds <= self.thresholds[i - 1].at_seconds:
                    raise TemporalScheduleError(
                        f"Thresholds must be sorted by at_seconds ascending: "
                        f"{self.thresholds[i - 1].at_seconds} >= {self.thresholds[i].at_seconds}"
                    )


@dataclass
class TokenUsage:
    """Runtime tracking for constraint verification.

    This class tracks token usage to verify constraint compliance.

    Attributes:
        quantity_consumed: Total quantity consumed.
        operations_in_period: Operations in current rate period.
        period_start: Start of current rate period.
        total_spend: Total spend so far.
        data_accessed: Set of data scope identifiers accessed.
        declared_purpose: The purpose declared for this usage.
    """

    quantity_consumed: int = 0
    operations_in_period: int = 0
    period_start: datetime | None = None
    total_spend: int = 0
    data_accessed: set[str] = field(default_factory=set)
    declared_purpose: str = ""
    current_tool_class: str = ""


@dataclass(frozen=True)
class CapabilityToken:
    """A capability token for fine-grained access control.

    Tokens are CBOR-encoded and signed with ML-DSA-65.

    Attributes:
        token_id: SHA-384(issuer+nonce)[:32] unique identifier.
        issuer_did: DID of the token issuer.
        subject_did: DID of the token holder.
        audience_did: DID of the service provider (optional).
        resource_uri: ARM-style resource URI.
        verbs: Set of permitted operations.
        constraints: Usage constraints.
        issued_at: When the token was issued.
        nonce: 16-byte random nonce.
        signature: ML-DSA-65 signature.
        parent_token_hash: Hash of parent token (for delegated tokens).
        max_delegation_depth: Maximum levels of delegation allowed.
        delegation_chain_length: Current position in delegation chain.
    """

    token_id: bytes
    issuer_did: DID
    subject_did: DID
    audience_did: DID | None
    resource_uri: str
    verbs: VerbSet
    constraints: Constraints
    issued_at: datetime
    nonce: bytes
    signature: bytes
    parent_token_hash: bytes | None = None
    max_delegation_depth: int = 0
    delegation_chain_length: int = 0
    toolchain_position: int = 0
    auditor_kem_pk: bytes | None = None
    temporal_attenuation: TemporalSchedule | None = None

    def to_cbor(self) -> bytes:
        """Serialize the token to CBOR (without signature for verification).

        Returns:
            CBOR-encoded token data.
        """
        return _encode_token_data(
            token_id=self.token_id,
            issuer_did=self.issuer_did,
            subject_did=self.subject_did,
            audience_did=self.audience_did,
            resource_uri=self.resource_uri,
            verbs=self.verbs,
            constraints=self.constraints,
            issued_at=self.issued_at,
            nonce=self.nonce,
            parent_token_hash=self.parent_token_hash,
            max_delegation_depth=self.max_delegation_depth,
            delegation_chain_length=self.delegation_chain_length,
            toolchain_position=self.toolchain_position,
            auditor_kem_pk=self.auditor_kem_pk,
            temporal_attenuation=self.temporal_attenuation,
        )

    def compute_hash(self) -> bytes:
        """Compute the SHA-384 hash of this token.

        Returns:
            The hash bytes.
        """
        return hashlib.sha384(self.to_cbor() + self.signature).digest()

    def is_expired(self, now: datetime | None = None) -> bool:
        """Check if the token has expired.

        Args:
            now: The current time (defaults to UTC now).

        Returns:
            True if the token has expired.
        """
        if now is None:
            now = datetime.now(UTC)
        if self.constraints.not_after is None:
            return False
        return now >= self.constraints.not_after

    def is_not_yet_valid(self, now: datetime | None = None) -> bool:
        """Check if the token is not yet valid.

        Args:
            now: The current time (defaults to UTC now).

        Returns:
            True if the token is not yet valid.
        """
        if now is None:
            now = datetime.now(UTC)
        if self.constraints.not_before is None:
            return False
        return now < self.constraints.not_before

    @classmethod
    def from_cbor(cls, data: bytes) -> CapabilityToken:
        """Deserialize a token from CBOR.

        Args:
            data: CBOR-encoded token including signature.

        Returns:
            A CapabilityToken instance.

        Raises:
            InvalidTokenError: If the CBOR data is malformed.
        """
        try:
            decoded = cbor2.loads(data)
            if not isinstance(decoded, dict):
                raise InvalidTokenError("Token data must be a CBOR map")

            # Extract signature
            signature = bytes.fromhex(decoded["signature"])

            # Parse DIDs
            issuer_did = DID.parse(decoded["issuer"])
            subject_did = DID.parse(decoded["subject"])
            audience_did = (
                DID.parse(decoded["audience"]) if decoded.get("audience") else None
            )

            # Parse verbs
            verbs = VerbSet(decoded["verbs"])

            # Parse constraints
            constraints_data = decoded.get("constraints", {})
            constraints = Constraints(
                not_before=(
                    datetime.fromisoformat(constraints_data["not_before"])
                    if constraints_data.get("not_before")
                    else None
                ),
                not_after=(
                    datetime.fromisoformat(constraints_data["not_after"])
                    if constraints_data.get("not_after")
                    else None
                ),
                quantity_limit=constraints_data.get("quantity_limit"),
                quantity_unit=constraints_data.get("quantity_unit", ""),
                rate_limit=constraints_data.get("rate_limit"),
                rate_period_seconds=constraints_data.get("rate_period_seconds", 3600),
                max_spend=constraints_data.get("max_spend"),
                spend_currency=constraints_data.get("spend_currency", ""),
                data_scope=frozenset(constraints_data.get("data_scope", [])),
                purpose=constraints_data.get("purpose", ""),
                allowed_toolchain=tuple(
                    constraints_data.get("allowed_toolchain", [])
                ),
            )

            # Parse temporal attenuation
            temporal_attenuation = None
            if decoded.get("temporal_attenuation"):
                temporal_attenuation = _dict_to_temporal_schedule(
                    decoded["temporal_attenuation"]
                )

            return cls(
                token_id=bytes.fromhex(decoded["token_id"]),
                issuer_did=issuer_did,
                subject_did=subject_did,
                audience_did=audience_did,
                resource_uri=decoded["resource"],
                verbs=verbs,
                constraints=constraints,
                issued_at=datetime.fromisoformat(decoded["iat"]),
                nonce=bytes.fromhex(decoded["nonce"]),
                signature=signature,
                parent_token_hash=(
                    bytes.fromhex(decoded["parent"]) if decoded.get("parent") else None
                ),
                max_delegation_depth=decoded.get("max_depth", 0),
                delegation_chain_length=decoded.get("chain_len", 0),
                toolchain_position=decoded.get("tc_pos", 0),
                auditor_kem_pk=(
                    bytes.fromhex(decoded["auditor_kem_pk"])
                    if decoded.get("auditor_kem_pk")
                    else None
                ),
                temporal_attenuation=temporal_attenuation,
            )
        except (KeyError, ValueError, TypeError, cbor2.CBORDecodeError) as e:
            raise InvalidTokenError(f"Failed to parse token CBOR: {e}") from e

    def to_cbor_with_signature(self) -> bytes:
        """Serialize the token to CBOR including signature.

        Returns:
            CBOR-encoded token data with signature.
        """
        return _encode_token_data_with_signature(
            token_id=self.token_id,
            issuer_did=self.issuer_did,
            subject_did=self.subject_did,
            audience_did=self.audience_did,
            resource_uri=self.resource_uri,
            verbs=self.verbs,
            constraints=self.constraints,
            issued_at=self.issued_at,
            nonce=self.nonce,
            signature=self.signature,
            parent_token_hash=self.parent_token_hash,
            max_delegation_depth=self.max_delegation_depth,
            delegation_chain_length=self.delegation_chain_length,
            toolchain_position=self.toolchain_position,
            auditor_kem_pk=self.auditor_kem_pk,
            temporal_attenuation=self.temporal_attenuation,
        )


# =============================================================================
# CBOR Encoding
# =============================================================================


def _constraints_to_dict(constraints: Constraints) -> dict[str, Any]:
    """Convert constraints to a dictionary for CBOR encoding.

    Args:
        constraints: The constraints to convert.

    Returns:
        A dictionary suitable for CBOR encoding.
    """
    result: dict[str, Any] = {}
    if constraints.not_before is not None:
        result["not_before"] = constraints.not_before.isoformat()
    if constraints.not_after is not None:
        result["not_after"] = constraints.not_after.isoformat()
    if constraints.quantity_limit is not None:
        result["quantity_limit"] = constraints.quantity_limit
    if constraints.quantity_unit:
        result["quantity_unit"] = constraints.quantity_unit
    if constraints.rate_limit is not None:
        result["rate_limit"] = constraints.rate_limit
        result["rate_period_seconds"] = constraints.rate_period_seconds
    if constraints.max_spend is not None:
        result["max_spend"] = constraints.max_spend
    if constraints.spend_currency:
        result["spend_currency"] = constraints.spend_currency
    if constraints.data_scope:
        result["data_scope"] = sorted(constraints.data_scope)
    if constraints.purpose:
        result["purpose"] = constraints.purpose
    if constraints.allowed_toolchain:
        result["allowed_toolchain"] = list(constraints.allowed_toolchain)
    return result


def _temporal_schedule_to_dict(schedule: TemporalSchedule) -> dict[str, Any]:
    """Convert a TemporalSchedule to a dictionary for CBOR encoding."""
    thresholds = []
    for t in schedule.thresholds:
        entry: dict[str, Any] = {"at_seconds": t.at_seconds}
        if t.max_spend is not None:
            entry["max_spend"] = t.max_spend
        if t.quantity_limit is not None:
            entry["quantity_limit"] = t.quantity_limit
        if t.rate_limit is not None:
            entry["rate_limit"] = t.rate_limit
        thresholds.append(entry)
    result: dict[str, Any] = {"thresholds": thresholds}
    if schedule.policy:
        result["policy"] = schedule.policy
    return result


def _dict_to_temporal_schedule(data: dict[str, Any]) -> TemporalSchedule:
    """Parse a TemporalSchedule from a CBOR-decoded dictionary."""
    thresholds = tuple(
        TemporalThreshold(
            at_seconds=t["at_seconds"],
            max_spend=t.get("max_spend"),
            quantity_limit=t.get("quantity_limit"),
            rate_limit=t.get("rate_limit"),
        )
        for t in data["thresholds"]
    )
    return TemporalSchedule(
        thresholds=thresholds,
        policy=data.get("policy", ""),
    )


def _encode_token_data(
    token_id: bytes,
    issuer_did: DID,
    subject_did: DID,
    audience_did: DID | None,
    resource_uri: str,
    verbs: VerbSet,
    constraints: Constraints,
    issued_at: datetime,
    nonce: bytes,
    parent_token_hash: bytes | None,
    max_delegation_depth: int,
    delegation_chain_length: int,
    toolchain_position: int = 0,
    auditor_kem_pk: bytes | None = None,
    temporal_attenuation: TemporalSchedule | None = None,
) -> bytes:
    """Encode token data to CBOR for signing.

    Args:
        token_id: Token identifier.
        issuer_did: Issuer's DID.
        subject_did: Subject's DID.
        audience_did: Audience DID (optional).
        resource_uri: Resource URI.
        verbs: Permitted operations.
        constraints: Usage constraints.
        issued_at: Issuance time.
        nonce: Random nonce.
        parent_token_hash: Parent token hash (for delegated tokens).
        max_delegation_depth: Maximum delegation depth.
        delegation_chain_length: Current chain length.
        toolchain_position: Current position in the toolchain.
        auditor_kem_pk: Optional auditor ML-KEM-768 public key.
        temporal_attenuation: Optional temporal decay schedule.

    Returns:
        CBOR-encoded bytes.
    """
    token_data = {
        "token_id": token_id.hex(),
        "issuer": str(issuer_did),
        "subject": str(subject_did),
        "audience": str(audience_did) if audience_did else None,
        "resource": resource_uri,
        "verbs": sorted(verbs.verbs),  # Sorted for determinism
        "constraints": _constraints_to_dict(constraints),
        "iat": issued_at.isoformat(),
        "nonce": nonce.hex(),
        "parent": parent_token_hash.hex() if parent_token_hash else None,
        "max_depth": max_delegation_depth,
        "chain_len": delegation_chain_length,
        "tc_pos": toolchain_position,
    }
    if auditor_kem_pk:
        token_data["auditor_kem_pk"] = auditor_kem_pk.hex()
    if temporal_attenuation is not None:
        token_data["temporal_attenuation"] = _temporal_schedule_to_dict(temporal_attenuation)
    return cbor2.dumps(token_data)


def _encode_token_data_with_signature(
    token_id: bytes,
    issuer_did: DID,
    subject_did: DID,
    audience_did: DID | None,
    resource_uri: str,
    verbs: VerbSet,
    constraints: Constraints,
    issued_at: datetime,
    nonce: bytes,
    signature: bytes,
    parent_token_hash: bytes | None,
    max_delegation_depth: int,
    delegation_chain_length: int,
    toolchain_position: int = 0,
    auditor_kem_pk: bytes | None = None,
    temporal_attenuation: TemporalSchedule | None = None,
) -> bytes:
    """Encode token data with signature to CBOR.

    Args:
        All args same as _encode_token_data plus signature.

    Returns:
        CBOR-encoded bytes including signature.
    """
    token_data = {
        "token_id": token_id.hex(),
        "issuer": str(issuer_did),
        "subject": str(subject_did),
        "audience": str(audience_did) if audience_did else None,
        "resource": resource_uri,
        "verbs": sorted(verbs.verbs),
        "constraints": _constraints_to_dict(constraints),
        "iat": issued_at.isoformat(),
        "nonce": nonce.hex(),
        "signature": signature.hex(),
        "parent": parent_token_hash.hex() if parent_token_hash else None,
        "max_depth": max_delegation_depth,
        "chain_len": delegation_chain_length,
        "tc_pos": toolchain_position,
    }
    if auditor_kem_pk:
        token_data["auditor_kem_pk"] = auditor_kem_pk.hex()
    if temporal_attenuation is not None:
        token_data["temporal_attenuation"] = _temporal_schedule_to_dict(temporal_attenuation)
    return cbor2.dumps(token_data)


# =============================================================================
# Token Creation
# =============================================================================


def create_token(
    issuer_did: DID,
    issuer_secret_key: bytes,
    subject_did: DID,
    resource_uri: str,
    verbs: set[str] | VerbSet,
    constraints: Constraints | None = None,
    audience_did: DID | None = None,
    max_delegation_depth: int = 0,
    validity_seconds: int = DEFAULT_VALIDITY_SECONDS,
    auditor_kem_pk: bytes | None = None,
    temporal_attenuation: TemporalSchedule | None = None,
) -> CapabilityToken:
    """Create a new capability token.

    Args:
        issuer_did: The DID of the token issuer.
        issuer_secret_key: The issuer's ML-DSA-65 secret key.
        subject_did: The DID of the token holder.
        resource_uri: The resource this token grants access to.
        verbs: The permitted operations (as set or VerbSet).
        constraints: Optional usage constraints.
        audience_did: Optional service provider DID.
        max_delegation_depth: Maximum delegation levels allowed.
        validity_seconds: Token validity duration in seconds.

    Returns:
        A signed CapabilityToken.

    Raises:
        InvalidKeyError: If the secret key is invalid.
        SignatureError: If signing fails.
    """
    # Generate nonce and compute token_id
    nonce = os.urandom(NONCE_SIZE)
    token_id = hashlib.sha384(str(issuer_did).encode() + nonce).digest()[:32]

    # Set timestamps
    issued_at = datetime.now(UTC)
    not_after = issued_at + timedelta(seconds=validity_seconds)

    # Normalize verbs
    verb_set = verbs if isinstance(verbs, VerbSet) else VerbSet(verbs)

    # Set default constraints if not provided
    if constraints is None:
        constraints = Constraints(not_after=not_after)
    elif constraints.not_after is None:
        constraints = Constraints(
            not_before=constraints.not_before,
            not_after=not_after,
            quantity_limit=constraints.quantity_limit,
            quantity_unit=constraints.quantity_unit,
            rate_limit=constraints.rate_limit,
            rate_period_seconds=constraints.rate_period_seconds,
            max_spend=constraints.max_spend,
            spend_currency=constraints.spend_currency,
            data_scope=constraints.data_scope,
            purpose=constraints.purpose,
            allowed_toolchain=constraints.allowed_toolchain,
        )

    # Encode and sign
    message = _encode_token_data(
        token_id=token_id,
        issuer_did=issuer_did,
        subject_did=subject_did,
        audience_did=audience_did,
        resource_uri=resource_uri,
        verbs=verb_set,
        constraints=constraints,
        issued_at=issued_at,
        nonce=nonce,
        parent_token_hash=None,
        max_delegation_depth=max_delegation_depth,
        delegation_chain_length=0,
        toolchain_position=0,
        auditor_kem_pk=auditor_kem_pk,
        temporal_attenuation=temporal_attenuation,
    )
    signature = sign(issuer_secret_key, message)

    return CapabilityToken(
        token_id=token_id,
        issuer_did=issuer_did,
        subject_did=subject_did,
        audience_did=audience_did,
        resource_uri=resource_uri,
        verbs=verb_set,
        constraints=constraints,
        issued_at=issued_at,
        nonce=nonce,
        signature=signature,
        parent_token_hash=None,
        max_delegation_depth=max_delegation_depth,
        delegation_chain_length=0,
        toolchain_position=0,
        auditor_kem_pk=auditor_kem_pk,
        temporal_attenuation=temporal_attenuation,
    )


# =============================================================================
# Token Verification
# =============================================================================


def verify_token(
    token: CapabilityToken,
    issuer_public_key: bytes,
    check_expiry: bool = True,
    usage: TokenUsage | None = None,
    crl: RevocationChecker | None = None,
) -> bool:
    """Verify a capability token's signature and constraints.

    Args:
        token: The token to verify.
        issuer_public_key: The issuer's ML-DSA-65 public key.
        check_expiry: Whether to check time-based constraints.
        usage: Optional usage tracking for constraint verification.
        crl: Optional revocation checker. If provided, checks revocation
             before other validation.

    Returns:
        True if the token is valid.

    Raises:
        TokenRevokedError: If the token has been revoked.
        InvalidTokenError: If the signature is invalid.
        TokenExpiredError: If the token has expired.
        TokenNotYetValidError: If the token is not yet valid.
        TokenConstraintViolation: If usage violates constraints.
    """
    # Check revocation first if CRL is provided
    if crl is not None and crl.is_revoked(token.token_id):
        raise TokenRevokedError(
            f"Token {token.token_id.hex()[:16]}... has been revoked"
        )

    # Verify signature
    message = token.to_cbor()
    try:
        verify(issuer_public_key, message, token.signature)
    except InvalidSignatureError as e:
        raise InvalidTokenError(f"Token signature verification failed: {e}") from e

    # Check time constraints
    if check_expiry:
        now = datetime.now(UTC)

        if token.is_not_yet_valid(now):
            raise TokenNotYetValidError(
                f"Token not valid until {token.constraints.not_before}"
            )

        if token.is_expired(now):
            raise TokenExpiredError(
                f"Token expired at {token.constraints.not_after}"
            )

    # Evaluate temporal attenuation
    effective_constraints = token.constraints
    if token.temporal_attenuation is not None:
        effective_constraints = evaluate_temporal_constraints(token)

    # Check usage constraints if provided
    if usage is not None:
        _verify_usage_constraints(token, usage, effective_constraints=effective_constraints)

    return True


def _verify_usage_constraints(
    token: CapabilityToken,
    usage: TokenUsage,
    effective_constraints: Constraints | None = None,
) -> None:
    """Verify that usage complies with token constraints.

    Args:
        token: The token with constraints.
        usage: The current usage tracking.
        effective_constraints: Optional override constraints (e.g. after temporal decay).

    Raises:
        TokenConstraintViolation: If any constraint is violated.
    """
    constraints = effective_constraints if effective_constraints is not None else token.constraints

    # Check quantity limit
    if (
        constraints.quantity_limit is not None
        and usage.quantity_consumed > constraints.quantity_limit
    ):
        raise TokenConstraintViolation(
            f"Quantity limit exceeded: "
            f"{usage.quantity_consumed} > {constraints.quantity_limit}"
        )

    # Check rate limit (active token bucket + passive comparison)
    if constraints.rate_limit is not None:
        # Active rate limiting via token bucket
        from qasp.protocol.rate_limiter import (
            RateLimitExceededError,
            get_rate_limiter_registry,
        )

        registry = get_rate_limiter_registry()
        limiter = registry.get_or_create(
            token.token_id,
            rate_limit=constraints.rate_limit,
            rate_period_seconds=constraints.rate_period_seconds,
        )
        try:
            limiter.consume_or_raise()
        except RateLimitExceededError as e:
            raise TokenConstraintViolation(
                f"Rate limit exceeded (token bucket): {e}"
            ) from e

        # Passive comparison as fallback
        now = datetime.now(UTC)
        if usage.period_start is not None:
            period_elapsed = (now - usage.period_start).total_seconds()
            if (
                period_elapsed < constraints.rate_period_seconds
                and usage.operations_in_period > constraints.rate_limit
            ):
                raise TokenConstraintViolation(
                    f"Rate limit exceeded: "
                    f"{usage.operations_in_period} > {constraints.rate_limit}"
                )

    # Check max spend
    if constraints.max_spend is not None and usage.total_spend > constraints.max_spend:
        raise TokenConstraintViolation(
            f"Spend limit exceeded: {usage.total_spend} > {constraints.max_spend}"
        )

    # Check data scope
    if constraints.data_scope and not usage.data_accessed.issubset(constraints.data_scope):
        unauthorized = usage.data_accessed - constraints.data_scope
        raise TokenConstraintViolation(
            f"Data scope violation: unauthorized access to {unauthorized}"
        )

    # Check purpose
    if (
        constraints.purpose
        and usage.declared_purpose
        and usage.declared_purpose != constraints.purpose
    ):
        raise TokenConstraintViolation(
            f"Purpose mismatch: declared '{usage.declared_purpose}' != "
            f"required '{constraints.purpose}'"
        )

    # Check toolchain position
    if constraints.allowed_toolchain and usage.current_tool_class:
        if token.toolchain_position >= len(constraints.allowed_toolchain):
            raise ToolchainViolationError(
                f"Toolchain position {token.toolchain_position} exceeds "
                f"chain length {len(constraints.allowed_toolchain)}"
            )
        expected_tool = constraints.allowed_toolchain[token.toolchain_position]
        if usage.current_tool_class != expected_tool:
            raise ToolchainViolationError(
                f"Tool class mismatch at position {token.toolchain_position}: "
                f"expected '{expected_tool}', got '{usage.current_tool_class}'"
            )


# =============================================================================
# Temporal Constraint Evaluation
# =============================================================================


def evaluate_temporal_constraints_raw(
    base_constraints: Constraints,
    schedule: TemporalSchedule,
    issued_at: datetime,
    current_time: datetime | None = None,
) -> Constraints:
    """Evaluate temporal attenuation against base constraints.

    Finds the latest applicable threshold and returns constraints with
    effective numeric values = min(base, threshold) for each field.

    Args:
        base_constraints: The token's base constraints.
        schedule: The temporal decay schedule.
        issued_at: When the token was issued.
        current_time: Current time (defaults to UTC now).

    Returns:
        Constraints with temporally attenuated numeric fields.
    """
    if not schedule.thresholds:
        return base_constraints

    if current_time is None:
        current_time = datetime.now(UTC)

    elapsed = (current_time - issued_at).total_seconds()

    # Clock skew or before any threshold
    if elapsed < 0:
        return base_constraints

    # Find latest applicable threshold
    active_threshold: TemporalThreshold | None = None
    for threshold in schedule.thresholds:
        if threshold.at_seconds <= elapsed:
            active_threshold = threshold
        else:
            break

    if active_threshold is None:
        return base_constraints

    # Compute effective values: min(base, threshold) where threshold is not None
    def _min_or_base(base_val: int | None, thresh_val: int | None) -> int | None:
        if thresh_val is None:
            return base_val
        if base_val is None:
            return thresh_val
        return min(base_val, thresh_val)

    return Constraints(
        not_before=base_constraints.not_before,
        not_after=base_constraints.not_after,
        quantity_limit=_min_or_base(base_constraints.quantity_limit, active_threshold.quantity_limit),
        quantity_unit=base_constraints.quantity_unit,
        rate_limit=_min_or_base(base_constraints.rate_limit, active_threshold.rate_limit),
        rate_period_seconds=base_constraints.rate_period_seconds,
        max_spend=_min_or_base(base_constraints.max_spend, active_threshold.max_spend),
        spend_currency=base_constraints.spend_currency,
        data_scope=base_constraints.data_scope,
        purpose=base_constraints.purpose,
        allowed_toolchain=base_constraints.allowed_toolchain,
    )


def evaluate_temporal_constraints(
    token: CapabilityToken,
    current_time: datetime | None = None,
) -> Constraints:
    """Evaluate temporal attenuation for a token.

    Args:
        token: The token with optional temporal_attenuation.
        current_time: Current time (defaults to UTC now).

    Returns:
        Effective constraints after temporal decay.
    """
    if token.temporal_attenuation is None:
        return token.constraints
    return evaluate_temporal_constraints_raw(
        token.constraints, token.temporal_attenuation, token.issued_at, current_time,
    )


# =============================================================================
# Token Attenuation
# =============================================================================


def _verify_temporal_monotonicity(
    parent_token: CapabilityToken,
    child_constraints: Constraints,
    child_temporal: TemporalSchedule | None,
) -> None:
    """Verify that child temporal schedule is at least as restrictive as parent.

    Checks all unique time points from both schedules and verifies
    the child's effective constraints are <= parent's at each point.

    Raises:
        AttenuationError: If any time point violates monotonicity.
    """
    parent_temporal = parent_token.temporal_attenuation
    if parent_temporal is None and child_temporal is None:
        return

    # Collect all unique time points to check
    time_points: set[int] = {0}
    if parent_temporal is not None:
        for t in parent_temporal.thresholds:
            time_points.add(t.at_seconds)
    if child_temporal is not None:
        for t in child_temporal.thresholds:
            time_points.add(t.at_seconds)

    # Use a synthetic issued_at as epoch reference
    epoch = datetime(2000, 1, 1, tzinfo=UTC)

    for seconds in sorted(time_points):
        check_time = epoch + timedelta(seconds=seconds)

        # Compute parent effective constraints at this time
        if parent_temporal is not None:
            parent_effective = evaluate_temporal_constraints_raw(
                parent_token.constraints, parent_temporal, epoch, check_time,
            )
        else:
            parent_effective = parent_token.constraints

        # Compute child effective constraints at this time
        if child_temporal is not None:
            child_effective = evaluate_temporal_constraints_raw(
                child_constraints, child_temporal, epoch, check_time,
            )
        else:
            child_effective = child_constraints

        # Check each numeric field: child must be <= parent (or both None)
        for field_name in ("max_spend", "quantity_limit", "rate_limit"):
            parent_val = getattr(parent_effective, field_name)
            child_val = getattr(child_effective, field_name)
            if parent_val is not None and (child_val is None or child_val > parent_val):
                raise AttenuationError(
                    f"Temporal monotonicity violation at t={seconds}s: "
                    f"child {field_name}={child_val} exceeds parent {field_name}={parent_val}"
                )


def attenuate_token(
    parent_token: CapabilityToken,
    delegator_secret_key: bytes,
    new_subject_did: DID,
    reduced_verbs: VerbSet | None = None,
    tightened_constraints: Constraints | None = None,
    toolchain_position: int | None = None,
    temporal_attenuation: TemporalSchedule | None = None,
    resource_uri: str | None = None,
) -> CapabilityToken:
    """Create an attenuated token from a parent token.

    Implements att(T, Δ) → T' where V_T' ⊆ V_T and constraints are tighter.

    Args:
        parent_token: The parent token to attenuate from.
        delegator_secret_key: The delegating subject's secret key.
        new_subject_did: The DID of the new token holder.
        reduced_verbs: New verb set (must be subset of parent).
        tightened_constraints: Additional constraint tightening.
        toolchain_position: Toolchain position override (defaults to parent's).
        temporal_attenuation: Optional temporal decay schedule for the child token.
        resource_uri: Narrowed resource URI (must be valid attenuation of parent).

    Returns:
        A new attenuated CapabilityToken.

    Raises:
        TokenExpiredError: If the parent token has expired.
        DelegationDepthExceeded: If delegation depth is 0.
        AttenuationError: If verbs are not a subset, constraints not tighter,
            or resource URI is an escalation.
    """
    # Check parent hasn't expired
    if parent_token.is_expired():
        raise TokenExpiredError(
            f"Cannot attenuate expired token (expired at {parent_token.constraints.not_after})"
        )

    # Check delegation depth
    if parent_token.max_delegation_depth <= 0:
        raise DelegationDepthExceeded(
            "Parent token does not allow delegation (max_delegation_depth=0)"
        )

    # Determine new verbs
    if reduced_verbs is None:
        new_verbs = parent_token.verbs
    else:
        if not reduced_verbs.issubset(parent_token.verbs):
            extra = set(reduced_verbs.verbs) - set(parent_token.verbs.verbs)
            raise AttenuationError(f"Cannot delegate verbs not held: {extra}")
        new_verbs = reduced_verbs

    # Determine new constraints
    if tightened_constraints is None:
        new_constraints = parent_token.constraints
    else:
        new_constraints = parent_token.constraints.tighten(tightened_constraints)
        if not new_constraints.is_tighter_than(parent_token.constraints):
            raise AttenuationError("New constraints are not tighter than parent")

    # Determine toolchain position
    if toolchain_position is not None:
        new_tc_pos = toolchain_position
    else:
        new_tc_pos = parent_token.toolchain_position

    # Determine resource URI: use narrowed URI or inherit parent's
    if resource_uri is not None:
        from qasp.protocol.arm import InvalidARMUriError, is_attenuation

        try:
            if not is_attenuation(parent_token.resource_uri, resource_uri):
                raise AttenuationError(
                    f"Resource URI '{resource_uri}' is not a valid attenuation "
                    f"of parent URI '{parent_token.resource_uri}' (scope escalation)"
                )
        except InvalidARMUriError:
            # If URIs don't conform to ARM format, require exact match
            if resource_uri != parent_token.resource_uri:
                raise AttenuationError(
                    f"Resource URI '{resource_uri}' does not match "
                    f"parent URI '{parent_token.resource_uri}'"
                )
        new_resource_uri = resource_uri
    else:
        new_resource_uri = parent_token.resource_uri

    # Determine temporal attenuation: inherit parent's if child doesn't specify one
    new_temporal = temporal_attenuation
    if new_temporal is None and parent_token.temporal_attenuation is not None:
        new_temporal = parent_token.temporal_attenuation

    # Verify temporal monotonicity
    if parent_token.temporal_attenuation is not None or new_temporal is not None:
        _verify_temporal_monotonicity(parent_token, new_constraints, new_temporal)

    # Generate new token
    nonce = os.urandom(NONCE_SIZE)
    token_id = hashlib.sha384(str(parent_token.subject_did).encode() + nonce).digest()[:32]
    issued_at = datetime.now(UTC)
    parent_hash = parent_token.compute_hash()
    new_depth = parent_token.max_delegation_depth - 1
    new_chain_length = parent_token.delegation_chain_length + 1

    # Encode and sign
    message = _encode_token_data(
        token_id=token_id,
        issuer_did=parent_token.subject_did,  # Delegator becomes issuer
        subject_did=new_subject_did,
        audience_did=parent_token.audience_did,
        resource_uri=new_resource_uri,
        verbs=new_verbs,
        constraints=new_constraints,
        issued_at=issued_at,
        nonce=nonce,
        parent_token_hash=parent_hash,
        max_delegation_depth=new_depth,
        delegation_chain_length=new_chain_length,
        toolchain_position=new_tc_pos,
        auditor_kem_pk=parent_token.auditor_kem_pk,
        temporal_attenuation=new_temporal,
    )
    signature = sign(delegator_secret_key, message)

    return CapabilityToken(
        token_id=token_id,
        issuer_did=parent_token.subject_did,
        subject_did=new_subject_did,
        audience_did=parent_token.audience_did,
        resource_uri=new_resource_uri,
        verbs=new_verbs,
        constraints=new_constraints,
        issued_at=issued_at,
        nonce=nonce,
        signature=signature,
        parent_token_hash=parent_hash,
        max_delegation_depth=new_depth,
        delegation_chain_length=new_chain_length,
        toolchain_position=new_tc_pos,
        auditor_kem_pk=parent_token.auditor_kem_pk,
        temporal_attenuation=new_temporal,
    )


def create_sub_invocation_token(
    parent_token: CapabilityToken,
    holder_secret_key: bytes,
    target_tool_class: str,
    new_subject_did: DID,
    reduced_verbs: VerbSet | None = None,
    tightened_constraints: Constraints | None = None,
    temporal_attenuation: TemporalSchedule | None = None,
) -> CapabilityToken:
    """Create a sub-invocation token for capability firebreaks.

    Validates the target tool against the parent's allowed toolchain and
    advances the toolchain position.

    Args:
        parent_token: The parent token to create a sub-invocation from.
        holder_secret_key: The holder's secret key for signing.
        target_tool_class: The tool class being invoked.
        new_subject_did: The DID of the sub-invocation target.
        reduced_verbs: Optional reduced verb set.
        tightened_constraints: Optional tightened constraints.
        temporal_attenuation: Optional temporal decay schedule.

    Returns:
        A new CapabilityToken with advanced toolchain position.

    Raises:
        ToolchainViolationError: If the target tool doesn't match the chain
            or the chain is exhausted.
    """
    toolchain = parent_token.constraints.allowed_toolchain
    pos = parent_token.toolchain_position

    if toolchain:
        if pos >= len(toolchain):
            raise ToolchainViolationError(
                f"Toolchain exhausted at position {pos} "
                f"(chain length {len(toolchain)})"
            )
        if target_tool_class != toolchain[pos]:
            raise ToolchainViolationError(
                f"Target tool '{target_tool_class}' does not match "
                f"expected '{toolchain[pos]}' at position {pos}"
            )

    new_position = pos + 1

    return attenuate_token(
        parent_token=parent_token,
        delegator_secret_key=holder_secret_key,
        new_subject_did=new_subject_did,
        reduced_verbs=reduced_verbs,
        tightened_constraints=tightened_constraints,
        toolchain_position=new_position,
        temporal_attenuation=temporal_attenuation,
    )


# =============================================================================
# Token Splitting
# =============================================================================


def split_token(
    token: CapabilityToken,
    holder_secret_key: bytes,
    split_amounts: list[int],
    new_subject_dids: list[DID] | None = None,
) -> list[CapabilityToken]:
    """Split a token's quantity constraint into multiple tokens.

    Example: A 2 vCPU-h token can be split into [1, 1] vCPU-h tokens.

    Args:
        token: The token to split.
        holder_secret_key: The token holder's secret key.
        split_amounts: List of quantities for each new token.
        new_subject_dids: Optional list of new subjects (defaults to same subject).

    Returns:
        List of new tokens with partitioned quantity limits.

    Raises:
        TokenConstraintViolation: If sum of amounts exceeds quantity_limit.
        AttenuationError: If token has no quantity_limit.
        ValueError: If split_amounts and new_subject_dids have different lengths.
    """
    # Validate quantity_limit exists
    if token.constraints.quantity_limit is None:
        raise AttenuationError("Cannot split token without quantity_limit")

    # Validate total doesn't exceed limit
    total = sum(split_amounts)
    if total > token.constraints.quantity_limit:
        raise TokenConstraintViolation(
            f"Split total {total} exceeds quantity_limit {token.constraints.quantity_limit}"
        )

    # Validate subject DIDs length
    if new_subject_dids is not None and len(new_subject_dids) != len(split_amounts):
        raise ValueError("split_amounts and new_subject_dids must have same length")

    # Create split tokens
    split_tokens = []
    for i, amount in enumerate(split_amounts):
        new_subject = new_subject_dids[i] if new_subject_dids else token.subject_did

        # Create tightened constraints with new quantity_limit
        tightened = Constraints(quantity_limit=amount)

        split_token_result = attenuate_token(
            parent_token=token,
            delegator_secret_key=holder_secret_key,
            new_subject_did=new_subject,
            reduced_verbs=None,  # Keep same verbs
            tightened_constraints=tightened,
        )
        split_tokens.append(split_token_result)

    return split_tokens


# =============================================================================
# Delegation Chain Verification
# =============================================================================


@runtime_checkable
class DIDResolver(Protocol):
    """Protocol for DID resolution."""

    def resolve(self, did: DID) -> bytes:
        """Resolve a DID to its public key.

        Args:
            did: The DID to resolve.

        Returns:
            The public key bytes.

        Raises:
            DIDResolutionError: If resolution fails.
        """
        ...


class LocalDIDResolver:
    """DID resolver using a local DIDRegistry."""

    def __init__(self, registry: DIDRegistry) -> None:
        """Initialize with a DID registry.

        Args:
            registry: The DIDRegistry to use for lookups.
        """
        self._registry = registry

    def resolve(self, did: DID) -> bytes:
        """Resolve a DID to its public key.

        Args:
            did: The DID to resolve.

        Returns:
            The public key bytes.

        Raises:
            DIDResolutionError: If the DID is not found.
        """
        document = self._registry.lookup(did)
        return document.get_public_key()


def verify_delegation_chain(
    tokens: list[CapabilityToken],
    root_issuer_public_key: bytes,
    did_resolver: DIDResolver | None = None,
    check_expiry: bool = True,
) -> bool:
    """Verify a chain of delegated tokens.

    The chain starts with the root issuer's token and each subsequent
    token must be properly attenuated from its parent.

    Args:
        tokens: List of tokens from root to leaf.
        root_issuer_public_key: The root issuer's public key.
        did_resolver: Optional resolver for intermediate DID public keys.
        check_expiry: Whether to check time-based constraints.

    Returns:
        True if the entire chain is valid.

    Raises:
        InvalidDelegationChainError: If the chain is invalid.
        InvalidTokenError: If any token signature is invalid.
        TokenExpiredError: If any token has expired.
    """
    if not tokens:
        raise InvalidDelegationChainError("Empty token chain")

    # First token must be root (no parent)
    root_token = tokens[0]
    if root_token.parent_token_hash is not None:
        raise InvalidDelegationChainError(
            "Root token cannot have a parent_token_hash"
        )

    # Verify root token
    try:
        verify_token(root_token, root_issuer_public_key, check_expiry=check_expiry)
    except (InvalidTokenError, TokenExpiredError, TokenNotYetValidError) as e:
        raise InvalidDelegationChainError(f"Root token verification failed: {e}") from e

    # Verify each subsequent token
    prev_token = root_token
    for i, token in enumerate(tokens[1:], start=1):
        # Check parent hash matches
        expected_hash = prev_token.compute_hash()
        if token.parent_token_hash != expected_hash:
            raise InvalidDelegationChainError(
                f"Token {i} parent_token_hash mismatch"
            )

        # Check chain_length increments
        if token.delegation_chain_length != prev_token.delegation_chain_length + 1:
            raise InvalidDelegationChainError(
                f"Token {i} has incorrect chain_length"
            )

        # Check depth decrements
        if token.max_delegation_depth != prev_token.max_delegation_depth - 1:
            raise InvalidDelegationChainError(
                f"Token {i} has incorrect max_delegation_depth"
            )

        # Check verbs are subset
        if not token.verbs.issubset(prev_token.verbs):
            raise InvalidDelegationChainError(
                f"Token {i} has verbs not granted by parent"
            )

        # Check constraints are tighter
        if not token.constraints.is_tighter_than(prev_token.constraints):
            raise InvalidDelegationChainError(
                f"Token {i} constraints are not tighter than parent"
            )

        # Check temporal monotonicity
        if prev_token.temporal_attenuation is not None or token.temporal_attenuation is not None:
            try:
                _verify_temporal_monotonicity(
                    prev_token, token.constraints, token.temporal_attenuation,
                )
            except AttenuationError as e:
                raise InvalidDelegationChainError(
                    f"Token {i} temporal monotonicity violation: {e}"
                ) from e

        # Verify issuer is previous subject
        if token.issuer_did != prev_token.subject_did:
            raise InvalidDelegationChainError(
                f"Token {i} issuer {token.issuer_did} != previous subject {prev_token.subject_did}"
            )

        # Check expiry if requested
        if check_expiry:
            now = datetime.now(UTC)
            if token.is_not_yet_valid(now):
                raise InvalidDelegationChainError(
                    f"Token {i} not yet valid (not_before={token.constraints.not_before})"
                )
            if token.is_expired(now):
                raise InvalidDelegationChainError(
                    f"Token {i} expired (not_after={token.constraints.not_after})"
                )

        # Verify signature if we have a resolver
        if did_resolver is not None:
            try:
                issuer_public_key = did_resolver.resolve(token.issuer_did)
                verify_token(token, issuer_public_key, check_expiry=False)
            except InvalidTokenError as e:
                raise InvalidDelegationChainError(
                    f"Token {i} signature verification failed: {e}"
                ) from e

        prev_token = token

    return True


# =============================================================================
# Temporal Policy Helpers
# =============================================================================


def linear_decay_schedule(
    initial_max_spend: int | None = None,
    initial_quantity_limit: int | None = None,
    initial_rate_limit: int | None = None,
    duration_seconds: int = 3600,
    steps: int = 10,
) -> TemporalSchedule:
    """Generate a linear decay schedule.

    Creates thresholds where each value decreases linearly from the initial
    value down to zero over the specified duration.

    Args:
        initial_max_spend: Starting max_spend value.
        initial_quantity_limit: Starting quantity_limit value.
        initial_rate_limit: Starting rate_limit value.
        duration_seconds: Total duration for the decay.
        steps: Number of threshold steps.

    Returns:
        A TemporalSchedule with linearly decaying thresholds.
    """
    thresholds = []
    for i in range(1, steps + 1):
        at_seconds = (duration_seconds * i) // steps
        factor = 1.0 - (i / steps)

        ms = int(initial_max_spend * factor) if initial_max_spend is not None else None
        ql = int(initial_quantity_limit * factor) if initial_quantity_limit is not None else None
        rl = int(initial_rate_limit * factor) if initial_rate_limit is not None else None

        thresholds.append(TemporalThreshold(
            at_seconds=at_seconds,
            max_spend=ms,
            quantity_limit=ql,
            rate_limit=rl,
        ))
    return TemporalSchedule(thresholds=tuple(thresholds), policy="linear_decay")


def exponential_decay_schedule(
    initial_max_spend: int | None = None,
    initial_quantity_limit: int | None = None,
    initial_rate_limit: int | None = None,
    half_life_seconds: int = 1800,
    duration_seconds: int = 3600,
    steps: int = 10,
) -> TemporalSchedule:
    """Generate an exponential decay schedule.

    Creates thresholds where each value decays exponentially with the
    given half-life.

    Args:
        initial_max_spend: Starting max_spend value.
        initial_quantity_limit: Starting quantity_limit value.
        initial_rate_limit: Starting rate_limit value.
        half_life_seconds: Time for values to halve.
        duration_seconds: Total duration for the decay.
        steps: Number of threshold steps.

    Returns:
        A TemporalSchedule with exponentially decaying thresholds.
    """
    import math

    thresholds = []
    for i in range(1, steps + 1):
        at_seconds = (duration_seconds * i) // steps
        factor = math.pow(2, -at_seconds / half_life_seconds)

        ms = int(initial_max_spend * factor) if initial_max_spend is not None else None
        ql = int(initial_quantity_limit * factor) if initial_quantity_limit is not None else None
        rl = int(initial_rate_limit * factor) if initial_rate_limit is not None else None

        thresholds.append(TemporalThreshold(
            at_seconds=at_seconds,
            max_spend=ms,
            quantity_limit=ql,
            rate_limit=rl,
        ))
    return TemporalSchedule(thresholds=tuple(thresholds), policy="exponential")


def step_schedule(thresholds: list[TemporalThreshold]) -> TemporalSchedule:
    """Create a step schedule from explicit thresholds.

    Args:
        thresholds: List of temporal thresholds (will be validated for ordering).

    Returns:
        A TemporalSchedule wrapping the thresholds.

    Raises:
        TemporalScheduleError: If thresholds are not sorted by at_seconds.
    """
    return TemporalSchedule(thresholds=tuple(thresholds), policy="step")


# =============================================================================
# Multi-Owner Tokens
# =============================================================================


@dataclass(frozen=True)
class AuthorityChainEntry:
    """A single authority chain with its root public key.

    Attributes:
        chain: Ordered tuple of tokens from root to leaf.
        root_public_key: The public key of the root issuer.
    """

    chain: tuple[CapabilityToken, ...]
    root_public_key: bytes


@dataclass(frozen=True)
class MultiOwnerCapabilityToken:
    """A capability token requiring authorization from multiple owners.

    Each authority chain represents one owner's delegation path. The
    effective permissions are the intersection of all chains' leaf tokens.

    Attributes:
        authority_chains: Tuple of AuthorityChainEntry instances.
    """

    authority_chains: tuple[AuthorityChainEntry, ...]

    def effective_verbs(self) -> VerbSet:
        """Compute the intersection of all chains' leaf token verbs."""
        if not self.authority_chains:
            return VerbSet(frozenset())
        result = self.authority_chains[0].chain[-1].verbs
        for entry in self.authority_chains[1:]:
            result = result.intersection(entry.chain[-1].verbs)
        return result

    def effective_constraints(self) -> Constraints:
        """Compute the most restrictive constraints across all chains."""
        constraints_list = [
            entry.chain[-1].constraints for entry in self.authority_chains
        ]
        return intersect_constraints(constraints_list)


def intersect_constraints(constraints_list: list[Constraints]) -> Constraints:
    """Intersect a list of constraints, taking the most restrictive value for each field.

    Args:
        constraints_list: List of Constraints to intersect.

    Returns:
        A single Constraints with the most restrictive values.

    Raises:
        MultiOwnerValidationError: If the list is empty.
    """
    if not constraints_list:
        raise MultiOwnerValidationError("Cannot intersect empty constraints list")

    if len(constraints_list) == 1:
        return constraints_list[0]

    result = constraints_list[0]
    for c in constraints_list[1:]:
        # not_before: take latest
        new_not_before = result.not_before
        if c.not_before is not None and (
            new_not_before is None or c.not_before > new_not_before
        ):
            new_not_before = c.not_before

        # not_after: take earliest
        new_not_after = result.not_after
        if c.not_after is not None and (
            new_not_after is None or c.not_after < new_not_after
        ):
            new_not_after = c.not_after

        # quantity_limit: take smallest
        new_quantity_limit = result.quantity_limit
        if c.quantity_limit is not None and (
            new_quantity_limit is None or c.quantity_limit < new_quantity_limit
        ):
            new_quantity_limit = c.quantity_limit

        # rate_limit: take smallest
        new_rate_limit = result.rate_limit
        if c.rate_limit is not None and (
            new_rate_limit is None or c.rate_limit < new_rate_limit
        ):
            new_rate_limit = c.rate_limit

        # max_spend: take smallest
        new_max_spend = result.max_spend
        if c.max_spend is not None and (
            new_max_spend is None or c.max_spend < new_max_spend
        ):
            new_max_spend = c.max_spend

        # data_scope: intersection
        new_data_scope = result.data_scope
        if c.data_scope:
            if new_data_scope:
                new_data_scope = new_data_scope.intersection(c.data_scope)
            else:
                new_data_scope = c.data_scope

        # allowed_toolchain: intersection preserving order
        new_toolchain = result.allowed_toolchain
        if c.allowed_toolchain:
            if new_toolchain:
                new_toolchain = tuple(
                    t for t in new_toolchain if t in c.allowed_toolchain
                )
            else:
                new_toolchain = c.allowed_toolchain

        result = Constraints(
            not_before=new_not_before,
            not_after=new_not_after,
            quantity_limit=new_quantity_limit,
            quantity_unit=result.quantity_unit or c.quantity_unit,
            rate_limit=new_rate_limit,
            rate_period_seconds=result.rate_period_seconds,
            max_spend=new_max_spend,
            spend_currency=result.spend_currency or c.spend_currency,
            data_scope=new_data_scope,
            purpose=result.purpose or c.purpose,
            allowed_toolchain=new_toolchain,
        )

    return result


def create_multi_owner_token(
    authority_chains: list[AuthorityChainEntry],
) -> MultiOwnerCapabilityToken:
    """Create a multi-owner capability token from authority chains.

    Args:
        authority_chains: List of authority chain entries.

    Returns:
        A MultiOwnerCapabilityToken.

    Raises:
        MultiOwnerValidationError: If authority_chains is empty.
    """
    if not authority_chains:
        raise MultiOwnerValidationError(
            "Cannot create multi-owner token with empty authority chains"
        )
    return MultiOwnerCapabilityToken(
        authority_chains=tuple(authority_chains),
    )


def verify_multi_owner_token(
    token: MultiOwnerCapabilityToken,
    did_resolver: DIDResolver | None = None,
    check_expiry: bool = True,
) -> bool:
    """Verify all authority chains in a multi-owner token.

    Args:
        token: The multi-owner token to verify.
        did_resolver: Optional DID resolver for signature verification.
        check_expiry: Whether to check time-based constraints.

    Returns:
        True if all chains are valid.

    Raises:
        MultiOwnerValidationError: If any chain fails verification.
    """
    if not token.authority_chains:
        raise MultiOwnerValidationError(
            "Cannot verify multi-owner token with empty authority chains"
        )

    for i, entry in enumerate(token.authority_chains):
        try:
            verify_delegation_chain(
                tokens=list(entry.chain),
                root_issuer_public_key=entry.root_public_key,
                did_resolver=did_resolver,
                check_expiry=check_expiry,
            )
        except (InvalidDelegationChainError, InvalidTokenError, TokenExpiredError) as e:
            raise MultiOwnerValidationError(
                f"Authority chain {i} verification failed: {e}"
            ) from e

    return True
