"""Threshold-signed capability tokens.

Creates standard CapabilityTokens where the issuer is a threshold group.
The resulting signature is a standard ML-DSA-65 signature indistinguishable
from single-signer tokens. No changes to verify_token() are required.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from qasp.crypto.threshold import (
    DKGResult,
    ThresholdCoordinator,
    ThresholdSigner,
    threshold_sign_with_retry,
)
from qasp.identity.did import DID
from qasp.identity.group import ThresholdGroup
from qasp.protocol.capability import (
    CapabilityToken,
    Constraints,
    TemporalSchedule,
    VerbSet,
    _encode_token_data,
)

__all__ = [
    "ThresholdTokenMetadata",
    "attenuate_token_threshold",
    "create_threshold_metadata",
    "create_threshold_signed_token",
]

NONCE_SIZE = 16
DEFAULT_VALIDITY_SECONDS = 3600


@dataclass(frozen=True)
class ThresholdTokenMetadata:
    """Auxiliary audit data for threshold-signed tokens.

    This is NOT part of the signed token — it records which group
    and which signers participated, for audit purposes.
    """

    group_did: DID
    threshold: int
    num_participants: int
    signer_indices: tuple[int, ...]
    signer_dids: tuple[DID, ...]
    token_id: bytes


def _make_coordinator(group: ThresholdGroup, signer_indices: list[int]) -> ThresholdCoordinator:
    """Build a ThresholdCoordinator from group data and the first DKG result."""
    # We need the group_t, group_t0, group_t1, group_tr, group_rho from any DKG result.
    # These are stored in the ThresholdGroup indirectly via the DKG results passed
    # to create_threshold_signed_token, so callers pass dkg_results directly.
    raise NotImplementedError("Use _make_coordinator_from_result instead")


def _make_coordinator_from_result(
    result: DKGResult, signer_indices: list[int]
) -> ThresholdCoordinator:
    return ThresholdCoordinator(
        group_public_key=result.group_public_key,
        group_t=result.group_t,
        group_t0=result.group_t0,
        group_t1=result.group_t1,
        group_tr=result.group_tr,
        group_rho=result.group_rho,
        signer_indices=signer_indices,
    )


def create_threshold_signed_token(
    group: ThresholdGroup,
    dkg_results: list[DKGResult],
    signer_indices: list[int],
    subject_did: DID,
    resource_uri: str,
    verbs: set[str] | VerbSet,
    constraints: Constraints | None = None,
    audience_did: DID | None = None,
    max_delegation_depth: int = 0,
    validity_seconds: int = DEFAULT_VALIDITY_SECONDS,
    max_attempts: int = 32,
) -> CapabilityToken:
    """Create a capability token signed by a threshold group.

    Args:
        group: The threshold group identity.
        dkg_results: DKG results for the signing participants.
        signer_indices: Participant indices forming the quorum.
        subject_did: The DID of the token holder.
        resource_uri: The resource this token grants access to.
        verbs: The permitted operations.
        constraints: Optional usage constraints.
        audience_did: Optional service provider DID.
        max_delegation_depth: Maximum delegation levels allowed.
        validity_seconds: Token validity duration in seconds.
        max_attempts: Maximum threshold signing attempts.

    Returns:
        A signed CapabilityToken with issuer_did = group.group_did.
    """
    nonce = os.urandom(NONCE_SIZE)
    token_id = hashlib.sha384(str(group.group_did).encode() + nonce).digest()[:32]

    issued_at = datetime.now(UTC)
    not_after = issued_at + timedelta(seconds=validity_seconds)

    verb_set = verbs if isinstance(verbs, VerbSet) else VerbSet(verbs)

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

    # Build the message to sign (same CBOR encoding as create_token)
    message = _encode_token_data(
        token_id=token_id,
        issuer_did=group.group_did,
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
    )

    # Build signers and coordinator
    result_by_index = {r.my_index: r for r in dkg_results}
    signers = [
        ThresholdSigner(result_by_index[idx], message, signer_indices)
        for idx in signer_indices
    ]
    coordinator = _make_coordinator_from_result(dkg_results[0], signer_indices)

    threshold_sig = threshold_sign_with_retry(signers, coordinator, message, max_attempts)

    return CapabilityToken(
        token_id=token_id,
        issuer_did=group.group_did,
        subject_did=subject_did,
        audience_did=audience_did,
        resource_uri=resource_uri,
        verbs=verb_set,
        constraints=constraints,
        issued_at=issued_at,
        nonce=nonce,
        signature=threshold_sig.signature,
        parent_token_hash=None,
        max_delegation_depth=max_delegation_depth,
        delegation_chain_length=0,
        toolchain_position=0,
    )


def attenuate_token_threshold(
    parent_token: CapabilityToken,
    group: ThresholdGroup,
    dkg_results: list[DKGResult],
    signer_indices: list[int],
    new_subject_did: DID,
    reduced_verbs: VerbSet | None = None,
    tightened_constraints: Constraints | None = None,
    max_attempts: int = 32,
) -> CapabilityToken:
    """Create an attenuated token signed by a threshold group.

    Same validation logic as attenuate_token() but uses threshold signing.

    Args:
        parent_token: The parent token to attenuate from.
        group: The threshold group identity (must be parent's subject).
        dkg_results: DKG results for the signing participants.
        signer_indices: Participant indices forming the quorum.
        new_subject_did: The DID of the new token holder.
        reduced_verbs: New verb set (must be subset of parent).
        tightened_constraints: Additional constraint tightening.
        max_attempts: Maximum threshold signing attempts.

    Returns:
        A new attenuated CapabilityToken signed by the group.
    """
    from qasp.protocol.capability import AttenuationError, DelegationDepthExceeded, TokenExpiredError

    if parent_token.is_expired():
        raise TokenExpiredError(
            f"Cannot attenuate expired token (expired at {parent_token.constraints.not_after})"
        )

    if parent_token.max_delegation_depth <= 0:
        raise DelegationDepthExceeded(
            "Parent token does not allow delegation (max_delegation_depth=0)"
        )

    if reduced_verbs is None:
        new_verbs = parent_token.verbs
    else:
        if not reduced_verbs.issubset(parent_token.verbs):
            extra = set(reduced_verbs.verbs) - set(parent_token.verbs.verbs)
            raise AttenuationError(f"Cannot delegate verbs not held: {extra}")
        new_verbs = reduced_verbs

    if tightened_constraints is None:
        new_constraints = parent_token.constraints
    else:
        new_constraints = parent_token.constraints.tighten(tightened_constraints)
        if not new_constraints.is_tighter_than(parent_token.constraints):
            raise AttenuationError("New constraints are not tighter than parent")

    nonce = os.urandom(NONCE_SIZE)
    token_id = hashlib.sha384(str(group.group_did).encode() + nonce).digest()[:32]
    issued_at = datetime.now(UTC)
    parent_hash = parent_token.compute_hash()
    new_depth = parent_token.max_delegation_depth - 1
    new_chain_length = parent_token.delegation_chain_length + 1

    message = _encode_token_data(
        token_id=token_id,
        issuer_did=group.group_did,
        subject_did=new_subject_did,
        audience_did=parent_token.audience_did,
        resource_uri=parent_token.resource_uri,
        verbs=new_verbs,
        constraints=new_constraints,
        issued_at=issued_at,
        nonce=nonce,
        parent_token_hash=parent_hash,
        max_delegation_depth=new_depth,
        delegation_chain_length=new_chain_length,
        toolchain_position=parent_token.toolchain_position,
    )

    result_by_index = {r.my_index: r for r in dkg_results}
    signers = [
        ThresholdSigner(result_by_index[idx], message, signer_indices)
        for idx in signer_indices
    ]
    coordinator = _make_coordinator_from_result(dkg_results[0], signer_indices)

    threshold_sig = threshold_sign_with_retry(signers, coordinator, message, max_attempts)

    return CapabilityToken(
        token_id=token_id,
        issuer_did=group.group_did,
        subject_did=new_subject_did,
        audience_did=parent_token.audience_did,
        resource_uri=parent_token.resource_uri,
        verbs=new_verbs,
        constraints=new_constraints,
        issued_at=issued_at,
        nonce=nonce,
        signature=threshold_sig.signature,
        parent_token_hash=parent_hash,
        max_delegation_depth=new_depth,
        delegation_chain_length=new_chain_length,
        toolchain_position=parent_token.toolchain_position,
    )


def create_threshold_metadata(
    group: ThresholdGroup,
    signer_indices: list[int],
    token: CapabilityToken,
) -> ThresholdTokenMetadata:
    """Create audit metadata for a threshold-signed token.

    Args:
        group: The threshold group that signed the token.
        signer_indices: The participant indices that signed.
        token: The resulting token.

    Returns:
        ThresholdTokenMetadata for audit logging.
    """
    signer_dids = tuple(
        group.member_dids[idx - 1] for idx in signer_indices
    )
    return ThresholdTokenMetadata(
        group_did=group.group_did,
        threshold=group.threshold,
        num_participants=group.num_participants,
        signer_indices=tuple(signer_indices),
        signer_dids=signer_dids,
        token_id=token.token_id,
    )
