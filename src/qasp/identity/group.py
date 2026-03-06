"""Threshold group DID for M-of-N delegation.

A ThresholdGroup wraps the combined public key from a DKG ceremony
into a standard did:qasp identity. Verifiers resolve the group DID,
get the combined public key, and verify standard ML-DSA-65 signatures.
Threshold mechanics are transparent to verification.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from qasp.crypto.threshold import DKGResult
from qasp.identity.did import (
    DID,
    DIDDocument,
    DIDRegistry,
    VerificationMethod,
    create_did,
    encode_public_key_multibase,
)
from qasp.identity.exceptions import ThresholdGroupError

__all__ = [
    "ThresholdGroup",
    "create_threshold_group",
    "get_threshold_policy",
    "is_threshold_did",
    "register_threshold_group",
]

# Service type used to encode M-of-N policy in DIDDocument
THRESHOLD_POLICY_SERVICE_TYPE = "ThresholdPolicy"


@dataclass(frozen=True)
class ThresholdGroup:
    """A threshold group identity derived from DKG.

    Attributes:
        group_did: The did:qasp identifier for the group.
        group_did_document: The DID document containing the group public key.
        group_public_key: The combined ML-DSA-65 public key (1952 bytes).
        threshold: The minimum signers required (M).
        num_participants: The total group size (N).
        member_dids: Ordered tuple of member DIDs (by participant index).
        member_indices: Mapping from DID string to participant index.
        created_at: Timestamp of group creation.
    """

    group_did: DID
    group_did_document: DIDDocument
    group_public_key: bytes
    threshold: int
    num_participants: int
    member_dids: tuple[DID, ...]
    member_indices: dict[str, int]
    created_at: datetime


def create_threshold_group(
    dkg_results: list[DKGResult],
    member_dids: list[DID],
) -> ThresholdGroup:
    """Create a threshold group identity from DKG results.

    Args:
        dkg_results: DKG results from all participants (one per member).
        member_dids: DIDs of the group members, ordered by participant index.

    Returns:
        A ThresholdGroup with a group DID derived from the combined public key.

    Raises:
        ThresholdGroupError: If DKG results are inconsistent or inputs invalid.
    """
    if not dkg_results:
        raise ThresholdGroupError("No DKG results provided")

    if len(member_dids) != len(dkg_results):
        raise ThresholdGroupError(
            f"Number of member DIDs ({len(member_dids)}) must match "
            f"number of DKG results ({len(dkg_results)})"
        )

    # Verify all results agree on group public key
    group_pk = dkg_results[0].group_public_key
    threshold = dkg_results[0].threshold
    num_participants = dkg_results[0].num_participants

    for i, r in enumerate(dkg_results[1:], 1):
        if r.group_public_key != group_pk:
            raise ThresholdGroupError(
                f"DKG result {i} has different group public key"
            )
        if r.threshold != threshold:
            raise ThresholdGroupError(
                f"DKG result {i} has different threshold "
                f"({r.threshold} vs {threshold})"
            )
        if r.num_participants != num_participants:
            raise ThresholdGroupError(
                f"DKG result {i} has different num_participants "
                f"({r.num_participants} vs {num_participants})"
            )

    if len(member_dids) != num_participants:
        raise ThresholdGroupError(
            f"Number of member DIDs ({len(member_dids)}) must match "
            f"num_participants ({num_participants})"
        )

    # Create group DID from combined public key
    group_did, base_doc = create_did(group_pk)
    did_string = str(group_did)

    # Build DID document with ThresholdPolicy service endpoint
    policy_endpoint = f"{threshold}-of-{num_participants}"

    # Re-create document with service endpoint
    group_doc = DIDDocument(
        did=group_did,
        verification_methods=base_doc.verification_methods,
        authentication=base_doc.authentication,
        assertion_method=base_doc.assertion_method,
        service_endpoints={THRESHOLD_POLICY_SERVICE_TYPE: policy_endpoint},
    )

    # Build member index mapping
    member_indices = {str(d): i + 1 for i, d in enumerate(member_dids)}

    return ThresholdGroup(
        group_did=group_did,
        group_did_document=group_doc,
        group_public_key=group_pk,
        threshold=threshold,
        num_participants=num_participants,
        member_dids=tuple(member_dids),
        member_indices=member_indices,
        created_at=datetime.now(UTC),
    )


def register_threshold_group(group: ThresholdGroup, registry: DIDRegistry) -> None:
    """Register a threshold group's DID document in a registry.

    Args:
        group: The threshold group to register.
        registry: The DID registry to register in.
    """
    registry.register(group.group_did_document)


def is_threshold_did(did_document: DIDDocument) -> bool:
    """Check whether a DID document represents a threshold group.

    Args:
        did_document: The DID document to check.

    Returns:
        True if the document has a ThresholdPolicy service endpoint.
    """
    return THRESHOLD_POLICY_SERVICE_TYPE in did_document.service_endpoints


def get_threshold_policy(did_document: DIDDocument) -> tuple[int, int] | None:
    """Extract the threshold policy (M, N) from a DID document.

    Args:
        did_document: The DID document to inspect.

    Returns:
        Tuple of (threshold, num_participants) or None if not a threshold DID.
    """
    endpoint = did_document.service_endpoints.get(THRESHOLD_POLICY_SERVICE_TYPE)
    if endpoint is None:
        return None

    try:
        parts = endpoint.split("-of-")
        if len(parts) != 2:
            return None
        return int(parts[0]), int(parts[1])
    except (ValueError, IndexError):
        return None
