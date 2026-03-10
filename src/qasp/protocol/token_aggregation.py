"""Token aggregation algebra for combining multiple capability tokens.

An agent holding multiple capability tokens from different authorities can
aggregate them into a single effective permission set:
- Verbs are **unioned** (the agent gains all permissions it holds).
- Resource URIs are **unioned**.
- Constraints are **intersected** (the tightest constraint wins).

This is distinct from multi-owner tokens (which *intersect* verbs because
multiple owners must agree) and from signature aggregation (which optimizes
delegation chain verification).
"""

from __future__ import annotations

from dataclasses import dataclass

from qasp.protocol.arm import InvalidARMUriError, uri_matches
from qasp.protocol.capability import (
    CapabilityError,
    CapabilityToken,
    Constraints,
    DIDResolver,
    RevocationChecker,
    TokenConstraintViolation,
    VerbSet,
    intersect_constraints,
    verify_token,
)

__all__ = [
    "AggregatedPermission",
    "ConstraintConflictError",
    "TokenAggregationError",
    "aggregate_tokens",
    "check_action_permitted",
]


# =============================================================================
# Exceptions
# =============================================================================


class ConstraintConflictError(CapabilityError):
    """Irreconcilable constraint conflict during aggregation.

    Raised when intersected constraints produce an impossible permission set
    (e.g., empty time window, conflicting purposes/units/currencies).
    """

    alert_code: int = 54


class TokenAggregationError(CapabilityError):
    """Structural error during token aggregation.

    Raised for empty token lists, mismatched subject_did, or
    inconsistent audience_did values.
    """

    alert_code: int = 55


# =============================================================================
# Data Structures
# =============================================================================


@dataclass(frozen=True)
class AggregatedPermission:
    """Result of aggregating multiple capability tokens.

    Attributes:
        verbs: Union of all token verbs.
        resource_uris: Union of all token resource URIs.
        constraints: Intersection of all token constraints.
        source_token_ids: Identifiers of the tokens that were aggregated.
    """

    verbs: VerbSet
    resource_uris: frozenset[str]
    constraints: Constraints
    source_token_ids: tuple[bytes, ...]


# =============================================================================
# Core Functions
# =============================================================================


def aggregate_tokens(
    tokens: list[CapabilityToken],
    issuer_public_keys: dict[str, bytes] | None = None,
    did_resolver: DIDResolver | None = None,
    check_expiry: bool = True,
    crl: RevocationChecker | None = None,
) -> AggregatedPermission:
    """Aggregate multiple capability tokens into a single effective permission.

    All tokens must belong to the same subject. Each token is independently
    verified before aggregation. If any token fails verification, the entire
    aggregation fails.

    Args:
        tokens: List of capability tokens to aggregate.
        issuer_public_keys: Map of issuer DID string -> public key bytes.
        did_resolver: Optional DID resolver for looking up issuer keys not
            in issuer_public_keys.
        check_expiry: Whether to check time-based constraints.
        crl: Optional revocation checker.

    Returns:
        An AggregatedPermission with unioned verbs/resources and
        intersected constraints.

    Raises:
        TokenAggregationError: If tokens list is empty, subjects differ,
            or audience DIDs are inconsistent.
        ConstraintConflictError: If intersected constraints are irreconcilable.
        InvalidTokenError: If any token's signature is invalid.
        TokenExpiredError: If any token has expired.
        TokenRevokedError: If any token has been revoked.
    """
    if not tokens:
        raise TokenAggregationError("Cannot aggregate empty token list")

    if issuer_public_keys is None:
        issuer_public_keys = {}

    # Single-token fast path
    if len(tokens) == 1:
        token = tokens[0]
        pub_key = _resolve_key(token, issuer_public_keys, did_resolver)
        verify_token(token, pub_key, check_expiry=check_expiry, crl=crl)
        return AggregatedPermission(
            verbs=token.verbs,
            resource_uris=frozenset({token.resource_uri}),
            constraints=token.constraints,
            source_token_ids=(token.token_id,),
        )

    # Validate same subject_did
    subject = tokens[0].subject_did
    for i, token in enumerate(tokens[1:], start=1):
        if token.subject_did != subject:
            raise TokenAggregationError(
                f"Token {i} subject_did {token.subject_did} does not match "
                f"token 0 subject_did {subject}"
            )

    # Validate audience_did consistency: non-None values must all match
    audience = None
    for i, token in enumerate(tokens):
        if token.audience_did is not None:
            if audience is None:
                audience = token.audience_did
            elif token.audience_did != audience:
                raise TokenAggregationError(
                    f"Token {i} audience_did {token.audience_did} does not match "
                    f"earlier audience_did {audience}"
                )

    # Verify each token independently
    for token in tokens:
        pub_key = _resolve_key(token, issuer_public_keys, did_resolver)
        verify_token(token, pub_key, check_expiry=check_expiry, crl=crl)

    # Compute verb union
    result_verbs = tokens[0].verbs
    for token in tokens[1:]:
        result_verbs = result_verbs.union(token.verbs)

    # Compute resource union
    resource_uris = frozenset(t.resource_uri for t in tokens)

    # Compute constraint intersection
    constraints = _aggregate_constraints([t.constraints for t in tokens])

    return AggregatedPermission(
        verbs=result_verbs,
        resource_uris=resource_uris,
        constraints=constraints,
        source_token_ids=tuple(t.token_id for t in tokens),
    )


def check_action_permitted(
    aggregation: AggregatedPermission,
    requested_verb: str,
    requested_resource: str,
) -> bool:
    """Check if an action is permitted by the aggregated permissions.

    Args:
        aggregation: The aggregated permission to check against.
        requested_verb: The verb to check.
        requested_resource: The resource URI to check.

    Returns:
        True if the action is permitted.

    Raises:
        TokenConstraintViolation: If the verb or resource is not permitted.
    """
    if requested_verb not in aggregation.verbs:
        raise TokenConstraintViolation(
            f"Verb '{requested_verb}' not in aggregated permissions"
        )
    # Use ARM URI matching: check if any aggregated URI covers the request
    resource_permitted = False
    for uri in aggregation.resource_uris:
        try:
            if uri_matches(uri, requested_resource):
                resource_permitted = True
                break
        except InvalidARMUriError:
            # Fall back to exact match for non-ARM URIs
            if uri == requested_resource:
                resource_permitted = True
                break
    if not resource_permitted:
        raise TokenConstraintViolation(
            f"Resource '{requested_resource}' not in aggregated permissions"
        )
    return True


# =============================================================================
# Private Helpers
# =============================================================================


def _resolve_key(
    token: CapabilityToken,
    issuer_public_keys: dict[str, bytes],
    did_resolver: DIDResolver | None,
) -> bytes:
    """Resolve the public key for a token's issuer.

    Checks the provided map first, then falls back to the DID resolver.

    Raises:
        TokenAggregationError: If the key cannot be resolved.
    """
    issuer_str = str(token.issuer_did)
    key = issuer_public_keys.get(issuer_str)
    if key is not None:
        return key
    if did_resolver is not None:
        return did_resolver.resolve(token.issuer_did)
    raise TokenAggregationError(
        f"No public key for issuer {issuer_str} and no DID resolver provided"
    )


def _aggregate_constraints(constraints_list: list[Constraints]) -> Constraints:
    """Intersect constraints and check for irreconcilable conflicts.

    Uses the existing ``intersect_constraints`` for the core algebra, then
    applies additional conflict checks that ``intersect_constraints`` silently
    ignores.

    Raises:
        ConstraintConflictError: If the intersection produces an impossible
            constraint set.
    """
    result = intersect_constraints(constraints_list)

    # Check for empty time window
    if (
        result.not_before is not None
        and result.not_after is not None
        and result.not_before >= result.not_after
    ):
        raise ConstraintConflictError(
            f"Empty time window: not_before ({result.not_before}) "
            f">= not_after ({result.not_after})"
        )

    # Check for conflicting purposes
    purposes = {c.purpose for c in constraints_list if c.purpose}
    if len(purposes) > 1:
        raise ConstraintConflictError(
            f"Conflicting purposes: {purposes}"
        )

    # Check for conflicting quantity units
    units = {c.quantity_unit for c in constraints_list if c.quantity_unit}
    if len(units) > 1:
        raise ConstraintConflictError(
            f"Conflicting quantity units: {units}"
        )

    # Check for conflicting spend currencies
    currencies = {c.spend_currency for c in constraints_list if c.spend_currency}
    if len(currencies) > 1:
        raise ConstraintConflictError(
            f"Conflicting spend currencies: {currencies}"
        )

    return result
