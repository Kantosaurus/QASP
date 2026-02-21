"""Signature aggregation for deep delegation chains.

Reduces O(d) independent ML-DSA-65 signature verifications to O(1) signature
verification + O(d) SHA-384 hash computations by chaining aggregate signatures.

The aggregate is stored in each delegated token's ``signature`` field. The root
token always carries a standard ML-DSA-65 signature. Verification reconstructs
the hash chain and checks only the final aggregate signature.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from qasp.crypto.exceptions import InvalidSignatureError
from qasp.crypto.signatures import sign, verify
from qasp.protocol.capability import (
    NONCE_SIZE,
    AttenuationError,
    CapabilityToken,
    Constraints,
    DelegationDepthExceeded,
    InvalidDelegationChainError,
    TokenExpiredError,
    TokenNotYetValidError,
    VerbSet,
    _encode_token_data,
    verify_delegation_chain,
    verify_token,
)

if TYPE_CHECKING:
    from qasp.protocol.capability import DIDResolver

__all__ = [
    "DelegationChain",
    "aggregate_sign",
    "aggregate_verify_chain",
    "attenuate_token_aggregate",
]


# =============================================================================
# Core Aggregation Primitives
# =============================================================================


def aggregate_sign(
    signer_sk: bytes,
    previous_aggregate: bytes,
    new_token_cbor: bytes,
) -> bytes:
    """Produce an aggregate signature over the chain so far.

    Computes ``digest = SHA-384(previous_aggregate || new_token_cbor)`` and
    signs the digest with *signer_sk*.

    Args:
        signer_sk: The delegator's ML-DSA-65 secret key.
        previous_aggregate: The aggregate signature from the previous step
            (for the first delegation this is the root token's standard
            signature).
        new_token_cbor: CBOR-encoded token data (without signature) for the
            new delegation step.

    Returns:
        The ML-DSA-65 signature over the aggregate digest.
    """
    digest = hashlib.sha384(previous_aggregate + new_token_cbor).digest()
    return sign(signer_sk, digest)


def aggregate_verify_chain(
    tokens: list[CapabilityToken],
    root_issuer_public_key: bytes,
    did_resolver: DIDResolver | None = None,
    check_expiry: bool = True,
) -> bool:
    """Verify an aggregated delegation chain.

    Verifies the root token's standard signature, performs structural checks
    on every token, and verifies only the **last** token's aggregate signature
    (which transitively covers the entire chain via the SHA-384 hash chain).

    Args:
        tokens: Ordered list of tokens from root to leaf.
        root_issuer_public_key: The root issuer's ML-DSA-65 public key.
        did_resolver: Resolver for intermediate DID public keys. Required to
            verify the final aggregate signature on chains with > 1 token.
        check_expiry: Whether to enforce time-based constraints.

    Returns:
        True if the chain is valid.

    Raises:
        InvalidDelegationChainError: If structural or signature checks fail.
    """
    if not tokens:
        raise InvalidDelegationChainError("Empty token chain")

    root = tokens[0]
    if root.parent_token_hash is not None:
        raise InvalidDelegationChainError(
            "Root token cannot have a parent_token_hash"
        )

    # Verify root token with standard signature check.
    try:
        verify_token(root, root_issuer_public_key, check_expiry=check_expiry)
    except (InvalidDelegationChainError, TokenExpiredError, TokenNotYetValidError) as e:
        raise InvalidDelegationChainError(
            f"Root token verification failed: {e}"
        ) from e
    except Exception as e:
        raise InvalidDelegationChainError(
            f"Root token verification failed: {e}"
        ) from e

    if len(tokens) == 1:
        return True

    # Reconstruct the hash chain.
    current_agg = root.signature
    prev_token = root
    last_index = len(tokens) - 1

    for i, token in enumerate(tokens[1:], start=1):
        # --- structural checks (mirroring verify_delegation_chain) ---

        expected_hash = prev_token.compute_hash()
        if token.parent_token_hash != expected_hash:
            raise InvalidDelegationChainError(
                f"Token {i} parent_token_hash mismatch"
            )

        if token.delegation_chain_length != prev_token.delegation_chain_length + 1:
            raise InvalidDelegationChainError(
                f"Token {i} has incorrect chain_length"
            )

        if token.max_delegation_depth != prev_token.max_delegation_depth - 1:
            raise InvalidDelegationChainError(
                f"Token {i} has incorrect max_delegation_depth"
            )

        if not token.verbs.issubset(prev_token.verbs):
            raise InvalidDelegationChainError(
                f"Token {i} has verbs not granted by parent"
            )

        if not token.constraints.is_tighter_than(prev_token.constraints):
            raise InvalidDelegationChainError(
                f"Token {i} constraints are not tighter than parent"
            )

        if token.issuer_did != prev_token.subject_did:
            raise InvalidDelegationChainError(
                f"Token {i} issuer {token.issuer_did} != "
                f"previous subject {prev_token.subject_did}"
            )

        if check_expiry:
            now = datetime.now(UTC)
            if token.is_not_yet_valid(now):
                raise InvalidDelegationChainError(
                    f"Token {i} not yet valid "
                    f"(not_before={token.constraints.not_before})"
                )
            if token.is_expired(now):
                raise InvalidDelegationChainError(
                    f"Token {i} expired "
                    f"(not_after={token.constraints.not_after})"
                )

        # --- aggregate hash-chain step ---

        expected_digest = hashlib.sha384(
            current_agg + token.to_cbor()
        ).digest()

        if i == last_index and did_resolver is not None:
            # Verify the final aggregate signature.
            issuer_pk = did_resolver.resolve(token.issuer_did)
            try:
                verify(issuer_pk, expected_digest, token.signature)
            except InvalidSignatureError as e:
                raise InvalidDelegationChainError(
                    f"Token {i} aggregate signature verification failed: {e}"
                ) from e

        current_agg = token.signature
        prev_token = token

    return True


# =============================================================================
# Aggregate Delegation
# =============================================================================


def attenuate_token_aggregate(
    parent_token: CapabilityToken,
    delegator_sk: bytes,
    new_subject_did: object,
    previous_aggregate: bytes,
    reduced_verbs: VerbSet | None = None,
    tightened_constraints: Constraints | None = None,
    toolchain_position: int | None = None,
) -> tuple[CapabilityToken, bytes]:
    """Create an attenuated token using aggregate signatures.

    Equivalent to :func:`~qasp.protocol.capability.attenuate_token` but the
    resulting token's ``signature`` field carries the running aggregate rather
    than an independent ML-DSA-65 signature.

    Args:
        parent_token: The parent token to attenuate from.
        delegator_sk: The delegating subject's ML-DSA-65 secret key.
        new_subject_did: DID of the new token holder.
        previous_aggregate: The aggregate signature up to and including the
            parent token (for the first delegation, pass ``root.signature``).
        reduced_verbs: Optional reduced verb set (must be subset of parent's).
        tightened_constraints: Optional constraint tightening.
        toolchain_position: Toolchain position override.

    Returns:
        A ``(token, aggregate)`` tuple where *token* has the aggregate stored
        in its ``signature`` field and *aggregate* equals ``token.signature``.

    Raises:
        TokenExpiredError: If the parent token has expired.
        DelegationDepthExceeded: If delegation depth is exhausted.
        AttenuationError: If verbs or constraints violate attenuation rules.
    """
    # --- validation (mirrors attenuate_token) ---

    if parent_token.is_expired():
        raise TokenExpiredError(
            f"Cannot attenuate expired token "
            f"(expired at {parent_token.constraints.not_after})"
        )

    if parent_token.max_delegation_depth <= 0:
        raise DelegationDepthExceeded(
            "Parent token does not allow delegation (max_delegation_depth=0)"
        )

    # Verbs
    if reduced_verbs is None:
        new_verbs = parent_token.verbs
    else:
        if not reduced_verbs.issubset(parent_token.verbs):
            extra = set(reduced_verbs.verbs) - set(parent_token.verbs.verbs)
            raise AttenuationError(f"Cannot delegate verbs not held: {extra}")
        new_verbs = reduced_verbs

    # Constraints
    if tightened_constraints is None:
        new_constraints = parent_token.constraints
    else:
        new_constraints = parent_token.constraints.tighten(tightened_constraints)
        if not new_constraints.is_tighter_than(parent_token.constraints):
            raise AttenuationError(
                "New constraints are not tighter than parent"
            )

    # Toolchain position
    new_tc_pos = (
        toolchain_position
        if toolchain_position is not None
        else parent_token.toolchain_position
    )

    # --- build the new token ---

    nonce = os.urandom(NONCE_SIZE)
    token_id = hashlib.sha384(
        str(parent_token.subject_did).encode() + nonce
    ).digest()[:32]
    issued_at = datetime.now(UTC)
    parent_hash = parent_token.compute_hash()
    new_depth = parent_token.max_delegation_depth - 1
    new_chain_length = parent_token.delegation_chain_length + 1

    cbor_message = _encode_token_data(
        token_id=token_id,
        issuer_did=parent_token.subject_did,
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
        toolchain_position=new_tc_pos,
    )

    # Aggregate signature
    signature = aggregate_sign(delegator_sk, previous_aggregate, cbor_message)

    token = CapabilityToken(
        token_id=token_id,
        issuer_did=parent_token.subject_did,
        subject_did=new_subject_did,
        audience_did=parent_token.audience_did,
        resource_uri=parent_token.resource_uri,
        verbs=new_verbs,
        constraints=new_constraints,
        issued_at=issued_at,
        nonce=nonce,
        signature=signature,
        parent_token_hash=parent_hash,
        max_delegation_depth=new_depth,
        delegation_chain_length=new_chain_length,
        toolchain_position=new_tc_pos,
    )

    return token, signature


# =============================================================================
# DelegationChain Container
# =============================================================================


@dataclass(frozen=True)
class DelegationChain:
    """Container for a delegation chain that auto-selects the verification path.

    Holds an ordered sequence of :class:`CapabilityToken` instances (root first,
    leaf last) together with an ``is_aggregated`` flag.  The :meth:`verify`
    method dispatches to :func:`aggregate_verify_chain` or
    :func:`~qasp.protocol.capability.verify_delegation_chain` accordingly.
    """

    tokens: tuple[CapabilityToken, ...]
    is_aggregated: bool = False

    # -- convenience properties --

    @property
    def root(self) -> CapabilityToken:
        """The root (first) token in the chain."""
        return self.tokens[0]

    @property
    def leaf(self) -> CapabilityToken:
        """The leaf (last) token in the chain."""
        return self.tokens[-1]

    @property
    def depth(self) -> int:
        """Number of delegation steps (0 for a root-only chain)."""
        return len(self.tokens) - 1

    @property
    def aggregate_signature(self) -> bytes | None:
        """The current aggregate signature, or *None* if not aggregated."""
        if self.is_aggregated and len(self.tokens) > 1:
            return self.tokens[-1].signature
        return None

    # -- verification --

    def verify(
        self,
        root_issuer_pk: bytes,
        did_resolver: DIDResolver | None = None,
        check_expiry: bool = True,
    ) -> bool:
        """Verify the delegation chain.

        Dispatches to :func:`aggregate_verify_chain` when the chain is
        aggregated and has at least one delegation step, otherwise falls back
        to :func:`~qasp.protocol.capability.verify_delegation_chain`.

        Args:
            root_issuer_pk: The root issuer's ML-DSA-65 public key.
            did_resolver: Optional DID resolver for signature verification.
            check_expiry: Whether to enforce time-based constraints.

        Returns:
            True if the chain is valid.
        """
        if self.is_aggregated and self.depth > 0:
            return aggregate_verify_chain(
                list(self.tokens),
                root_issuer_pk,
                did_resolver,
                check_expiry,
            )
        return verify_delegation_chain(
            list(self.tokens),
            root_issuer_pk,
            did_resolver,
            check_expiry,
        )

    # -- construction --

    @classmethod
    def from_tokens(
        cls,
        tokens: list[CapabilityToken] | tuple[CapabilityToken, ...],
        is_aggregated: bool = False,
    ) -> DelegationChain:
        """Create a :class:`DelegationChain` from a sequence of tokens.

        Args:
            tokens: Ordered tokens (root first).
            is_aggregated: Whether the chain uses aggregate signatures.

        Returns:
            A new :class:`DelegationChain`.

        Raises:
            InvalidDelegationChainError: If the token list is empty.
        """
        token_tuple = tuple(tokens)
        if not token_tuple:
            raise InvalidDelegationChainError("Empty token list")
        return cls(tokens=token_tuple, is_aggregated=is_aggregated)
