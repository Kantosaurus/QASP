"""Relay-specific wrapper around capability.attenuate_token (PRD §4.3)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from qasp.identity.did import DID
from qasp.protocol.capability import (
    ARM_READ,
    ARM_RELAY,
    ARM_WRITE,
    CapabilityToken,
    Constraints,
    VerbSet,
    attenuate_token,
)

__all__ = ["attenuate_for_target"]


def attenuate_for_target(
    *,
    source_token: CapabilityToken,
    relay_secret_key: bytes,
    target_did: DID,
    session_id: bytes,
    max_duration_sec: int | None = None,
) -> CapabilityToken:
    """Derive an attenuated relay token for a forwarding target (PRD §4.3).

    Given a capability token issued by Alice to the relay (with ARM_RELAY
    authority), produce a child token addressed to `target_did` that:
      - restricts verbs to {ARM_READ, ARM_WRITE} (strips ARM_DELEGATE, ARM_EXEC,
        ARM_RELAY — Bob cannot re-relay Alice's grant),
      - tightens constraints to an optional `max_duration_sec` horizon,
      - is signed by the relay (the new child's issuer is the relay).

    Resource URI narrowing to qasp://{relay}/relay/session/{id} is deferred
    until ARM URI grammar supports DID-shaped providers; the PoC inherits the
    parent's resource URI.

    Raises:
        ValueError: if `source_token` lacks the ARM_RELAY verb.
    """
    if ARM_RELAY not in source_token.verbs:
        raise ValueError(
            "source token lacks ARM_RELAY — cannot be used for relay forwarding"
        )

    target_verbs = VerbSet({ARM_READ, ARM_WRITE})
    tightened: Constraints | None = None
    if max_duration_sec is not None:
        tightened = Constraints(
            not_after=datetime.now(UTC) + timedelta(seconds=max_duration_sec),
        )

    return attenuate_token(
        parent_token=source_token,
        delegator_secret_key=relay_secret_key,
        new_subject_did=target_did,
        reduced_verbs=target_verbs,
        tightened_constraints=tightened,
    )
