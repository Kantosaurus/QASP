"""Shared utilities for QASP demo scenarios.

Provides reusable identity setup, DID registry wiring,
and logging helpers for scenario scripts.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from qasp.crypto.signatures import generate_keypair
from qasp.identity.did import DID, DIDDocument, DIDRegistry, create_did
from qasp.protocol.capability import CapabilityToken, LocalDIDResolver

logger = logging.getLogger("qasp.demo")


@dataclass
class AgentIdentity:
    """Bundle of identity material for a single agent."""

    name: str
    public_key: bytes
    secret_key: bytes
    did: DID
    did_document: DIDDocument


def create_agent(name: str) -> AgentIdentity:
    """Generate ML-DSA-65 keys + DID for a named agent."""
    pk, sk = generate_keypair()
    did, doc = create_did(pk)
    return AgentIdentity(
        name=name,
        public_key=pk,
        secret_key=sk,
        did=did,
        did_document=doc,
    )


def setup_did_registry(*agents: AgentIdentity) -> DIDRegistry:
    """Create a DIDRegistry and register all supplied agents."""
    registry = DIDRegistry()
    for agent in agents:
        registry.register(agent.did_document)
    return registry


def setup_did_resolver(registry: DIDRegistry) -> LocalDIDResolver:
    """Wrap a registry in a LocalDIDResolver."""
    return LocalDIDResolver(registry)


def log_token_summary(label: str, token: CapabilityToken) -> None:
    """Log a one-line token summary."""
    logger.info(
        "[%s] token_id=%s resource=%s verbs=%s depth=%d",
        label,
        token.token_id.hex()[:16],
        token.resource_uri,
        sorted(token.verbs.verbs),
        token.max_delegation_depth,
    )


def log_receipt_summary(label: str, chain_length: int, verified: bool) -> None:
    """Log a receipt-chain verification summary."""
    status = "VALID" if verified else "INVALID"
    logger.info(
        "[%s] receipt chain: %d receipts, status=%s",
        label,
        chain_length,
        status,
    )
