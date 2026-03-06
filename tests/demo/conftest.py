"""Shared fixtures for demo scenario tests."""

from __future__ import annotations

import pytest

from examples.demo_common import AgentIdentity, create_agent, setup_did_registry, setup_did_resolver
from qasp.identity.did import DIDRegistry
from qasp.protocol.capability import LocalDIDResolver


@pytest.fixture(scope="module")
def alice() -> AgentIdentity:
    return create_agent("Alice")


@pytest.fixture(scope="module")
def alpha() -> AgentIdentity:
    return create_agent("Alpha")


@pytest.fixture(scope="module")
def beta() -> AgentIdentity:
    return create_agent("Beta")


@pytest.fixture(scope="module")
def gamma() -> AgentIdentity:
    return create_agent("Gamma")


@pytest.fixture(scope="module")
def did_registry(alice: AgentIdentity, alpha: AgentIdentity, beta: AgentIdentity, gamma: AgentIdentity) -> DIDRegistry:
    return setup_did_registry(alice, alpha, beta, gamma)


@pytest.fixture(scope="module")
def did_resolver(did_registry: DIDRegistry) -> LocalDIDResolver:
    return setup_did_resolver(did_registry)
