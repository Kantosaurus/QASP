"""A2A (Agent-to-Agent) bridge.

This module implements a bridge between QASP and Google's
A2A protocol.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from qasp.protocol.capability import (
    CapabilityToken,
    verify_token,
)

if TYPE_CHECKING:
    from qasp.identity.did import DID
    from qasp.protocol.connection import QASPConnection

__all__ = [
    "A2ABridge",
    "A2ATaskBackend",
    "A2ATaskState",
    "AgentCapabilities",
    "AgentCard",
    "AgentSkill",
    "DelegationRecord",
    "QASP_EXTENSION_URI",
    "QASP_TOKEN_METADATA_KEY",
    "QASPAgentCard",
    "QASPExtension",
    "SkillCapabilityMapping",
    "TaskSessionMapping",
    "TaskState",
    "check_connection_for_task",
    "create_delegation_token",
    "create_qasp_agent_extension",
    "extract_qasp_extension",
    "map_capability_to_skill",
    "map_skill_to_capability",
]

# Constants used by bridges/__init__.py
QASP_EXTENSION_URI = "urn:qasp:a2a:extension:1.0"
QASP_TOKEN_METADATA_KEY = "qasp_token"

@dataclass
class AgentSkill:
    """An A2A agent skill descriptor."""
    name: str
    description: str = ""


@dataclass
class AgentCapabilities:
    """Agent capability descriptors."""
    skills: list[AgentSkill] = field(default_factory=list)


@dataclass
class QASPExtension:
    """QASP extension data embedded in an A2A agent card."""
    did: str = ""
    sig_public_key: str = ""
    capabilities: list[str] = field(default_factory=list)
    qasp_version: str = "1.0"


@dataclass
class AgentCard:
    """Generic A2A agent card."""
    name: str = ""
    description: str = ""
    skills: list[AgentSkill] = field(default_factory=list)
    qasp: QASPExtension | None = None


@dataclass
class DelegationRecord:
    """Record of a token delegation."""
    token_id: str = ""
    delegator_did: str = ""
    delegate_did: str = ""


@dataclass
class SkillCapabilityMapping:
    """Mapping between A2A skills and QASP capabilities."""
    skill_name: str = ""
    resource_uri: str = ""
    verbs: list[str] = field(default_factory=list)


@dataclass
class TaskSessionMapping:
    """Mapping between A2A task ID and QASP session."""
    task_id: str = ""
    session_id: str = ""


def create_qasp_agent_extension(did: str, public_key: bytes, capabilities: list[str] | None = None) -> QASPExtension:
    """Create a QASP extension for an A2A agent card."""
    return QASPExtension(
        did=did,
        sig_public_key=base64.b64encode(public_key).decode(),
        capabilities=capabilities or [],
    )


def extract_qasp_extension(card: dict[str, Any]) -> QASPExtension | None:
    """Extract QASP extension from an agent card dict."""
    qasp_data = card.get("qasp")
    if qasp_data is None:
        return None
    return QASPExtension(**qasp_data)


def map_skill_to_capability(skill: AgentSkill, resource_prefix: str = "qasp://a2a") -> SkillCapabilityMapping:
    """Map an A2A skill to a QASP capability."""
    return SkillCapabilityMapping(
        skill_name=skill.name,
        resource_uri=f"{resource_prefix}/{skill.name}",
        verbs=["execute"],
    )


def map_capability_to_skill(mapping: SkillCapabilityMapping) -> AgentSkill:
    """Map a QASP capability back to an A2A skill."""
    return AgentSkill(name=mapping.skill_name)


def create_delegation_token(*args: Any, **kwargs: Any) -> Any:
    """Create a delegation token for cross-protocol use. Placeholder."""
    raise NotImplementedError("Use qasp.protocol.capability.attenuate_token")


def check_connection_for_task(*args: Any, **kwargs: Any) -> bool:
    """Check if a QASP connection supports a given task. Placeholder."""
    return True


class A2ATaskState(Enum):
    """A2A task lifecycle states."""

    SUBMITTED = auto()
    WORKING = auto()
    COMPLETED = auto()
    FAILED = auto()


# Alias for bridges/__init__.py compatibility
TaskState = A2ATaskState


@runtime_checkable
class A2ATaskBackend(Protocol):
    """Backend protocol for A2A task execution."""

    def execute_task(self, task: dict[str, Any]) -> dict[str, Any]:
        """Execute a task and return the result."""
        ...


class A2ABridge:
    """Bridge between QASP and A2A protocols.

    Allows QASP agents to interact with A2A-compatible agents.
    """

    def __init__(
        self,
        backend: A2ATaskBackend | None = None,
        qasp_connection: QASPConnection | None = None,
    ) -> None:
        """Initialize the A2A bridge.

        Args:
            backend: Optional task execution backend.
            qasp_connection: Optional QASP connection.
        """
        self._backend = backend
        self._connection = qasp_connection
        self._tasks: dict[str, dict[str, Any]] = {}
        self._agent_cards: dict[str, dict[str, Any]] = {}

    def register_agent_card(self, endpoint: str, card: dict[str, Any]) -> None:
        """Register an agent card for testing/discovery.

        Args:
            endpoint: The agent endpoint URL.
            card: The agent card data.
        """
        self._agent_cards[endpoint] = card

    def get_agent_card(self, endpoint: str) -> dict[str, Any]:
        """Get an A2A agent card.

        Args:
            endpoint: The agent endpoint URL.

        Returns:
            The agent card data.

        Raises:
            KeyError: If the endpoint is not registered.
        """
        if endpoint not in self._agent_cards:
            raise KeyError(f"No agent card registered for endpoint: {endpoint}")
        return self._agent_cards[endpoint]

    def send_task(
        self,
        endpoint: str,
        task: dict[str, Any],
    ) -> str:
        """Send a task to an A2A agent.

        Args:
            endpoint: The agent endpoint.
            task: The task definition.

        Returns:
            The task ID.
        """
        task_id = os.urandom(16).hex()

        self._tasks[task_id] = {
            "id": task_id,
            "endpoint": endpoint,
            "task": task,
            "state": A2ATaskState.SUBMITTED,
            "result": None,
        }

        if self._backend is not None:
            self._tasks[task_id]["state"] = A2ATaskState.WORKING
            try:
                result = self._backend.execute_task(task)
                self._tasks[task_id]["state"] = A2ATaskState.COMPLETED
                self._tasks[task_id]["result"] = result
            except Exception as e:
                self._tasks[task_id]["state"] = A2ATaskState.FAILED
                self._tasks[task_id]["result"] = {"error": str(e)}

        return task_id

    def get_task_status(
        self,
        endpoint: str,
        task_id: str,
    ) -> dict[str, Any]:
        """Get the status of an A2A task.

        Args:
            endpoint: The agent endpoint.
            task_id: The task ID.

        Returns:
            Dict with 'state' and 'result' keys.

        Raises:
            KeyError: If the task ID is not found.
        """
        if task_id not in self._tasks:
            raise KeyError(f"Task not found: {task_id}")
        entry = self._tasks[task_id]
        return {
            "state": entry["state"],
            "result": entry["result"],
        }


class QASPAgentCard:
    """Generate an A2A-compatible agent card for a QASP agent.

    Allows A2A clients to discover and interact with QASP agents.
    """

    def __init__(
        self,
        name: str,
        description: str,
        did: DID,
        public_key: bytes,
        capabilities: list[str] | None = None,
        skills: list[str] | None = None,
        handler: Any = None,
    ) -> None:
        """Initialize the agent card.

        Args:
            name: The agent name.
            description: Agent description.
            did: The agent's DID.
            public_key: The agent's public key.
            capabilities: Optional list of capability strings.
            skills: Optional list of skill strings.
            handler: Optional task handler callable.
        """
        self._name = name
        self._description = description
        self._did = did
        self._public_key = public_key
        self._capabilities = capabilities or []
        self._skills = skills or []
        self._handler = handler

    @property
    def name(self) -> str:
        return self._name

    @property
    def did(self) -> DID:
        return self._did

    def to_dict(self) -> dict[str, Any]:
        """Generate the agent card as a dictionary.

        Returns:
            A2A-compatible agent card with qasp extension.
        """
        return {
            "name": self._name,
            "description": self._description,
            "skills": self._skills,
            "qasp": {
                "did": str(self._did),
                "sig_public_key": base64.b64encode(self._public_key).decode(),
                "capabilities": self._capabilities,
                "qasp_version": "1.0",
            },
        }

    def handle_task(
        self,
        task: dict[str, Any],
        issuer_public_key: bytes,
    ) -> dict[str, Any]:
        """Handle an incoming A2A task with QASP token verification.

        Args:
            task: The task definition (may contain qasp_token in metadata).
            issuer_public_key: Public key for verifying the QASP token.

        Returns:
            The task result.

        Raises:
            CapabilityError: If token verification fails.
        """
        meta = task.get("metadata", {})
        token_b64 = meta.get("qasp_token")
        if token_b64 is not None:
            token_cbor = base64.b64decode(token_b64)
            token = CapabilityToken.from_cbor(token_cbor)
            verify_token(token, issuer_public_key)

        if self._handler is not None:
            return self._handler(task)
        return {"status": "completed", "message": f"Task handled by {self._name}"}
