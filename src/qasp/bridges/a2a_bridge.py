"""A2A (Agent-to-Agent) bridge.

Bidirectional bridge between QASP and Google's A2A protocol:
- AgentCard / QASPExtension: QASP-aware agent discovery
- A2ABridge: Task dispatch with QASP capability tokens
- QASPAgentCard: Expose QASP agents as A2A-compatible cards
"""

from __future__ import annotations

import base64
import os
import time
from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING, Any

from qasp.protocol.capability import (
    CapabilityToken,
    Constraints,
    VerbSet,
    attenuate_token,
    create_token,
    verify_token,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from qasp.identity.did import DID
    from qasp.protocol.connection import QASPConnection

__all__ = [
    "A2ABridge",
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

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

QASP_EXTENSION_URI = "urn:qasp:a2a-extension:v1"
QASP_TOKEN_METADATA_KEY = "qasp_token"


# ---------------------------------------------------------------------------
# TaskState
# ---------------------------------------------------------------------------


class TaskState(IntEnum):
    SUBMITTED = 0
    WORKING = 1
    COMPLETED = 3
    CANCELED = 4
    FAILED = 5
    AUTH_REQUIRED = 6
    UNKNOWN = 7


A2ATaskState = TaskState


# ---------------------------------------------------------------------------
# Frozen Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AgentSkill:
    id: str
    name: str
    description: str
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class QASPExtension:
    agent_did: str
    qasp_endpoint: str
    supported_cipher_suites: tuple[str, ...] = ()
    protocol_version: str = "1.0"

    def to_extension_dict(self) -> dict[str, Any]:
        return {
            "uri": QASP_EXTENSION_URI,
            "params": {
                "agent_did": self.agent_did,
                "qasp_endpoint": self.qasp_endpoint,
                "supported_cipher_suites": list(self.supported_cipher_suites),
                "protocol_version": self.protocol_version,
            },
        }

    @classmethod
    def from_extension_dict(cls, params: dict[str, Any]) -> QASPExtension:
        return cls(
            agent_did=params["agent_did"],
            qasp_endpoint=params["qasp_endpoint"],
            supported_cipher_suites=tuple(params.get("supported_cipher_suites", ())),
            protocol_version=params.get("protocol_version", "1.0"),
        )


@dataclass(frozen=True)
class AgentCapabilities:
    extensions: tuple[dict[str, Any], ...] = ()


@dataclass(frozen=True)
class AgentCard:
    name: str
    description: str
    url: str
    skills: tuple[AgentSkill, ...] = ()
    capabilities: AgentCapabilities | None = None


@dataclass(frozen=True)
class SkillCapabilityMapping:
    skill_id: str
    resource_uri: str
    verbs: VerbSet


@dataclass(frozen=True)
class TaskSessionMapping:
    task_id: str
    session_id: bytes
    capability_token_id: bytes
    state: TaskState
    created_at: float


@dataclass(frozen=True)
class DelegationRecord:
    parent_task_id: str
    child_task_id: str
    parent_token_id: bytes
    attenuated_token_id: bytes
    delegate_did: str


# ---------------------------------------------------------------------------
# Tag <-> Verb mapping tables
# ---------------------------------------------------------------------------

_TAG_TO_VERB: dict[str, str] = {
    "read": "read",
    "query": "read",
    "search": "read",
    "get": "read",
    "fetch": "read",
    "list": "read",
    "write": "write",
    "create": "write",
    "update": "write",
    "set": "write",
    "delete": "delete",
    "remove": "delete",
    "execute": "execute",
    "run": "execute",
    "invoke": "execute",
    "call": "execute",
}

_VERB_TO_TAGS: dict[str, tuple[str, ...]] = {
    "read": ("read",),
    "write": ("write",),
    "delete": ("delete",),
    "execute": ("execute",),
}


# ---------------------------------------------------------------------------
# Mapping Functions
# ---------------------------------------------------------------------------


def map_skill_to_capability(
    skill: AgentSkill, agent_did_str: str,
) -> SkillCapabilityMapping:
    """Map an A2A skill to a QASP capability."""
    # Extract DID identifier (the part after "did:qasp:")
    did_identifier = agent_did_str
    if did_identifier.startswith("did:qasp:"):
        did_identifier = did_identifier[len("did:qasp:"):]

    verbs: set[str] = set()
    for tag in skill.tags:
        verb = _TAG_TO_VERB.get(tag)
        if verb is not None:
            verbs.add(verb)
    if not verbs:
        verbs = {"execute"}

    resource_uri = f"qasp://a2a/{did_identifier}/skills/{skill.id}"

    return SkillCapabilityMapping(
        skill_id=skill.id,
        resource_uri=resource_uri,
        verbs=VerbSet(verbs),
    )


def map_capability_to_skill(token: CapabilityToken) -> AgentSkill:
    """Extract an AgentSkill from a capability token."""
    # Skill ID is the last segment of the resource URI
    skill_id = token.resource_uri.rsplit("/", 1)[-1]

    tags: list[str] = []
    for verb in sorted(token.verbs):
        verb_tags = _VERB_TO_TAGS.get(verb)
        if verb_tags is not None:
            tags.extend(verb_tags)

    return AgentSkill(
        id=skill_id,
        name=skill_id,
        description="",
        tags=tuple(tags),
    )


def extract_qasp_extension(card: AgentCard) -> QASPExtension | None:
    """Extract QASPExtension from an AgentCard's capabilities."""
    if card.capabilities is None:
        return None
    for ext_dict in card.capabilities.extensions:
        if ext_dict.get("uri") == QASP_EXTENSION_URI:
            return QASPExtension.from_extension_dict(ext_dict["params"])
    return None


def create_qasp_agent_extension(ext: QASPExtension) -> dict[str, Any]:
    """Serialize a QASPExtension to an extension dict."""
    return ext.to_extension_dict()


def create_delegation_token(
    parent_token: CapabilityToken,
    delegator_secret_key: bytes,
    delegate_did: DID,
    skill: AgentSkill,
    time_limit_seconds: float | None = None,
) -> CapabilityToken:
    """Create an attenuated delegation token for a skill."""
    from datetime import UTC, datetime, timedelta

    # Map skill tags to verbs and intersect with parent
    skill_verbs: set[str] = set()
    for tag in skill.tags:
        verb = _TAG_TO_VERB.get(tag)
        if verb is not None:
            skill_verbs.add(verb)
    if not skill_verbs:
        skill_verbs = {"execute"}

    # Intersect with parent token verbs
    parent_verb_set = set(parent_token.verbs.verbs)
    reduced = skill_verbs & parent_verb_set

    # Build tighter constraints if time_limit_seconds is specified
    tightened: Constraints | None = None
    if time_limit_seconds is not None:
        new_expiry = datetime.now(UTC) + timedelta(seconds=time_limit_seconds)
        # Don't exceed parent expiry
        if parent_token.constraints.not_after is not None:
            new_expiry = min(new_expiry, parent_token.constraints.not_after)
        tightened = Constraints(not_after=new_expiry)

    return attenuate_token(
        parent_token=parent_token,
        delegator_secret_key=delegator_secret_key,
        new_subject_did=delegate_did,
        reduced_verbs=VerbSet(reduced) if reduced != parent_verb_set else None,
        tightened_constraints=tightened,
    )


def check_connection_for_task(connection: Any, task_state: TaskState) -> bool:
    """Check whether a QASP connection supports a given task state."""
    from qasp.protocol.states import ConnectionState

    conn_state = connection.state

    if task_state in (TaskState.SUBMITTED, TaskState.WORKING):
        return conn_state == ConnectionState.ESTABLISHED
    if task_state == TaskState.AUTH_REQUIRED:
        return conn_state == ConnectionState.IDLE
    # COMPLETED, CANCELED, FAILED, UNKNOWN — allow any state
    return True


# ---------------------------------------------------------------------------
# A2ABridge
# ---------------------------------------------------------------------------


class A2ABridge:
    """Bridge between QASP and A2A protocols."""

    def __init__(
        self,
        qasp_connection: QASPConnection | None = None,
        agent_did: DID | None = None,
        secret_key: bytes | None = None,
        backend: Any = None,
    ) -> None:
        self._connection = qasp_connection
        self._agent_did = agent_did
        self._secret_key = secret_key
        self._backend = backend

        # Old-style storage (sync mode)
        self._tasks: dict[str, dict[str, Any]] = {}
        self._agent_cards: dict[str, dict[str, Any]] = {}

        # New-style storage (async mode)
        self._card_cache: dict[str, AgentCard] = {}
        self._task_sessions: dict[str, TaskSessionMapping] = {}
        self._delegation_records: dict[str, DelegationRecord] = {}
        self._task_tokens: dict[str, CapabilityToken] = {}

    # ------------------------------------------------------------------
    # Old-style sync methods (backward compat for integration tests)
    # ------------------------------------------------------------------

    def register_agent_card(self, endpoint: str, card: dict[str, Any]) -> None:
        self._agent_cards[endpoint] = card

    def get_agent_card(self, endpoint: str) -> dict[str, Any]:
        if endpoint not in self._agent_cards:
            raise KeyError(f"No agent card registered for endpoint: {endpoint}")
        return self._agent_cards[endpoint]

    def _send_task_sync(
        self, endpoint: str, task: dict[str, Any],
    ) -> str:
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

    def _get_task_status_sync(
        self, endpoint: str, task_id: str,
    ) -> dict[str, Any]:
        if task_id not in self._tasks:
            raise KeyError(f"Task not found: {task_id}")
        entry = self._tasks[task_id]
        return {"state": entry["state"], "result": entry["result"]}

    # ------------------------------------------------------------------
    # New-style async methods
    # ------------------------------------------------------------------

    async def _send_task_async(
        self,
        endpoint: str,
        task_message: dict[str, Any],
        skill_id: str | None = None,
        parent_task_id: str | None = None,
    ) -> str:
        if self._connection is not None and not self._connection.is_established:
            raise ConnectionError("QASP connection not established")

        task_id = os.urandom(16).hex()

        # Determine parent token
        parent_token: CapabilityToken | None = None
        if parent_task_id is not None and parent_task_id in self._task_tokens:
            parent_token = self._task_tokens[parent_task_id]

        # Create or attenuate capability token
        token: CapabilityToken | None = None
        if parent_token is not None and self._secret_key is not None:
            # Look up skill from card cache
            card = self._card_cache.get(endpoint)
            skill: AgentSkill | None = None
            if card is not None and skill_id is not None:
                for s in card.skills:
                    if s.id == skill_id:
                        skill = s
                        break
            if skill is None:
                skill = AgentSkill(
                    id=skill_id or "default",
                    name=skill_id or "default",
                    description="",
                    tags=("execute",),
                )

            target_did = self._agent_did
            if target_did is not None:
                token = create_delegation_token(
                    parent_token=parent_token,
                    delegator_secret_key=self._secret_key,
                    delegate_did=target_did,
                    skill=skill,
                )
        elif self._agent_did is not None and self._secret_key is not None and skill_id is not None:
            # Create a fresh token for a root task
            card = self._card_cache.get(endpoint)
            skill_obj: AgentSkill | None = None
            if card is not None:
                for s in card.skills:
                    if s.id == skill_id:
                        skill_obj = s
                        break
            if skill_obj is None:
                skill_obj = AgentSkill(
                    id=skill_id, name=skill_id, description="", tags=("execute",),
                )

            mapping = map_skill_to_capability(skill_obj, str(self._agent_did))
            token = create_token(
                issuer_did=self._agent_did,
                issuer_secret_key=self._secret_key,
                subject_did=self._agent_did,
                resource_uri=mapping.resource_uri,
                verbs=mapping.verbs,
                max_delegation_depth=3,
            )

        # Store token for potential future delegation
        if token is not None:
            self._task_tokens[task_id] = token

        # Build session mapping
        session_id = b""
        if self._connection is not None:
            session_id = self._connection.session_id or b""

        token_id = token.token_id if token is not None else b""

        self._task_sessions[task_id] = TaskSessionMapping(
            task_id=task_id,
            session_id=session_id,
            capability_token_id=token_id,
            state=TaskState.SUBMITTED,
            created_at=time.time(),
        )

        # Track delegation
        if parent_task_id is not None:
            parent_token_id = b""
            if parent_task_id in self._task_tokens:
                parent_token_id = self._task_tokens[parent_task_id].token_id

            self._delegation_records[task_id] = DelegationRecord(
                parent_task_id=parent_task_id,
                child_task_id=task_id,
                parent_token_id=parent_token_id,
                attenuated_token_id=token_id,
                delegate_did=str(self._agent_did) if self._agent_did else "",
            )

        # Send via connection
        if self._connection is not None:
            self._connection.send_data(task_message)

        return task_id

    async def _get_task_status_async(
        self, endpoint: str, task_id: str,
    ) -> TaskState:
        if task_id not in self._task_sessions:
            return TaskState.UNKNOWN
        return self._task_sessions[task_id].state

    async def _cancel_task_async(self, task_id: str) -> None:
        if task_id not in self._task_sessions:
            raise KeyError(f"Unknown task: {task_id}")
        old = self._task_sessions[task_id]
        self._task_sessions[task_id] = TaskSessionMapping(
            task_id=old.task_id,
            session_id=old.session_id,
            capability_token_id=old.capability_token_id,
            state=TaskState.CANCELED,
            created_at=old.created_at,
        )

    # ------------------------------------------------------------------
    # Dispatch methods — detect mode and delegate
    # ------------------------------------------------------------------

    def send_task(
        self,
        endpoint: str,
        task: dict[str, Any] | None = None,
        *,
        task_message: dict[str, Any] | None = None,
        skill_id: str | None = None,
        parent_task_id: str | None = None,
    ) -> Any:
        """Send a task. Sync when using backend, async otherwise."""
        if self._connection is not None or task_message is not None:
            msg = task_message if task_message is not None else (task or {})
            return self._send_task_async(endpoint, msg, skill_id, parent_task_id)
        return self._send_task_sync(endpoint, task or {})

    def get_task_status(self, endpoint: str, task_id: str) -> Any:
        if self._connection is not None or task_id in self._task_sessions:
            return self._get_task_status_async(endpoint, task_id)
        return self._get_task_status_sync(endpoint, task_id)

    def cancel_task(self, task_id: str) -> Any:
        return self._cancel_task_async(task_id)

    def get_delegation_chain(self, task_id: str) -> list[DelegationRecord]:
        chain: list[DelegationRecord] = []
        current = task_id
        while current in self._delegation_records:
            record = self._delegation_records[current]
            chain.append(record)
            current = record.parent_task_id
        return chain


# ---------------------------------------------------------------------------
# QASPAgentCard
# ---------------------------------------------------------------------------


class QASPAgentCard:
    """Generate an A2A-compatible agent card for a QASP agent.

    Supports both old-style (did/public_key) and new-style
    (qasp_connection/agent_did/secret_key) construction.
    """

    def __init__(
        self,
        name: str = "",
        description: str = "",
        # Old-style params
        did: DID | None = None,
        public_key: bytes | None = None,
        capabilities: list[str] | None = None,
        skills: list[str] | None = None,
        handler: Any = None,
        # New-style params
        qasp_connection: QASPConnection | None = None,
        agent_did: DID | None = None,
        url: str = "",
        secret_key: bytes | None = None,
        capability_tokens: list[CapabilityToken] | None = None,
    ) -> None:
        self._name = name
        self._description = description
        self._url = url
        self._handler: Callable[..., Awaitable[Any]] | None = None

        # Detect mode
        if qasp_connection is not None or agent_did is not None:
            # New-style
            self._mode = "new"
            self._connection = qasp_connection
            self._agent_did = agent_did
            self._secret_key = secret_key
            self._capability_tokens = capability_tokens or []
            self._did = agent_did
            self._public_key = None
            self._old_capabilities: list[str] = []
            self._old_skills: list[str] = []
            self._old_handler = None
        else:
            # Old-style
            self._mode = "old"
            self._did = did
            self._public_key = public_key
            self._old_capabilities = capabilities or []
            self._old_skills = skills or []
            self._old_handler = handler
            self._connection = None
            self._agent_did = None
            self._secret_key = None
            self._capability_tokens = []

    @property
    def name(self) -> str:
        return self._name

    @property
    def did(self) -> DID | None:
        return self._did

    def register_handler(
        self, handler: Callable[..., Awaitable[Any]],
    ) -> None:
        self._handler = handler

    def to_dict(self) -> dict[str, Any]:
        if self._mode == "old":
            return self._to_dict_old()
        return self._to_dict_new()

    def _to_dict_old(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "name": self._name,
            "description": self._description,
            "skills": self._old_skills,
            "qasp": {
                "did": str(self._did) if self._did else "",
                "sig_public_key": (
                    base64.b64encode(self._public_key).decode()
                    if self._public_key
                    else ""
                ),
                "capabilities": self._old_capabilities,
                "qasp_version": "1.0",
            },
        }
        return result

    def _to_dict_new(self) -> dict[str, Any]:
        # Build skills from capability tokens
        skill_dicts: list[dict[str, Any]] = []
        for token in self._capability_tokens:
            skill = map_capability_to_skill(token)
            skill_dicts.append({
                "id": skill.id,
                "name": skill.name,
                "description": skill.description,
                "tags": list(skill.tags),
            })

        # Build QASP extension
        ext = QASPExtension(
            agent_did=str(self._agent_did) if self._agent_did else "",
            qasp_endpoint=self._url,
        )

        return {
            "name": self._name,
            "description": self._description,
            "url": self._url,
            "skills": skill_dicts,
            "capabilities": {
                "extensions": [ext.to_extension_dict()],
            },
        }

    def to_agent_card(self) -> AgentCard:
        d = self.to_dict()
        skills: list[AgentSkill] = []
        for s in d.get("skills", []):
            if isinstance(s, dict):
                skills.append(AgentSkill(
                    id=s.get("id", s.get("name", "")),
                    name=s.get("name", ""),
                    description=s.get("description", ""),
                    tags=tuple(s.get("tags", ())),
                ))
            elif isinstance(s, str):
                skills.append(AgentSkill(id=s, name=s, description=""))

        caps = None
        if "capabilities" in d and isinstance(d["capabilities"], dict):
            exts = d["capabilities"].get("extensions", ())
            caps = AgentCapabilities(extensions=tuple(exts))

        return AgentCard(
            name=d.get("name", ""),
            description=d.get("description", ""),
            url=d.get("url", self._url),
            skills=tuple(skills),
            capabilities=caps,
        )

    def handle_task(
        self,
        task: dict[str, Any],
        issuer_public_key: bytes | None = None,
    ) -> Any:
        """Handle a task. Sync in old mode, returns coroutine in new mode."""
        if self._mode == "old":
            return self._handle_task_old(task, issuer_public_key)
        return self._handle_task_new(task)

    def _handle_task_old(
        self,
        task: dict[str, Any],
        issuer_public_key: bytes | None = None,
    ) -> dict[str, Any]:
        meta = task.get("metadata", {})
        token_b64 = meta.get("qasp_token")
        if token_b64 is not None and issuer_public_key is not None:
            token_cbor = base64.b64decode(token_b64)
            token = CapabilityToken.from_cbor(token_cbor)
            verify_token(token, issuer_public_key)

        if self._old_handler is not None:
            return self._old_handler(task)
        return {"status": "completed", "message": f"Task handled by {self._name}"}

    async def _handle_task_new(
        self, task: dict[str, Any],
    ) -> dict[str, Any]:
        if self._handler is None:
            raise RuntimeError("No task handler registered")

        task_id = task.get("task_id", os.urandom(16).hex())

        # Extract token if present
        token: CapabilityToken | None = None
        meta = task.get("metadata", {})
        token_b64 = meta.get("qasp_token")
        if token_b64 is not None:
            token_cbor = base64.b64decode(token_b64)
            token = CapabilityToken.from_cbor(token_cbor)

        artifacts = await self._handler(task, token)

        return {
            "task_id": task_id,
            "state": TaskState.COMPLETED,
            "artifacts": artifacts,
        }
