"""Comprehensive tests for the A2A bridge module."""

from __future__ import annotations

from unittest.mock import MagicMock, PropertyMock

import pytest

from qasp.bridges.a2a_bridge import (
    QASP_EXTENSION_URI,
    A2ABridge,
    AgentCapabilities,
    AgentCard,
    AgentSkill,
    DelegationRecord,
    QASPAgentCard,
    QASPExtension,
    SkillCapabilityMapping,
    TaskSessionMapping,
    TaskState,
    check_connection_for_task,
    create_delegation_token,
    create_qasp_agent_extension,
    extract_qasp_extension,
    map_capability_to_skill,
    map_skill_to_capability,
)
from qasp.identity.did import DID
from qasp.protocol.capability import (
    CapabilityToken,
    DelegationDepthExceeded,
    VerbSet,
    create_token,
)
from qasp.protocol.states import ConnectionState

# =============================================================================
# TestQASPExtension (Step 2)
# =============================================================================


class TestQASPExtension:
    def test_roundtrip_to_from_extension_dict(
        self, sample_qasp_extension: QASPExtension,
    ) -> None:
        ext_dict = sample_qasp_extension.to_extension_dict()
        restored = QASPExtension.from_extension_dict(ext_dict["params"])
        assert restored.agent_did == sample_qasp_extension.agent_did
        assert restored.qasp_endpoint == sample_qasp_extension.qasp_endpoint
        assert restored.supported_cipher_suites == sample_qasp_extension.supported_cipher_suites
        assert restored.protocol_version == sample_qasp_extension.protocol_version

    def test_extension_uri_constant(self) -> None:
        assert QASP_EXTENSION_URI == "urn:qasp:a2a-extension:v1"

    def test_to_extension_dict_has_uri(
        self, sample_qasp_extension: QASPExtension,
    ) -> None:
        ext_dict = sample_qasp_extension.to_extension_dict()
        assert ext_dict["uri"] == QASP_EXTENSION_URI
        assert "params" in ext_dict


# =============================================================================
# TestSkillCapabilityMapping (Step 4)
# =============================================================================


class TestSkillCapabilityMapping:
    def test_read_tags_map_to_read_verb(self, agent_did: DID) -> None:
        for tag in ("read", "query", "search", "get", "fetch", "list"):
            skill = AgentSkill(id="s1", name="s1", description="", tags=(tag,))
            mapping = map_skill_to_capability(skill, str(agent_did))
            assert "read" in mapping.verbs

    def test_execute_tags_map_to_execute_verb(self, agent_did: DID) -> None:
        for tag in ("execute", "run", "invoke", "call"):
            skill = AgentSkill(id="s1", name="s1", description="", tags=(tag,))
            mapping = map_skill_to_capability(skill, str(agent_did))
            assert "execute" in mapping.verbs

    def test_multiple_tags_map_to_multiple_verbs(self, agent_did: DID) -> None:
        skill = AgentSkill(
            id="multi", name="multi", description="",
            tags=("read", "write", "execute"),
        )
        mapping = map_skill_to_capability(skill, str(agent_did))
        assert "read" in mapping.verbs
        assert "write" in mapping.verbs
        assert "execute" in mapping.verbs

    def test_no_tags_default_to_execute(self, agent_did: DID) -> None:
        skill = AgentSkill(id="s1", name="s1", description="", tags=())
        mapping = map_skill_to_capability(skill, str(agent_did))
        assert "execute" in mapping.verbs

    def test_resource_uri_format(self, agent_did: DID) -> None:
        skill = AgentSkill(id="myskill", name="myskill", description="", tags=("read",))
        mapping = map_skill_to_capability(skill, str(agent_did))
        assert mapping.resource_uri == f"qasp://a2a/{agent_did.identifier}/skills/myskill"

    def test_write_tags_map_to_write_verb(self, agent_did: DID) -> None:
        for tag in ("write", "create", "update", "set"):
            skill = AgentSkill(id="s1", name="s1", description="", tags=(tag,))
            mapping = map_skill_to_capability(skill, str(agent_did))
            assert "write" in mapping.verbs

    def test_delete_tags_map_to_delete_verb(self, agent_did: DID) -> None:
        for tag in ("delete", "remove"):
            skill = AgentSkill(id="s1", name="s1", description="", tags=(tag,))
            mapping = map_skill_to_capability(skill, str(agent_did))
            assert "delete" in mapping.verbs


# =============================================================================
# TestCapabilityToSkillMapping (Reverse)
# =============================================================================


class TestCapabilityToSkillMapping:
    def test_token_to_skill_roundtrip(
        self, sample_capability_token: CapabilityToken,
    ) -> None:
        skill = map_capability_to_skill(sample_capability_token)
        assert skill.id == "summarize"
        assert isinstance(skill.tags, tuple)
        assert len(skill.tags) > 0

    def test_verbs_to_tags_mapping(
        self, sample_capability_token: CapabilityToken,
    ) -> None:
        skill = map_capability_to_skill(sample_capability_token)
        # Token has {"read", "execute"} verbs -> should map to tags
        assert "execute" in skill.tags or "read" in skill.tags


# =============================================================================
# TestExtractQASPExtension (Step 5)
# =============================================================================


class TestExtractQASPExtension:
    def test_extracts_from_card_with_extension(
        self, sample_agent_card: AgentCard, sample_qasp_extension: QASPExtension,
    ) -> None:
        ext = extract_qasp_extension(sample_agent_card)
        assert ext is not None
        assert ext.agent_did == sample_qasp_extension.agent_did

    def test_returns_none_without_extension(self) -> None:
        card = AgentCard(
            name="NoExt",
            description="No extensions",
            url="https://example.com",
            skills=(),
        )
        assert extract_qasp_extension(card) is None

    def test_ignores_non_qasp_extensions(self) -> None:
        caps = AgentCapabilities(
            extensions=({"uri": "urn:other:ext:v1", "params": {}},),
        )
        card = AgentCard(
            name="Other",
            description="Non-QASP",
            url="https://example.com",
            skills=(),
            capabilities=caps,
        )
        assert extract_qasp_extension(card) is None

    def test_create_qasp_agent_extension(
        self, sample_qasp_extension: QASPExtension,
    ) -> None:
        ext_dict = create_qasp_agent_extension(sample_qasp_extension)
        assert ext_dict["uri"] == QASP_EXTENSION_URI


# =============================================================================
# TestTaskStateMapping (Step 6)
# =============================================================================


class TestTaskStateMapping:
    def test_submitted_requires_established(self, mock_connection: MagicMock) -> None:
        assert check_connection_for_task(mock_connection, TaskState.SUBMITTED) is True

    def test_auth_required_maps_to_idle(self, mock_connection: MagicMock) -> None:
        type(mock_connection).state = PropertyMock(return_value=ConnectionState.IDLE)
        assert check_connection_for_task(mock_connection, TaskState.AUTH_REQUIRED) is True

    def test_auth_required_fails_when_established(
        self, mock_connection: MagicMock,
    ) -> None:
        assert check_connection_for_task(mock_connection, TaskState.AUTH_REQUIRED) is False

    def test_completed_allows_any_state(self, mock_connection: MagicMock) -> None:
        assert check_connection_for_task(mock_connection, TaskState.COMPLETED) is True

    def test_canceled_allows_any_state(self, mock_connection: MagicMock) -> None:
        assert check_connection_for_task(mock_connection, TaskState.CANCELED) is True

    def test_working_requires_established(self, mock_connection: MagicMock) -> None:
        type(mock_connection).state = PropertyMock(return_value=ConnectionState.IDLE)
        assert check_connection_for_task(mock_connection, TaskState.WORKING) is False


# =============================================================================
# TestQASPAgentCard (Step 8)
# =============================================================================


class TestQASPAgentCard:
    def test_to_dict_valid_structure(
        self,
        mock_connection: MagicMock,
        agent_did: DID,
        agent_secret_key: bytes,
        sample_capability_token: CapabilityToken,
    ) -> None:
        card = QASPAgentCard(
            name="MyAgent",
            description="Test agent",
            qasp_connection=mock_connection,
            agent_did=agent_did,
            url="qasp://localhost:9000",
            secret_key=agent_secret_key,
            capability_tokens=[sample_capability_token],
        )
        d = card.to_dict()
        assert d["name"] == "MyAgent"
        assert d["description"] == "Test agent"
        assert d["url"] == "qasp://localhost:9000"
        assert "skills" in d
        assert "capabilities" in d

    def test_to_dict_includes_qasp_extension(
        self,
        mock_connection: MagicMock,
        agent_did: DID,
        agent_secret_key: bytes,
    ) -> None:
        card = QASPAgentCard(
            name="MyAgent",
            description="Test",
            qasp_connection=mock_connection,
            agent_did=agent_did,
            url="qasp://localhost:9000",
            secret_key=agent_secret_key,
        )
        d = card.to_dict()
        extensions = d["capabilities"]["extensions"]
        assert len(extensions) == 1
        assert extensions[0]["uri"] == QASP_EXTENSION_URI

    def test_to_dict_includes_skills_from_capabilities(
        self,
        mock_connection: MagicMock,
        agent_did: DID,
        agent_secret_key: bytes,
        sample_capability_token: CapabilityToken,
    ) -> None:
        card = QASPAgentCard(
            name="MyAgent",
            description="Test",
            qasp_connection=mock_connection,
            agent_did=agent_did,
            url="qasp://localhost:9000",
            secret_key=agent_secret_key,
            capability_tokens=[sample_capability_token],
        )
        d = card.to_dict()
        assert len(d["skills"]) == 1
        assert d["skills"][0]["id"] == "summarize"

    @pytest.mark.asyncio
    async def test_handle_task_with_registered_handler(
        self,
        mock_connection: MagicMock,
        agent_did: DID,
        agent_secret_key: bytes,
    ) -> None:
        card = QASPAgentCard(
            name="MyAgent",
            description="Test",
            qasp_connection=mock_connection,
            agent_did=agent_did,
            url="qasp://localhost:9000",
            secret_key=agent_secret_key,
        )

        async def handler(
            task: dict, token: CapabilityToken | None,  # noqa: ARG001
        ) -> dict:
            return {"result": "done"}

        card.register_handler(handler)
        result = await card.handle_task({"task_id": "t1", "skill_id": "test"})
        assert result["task_id"] == "t1"
        assert result["state"] == TaskState.COMPLETED
        assert result["artifacts"] == {"result": "done"}

    @pytest.mark.asyncio
    async def test_handle_task_without_handler_raises(
        self,
        mock_connection: MagicMock,
        agent_did: DID,
        agent_secret_key: bytes,
    ) -> None:
        card = QASPAgentCard(
            name="MyAgent",
            description="Test",
            qasp_connection=mock_connection,
            agent_did=agent_did,
            url="qasp://localhost:9000",
            secret_key=agent_secret_key,
        )
        with pytest.raises(RuntimeError, match="No task handler registered"):
            await card.handle_task({"task_id": "t1"})

    def test_to_agent_card_returns_agent_card(
        self,
        mock_connection: MagicMock,
        agent_did: DID,
        agent_secret_key: bytes,
    ) -> None:
        card = QASPAgentCard(
            name="MyAgent",
            description="Test",
            qasp_connection=mock_connection,
            agent_did=agent_did,
            url="qasp://localhost:9000",
            secret_key=agent_secret_key,
        )
        agent_card = card.to_agent_card()
        assert isinstance(agent_card, AgentCard)
        assert agent_card.name == "MyAgent"


# =============================================================================
# TestA2ABridge (Step 7)
# =============================================================================


class TestA2ABridge:
    def test_init_stores_connection_and_did(
        self,
        mock_connection: MagicMock,
        agent_did: DID,
        agent_secret_key: bytes,
    ) -> None:
        bridge = A2ABridge(
            qasp_connection=mock_connection,
            agent_did=agent_did,
            secret_key=agent_secret_key,
        )
        assert bridge._connection is mock_connection
        assert bridge._agent_did == agent_did

    @pytest.mark.asyncio
    async def test_send_task_creates_capability_token(
        self,
        mock_connection: MagicMock,
        agent_did: DID,
        agent_secret_key: bytes,
        sample_agent_card: AgentCard,
    ) -> None:
        bridge = A2ABridge(
            qasp_connection=mock_connection,
            agent_did=agent_did,
            secret_key=agent_secret_key,
        )
        # Pre-populate card cache to avoid HTTP fetch
        bridge._card_cache["https://agent.example.com"] = sample_agent_card

        task_id = await bridge.send_task(
            endpoint="https://agent.example.com",
            task_message={"text": "hello"},
            skill_id="summarize",
        )
        assert isinstance(task_id, str)
        assert task_id in bridge._task_sessions
        mapping = bridge._task_sessions[task_id]
        assert mapping.state == TaskState.SUBMITTED
        # Verify send_data was called
        mock_connection.send_data.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_task_with_parent_creates_attenuated_token(
        self,
        mock_connection: MagicMock,
        agent_did: DID,
        agent_secret_key: bytes,
        sample_agent_card: AgentCard,
    ) -> None:
        bridge = A2ABridge(
            qasp_connection=mock_connection,
            agent_did=agent_did,
            secret_key=agent_secret_key,
        )
        bridge._card_cache["https://agent.example.com"] = sample_agent_card

        # Create a parent task first
        parent_id = await bridge.send_task(
            endpoint="https://agent.example.com",
            task_message={"text": "parent"},
            skill_id="summarize",
        )

        # Now create child task referencing the parent
        child_id = await bridge.send_task(
            endpoint="https://agent.example.com",
            task_message={"text": "child"},
            parent_task_id=parent_id,
        )
        assert child_id != parent_id
        assert child_id in bridge._delegation_records
        record = bridge._delegation_records[child_id]
        assert record.parent_task_id == parent_id

    @pytest.mark.asyncio
    async def test_get_task_status_returns_state(
        self,
        mock_connection: MagicMock,
        agent_did: DID,
        agent_secret_key: bytes,
        sample_agent_card: AgentCard,
    ) -> None:
        bridge = A2ABridge(
            qasp_connection=mock_connection,
            agent_did=agent_did,
            secret_key=agent_secret_key,
        )
        bridge._card_cache["https://agent.example.com"] = sample_agent_card

        task_id = await bridge.send_task(
            endpoint="https://agent.example.com",
            task_message={"text": "hello"},
            skill_id="summarize",
        )
        status = await bridge.get_task_status("https://agent.example.com", task_id)
        assert status == TaskState.SUBMITTED

    @pytest.mark.asyncio
    async def test_get_task_status_unknown_task(
        self,
        mock_connection: MagicMock,
        agent_did: DID,
        agent_secret_key: bytes,
    ) -> None:
        bridge = A2ABridge(
            qasp_connection=mock_connection,
            agent_did=agent_did,
            secret_key=agent_secret_key,
        )
        status = await bridge.get_task_status("https://example.com", "nonexistent")
        assert status == TaskState.UNKNOWN

    @pytest.mark.asyncio
    async def test_cancel_task_updates_state(
        self,
        mock_connection: MagicMock,
        agent_did: DID,
        agent_secret_key: bytes,
        sample_agent_card: AgentCard,
    ) -> None:
        bridge = A2ABridge(
            qasp_connection=mock_connection,
            agent_did=agent_did,
            secret_key=agent_secret_key,
        )
        bridge._card_cache["https://agent.example.com"] = sample_agent_card

        task_id = await bridge.send_task(
            endpoint="https://agent.example.com",
            task_message={"text": "hello"},
            skill_id="summarize",
        )
        await bridge.cancel_task(task_id)
        status = await bridge.get_task_status("https://agent.example.com", task_id)
        assert status == TaskState.CANCELED

    @pytest.mark.asyncio
    async def test_cancel_unknown_task_raises(
        self,
        mock_connection: MagicMock,
        agent_did: DID,
        agent_secret_key: bytes,
    ) -> None:
        bridge = A2ABridge(
            qasp_connection=mock_connection,
            agent_did=agent_did,
            secret_key=agent_secret_key,
        )
        with pytest.raises(KeyError, match="Unknown task"):
            await bridge.cancel_task("nonexistent")

    @pytest.mark.asyncio
    async def test_delegation_chain_tracking(
        self,
        mock_connection: MagicMock,
        agent_did: DID,
        agent_secret_key: bytes,
        sample_agent_card: AgentCard,
    ) -> None:
        bridge = A2ABridge(
            qasp_connection=mock_connection,
            agent_did=agent_did,
            secret_key=agent_secret_key,
        )
        bridge._card_cache["https://agent.example.com"] = sample_agent_card

        # Create a chain: root -> child
        root_id = await bridge.send_task(
            endpoint="https://agent.example.com",
            task_message={"text": "root"},
            skill_id="summarize",
        )
        child_id = await bridge.send_task(
            endpoint="https://agent.example.com",
            task_message={"text": "child"},
            parent_task_id=root_id,
        )

        chain = bridge.get_delegation_chain(child_id)
        assert len(chain) == 1
        assert chain[0].parent_task_id == root_id
        assert chain[0].child_task_id == child_id

    @pytest.mark.asyncio
    async def test_send_task_connection_not_established_raises(
        self,
        mock_connection: MagicMock,
        agent_did: DID,
        agent_secret_key: bytes,
        sample_agent_card: AgentCard,
    ) -> None:
        type(mock_connection).is_established = PropertyMock(return_value=False)
        bridge = A2ABridge(
            qasp_connection=mock_connection,
            agent_did=agent_did,
            secret_key=agent_secret_key,
        )
        bridge._card_cache["https://agent.example.com"] = sample_agent_card

        with pytest.raises(ConnectionError, match="not established"):
            await bridge.send_task(
                endpoint="https://agent.example.com",
                task_message={"text": "hello"},
                skill_id="summarize",
            )


# =============================================================================
# TestDelegationMapping (Step 9)
# =============================================================================


class TestDelegationMapping:
    def test_create_delegation_token_attenuates_parent(
        self,
        sample_capability_token: CapabilityToken,
        agent_secret_key: bytes,
        delegate_did: DID,
    ) -> None:
        skill = AgentSkill(
            id="child_skill", name="Child", description="",
            tags=("read",),
        )
        child_token = create_delegation_token(
            parent_token=sample_capability_token,
            delegator_secret_key=agent_secret_key,
            delegate_did=delegate_did,
            skill=skill,
        )
        assert child_token.subject_did == delegate_did
        assert child_token.parent_token_hash is not None

    def test_delegation_token_reduced_verbs(
        self,
        sample_capability_token: CapabilityToken,
        agent_secret_key: bytes,
        delegate_did: DID,
    ) -> None:
        # Parent has {"read", "execute"}, skill only needs "read"
        skill = AgentSkill(
            id="reader", name="Reader", description="",
            tags=("read",),
        )
        child_token = create_delegation_token(
            parent_token=sample_capability_token,
            delegator_secret_key=agent_secret_key,
            delegate_did=delegate_did,
            skill=skill,
        )
        assert "read" in child_token.verbs
        # Should be reduced to just "read" (intersection with parent)
        assert child_token.verbs.verbs == frozenset({"read"})

    def test_delegation_token_tighter_time(
        self,
        sample_capability_token: CapabilityToken,
        agent_secret_key: bytes,
        delegate_did: DID,
    ) -> None:
        skill = AgentSkill(
            id="s1", name="s1", description="", tags=("execute",),
        )
        child_token = create_delegation_token(
            parent_token=sample_capability_token,
            delegator_secret_key=agent_secret_key,
            delegate_did=delegate_did,
            skill=skill,
            time_limit_seconds=60,
        )
        # Child expiry should be tighter (sooner) than parent
        assert child_token.constraints.not_after is not None
        assert sample_capability_token.constraints.not_after is not None
        assert child_token.constraints.not_after <= sample_capability_token.constraints.not_after

    def test_delegation_depth_exceeded_raises(
        self,
        agent_did: DID,
        agent_secret_key: bytes,
        remote_did: DID,
        delegate_did: DID,
    ) -> None:
        # Create token with depth=0 (no delegation allowed)
        token = create_token(
            issuer_did=agent_did,
            issuer_secret_key=agent_secret_key,
            subject_did=remote_did,
            resource_uri="qasp://test",
            verbs={"execute"},
            max_delegation_depth=0,
        )
        skill = AgentSkill(
            id="s1", name="s1", description="", tags=("execute",),
        )
        with pytest.raises(DelegationDepthExceeded):
            create_delegation_token(
                parent_token=token,
                delegator_secret_key=agent_secret_key,
                delegate_did=delegate_did,
                skill=skill,
            )


# =============================================================================
# TestTaskState
# =============================================================================


class TestTaskState:
    def test_task_state_values(self) -> None:
        assert TaskState.SUBMITTED == 0
        assert TaskState.WORKING == 1
        assert TaskState.COMPLETED == 3
        assert TaskState.CANCELED == 4
        assert TaskState.FAILED == 5

    def test_task_state_is_int(self) -> None:
        assert isinstance(TaskState.SUBMITTED, int)


# =============================================================================
# TestDataclassFrozen
# =============================================================================


class TestDataclassFrozen:
    def test_agent_skill_is_frozen(self) -> None:
        skill = AgentSkill(id="s", name="s", description="", tags=())
        with pytest.raises(AttributeError):
            skill.id = "other"  # type: ignore[misc]

    def test_agent_card_is_frozen(self) -> None:
        card = AgentCard(name="n", description="d", url="u", skills=())
        with pytest.raises(AttributeError):
            card.name = "other"  # type: ignore[misc]

    def test_qasp_extension_is_frozen(self) -> None:
        ext = QASPExtension(
            agent_did="did:qasp:test",
            qasp_endpoint="qasp://localhost",
            supported_cipher_suites=(),
        )
        with pytest.raises(AttributeError):
            ext.agent_did = "other"  # type: ignore[misc]

    def test_skill_capability_mapping_is_frozen(self) -> None:
        m = SkillCapabilityMapping(
            skill_id="s", resource_uri="r", verbs=VerbSet({"read"}),
        )
        with pytest.raises(AttributeError):
            m.skill_id = "other"  # type: ignore[misc]

    def test_task_session_mapping_is_frozen(self) -> None:
        m = TaskSessionMapping(
            task_id="t",
            session_id=b"",
            capability_token_id=b"",
            state=TaskState.SUBMITTED,
            created_at=0.0,
        )
        with pytest.raises(AttributeError):
            m.task_id = "other"  # type: ignore[misc]

    def test_delegation_record_is_frozen(self) -> None:
        r = DelegationRecord(
            parent_task_id="p",
            child_task_id="c",
            parent_token_id=b"",
            attenuated_token_id=b"",
            delegate_did="",
        )
        with pytest.raises(AttributeError):
            r.parent_task_id = "other"  # type: ignore[misc]
