"""Comprehensive tests for the MCP bridge module."""

from __future__ import annotations

import base64
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from mcp import ClientSession

from qasp.bridges.mcp_bridge import (
    MCPAuthorizationError,
    MCPBridge,
    MCPBridgeError,
    MCPConnectionError,
    MCPServerIdentity,
    MCPTokenExtractionError,
    MCPToolNotFoundError,
    QASPToolProvider,
    ScopeMapping,
    ToolMapping,
    extract_qasp_token,
    generate_mcp_server_identity,
    infer_verbs_from_tool_name,
    inject_qasp_token,
    scope_to_resource_mapping,
    tool_name_to_resource_uri,
)
from qasp.crypto.signatures import generate_keypair
from qasp.identity.did import DID, DIDDocument, DIDRegistry, create_did
from qasp.protocol.capability import (
    CapabilityToken,
    Constraints,
    VerbSet,
    create_token,
    verify_token,
)


# =============================================================================
# Data Structures
# =============================================================================


class TestToolMapping:
    def test_frozen(self) -> None:
        tm = ToolMapping(
            tool_name="foo",
            resource_uri="qasp://mcp/tools/foo",
            verbs=VerbSet({"execute"}),
        )
        with pytest.raises(FrozenInstanceError):
            tm.tool_name = "bar"  # type: ignore[misc]

    def test_attributes(self) -> None:
        tm = ToolMapping(
            tool_name="read_file",
            resource_uri="qasp://mcp/tools/read_file",
            verbs=VerbSet({"execute", "read"}),
            input_schema={"type": "object"},
            description="Read a file",
        )
        assert tm.tool_name == "read_file"
        assert tm.resource_uri == "qasp://mcp/tools/read_file"
        assert "execute" in tm.verbs
        assert "read" in tm.verbs
        assert tm.input_schema == {"type": "object"}
        assert tm.description == "Read a file"

    def test_defaults(self) -> None:
        tm = ToolMapping(
            tool_name="x",
            resource_uri="qasp://mcp/tools/x",
            verbs=VerbSet({"execute"}),
        )
        assert tm.input_schema == {}
        assert tm.description == ""


class TestScopeMapping:
    def test_frozen(self) -> None:
        sm = ScopeMapping(
            scope="files:read",
            resource_uri="qasp://mcp/files",
            verbs=VerbSet({"execute", "read"}),
        )
        with pytest.raises(FrozenInstanceError):
            sm.scope = "other"  # type: ignore[misc]

    def test_attributes(self) -> None:
        sm = ScopeMapping(
            scope="files:read",
            resource_uri="qasp://mcp/files",
            verbs=VerbSet({"execute", "read"}),
        )
        assert sm.scope == "files:read"
        assert sm.resource_uri == "qasp://mcp/files"
        assert "read" in sm.verbs


class TestMCPServerIdentity:
    def test_frozen(self, server_identity: MCPServerIdentity) -> None:
        with pytest.raises(FrozenInstanceError):
            server_identity.did = DID()  # type: ignore[misc]

    def test_did_matches_key(self, server_identity: MCPServerIdentity) -> None:
        assert server_identity.did.verify_key(server_identity.public_key)

    def test_did_document_has_key(self, server_identity: MCPServerIdentity) -> None:
        pk = server_identity.did_document.get_public_key()
        assert pk == server_identity.public_key


# =============================================================================
# Token Injection / Extraction
# =============================================================================


class TestTokenInjectionExtraction:
    def test_roundtrip(self, mcp_sample_capability_token: CapabilityToken) -> None:
        meta = inject_qasp_token(mcp_sample_capability_token)
        assert "qasp_token" in meta
        assert "qasp_token_id" in meta

        extracted = extract_qasp_token(meta)
        assert extracted.token_id == mcp_sample_capability_token.token_id
        assert extracted.resource_uri == mcp_sample_capability_token.resource_uri
        assert str(extracted.issuer_did) == str(mcp_sample_capability_token.issuer_did)

    def test_missing_meta_raises(self) -> None:
        with pytest.raises(MCPTokenExtractionError, match="No _meta provided"):
            extract_qasp_token(None)

    def test_empty_meta_raises(self) -> None:
        with pytest.raises(MCPTokenExtractionError, match="No _meta provided"):
            extract_qasp_token({})

    def test_missing_token_field_raises(self) -> None:
        with pytest.raises(MCPTokenExtractionError, match="Missing"):
            extract_qasp_token({"qasp_token_id": "abc"})

    def test_missing_token_id_field_raises(self) -> None:
        with pytest.raises(MCPTokenExtractionError, match="Missing"):
            extract_qasp_token({"qasp_token": "abc"})

    def test_malformed_base64_raises(self) -> None:
        with pytest.raises(MCPTokenExtractionError, match="Invalid base64"):
            extract_qasp_token({
                "qasp_token": "!!!not-base64!!!",
                "qasp_token_id": "deadbeef",
            })

    def test_malformed_cbor_raises(self) -> None:
        bad_cbor = base64.b64encode(b"not-cbor-data").decode()
        with pytest.raises(MCPTokenExtractionError, match="Invalid CBOR"):
            extract_qasp_token({
                "qasp_token": bad_cbor,
                "qasp_token_id": "deadbeef",
            })

    def test_token_id_mismatch_raises(
        self, mcp_sample_capability_token: CapabilityToken
    ) -> None:
        meta = inject_qasp_token(mcp_sample_capability_token)
        meta["qasp_token_id"] = "0000000000000000"
        with pytest.raises(MCPTokenExtractionError, match="Token ID mismatch"):
            extract_qasp_token(meta)


# =============================================================================
# Verb Inference
# =============================================================================


class TestVerbInference:
    def test_read_prefix(self) -> None:
        verbs = infer_verbs_from_tool_name("read_file")
        assert "execute" in verbs
        assert "read" in verbs
        assert len(verbs) == 2

    def test_write_prefix(self) -> None:
        verbs = infer_verbs_from_tool_name("write_config")
        assert "execute" in verbs
        assert "write" in verbs
        assert len(verbs) == 2

    def test_delete_prefix(self) -> None:
        verbs = infer_verbs_from_tool_name("delete_record")
        assert "execute" in verbs
        assert "delete" in verbs
        assert len(verbs) == 2

    def test_default(self) -> None:
        verbs = infer_verbs_from_tool_name("run_query")
        assert "execute" in verbs
        assert len(verbs) == 1

    def test_no_prefix(self) -> None:
        verbs = infer_verbs_from_tool_name("search")
        assert "execute" in verbs
        assert len(verbs) == 1


# =============================================================================
# Resource URI Mapping
# =============================================================================


class TestToolNameToResourceUri:
    def test_basic(self) -> None:
        assert tool_name_to_resource_uri("read_file") == "qasp://mcp/tools/read_file"

    def test_preserves_name(self) -> None:
        assert tool_name_to_resource_uri("my-tool") == "qasp://mcp/tools/my-tool"


# =============================================================================
# Scope Mapping
# =============================================================================


class TestScopeMappingFunction:
    def test_resource_action_format(self) -> None:
        sm = scope_to_resource_mapping("files:read")
        assert sm.scope == "files:read"
        assert sm.resource_uri == "qasp://mcp/files"
        assert "read" in sm.verbs
        assert "execute" in sm.verbs

    def test_write_action(self) -> None:
        sm = scope_to_resource_mapping("data:write")
        assert "write" in sm.verbs
        assert "execute" in sm.verbs

    def test_delete_action(self) -> None:
        sm = scope_to_resource_mapping("records:delete")
        assert "delete" in sm.verbs

    def test_admin_action(self) -> None:
        sm = scope_to_resource_mapping("system:admin")
        assert "read" in sm.verbs
        assert "write" in sm.verbs
        assert "delete" in sm.verbs
        assert "execute" in sm.verbs

    def test_unknown_action_fallback(self) -> None:
        sm = scope_to_resource_mapping("resource:unknown_action")
        assert "execute" in sm.verbs
        assert len(sm.verbs) == 1

    def test_no_colon_format(self) -> None:
        sm = scope_to_resource_mapping("openid")
        assert sm.resource_uri == "qasp://mcp/openid"
        assert "execute" in sm.verbs
        assert len(sm.verbs) == 1


# =============================================================================
# MCPServerIdentity Generation
# =============================================================================


class TestGenerateMCPServerIdentity:
    def test_generates_valid_identity(self) -> None:
        identity = generate_mcp_server_identity("test")
        assert identity.did.method == "qasp"
        assert identity.did.verify_key(identity.public_key)
        assert len(identity.public_key) == 1952
        assert len(identity.secret_key) == 4032

    def test_unique_per_call(self) -> None:
        id1 = generate_mcp_server_identity("a")
        id2 = generate_mcp_server_identity("b")
        assert str(id1.did) != str(id2.did)


# =============================================================================
# QASPToolProvider
# =============================================================================


class TestQASPToolProvider:
    @pytest.fixture
    def provider(self, bridge_did_registry: DIDRegistry) -> QASPToolProvider:
        return QASPToolProvider("test-provider", bridge_did_registry)

    @pytest.fixture
    def registered_provider(
        self, provider: QASPToolProvider
    ) -> QASPToolProvider:
        async def handler(args: dict[str, Any]) -> str:
            return f"result: {args.get('input', '')}"

        provider.register_capability(
            resource_uri="qasp://mcp/tools/test_tool",
            verbs={"execute", "read"},
            tool_name="test_tool",
            description="A test tool",
            input_schema={"type": "object", "properties": {"input": {"type": "string"}}},
            handler=handler,
        )
        return provider

    def test_register_and_list_tools(
        self, registered_provider: QASPToolProvider
    ) -> None:
        tools = registered_provider.get_tools()
        assert len(tools) == 1
        assert tools[0].name == "test_tool"
        assert tools[0].description == "A test tool"

    def test_identity_registered(
        self, provider: QASPToolProvider, bridge_did_registry: DIDRegistry
    ) -> None:
        identity = provider.identity
        doc = bridge_did_registry.lookup(identity.did)
        assert doc == identity.did_document

    async def test_handle_call_tool_valid_token(
        self,
        registered_provider: QASPToolProvider,
        bridge_did_registry: DIDRegistry,
        bridge_issuer_did: DID,
        bridge_issuer_secret_key: bytes,
        bridge_subject_did: DID,
    ) -> None:
        token = create_token(
            issuer_did=bridge_issuer_did,
            issuer_secret_key=bridge_issuer_secret_key,
            subject_did=bridge_subject_did,
            resource_uri="qasp://mcp/tools/test_tool",
            verbs={"execute", "read"},
        )
        meta = inject_qasp_token(token)

        result = await registered_provider.handle_call_tool(
            "test_tool", {"input": "hello"}, meta=meta
        )
        assert result.content[0].text == "result: hello"  # type: ignore[union-attr]

    async def test_handle_call_tool_no_meta_raises(
        self, registered_provider: QASPToolProvider
    ) -> None:
        with pytest.raises(MCPTokenExtractionError):
            await registered_provider.handle_call_tool("test_tool", {})

    async def test_handle_call_tool_unknown_tool_raises(
        self, registered_provider: QASPToolProvider
    ) -> None:
        with pytest.raises(MCPToolNotFoundError, match="Unknown tool"):
            await registered_provider.handle_call_tool("nonexistent", {})

    async def test_handle_call_tool_wrong_resource_uri_raises(
        self,
        registered_provider: QASPToolProvider,
        bridge_issuer_did: DID,
        bridge_issuer_secret_key: bytes,
        bridge_subject_did: DID,
    ) -> None:
        token = create_token(
            issuer_did=bridge_issuer_did,
            issuer_secret_key=bridge_issuer_secret_key,
            subject_did=bridge_subject_did,
            resource_uri="qasp://mcp/tools/other_tool",
            verbs={"execute"},
        )
        meta = inject_qasp_token(token)

        with pytest.raises(MCPAuthorizationError, match="resource_uri"):
            await registered_provider.handle_call_tool("test_tool", {}, meta=meta)

    async def test_handle_call_tool_missing_execute_verb_raises(
        self,
        registered_provider: QASPToolProvider,
        bridge_issuer_did: DID,
        bridge_issuer_secret_key: bytes,
        bridge_subject_did: DID,
    ) -> None:
        token = create_token(
            issuer_did=bridge_issuer_did,
            issuer_secret_key=bridge_issuer_secret_key,
            subject_did=bridge_subject_did,
            resource_uri="qasp://mcp/tools/test_tool",
            verbs={"read"},
        )
        meta = inject_qasp_token(token)

        with pytest.raises(MCPAuthorizationError, match="execute"):
            await registered_provider.handle_call_tool("test_tool", {}, meta=meta)

    async def test_handle_call_tool_expired_token_raises(
        self,
        registered_provider: QASPToolProvider,
        bridge_issuer_did: DID,
        bridge_issuer_secret_key: bytes,
        bridge_subject_did: DID,
    ) -> None:
        token = create_token(
            issuer_did=bridge_issuer_did,
            issuer_secret_key=bridge_issuer_secret_key,
            subject_did=bridge_subject_did,
            resource_uri="qasp://mcp/tools/test_tool",
            verbs={"execute"},
            constraints=Constraints(
                not_after=datetime.now(UTC) - timedelta(hours=1),
            ),
            validity_seconds=0,
        )
        meta = inject_qasp_token(token)

        with pytest.raises(MCPAuthorizationError, match="Token verification failed"):
            await registered_provider.handle_call_tool("test_tool", {}, meta=meta)

    def test_create_mcp_server(
        self, registered_provider: QASPToolProvider
    ) -> None:
        server = registered_provider.create_mcp_server()
        assert server is not None


# =============================================================================
# MCPBridge
# =============================================================================


class TestMCPBridge:
    def test_requires_command_or_session(self) -> None:
        with pytest.raises(MCPBridgeError, match="Either server_command or session"):
            MCPBridge()

    def test_identity_before_connect_raises(self) -> None:
        bridge = MCPBridge(server_command="echo test")
        with pytest.raises(MCPBridgeError, match="not connected"):
            _ = bridge.identity

    async def test_connect_with_session(self) -> None:
        mock_session = AsyncMock(spec=ClientSession)
        mock_tool = MagicMock()
        mock_tool.name = "read_data"
        mock_tool.inputSchema = {"type": "object"}
        mock_tool.description = "Read data"

        mock_list_result = MagicMock()
        mock_list_result.tools = [mock_tool]
        mock_session.list_tools.return_value = mock_list_result

        bridge = MCPBridge(session=mock_session, server_name="test-mcp")
        await bridge.connect()

        assert bridge.identity.did.method == "qasp"
        assert "read_data" in bridge.tool_mappings
        mapping = bridge.tool_mappings["read_data"]
        assert mapping.resource_uri == "qasp://mcp/tools/read_data"
        assert "read" in mapping.verbs
        assert "execute" in mapping.verbs

        await bridge.disconnect()

    async def test_list_tools(self) -> None:
        mock_session = AsyncMock(spec=ClientSession)
        mock_tool1 = MagicMock()
        mock_tool1.name = "read_file"
        mock_tool1.inputSchema = {}
        mock_tool1.description = "Read a file"
        mock_tool2 = MagicMock()
        mock_tool2.name = "write_file"
        mock_tool2.inputSchema = {}
        mock_tool2.description = "Write a file"

        mock_list_result = MagicMock()
        mock_list_result.tools = [mock_tool1, mock_tool2]
        mock_session.list_tools.return_value = mock_list_result

        bridge = MCPBridge(session=mock_session, server_name="test")
        await bridge.connect()

        tools = bridge.list_tools()
        assert len(tools) == 2
        names = {t.tool_name for t in tools}
        assert names == {"read_file", "write_file"}

        await bridge.disconnect()

    async def test_issue_capability_token(self) -> None:
        mock_session = AsyncMock(spec=ClientSession)
        mock_tool = MagicMock()
        mock_tool.name = "search"
        mock_tool.inputSchema = {}
        mock_tool.description = ""

        mock_list_result = MagicMock()
        mock_list_result.tools = [mock_tool]
        mock_session.list_tools.return_value = mock_list_result

        bridge = MCPBridge(session=mock_session, server_name="test")
        await bridge.connect()

        pk, _ = generate_keypair()
        subject_did, _ = create_did(pk)

        token = bridge.issue_capability_token(subject_did, "search")
        assert token.resource_uri == "qasp://mcp/tools/search"
        assert str(token.issuer_did) == str(bridge.identity.did)
        assert str(token.subject_did) == str(subject_did)
        assert "execute" in token.verbs

        verify_token(token, bridge.identity.public_key)

        await bridge.disconnect()

    async def test_issue_token_unknown_tool_raises(self) -> None:
        mock_session = AsyncMock(spec=ClientSession)
        mock_list_result = MagicMock()
        mock_list_result.tools = []
        mock_session.list_tools.return_value = mock_list_result

        bridge = MCPBridge(session=mock_session, server_name="test")
        await bridge.connect()

        pk, _ = generate_keypair()
        subject_did, _ = create_did(pk)

        with pytest.raises(MCPToolNotFoundError):
            bridge.issue_capability_token(subject_did, "nonexistent")

        await bridge.disconnect()

    async def test_call_tool_with_valid_token(self) -> None:
        mock_session = AsyncMock(spec=ClientSession)
        mock_tool = MagicMock()
        mock_tool.name = "search"
        mock_tool.inputSchema = {}
        mock_tool.description = ""

        mock_list_result = MagicMock()
        mock_list_result.tools = [mock_tool]
        mock_session.list_tools.return_value = mock_list_result

        mock_call_result = MagicMock()
        mock_call_result.content = [MagicMock(text="found it")]
        mock_session.call_tool.return_value = mock_call_result

        bridge = MCPBridge(session=mock_session, server_name="test")
        await bridge.connect()

        pk, _ = generate_keypair()
        subject_did, _ = create_did(pk)
        token = bridge.issue_capability_token(subject_did, "search")

        result = await bridge.call_tool("search", {"query": "test"}, token)
        assert result == mock_call_result

        mock_session.call_tool.assert_called_once()
        call_kwargs = mock_session.call_tool.call_args
        assert "meta" in call_kwargs.kwargs
        assert "qasp_token" in call_kwargs.kwargs["meta"]

        await bridge.disconnect()

    async def test_call_tool_wrong_resource_raises(self) -> None:
        mock_session = AsyncMock(spec=ClientSession)
        mock_tool1 = MagicMock()
        mock_tool1.name = "search"
        mock_tool1.inputSchema = {}
        mock_tool1.description = ""
        mock_tool2 = MagicMock()
        mock_tool2.name = "delete_item"
        mock_tool2.inputSchema = {}
        mock_tool2.description = ""

        mock_list_result = MagicMock()
        mock_list_result.tools = [mock_tool1, mock_tool2]
        mock_session.list_tools.return_value = mock_list_result

        bridge = MCPBridge(session=mock_session, server_name="test")
        await bridge.connect()

        pk, _ = generate_keypair()
        subject_did, _ = create_did(pk)

        token = bridge.issue_capability_token(subject_did, "search")

        with pytest.raises(MCPAuthorizationError, match="resource_uri"):
            await bridge.call_tool("delete_item", {}, token)

        await bridge.disconnect()

    async def test_call_tool_not_connected_raises(self) -> None:
        bridge = MCPBridge(server_command="echo test")

        pk, _ = generate_keypair()
        subject_did, _ = create_did(pk)
        issuer_pk, issuer_sk = generate_keypair()
        issuer_did, _ = create_did(issuer_pk)
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_sk,
            subject_did=subject_did,
            resource_uri="qasp://mcp/tools/foo",
            verbs={"execute"},
        )

        with pytest.raises(MCPConnectionError, match="not connected"):
            await bridge.call_tool("foo", {}, token)

    async def test_call_tool_unknown_tool_raises(self) -> None:
        mock_session = AsyncMock(spec=ClientSession)
        mock_list_result = MagicMock()
        mock_list_result.tools = []
        mock_session.list_tools.return_value = mock_list_result

        bridge = MCPBridge(session=mock_session, server_name="test")
        await bridge.connect()

        pk, sk = generate_keypair()
        subject_did, _ = create_did(pk)
        token = create_token(
            issuer_did=bridge.identity.did,
            issuer_secret_key=bridge.identity.secret_key,
            subject_did=subject_did,
            resource_uri="qasp://mcp/tools/nonexistent",
            verbs={"execute"},
        )

        with pytest.raises(MCPToolNotFoundError):
            await bridge.call_tool("nonexistent", {}, token)

        await bridge.disconnect()

    async def test_map_oauth_scopes(self) -> None:
        mock_session = AsyncMock(spec=ClientSession)
        mock_list_result = MagicMock()
        mock_list_result.tools = []
        mock_session.list_tools.return_value = mock_list_result

        bridge = MCPBridge(session=mock_session, server_name="test")
        await bridge.connect()

        pk, _ = generate_keypair()
        subject_did, _ = create_did(pk)

        tokens = bridge.map_oauth_scopes(
            ["files:read", "data:write", "system:admin"],
            subject_did,
        )

        assert len(tokens) == 3

        assert tokens[0].resource_uri == "qasp://mcp/files"
        assert "read" in tokens[0].verbs
        assert "execute" in tokens[0].verbs

        assert tokens[1].resource_uri == "qasp://mcp/data"
        assert "write" in tokens[1].verbs

        assert tokens[2].resource_uri == "qasp://mcp/system"
        assert "read" in tokens[2].verbs
        assert "write" in tokens[2].verbs
        assert "delete" in tokens[2].verbs

        for token in tokens:
            verify_token(token, bridge.identity.public_key)

        await bridge.disconnect()

    async def test_async_context_manager(self) -> None:
        mock_session = AsyncMock(spec=ClientSession)
        mock_list_result = MagicMock()
        mock_list_result.tools = []
        mock_session.list_tools.return_value = mock_list_result

        async with MCPBridge(session=mock_session, server_name="test") as bridge:
            assert bridge.identity is not None

    async def test_connect_idempotent(self) -> None:
        mock_session = AsyncMock(spec=ClientSession)
        mock_list_result = MagicMock()
        mock_list_result.tools = []
        mock_session.list_tools.return_value = mock_list_result

        bridge = MCPBridge(session=mock_session, server_name="test")
        await bridge.connect()
        identity1 = bridge.identity
        await bridge.connect()  # should be a no-op
        assert bridge.identity is identity1

        await bridge.disconnect()

    async def test_call_tool_missing_execute_verb_raises(self) -> None:
        mock_session = AsyncMock(spec=ClientSession)
        mock_tool = MagicMock()
        mock_tool.name = "search"
        mock_tool.inputSchema = {}
        mock_tool.description = ""

        mock_list_result = MagicMock()
        mock_list_result.tools = [mock_tool]
        mock_session.list_tools.return_value = mock_list_result

        bridge = MCPBridge(session=mock_session, server_name="test")
        await bridge.connect()

        pk, _ = generate_keypair()
        subject_did, _ = create_did(pk)

        token = create_token(
            issuer_did=bridge.identity.did,
            issuer_secret_key=bridge.identity.secret_key,
            subject_did=subject_did,
            resource_uri="qasp://mcp/tools/search",
            verbs={"read"},
        )

        with pytest.raises(MCPAuthorizationError, match="execute"):
            await bridge.call_tool("search", {}, token)

        await bridge.disconnect()
