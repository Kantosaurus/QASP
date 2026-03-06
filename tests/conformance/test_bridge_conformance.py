"""Conformance tests for MCP and A2A bridges.

Tests MCP token injection/verification and A2A skill mapping.
"""

from __future__ import annotations

import base64

import pytest

from qasp.crypto import signatures
from qasp.identity.did import DID, DIDDocument, DIDRegistry, create_did
from qasp.protocol.capability import (
    CapabilityToken,
    Constraints,
    VerbSet,
    create_token,
    verify_token,
)

from qasp.bridges.mcp_bridge import (
    MCPAuthorizationError,
    MCPTokenExtractionError,
    extract_qasp_token,
    generate_mcp_server_identity,
    infer_verbs_from_tool_name,
    inject_qasp_token,
    scope_to_resource_mapping,
    tool_name_to_resource_uri,
)
from qasp.bridges.a2a_bridge import (
    AgentCard,
    AgentCapabilities,
    AgentSkill,
    QASPExtension,
    extract_qasp_extension,
    map_capability_to_skill,
    map_skill_to_capability,
)


# =============================================================================
# MCP Token Injection/Extraction
# =============================================================================


class TestMCPTokenTransport:
    """Verify MCP _meta token injection and extraction."""

    def test_inject_and_extract_roundtrip(
        self,
        alice_keypair: tuple[bytes, bytes],
        alice_did: tuple[DID, DIDDocument],
        alpha_did: tuple[DID, DIDDocument],
    ) -> None:
        token = create_token(
            issuer_did=alice_did[0],
            issuer_secret_key=alice_keypair[1],
            subject_did=alpha_did[0],
            resource_uri="qasp://mcp/tools/read_file",
            verbs={"execute", "read"},
        )

        meta = inject_qasp_token(token)
        assert "qasp_token_id" in meta
        assert "qasp_token" in meta

        extracted = extract_qasp_token(meta)
        assert extracted.token_id == token.token_id
        assert extracted.resource_uri == token.resource_uri

    def test_extract_missing_meta_fails(self) -> None:
        with pytest.raises(MCPTokenExtractionError):
            extract_qasp_token(None)

    def test_extract_missing_fields_fails(self) -> None:
        with pytest.raises(MCPTokenExtractionError):
            extract_qasp_token({"qasp_token": "abc"})

    def test_extract_invalid_base64_fails(self) -> None:
        with pytest.raises(MCPTokenExtractionError):
            extract_qasp_token({
                "qasp_token": "not-valid-base64!!!",
                "qasp_token_id": "abc123",
            })

    def test_extract_token_id_mismatch_fails(
        self,
        alice_keypair: tuple[bytes, bytes],
        alice_did: tuple[DID, DIDDocument],
        alpha_did: tuple[DID, DIDDocument],
    ) -> None:
        token = create_token(
            issuer_did=alice_did[0],
            issuer_secret_key=alice_keypair[1],
            subject_did=alpha_did[0],
            resource_uri="qasp://mcp/tools/read_file",
            verbs={"execute"},
        )

        meta = inject_qasp_token(token)
        meta["qasp_token_id"] = "wrong_id"

        with pytest.raises(MCPTokenExtractionError):
            extract_qasp_token(meta)


# =============================================================================
# MCP Tool Name Mapping
# =============================================================================


class TestMCPToolMapping:
    """Verify MCP tool name to resource URI and verb mapping."""

    def test_tool_name_to_uri(self) -> None:
        assert tool_name_to_resource_uri("read_file") == "qasp://mcp/tools/read_file"
        assert tool_name_to_resource_uri("execute_query") == "qasp://mcp/tools/execute_query"

    def test_infer_verbs_read(self) -> None:
        verbs = infer_verbs_from_tool_name("read_file")
        assert "execute" in verbs
        assert "read" in verbs

    def test_infer_verbs_write(self) -> None:
        verbs = infer_verbs_from_tool_name("write_data")
        assert "execute" in verbs
        assert "write" in verbs

    def test_infer_verbs_delete(self) -> None:
        verbs = infer_verbs_from_tool_name("delete_record")
        assert "execute" in verbs
        assert "delete" in verbs

    def test_infer_verbs_default(self) -> None:
        verbs = infer_verbs_from_tool_name("do_something")
        assert "execute" in verbs
        assert len(verbs) == 1


# =============================================================================
# MCP OAuth Scope Mapping
# =============================================================================


class TestMCPScopeMapping:
    """Verify OAuth scope to QASP resource mapping."""

    def test_scope_with_action(self) -> None:
        mapping = scope_to_resource_mapping("files:read")
        assert mapping.resource_uri == "qasp://mcp/files"
        assert "read" in mapping.verbs
        assert "execute" in mapping.verbs

    def test_scope_without_action(self) -> None:
        mapping = scope_to_resource_mapping("admin")
        assert mapping.resource_uri == "qasp://mcp/admin"
        assert "execute" in mapping.verbs


# =============================================================================
# MCP Server Identity
# =============================================================================


class TestMCPServerIdentity:
    """Verify MCP server identity generation."""

    def test_generate_identity(self) -> None:
        identity = generate_mcp_server_identity("test-server")
        assert identity.did is not None
        assert identity.did_document is not None
        assert identity.public_key is not None
        assert identity.secret_key is not None
        assert str(identity.did).startswith("did:qasp:")


# =============================================================================
# A2A Skill Mapping
# =============================================================================


class TestA2ASkillMapping:
    """Verify A2A skill to QASP capability mapping."""

    def test_skill_to_capability(self) -> None:
        skill = AgentSkill(
            id="search",
            name="Search",
            description="Search the web",
            tags=("read", "query"),
        )

        mapping = map_skill_to_capability(skill, "did:qasp:test123")
        assert mapping.skill_id == "search"
        assert "read" in mapping.verbs
        assert mapping.resource_uri == "qasp://a2a/test123/skills/search"

    def test_skill_without_matching_tags(self) -> None:
        skill = AgentSkill(
            id="custom",
            name="Custom",
            description="Custom skill",
            tags=("unknown_tag",),
        )

        mapping = map_skill_to_capability(skill, "did:qasp:abc")
        assert "execute" in mapping.verbs

    def test_capability_to_skill(
        self,
        alice_keypair: tuple[bytes, bytes],
        alice_did: tuple[DID, DIDDocument],
        alpha_did: tuple[DID, DIDDocument],
    ) -> None:
        token = create_token(
            issuer_did=alice_did[0],
            issuer_secret_key=alice_keypair[1],
            subject_did=alpha_did[0],
            resource_uri="qasp://a2a/test/skills/search",
            verbs={"read", "execute"},
        )

        skill = map_capability_to_skill(token)
        assert skill.id == "search"
        assert "read" in skill.tags
        assert "execute" in skill.tags


# =============================================================================
# A2A QASP Extension
# =============================================================================


class TestA2AQASPExtension:
    """Verify QASP extension in A2A Agent Cards."""

    def test_extension_roundtrip(self) -> None:
        ext = QASPExtension(
            agent_did="did:qasp:test123",
            qasp_endpoint="https://agent.example.com:8443",
            supported_cipher_suites=("PQ-Strict", "Hybrid-Transition"),
            protocol_version="1.0",
        )

        ext_dict = ext.to_extension_dict()
        assert ext_dict["uri"] == "urn:qasp:a2a-extension:v1"
        assert ext_dict["params"]["agent_did"] == "did:qasp:test123"

        restored = QASPExtension.from_extension_dict(ext_dict["params"])
        assert restored.agent_did == ext.agent_did
        assert restored.qasp_endpoint == ext.qasp_endpoint
        assert restored.supported_cipher_suites == ext.supported_cipher_suites

    def test_extract_from_agent_card(self) -> None:
        ext = QASPExtension(
            agent_did="did:qasp:test123",
            qasp_endpoint="https://agent.example.com:8443",
        )

        card = AgentCard(
            name="Test Agent",
            description="A test agent",
            url="https://agent.example.com",
            skills=(
                AgentSkill(id="search", name="Search", description=""),
            ),
            capabilities=AgentCapabilities(
                extensions=(ext.to_extension_dict(),),
            ),
        )

        extracted = extract_qasp_extension(card)
        assert extracted is not None
        assert extracted.agent_did == "did:qasp:test123"

    def test_extract_from_card_without_extension(self) -> None:
        card = AgentCard(
            name="Test Agent",
            description="No QASP",
            url="https://agent.example.com",
        )

        assert extract_qasp_extension(card) is None
