"""MCP (Model Context Protocol) bridge.

Bidirectional bridge between QASP and MCP:
- QASPToolProvider: Exposes QASP capabilities as MCP tools (QASP -> MCP)
- MCPBridge: Wraps MCP servers as QASP agents (MCP -> QASP)

Every call is gated by QASP capability token verification. Tokens are
transported via MCP ``_meta`` fields.
"""

from __future__ import annotations

import base64
import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from mcp import ClientSession
from mcp.client.stdio import stdio_client
from mcp.server.lowlevel import Server
from mcp.types import CallToolResult, TextContent, Tool

from qasp.crypto.signatures import generate_keypair
from qasp.identity.did import DID, DIDDocument, DIDRegistry, create_did
from qasp.protocol.capability import (
    CapabilityToken,
    Constraints,
    InvalidTokenError,
    RevocationChecker,
    VerbSet,
    create_token,
    verify_token,
)

logger = logging.getLogger(__name__)

__all__ = [
    "MCPAuthorizationError",
    "MCPBridge",
    "MCPBridgeError",
    "MCPConnectionError",
    "MCPServerIdentity",
    "MCPTokenExtractionError",
    "MCPToolNotFoundError",
    "QASPToolProvider",
    "ScopeMapping",
    "ToolMapping",
    "extract_qasp_token",
    "generate_mcp_server_identity",
    "infer_verbs_from_tool_name",
    "inject_qasp_token",
    "scope_to_resource_mapping",
    "tool_name_to_resource_uri",
]


# =============================================================================
# Exceptions
# =============================================================================


class MCPBridgeError(Exception):
    """Base exception for MCP bridge errors."""


class MCPConnectionError(MCPBridgeError):
    """Raised when MCP server connection fails."""


class MCPToolNotFoundError(MCPBridgeError):
    """Raised when a requested MCP tool is not found."""


class MCPTokenExtractionError(MCPBridgeError):
    """Raised when QASP token extraction from MCP meta fails."""


class MCPAuthorizationError(MCPBridgeError):
    """Raised when QASP capability token authorization fails."""


# =============================================================================
# Data Structures
# =============================================================================


@dataclass(frozen=True)
class ToolMapping:
    """Maps an MCP tool to a QASP resource URI and verb set."""

    tool_name: str
    resource_uri: str
    verbs: VerbSet
    input_schema: dict[str, Any] = field(default_factory=dict)
    description: str = ""


@dataclass(frozen=True)
class ScopeMapping:
    """Maps an OAuth scope string to a QASP resource URI and verb set."""

    scope: str
    resource_uri: str
    verbs: VerbSet


@dataclass(frozen=True)
class MCPServerIdentity:
    """Auto-generated identity for a wrapped MCP server."""

    did: DID
    did_document: DIDDocument
    public_key: bytes
    secret_key: bytes


# =============================================================================
# Helper Functions
# =============================================================================


def extract_qasp_token(meta: dict[str, Any] | None) -> CapabilityToken:
    """Extract and decode a QASP capability token from MCP ``_meta``.

    The meta dict must contain ``qasp_token`` (base64-encoded CBOR) and
    ``qasp_token_id`` (hex-encoded token ID). The decoded token's ID is
    checked against ``qasp_token_id``.

    Raises:
        MCPTokenExtractionError: If meta is missing, malformed, or token_id
            doesn't match.
    """
    if not meta:
        raise MCPTokenExtractionError("No _meta provided; QASP token required")

    token_b64 = meta.get("qasp_token")
    token_id_hex = meta.get("qasp_token_id")

    if not token_b64 or not token_id_hex:
        raise MCPTokenExtractionError(
            "Missing qasp_token or qasp_token_id in _meta"
        )

    try:
        token_cbor = base64.b64decode(token_b64)
    except Exception as e:
        raise MCPTokenExtractionError(f"Invalid base64 in qasp_token: {e}") from e

    try:
        token = CapabilityToken.from_cbor(token_cbor)
    except InvalidTokenError as e:
        raise MCPTokenExtractionError(f"Invalid CBOR token: {e}") from e

    if token.token_id.hex() != token_id_hex:
        raise MCPTokenExtractionError(
            f"Token ID mismatch: meta says {token_id_hex}, "
            f"token contains {token.token_id.hex()}"
        )

    return token


def inject_qasp_token(token: CapabilityToken) -> dict[str, str]:
    """Serialize a QASP capability token for MCP ``_meta`` transport.

    Returns:
        A dict with ``qasp_token_id`` (hex) and ``qasp_token`` (base64 CBOR).
    """
    token_cbor = token.to_cbor_with_signature()
    return {
        "qasp_token_id": token.token_id.hex(),
        "qasp_token": base64.b64encode(token_cbor).decode("ascii"),
    }


def tool_name_to_resource_uri(name: str) -> str:
    """Convert an MCP tool name to a QASP resource URI.

    Example: ``"read_file"`` -> ``"qasp://mcp/tools/read_file"``
    """
    return f"qasp://mcp/tools/{name}"


def infer_verbs_from_tool_name(name: str) -> VerbSet:
    """Heuristically infer QASP verbs from an MCP tool name.

    Prefixes: ``read_*`` -> {execute,read}, ``write_*`` -> {execute,write},
    ``delete_*`` -> {execute,delete}, default -> {execute}.
    """
    if name.startswith("read_"):
        return VerbSet({"execute", "read"})
    if name.startswith("write_"):
        return VerbSet({"execute", "write"})
    if name.startswith("delete_"):
        return VerbSet({"execute", "delete"})
    return VerbSet({"execute"})


_VERB_MAP: dict[str, set[str]] = {
    "read": {"execute", "read"},
    "write": {"execute", "write"},
    "delete": {"execute", "delete"},
    "create": {"execute", "write"},
    "update": {"execute", "write"},
    "list": {"execute", "read"},
    "admin": {"execute", "read", "write", "delete"},
}


def scope_to_resource_mapping(scope: str) -> ScopeMapping:
    """Parse an OAuth scope string into a QASP ScopeMapping.

    Supports ``"resource:action"`` format (e.g. ``"files:read"``).
    Falls back to ``{execute}`` for unknown actions.
    """
    if ":" in scope:
        resource, action = scope.split(":", 1)
    else:
        resource = scope
        action = ""

    resource_uri = f"qasp://mcp/{resource}"
    verbs = _VERB_MAP.get(action, {"execute"})

    return ScopeMapping(scope=scope, resource_uri=resource_uri, verbs=VerbSet(verbs))


def generate_mcp_server_identity(name: str) -> MCPServerIdentity:
    """Generate a fresh ML-DSA-65 identity for a wrapped MCP server."""
    public_key, secret_key = generate_keypair()
    did, did_document = create_did(public_key)
    logger.debug("Generated MCP server identity for %s: %s", name, did)
    return MCPServerIdentity(
        did=did,
        did_document=did_document,
        public_key=public_key,
        secret_key=secret_key,
    )


# =============================================================================
# QASPToolProvider (QASP -> MCP direction)
# =============================================================================


@dataclass
class _RegisteredCapability:
    """Internal storage for a registered capability."""

    resource_uri: str
    verbs: VerbSet
    tool_name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[..., Awaitable[Any]]


class QASPToolProvider:
    """Expose QASP capabilities as MCP tools.

    On every ``tools/call``, the provider extracts a QASP capability token
    from the request ``_meta``, verifies it (signature, expiry, revocation,
    resource URI, verb check), then dispatches to the registered handler.
    """

    def __init__(
        self,
        server_name: str,
        did_registry: DIDRegistry,
        revocation_checker: RevocationChecker | None = None,
    ) -> None:
        self._server_name = server_name
        self._did_registry = did_registry
        self._revocation_checker = revocation_checker
        self._capabilities: dict[str, _RegisteredCapability] = {}
        self._identity = generate_mcp_server_identity(server_name)
        self._did_registry.register(self._identity.did_document)

    @property
    def identity(self) -> MCPServerIdentity:
        return self._identity

    def register_capability(
        self,
        resource_uri: str,
        verbs: set[str] | VerbSet,
        tool_name: str,
        description: str,
        input_schema: dict[str, Any],
        handler: Callable[..., Awaitable[Any]],
    ) -> None:
        """Register a QASP capability as an MCP tool."""
        verb_set = verbs if isinstance(verbs, VerbSet) else VerbSet(verbs)
        self._capabilities[tool_name] = _RegisteredCapability(
            resource_uri=resource_uri,
            verbs=verb_set,
            tool_name=tool_name,
            description=description,
            input_schema=input_schema,
            handler=handler,
        )

    def get_tools(self) -> list[Tool]:
        """Return MCP Tool definitions for all registered capabilities."""
        tools: list[Tool] = []
        for cap in self._capabilities.values():
            tools.append(
                Tool(
                    name=cap.tool_name,
                    description=cap.description,
                    inputSchema=cap.input_schema,
                )
            )
        return tools

    async def handle_call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        meta: dict[str, Any] | None = None,
    ) -> CallToolResult:
        """Handle an MCP ``tools/call`` request with QASP token verification.

        Raises:
            MCPToolNotFoundError: If the tool is not registered.
            MCPTokenExtractionError: If the token cannot be extracted.
            MCPAuthorizationError: If authorization fails.
        """
        cap = self._capabilities.get(name)
        if cap is None:
            raise MCPToolNotFoundError(f"Unknown tool: {name}")

        # Extract and verify token
        token = extract_qasp_token(meta)

        # Resolve issuer public key
        issuer_doc = self._did_registry.lookup(token.issuer_did)
        issuer_pk = issuer_doc.get_public_key()

        try:
            verify_token(
                token,
                issuer_pk,
                crl=self._revocation_checker,
            )
        except Exception as e:
            raise MCPAuthorizationError(f"Token verification failed: {e}") from e

        # Check resource URI
        if token.resource_uri != cap.resource_uri:
            raise MCPAuthorizationError(
                f"Token resource_uri '{token.resource_uri}' does not match "
                f"tool resource_uri '{cap.resource_uri}'"
            )

        # Check verb
        if "execute" not in token.verbs:
            raise MCPAuthorizationError(
                "Token missing required 'execute' verb"
            )

        # Call handler
        result = await cap.handler(arguments or {})

        # Wrap result
        if isinstance(result, CallToolResult):
            return result
        text = result if isinstance(result, str) else json.dumps(result)
        return CallToolResult(content=[TextContent(type="text", text=text)])

    def create_mcp_server(self) -> Server:
        """Create a low-level MCP Server wired to this provider."""
        server = Server(self._server_name)

        @server.list_tools()
        async def _list_tools() -> list[Tool]:
            return self.get_tools()

        @server.call_tool()
        async def _call_tool(
            name: str, arguments: dict[str, Any] | None
        ) -> list[TextContent]:
            # NOTE: The low-level Server call_tool handler receives
            # (name, arguments) — _meta is not forwarded by the SDK.
            # For full QASP token verification, use handle_call_tool()
            # directly or via a custom transport that passes meta.
            result = await self.handle_call_tool(name, arguments)
            return result.content  # type: ignore[return-value]

        return server


# =============================================================================
# MCPBridge (MCP -> QASP direction)
# =============================================================================


class MCPBridge:
    """Wrap an MCP server as a QASP agent.

    Supports both internal lifecycle (launch via ``server_command``) and
    external session injection. Every ``call_tool`` is gated by QASP
    capability token verification.
    """

    def __init__(
        self,
        *,
        server_command: str | list[str] | None = None,
        session: ClientSession | None = None,
        server_name: str = "mcp-server",
        did_registry: DIDRegistry | None = None,
        revocation_checker: RevocationChecker | None = None,
    ) -> None:
        if server_command is None and session is None:
            raise MCPBridgeError(
                "Either server_command or session must be provided"
            )

        self._server_command = server_command
        self._external_session = session
        self._server_name = server_name
        self._did_registry = did_registry or DIDRegistry()
        self._revocation_checker = revocation_checker

        self._identity: MCPServerIdentity | None = None
        self._tool_mappings: dict[str, ToolMapping] = {}
        self._session: ClientSession | None = None
        self._stdio_context: Any = None
        self._session_context: Any = None
        self._connected = False

    @property
    def identity(self) -> MCPServerIdentity:
        if self._identity is None:
            raise MCPBridgeError("Bridge not connected; call connect() first")
        return self._identity

    @property
    def tool_mappings(self) -> dict[str, ToolMapping]:
        return dict(self._tool_mappings)

    async def connect(self) -> None:
        """Connect to the MCP server and discover tools.

        Raises:
            MCPConnectionError: If connection or initialization fails.
        """
        if self._connected:
            return

        try:
            if self._external_session is not None:
                self._session = self._external_session
            else:
                assert self._server_command is not None
                cmd = self._server_command
                if isinstance(cmd, str):
                    cmd = cmd.split()

                server_params = _make_stdio_server_params(cmd)
                self._stdio_context = stdio_client(server_params)
                read_stream, write_stream = await self._stdio_context.__aenter__()

                self._session_context = ClientSession(read_stream, write_stream)
                self._session = await self._session_context.__aenter__()
                await self._session.initialize()

        except Exception as e:
            raise MCPConnectionError(
                f"Failed to connect to MCP server: {e}"
            ) from e

        # Generate identity
        self._identity = generate_mcp_server_identity(self._server_name)
        self._did_registry.register(self._identity.did_document)

        # Discover tools
        try:
            result = await self._session.list_tools()
            for tool in result.tools:
                name = tool.name
                resource_uri = tool_name_to_resource_uri(name)
                verbs = infer_verbs_from_tool_name(name)
                self._tool_mappings[name] = ToolMapping(
                    tool_name=name,
                    resource_uri=resource_uri,
                    verbs=verbs,
                    input_schema=tool.inputSchema if tool.inputSchema else {},
                    description=tool.description or "",
                )
        except Exception as e:
            raise MCPConnectionError(
                f"Failed to discover MCP tools: {e}"
            ) from e

        self._connected = True
        logger.info(
            "MCPBridge connected to %s — %d tools discovered",
            self._server_name,
            len(self._tool_mappings),
        )

    async def disconnect(self) -> None:
        """Disconnect from the MCP server."""
        if self._session_context is not None:
            try:
                await self._session_context.__aexit__(None, None, None)
            except Exception:
                pass
            self._session_context = None

        if self._stdio_context is not None:
            try:
                await self._stdio_context.__aexit__(None, None, None)
            except Exception:
                pass
            self._stdio_context = None

        self._session = None
        self._connected = False

    async def __aenter__(self) -> MCPBridge:
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.disconnect()

    def issue_capability_token(
        self,
        subject_did: DID,
        tool_name: str,
        verbs: set[str] | VerbSet | None = None,
        constraints: Constraints | None = None,
    ) -> CapabilityToken:
        """Issue a QASP capability token for an MCP tool.

        The bridge's auto-generated DID is used as the token issuer.

        Raises:
            MCPToolNotFoundError: If the tool is not known.
            MCPBridgeError: If the bridge is not connected.
        """
        identity = self.identity  # raises if not connected
        mapping = self._tool_mappings.get(tool_name)
        if mapping is None:
            raise MCPToolNotFoundError(f"Unknown tool: {tool_name}")

        verb_set: VerbSet
        if verbs is not None:
            verb_set = verbs if isinstance(verbs, VerbSet) else VerbSet(verbs)
        else:
            verb_set = mapping.verbs

        return create_token(
            issuer_did=identity.did,
            issuer_secret_key=identity.secret_key,
            subject_did=subject_did,
            resource_uri=mapping.resource_uri,
            verbs=verb_set,
            constraints=constraints,
        )

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        qasp_token: CapabilityToken,
    ) -> Any:
        """Call an MCP tool with QASP token verification.

        Raises:
            MCPToolNotFoundError: If the tool is not known.
            MCPAuthorizationError: If authorization fails.
            MCPConnectionError: If the bridge is not connected.
        """
        if not self._connected or self._session is None:
            raise MCPConnectionError("Bridge not connected")

        mapping = self._tool_mappings.get(name)
        if mapping is None:
            raise MCPToolNotFoundError(f"Unknown tool: {name}")

        # Verify token
        identity = self.identity
        try:
            verify_token(
                qasp_token,
                identity.public_key,
                crl=self._revocation_checker,
            )
        except Exception as e:
            raise MCPAuthorizationError(
                f"Token verification failed: {e}"
            ) from e

        # Check resource URI
        if qasp_token.resource_uri != mapping.resource_uri:
            raise MCPAuthorizationError(
                f"Token resource_uri '{qasp_token.resource_uri}' does not match "
                f"tool resource_uri '{mapping.resource_uri}'"
            )

        # Check verb
        if "execute" not in qasp_token.verbs:
            raise MCPAuthorizationError(
                "Token missing required 'execute' verb"
            )

        # Inject token into meta and call
        meta = inject_qasp_token(qasp_token)
        result = await self._session.call_tool(name, arguments, meta=meta)
        return result

    def list_tools(self) -> list[ToolMapping]:
        """List discovered MCP tools as ToolMappings."""
        return list(self._tool_mappings.values())

    def map_oauth_scopes(
        self,
        scopes: list[str],
        subject_did: DID,
        constraints: Constraints | None = None,
    ) -> list[CapabilityToken]:
        """Map OAuth scopes to QASP capability tokens.

        Each scope is parsed via ``scope_to_resource_mapping()`` and a
        corresponding token is issued with the bridge's identity as issuer.

        Raises:
            MCPBridgeError: If the bridge is not connected.
        """
        identity = self.identity  # raises if not connected
        tokens: list[CapabilityToken] = []
        for scope in scopes:
            mapping = scope_to_resource_mapping(scope)
            token = create_token(
                issuer_did=identity.did,
                issuer_secret_key=identity.secret_key,
                subject_did=subject_did,
                resource_uri=mapping.resource_uri,
                verbs=mapping.verbs,
                constraints=constraints,
            )
            tokens.append(token)
        return tokens


# =============================================================================
# Internal Helpers
# =============================================================================


def _make_stdio_server_params(cmd: list[str]) -> Any:
    """Create StdioServerParameters for ``stdio_client``."""
    from mcp.client.stdio import StdioServerParameters

    return StdioServerParameters(command=cmd[0], args=cmd[1:])
