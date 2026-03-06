"""MCP (Model Context Protocol) bridge.

This module implements a bridge between QASP and MCP protocols.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from qasp.protocol.capability import (
    CapabilityError,
    CapabilityToken,
    InvalidTokenError,
    verify_token,
)

if TYPE_CHECKING:
    from qasp.protocol.connection import QASPConnection

__all__ = [
    "MCPBridge",
    "MCPToolBackend",
    "QASPToolProvider",
]


@runtime_checkable
class MCPToolBackend(Protocol):
    """Backend protocol for MCP tool execution."""

    def list_tools(self) -> list[dict[str, Any]]:
        """List available tools."""
        ...

    def execute_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        """Execute a tool by name."""
        ...

    def list_resources(self) -> list[dict[str, Any]]:
        """List available resources."""
        ...

    def read_resource(self, uri: str) -> Any:
        """Read a resource by URI."""
        ...


class MCPBridge:
    """Bridge between QASP and MCP protocols.

    Allows QASP agents to interact with MCP-compatible tools
    and resources, with QASP capability token verification.
    """

    def __init__(
        self,
        backend: MCPToolBackend,
        issuer_public_key: bytes,
        qasp_connection: QASPConnection | None = None,
    ) -> None:
        """Initialize the MCP bridge.

        Args:
            backend: The MCP tool backend to delegate to.
            issuer_public_key: Public key for verifying QASP tokens.
            qasp_connection: Optional QASP connection.
        """
        self._backend = backend
        self._issuer_public_key = issuer_public_key
        self._connection = qasp_connection

    def list_tools(self) -> list[dict[str, Any]]:
        """List available MCP tools.

        Returns:
            List of tool definitions.
        """
        return self._backend.list_tools()

    def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        meta: dict[str, Any] | None = None,
    ) -> Any:
        """Call an MCP tool with QASP token verification.

        Args:
            name: The tool name.
            arguments: Tool arguments.
            meta: Metadata containing qasp_token and qasp_token_id.

        Returns:
            The tool result.

        Raises:
            CapabilityError: If token is missing, invalid, or unauthorized.
        """
        if meta is None:
            raise CapabilityError("QASP token required: no meta provided")

        token_b64 = meta.get("qasp_token")
        if token_b64 is None:
            raise CapabilityError("QASP token required: qasp_token missing from meta")

        token_cbor = base64.b64decode(token_b64)
        token = CapabilityToken.from_cbor(token_cbor)

        verify_token(token, self._issuer_public_key)

        expected_uri = f"qasp://mcp/tools/{name}"
        if token.resource_uri != expected_uri:
            raise CapabilityError(
                f"Token resource URI mismatch: expected {expected_uri}, "
                f"got {token.resource_uri}"
            )

        if "execute" not in token.verbs:
            raise CapabilityError(
                f"Token does not grant 'execute' verb for tool {name}"
            )

        return self._backend.execute_tool(name, arguments)

    def list_resources(self) -> list[dict[str, Any]]:
        """List available MCP resources."""
        return self._backend.list_resources()

    def read_resource(self, uri: str) -> Any:
        """Read an MCP resource."""
        return self._backend.read_resource(uri)


class QASPToolProvider:
    """Expose QASP capabilities as MCP tools.

    Allows MCP clients to interact with QASP agents.
    """

    def __init__(
        self,
        tools: list[dict[str, Any]],
        handler: Any = None,
        issuer_public_key: bytes | None = None,
    ) -> None:
        """Initialize the tool provider.

        Args:
            tools: List of tool definitions.
            handler: Callable to handle tool calls.
            issuer_public_key: Public key for token verification.
        """
        self._tools = tools
        self._handler = handler
        self._issuer_public_key = issuer_public_key

    def get_tools(self) -> list[dict[str, Any]]:
        """Get tool definitions for QASP capabilities.

        Returns:
            List of MCP tool definitions.
        """
        return list(self._tools)

    def handle_call(
        self,
        name: str,
        arguments: dict[str, Any],
        token: CapabilityToken | None = None,
    ) -> Any:
        """Handle an MCP tool call.

        Args:
            name: The tool name.
            arguments: Tool arguments.
            token: Optional QASP token for verification.

        Returns:
            The call result.

        Raises:
            InvalidTokenError: If token verification fails.
        """
        if token is not None and self._issuer_public_key is not None:
            verify_token(token, self._issuer_public_key)

        if self._handler is not None:
            return self._handler(name, arguments)
        raise InvalidTokenError(f"No handler registered for tool {name}")

    @staticmethod
    def inject_token_meta(token: CapabilityToken) -> dict[str, Any]:
        """Create meta dict with QASP token for MCP call_tool.

        Args:
            token: The QASP capability token.

        Returns:
            Dict with qasp_token_id and qasp_token fields.
        """
        return {
            "qasp_token_id": token.token_id.hex(),
            "qasp_token": base64.b64encode(token.to_cbor_with_signature()).decode(),
        }
