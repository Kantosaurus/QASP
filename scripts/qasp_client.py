"""QASP Client — Simple REST wrapper for the QASP Authority Server.

Usage:
    from scripts.qasp_client import QASPClient

    qasp = QASPClient("http://localhost:8080")
    me = qasp.register("MyAgent", [{"name": "echo", "description": "Echo input"}])
    agents = qasp.discover()
    token = qasp.request_token(agents[0]["did"], "echo")
    result = qasp.call_tool(agents[0]["did"], "echo", {"msg": "hi"}, token["token"])
"""

from __future__ import annotations

from typing import Any

import httpx


class QASPError(Exception):
    """Raised when the QASP server returns an error."""

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"HTTP {status_code}: {detail}")


class QASPClient:
    """Thin REST client for a QASP authority server."""

    def __init__(self, server_url: str, timeout: float = 30.0) -> None:
        """Connect to a QASP authority server.

        Args:
            server_url: Base URL of the server (e.g. "http://localhost:8080").
            timeout: HTTP request timeout in seconds.
        """
        self._base = server_url.rstrip("/")
        self._timeout = timeout
        self._api_key: str | None = None
        self._did: str | None = None

    # -- internal helpers ---------------------------------------------------

    def _headers(self) -> dict[str, str]:
        h: dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            h["X-API-Key"] = self._api_key
        return h

    def _request(
        self,
        method: str,
        path: str,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        with httpx.Client(timeout=self._timeout) as client:
            resp = client.request(
                method,
                f"{self._base}{path}",
                json=json,
                params=params,
                headers=self._headers(),
            )
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                detail = resp.text
            raise QASPError(resp.status_code, detail)
        return resp.json()

    # -- public API ---------------------------------------------------------

    def info(self) -> dict[str, Any]:
        """Get server info."""
        return self._request("GET", "/")

    def register(
        self,
        name: str,
        tools: list[dict[str, Any]],
        callback_url: str = "",
    ) -> dict[str, Any]:
        """Register this agent with the authority.

        Args:
            name: Human-readable agent name.
            tools: List of tool definitions, each with "name" and "description".
            callback_url: Optional URL where the server relays tool calls.

        Returns:
            Dict with agent_id, did, api_key, public_key.
        """
        result = self._request("POST", "/register", json={
            "name": name,
            "tools": tools,
            "callback_url": callback_url,
        })
        self._api_key = result["api_key"]
        self._did = result["did"]
        return result

    def discover(
        self,
        capability: str = "*",
        min_trust: float = 0.0,
    ) -> list[dict[str, Any]]:
        """Find other registered agents.

        Args:
            capability: Capability URI pattern (supports wildcards).
            min_trust: Minimum trust score threshold.

        Returns:
            List of agent info dicts.
        """
        return self._request("GET", "/discover", params={
            "capability": capability,
            "min_trust": min_trust,
        })

    def request_token(
        self,
        target_did: str,
        tool_name: str,
        verbs: list[str] | None = None,
    ) -> dict[str, Any]:
        """Request a QASP capability token for calling a tool.

        Args:
            target_did: DID of the agent whose tool you want to call.
            tool_name: Name of the tool.
            verbs: Permitted operations (default: ["exec"]).

        Returns:
            Dict with token (base64), token_id, resource_uri, expires_at.
        """
        return self._request("POST", "/tokens/request", json={
            "target_did": target_did,
            "tool_name": tool_name,
            "verbs": verbs,
        })

    def call_tool(
        self,
        target_did: str,
        tool_name: str,
        arguments: dict[str, Any],
        token: str,
    ) -> dict[str, Any]:
        """Call a tool on another agent (relayed through the server).

        Args:
            target_did: DID of the target agent.
            tool_name: Name of the tool to invoke.
            arguments: Tool arguments.
            token: Base64-encoded QASP capability token.

        Returns:
            Dict with result, metering, receipt_id.
        """
        return self._request("POST", "/tools/call", json={
            "target_did": target_did,
            "tool_name": tool_name,
            "arguments": arguments,
            "token": token,
        })

    def revoke_token(self, token_id: str) -> dict[str, Any]:
        """Revoke a previously issued token.

        Args:
            token_id: Hex-encoded token ID.

        Returns:
            Confirmation dict.
        """
        return self._request("POST", "/tokens/revoke", json={
            "token_id": token_id,
        })

    def check_token(self, token_id: str) -> dict[str, Any]:
        """Check token status via OCSP.

        Args:
            token_id: Hex-encoded token ID.

        Returns:
            Dict with status ("GOOD", "REVOKED", or "UNKNOWN").
        """
        return self._request("GET", f"/tokens/status/{token_id}")

    def get_trust(self, did: str) -> dict[str, Any]:
        """Query an agent's trust score.

        Args:
            did: The agent's DID string.

        Returns:
            Dict with score, interaction_count, components.
        """
        return self._request("GET", f"/trust/{did}")

    def report_interaction(self, did: str, outcome: str, details: str = "") -> dict[str, Any]:
        """Report an interaction outcome to update trust scores.

        Args:
            did: DID of the agent to report on.
            outcome: "success" or "failure".
            details: Optional description.

        Returns:
            Updated trust info.
        """
        return self._request("POST", f"/trust/{did}/report", json={
            "outcome": outcome,
            "details": details,
        })

    def open_dispute(
        self,
        respondent_did: str,
        dispute_type: str,
        description: str = "",
    ) -> dict[str, Any]:
        """File a dispute against another agent.

        Args:
            respondent_did: DID of the agent being disputed.
            dispute_type: Type of dispute (e.g. "overcharge").
            description: Description of the issue.

        Returns:
            Dict with dispute_id and status.
        """
        return self._request("POST", "/disputes/open", json={
            "respondent_did": respondent_did,
            "type": dispute_type,
            "description": description,
        })

    def get_dispute(self, dispute_id: str) -> dict[str, Any]:
        """Get dispute status.

        Args:
            dispute_id: The dispute ID.

        Returns:
            Full dispute record.
        """
        return self._request("GET", f"/disputes/{dispute_id}")
