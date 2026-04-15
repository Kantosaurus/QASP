"""QASP MCP Server — Expose the QASP protocol as MCP tools.

Lets any MCP-capable AI agent (OpenClaw, Claude, etc.) join a QASP
network without knowing anything about the protocol. The agent sees
standard MCP tools and calls them naturally.

Run (stdio, for MCP client config):
    python scripts/qasp_mcp_server.py

Run (SSE, for remote agents):
    python scripts/qasp_mcp_server.py --transport sse --port 8888

The server expects a running QASP Authority Server. Set the URL via
--server flag or QASP_SERVER_URL env var (default: http://localhost:8080).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

logger = logging.getLogger("qasp.mcp")

# ============================================================================
# QASP client (embedded, no import dependency on scripts/)
# ============================================================================


class _QASPClient:
    """Minimal QASP REST client embedded for standalone use."""

    def __init__(self, server_url: str, timeout: float = 30.0) -> None:
        self._base = server_url.rstrip("/")
        self._timeout = timeout
        self.api_key: str | None = None
        self.did: str | None = None
        self.name: str | None = None

    def _headers(self) -> dict[str, str]:
        h: dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            h["X-API-Key"] = self.api_key
        return h

    def _request(
        self,
        method: str,
        path: str,
        json_body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> Any:
        with httpx.Client(timeout=self._timeout) as client:
            resp = client.request(
                method,
                f"{self._base}{path}",
                json=json_body,
                params=params,
                headers=self._headers(),
            )
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                detail = resp.text
            raise RuntimeError(f"QASP server error (HTTP {resp.status_code}): {detail}")
        return resp.json()


# ============================================================================
# Session state — tracks registered agents by name
# ============================================================================

_server_url: str = "http://localhost:8080"
_sessions: dict[str, _QASPClient] = {}
_token_cache: dict[str, dict[str, Any]] = {}  # "did:target_did:tool" -> token info


def _get_session(agent_name: str) -> _QASPClient:
    """Look up a registered session by agent name."""
    client = _sessions.get(agent_name)
    if client is None:
        registered = list(_sessions.keys()) or ["(none)"]
        raise RuntimeError(
            f"Agent '{agent_name}' is not registered. "
            f"Call qasp_register first. Registered agents: {', '.join(registered)}"
        )
    return client


# ============================================================================
# MCP Server
# ============================================================================

mcp = FastMCP(
    "qasp-protocol",
    instructions=(
        "QASP (Quantum-Aware Secure Protocol) tools for secure agent-to-agent "
        "communication. Workflow: 1) qasp_register to join the network, "
        "2) qasp_discover to find other agents, 3) qasp_request_token to get "
        "permission for a specific tool, 4) qasp_call_tool to invoke it. "
        "Tokens are scoped per-tool, rate-limited, and expire after 1 hour."
    ),
)


# -- Server info -------------------------------------------------------------

@mcp.tool()
def qasp_server_info() -> dict[str, Any]:
    """Get QASP Authority Server status.

    Returns the server's DID, version, number of registered agents,
    and list of active security features. Use this to verify the
    server is running before registering.
    """
    client = _QASPClient(_server_url)
    return client._request("GET", "/")


# -- Registration ------------------------------------------------------------

@mcp.tool()
def qasp_register(
    agent_name: str,
    tools: list[dict[str, str]] | None = None,
    callback_url: str = "",
) -> dict[str, Any]:
    """Register an agent with the QASP authority server.

    This creates a post-quantum identity (ML-DSA-65 keypair + did:qasp DID)
    for the agent and returns credentials for all subsequent operations.

    Args:
        agent_name: Human-readable name for this agent (e.g. "ResearchBot").
        tools: Tools this agent offers to others. Each dict needs "name" and
               "description" keys. Example: [{"name": "summarize",
               "description": "Summarize text"}]. Pass empty list or None
               if this agent only consumes tools.
        callback_url: URL where the server relays incoming tool calls.
                      Only needed if this agent serves tools to others.
                      Example: "http://localhost:9001".

    Returns:
        Dict with agent_id, did, api_key, public_key.
        The api_key is stored automatically for subsequent calls.
    """
    if agent_name in _sessions:
        client = _sessions[agent_name]
        return {
            "status": "already_registered",
            "agent_name": agent_name,
            "did": client.did,
            "message": f"Agent '{agent_name}' is already registered. Use its name in other tools.",
        }

    client = _QASPClient(_server_url)
    result = client._request("POST", "/register", json_body={
        "name": agent_name,
        "tools": tools or [],
        "callback_url": callback_url,
    })
    client.api_key = result["api_key"]
    client.did = result["did"]
    client.name = agent_name
    _sessions[agent_name] = client

    return {
        "agent_name": agent_name,
        "did": result["did"],
        "agent_id": result["agent_id"],
        "message": (
            f"Agent '{agent_name}' registered successfully with DID {result['did']}. "
            f"Use agent_name='{agent_name}' in all subsequent QASP tool calls."
        ),
    }


@mcp.tool()
def qasp_unregister(agent_name: str) -> dict[str, Any]:
    """Unregister an existing MCP session from the QASP authority.

    Args:
        agent_name: Name of your registered agent.

    Returns:
        Confirmation that the agent identity has been removed.
    """
    client = _get_session(agent_name)
    result = client._request("DELETE", "/unregister")

    did = client.did
    _sessions.pop(agent_name, None)

    if did:
        keys_to_drop = [k for k in _token_cache if k.startswith(f"{did}:")]
        for key in keys_to_drop:
            _token_cache.pop(key, None)

    return {
        "agent_name": agent_name,
        "did": result.get("did", did),
        "unregistered": bool(result.get("unregistered", False)),
        "message": f"Agent '{agent_name}' unregistered successfully.",
    }


# -- Discovery ---------------------------------------------------------------

@mcp.tool()
def qasp_discover(
    agent_name: str,
    capability: str = "*",
    min_trust: float = 0.0,
) -> list[dict[str, Any]]:
    """Discover other agents registered on the QASP network.

    Returns a list of agents with their tools, trust scores, and endpoints,
    sorted by trust score (highest first).

    Args:
        agent_name: Name of your registered agent (used for authentication).
        capability: Filter by ARM resource URI pattern. Use "*" for all agents,
                    or a pattern like "qasp://*/tools/summarize" to find agents
                    with a specific tool.
        min_trust: Minimum Bayesian trust score (0.0 to 1.0). Agents below
                   this threshold are excluded.

    Returns:
        List of agent dicts, each with name, did, tools, trust_score, endpoint.
    """
    client = _get_session(agent_name)
    agents = client._request("GET", "/discover", params={
        "capability": capability,
        "min_trust": min_trust,
    })

    # Annotate with helpful context
    for agent in agents:
        tool_names = [t["name"] for t in agent.get("tools", [])]
        agent["available_tools"] = tool_names

    return agents


# -- Token operations --------------------------------------------------------

@mcp.tool()
def qasp_request_token(
    agent_name: str,
    target_did: str,
    tool_name: str,
) -> dict[str, Any]:
    """Request a capability token to call a specific tool on another agent.

    The QASP authority signs a token (ML-DSA-65 post-quantum signature) that
    grants permission to call exactly one tool on one target agent. Tokens
    are rate-limited (10 calls per 60 seconds) and expire after 1 hour.

    You MUST request a token before calling qasp_call_tool.

    Args:
        agent_name: Name of your registered agent.
        target_did: The DID of the agent whose tool you want to call.
                    Get this from qasp_discover results.
        tool_name: Name of the tool you want to call on the target agent.

    Returns:
        Dict with token (base64 string to pass to qasp_call_tool),
        token_id (for status checks or revocation), resource_uri,
        verbs, and expires_at.
    """
    client = _get_session(agent_name)
    result = client._request("POST", "/tokens/request", json_body={
        "target_did": target_did,
        "tool_name": tool_name,
    })

    # Cache the token for convenience
    cache_key = f"{client.did}:{target_did}:{tool_name}"
    _token_cache[cache_key] = result

    return {
        **result,
        "message": (
            f"Token granted for tool '{tool_name}' on {target_did}. "
            f"Rate limit: 10 calls/60s. Expires: {result.get('expires_at', 'unknown')}. "
            f"Pass the 'token' value to qasp_call_tool."
        ),
    }


@mcp.tool()
def qasp_check_token(token_id: str) -> dict[str, Any]:
    """Check whether a capability token is still valid (OCSP status query).

    Args:
        token_id: Hex-encoded token ID from qasp_request_token result.

    Returns:
        Dict with token_id and status ("GOOD", "REVOKED", or "UNKNOWN").
        If revoked, includes revoked_at timestamp.
    """
    client = _QASPClient(_server_url)
    return client._request("GET", f"/tokens/status/{token_id}")


@mcp.tool()
def qasp_revoke_token(agent_name: str, token_id: str) -> dict[str, Any]:
    """Revoke a capability token so it can no longer be used.

    Revocation is immediate — the token is added to the Certificate
    Revocation List (CRL) and any subsequent call using it will be
    rejected with a 403 error.

    Args:
        agent_name: Name of your registered agent.
        token_id: Hex-encoded token ID from qasp_request_token result.

    Returns:
        Confirmation with revocation details.
    """
    client = _get_session(agent_name)
    return client._request("POST", "/tokens/revoke", json_body={
        "token_id": token_id,
    })


# -- Tool calling ------------------------------------------------------------

@mcp.tool()
def qasp_call_tool(
    agent_name: str,
    target_did: str,
    tool_name: str,
    arguments: dict[str, Any],
    token: str,
) -> dict[str, Any]:
    """Call a tool on another agent through the QASP authority server.

    The server performs a 7-step verified relay:
    1. Verify ML-DSA-65 signature on the capability token
    2. Check token has not expired
    3. Check token is not revoked (CRL lookup)
    4. Verify ARM resource URI scope matches the target tool
    5. Verify the 'exec' verb is permitted
    6. Check token-bucket rate limit
    7. Relay the call to the target agent's callback URL

    Args:
        agent_name: Name of your registered agent.
        target_did: DID of the agent whose tool you're calling.
        tool_name: Name of the tool to invoke.
        arguments: Dict of arguments to pass to the tool.
        token: Base64-encoded capability token from qasp_request_token.

    Returns:
        Dict with result (the tool's response), metering (cost info),
        and receipt_id (for audit trail).
    """
    client = _get_session(agent_name)
    return client._request("POST", "/tools/call", json_body={
        "target_did": target_did,
        "tool_name": tool_name,
        "arguments": arguments,
        "token": token,
    })


# -- Trust -------------------------------------------------------------------

@mcp.tool()
def qasp_get_trust(target_did: str) -> dict[str, Any]:
    """Query an agent's Bayesian trust score.

    Trust scores range from 0.0 to 1.0 and are composed of:
    - reputation: Based on interaction success/failure history
    - certification: Based on audit certification (if any)
    - behavioral: Based on behavioral verification
    - witness: Based on third-party attestations
    - confidence: How reliable the score is (increases with interactions)

    Args:
        target_did: DID of the agent to query.

    Returns:
        Dict with overall score, interaction_count, and component breakdown.
    """
    client = _QASPClient(_server_url)
    return client._request("GET", f"/trust/{target_did}")


@mcp.tool()
def qasp_report_interaction(
    agent_name: str,
    target_did: str,
    outcome: str,
    details: str = "",
) -> dict[str, Any]:
    """Report the outcome of an interaction to update trust scores.

    Call this after using qasp_call_tool to feed the Bayesian trust
    system. Positive reports increase trust; negative reports decrease it.
    Trust updates are capped to prevent gaming.

    Args:
        agent_name: Name of your registered agent.
        target_did: DID of the agent you interacted with.
        outcome: "success" or "failure".
        details: Optional description of what happened.

    Returns:
        Updated trust information for the target agent.
    """
    client = _get_session(agent_name)
    return client._request("POST", f"/trust/{target_did}/report", json_body={
        "outcome": outcome,
        "details": details,
    })


# -- Disputes ----------------------------------------------------------------

@mcp.tool()
def qasp_open_dispute(
    agent_name: str,
    respondent_did: str,
    dispute_type: str,
    description: str = "",
) -> dict[str, Any]:
    """Open a formal dispute against another agent.

    Use this when an agent behaves badly — overcharges, returns garbage
    data, fails to respond, etc. Disputes are tracked by the authority
    server and can be retrieved later.

    Args:
        agent_name: Name of your registered agent (the claimant).
        respondent_did: DID of the agent you're filing against.
        dispute_type: Category of dispute. Common types: "overcharge",
                      "service_failure", "data_quality", "timeout",
                      "unauthorized_access".
        description: Detailed description of the issue.

    Returns:
        Dict with dispute_id and status ("OPEN").
    """
    client = _get_session(agent_name)
    return client._request("POST", "/disputes/open", json_body={
        "respondent_did": respondent_did,
        "type": dispute_type,
        "description": description,
    })


@mcp.tool()
def qasp_get_dispute(dispute_id: str) -> dict[str, Any]:
    """Get the status and details of a dispute.

    Args:
        dispute_id: The dispute ID returned by qasp_open_dispute.

    Returns:
        Full dispute record including claimant, respondent, type,
        description, status, opened_at, and verdict (if resolved).
    """
    client = _QASPClient(_server_url)
    return client._request("GET", f"/disputes/{dispute_id}")


# -- Convenience: discover + call in one shot --------------------------------

@mcp.tool()
def qasp_find_and_call(
    agent_name: str,
    tool_name: str,
    arguments: dict[str, Any],
    min_trust: float = 0.0,
) -> dict[str, Any]:
    """Find an agent with a specific tool and call it in one step.

    Convenience tool that combines discover, request_token, and call_tool.
    Picks the highest-trust agent that has the requested tool.

    Args:
        agent_name: Name of your registered agent.
        tool_name: Name of the tool you want to call.
        arguments: Arguments to pass to the tool.
        min_trust: Minimum trust score for the target agent.

    Returns:
        Dict with target agent info, the tool result, and metering data.
        Returns an error if no agent with the requested tool is found.
    """
    client = _get_session(agent_name)

    # Discover agents with matching tool
    agents = client._request("GET", "/discover", params={
        "capability": f"qasp://*/tools/{tool_name}",
        "min_trust": min_trust,
    })

    if not agents:
        return {
            "error": f"No agent found with tool '{tool_name}' (min_trust={min_trust})",
            "suggestion": "Try qasp_discover with capability='*' to see all available agents and tools.",
        }

    # Pick the highest-trust agent (list is pre-sorted by server)
    target = agents[0]
    target_did = target["did"]

    # Request token
    token_info = client._request("POST", "/tokens/request", json_body={
        "target_did": target_did,
        "tool_name": tool_name,
    })

    # Call the tool
    result = client._request("POST", "/tools/call", json_body={
        "target_did": target_did,
        "tool_name": tool_name,
        "arguments": arguments,
        "token": token_info["token"],
    })

    return {
        "target_agent": target["name"],
        "target_did": target_did,
        "target_trust": target.get("trust_score"),
        "token_id": token_info["token_id"],
        "result": result.get("result"),
        "metering": result.get("metering"),
        "receipt_id": result.get("receipt_id"),
    }


# ============================================================================
# Entry point
# ============================================================================


def main() -> None:
    parser = argparse.ArgumentParser(description="QASP MCP Server")
    parser.add_argument(
        "--server",
        default=os.environ.get("QASP_SERVER_URL", "http://localhost:8080"),
        help="QASP Authority Server URL (default: $QASP_SERVER_URL or http://localhost:8080)",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="MCP transport (default: stdio)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8888,
        help="Port for SSE transport (default: 8888)",
    )
    parser.add_argument(
        "--log-level",
        default="info",
        help="Log level (default: info)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )

    global _server_url
    _server_url = args.server

    logger.info("QASP MCP Server starting")
    logger.info("  Authority server: %s", _server_url)
    logger.info("  Transport: %s", args.transport)

    if args.transport == "sse":
        logger.info("  SSE port: %d", args.port)
        mcp.run(transport="sse", port=args.port)
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
