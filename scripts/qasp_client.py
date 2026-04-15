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

import asyncio
import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from threading import Lock
from typing import Any, Callable

import httpx

logger = logging.getLogger(__name__)


class QASPError(Exception):
    """Raised when the QASP server returns an error."""

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"HTTP {status_code}: {detail}")


# -- NLP conversation logging -----------------------------------------------


class MessageDirection(str, Enum):
    SENT = "sent"
    RECEIVED = "received"


@dataclass
class LogEntry:
    direction: MessageDirection
    sender_name: str
    content: str
    intent: str | None
    timestamp: str
    message_id: str
    reply_to: str | None = None

    def format(self) -> str:
        arrow = ">>" if self.direction == MessageDirection.SENT else "<<"
        tag = f" [{self.intent}]" if self.intent else ""
        return f"  {arrow} [{self.timestamp}] {self.sender_name}{tag}: {self.content}"


class ConversationLog:
    """Thread-safe in-memory log for a single conversation."""

    def __init__(
        self,
        conversation_id: str,
        agent_name: str,
        partner_name: str = "",
        partner_did: str = "",
        topic: str = "",
    ) -> None:
        self.conversation_id = conversation_id
        self.agent_name = agent_name
        self.partner_name = partner_name
        self.partner_did = partner_did
        self.topic = topic
        self.entries: list[LogEntry] = []
        self._lock = Lock()

    def log_outgoing(
        self,
        message_id: str,
        content: str,
        intent: str | None = None,
        timestamp: str = "",
        reply_to: str | None = None,
    ) -> None:
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        with self._lock:
            self.entries.append(LogEntry(
                direction=MessageDirection.SENT,
                sender_name=self.agent_name,
                content=content,
                intent=intent,
                timestamp=ts,
                message_id=message_id,
                reply_to=reply_to,
            ))

    def log_incoming(
        self,
        message_id: str,
        sender_name: str,
        content: str,
        intent: str | None = None,
        timestamp: str = "",
        reply_to: str | None = None,
    ) -> None:
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        with self._lock:
            self.entries.append(LogEntry(
                direction=MessageDirection.RECEIVED,
                sender_name=sender_name,
                content=content,
                intent=intent,
                timestamp=ts,
                message_id=message_id,
                reply_to=reply_to,
            ))

    def format_transcript(self) -> str:
        with self._lock:
            lines: list[str] = []
            if self.topic:
                lines.append(f"Topic: {self.topic}")
            lines.append(f"Participants: {self.agent_name}, {self.partner_name or self.partner_did}")
            lines.append("")
            for entry in self.entries:
                lines.append(entry.format())
            return "\n".join(lines)

    def __len__(self) -> int:
        with self._lock:
            return len(self.entries)


# -- intent classification (rule-based, no ML dependencies) -----------------

_GREETING_WORDS = re.compile(
    r"^(hi|hello|hey|greetings|good\s+(morning|afternoon|evening)|howdy|yo)\b",
    re.IGNORECASE,
)
_FAREWELL_WORDS = re.compile(
    r"\b(goodbye|bye|farewell|see\s+you|take\s+care|signing\s+off)\b",
    re.IGNORECASE,
)
_REQUEST_PHRASES = re.compile(
    r"\b(could\s+you|please|can\s+you|would\s+you|i\s+need|send\s+me|help\s+me|"
    r"look\s+up|fetch|retrieve|get\s+me|find)\b",
    re.IGNORECASE,
)
_RESPONSE_WORDS = re.compile(
    r"^(sure|yes|no|okay|ok|done|here|absolutely|of\s+course|certainly|right)\b",
    re.IGNORECASE,
)
_NOTIFICATION_WORDS = re.compile(
    r"\b(alert|notice|update|fyi|heads\s+up|warning|reminder|letting\s+you\s+know)\b",
    re.IGNORECASE,
)


def _classify_intent(text: str) -> str:
    """Classify a message's conversational intent (rule-based)."""
    stripped = text.strip()
    if stripped.endswith("?"):
        return "question"
    if _GREETING_WORDS.search(stripped):
        return "greeting"
    if _FAREWELL_WORDS.search(stripped):
        return "farewell"
    if _REQUEST_PHRASES.search(stripped):
        return "request"
    if _RESPONSE_WORDS.search(stripped):
        return "response"
    if _NOTIFICATION_WORDS.search(stripped):
        return "notification"
    return "statement"


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
        self._agent_name: str = ""
        self._conversations: dict[str, ConversationLog] = {}

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
        self._agent_name = name
        return result

    def unregister(self) -> dict[str, Any]:
        """Unregister this agent identity from the authority.

        Returns:
            Dict with unregistered status and DID details.
        """
        result = self._request("DELETE", "/unregister")
        self._api_key = None
        self._did = None
        self._agent_name = ""
        self._conversations.clear()
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

    # -- messaging ----------------------------------------------------------

    def open_conversation(
        self,
        target_did: str,
        topic: str = "",
    ) -> dict[str, Any]:
        """Open a conversation with another agent.

        Args:
            target_did: DID of the agent to converse with.
            topic: Optional conversation topic.

        Returns:
            Dict with conversation_id, token, token_id, resource_uri,
            participants, created_at.
        """
        result = self._request("POST", "/conversations/open", json={
            "target_did": target_did,
            "topic": topic,
        })
        cid = result["conversation_id"]
        self._conversations[cid] = ConversationLog(
            conversation_id=cid,
            agent_name=self._agent_name,
            partner_did=target_did,
            topic=topic,
        )
        return result

    def send_message(
        self,
        conversation_id: str,
        content: str,
        token: str,
        content_type: str = "text/plain",
        reply_to: str | None = None,
        intent: str | None = None,
    ) -> dict[str, Any]:
        """Send a message in a conversation.

        Args:
            conversation_id: The conversation to send in.
            content: Message content (natural language).
            token: Base64-encoded QASP capability token.
            content_type: MIME type of content.
            reply_to: Optional message_id to reply to.
            intent: Optional intent tag (auto-classified if omitted).

        Returns:
            Dict with message_id, conversation_id, delivered, metering,
            receipt_id.
        """
        classified = intent or _classify_intent(content)
        payload: dict[str, Any] = {
            "conversation_id": conversation_id,
            "content": content,
            "token": token,
            "content_type": content_type,
            "intent": classified,
        }
        if reply_to:
            payload["reply_to"] = reply_to
        result = self._request("POST", "/messages/send", json=payload)
        log = self._conversations.get(conversation_id)
        if log:
            log.log_outgoing(
                result["message_id"], content, classified,
                datetime.now(timezone.utc).isoformat(), reply_to,
            )
        return result

    # -- NLP convenience methods --------------------------------------------

    def say(
        self,
        conversation_id: str,
        message: str,
        token: str,
        reply_to: str | None = None,
    ) -> dict[str, Any]:
        """Send a natural-language message in a conversation.

        Args:
            conversation_id: The conversation to send in.
            message: What you want to say (plain text).
            token: Base64-encoded QASP capability token.
            reply_to: Optional message_id to reply to.
        """
        return self.send_message(conversation_id, message, token, reply_to=reply_to)

    def ask(
        self,
        conversation_id: str,
        question: str,
        token: str,
        reply_to: str | None = None,
    ) -> dict[str, Any]:
        """Ask a question in a conversation. Appends '?' if missing.

        Args:
            conversation_id: The conversation to send in.
            question: The question to ask.
            token: Base64-encoded QASP capability token.
            reply_to: Optional message_id to reply to.
        """
        if not question.rstrip().endswith("?"):
            question = question.rstrip() + "?"
        return self.send_message(
            conversation_id, question, token,
            reply_to=reply_to, intent="question",
        )

    def reply(
        self,
        conversation_id: str,
        message: str,
        token: str,
        to_message_id: str,
    ) -> dict[str, Any]:
        """Reply to a specific message in the conversation.

        Args:
            conversation_id: The conversation to send in.
            message: Your reply text.
            token: Base64-encoded QASP capability token.
            to_message_id: The message_id you are replying to.
        """
        return self.send_message(
            conversation_id, message, token, reply_to=to_message_id,
        )

    def greet(
        self,
        conversation_id: str,
        token: str,
        greeting: str = "",
    ) -> dict[str, Any]:
        """Send a greeting in the conversation.

        Args:
            conversation_id: The conversation to send in.
            token: Base64-encoded QASP capability token.
            greeting: Custom greeting text (uses a default if empty).
        """
        text = greeting or f"Hello from {self._agent_name}! How can I help you today?"
        return self.send_message(
            conversation_id, text, token, intent="greeting",
        )

    def farewell(
        self,
        conversation_id: str,
        token: str,
        message: str = "",
    ) -> dict[str, Any]:
        """Send a farewell and close the conversation.

        Args:
            conversation_id: The conversation to send in.
            token: Base64-encoded QASP capability token.
            message: Custom farewell text (uses a default if empty).

        Returns:
            Dict with conversation_id, status, closed_at, closed_by.
        """
        text = message or f"Thanks for the conversation! Goodbye from {self._agent_name}."
        self.send_message(conversation_id, text, token, intent="farewell")
        return self.close_conversation(conversation_id)

    # -- conversation log access --------------------------------------------

    def get_transcript(self, conversation_id: str) -> str:
        """Get a formatted local transcript of the conversation.

        Args:
            conversation_id: The conversation to get the transcript for.

        Returns:
            Human-readable transcript string.
        """
        log = self._conversations.get(conversation_id)
        if log:
            return log.format_transcript()
        return "(no local log for this conversation)"

    def get_server_transcript(self, conversation_id: str) -> dict[str, Any]:
        """Fetch the authoritative transcript from the server.

        Args:
            conversation_id: The conversation to get the transcript for.

        Returns:
            Dict with conversation_id, topic, transcript, message_count.
        """
        return self._request(
            "GET", f"/conversations/{conversation_id}/transcript",
        )

    def get_conversation_log(self, conversation_id: str) -> ConversationLog | None:
        """Get the local ConversationLog object for direct access.

        Args:
            conversation_id: The conversation to look up.

        Returns:
            The ConversationLog or None if not tracked locally.
        """
        return self._conversations.get(conversation_id)

    # -- core messaging (continued) -----------------------------------------

    def list_conversations(
        self,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        """List conversations this agent participates in.

        Args:
            status: Filter by status ("ACTIVE" or "CLOSED").

        Returns:
            List of conversation info dicts.
        """
        params: dict[str, Any] = {}
        if status:
            params["status"] = status
        return self._request("GET", "/conversations", params=params)

    def get_messages(
        self,
        conversation_id: str,
        since: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Get messages in a conversation.

        Args:
            conversation_id: The conversation to query.
            since: ISO timestamp to filter messages after.
            limit: Maximum number of messages to return.

        Returns:
            Dict with conversation_id, messages list, total.
        """
        params: dict[str, Any] = {"limit": limit}
        if since:
            params["since"] = since
        return self._request(
            "GET", f"/conversations/{conversation_id}/messages", params=params,
        )

    def close_conversation(self, conversation_id: str) -> dict[str, Any]:
        """Close a conversation.

        Args:
            conversation_id: The conversation to close.

        Returns:
            Dict with conversation_id, status, closed_at, closed_by.
        """
        return self._request(
            "POST", f"/conversations/{conversation_id}/close",
        )

    def get_inbox(self, limit: int = 50) -> list[dict[str, Any]]:
        """Poll for undelivered messages and auto-log them.

        Args:
            limit: Maximum number of messages to return.

        Returns:
            Dict with messages list and total.
        """
        result = self._request("GET", "/messages/inbox", params={"limit": limit})
        for msg in result.get("messages", []):
            cid = msg.get("conversation_id", "")
            log = self._conversations.get(cid)
            if log is None:
                log = ConversationLog(
                    conversation_id=cid,
                    agent_name=self._agent_name,
                    partner_name=msg.get("sender_name", ""),
                    partner_did=msg.get("sender_did", ""),
                )
                self._conversations[cid] = log
            log.log_incoming(
                message_id=msg.get("message_id", ""),
                sender_name=msg.get("sender_name", msg.get("sender_did", "unknown")),
                content=msg.get("content", ""),
                intent=msg.get("intent"),
                timestamp=msg.get("created_at", ""),
                reply_to=msg.get("reply_to"),
            )
        return result

    def acknowledge_message(self, message_id: str) -> dict[str, Any]:
        """Acknowledge receipt of a message.

        Args:
            message_id: The message to acknowledge.

        Returns:
            Confirmation dict.
        """
        return self._request("POST", "/messages/acknowledge", json={
            "message_id": message_id,
        })

    def request_message_token(
        self,
        target_did: str,
    ) -> dict[str, Any]:
        """Request a capability token for messaging another agent.

        Convenience method — calls request_token with tool_name="_messages"
        and verbs=["message"].

        Args:
            target_did: DID of the target agent.

        Returns:
            Dict with token (base64), token_id, resource_uri, expires_at.
        """
        return self.request_token(
            target_did, "_messages", verbs=["message"],
        )

    def create_websocket_listener(
        self,
        on_message: Callable[[dict], None] | None = None,
        on_conversation: Callable[[dict], None] | None = None,
        on_tool_call: Callable[[dict], dict] | None = None,
        on_token_revoked: Callable[[dict], None] | None = None,
        on_token_requested: Callable[[dict], None] | None = None,
        on_trust_updated: Callable[[dict], None] | None = None,
        on_dispute: Callable[[dict], None] | None = None,
        on_connect: Callable[[], None] | None = None,
        on_disconnect: Callable[[], None] | None = None,
    ) -> "QASPWebSocketListener":
        """Create a WebSocket listener for real-time server push.

        Call ``await listener.run()`` in an async context, or use
        ``asyncio.run(listener.run())`` from synchronous code.

        Callbacks:
            on_message: Called with message payload when a chat message arrives.
            on_conversation: Called when another agent opens a conversation.
            on_tool_call: Called when another agent invokes one of your tools.
                Must return a dict result that will be sent back to the caller.
            on_token_revoked: Called when one of your tokens is revoked.
            on_token_requested: Called when another agent requests a token for your tool.
            on_trust_updated: Called when your trust score changes.
            on_dispute: Called when a dispute is opened against you.
            on_connect / on_disconnect: Connection lifecycle callbacks.
        """
        if not self._api_key:
            raise QASPError(0, "Must register before creating WebSocket listener")
        return QASPWebSocketListener(
            server_url=self._base,
            api_key=self._api_key,
            conversations=self._conversations,
            agent_name=self._agent_name,
            on_message=on_message,
            on_conversation=on_conversation,
            on_tool_call=on_tool_call,
            on_token_revoked=on_token_revoked,
            on_token_requested=on_token_requested,
            on_trust_updated=on_trust_updated,
            on_dispute=on_dispute,
            on_connect=on_connect,
            on_disconnect=on_disconnect,
        )


class QASPWebSocketListener:
    """Async WebSocket listener for real-time communication with QASP server.

    Handles all server-to-agent push: messages, conversations, tool calls,
    token revocations, and disputes. For tool calls, the ``on_tool_call``
    callback must return a dict result — this is automatically sent back
    to the server so the calling agent receives the response.
    """

    def __init__(
        self,
        server_url: str,
        api_key: str,
        conversations: dict[str, ConversationLog] | None = None,
        agent_name: str = "",
        on_message: Callable[[dict], None] | None = None,
        on_relay_data: Callable[["Any"], None] | None = None,
        on_conversation: Callable[[dict], None] | None = None,
        on_tool_call: Callable[[dict], dict] | None = None,
        on_token_revoked: Callable[[dict], None] | None = None,
        on_token_requested: Callable[[dict], None] | None = None,
        on_trust_updated: Callable[[dict], None] | None = None,
        on_dispute: Callable[[dict], None] | None = None,
        on_connect: Callable[[], None] | None = None,
        on_disconnect: Callable[[], None] | None = None,
        reconnect_delay: float = 2.0,
        max_reconnect_delay: float = 60.0,
    ):
        ws_base = server_url.replace("https://", "wss://").replace("http://", "ws://")
        self._ws_url = f"{ws_base.rstrip('/')}/ws?api_key={api_key}"
        self._conversations = conversations if conversations is not None else {}
        self._agent_name = agent_name
        self._on_message = on_message
        self._on_relay_data = on_relay_data
        self._on_conversation = on_conversation
        self._on_tool_call = on_tool_call
        self._on_token_revoked = on_token_revoked
        self._on_token_requested = on_token_requested
        self._on_trust_updated = on_trust_updated
        self._on_dispute = on_dispute
        self._on_connect = on_connect
        self._on_disconnect = on_disconnect
        self._reconnect_delay = reconnect_delay
        self._max_reconnect_delay = max_reconnect_delay
        self._running = False
        self._ws = None
        # QASP-Relay (CapFlow) state
        self._relay_sessions: dict[bytes, Any] = {}  # session_id -> last-seen Grant
        self._relay_next_seq: dict[bytes, int] = {}
        self._pending_relay_frames: asyncio.Queue = asyncio.Queue()

    async def _handle(self, ws: Any, data: dict) -> None:
        """Dispatch an incoming WebSocket message to the appropriate callback."""
        msg_type = data.get("type", "")
        payload = data.get("payload", {})

        if msg_type == "message":
            # Auto-log incoming message
            cid = payload.get("conversation_id", "")
            log = self._conversations.get(cid)
            if log is None and cid:
                log = ConversationLog(
                    conversation_id=cid,
                    agent_name=self._agent_name,
                    partner_name=payload.get("sender_name", ""),
                    partner_did=payload.get("sender_did", ""),
                )
                self._conversations[cid] = log
            if log:
                log.log_incoming(
                    message_id=payload.get("message_id", ""),
                    sender_name=payload.get("sender_name", payload.get("sender_did", "unknown")),
                    content=payload.get("content", ""),
                    intent=payload.get("intent"),
                    timestamp=payload.get("created_at", ""),
                    reply_to=payload.get("reply_to"),
                )
            if self._on_message:
                self._on_message(payload)
        elif msg_type == "conversation_opened":
            # Auto-track new conversation
            cid = payload.get("conversation_id", "")
            if cid and cid not in self._conversations:
                self._conversations[cid] = ConversationLog(
                    conversation_id=cid,
                    agent_name=self._agent_name,
                    partner_name=payload.get("initiator_name", ""),
                    partner_did=payload.get("initiator_did", ""),
                    topic=payload.get("topic", ""),
                )
            if self._on_conversation:
                self._on_conversation(payload)
        elif msg_type == "tool_call":
            request_id = data.get("request_id")
            if self._on_tool_call and request_id:
                try:
                    result = self._on_tool_call(payload)
                except Exception as exc:
                    result = {"error": str(exc)}
                await ws.send(json.dumps({
                    "type": "tool_result",
                    "request_id": request_id,
                    "result": result,
                }))
            elif request_id:
                await ws.send(json.dumps({
                    "type": "tool_result",
                    "request_id": request_id,
                    "result": {"error": "No tool_call handler registered"},
                }))
        elif msg_type == "token_revoked":
            if self._on_token_revoked:
                self._on_token_revoked(payload)
        elif msg_type == "token_requested":
            if self._on_token_requested:
                self._on_token_requested(payload)
        elif msg_type == "trust_updated":
            if self._on_trust_updated:
                self._on_trust_updated(payload)
        elif msg_type == "dispute_opened":
            if self._on_dispute:
                self._on_dispute(payload)
        elif msg_type in ("connected", "pong"):
            pass
        else:
            logger.debug("Unhandled WebSocket message type: %s", msg_type)

    async def _handle_relay_bytes(self, frame: bytes) -> None:
        """Decode a CBOR relay frame and route to the appropriate handler."""
        try:
            from qasp.protocol.relay.messages import (
                RelayData,
                RelaySessionGrant,
                RelaySessionNotify,
                decode_relay_frame,
            )
            msg = decode_relay_frame(frame)
        except ValueError as exc:
            logger.warning("Ignoring malformed relay frame: %s", exc)
            return

        if isinstance(msg, RelaySessionGrant):
            # Cache so send_relay_data can use the SCM
            self._relay_sessions[msg.session_id] = msg
            await self._pending_relay_frames.put(msg)
        elif isinstance(msg, RelayData):
            if self._on_relay_data:
                try:
                    self._on_relay_data(msg)
                except Exception as exc:
                    logger.warning("on_relay_data callback raised: %s", exc)
        else:
            # Notify / Deny / Close / Accept — surface via the queue for callers to await
            await self._pending_relay_frames.put(msg)

    async def _await_relay(self, predicate, timeout: float = 5.0):
        """Pop frames from _pending_relay_frames until predicate(frame) is True."""
        async def _drain():
            while True:
                frame = await self._pending_relay_frames.get()
                if predicate(frame):
                    return frame
        return await asyncio.wait_for(_drain(), timeout=timeout)

    async def open_relay_session(
        self,
        target_did: str,
        capability_token_bytes: bytes,
        *,
        max_messages: int | None = 100,
        max_bytes: int | None = 10_000,
        duration_sec: int = 60,
        purpose: str | None = None,
        timeout: float = 5.0,
    ) -> "Any":
        """Send a RelaySessionRequest and wait for the matching RelaySessionGrant.

        Returns the Grant object (with session_id + scm).
        """
        from qasp.protocol.relay.messages import (
            RelaySessionGrant,
            RelaySessionParams,
            RelaySessionRequest,
        )
        if self._ws is None:
            raise RuntimeError("WebSocket is not connected")
        req = RelaySessionRequest(
            target_agent=target_did,
            capability_token=capability_token_bytes,
            session_params=RelaySessionParams(
                max_messages=max_messages,
                max_bytes=max_bytes,
                max_rate=None,
                duration_sec=duration_sec,
                purpose=purpose,
            ),
            ephemeral_pk=None,
            nonce=os.urandom(32),
        )
        await self._ws.send(req.to_cbor())
        grant = await self._await_relay(
            lambda m: isinstance(m, RelaySessionGrant),
            timeout=timeout,
        )
        self._relay_sessions[grant.session_id] = grant
        self._relay_next_seq.setdefault(grant.session_id, 1)
        return grant

    async def send_relay_data(
        self,
        session_id: bytes,
        payload: bytes,
        *,
        receipt_ack_seq: int | None = None,
    ) -> None:
        """Send a RelayData frame over an established relay session."""
        from qasp.protocol.relay.messages import RelayData
        if self._ws is None:
            raise RuntimeError("WebSocket is not connected")
        grant = self._relay_sessions.get(session_id)
        if grant is None:
            raise KeyError(f"no active relay session {session_id.hex()}")
        seq = self._relay_next_seq.get(session_id, 1)
        self._relay_next_seq[session_id] = seq + 1
        ack_bytes = (
            receipt_ack_seq.to_bytes(8, "big") if receipt_ack_seq is not None else None
        )
        frame = RelayData(
            session_id=session_id,
            scm=grant.scm,
            seq=seq,
            payload=payload,
            receipt_ack=ack_bytes,
        )
        await self._ws.send(frame.to_cbor())

    async def close_relay_session(
        self,
        session_id: bytes,
        reason_text: str = "done",
        reason_code: int = 0x26,
    ) -> None:
        """Close an established relay session."""
        from qasp.protocol.relay.messages import RelaySessionClose
        if self._ws is None:
            raise RuntimeError("WebSocket is not connected")
        frame = RelaySessionClose(
            session_id=session_id,
            reason_code=reason_code,
            reason_text=reason_text,
        )
        await self._ws.send(frame.to_cbor())
        self._relay_sessions.pop(session_id, None)
        self._relay_next_seq.pop(session_id, None)

    async def accept_relay_session(
        self, session_id: bytes, accepted: bool = True,
    ) -> None:
        """Respond to an incoming RelaySessionNotify by accepting (or declining)."""
        from qasp.protocol.relay.messages import RelaySessionAccept
        if self._ws is None:
            raise RuntimeError("WebSocket is not connected")
        frame = RelaySessionAccept(session_id=session_id, accepted=accepted)
        await self._ws.send(frame.to_cbor())

    async def await_relay_notify(self, timeout: float = 5.0) -> "Any":
        """Block until a RelaySessionNotify arrives."""
        from qasp.protocol.relay.messages import RelaySessionNotify
        return await self._await_relay(
            lambda m: isinstance(m, RelaySessionNotify), timeout=timeout,
        )

    async def run(self) -> None:
        """Connect and listen forever, reconnecting on failure."""
        try:
            import websockets  # noqa: F401
        except ImportError:
            raise ImportError(
                "The 'websockets' package is required for WebSocket support. "
                "Install it with: pip install websockets"
            )

        self._running = True
        delay = self._reconnect_delay

        while self._running:
            try:
                async with websockets.connect(self._ws_url) as ws:
                    self._ws = ws
                    delay = self._reconnect_delay
                    if self._on_connect:
                        self._on_connect()

                    async for raw in ws:
                        if isinstance(raw, (bytes, bytearray)):
                            # Binary CBOR frame — route to relay handler if any
                            await self._handle_relay_bytes(bytes(raw))
                        else:
                            # Text JSON frame — existing dispatch
                            data = json.loads(raw)
                            await self._handle(ws, data)

            except Exception as exc:
                self._ws = None
                if self._on_disconnect:
                    self._on_disconnect()
                if not self._running:
                    break
                logger.debug("WebSocket connection lost (%s), reconnecting in %.1fs...", exc, delay)
                await asyncio.sleep(delay)
                delay = min(delay * 2, self._max_reconnect_delay)

    def stop(self) -> None:
        """Signal the listener to stop and close the connection."""
        self._running = False
        if self._ws:
            asyncio.ensure_future(self._ws.close())
