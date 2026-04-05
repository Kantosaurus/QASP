"""QASP Authority Server — Live demo for audience agents.

Run:
    python scripts/qasp_server.py --host 0.0.0.0 --port 8080

Every audience member registers via REST, discovers peers, requests
capability tokens, and calls each other's tools — all secured by
QASP with ML-DSA-65 post-quantum signatures.

Optional dependencies:
    pip install prometheus-client   # for GET /metrics endpoint
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import re
import sqlite3
import threading
import time
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
import uvicorn
from fastapi import FastAPI, Header, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from starlette.responses import Response

# Optional: Prometheus metrics
try:
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        CollectorRegistry,
        Counter,
        Gauge,
        Histogram,
        generate_latest,
    )

    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

from qasp.crypto.signatures import generate_keypair
from qasp.identity.did import DID, DIDRegistry, create_did
from qasp.protocol.arm import uri_matches
from qasp.protocol.capability import (
    ARM_EXEC,
    ARM_MESSAGE,
    CapabilityToken,
    Constraints,
    create_token,
    verify_token,
)
from qasp.protocol.ocsp import OCSPResponder, OCSPStatus, create_ocsp_request
from qasp.protocol.rate_limiter import RateLimiterRegistry
from qasp.protocol.revocation import (
    CertificateRevocationList,
    RevocationReason,
    RevocationUrgency,
)
from qasp.trust.registry import TrustRegistry
from qasp.trust.scoring import TrustScorer

logger = logging.getLogger("qasp.server")


# ============================================================================
# Persistent storage (SQLite)
# ============================================================================

_STORE_SCHEMA = """\
CREATE TABLE IF NOT EXISTS metering_records (
    receipt_id   TEXT PRIMARY KEY,
    agent_did    TEXT NOT NULL,
    tool         TEXT NOT NULL,
    target_did   TEXT NOT NULL,
    timestamp    TEXT NOT NULL,
    units        INTEGER NOT NULL,
    cost         INTEGER NOT NULL,
    currency     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS token_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    token_id     TEXT NOT NULL,
    event_type   TEXT NOT NULL,
    timestamp    TEXT NOT NULL,
    details      TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS disputes (
    dispute_id      TEXT PRIMARY KEY,
    claimant_did    TEXT NOT NULL,
    respondent_did  TEXT NOT NULL,
    type            TEXT NOT NULL,
    description     TEXT DEFAULT '',
    status          TEXT NOT NULL,
    opened_at       TEXT NOT NULL,
    verdict         TEXT
);
CREATE TABLE IF NOT EXISTS conversations (
    conversation_id  TEXT PRIMARY KEY,
    initiator_did    TEXT NOT NULL,
    participant_did  TEXT NOT NULL,
    topic            TEXT DEFAULT '',
    status           TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at       TEXT NOT NULL,
    closed_at        TEXT,
    message_count    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS messages (
    message_id       TEXT PRIMARY KEY,
    conversation_id  TEXT NOT NULL,
    sender_did       TEXT NOT NULL,
    recipient_did    TEXT NOT NULL,
    content_type     TEXT NOT NULL DEFAULT 'text/plain',
    content          TEXT NOT NULL,
    intent           TEXT DEFAULT NULL,
    reply_to         TEXT,
    created_at       TEXT NOT NULL,
    delivered        INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (conversation_id) REFERENCES conversations(conversation_id)
);
"""


class PersistentStore:
    """SQLite-backed persistence for metering, token events, and disputes."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        for statement in _STORE_SCHEMA.strip().split(";"):
            statement = statement.strip()
            if statement:
                self._conn.execute(statement)
        self._conn.commit()
        # Enable WAL for file-based databases
        if db_path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")

    # -- metering --

    def insert_metering(self, agent_did: str, record: dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO metering_records "
                "(receipt_id, agent_did, tool, target_did, timestamp, units, cost, currency) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    record["receipt_id"], agent_did, record["tool"],
                    record["target"], record["timestamp"],
                    record["units"], record["cost"], record["currency"],
                ),
            )
            self._conn.commit()

    def query_metering(
        self,
        agent_did: str,
        tool: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        clauses = ["agent_did = ?"]
        params: list[Any] = [agent_did]
        if tool:
            clauses.append("tool = ?")
            params.append(tool)
        if since:
            clauses.append("timestamp >= ?")
            params.append(since)
        if until:
            clauses.append("timestamp <= ?")
            params.append(until)
        params.append(limit)
        sql = (
            "SELECT * FROM metering_records WHERE "
            + " AND ".join(clauses)
            + " ORDER BY timestamp DESC LIMIT ?"
        )
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def metering_summary(self, agent_did: str) -> dict[str, Any]:
        with self._lock:
            row = self._conn.execute(
                "SELECT COALESCE(SUM(units),0) AS total_units, "
                "COALESCE(SUM(cost),0) AS total_cost, "
                "COUNT(*) AS total_calls "
                "FROM metering_records WHERE agent_did = ?",
                (agent_did,),
            ).fetchone()
            by_tool_rows = self._conn.execute(
                "SELECT tool, SUM(units) AS units, SUM(cost) AS cost, COUNT(*) AS calls "
                "FROM metering_records WHERE agent_did = ? GROUP BY tool",
                (agent_did,),
            ).fetchall()
        by_tool = {r["tool"]: {"units": r["units"], "cost": r["cost"], "calls": r["calls"]} for r in by_tool_rows}
        return {
            "total_units": row["total_units"],
            "total_cost": row["total_cost"],
            "total_calls": row["total_calls"],
            "by_tool": by_tool,
        }

    # -- token events --

    def insert_token_event(self, token_id: str, event_type: str, details: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO token_events (token_id, event_type, timestamp, details) "
                "VALUES (?, ?, ?, ?)",
                (token_id, event_type, datetime.now(UTC).isoformat(), details),
            )
            self._conn.commit()

    def query_token_events(self, token_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT token_id, event_type, timestamp, details "
                "FROM token_events WHERE token_id = ? ORDER BY id",
                (token_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    # -- disputes --

    def insert_dispute(self, dispute: dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO disputes "
                "(dispute_id, claimant_did, respondent_did, type, description, status, opened_at, verdict) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    dispute["dispute_id"], dispute["claimant_did"],
                    dispute["respondent_did"], dispute["type"],
                    dispute.get("description", ""), dispute["status"],
                    dispute["opened_at"],
                    json.dumps(dispute["verdict"]) if dispute.get("verdict") else None,
                ),
            )
            self._conn.commit()

    def query_disputes(self, status: str | None = None) -> list[dict[str, Any]]:
        if status:
            sql = "SELECT * FROM disputes WHERE status = ? ORDER BY opened_at DESC"
            params: tuple[Any, ...] = (status.upper(),)
        else:
            sql = "SELECT * FROM disputes ORDER BY opened_at DESC"
            params = ()
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            if d.get("verdict"):
                d["verdict"] = json.loads(d["verdict"])
            results.append(d)
        return results

    # -- conversations --

    def insert_conversation(self, conv: dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO conversations "
                "(conversation_id, initiator_did, participant_did, topic, status, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    conv["conversation_id"], conv["initiator_did"],
                    conv["participant_did"], conv.get("topic", ""),
                    conv.get("status", "ACTIVE"), conv["created_at"],
                ),
            )
            self._conn.commit()

    def query_conversations(
        self, agent_did: str, status: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses = ["(initiator_did = ? OR participant_did = ?)"]
        params: list[Any] = [agent_did, agent_did]
        if status:
            clauses.append("status = ?")
            params.append(status.upper())
        sql = (
            "SELECT * FROM conversations WHERE "
            + " AND ".join(clauses)
            + " ORDER BY created_at DESC"
        )
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def close_conversation(self, conversation_id: str, closed_at: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE conversations SET status = 'CLOSED', closed_at = ? "
                "WHERE conversation_id = ?",
                (closed_at, conversation_id),
            )
            self._conn.commit()

    def get_conversation(self, conversation_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM conversations WHERE conversation_id = ?",
                (conversation_id,),
            ).fetchone()
        return dict(row) if row else None

    # -- messages --

    def insert_message(self, msg: dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO messages "
                "(message_id, conversation_id, sender_did, recipient_did, "
                "content_type, content, intent, reply_to, created_at, delivered) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    msg["message_id"], msg["conversation_id"],
                    msg["sender_did"], msg["recipient_did"],
                    msg.get("content_type", "text/plain"), msg["content"],
                    msg.get("intent"), msg.get("reply_to"), msg["created_at"],
                    1 if msg.get("delivered") else 0,
                ),
            )
            self._conn.execute(
                "UPDATE conversations SET message_count = message_count + 1 "
                "WHERE conversation_id = ?",
                (msg["conversation_id"],),
            )
            self._conn.commit()

    def mark_message_delivered(self, message_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE messages SET delivered = 1 WHERE message_id = ?",
                (message_id,),
            )
            self._conn.commit()

    def query_messages(
        self,
        conversation_id: str,
        since: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        clauses = ["conversation_id = ?"]
        params: list[Any] = [conversation_id]
        if since:
            clauses.append("created_at >= ?")
            params.append(since)
        params.append(limit)
        sql = (
            "SELECT * FROM messages WHERE "
            + " AND ".join(clauses)
            + " ORDER BY created_at ASC LIMIT ?"
        )
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def query_inbox(self, agent_did: str, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM messages WHERE recipient_did = ? AND delivered = 0 "
                "ORDER BY created_at ASC LIMIT ?",
                (agent_did, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    # -- receipts (cross-agent query) --

    def query_all_metering(
        self, agent_did: str | None = None, limit: int = 100,
    ) -> list[dict[str, Any]]:
        if agent_did:
            sql = "SELECT * FROM metering_records WHERE agent_did = ? ORDER BY timestamp DESC LIMIT ?"
            params: tuple[Any, ...] = (agent_did, limit)
        else:
            sql = "SELECT * FROM metering_records ORDER BY timestamp DESC LIMIT ?"
            params = (limit,)
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]


# ============================================================================
# Pydantic request/response models
# ============================================================================


class ToolDef(BaseModel):
    name: str
    description: str = ""
    input_schema: dict[str, Any] | None = None


class RegisterRequest(BaseModel):
    name: str
    tools: list[ToolDef] = []
    callback_url: str = ""


class TokenRequest(BaseModel):
    target_did: str
    tool_name: str
    verbs: list[str] | None = None


class TokenRevokeRequest(BaseModel):
    token_id: str


class ToolCallRequest(BaseModel):
    target_did: str
    tool_name: str
    arguments: dict[str, Any] = {}
    token: str


class TrustReportRequest(BaseModel):
    outcome: str  # "success" or "failure"
    details: str = ""


class DisputeOpenRequest(BaseModel):
    respondent_did: str
    type: str  # "overcharge", "service_failure", etc.
    description: str = ""


class ConversationOpenRequest(BaseModel):
    target_did: str
    topic: str = ""


class MessageSendRequest(BaseModel):
    conversation_id: str
    content: str
    content_type: str = "text/plain"
    intent: str | None = None
    reply_to: str | None = None
    token: str  # base64 capability token


class MessageAckRequest(BaseModel):
    message_id: str


class AgentUpdateRequest(BaseModel):
    name: str | None = None
    tools: list[ToolDef] | None = None
    callback_url: str | None = None


# ============================================================================
# Server state
# ============================================================================


class AgentRecord:
    """Per-agent state held by the authority."""

    __slots__ = (
        "agent_id", "name", "did", "did_str",
        "public_key", "secret_key", "api_key",
        "callback_url", "tools", "tokens_issued", "metering",
        "ip_address",
    )

    def __init__(
        self,
        agent_id: str,
        name: str,
        did: DID,
        public_key: bytes,
        secret_key: bytes,
        api_key: str,
        callback_url: str,
        tools: list[dict[str, Any]],
        ip_address: str = "",
    ) -> None:
        self.agent_id = agent_id
        self.name = name
        self.did = did
        self.did_str = str(did)
        self.public_key = public_key
        self.secret_key = secret_key
        self.api_key = api_key
        self.callback_url = callback_url
        self.tools = tools
        self.ip_address = ip_address
        self.tokens_issued: dict[str, CapabilityToken] = {}
        self.metering: list[dict[str, Any]] = []


class AuthorityState:
    """All server-side state, initialised at startup."""

    def __init__(self, db_path: str = ":memory:", admin_api_key: str | None = None) -> None:
        # Authority identity
        self.public_key, self.secret_key = generate_keypair()
        self.did, self.did_doc = create_did(self.public_key)

        # Registries
        self.did_registry = DIDRegistry()
        self.did_registry.register(self.did_doc)

        self.trust_registry = TrustRegistry()
        self.trust_scorer = TrustScorer()

        self.crl = CertificateRevocationList()
        self.ocsp = OCSPResponder(
            responder_did=str(self.did),
            responder_secret_key=self.secret_key,
            responder_public_key=self.public_key,
            crl=self.crl,
        )
        self.rate_limiters = RateLimiterRegistry()

        # Agent lookup tables
        self.agents_by_api_key: dict[str, AgentRecord] = {}
        self.agents_by_did: dict[str, AgentRecord] = {}

        # Dispute storage (simple dict for demo)
        self.disputes: dict[str, dict[str, Any]] = {}

        # Token lookup (token_id hex -> CapabilityToken)
        self.tokens: dict[str, CapabilityToken] = {}

        # Persistent storage
        self.store = PersistentStore(db_path)

        # WebSocket connection manager
        self.ws_manager = ConnectionManager()

        # Admin API key
        self.admin_api_key = admin_api_key or uuid.uuid4().hex

        logger.info("Authority DID: %s", self.did)

    # -- helpers --

    def resolve_agent(self, api_key: str) -> AgentRecord:
        agent = self.agents_by_api_key.get(api_key)
        if agent is None:
            raise HTTPException(status_code=401, detail="Invalid API key")
        return agent

    def resolve_target(self, target_did: str) -> AgentRecord:
        agent = self.agents_by_did.get(target_did)
        if agent is None:
            raise HTTPException(status_code=404, detail=f"Agent not found: {target_did}")
        return agent

    def check_name_ip_conflict(
        self, name: str, ip_address: str, exclude_did: str | None = None,
    ) -> None:
        """Raise 409 if another agent from the same IP already uses this name."""
        if not ip_address:
            return
        for agent in self.agents_by_did.values():
            if (
                agent.ip_address == ip_address
                and agent.name == name
                and agent.did_str != exclude_did
            ):
                raise HTTPException(
                    status_code=409,
                    detail=f"An agent named '{name}' is already registered from this IP address",
                )

    def compute_trust(self, did_str: str) -> dict[str, Any]:
        entry = self.trust_registry.lookup(did_str)
        if entry is None:
            return {"score": 0.5, "interaction_count": 0, "components": {}}
        score = self.trust_scorer.calculate(
            certification_score=entry.audit_certified_score or None,
            reputation_score=entry.reputation_score,
            behavioral_score=entry.behavioral_score,
            reputation_confidence=min(1.0, entry.total_interactions / 50.0),
            interaction_count=entry.total_interactions,
        )
        return {
            "score": round(score.overall, 4),
            "interaction_count": entry.total_interactions,
            "components": {
                "reputation": round(score.reputation_component, 4),
                "certification": round(score.certification_component, 4),
                "behavioral": round(score.behavioral_component, 4),
                "witness": round(score.witness_component, 4),
                "confidence": round(score.confidence, 4),
            },
        }


# ============================================================================
# WebSocket connection manager
# ============================================================================


class ConnectionManager:
    """Manages active WebSocket connections indexed by agent DID."""

    def __init__(self) -> None:
        self._connections: dict[str, WebSocket] = {}
        self._lock = asyncio.Lock()
        # Pending request-response futures keyed by request_id
        self._pending: dict[str, asyncio.Future] = {}

    async def connect(self, did_str: str, websocket: WebSocket) -> None:
        async with self._lock:
            old = self._connections.get(did_str)
            if old is not None:
                try:
                    await old.close(code=4001, reason="Superseded by new connection")
                except Exception:
                    pass
            self._connections[did_str] = websocket

    async def disconnect(self, did_str: str) -> None:
        async with self._lock:
            self._connections.pop(did_str, None)

    def is_connected(self, did_str: str) -> bool:
        return did_str in self._connections

    async def send_json(self, did_str: str, data: dict) -> bool:
        ws = self._connections.get(did_str)
        if ws is None:
            return False
        try:
            await ws.send_json(data)
            return True
        except Exception:
            await self.disconnect(did_str)
            return False

    async def send_and_wait(
        self, did_str: str, data: dict, request_id: str, timeout: float = 30.0,
    ) -> dict | None:
        """Send a message and wait for a response matching request_id.

        Used for tool call relay where the server needs the agent's result.
        Returns the response payload, or None on timeout/failure.
        """
        loop = asyncio.get_running_loop()
        future: asyncio.Future[dict] = loop.create_future()
        self._pending[request_id] = future

        ok = await self.send_json(did_str, data)
        if not ok:
            self._pending.pop(request_id, None)
            return None

        try:
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError:
            return None
        finally:
            self._pending.pop(request_id, None)

    def resolve_pending(self, request_id: str, result: dict) -> bool:
        """Resolve a pending request-response future. Called from WS listen loop."""
        future = self._pending.get(request_id)
        if future is None or future.done():
            return False
        future.set_result(result)
        return True

    @property
    def connected_count(self) -> int:
        return len(self._connections)


# ============================================================================
# FastAPI app
# ============================================================================

state: AuthorityState  # set in main()
app = FastAPI(title="QASP Authority", version="0.1.0")

# -- Prometheus metrics (conditional) --

if PROMETHEUS_AVAILABLE:
    METRICS_REGISTRY = CollectorRegistry()
    AGENTS_REGISTERED = Gauge(
        "qasp_agents_registered_total",
        "Number of currently registered agents",
        registry=METRICS_REGISTRY,
    )
    TOKENS_ISSUED = Counter(
        "qasp_tokens_issued_total",
        "Total capability tokens issued",
        registry=METRICS_REGISTRY,
    )
    TOKENS_REVOKED = Counter(
        "qasp_tokens_revoked_total",
        "Total capability tokens revoked",
        registry=METRICS_REGISTRY,
    )
    TOOL_CALLS = Counter(
        "qasp_tool_calls_total",
        "Total tool calls relayed",
        ["status"],
        registry=METRICS_REGISTRY,
    )
    TOOL_CALLS_RATE_LIMITED = Counter(
        "qasp_tool_calls_rate_limited_total",
        "Total tool calls rejected due to rate limiting",
        registry=METRICS_REGISTRY,
    )
    DISPUTES_OPENED = Counter(
        "qasp_disputes_opened_total",
        "Total disputes opened",
        registry=METRICS_REGISTRY,
    )
    METERING_UNITS = Counter(
        "qasp_metering_units_total",
        "Total metering units consumed",
        registry=METRICS_REGISTRY,
    )
    METERING_COST = Counter(
        "qasp_metering_cost_total",
        "Total metering cost (credits)",
        registry=METRICS_REGISTRY,
    )
    MESSAGES_RELAYED = Counter(
        "qasp_messages_relayed_total",
        "Total agent-to-agent messages relayed",
        registry=METRICS_REGISTRY,
    )
    CONVERSATIONS_OPENED = Counter(
        "qasp_conversations_opened_total",
        "Total conversations opened",
        registry=METRICS_REGISTRY,
    )
    AGENTS_UPDATED = Counter(
        "qasp_agents_updated_total",
        "Total agent update operations",
        registry=METRICS_REGISTRY,
    )
    WEBSOCKET_CONNECTIONS = Gauge(
        "qasp_websocket_connections_active",
        "Number of active WebSocket connections",
        registry=METRICS_REGISTRY,
    )
    HTTP_REQUEST_DURATION = Histogram(
        "qasp_http_request_duration_seconds",
        "HTTP request duration in seconds",
        ["method", "endpoint", "status_code"],
        registry=METRICS_REGISTRY,
    )

    _PATH_NORMALIZE = re.compile(r"/[0-9a-f]{16,}")

    @app.middleware("http")
    async def metrics_middleware(request, call_next):  # type: ignore[no-untyped-def]
        start = time.perf_counter()
        response = await call_next(request)
        duration = time.perf_counter() - start
        path = _PATH_NORMALIZE.sub("/{id}", request.url.path)
        HTTP_REQUEST_DURATION.labels(
            method=request.method,
            endpoint=path,
            status_code=response.status_code,
        ).observe(duration)
        return response


def _api_key(x_api_key: str | None = Header(None)) -> str:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")
    return x_api_key


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


# -- Info -------------------------------------------------------------------

@app.get("/")
def root():
    return {
        "name": "QASP Authority",
        "version": "0.1.0",
        "did": str(state.did),
        "agents_registered": len(state.agents_by_did),
        "features": [
            "ML-DSA-65 post-quantum signatures",
            "DID-based agent identity",
            "Capability token issuance & verification",
            "ARM URI scope checks",
            "Token bucket rate limiting",
            "Certificate Revocation List (CRL)",
            "OCSP token status",
            "Bayesian trust scoring",
            "Dispute resolution",
            "Tool call relay with metering",
            "Agent-to-agent messaging with conversations",
            "WebSocket real-time push",
        ],
    }


@app.get("/features")
def features():
    return [
        {"id": "did", "name": "Decentralised Identity", "description": "ML-DSA-65 keypair + did:qasp per agent"},
        {"id": "capability", "name": "Capability Tokens", "description": "CBOR-encoded, ML-DSA-65 signed, attenuable tokens"},
        {"id": "arm", "name": "ARM URI Scoping", "description": "qasp:// resource URIs with wildcard + prefix matching"},
        {"id": "rate_limit", "name": "Rate Limiting", "description": "Token-bucket rate limiter per token"},
        {"id": "revocation", "name": "Token Revocation", "description": "CRL with BFS cascade revocation"},
        {"id": "ocsp", "name": "OCSP Status", "description": "Real-time per-token revocation status"},
        {"id": "trust", "name": "Trust Scoring", "description": "Bayesian reputation with anti-gaming caps"},
        {"id": "dispute", "name": "Dispute Resolution", "description": "Open disputes, evidence, binding verdicts"},
        {"id": "relay", "name": "Tool Call Relay", "description": "Verify token → relay to agent callback → meter usage"},
        {"id": "metering", "name": "Usage Metering", "description": "Per-call receipts with cost tracking"},
        {"id": "websocket", "name": "WebSocket Push", "description": "Real-time server-to-agent delivery via persistent WebSocket connections"},
    ]


# -- Metrics ----------------------------------------------------------------

@app.get("/metrics")
def metrics():
    if not PROMETHEUS_AVAILABLE:
        raise HTTPException(
            status_code=501,
            detail="prometheus-client not installed. Run: pip install prometheus-client",
        )
    return Response(
        content=generate_latest(METRICS_REGISTRY),
        media_type=CONTENT_TYPE_LATEST,
    )


# -- Registration -----------------------------------------------------------

@app.post("/register")
def register(body: RegisterRequest, request: Request):
    logger.info("--- POST /register ---")
    logger.info("  Agent name: %s", body.name)
    logger.info("  Tools declared: %s", [t.name for t in body.tools])
    logger.info("  Callback URL: %s", body.callback_url or "(none)")

    client_ip = _client_ip(request)
    logger.info("  Client IP: %s", client_ip or "(unknown)")
    state.check_name_ip_conflict(name=body.name, ip_address=client_ip)

    logger.info("  Generating ML-DSA-65 keypair (pub=1952 bytes, sec=4032 bytes)...")
    t0 = time.perf_counter()
    pub, sec = generate_keypair()
    elapsed_ms = (time.perf_counter() - t0) * 1000
    logger.info("  >> Keypair generated in %.1fms", elapsed_ms)

    did, did_doc = create_did(pub)
    did_str = str(did)
    logger.info("  >> DID created: %s", did_str)

    # Register DID
    state.did_registry.register(did_doc)
    logger.info("  >> DID document registered in DID registry")

    # Register trust entry
    state.trust_registry.register(did)
    logger.info("  >> Trust entry initialised (score=0.5)")

    # Build tool list with resource URIs
    tools: list[dict[str, Any]] = []
    did_short = did.identifier[:12]
    for t in body.tools:
        resource_uri = f"qasp://agents/{did_short}/tools/{t.name}"
        tools.append({
            "name": t.name,
            "description": t.description,
            "input_schema": t.input_schema or {"type": "object"},
            "resource_uri": resource_uri,
        })
        logger.info("  >> Tool '%s' -> ARM URI: %s", t.name, resource_uri)

    # Virtual messaging tool — every agent can receive messages
    msg_resource_uri = f"qasp://agents/{did_short}/messages"
    tools.append({
        "name": "_messages",
        "description": "Agent-to-agent messaging",
        "input_schema": {"type": "object"},
        "resource_uri": msg_resource_uri,
    })
    logger.info("  >> Virtual tool '_messages' -> ARM URI: %s", msg_resource_uri)

    api_key = uuid.uuid4().hex
    agent = AgentRecord(
        agent_id=uuid.uuid4().hex,
        name=body.name,
        did=did,
        public_key=pub,
        secret_key=sec,
        api_key=api_key,
        callback_url=body.callback_url,
        tools=tools,
        ip_address=client_ip,
    )
    state.agents_by_api_key[api_key] = agent
    state.agents_by_did[did_str] = agent

    logger.info("  Agent '%s' registered successfully (total agents: %d)", body.name, len(state.agents_by_did))

    if PROMETHEUS_AVAILABLE:
        AGENTS_REGISTERED.set(len(state.agents_by_did))

    return {
        "agent_id": agent.agent_id,
        "did": did_str,
        "api_key": api_key,
        "public_key": base64.b64encode(pub).decode(),
    }


# -- Agent update -----------------------------------------------------------

@app.put("/agents/update")
async def update_agent(body: AgentUpdateRequest, request: Request, x_api_key: str | None = Header(None)):
    agent = state.resolve_agent(_api_key(x_api_key))

    logger.info("--- PUT /agents/update ---")
    logger.info("  Agent: '%s' (%s)", agent.name, agent.did_str)
    logger.info("  Fields to update: name=%s  tools=%s  callback_url=%s",
                body.name is not None, body.tools is not None, body.callback_url is not None)

    if body.name is None and body.tools is None and body.callback_url is None:
        raise HTTPException(status_code=400, detail="No fields to update")

    changes: dict[str, Any] = {}

    # -- Name --
    if body.name is not None:
        client_ip = _client_ip(request)
        state.check_name_ip_conflict(
            name=body.name, ip_address=client_ip, exclude_did=agent.did_str,
        )
        old_name = agent.name
        agent.name = body.name
        changes["name"] = {"old": old_name, "new": body.name}
        logger.info("  >> Name updated: '%s' -> '%s'", old_name, body.name)

    # -- Callback URL --
    if body.callback_url is not None:
        old_url = agent.callback_url
        agent.callback_url = body.callback_url
        changes["callback_url"] = {"old": old_url, "new": body.callback_url}
        logger.info("  >> Callback URL updated: '%s' -> '%s'", old_url, body.callback_url)

    # -- Tools --
    revoked_count = 0
    if body.tools is not None:
        did_short = agent.did.identifier[:12]

        # Filter out _messages if caller accidentally includes it
        body_tools = [t for t in body.tools if t.name != "_messages"]

        old_tool_names = {t["name"] for t in agent.tools if t["name"] != "_messages"}
        new_tool_names = {t.name for t in body_tools}
        removed_tools = old_tool_names - new_tool_names
        added_tools = new_tool_names - old_tool_names

        # Build new tool list with resource URIs
        new_tools: list[dict[str, Any]] = []
        for t in body_tools:
            resource_uri = f"qasp://agents/{did_short}/tools/{t.name}"
            new_tools.append({
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema or {"type": "object"},
                "resource_uri": resource_uri,
            })
            logger.info("  >> Tool '%s' -> ARM URI: %s", t.name, resource_uri)

        # Always add virtual messaging tool
        msg_resource_uri = f"qasp://agents/{did_short}/messages"
        new_tools.append({
            "name": "_messages",
            "description": "Agent-to-agent messaging",
            "input_schema": {"type": "object"},
            "resource_uri": msg_resource_uri,
        })

        # Revoke tokens bound to removed tools
        for tool_name in removed_tools:
            removed_uri = f"qasp://agents/{did_short}/tools/{tool_name}"
            logger.info("  >> Revoking tokens for removed tool '%s' (URI: %s)", tool_name, removed_uri)

            tokens_to_revoke = [
                (tid_hex, tok) for tid_hex, tok in state.tokens.items()
                if tok.resource_uri == removed_uri
            ]

            for tid_hex, tok in tokens_to_revoke:
                token_id_bytes = bytes.fromhex(tid_hex)
                if state.crl.is_revoked(token_id_bytes):
                    continue
                try:
                    entries = state.crl.revoke(
                        token_id=token_id_bytes,
                        reason=RevocationReason.PRIVILEGE_WITHDRAWN,
                        urgency=RevocationUrgency.CRITICAL,
                        revoker_did=str(state.did),
                        revoker_secret_key=state.secret_key,
                    )
                    state.ocsp.invalidate(token_id_bytes)
                    state.store.insert_token_event(tid_hex, "revoked", f"tool_removed:{tool_name}")
                    revoked_count += len(entries)
                    logger.info("    Revoked token %s... (%d entries incl. cascade)", tid_hex[:16], len(entries))
                    # Notify holders of the revoked token (and cascade)
                    await _notify_revocation(tid_hex, str(state.did), "PRIVILEGE_WITHDRAWN")
                except Exception as exc:
                    logger.warning("    Failed to revoke token %s...: %s", tid_hex[:16], exc)

        agent.tools = new_tools
        changes["tools"] = {
            "added": sorted(added_tools),
            "removed": sorted(removed_tools),
            "total": len(new_tools),
            "tokens_revoked": revoked_count,
        }
        logger.info("  >> Tools updated: %d added, %d removed, %d tokens revoked",
                     len(added_tools), len(removed_tools), revoked_count)

    if PROMETHEUS_AVAILABLE:
        AGENTS_UPDATED.inc()
        if revoked_count > 0:
            TOKENS_REVOKED.inc(revoked_count)

    logger.info("  Agent '%s' updated successfully", agent.name)

    return {
        "agent_id": agent.agent_id,
        "did": agent.did_str,
        "name": agent.name,
        "tools": agent.tools,
        "callback_url": agent.callback_url,
        "changes": changes,
    }


# -- Discovery --------------------------------------------------------------

@app.get("/discover")
def discover(
    capability: str = Query("*"),
    min_trust: float = Query(0.0),
    x_api_key: str | None = Header(None),
):
    _api_key(x_api_key)
    logger.info("--- GET /discover ---")
    logger.info("  Filter: capability=%s  min_trust=%.2f", capability, min_trust)

    results: list[dict[str, Any]] = []
    for agent in state.agents_by_did.values():
        trust = state.compute_trust(agent.did_str)
        if trust["score"] < min_trust:
            logger.info("  Skipped '%s' (trust %.4f < min %.2f)", agent.name, trust["score"], min_trust)
            continue

        # Capability filter
        if capability != "*":
            matched = any(
                uri_matches(capability, t["resource_uri"])
                for t in agent.tools
            )
            if not matched:
                logger.info("  Skipped '%s' (no matching capability)", agent.name)
                continue

        logger.info("  Matched '%s'  DID=%s  trust=%.4f  tools=%d", agent.name, agent.did_str, trust["score"], len(agent.tools))
        results.append({
            "name": agent.name,
            "did": agent.did_str,
            "tools": agent.tools,
            "trust_score": trust["score"],
            "endpoint": agent.callback_url or "(relay via server)",
        })

    results.sort(key=lambda r: r["trust_score"], reverse=True)
    logger.info("  Returning %d agents (sorted by trust)", len(results))
    return results


# -- Token operations -------------------------------------------------------

@app.post("/tokens/request")
async def request_token(body: TokenRequest, x_api_key: str | None = Header(None)):
    caller = state.resolve_agent(_api_key(x_api_key))
    target = state.resolve_target(body.target_did)

    logger.info("--- POST /tokens/request ---")
    logger.info("  Caller: '%s' (%s)", caller.name, caller.did_str)
    logger.info("  Target: '%s' (%s)", target.name, target.did_str)
    logger.info("  Tool:   %s", body.tool_name)

    # Find the tool
    tool = next((t for t in target.tools if t["name"] == body.tool_name), None)
    if tool is None:
        logger.warning("  DENIED: Tool '%s' not found on target agent", body.tool_name)
        raise HTTPException(status_code=404, detail=f"Tool '{body.tool_name}' not found on target agent")

    resource_uri = tool["resource_uri"]
    verbs = set(body.verbs) if body.verbs else {ARM_EXEC}
    logger.info("  Resource URI: %s", resource_uri)
    logger.info("  Verbs: %s", sorted(verbs))

    # Authority issues token on behalf of the caller → target
    logger.info("  Signing token with authority ML-DSA-65 key...")
    t0 = time.perf_counter()
    token = create_token(
        issuer_did=state.did,
        issuer_secret_key=state.secret_key,
        subject_did=caller.did,
        resource_uri=resource_uri,
        verbs=verbs,
        audience_did=target.did,
        constraints=Constraints(rate_limit=10, rate_period_seconds=60),
        validity_seconds=3600,
    )
    elapsed_ms = (time.perf_counter() - t0) * 1000
    logger.info("  >> Token signed in %.1fms", elapsed_ms)

    # Register in CRL for OCSP tracking
    state.crl.register_token(token)

    # Store
    tid_hex = token.token_id.hex()
    state.tokens[tid_hex] = token
    caller.tokens_issued[tid_hex] = token
    state.store.insert_token_event(tid_hex, "issued", resource_uri)

    if PROMETHEUS_AVAILABLE:
        TOKENS_ISSUED.inc()

    token_cbor = token.to_cbor_with_signature()

    expires = token.constraints.not_after.isoformat() if token.constraints.not_after else "never"
    logger.info("  >> Token issued: id=%s  expires=%s  rate_limit=10/60s", tid_hex[:16] + "...", expires)
    logger.info("  >> Registered in CRL for OCSP tracking")

    # Notify target agent that a token was requested for their tool
    if state.ws_manager.is_connected(target.did_str):
        await state.ws_manager.send_json(target.did_str, {
            "type": "token_requested",
            "payload": {
                "token_id": tid_hex,
                "requester_did": caller.did_str,
                "requester_name": caller.name,
                "tool_name": body.tool_name,
                "resource_uri": resource_uri,
                "verbs": sorted(verbs),
            },
        })
        logger.info("  >> Target notified of token request via WebSocket")

    return {
        "token": base64.b64encode(token_cbor).decode(),
        "token_id": tid_hex,
        "resource_uri": resource_uri,
        "verbs": sorted(verbs),
        "expires_at": token.constraints.not_after.isoformat() if token.constraints.not_after else None,
    }


@app.post("/tokens/revoke")
async def revoke_token(body: TokenRevokeRequest, x_api_key: str | None = Header(None)):
    caller = state.resolve_agent(_api_key(x_api_key))

    logger.info("--- POST /tokens/revoke ---")
    logger.info("  Revoker: '%s' (%s)", caller.name, caller.did_str)
    logger.info("  Token ID: %s", body.token_id)

    token_id_bytes = bytes.fromhex(body.token_id)

    try:
        entries = state.crl.revoke(
            token_id=token_id_bytes,
            reason=RevocationReason.OWNER_REQUEST,
            urgency=RevocationUrgency.CRITICAL,
            revoker_did=str(caller.did),
            revoker_secret_key=state.secret_key,
        )
    except Exception as exc:
        logger.warning("  FAILED: %s", exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Invalidate OCSP cache
    state.ocsp.invalidate(token_id_bytes)
    state.store.insert_token_event(body.token_id, "revoked")

    if PROMETHEUS_AVAILABLE:
        TOKENS_REVOKED.inc()

    # Notify all affected agents via WebSocket (subject + cascade holders)
    await _notify_revocation(body.token_id, caller.did_str, "OWNER_REQUEST")

    logger.info("  >> Token revoked (reason=OWNER_REQUEST, urgency=CRITICAL)")
    logger.info("  >> CRL entries created: %d (includes cascade children)", len(entries))
    logger.info("  >> OCSP cache invalidated")

    return {
        "revoked": True,
        "token_id": body.token_id,
        "entries_created": len(entries),
    }


@app.get("/tokens/status/{token_id}")
def token_status(token_id: str):
    logger.info("--- GET /tokens/status/%s ---", token_id[:16] + "...")

    token_id_bytes = bytes.fromhex(token_id)
    request = create_ocsp_request(token_id_bytes)
    response = state.ocsp.handle_request(request)

    status_name = OCSPStatus(response.status).name
    result: dict[str, Any] = {
        "token_id": token_id,
        "status": status_name,
    }
    if response.revocation_time is not None:
        result["revoked_at"] = datetime.fromtimestamp(response.revocation_time, tz=UTC).isoformat()
        logger.info("  >> OCSP status: %s (revoked at %s)", status_name, result["revoked_at"])
    else:
        logger.info("  >> OCSP status: %s", status_name)
    return result


# -- Tool call relay --------------------------------------------------------

@app.post("/tools/call")
async def call_tool(body: ToolCallRequest, x_api_key: str | None = Header(None)):
    caller = state.resolve_agent(_api_key(x_api_key))
    target = state.resolve_target(body.target_did)

    logger.info("--- POST /tools/call ---")
    logger.info("  Caller: '%s' (%s)", caller.name, caller.did_str)
    logger.info("  Target: '%s' (%s)", target.name, target.did_str)
    logger.info("  Tool:   %s", body.tool_name)
    logger.info("  Args:   %s", body.arguments)

    # Find tool
    tool = next((t for t in target.tools if t["name"] == body.tool_name), None)
    if tool is None:
        logger.warning("  DENIED: Tool '%s' not found on target", body.tool_name)
        raise HTTPException(status_code=404, detail=f"Tool '{body.tool_name}' not found")

    # Decode token
    try:
        token_cbor = base64.b64decode(body.token)
        token = CapabilityToken.from_cbor(token_cbor)
    except Exception as exc:
        logger.warning("  DENIED: Invalid token encoding: %s", exc)
        raise HTTPException(status_code=400, detail=f"Invalid token encoding: {exc}") from exc

    logger.info("  [1/7] Verifying ML-DSA-65 signature...")
    t0 = time.perf_counter()
    # 1) Verify signature, expiry, revocation
    try:
        verify_token(
            token=token,
            issuer_public_key=state.public_key,
            check_expiry=True,
            crl=state.crl,
        )
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - t0) * 1000
        logger.warning("  DENIED: Token verification failed (%.1fms): %s", elapsed_ms, exc)
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    elapsed_ms = (time.perf_counter() - t0) * 1000
    expires_str = token.constraints.not_after.isoformat() if token.constraints.not_after else "never"
    logger.info("  [1/7] >> Signature valid (ML-DSA-65, verified in %.1fms)", elapsed_ms)
    logger.info("  [2/7] >> Token not expired (expires %s)", expires_str)
    logger.info("  [3/7] >> Token not revoked (CRL clear)")

    # 2) ARM URI scope check
    logger.info("  [4/7] Checking ARM URI scope...")
    logger.info("         Token grants: %s", token.resource_uri)
    logger.info("         Tool requires: %s", tool["resource_uri"])
    if not uri_matches(token.resource_uri, tool["resource_uri"]):
        logger.warning("  DENIED: ARM URI scope mismatch")
        raise HTTPException(
            status_code=403,
            detail=f"Resource URI mismatch: token grants '{token.resource_uri}', tool requires '{tool['resource_uri']}'",
        )
    logger.info("  [4/7] >> ARM URI scope match confirmed")

    # 3) Verb check
    logger.info("  [5/7] Checking verb permissions (token has: %s)...", sorted(token.verbs))
    if ARM_EXEC not in token.verbs:
        logger.warning("  DENIED: Token missing 'exec' verb")
        raise HTTPException(status_code=403, detail="Token missing 'exec' verb")
    logger.info("  [5/7] >> Verb 'exec' permitted")

    # 4) Rate limiting
    rate_limit = token.constraints.rate_limit or 10
    rate_period = token.constraints.rate_period_seconds or 60
    limiter = state.rate_limiters.get_or_create(
        token_id=token.token_id,
        rate_limit=rate_limit,
        rate_period_seconds=rate_period,
    )
    tokens_before = limiter.tokens_available
    if not limiter.consume():
        if PROMETHEUS_AVAILABLE:
            TOOL_CALLS_RATE_LIMITED.inc()
        logger.warning("  DENIED: Rate limit exceeded (%d/%d used in %ds window)", rate_limit, rate_limit, rate_period)
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded ({rate_limit} calls per {rate_period}s). Retry after {1.0 / limiter.refill_rate:.1f}s",
        )
    logger.info("  [6/7] >> Rate limit OK (%.0f/%d tokens remaining, %ds window)", limiter.tokens_available, rate_limit, rate_period)

    # 5) Relay to target: WebSocket > callback > echo
    call_result: Any = None

    # Tier 1: WebSocket relay (request-response)
    if state.ws_manager.is_connected(target.did_str):
        request_id = uuid.uuid4().hex
        logger.info("  [7/7] Relaying via WebSocket (request_id=%s)...", request_id[:12])
        t0 = time.perf_counter()
        ws_result = await state.ws_manager.send_and_wait(
            target.did_str,
            {
                "type": "tool_call",
                "request_id": request_id,
                "payload": {
                    "tool_name": body.tool_name,
                    "arguments": body.arguments,
                    "caller_did": caller.did_str,
                    "caller_name": caller.name,
                },
            },
            request_id=request_id,
            timeout=30.0,
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000
        if ws_result is not None:
            call_result = ws_result
            logger.info("  [7/7] >> WebSocket relay complete (%.0fms)", elapsed_ms)
        else:
            logger.info("  [7/7] >> WebSocket relay timed out (%.0fms), falling back...", elapsed_ms)

    # Tier 2: Callback relay
    if call_result is None and target.callback_url:
        relay_url = f"{target.callback_url.rstrip('/')}/tools/{body.tool_name}"
        logger.info("  [7/7] Relaying to callback: %s", relay_url)
        t0 = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    relay_url,
                    json=body.arguments,
                    headers={"X-QASP-Caller-DID": str(caller.did)},
                )
                call_result = resp.json()
            elapsed_ms = (time.perf_counter() - t0) * 1000
            logger.info("  [7/7] >> Callback relay complete (%d %s, %.0fms)", resp.status_code, resp.reason_phrase, elapsed_ms)
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - t0) * 1000
            logger.warning("  [7/7] >> Callback relay FAILED (%.0fms): %s", elapsed_ms, exc)
            call_result = {"error": f"Callback failed: {exc}"}

    # Tier 3: Echo (demo mode)
    if call_result is None:
        logger.info("  [7/7] No real-time channel — echoing arguments (demo mode)")
        call_result = {
            "echo": body.arguments,
            "tool": body.tool_name,
            "handled_by": target.name,
            "note": "No callback_url or WebSocket connected; echoing arguments",
        }

    # 6) Metering
    receipt_id = uuid.uuid4().hex
    metering = {"units": 1, "cost": 10, "currency": "credits"}
    metering_record = {
        "receipt_id": receipt_id,
        "tool": body.tool_name,
        "target": body.target_did,
        "timestamp": datetime.now(UTC).isoformat(),
        **metering,
    }
    caller.metering.append(metering_record)
    state.store.insert_metering(caller.did_str, metering_record)

    if PROMETHEUS_AVAILABLE:
        TOOL_CALLS.labels(status="success").inc()
        METERING_UNITS.inc(metering["units"])
        METERING_COST.inc(metering["cost"])

    logger.info("  >> Metering: receipt=%s  cost=%d credits", receipt_id[:12] + "...", metering["cost"])

    # 7) Report successful interaction for trust
    old_trust = state.compute_trust(target.did_str)
    try:
        state.trust_registry.update_reputation(target.did_str, success=True)
    except Exception:
        pass
    new_trust = state.compute_trust(target.did_str)
    logger.info("  >> Trust updated for '%s': %.4f -> %.4f", target.name, old_trust["score"], new_trust["score"])

    logger.info("  CALL COMPLETE (all 7 checks passed)")

    return {
        "result": call_result,
        "metering": metering,
        "receipt_id": receipt_id,
    }


# -- Trust ------------------------------------------------------------------

@app.get("/trust/{did}")
def get_trust(did: str):
    return state.compute_trust(did)


@app.post("/trust/{did}/report")
async def report_trust(did: str, body: TrustReportRequest, x_api_key: str | None = Header(None)):
    _api_key(x_api_key)

    logger.info("--- POST /trust/%s/report ---", did[:24] + "...")
    old_trust = state.compute_trust(did)
    logger.info("  Outcome: %s", body.outcome)
    logger.info("  Current trust: %.4f (%d interactions)", old_trust["score"], old_trust["interaction_count"])

    success = body.outcome.lower() == "success"
    try:
        state.trust_registry.update_reputation(did, success=success)
    except Exception as exc:
        logger.warning("  FAILED: %s", exc)
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    new_trust = state.compute_trust(did)
    logger.info("  >> Trust updated: %.4f -> %.4f (%+.4f)", old_trust["score"], new_trust["score"], new_trust["score"] - old_trust["score"])

    # Notify the affected agent of trust score change
    if state.ws_manager.is_connected(did):
        await state.ws_manager.send_json(did, {
            "type": "trust_updated",
            "payload": {
                "old_score": old_trust["score"],
                "new_score": new_trust["score"],
                "delta": round(new_trust["score"] - old_trust["score"], 4),
                "outcome": body.outcome,
                "components": new_trust["components"],
            },
        })
        logger.info("  >> Agent notified of trust change via WebSocket")

    return {
        "did": did,
        "outcome": body.outcome,
        "updated_trust": new_trust,
    }


# -- Disputes ---------------------------------------------------------------

@app.post("/disputes/open")
async def open_dispute(body: DisputeOpenRequest, x_api_key: str | None = Header(None)):
    caller = state.resolve_agent(_api_key(x_api_key))

    logger.info("--- POST /disputes/open ---")
    logger.info("  Claimant: '%s' (%s)", caller.name, caller.did_str)
    logger.info("  Respondent DID: %s", body.respondent_did)
    logger.info("  Type: %s", body.type)
    logger.info("  Description: %s", body.description or "(none)")

    dispute_id = uuid.uuid4().hex
    now = datetime.now(UTC).isoformat()
    dispute = {
        "dispute_id": dispute_id,
        "claimant_did": caller.did_str,
        "respondent_did": body.respondent_did,
        "type": body.type,
        "description": body.description,
        "status": "OPEN",
        "opened_at": now,
        "verdict": None,
    }
    state.disputes[dispute_id] = dispute
    state.store.insert_dispute(dispute)

    if PROMETHEUS_AVAILABLE:
        DISPUTES_OPENED.inc()

    # Notify respondent via WebSocket
    if state.ws_manager.is_connected(body.respondent_did):
        await state.ws_manager.send_json(body.respondent_did, {
            "type": "dispute_opened",
            "payload": {
                "dispute_id": dispute_id,
                "claimant_did": caller.did_str,
                "claimant_name": caller.name,
                "type": body.type,
                "description": body.description,
                "opened_at": now,
            },
        })
        logger.info("  >> Respondent notified via WebSocket")

    logger.info("  >> Dispute created: id=%s  status=OPEN", dispute_id)
    return {"dispute_id": dispute_id, "status": "OPEN"}


@app.get("/disputes/{dispute_id}")
def get_dispute(dispute_id: str):
    dispute = state.disputes.get(dispute_id)
    if dispute is None:
        raise HTTPException(status_code=404, detail="Dispute not found")
    return dispute


# -- Token verification helper ----------------------------------------------


def _verify_capability_token(
    token_b64: str,
    required_uri: str,
    required_verb: str,
) -> CapabilityToken:
    """Decode and verify a capability token (reusable 7-step pipeline).

    Returns the verified CapabilityToken on success, raises HTTPException on failure.
    """
    # Decode
    try:
        token_cbor = base64.b64decode(token_b64)
        token = CapabilityToken.from_cbor(token_cbor)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid token encoding: {exc}") from exc

    # 1-3) Signature, expiry, revocation
    try:
        verify_token(
            token=token,
            issuer_public_key=state.public_key,
            check_expiry=True,
            crl=state.crl,
        )
    except Exception as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    # 4) ARM URI scope check
    if not uri_matches(token.resource_uri, required_uri):
        raise HTTPException(
            status_code=403,
            detail=f"Resource URI mismatch: token grants '{token.resource_uri}', requires '{required_uri}'",
        )

    # 5) Verb check
    if required_verb not in token.verbs:
        raise HTTPException(
            status_code=403,
            detail=f"Token missing '{required_verb}' verb",
        )

    # 6) Rate limiting
    rate_limit = token.constraints.rate_limit or 30
    rate_period = token.constraints.rate_period_seconds or 60
    limiter = state.rate_limiters.get_or_create(
        token_id=token.token_id,
        rate_limit=rate_limit,
        rate_period_seconds=rate_period,
    )
    if not limiter.consume():
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded ({rate_limit} per {rate_period}s)",
        )

    return token


# -- Messaging --------------------------------------------------------------

MIN_MESSAGE_TRUST_SCORE = 0.3


@app.post("/conversations/open")
async def open_conversation(body: ConversationOpenRequest, x_api_key: str | None = Header(None)):
    caller = state.resolve_agent(_api_key(x_api_key))
    target = state.resolve_target(body.target_did)

    logger.info("--- POST /conversations/open ---")
    logger.info("  Initiator: '%s' (%s)", caller.name, caller.did_str)
    logger.info("  Target: '%s' (%s)", target.name, target.did_str)
    logger.info("  Topic: %s", body.topic or "(none)")

    # Trust gate
    caller_trust = state.compute_trust(caller.did_str)
    if caller_trust["score"] < MIN_MESSAGE_TRUST_SCORE:
        logger.warning("  DENIED: Caller trust %.4f < %.2f", caller_trust["score"], MIN_MESSAGE_TRUST_SCORE)
        raise HTTPException(
            status_code=403,
            detail=f"Sender trust score {caller_trust['score']:.4f} below messaging threshold {MIN_MESSAGE_TRUST_SCORE}",
        )

    # Create conversation
    conversation_id = uuid.uuid4().hex
    now = datetime.now(UTC).isoformat()
    conv = {
        "conversation_id": conversation_id,
        "initiator_did": caller.did_str,
        "participant_did": target.did_str,
        "topic": body.topic,
        "status": "ACTIVE",
        "created_at": now,
    }
    state.store.insert_conversation(conv)

    # Issue capability token for caller -> target messaging
    target_short = target.did.identifier[:12]
    resource_uri = f"qasp://agents/{target_short}/messages/{conversation_id}"
    token = create_token(
        issuer_did=state.did,
        issuer_secret_key=state.secret_key,
        subject_did=caller.did,
        resource_uri=resource_uri,
        verbs={ARM_MESSAGE},
        audience_did=target.did,
        constraints=Constraints(rate_limit=30, rate_period_seconds=60),
        validity_seconds=3600,
    )
    state.crl.register_token(token)
    tid_hex = token.token_id.hex()
    state.tokens[tid_hex] = token
    caller.tokens_issued[tid_hex] = token
    state.store.insert_token_event(tid_hex, "issued", resource_uri)
    token_cbor = token.to_cbor_with_signature()

    if PROMETHEUS_AVAILABLE:
        CONVERSATIONS_OPENED.inc()
        TOKENS_ISSUED.inc()

    # Notify target: WebSocket > callback
    conv_payload = {
        "conversation_id": conversation_id,
        "initiator_did": caller.did_str,
        "initiator_name": caller.name,
        "topic": body.topic,
    }
    if state.ws_manager.is_connected(target.did_str):
        await state.ws_manager.send_json(
            target.did_str, {"type": "conversation_opened", "payload": conv_payload},
        )
        logger.info("  >> Target notified via WebSocket")
    elif target.callback_url:
        try:
            with httpx.Client(timeout=10) as client:
                client.post(
                    f"{target.callback_url.rstrip('/')}/conversations/new",
                    json=conv_payload,
                    headers={"X-QASP-Caller-DID": caller.did_str},
                )
            logger.info("  >> Target notified via callback")
        except Exception as exc:
            logger.warning("  >> Target notification failed: %s", exc)

    logger.info("  >> Conversation opened: id=%s", conversation_id)

    return {
        "conversation_id": conversation_id,
        "token": base64.b64encode(token_cbor).decode(),
        "token_id": tid_hex,
        "resource_uri": resource_uri,
        "participants": [caller.did_str, target.did_str],
        "created_at": now,
    }


@app.post("/messages/send")
async def send_message(body: MessageSendRequest, x_api_key: str | None = Header(None)):
    caller = state.resolve_agent(_api_key(x_api_key))

    logger.info("--- POST /messages/send ---")
    logger.info("  Sender: '%s' (%s)", caller.name, caller.did_str)
    logger.info("  Conversation: %s", body.conversation_id)
    logger.info("  Content: %.80s%s", body.content, "..." if len(body.content) > 80 else "")
    logger.info("  Intent: %s", body.intent or "unclassified")

    # Validate conversation exists and caller is a participant
    conv = state.store.get_conversation(body.conversation_id)
    if conv is None:
        raise HTTPException(status_code=404, detail="Conversation not found")
    if conv["status"] != "ACTIVE":
        raise HTTPException(status_code=400, detail="Conversation is closed")
    if caller.did_str not in (conv["initiator_did"], conv["participant_did"]):
        raise HTTPException(status_code=403, detail="Not a participant in this conversation")

    # Determine recipient
    recipient_did = conv["participant_did"] if caller.did_str == conv["initiator_did"] else conv["initiator_did"]
    target = state.resolve_target(recipient_did)

    # Build the expected resource URI for token verification
    target_short = target.did.identifier[:12]
    expected_uri = f"qasp://agents/{target_short}/messages/{body.conversation_id}"

    # Verify token (7-step pipeline)
    logger.info("  Verifying capability token...")
    _verify_capability_token(body.token, expected_uri, ARM_MESSAGE)
    logger.info("  >> Token verified")

    # Trust gate
    caller_trust = state.compute_trust(caller.did_str)
    if caller_trust["score"] < MIN_MESSAGE_TRUST_SCORE:
        raise HTTPException(
            status_code=403,
            detail=f"Sender trust {caller_trust['score']:.4f} below threshold {MIN_MESSAGE_TRUST_SCORE}",
        )

    # Content size limit (64KB)
    if len(body.content.encode("utf-8")) > 65536:
        raise HTTPException(status_code=400, detail="Message content exceeds 64KB limit")

    # Store message
    message_id = uuid.uuid4().hex
    now = datetime.now(UTC).isoformat()
    delivered = False

    msg_record = {
        "message_id": message_id,
        "conversation_id": body.conversation_id,
        "sender_did": caller.did_str,
        "recipient_did": recipient_did,
        "content_type": body.content_type,
        "content": body.content,
        "intent": body.intent,
        "reply_to": body.reply_to,
        "created_at": now,
        "delivered": False,
    }

    # 3-tier delivery: WebSocket > callback > inbox polling
    relay_payload = {
        "message_id": message_id,
        "conversation_id": body.conversation_id,
        "sender_did": caller.did_str,
        "sender_name": caller.name,
        "content_type": body.content_type,
        "content": body.content,
        "intent": body.intent,
        "reply_to": body.reply_to,
        "created_at": now,
    }

    # Tier 1: WebSocket push
    if state.ws_manager.is_connected(recipient_did):
        logger.info("  Delivering via WebSocket...")
        ws_ok = await state.ws_manager.send_json(
            recipient_did, {"type": "message", "payload": relay_payload},
        )
        if ws_ok:
            delivered = True
            logger.info("  >> Delivered via WebSocket")
        else:
            logger.info("  >> WebSocket delivery failed, falling back...")

    # Tier 2: Callback relay
    if not delivered and target.callback_url:
        relay_url = f"{target.callback_url.rstrip('/')}/messages/{body.conversation_id}"
        logger.info("  Relaying to callback: %s", relay_url)
        t0 = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    relay_url,
                    json=relay_payload,
                    headers={
                        "X-QASP-Caller-DID": caller.did_str,
                        "X-QASP-Message-ID": message_id,
                    },
                )
                if resp.status_code < 400:
                    delivered = True
            elapsed_ms = (time.perf_counter() - t0) * 1000
            logger.info("  >> Relay %s (%.0fms)", "delivered" if delivered else "failed", elapsed_ms)
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - t0) * 1000
            logger.warning("  >> Relay FAILED (%.0fms): %s", elapsed_ms, exc)

    # Tier 3: Inbox polling (no action needed — message stored undelivered)
    if not delivered:
        logger.info("  No real-time channel — message queued for inbox polling")

    msg_record["delivered"] = delivered
    state.store.insert_message(msg_record)

    # Metering (5 credits per message, cheaper than tool calls at 10)
    receipt_id = uuid.uuid4().hex
    metering = {"units": 1, "cost": 5, "currency": "credits"}
    metering_record = {
        "receipt_id": receipt_id,
        "tool": "_messages",
        "target": recipient_did,
        "timestamp": now,
        **metering,
    }
    caller.metering.append(metering_record)
    state.store.insert_metering(caller.did_str, metering_record)

    if PROMETHEUS_AVAILABLE:
        MESSAGES_RELAYED.inc()
        METERING_UNITS.inc(metering["units"])
        METERING_COST.inc(metering["cost"])

    # Trust update
    try:
        state.trust_registry.update_reputation(caller.did_str, success=True)
    except Exception:
        pass

    logger.info("  >> Message sent: id=%s  delivered=%s  cost=%d credits", message_id[:12] + "...", delivered, metering["cost"])

    return {
        "message_id": message_id,
        "conversation_id": body.conversation_id,
        "delivered": delivered,
        "metering": metering,
        "receipt_id": receipt_id,
    }


@app.get("/conversations")
def list_conversations(
    status: str | None = Query(None),
    x_api_key: str | None = Header(None),
):
    caller = state.resolve_agent(_api_key(x_api_key))
    logger.info("--- GET /conversations ---")
    convs = state.store.query_conversations(caller.did_str, status=status)
    logger.info("  Returning %d conversations for '%s'", len(convs), caller.name)
    return convs


@app.get("/conversations/{conversation_id}/messages")
def get_conversation_messages(
    conversation_id: str,
    since: str | None = Query(None),
    limit: int = Query(50),
    x_api_key: str | None = Header(None),
):
    caller = state.resolve_agent(_api_key(x_api_key))

    # Verify caller is a participant
    conv = state.store.get_conversation(conversation_id)
    if conv is None:
        raise HTTPException(status_code=404, detail="Conversation not found")
    if caller.did_str not in (conv["initiator_did"], conv["participant_did"]):
        raise HTTPException(status_code=403, detail="Not a participant in this conversation")

    messages = state.store.query_messages(conversation_id, since=since, limit=limit)
    return {"conversation_id": conversation_id, "messages": messages, "total": len(messages)}


@app.get("/conversations/{conversation_id}/transcript")
def get_conversation_transcript(
    conversation_id: str,
    x_api_key: str | None = Header(None),
):
    caller = state.resolve_agent(_api_key(x_api_key))

    conv = state.store.get_conversation(conversation_id)
    if conv is None:
        raise HTTPException(status_code=404, detail="Conversation not found")
    if caller.did_str not in (conv["initiator_did"], conv["participant_did"]):
        raise HTTPException(status_code=403, detail="Not a participant in this conversation")

    messages = state.store.query_messages(conversation_id, limit=500)

    # Build agent name lookup
    names: dict[str, str] = {}
    for ag in state.agents_by_did.values():
        names[ag.did_str] = ag.name

    lines: list[str] = []
    topic = conv.get("topic", "")
    if topic:
        lines.append(f"Topic: {topic}")
        lines.append("")
    for msg in messages:
        sender = names.get(msg["sender_did"], msg["sender_did"][:16])
        ts = msg["created_at"]
        intent_tag = f" [{msg.get('intent', '')}]" if msg.get("intent") else ""
        lines.append(f"[{ts}] {sender}{intent_tag}: {msg['content']}")

    logger.info("--- GET /conversations/%s/transcript ---", conversation_id[:12] + "...")
    logger.info("  %d messages for '%s'", len(messages), caller.name)

    return {
        "conversation_id": conversation_id,
        "topic": topic,
        "transcript": "\n".join(lines),
        "message_count": len(messages),
    }


@app.post("/conversations/{conversation_id}/close")
def close_conversation(conversation_id: str, x_api_key: str | None = Header(None)):
    caller = state.resolve_agent(_api_key(x_api_key))

    conv = state.store.get_conversation(conversation_id)
    if conv is None:
        raise HTTPException(status_code=404, detail="Conversation not found")
    if caller.did_str not in (conv["initiator_did"], conv["participant_did"]):
        raise HTTPException(status_code=403, detail="Not a participant in this conversation")
    if conv["status"] == "CLOSED":
        raise HTTPException(status_code=400, detail="Conversation already closed")

    now = datetime.now(UTC).isoformat()
    state.store.close_conversation(conversation_id, now)

    logger.info("--- POST /conversations/%s/close ---", conversation_id[:12] + "...")
    logger.info("  Closed by '%s' (%s)", caller.name, caller.did_str)

    return {
        "conversation_id": conversation_id,
        "status": "CLOSED",
        "closed_at": now,
        "closed_by": caller.did_str,
    }


@app.get("/messages/inbox")
def get_inbox(
    limit: int = Query(50),
    x_api_key: str | None = Header(None),
):
    caller = state.resolve_agent(_api_key(x_api_key))
    logger.info("--- GET /messages/inbox ---")
    messages = state.store.query_inbox(caller.did_str, limit=limit)
    logger.info("  Returning %d pending messages for '%s'", len(messages), caller.name)
    return {"messages": messages, "total": len(messages)}


@app.post("/messages/acknowledge")
def acknowledge_message(body: MessageAckRequest, x_api_key: str | None = Header(None)):
    caller = state.resolve_agent(_api_key(x_api_key))

    logger.info("--- POST /messages/acknowledge ---")
    logger.info("  Agent: '%s' (%s)", caller.name, caller.did_str)
    logger.info("  Message ID: %s", body.message_id)

    state.store.mark_message_delivered(body.message_id)
    return {"message_id": body.message_id, "acknowledged": True}


# -- WebSocket helpers -------------------------------------------------------


async def _notify_revocation(token_id_hex: str, revoker_did: str, reason: str) -> int:
    """Push token_revoked to the subject AND all holders of cascaded descendants.

    Returns the number of agents notified.
    """
    notified: set[str] = set()
    # Collect all affected token IDs (the revoked token + any cascade children)
    affected_tids = [token_id_hex]
    # Check CRL entries for cascaded revocations sharing the same root
    for tid_hex, tok in state.tokens.items():
        if tid_hex == token_id_hex:
            continue
        token_id_bytes = bytes.fromhex(tid_hex)
        if state.crl.is_revoked(token_id_bytes):
            # If this token's parent is the revoked one, it's part of the cascade
            if tok.parent_token_hash is not None:
                parent_hex = tok.parent_token_hash.hex()
                if parent_hex == token_id_hex or parent_hex in affected_tids:
                    affected_tids.append(tid_hex)

    for tid_hex in affected_tids:
        tok = state.tokens.get(tid_hex)
        if tok is None:
            continue
        subject_did = str(tok.subject_did)
        if subject_did in notified:
            continue
        if state.ws_manager.is_connected(subject_did):
            await state.ws_manager.send_json(subject_did, {
                "type": "token_revoked",
                "payload": {
                    "token_id": tid_hex,
                    "revoker_did": revoker_did,
                    "reason": reason,
                },
            })
            notified.add(subject_did)

    if notified:
        logger.info("  >> Revocation notices pushed to %d agent(s) via WebSocket", len(notified))
    return len(notified)


# -- WebSocket real-time channel ---------------------------------------------


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, api_key: str = Query(...)):
    # Authenticate before accepting
    agent = state.agents_by_api_key.get(api_key)
    if agent is None:
        await websocket.close(code=4003, reason="Invalid API key")
        return

    await websocket.accept()
    await state.ws_manager.connect(agent.did_str, websocket)
    if PROMETHEUS_AVAILABLE:
        WEBSOCKET_CONNECTIONS.inc()
    logger.info("WebSocket CONNECTED: '%s' (%s)", agent.name, agent.did_str)

    # Welcome message
    await websocket.send_json({
        "type": "connected",
        "agent_did": agent.did_str,
        "server_did": str(state.did),
        "timestamp": datetime.now(UTC).isoformat(),
    })

    # Flush pending inbox messages
    pending = state.store.query_inbox(agent.did_str, limit=50)
    for msg in pending:
        await websocket.send_json({"type": "message", "payload": msg})
        state.store.mark_message_delivered(msg["message_id"])
    if pending:
        logger.info("  Flushed %d pending messages to '%s' via WebSocket", len(pending), agent.name)

    # Listen loop
    try:
        while True:
            data = await websocket.receive_json()
            msg_type = data.get("type", "")

            if msg_type == "ping":
                await websocket.send_json({
                    "type": "pong",
                    "timestamp": datetime.now(UTC).isoformat(),
                })
            elif msg_type == "ack":
                message_id = data.get("message_id")
                if message_id:
                    state.store.mark_message_delivered(message_id)
            elif msg_type == "tool_result":
                request_id = data.get("request_id")
                if request_id:
                    state.ws_manager.resolve_pending(request_id, data.get("result", {}))
            else:
                await websocket.send_json({
                    "type": "error",
                    "detail": f"Unknown message type: {msg_type}",
                })
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.warning("WebSocket error for '%s': %s", agent.name, exc)
    finally:
        await state.ws_manager.disconnect(agent.did_str)
        if PROMETHEUS_AVAILABLE:
            WEBSOCKET_CONNECTIONS.dec()
        logger.info("WebSocket DISCONNECTED: '%s' (%s)", agent.name, agent.did_str)


# -- Admin ------------------------------------------------------------------


def _admin_key(x_admin_key: str | None) -> str:
    """Validate the admin API key from X-Admin-Key header."""
    if not x_admin_key or x_admin_key != state.admin_api_key:
        raise HTTPException(status_code=403, detail="Invalid or missing X-Admin-Key header")
    return x_admin_key


@app.get("/admin/agents")
def admin_list_agents(x_admin_key: str | None = Header(None)):
    _admin_key(x_admin_key)
    agents = []
    for agent in state.agents_by_did.values():
        trust = state.compute_trust(agent.did_str)
        agents.append({
            "did": agent.did_str,
            "name": agent.name,
            "tools_count": len(agent.tools),
            "tokens_issued": len(agent.tokens_issued),
            "metering_count": len(agent.metering),
            "trust_score": trust["score"],
        })
    return {"agents": agents, "total": len(agents)}


@app.get("/admin/agents/{did}/metering")
def admin_agent_metering(
    did: str,
    tool: str | None = Query(None),
    since: str | None = Query(None),
    until: str | None = Query(None),
    limit: int = Query(100),
    x_admin_key: str | None = Header(None),
):
    _admin_key(x_admin_key)
    if did not in state.agents_by_did:
        raise HTTPException(status_code=404, detail=f"Agent not found: {did}")
    records = state.store.query_metering(did, tool=tool, since=since, until=until, limit=limit)
    return {"agent_did": did, "records": records, "total": len(records)}


@app.get("/admin/agents/{did}/metering/summary")
def admin_agent_metering_summary(did: str, x_admin_key: str | None = Header(None)):
    _admin_key(x_admin_key)
    if did not in state.agents_by_did:
        raise HTTPException(status_code=404, detail=f"Agent not found: {did}")
    summary = state.store.metering_summary(did)
    return {"agent_did": did, **summary}


@app.get("/admin/receipts")
def admin_receipts(
    agent_did: str | None = Query(None),
    limit: int = Query(100),
    x_admin_key: str | None = Header(None),
):
    _admin_key(x_admin_key)
    records = state.store.query_all_metering(agent_did=agent_did, limit=limit)
    return {"records": records, "total": len(records)}


@app.get("/admin/tokens")
def admin_list_tokens(
    status: str | None = Query(None),
    x_admin_key: str | None = Header(None),
):
    _admin_key(x_admin_key)
    tokens = []
    for tid_hex, token in state.tokens.items():
        token_id_bytes = bytes.fromhex(tid_hex)
        is_revoked = state.crl.is_revoked(token_id_bytes)
        is_expired = token.is_expired()
        current_status = "revoked" if is_revoked else ("expired" if is_expired else "active")

        if status and current_status != status.lower():
            continue

        tokens.append({
            "token_id": tid_hex,
            "subject_did": str(token.subject_did),
            "audience_did": str(token.audience_did) if token.audience_did else None,
            "resource_uri": token.resource_uri,
            "verbs": sorted(token.verbs.verbs),
            "status": current_status,
            "expires_at": token.constraints.not_after.isoformat() if token.constraints.not_after else None,
        })
    return {"tokens": tokens, "total": len(tokens)}


@app.get("/admin/tokens/{token_id}/history")
def admin_token_history(token_id: str, x_admin_key: str | None = Header(None)):
    _admin_key(x_admin_key)
    if token_id not in state.tokens:
        raise HTTPException(status_code=404, detail="Token not found")

    token = state.tokens[token_id]
    token_id_bytes = bytes.fromhex(token_id)
    is_revoked = state.crl.is_revoked(token_id_bytes)
    is_expired = token.is_expired()
    current_status = "revoked" if is_revoked else ("expired" if is_expired else "active")

    events = state.store.query_token_events(token_id)
    return {
        "token_id": token_id,
        "current_status": current_status,
        "events": events,
    }


@app.get("/admin/disputes")
def admin_list_disputes(
    status: str | None = Query(None),
    x_admin_key: str | None = Header(None),
):
    _admin_key(x_admin_key)
    disputes = state.store.query_disputes(status=status)
    return {"disputes": disputes, "total": len(disputes)}


# ============================================================================
# Entry point
# ============================================================================


def main() -> None:
    parser = argparse.ArgumentParser(description="QASP Authority Server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--log-level", default="info")
    parser.add_argument("--db", default="qasp_authority.db", help="SQLite database path (default: qasp_authority.db)")
    parser.add_argument("--admin-key", default=None, help="Admin API key for /admin/ endpoints (auto-generated if omitted)")
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    global state
    state = AuthorityState(db_path=args.db, admin_api_key=args.admin_key)

    print()
    print("=" * 64)
    print("  QASP Authority Server")
    print(f"  DID:  {state.did}")
    print(f"  URL:  http://{args.host}:{args.port}")
    print()
    print("  Crypto:  ML-DSA-65 (FIPS 204) post-quantum signatures")
    print("  Tokens:  CBOR-encoded, 1hr validity, 10 calls/60s limit")
    print("  Trust:   Bayesian scoring with anti-gaming caps")
    print("  Messaging: Agent-to-agent conversations with inbox")
    print()
    print(f"  DB:       {args.db}")
    print(f"  Admin:    X-Admin-Key: {state.admin_api_key}")
    print(f"  Metrics:  /metrics {'(prometheus-client loaded)' if PROMETHEUS_AVAILABLE else '(prometheus-client not installed)'}")
    print("=" * 64)
    print()

    uvicorn.run(app, host=args.host, port=args.port, log_level=args.log_level)


if __name__ == "__main__":
    main()
