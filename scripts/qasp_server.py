"""QASP Authority Server — Live demo for audience agents.

Run:
    python scripts/qasp_server.py --host 0.0.0.0 --port 8080

Every audience member registers via REST, discovers peers, requests
capability tokens, and calls each other's tools — all secured by
QASP with ML-DSA-65 post-quantum signatures.
"""

from __future__ import annotations

import argparse
import base64
import logging
import time
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
import uvicorn
from fastapi import FastAPI, Header, HTTPException, Query
from pydantic import BaseModel

from qasp.crypto.signatures import generate_keypair
from qasp.identity.did import DID, DIDRegistry, create_did
from qasp.protocol.arm import uri_matches
from qasp.protocol.capability import (
    ARM_EXEC,
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


# ============================================================================
# Server state
# ============================================================================


class AgentRecord:
    """Per-agent state held by the authority."""

    __slots__ = (
        "agent_id", "name", "did", "did_str",
        "public_key", "secret_key", "api_key",
        "callback_url", "tools", "tokens_issued", "metering",
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
        self.tokens_issued: dict[str, CapabilityToken] = {}
        self.metering: list[dict[str, Any]] = []


class AuthorityState:
    """All server-side state, initialised at startup."""

    def __init__(self) -> None:
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
# FastAPI app
# ============================================================================

state: AuthorityState  # set in main()
app = FastAPI(title="QASP Authority", version="0.1.0")


def _api_key(x_api_key: str | None = Header(None)) -> str:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")
    return x_api_key


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
    ]


# -- Registration -----------------------------------------------------------

@app.post("/register")
def register(body: RegisterRequest):
    logger.info("--- POST /register ---")
    logger.info("  Agent name: %s", body.name)
    logger.info("  Tools declared: %s", [t.name for t in body.tools])
    logger.info("  Callback URL: %s", body.callback_url or "(none)")

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
    )
    state.agents_by_api_key[api_key] = agent
    state.agents_by_did[did_str] = agent

    logger.info("  Agent '%s' registered successfully (total agents: %d)", body.name, len(state.agents_by_did))

    return {
        "agent_id": agent.agent_id,
        "did": did_str,
        "api_key": api_key,
        "public_key": base64.b64encode(pub).decode(),
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
def request_token(body: TokenRequest, x_api_key: str | None = Header(None)):
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

    token_cbor = token.to_cbor_with_signature()

    expires = token.constraints.not_after.isoformat() if token.constraints.not_after else "never"
    logger.info("  >> Token issued: id=%s  expires=%s  rate_limit=10/60s", tid_hex[:16] + "...", expires)
    logger.info("  >> Registered in CRL for OCSP tracking")

    return {
        "token": base64.b64encode(token_cbor).decode(),
        "token_id": tid_hex,
        "resource_uri": resource_uri,
        "verbs": sorted(verbs),
        "expires_at": token.constraints.not_after.isoformat() if token.constraints.not_after else None,
    }


@app.post("/tokens/revoke")
def revoke_token(body: TokenRevokeRequest, x_api_key: str | None = Header(None)):
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
    tokens_before = limiter.tokens
    if not limiter.consume():
        logger.warning("  DENIED: Rate limit exceeded (%d/%d used in %ds window)", rate_limit, rate_limit, rate_period)
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded ({rate_limit} calls per {rate_period}s). Retry after {1.0 / limiter.refill_rate:.1f}s",
        )
    logger.info("  [6/7] >> Rate limit OK (%.0f/%d tokens remaining, %ds window)", limiter.tokens, rate_limit, rate_period)

    # 5) Relay to target callback
    call_result: Any = None
    if target.callback_url:
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
            logger.info("  [7/7] >> Relay complete (%d %s, %.0fms)", resp.status_code, resp.reason_phrase, elapsed_ms)
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - t0) * 1000
            logger.warning("  [7/7] >> Relay FAILED (%.0fms): %s", elapsed_ms, exc)
            call_result = {"error": f"Callback failed: {exc}"}
    else:
        logger.info("  [7/7] No callback_url — echoing arguments (demo mode)")
        call_result = {
            "echo": body.arguments,
            "tool": body.tool_name,
            "handled_by": target.name,
            "note": "No callback_url configured; echoing arguments",
        }

    # 6) Metering
    receipt_id = uuid.uuid4().hex
    metering = {"units": 1, "cost": 10, "currency": "credits"}
    caller.metering.append({
        "receipt_id": receipt_id,
        "tool": body.tool_name,
        "target": body.target_did,
        "timestamp": datetime.now(UTC).isoformat(),
        **metering,
    })
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
def report_trust(did: str, body: TrustReportRequest, x_api_key: str | None = Header(None)):
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

    return {
        "did": did,
        "outcome": body.outcome,
        "updated_trust": new_trust,
    }


# -- Disputes ---------------------------------------------------------------

@app.post("/disputes/open")
def open_dispute(body: DisputeOpenRequest, x_api_key: str | None = Header(None)):
    caller = state.resolve_agent(_api_key(x_api_key))

    logger.info("--- POST /disputes/open ---")
    logger.info("  Claimant: '%s' (%s)", caller.name, caller.did_str)
    logger.info("  Respondent DID: %s", body.respondent_did)
    logger.info("  Type: %s", body.type)
    logger.info("  Description: %s", body.description or "(none)")

    dispute_id = uuid.uuid4().hex
    dispute = {
        "dispute_id": dispute_id,
        "claimant_did": caller.did_str,
        "respondent_did": body.respondent_did,
        "type": body.type,
        "description": body.description,
        "status": "OPEN",
        "opened_at": datetime.now(UTC).isoformat(),
        "verdict": None,
    }
    state.disputes[dispute_id] = dispute
    logger.info("  >> Dispute created: id=%s  status=OPEN", dispute_id)
    return {"dispute_id": dispute_id, "status": "OPEN"}


@app.get("/disputes/{dispute_id}")
def get_dispute(dispute_id: str):
    dispute = state.disputes.get(dispute_id)
    if dispute is None:
        raise HTTPException(status_code=404, detail="Dispute not found")
    return dispute


# ============================================================================
# Entry point
# ============================================================================


def main() -> None:
    parser = argparse.ArgumentParser(description="QASP Authority Server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--log-level", default="info")
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    global state
    state = AuthorityState()

    print()
    print("=" * 64)
    print("  QASP Authority Server")
    print(f"  DID:  {state.did}")
    print(f"  URL:  http://{args.host}:{args.port}")
    print()
    print("  Crypto:  ML-DSA-65 (FIPS 204) post-quantum signatures")
    print("  Tokens:  CBOR-encoded, 1hr validity, 10 calls/60s limit")
    print("  Trust:   Bayesian scoring with anti-gaming caps")
    print("=" * 64)
    print()

    uvicorn.run(app, host=args.host, port=args.port, log_level=args.log_level)


if __name__ == "__main__":
    main()
