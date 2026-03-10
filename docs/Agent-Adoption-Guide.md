# QASP Agent Adoption and Integration Guide

## Document Control

| Field | Value |
|---|---|
| Document Title | QASP Agent Adoption and Integration Guide |
| Version | 1.0.0 |
| Date | 2026-03-10 |
| Classification | Public — Engineering Reference |
| Audience | Software engineers, platform architects, AI agent developers |
| Status | Released |

### Revision History

| Version | Date | Author | Summary |
|---|---|---|---|
| 0.1 | 2026-02-14 | QASP Platform Team | Initial draft |
| 0.9 | 2026-03-01 | QASP Platform Team | Added language guides and appendices |
| 1.0 | 2026-03-10 | QASP Platform Team | Released for public adoption |

---

## Table of Contents

1. Introduction
2. Architecture Overview for Adopters
3. Prerequisites and Readiness Assessment
4. Integration Guide: Step-by-Step
5. Exposing Tools to Other Agents
6. Language-Specific Integration Guides
7. Integration Patterns
8. Production Readiness Checklist
9. Testing Your Integration
10. Security Best Practices for Agents
11. Operational Guidance
12. Migration Guide
13. FAQ and Troubleshooting
14. Appendix A: Complete Python Integration Example
15. Appendix B: Complete JavaScript Integration Example
16. Appendix C: API Quick Reference Card
17. Appendix D: Token Lifecycle State Diagram
18. Appendix E: Agent Capability Checklist

---

## 1. Introduction

### 1.1 What Is QASP and Why Adopt It

QASP (Quantum-Aware Secure Protocol) is a protocol that enables AI agents to discover one another, request scoped access tokens, and invoke each other's tools — all secured by post-quantum cryptography. It is designed for the era in which sufficiently capable quantum computers could break the elliptic-curve and RSA schemes that most current security infrastructure depends on.

The cryptographic core uses ML-DSA-65 (Module Lattice Digital Signature Algorithm, NIST FIPS 204) for all identity proofs and token signatures, and assigns every participating agent a Decentralised Identifier (DID) of the form `did:qasp:<identifier>`. These identifiers and their associated keypairs are fully managed by the QASP Authority Server. Agents never handle raw cryptographic material.

From the perspective of a developer integrating an AI agent, QASP is a straightforward REST API. You call HTTP endpoints, receive JSON responses, and store three strings. The protocol's cryptographic sophistication is entirely opaque to your agent code.

The protocol addresses five practical enterprise problems that arise as AI agent populations grow:

**Identity proliferation.** As the number of agents in a system increases, so does the attack surface created by ad-hoc identity schemes (shared secrets, bearer tokens with no scope). QASP assigns each agent a verifiable, globally unique DID from its first registration call.

**Least-privilege enforcement.** Agents should not hold blanket credentials that permit unlimited access to peer services. QASP capability tokens are scoped to a single named tool on a single agent, expire after one hour by default, and carry an embedded rate limit. A compromised token produces bounded damage.

**Trust without prior relationship.** When Agent A has never interacted with Agent B, there is no basis for a trust decision. QASP's Bayesian trust scoring system aggregates reported outcomes across all interactions on the network, providing a continuously updated, anti-gamed trust score that any agent can query before deciding whether to engage.

**Auditability.** Every tool call through the authority produces a receipt ID and a metering record. The token issuance and revocation log provides a complete audit trail.

**Dispute resolution.** When agents disagree about a transaction — overcharges, incorrect outputs, service failures — QASP provides a formal dispute mechanism backed by the authority.

### 1.2 The Agent Participation Model

QASP follows a hub-and-spoke topology where the QASP Authority Server acts as the trusted hub for all cryptographic operations. Agents are the spokes. The authority:

- Generates and holds the keypair for every registered agent
- Signs all capability tokens with its own ML-DSA-65 key
- Verifies token signatures, expiry, revocation status, scope, and rate limits on every tool call
- Relays verified tool calls to the target agent's callback URL
- Maintains trust scores, dispute records, and the certificate revocation list (CRL)

The result is that agents operate as thin HTTP clients. An agent participates fully in the QASP network by doing nothing more than:

1. Sending a POST request to `/register` to receive credentials
2. Sending a GET request to `/discover` to find peers
3. Sending a POST request to `/tokens/request` to get a scoped token
4. Sending a POST request to `/tools/call` to invoke a peer's tool

No cryptographic library is required. No binary protocol is required. No SDK is required. Any runtime that can speak HTTP and JSON participates on equal terms.

### 1.3 Benefits of QASP Adoption

**Post-quantum security without cryptographic expertise.** Your engineering team does not need to understand lattice-based cryptography, key encapsulation mechanisms, or CBOR encoding. The authority server handles all of it. Your agent code sees base64 strings and JSON.

**Scoped, time-limited, revocable tokens.** Each token is bound to a specific tool on a specific agent and expires after one hour. If a token is exposed, it can be revoked immediately via a single POST request, and the OCSP endpoint provides real-time status verification.

**Built-in rate limiting.** Token bucket rate limiting (default: 10 calls per 60 seconds per token) is enforced server-side. Agents do not need to implement their own rate limiting logic when calling peer tools.

**Reputation-based trust scoring.** The Bayesian trust system uses a Beta distribution model with anti-gaming caps. A new agent starts at a trust score of 0.5. Scores above 0.7 require at least 10 interactions, above 0.8 require 50, and above 0.9 require 200. This makes reputation manipulation costly and slow.

**Pluggable tool discovery.** The `/discover` endpoint with ARM URI pattern matching lets agents find peers by capability pattern (for example, `qasp://*/tools/summarize`) or by minimum trust threshold, without any hardcoded agent addresses.

**Zero-infrastructure trust for tool providers.** An agent that wants to expose tools to the network does not need to implement authentication, token verification, or rate limiting in its callback server. All of that runs in the authority. The callback receives verified, authorized, rate-checked calls.

### 1.4 Document Scope and Audience

This guide covers everything an engineering team needs to integrate an AI agent into an existing QASP network. It assumes the QASP Authority Server is already running and accessible. It does not cover deploying or administering the authority server.

The primary audience is engineers building:

- AI agent runtimes that need to call external tools
- Services that want to expose capabilities to AI agents
- Agent orchestration frameworks that manage multiple agents
- Infrastructure teams evaluating QASP for enterprise deployment

The guide progresses from conceptual overview (Sections 1–3) through step-by-step integration (Sections 4–6) to production operations (Sections 8–12). Readers integrating a specific language runtime may jump directly to Section 6. Readers migrating from an existing protocol should begin at Section 12.

---

## 2. Architecture Overview for Adopters

### 2.1 QASP Network Topology

The network consists of three logical roles:

```
                        QASP Authority Server
                       +--------------------------------+
                       |  DID Registry                  |
                       |  Token Issuance (ML-DSA-65)    |
                       |  Token Verification            |
                       |  Rate Limiter Registry         |
                       |  Certificate Revocation List   |
                       |  OCSP Responder                |
                       |  Trust Registry + Scorer       |
                       |  Dispute Store                 |
                       |  Tool Call Relay               |
                       +---------------+----------------+
                                       | HTTPS / JSON
              +------------------------+------------------------+
              |                        |                        |
     +--------+-------+       +--------+-------+       +--------+-------+
     |  Agent A        |       |  Agent B        |       |  Agent C        |
     |  (Consumer)     |       |  (Provider)     |       |  (Dual)         |
     |                 |       |                 |       |                 |
     |  HTTP client    |       |  HTTP client    |       |  HTTP client    |
     |                 |       |  + callback     |       |  + callback     |
     |                 |       |    server       |       |    server       |
     +-----------------+       +-----------------+       +-----------------+
```

All communication between agents flows through the authority server. Agents do not contact each other directly. When Agent A calls a tool on Agent B, the sequence is:

1. Agent A sends `POST /tools/call` to the authority with its token and arguments
2. The authority validates the token, rate checks, and scope checks
3. The authority forwards the verified call to Agent B's callback URL
4. Agent B's callback processes and returns a result
5. The authority meters the call, records a receipt, and returns the result to Agent A

Agent B's callback server receives only pre-validated calls. It never needs to inspect tokens or API keys.

### 2.2 Communication Model

Every interaction uses plain HTTPS with JSON bodies and JSON responses. There are no binary framing protocols, no persistent connections, no WebSocket upgrades, and no streaming requirements for basic operation.

Request conventions:
- `GET` requests carry parameters as query strings
- `POST` requests carry bodies as `Content-Type: application/json`
- All authenticated requests carry `X-API-Key: <api_key>` as a header
- All responses are JSON objects or JSON arrays

The base URL of the authority server is the only configuration an agent needs. Everything else — DIDs, resource URIs, token formats — is returned by the server and used opaquely.

### 2.3 Security Model from the Agent's Perspective

From an integrating agent's viewpoint, there are two distinct security layers:

**Authentication** establishes that a request is coming from a registered agent. It uses the `X-API-Key` header returned at registration. This key is a UUID hex string (32 hex characters). It must be stored securely and sent with every request to authenticated endpoints.

**Authorization** establishes that a specific action on a specific resource is permitted. It uses capability tokens — base64-encoded, CBOR-serialized, ML-DSA-65 signed blobs. Agents do not parse, verify, or generate tokens. They receive them from `/tokens/request` and pass them opaquely to `/tools/call`. The authority verifies everything.

The agent security posture reduces to three rules:

1. Protect the API key as you would a private key. Do not log it, commit it to source control, or embed it in client-side code.
2. Acquire tokens with the narrowest scope required (specific tool, specific target).
3. Revoke tokens that are no longer needed or that may have been exposed.

### 2.4 What the Authority Server Handles vs. What the Agent Handles

| Concern | Authority Server | Agent |
|---|---|---|
| Keypair generation | Generates ML-DSA-65 keypair per agent at registration | Nothing |
| DID creation | Derives `did:qasp:<id>` from public key | Stores the DID string |
| Token signing | Signs tokens with ML-DSA-65 authority key | Nothing |
| Token verification | Verifies signature, expiry, revocation, scope, verb | Nothing |
| Rate limiting | Enforces token bucket per token ID | Honors 429 responses |
| Revocation | Maintains CRL, OCSP responder | Optionally calls revoke endpoint |
| Trust scoring | Bayesian update on reported outcomes | Optionally reports outcomes |
| Tool call relay | Forwards verified calls to callback URL | Implements callback handler |
| Metering | Records per-call receipt with cost | Reads receipt from response |
| Dispute handling | Stores and tracks disputes | Opens disputes, queries status |

---

## 3. Prerequisites and Readiness Assessment

### 3.1 Minimum Agent Capabilities (Checklist)

The following are the non-negotiable requirements for any agent to join the QASP network. An agent that satisfies all five can register, discover, acquire tokens, and call tools.

- [ ] Can send an HTTP POST request with a JSON body to an HTTPS URL
- [ ] Can send an HTTP GET request with query string parameters to an HTTPS URL
- [ ] Can set custom request headers (specifically `X-API-Key` and `Content-Type`)
- [ ] Can store three strings in memory or persistent state: `api_key`, `did`, and one or more `token` values
- [ ] Has at least one tool definition with a `name` field and a `description` field

> **Note:** If your agent runtime cannot set custom headers, it cannot authenticate with the QASP authority. This is the single most common blocker for constrained runtimes. Verify header support before beginning integration.

### 3.2 Full-Featured Agent Capabilities (Checklist)

These capabilities unlock additional QASP features and improve production reliability.

- [ ] Runs an HTTP server capable of accepting POST requests (enables receiving tool calls)
- [ ] Serves the callback path `POST /tools/{tool_name}` with JSON request and response bodies
- [ ] Returns HTTP responses within 30 seconds on all callback paths
- [ ] Implements token caching keyed by `(target_did, tool_name)` to avoid redundant token requests
- [ ] Checks token expiry before reuse (parse `expires_at` from the token request response)
- [ ] Reports interaction outcomes via `POST /trust/{did}/report` after each tool call
- [ ] Handles HTTP 429 responses with exponential backoff and retry
- [ ] Handles HTTP 403 responses by discarding the cached token and re-requesting
- [ ] Stores API key in environment variable or secrets manager, not in source code
- [ ] Has tool definitions with `input_schema` for richer discoverability

### 3.3 Network Requirements

- HTTPS access to the QASP Authority Server on its configured port (default 8080 in development, 443 in production)
- Outbound TCP allowed to the authority server's hostname and port
- If exposing a callback endpoint: inbound TCP from the authority server's IP range to your callback port
- No special firewall rules are needed for agent-to-agent communication because all tool calls are relayed through the authority

For production deployments where the callback server runs behind a load balancer or NAT, ensure the `callback_url` registered with the authority resolves to the correct inbound address. The authority makes a direct HTTP POST to this URL for every tool call.

### 3.4 Team Skill Requirements

| Skill | Required | Notes |
|---|---|---|
| HTTP client usage in target language | Required | GET/POST with custom headers |
| JSON serialization/deserialization | Required | All payloads are JSON |
| Environment variable or secrets management | Required | For API key storage |
| HTTP server implementation | Optional | Only for tool providers |
| Understanding of token expiry and caching | Recommended | Reduces unnecessary requests |
| Familiarity with retry and backoff patterns | Recommended | For 429 handling |
| Post-quantum cryptography knowledge | Not required | Handled entirely by authority |

### 3.5 Readiness Assessment Matrix

Score your agent against the following. A score of 12 or above indicates readiness to proceed.

| Capability | Points | Your Score |
|---|---|---|
| HTTP POST with JSON body | 3 | |
| Custom header support | 3 | |
| State storage (3 strings) | 2 | |
| At least one tool definition | 1 | |
| HTTPS support | 2 | |
| Callback server capability | 2 | |
| Secrets management | 2 | |
| Error handling (4xx/5xx) | 1 | |
| Retry logic | 1 | |
| **Total** | **17** | |

**Interpretation:**
- 10–12: Minimum viable integration. Proceed to Section 4.
- 13–15: Standard integration. All core features available.
- 16–17: Full-featured integration. Production-ready.

---

## 4. Integration Guide: Step-by-Step

This section walks through all seven integration phases in order. Each phase is independent after registration; phases 2–7 can be implemented progressively.

### 4.1 Phase 1: Registration

Registration is a single HTTP POST that returns the credentials your agent will use for all subsequent interactions. It is typically called once at agent startup. If the authority server restarts and loses state, you will need to re-register (see Section 11.3).

**What happens server-side during registration:**

1. The authority generates a fresh ML-DSA-65 keypair for your agent
2. It derives a `did:qasp:<identifier>` from the public key hash
3. It registers the DID document in its DID registry
4. It creates a trust entry with an initial score of 0.5
5. It generates a UUID API key
6. It maps each tool definition to an ARM resource URI: `qasp://agents/{did_short}/tools/{tool_name}`
7. It returns the agent ID, DID, API key, and base64-encoded public key

Your agent needs to store only the `api_key` and `did`. The public key is informational.

**Python (using qasp_client.py):**

```python
from scripts.qasp_client import QASPClient, QASPError

qasp = QASPClient("https://qasp.example.com")

try:
    registration = qasp.register(
        name="DataAnalysisAgent",
        tools=[
            {
                "name": "analyze",
                "description": "Analyze a dataset and return statistical insights",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "data": {"type": "string", "description": "CSV or JSON data"},
                        "metric": {"type": "string", "enum": ["mean", "median", "stddev"]}
                    },
                    "required": ["data"]
                }
            },
            {
                "name": "summarize",
                "description": "Produce a plain-language summary of structured data"
            }
        ],
        callback_url="https://my-agent.example.com"
    )
except QASPError as e:
    print(f"Registration failed ({e.status_code}): {e.detail}")
    raise SystemExit(1)

# After register(), qasp._api_key and qasp._did are set automatically.
# Store these for persistence across restarts.
api_key = registration["api_key"]   # store securely
my_did = registration["did"]        # store for reference

print(f"Registered. DID: {my_did}")
print(f"Public key (informational): {registration['public_key'][:20]}...")
```

**Python (using raw httpx):**

```python
import httpx
import os

AUTHORITY_URL = "https://qasp.example.com"

resp = httpx.post(
    f"{AUTHORITY_URL}/register",
    json={
        "name": "DataAnalysisAgent",
        "tools": [
            {"name": "analyze", "description": "Analyze a dataset"}
        ],
        "callback_url": "https://my-agent.example.com"
    }
)
resp.raise_for_status()

data = resp.json()
api_key = data["api_key"]
my_did = data["did"]

# Persist securely — do not hardcode or log api_key
os.environ["QASP_API_KEY"] = api_key
os.environ["QASP_DID"] = my_did
```

**JavaScript (fetch):**

```javascript
const AUTHORITY_URL = "https://qasp.example.com";

async function register(name, tools, callbackUrl = "") {
    const response = await fetch(`${AUTHORITY_URL}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, tools, callback_url: callbackUrl })
    });

    if (!response.ok) {
        const err = await response.json();
        throw new Error(`Registration failed ${response.status}: ${err.detail}`);
    }

    const data = await response.json();
    // Store securely — in Node.js, use environment variables or a secrets manager
    process.env.QASP_API_KEY = data.api_key;
    process.env.QASP_DID = data.did;
    return data;
}

const reg = await register("JSAgent", [
    { name: "fetch_data", description: "Fetch data from an external source" }
], "https://js-agent.example.com");

console.log("Registered DID:", reg.did);
```

**curl:**

```bash
curl -s -X POST https://qasp.example.com/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ShellAgent",
    "tools": [
      {"name": "echo", "description": "Echo input back"}
    ],
    "callback_url": "https://shell-agent.example.com"
  }' | tee registration.json

# Extract values for use in subsequent calls
export QASP_API_KEY=$(jq -r '.api_key' registration.json)
export QASP_DID=$(jq -r '.did' registration.json)
echo "Registered: $QASP_DID"
```

**Storing credentials securely:**

> **Warning:** The `api_key` returned at registration is equivalent to a password. It is not recoverable if lost — you must re-register. Never log it, never commit it to source control, and never embed it in client-side browser code. Store it in an environment variable, a secrets manager (AWS Secrets Manager, HashiCorp Vault, Kubernetes Secret), or an encrypted configuration file with appropriate file permissions.

For applications that restart frequently, persist both `api_key` and `did` to durable storage on first registration. On subsequent startups, load from storage rather than re-registering. The authority's trust score for your DID accumulates over time; re-registering creates a new DID with a fresh score of 0.5.

### 4.2 Phase 2: Discovery

Discovery lets your agent find other agents on the network. It returns a list of agent records sorted by trust score descending.

```python
# Discover all agents
agents = qasp.discover()

# Discover agents with a specific tool, minimum trust 0.3
agents = qasp.discover(capability="qasp://*/tools/summarize", min_trust=0.3)

# Each agent record contains:
# {
#   "name": "SummarizerAgent",
#   "did": "did:qasp:2ZTp9sZY...",
#   "tools": [
#     {
#       "name": "summarize",
#       "description": "Produce a plain-language summary",
#       "resource_uri": "qasp://agents/2ZTp9sZY.../tools/summarize",
#       "input_schema": {"type": "object", ...}
#     }
#   ],
#   "trust_score": 0.62,
#   "endpoint": "https://summarizer.example.com"
# }

for agent in agents:
    print(f"{agent['name']} (trust: {agent['trust_score']:.2f})")
    for tool in agent['tools']:
        print(f"  - {tool['name']}: {tool['description']}")
```

**Filtering by capability pattern:**

The `capability` parameter uses ARM URI matching. The pattern `qasp://*/tools/analyze` matches any agent's `analyze` tool. The wildcard `*` in the provider segment matches any DID prefix. You can also use exact resource URIs if you already know the target.

```python
# Find agents with an "analyze" tool
analysts = qasp.discover(capability="qasp://*/tools/analyze")

# Find agents with any tool (default)
all_agents = qasp.discover()

# Find only highly trusted agents
trusted = qasp.discover(min_trust=0.7)
```

**Caching discovery results:**

The discovery endpoint is authenticated and hits the server each call. For agents that invoke tools in a loop, cache results with a short TTL (60–300 seconds) to avoid saturating the endpoint.

```python
import time

_discovery_cache: dict[str, list] = {}
_cache_timestamps: dict[str, float] = {}
CACHE_TTL = 120  # seconds

def discover_cached(qasp_client, capability="*", min_trust=0.0) -> list:
    key = f"{capability}:{min_trust}"
    now = time.time()
    if key in _discovery_cache and (now - _cache_timestamps[key]) < CACHE_TTL:
        return _discovery_cache[key]
    results = qasp_client.discover(capability=capability, min_trust=min_trust)
    _discovery_cache[key] = results
    _cache_timestamps[key] = now
    return results
```

### 4.3 Phase 3: Token Acquisition

Before calling any tool, your agent must acquire a capability token scoped to that tool. Tokens are issued by the authority on behalf of your agent, signed with the authority's ML-DSA-65 key, and valid for one hour.

```python
# Request a token to call the "analyze" tool on a specific agent
token_info = qasp.request_token(
    target_did="did:qasp:2ZTp9sZY...",
    tool_name="analyze"
)

# token_info contains:
# {
#   "token": "base64-encoded-cbor-blob...",  <-- pass this to call_tool
#   "token_id": "a1b2c3d4...",               <-- hex string, use for revoke/status
#   "resource_uri": "qasp://agents/2ZTp9sZY.../tools/analyze",
#   "verbs": ["exec"],
#   "expires_at": "2026-03-10T15:00:00+00:00"
# }
```

**Token scope and lifetime:**

Each token is scoped to:
- A specific resource URI (`qasp://agents/{did_short}/tools/{tool_name}`)
- A specific verb set (default: `["exec"]`)
- A specific subject (your agent's DID)
- A specific audience (the target agent's DID)
- A rate limit (default: 10 calls per 60 seconds)
- An expiry time (default: 1 hour from issuance)

Attempting to use a token against a different tool or agent will result in a 403 Forbidden response with the detail `Resource URI mismatch`.

**Token caching strategy:**

Do not request a new token for every call. Cache tokens by `(target_did, tool_name)` and reuse them until they are within 5 minutes of expiry.

```python
import datetime

_token_cache: dict[tuple, dict] = {}

def get_token(qasp_client, target_did: str, tool_name: str) -> str:
    """Return a valid cached token or request a fresh one."""
    key = (target_did, tool_name)
    cached = _token_cache.get(key)

    if cached:
        expires_at = datetime.datetime.fromisoformat(cached["expires_at"])
        now = datetime.datetime.now(datetime.timezone.utc)
        # Refresh if less than 5 minutes remain
        if (expires_at - now).total_seconds() > 300:
            return cached["token"]

    # Request fresh token
    token_info = qasp_client.request_token(target_did, tool_name)
    _token_cache[key] = token_info
    return token_info["token"]
```

### 4.4 Phase 4: Tool Invocation

With a valid token, your agent can call any tool on any agent. The call is relayed through the authority, which performs all validation before forwarding.

```python
result = qasp.call_tool(
    target_did="did:qasp:2ZTp9sZY...",
    tool_name="analyze",
    arguments={
        "data": "col1,col2\n1,2\n3,4",
        "metric": "mean"
    },
    token=token_info["token"]
)

# result contains:
# {
#   "result": { ... },    <-- the target agent's response
#   "metering": {
#     "units": 1,
#     "cost": 10,
#     "currency": "credits"
#   },
#   "receipt_id": "f47ac10b..."
# }

print(result["result"])
print(f"Cost: {result['metering']['cost']} {result['metering']['currency']}")
print(f"Receipt: {result['receipt_id']}")
```

**The 7-step verification sequence:**

When the authority receives `POST /tools/call`, it performs these checks in order before relaying to the callback:

1. Authenticates the caller via `X-API-Key`
2. Resolves the target agent by `target_did`
3. Looks up the named tool on the target agent
4. Decodes the base64 token and deserializes CBOR
5. Verifies the ML-DSA-65 signature and checks expiry and revocation status against the CRL
6. Validates ARM URI scope (token's resource URI must match the tool's URI)
7. Checks the `exec` verb is present in the token and enforces the rate limit

If any step fails, the authority returns a 4xx error without contacting the target agent. The target agent's callback only receives calls that have passed all seven checks.

**Handling errors from tool calls:**

```python
from scripts.qasp_client import QASPError
import time

def call_tool_with_retry(qasp_client, target_did, tool_name, arguments, max_retries=3):
    token = get_token(qasp_client, target_did, tool_name)
    delay = 1.0

    for attempt in range(max_retries):
        try:
            return qasp_client.call_tool(target_did, tool_name, arguments, token)

        except QASPError as e:
            if e.status_code == 429:
                # Rate limited — wait and retry
                print(f"Rate limited. Waiting {delay:.1f}s before retry {attempt + 1}")
                time.sleep(delay)
                delay *= 2  # exponential backoff
                continue

            elif e.status_code == 403:
                # Token expired or revoked — clear cache and re-request
                key = (target_did, tool_name)
                _token_cache.pop(key, None)
                token = get_token(qasp_client, target_did, tool_name)
                continue

            elif e.status_code == 404:
                # Agent or tool not found — do not retry
                raise

            else:
                raise

    raise RuntimeError(f"Failed after {max_retries} retries")
```

### 4.5 Phase 5: Token Management

**Checking token status (OCSP):**

The authority provides real-time token status via the OCSP endpoint. This is a public endpoint that does not require authentication, suitable for external validators.

```python
status = qasp.check_token(token_info["token_id"])
# {"token_id": "a1b2c3d4...", "status": "GOOD"}
# or
# {"token_id": "a1b2c3d4...", "status": "REVOKED", "revoked_at": "2026-03-10T..."}
# or
# {"token_id": "a1b2c3d4...", "status": "UNKNOWN"}

if status["status"] == "GOOD":
    print("Token is valid")
elif status["status"] == "REVOKED":
    print(f"Token revoked at {status.get('revoked_at', 'unknown time')}")
```

**Revoking tokens:**

Revoke tokens when:
- The task they were issued for is complete
- You suspect the token may have been logged or exposed
- The target agent or its tool is no longer trusted

```python
revoke_result = qasp.revoke_token(token_info["token_id"])
# {"revoked": true, "token_id": "...", "entries_created": 1}

# Confirm revocation via OCSP
status = qasp.check_token(token_info["token_id"])
assert status["status"] == "REVOKED"
```

After revocation, any subsequent call using the revoked token will receive HTTP 403 with detail `Token ... has been revoked`.

**Token refresh before expiry:**

For long-running processes, implement proactive refresh to avoid mid-operation token expiry:

```python
def ensure_fresh_token(qasp_client, target_did, tool_name, refresh_window_seconds=300):
    """Return a token guaranteed to be valid for at least refresh_window_seconds."""
    key = (target_did, tool_name)
    cached = _token_cache.get(key)

    if cached:
        expires_at = datetime.datetime.fromisoformat(cached["expires_at"])
        now = datetime.datetime.now(datetime.timezone.utc)
        remaining = (expires_at - now).total_seconds()
        if remaining > refresh_window_seconds:
            return cached["token"]
        # Proactively revoke the old token before requesting a new one
        try:
            qasp_client.revoke_token(cached["token_id"])
        except Exception:
            pass  # Best-effort revocation

    token_info = qasp_client.request_token(target_did, tool_name)
    _token_cache[key] = token_info
    return token_info["token"]
```

### 4.6 Phase 6: Trust Participation

Reporting interaction outcomes is optional but important. The QASP trust network is only as accurate as the data agents contribute to it. Agents that consistently report are more trustworthy sources of network intelligence.

**Reporting outcomes:**

```python
# After a successful tool call
qasp.report_interaction(
    did="did:qasp:2ZTp9sZY...",
    outcome="success"
)

# After a failed or problematic tool call
qasp.report_interaction(
    did="did:qasp:2ZTp9sZY...",
    outcome="failure",
    details="Tool returned malformed JSON after 28 seconds"
)
```

**Querying trust scores:**

```python
trust = qasp.get_trust("did:qasp:2ZTp9sZY...")
# {
#   "score": 0.62,
#   "interaction_count": 14,
#   "components": {
#     "reputation": 0.58,
#     "certification": 0.0,
#     "behavioral": 0.65,
#     "witness": 0.50,
#     "confidence": 0.28
#   }
# }
```

**Using trust for decision-making:**

The trust score runs from 0.0 to 1.0 with the following interpretation guidance:

| Score Range | Interpretation | Recommended Policy |
|---|---|---|
| 0.0 – 0.3 | Low trust, few or mostly failed interactions | Require human approval before use |
| 0.3 – 0.5 | Moderate trust or new agent | Proceed with logging and monitoring |
| 0.5 – 0.7 | Established agent with positive history | Normal operation |
| 0.7 – 0.9 | High trust, many successful interactions | Prefer for critical tasks |
| 0.9 – 1.0 | Exceptional trust, large interaction history | First-choice for sensitive operations |

```python
def select_best_agent(agents: list, min_trust: float = 0.4) -> dict | None:
    """Select the highest-trust agent that meets the minimum threshold."""
    eligible = [a for a in agents if a["trust_score"] >= min_trust]
    if not eligible:
        return None
    return max(eligible, key=lambda a: a["trust_score"])
```

### 4.7 Phase 7: Dispute Resolution

When a tool call produces an unacceptable outcome — incorrect results, overcharging, timeout without result — use the dispute mechanism to create a formal record.

```python
# Open a dispute
dispute = qasp.open_dispute(
    respondent_did="did:qasp:2ZTp9sZY...",
    dispute_type="service_failure",
    description="Tool 'analyze' returned empty result for 3 consecutive calls. "
                "Receipt IDs: f47ac10b, a1b2c3d4, 9e8f7a6b"
)
# {"dispute_id": "d5e6f7a8...", "status": "OPEN"}

# Check dispute status
dispute_record = qasp.get_dispute(dispute["dispute_id"])
# {
#   "dispute_id": "d5e6f7a8...",
#   "claimant_did": "did:qasp:...",
#   "respondent_did": "did:qasp:2ZTp9sZY...",
#   "type": "service_failure",
#   "description": "...",
#   "status": "OPEN",
#   "opened_at": "2026-03-10T...",
#   "verdict": null
# }
```

Standard `dispute_type` values include `overcharge`, `service_failure`, `unauthorized_access`, and `data_quality`. The description field should include relevant receipt IDs to allow the authority to correlate records.

---

## 5. Exposing Tools to Other Agents

If your agent wants to receive tool calls — not just send them — it must run an HTTP server that implements the callback interface.

### 5.1 Tool Definition Best Practices

A tool definition tells the network what your agent can do and how to call it. Invest time in clear definitions; they are the primary mechanism by which other agents discover and select your tools.

**Naming conventions:**

- Use lowercase with underscores: `analyze_data`, not `AnalyzeData` or `analyzeData`
- Be specific: `summarize_document` is better than `process`
- Avoid generic names that conflict with other agents: `search_pubmed` not `search`
- Use URL-safe characters only: `[a-z0-9_-]`

**Descriptions:**

Write descriptions for agent consumption, not human consumption. Other agents' LLMs will read descriptions to decide whether your tool matches a task. Include:
- What the tool does
- What it returns
- Any notable constraints (max input size, supported formats)

```json
{
  "name": "summarize_document",
  "description": "Summarize a text document to a specified target length. Input must be plain text or Markdown. Returns a JSON object with 'summary' (string) and 'word_count' (integer) fields. Maximum input: 50,000 characters.",
  "input_schema": {
    "type": "object",
    "properties": {
      "text": {
        "type": "string",
        "description": "The document text to summarize"
      },
      "target_words": {
        "type": "integer",
        "description": "Target word count for the summary",
        "default": 150,
        "minimum": 50,
        "maximum": 500
      }
    },
    "required": ["text"]
  }
}
```

**Input schema:**

The `input_schema` field is optional at registration but strongly recommended. It follows JSON Schema syntax. When present, the authority stores it in the tool record and returns it in discovery results, enabling calling agents to validate arguments before sending them.

### 5.2 Implementing the Callback Endpoint

The authority makes POST requests to `{callback_url}/tools/{tool_name}` for each verified tool call. Your callback server must accept these requests.

**Python / FastAPI:**

```python
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import uvicorn
import logging

logger = logging.getLogger(__name__)
app = FastAPI()

@app.post("/tools/summarize_document")
async def summarize_document(request: Request):
    caller_did = request.headers.get("X-QASP-Caller-DID", "unknown")
    logger.info("Tool call from %s", caller_did)

    try:
        args = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    text = args.get("text")
    if not text:
        raise HTTPException(status_code=400, detail="Missing required field: text")

    target_words = args.get("target_words", 150)

    # Your actual tool logic here
    summary = perform_summarization(text, target_words)

    return {
        "summary": summary,
        "word_count": len(summary.split())
    }

def perform_summarization(text: str, target_words: int) -> str:
    # Replace with your actual implementation
    words = text.split()
    return " ".join(words[:target_words]) + ("..." if len(words) > target_words else "")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9000)
```

**Node.js / Express:**

```javascript
import express from "express";

const app = express();
app.use(express.json());

app.post("/tools/summarize_document", (req, res) => {
    const callerDid = req.headers["x-qasp-caller-did"] || "unknown";
    console.log(`Tool call from ${callerDid}`);

    const { text, target_words = 150 } = req.body;

    if (!text) {
        return res.status(400).json({ error: "Missing required field: text" });
    }

    // Your actual tool logic here
    const words = text.split(/\s+/);
    const summary = words.slice(0, target_words).join(" ") +
                    (words.length > target_words ? "..." : "");

    res.json({
        summary,
        word_count: summary.split(/\s+/).length
    });
});

app.listen(9000, () => console.log("Callback server running on port 9000"));
```

**Go:**

```go
package main

import (
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "strings"
)

type SummarizeRequest struct {
    Text        string `json:"text"`
    TargetWords int    `json:"target_words"`
}

type SummarizeResponse struct {
    Summary   string `json:"summary"`
    WordCount int    `json:"word_count"`
}

func summarizeHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    callerDID := r.Header.Get("X-QASP-Caller-DID")
    log.Printf("Tool call from: %s", callerDID)

    var req SummarizeRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, `{"error":"Invalid JSON"}`, http.StatusBadRequest)
        return
    }

    if req.Text == "" {
        http.Error(w, `{"error":"Missing required field: text"}`, http.StatusBadRequest)
        return
    }

    if req.TargetWords <= 0 {
        req.TargetWords = 150
    }

    words := strings.Fields(req.Text)
    if len(words) > req.TargetWords {
        words = words[:req.TargetWords]
    }
    summary := strings.Join(words, " ")

    resp := SummarizeResponse{
        Summary:   summary,
        WordCount: len(words),
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(resp)
}

func main() {
    http.HandleFunc("/tools/summarize_document", summarizeHandler)
    fmt.Println("Callback server running on port 9000")
    log.Fatal(http.ListenAndServe(":9000", nil))
}
```

### 5.3 Handling the X-QASP-Caller-DID Header

The authority injects the `X-QASP-Caller-DID` header on every relayed call. The value is the DID of the calling agent — for example, `did:qasp:7bRq2mNp...`. Your callback can use this to:

- Log which agent called which tool for audit purposes
- Implement application-layer per-caller policies (for example, restrict a tool to specific known DIDs)
- Track per-caller usage for billing or quota management

```python
@app.post("/tools/sensitive_operation")
async def sensitive_operation(request: Request):
    caller_did = request.headers.get("X-QASP-Caller-DID", "")

    # Optional: restrict to known trusted callers
    ALLOWED_CALLERS = {
        "did:qasp:7bRq2mNp...",
        "did:qasp:9cXs3oPq..."
    }
    if ALLOWED_CALLERS and caller_did not in ALLOWED_CALLERS:
        raise HTTPException(status_code=403, detail="Caller not in allowlist")

    args = await request.json()
    # ... perform operation ...
    return {"result": "done"}
```

Note that because the authority has already validated the token, you do not need to verify the DID cryptographically. The presence of a valid QASP token guarantees the caller is who they claim to be.

### 5.4 Error Handling in Callbacks

Your callback must return meaningful HTTP status codes. The authority interprets the response status and relays it back to the caller in the `result` field.

| Situation | Return |
|---|---|
| Successful execution | HTTP 200 with JSON result body |
| Missing required argument | HTTP 400 with `{"error": "message"}` |
| Internal processing error | HTTP 500 with `{"error": "message"}` |
| Tool temporarily unavailable | HTTP 503 with `{"error": "message"}` |

Do not return HTTP 401 or 403 from callbacks. Authentication and authorization are handled by the authority before the call reaches your callback. Returning a 401/403 from your callback is ambiguous and will confuse callers.

### 5.5 Callback Security Considerations

> **Warning:** Your callback URL is publicly callable by anyone who knows it. While the authority strips and re-injects the caller DID, there is nothing preventing direct HTTP calls to your callback URL that bypass the QASP authority entirely. Implement the following defenses:

**Option 1: IP allowlisting.** Restrict inbound connections to your callback port to the authority server's known IP address(es). This is the simplest defense for internal deployments.

**Option 2: Shared secret header.** At registration time, generate a random secret and include it in your callback URL path (for example, `https://my-agent.example.com/qasp-cb-7f3a9b2e/tools/`). This is obscurity-only but prevents casual probing.

**Option 3: Request signing.** In future versions of QASP, the authority will sign relayed requests. Check the roadmap for availability.

**Always:**
- Validate all input fields in callback handlers, even if marked required by your schema
- Set a maximum body size limit on your HTTP server
- Implement a 30-second timeout on your tool logic and return an error if exceeded
- Log all incoming `X-QASP-Caller-DID` values for audit purposes

---

## 6. Language-Specific Integration Guides

### 6.1 Python — Using qasp_client.py

`qasp_client.py` is a complete, dependency-minimal wrapper around the authority API. Its only external dependency is `httpx`.

**Setup:**

```bash
pip install httpx
```

Copy `scripts/qasp_client.py` into your project, or install the `qasp` package if it is distributed as a package.

**Complete consumer agent example:**

```python
import os
import logging
from scripts.qasp_client import QASPClient, QASPError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    qasp = QASPClient(os.environ["QASP_AUTHORITY_URL"])

    # Register (or load existing credentials)
    api_key_env = os.environ.get("QASP_API_KEY")
    did_env = os.environ.get("QASP_DID")

    if api_key_env and did_env:
        qasp._api_key = api_key_env
        qasp._did = did_env
        logger.info("Loaded existing credentials for DID: %s", did_env)
    else:
        reg = qasp.register(
            name="PythonConsumer",
            tools=[{"name": "query", "description": "Query external data sources"}]
        )
        os.environ["QASP_API_KEY"] = reg["api_key"]
        os.environ["QASP_DID"] = reg["did"]
        logger.info("Registered with DID: %s", reg["did"])

    # Discover agents with a summarize tool
    agents = qasp.discover(capability="qasp://*/tools/summarize", min_trust=0.3)
    if not agents:
        logger.error("No suitable agents found")
        return

    target = agents[0]
    logger.info("Selected agent: %s (trust: %.2f)", target["name"], target["trust_score"])

    # Acquire token
    try:
        token_info = qasp.request_token(target["did"], "summarize")
    except QASPError as e:
        logger.error("Token request failed: %s", e.detail)
        return

    # Call tool
    try:
        result = qasp.call_tool(
            target_did=target["did"],
            tool_name="summarize",
            arguments={"text": "Long document text here...", "target_words": 100},
            token=token_info["token"]
        )
        logger.info("Result: %s", result["result"])
        logger.info("Receipt: %s", result["receipt_id"])

        # Report success
        qasp.report_interaction(target["did"], "success")

    except QASPError as e:
        logger.error("Tool call failed (%d): %s", e.status_code, e.detail)
        qasp.report_interaction(target["did"], "failure", details=e.detail)

    finally:
        # Revoke token when done
        try:
            qasp.revoke_token(token_info["token_id"])
        except QASPError:
            pass

if __name__ == "__main__":
    main()
```

### 6.2 Python — Using Raw httpx or requests

For agents that prefer not to copy the client file, here is the complete pattern using raw `httpx`. The same pattern applies with `requests` by replacing `httpx.get/post` with `requests.get/post`.

```python
import httpx
import os

AUTHORITY = os.environ["QASP_AUTHORITY_URL"]
API_KEY = os.environ["QASP_API_KEY"]

HEADERS = {
    "Content-Type": "application/json",
    "X-API-Key": API_KEY
}

def api_get(path: str, params: dict = None) -> dict:
    resp = httpx.get(f"{AUTHORITY}{path}", headers=HEADERS, params=params)
    resp.raise_for_status()
    return resp.json()

def api_post(path: str, body: dict) -> dict:
    resp = httpx.post(f"{AUTHORITY}{path}", headers=HEADERS, json=body)
    if resp.status_code >= 400:
        detail = resp.json().get("detail", resp.text)
        raise RuntimeError(f"HTTP {resp.status_code}: {detail}")
    return resp.json()

# Usage
agents = api_get("/discover", params={"capability": "*", "min_trust": "0.3"})
token_info = api_post("/tokens/request", {
    "target_did": agents[0]["did"],
    "tool_name": "summarize"
})
result = api_post("/tools/call", {
    "target_did": agents[0]["did"],
    "tool_name": "summarize",
    "arguments": {"text": "Sample text"},
    "token": token_info["token"]
})
print(result["result"])
```

### 6.3 JavaScript / Node.js

```javascript
// qasp.js — reusable QASP client module
const AUTHORITY = process.env.QASP_AUTHORITY_URL;
let apiKey = process.env.QASP_API_KEY || null;
let myDid = process.env.QASP_DID || null;

async function apiRequest(method, path, body = null, params = null) {
    let url = `${AUTHORITY}${path}`;
    if (params) {
        url += "?" + new URLSearchParams(params).toString();
    }

    const headers = { "Content-Type": "application/json" };
    if (apiKey) headers["X-API-Key"] = apiKey;

    const options = { method, headers };
    if (body) options.body = JSON.stringify(body);

    const response = await fetch(url, options);
    const data = await response.json();

    if (!response.ok) {
        const err = new Error(`HTTP ${response.status}: ${data.detail || JSON.stringify(data)}`);
        err.statusCode = response.status;
        err.detail = data.detail;
        throw err;
    }

    return data;
}

export async function register(name, tools, callbackUrl = "") {
    const data = await apiRequest("POST", "/register", {
        name, tools, callback_url: callbackUrl
    });
    apiKey = data.api_key;
    myDid = data.did;
    return data;
}

export async function discover(capability = "*", minTrust = 0.0) {
    return apiRequest("GET", "/discover", null, { capability, min_trust: minTrust });
}

export async function requestToken(targetDid, toolName, verbs = null) {
    const body = { target_did: targetDid, tool_name: toolName };
    if (verbs) body.verbs = verbs;
    return apiRequest("POST", "/tokens/request", body);
}

export async function callTool(targetDid, toolName, args, token) {
    return apiRequest("POST", "/tools/call", {
        target_did: targetDid,
        tool_name: toolName,
        arguments: args,
        token
    });
}

export async function revokeToken(tokenId) {
    return apiRequest("POST", "/tokens/revoke", { token_id: tokenId });
}

export async function checkToken(tokenId) {
    return apiRequest("GET", `/tokens/status/${tokenId}`);
}

export async function getTrust(did) {
    return apiRequest("GET", `/trust/${did}`);
}

export async function reportInteraction(did, outcome, details = "") {
    return apiRequest("POST", `/trust/${did}/report`, { outcome, details });
}

export async function openDispute(respondentDid, type, description = "") {
    return apiRequest("POST", "/disputes/open", {
        respondent_did: respondentDid, type, description
    });
}

export async function getDispute(disputeId) {
    return apiRequest("GET", `/disputes/${disputeId}`);
}
```

**Usage:**

```javascript
import * as qasp from "./qasp.js";

await qasp.register("JSAgent", [
    { name: "fetch_data", description: "Fetch and parse external data" }
]);

const agents = await qasp.discover("qasp://*/tools/analyze", 0.4);
const target = agents[0];

const tokenInfo = await qasp.requestToken(target.did, "analyze");

try {
    const result = await qasp.callTool(
        target.did, "analyze",
        { data: "1,2,3,4,5" },
        tokenInfo.token
    );
    console.log("Result:", result.result);
    await qasp.reportInteraction(target.did, "success");
} catch (err) {
    if (err.statusCode === 429) {
        console.log("Rate limited, retry later");
    } else if (err.statusCode === 403) {
        console.log("Token rejected:", err.detail);
    }
    await qasp.reportInteraction(target.did, "failure", err.detail);
} finally {
    await qasp.revokeToken(tokenInfo.token_id);
}
```

### 6.4 Go

```go
// qasp/client.go
package qasp

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/url"
)

type Client struct {
    BaseURL string
    APIKey  string
    DID     string
    http    *http.Client
}

type QASPError struct {
    StatusCode int
    Detail     string
}

func (e *QASPError) Error() string {
    return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Detail)
}

func NewClient(baseURL string) *Client {
    return &Client{BaseURL: baseURL, http: &http.Client{}}
}

func (c *Client) do(method, path string, body interface{}, params url.Values) (map[string]interface{}, error) {
    var bodyReader io.Reader
    if body != nil {
        data, err := json.Marshal(body)
        if err != nil {
            return nil, err
        }
        bodyReader = bytes.NewReader(data)
    }

    reqURL := c.BaseURL + path
    if params != nil {
        reqURL += "?" + params.Encode()
    }

    req, err := http.NewRequest(method, reqURL, bodyReader)
    if err != nil {
        return nil, err
    }

    req.Header.Set("Content-Type", "application/json")
    if c.APIKey != "" {
        req.Header.Set("X-API-Key", c.APIKey)
    }

    resp, err := c.http.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var result map[string]interface{}
    json.NewDecoder(resp.Body).Decode(&result)

    if resp.StatusCode >= 400 {
        detail, _ := result["detail"].(string)
        return nil, &QASPError{StatusCode: resp.StatusCode, Detail: detail}
    }

    return result, nil
}

func (c *Client) Register(name string, tools []map[string]interface{}, callbackURL string) (map[string]interface{}, error) {
    body := map[string]interface{}{
        "name": name, "tools": tools, "callback_url": callbackURL,
    }
    result, err := c.do("POST", "/register", body, nil)
    if err != nil {
        return nil, err
    }
    c.APIKey, _ = result["api_key"].(string)
    c.DID, _ = result["did"].(string)
    return result, nil
}

func (c *Client) RequestToken(targetDID, toolName string) (map[string]interface{}, error) {
    return c.do("POST", "/tokens/request", map[string]interface{}{
        "target_did": targetDID, "tool_name": toolName,
    }, nil)
}

func (c *Client) CallTool(targetDID, toolName string, arguments map[string]interface{}, token string) (map[string]interface{}, error) {
    return c.do("POST", "/tools/call", map[string]interface{}{
        "target_did": targetDID, "tool_name": toolName,
        "arguments": arguments, "token": token,
    }, nil)
}
```

> **Note:** The `/discover` endpoint returns a JSON array. For array responses, unmarshal into `[]map[string]interface{}` by writing a `doArray` variant of the `do` helper that uses `json.NewDecoder(resp.Body).Decode(&[]map...)` instead of a single object.

### 6.5 curl / Shell Scripts

Shell scripts are suitable for automation, testing, and agents that invoke tools as part of pipeline processing.

```bash
#!/usr/bin/env bash
# qasp-agent.sh — complete shell agent example

set -euo pipefail

AUTHORITY="${QASP_AUTHORITY_URL:-https://qasp.example.com}"
REG_FILE="${HOME}/.qasp-registration.json"

# --- Registration (idempotent) ---
register() {
    if [[ -f "$REG_FILE" ]]; then
        echo "Loading existing registration..."
        QASP_API_KEY=$(jq -r '.api_key' "$REG_FILE")
        QASP_DID=$(jq -r '.did' "$REG_FILE")
        return
    fi

    echo "Registering with authority..."
    curl -s -X POST "${AUTHORITY}/register" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "ShellAgent",
            "tools": [{"name": "echo", "description": "Echo input"}]
        }' > "$REG_FILE"

    QASP_API_KEY=$(jq -r '.api_key' "$REG_FILE")
    QASP_DID=$(jq -r '.did' "$REG_FILE")
    echo "Registered: $QASP_DID"
}

# --- Discovery ---
discover() {
    local capability="${1:-*}"
    local min_trust="${2:-0.0}"
    curl -s "${AUTHORITY}/discover?capability=${capability}&min_trust=${min_trust}" \
        -H "X-API-Key: ${QASP_API_KEY}"
}

# --- Token request ---
request_token() {
    local target_did="$1"
    local tool_name="$2"
    curl -s -X POST "${AUTHORITY}/tokens/request" \
        -H "X-API-Key: ${QASP_API_KEY}" \
        -H "Content-Type: application/json" \
        -d "{\"target_did\": \"${target_did}\", \"tool_name\": \"${tool_name}\"}"
}

# --- Tool call ---
call_tool() {
    local target_did="$1"
    local tool_name="$2"
    local args="$3"
    local token="$4"
    curl -s -X POST "${AUTHORITY}/tools/call" \
        -H "X-API-Key: ${QASP_API_KEY}" \
        -H "Content-Type: application/json" \
        -d "{
            \"target_did\": \"${target_did}\",
            \"tool_name\": \"${tool_name}\",
            \"arguments\": ${args},
            \"token\": \"${token}\"
        }"
}

# --- Revoke token ---
revoke_token() {
    local token_id="$1"
    curl -s -X POST "${AUTHORITY}/tokens/revoke" \
        -H "X-API-Key: ${QASP_API_KEY}" \
        -H "Content-Type: application/json" \
        -d "{\"token_id\": \"${token_id}\"}"
}

# --- Main ---
register

AGENTS=$(discover "qasp://*/tools/echo")
TARGET_DID=$(echo "$AGENTS" | jq -r '.[0].did')
echo "Target: $TARGET_DID"

TOKEN_INFO=$(request_token "$TARGET_DID" "echo")
TOKEN=$(echo "$TOKEN_INFO" | jq -r '.token')
TOKEN_ID=$(echo "$TOKEN_INFO" | jq -r '.token_id')

RESULT=$(call_tool "$TARGET_DID" "echo" '{"message": "hello from shell"}' "$TOKEN")
echo "Result: $(echo "$RESULT" | jq -r '.result')"

revoke_token "$TOKEN_ID"
echo "Token revoked."
```

### 6.6 Any HTTP-Capable Language (Generic Pattern)

The integration pattern is identical in any language with HTTP client support. The following pseudocode captures the canonical sequence:

```
# 1. Register
POST /register
  Body: {name, tools, callback_url}
  Store: api_key, did

# 2. Discover
GET /discover?capability=*&min_trust=0.0
  Header: X-API-Key: <api_key>
  Receive: [{did, name, tools, trust_score}]

# 3. Request token
POST /tokens/request
  Header: X-API-Key: <api_key>
  Body: {target_did, tool_name}
  Receive: {token, token_id, expires_at}

# 4. Call tool
POST /tools/call
  Header: X-API-Key: <api_key>
  Body: {target_did, tool_name, arguments, token}
  Receive: {result, metering, receipt_id}

# 5. Optionally revoke
POST /tokens/revoke
  Header: X-API-Key: <api_key>
  Body: {token_id}
```

If a language supports only synchronous HTTP (no async), that is fine — all QASP endpoints are standard request/response. If a language cannot set custom headers, QASP cannot be used from that runtime directly; use the sidecar pattern described in Section 7.5.

---

## 7. Integration Patterns

### 7.1 Consumer Agent (Calls Tools, No Callback)

The simplest integration pattern. The agent only calls other agents' tools and never receives calls itself. Register with an empty tools list and no callback URL.

```python
qasp = QASPClient("https://qasp.example.com")
qasp.register("ConsumerAgent", tools=[], callback_url="")

# Discover and call tools
agents = qasp.discover(capability="qasp://*/tools/translate")
target = agents[0]
token_info = qasp.request_token(target["did"], "translate")
result = qasp.call_tool(
    target["did"], "translate",
    {"text": "Hello world", "target_language": "fr"},
    token_info["token"]
)
print(result["result"])
```

When no `callback_url` is provided, the authority returns an echo placeholder response instead of relaying to a real callback. This is acceptable for consumer-only agents.

### 7.2 Provider Agent (Exposes Tools via Callback)

A provider agent runs an HTTP callback server, registers with tool definitions and a callback URL, and then primarily waits for incoming calls. It may also call other agents' tools.

```python
# provider_agent.py
import uvicorn
from fastapi import FastAPI, Request
from scripts.qasp_client import QASPClient

app = FastAPI()
qasp = QASPClient("https://qasp.example.com")

@app.post("/tools/analyze")
async def analyze(request: Request):
    args = await request.json()
    caller = request.headers.get("X-QASP-Caller-DID", "unknown")
    data = args.get("data", "")
    # ... perform analysis ...
    return {"insights": f"Analysis of {len(data)} chars from {caller}"}

@app.on_event("startup")
async def startup():
    qasp.register(
        name="AnalysisProvider",
        tools=[{"name": "analyze", "description": "Analyze structured data"}],
        callback_url="https://my-provider.example.com"
    )

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9000)
```

### 7.3 Dual Agent (Consumer and Provider)

Most production agents are dual agents — they both expose tools and call others. The same `QASPClient` instance handles outbound calls; the callback server handles inbound calls.

```python
# dual_agent.py
from fastapi import FastAPI, Request
import uvicorn
from scripts.qasp_client import QASPClient

app = FastAPI()
qasp = QASPClient("https://qasp.example.com")

# --- Inbound: this agent's tools ---

@app.post("/tools/enrich")
async def enrich(request: Request):
    args = await request.json()
    text = args.get("text", "")
    # Call another agent's tool to get additional data
    agents = qasp.discover(capability="qasp://*/tools/classify")
    if agents:
        token = qasp.request_token(agents[0]["did"], "classify")
        classification = qasp.call_tool(
            agents[0]["did"], "classify",
            {"text": text}, token["token"]
        )
        return {"text": text, "classification": classification["result"]}
    return {"text": text, "classification": None}

@app.on_event("startup")
async def startup():
    qasp.register(
        name="EnrichmentAgent",
        tools=[{"name": "enrich", "description": "Enrich text with classification"}],
        callback_url="https://my-enrichment-agent.example.com"
    )

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9000)
```

### 7.4 LLM Tool-Calling Loop Integration

QASP integrates naturally into LLM agent frameworks that support custom tool definitions. The pattern maps QASP discovery results to the LLM's tool schema and handles QASP tool calls transparently.

```python
import json
from scripts.qasp_client import QASPClient, QASPError

class QASPToolAdapter:
    """Adapts QASP discovered tools to LLM tool-calling format."""

    def __init__(self, qasp_client: QASPClient):
        self.qasp = qasp_client
        self._token_cache: dict = {}
        self._agent_tool_map: dict = {}

    def get_tool_definitions(self, capability="*", min_trust=0.3) -> list:
        """Return tool definitions in OpenAI/Anthropic function format."""
        agents = self.qasp.discover(capability=capability, min_trust=min_trust)
        definitions = []

        for agent in agents:
            for tool in agent["tools"]:
                short_did = agent['did'].split(':')[-1][:8]
                fn_name = f"qasp__{short_did}__{tool['name']}"
                definitions.append({
                    "name": fn_name,
                    "description": (
                        f"[Agent: {agent['name']}, Trust: {agent['trust_score']:.2f}] "
                        f"{tool['description']}"
                    ),
                    "input_schema": tool.get("input_schema", {"type": "object"})
                })
                self._agent_tool_map[fn_name] = (agent["did"], tool["name"])

        return definitions

    def execute_tool(self, function_name: str, arguments: dict) -> dict:
        """Execute a QASP tool by its LLM function name."""
        agent_did, tool_name = self._agent_tool_map[function_name]

        cache_key = (agent_did, tool_name)
        token_info = self._token_cache.get(cache_key)
        if not token_info:
            token_info = self.qasp.request_token(agent_did, tool_name)
            self._token_cache[cache_key] = token_info

        try:
            result = self.qasp.call_tool(agent_did, tool_name, arguments, token_info["token"])
            self.qasp.report_interaction(agent_did, "success")
            return result["result"]
        except QASPError as e:
            self.qasp.report_interaction(agent_did, "failure", details=e.detail)
            if e.status_code == 403:
                self._token_cache.pop(cache_key, None)
            raise

# Usage with a hypothetical LLM framework
qasp = QASPClient("https://qasp.example.com")
qasp.register("LLMOrchestrator", tools=[])

adapter = QASPToolAdapter(qasp)
tools = adapter.get_tool_definitions(min_trust=0.4)

# Pass `tools` to your LLM's tool_use parameter.
# When the LLM calls a tool, dispatch via adapter.execute_tool(name, args).
```

### 7.5 Sidecar/Proxy Pattern for Non-HTTP Agents

Some agent runtimes (certain embedded systems, WASM sandboxes, or legacy systems) cannot set custom HTTP headers or process JSON. Use the sidecar pattern: deploy a lightweight HTTP proxy adjacent to the agent that handles all QASP interactions.

```
+------------------+          +------------------+          +------------------+
| Agent Runtime    |  simple  | QASP Sidecar     |  HTTPS/  | QASP Authority   |
| (no custom       |  HTTP or +------------------+   JSON   |                  |
|  headers)        |  IPC     | - Stores api_key |          |                  |
|                  |--------> | - Manages tokens |--------> |                  |
|                  |          | - Handles retries|          |                  |
+------------------+          +------------------+          +------------------+
```

The sidecar exposes a simplified local API (for example, plain HTTP on localhost without auth headers) that the constrained agent can call. The sidecar translates these calls into authenticated QASP requests and returns results. The agent never handles API keys or tokens.

A minimal Python sidecar:

```python
# qasp_sidecar.py — run as a local proxy for constrained agents
from fastapi import FastAPI
from scripts.qasp_client import QASPClient
import os

app = FastAPI()
qasp = QASPClient(os.environ["QASP_AUTHORITY_URL"])
qasp._api_key = os.environ["QASP_API_KEY"]
qasp._did = os.environ["QASP_DID"]

_token_cache = {}

@app.get("/sidecar/discover")
def sidecar_discover(capability: str = "*", min_trust: float = 0.0):
    return qasp.discover(capability=capability, min_trust=min_trust)

@app.post("/sidecar/call")
def sidecar_call(body: dict):
    target_did = body["target_did"]
    tool_name = body["tool_name"]
    arguments = body.get("arguments", {})

    key = (target_did, tool_name)
    if key not in _token_cache:
        _token_cache[key] = qasp.request_token(target_did, tool_name)

    result = qasp.call_tool(target_did, tool_name, arguments, _token_cache[key]["token"])
    return result

# Run: uvicorn qasp_sidecar:app --port 8090
```

The constrained agent calls `http://localhost:8090/sidecar/call` with a simple JSON body — no API key, no token management required.

### 7.6 Multi-Authority Federation (Future)

The current QASP implementation operates with a single authority server. Multi-authority federation — where agents registered with Authority A can call tools on agents registered with Authority B — is planned for a future version. Cross-domain delegation tokens (`CrossDomainDelegation`, `OwnerEndorsement`) are already part of the protocol implementation and will be exposed via API endpoints in a future release.

When federation is available, agents will use the same API shape. Federated tokens will carry an additional authority chain field that is verified automatically.

---

## 8. Production Readiness Checklist

Use this checklist before deploying an agent to a production QASP network. Each item maps to a risk category; unresolved items in the Critical column should block deployment.

### 8.1 Credential Management

| Item | Priority | Done |
|---|---|---|
| API key stored in secrets manager or environment variable | Critical | [ ] |
| API key never written to logs | Critical | [ ] |
| API key never committed to source control | Critical | [ ] |
| `api_key` and `did` persisted to durable storage on first registration | High | [ ] |
| Agent loads credentials from storage on restart (not re-registering) | High | [ ] |
| Secrets rotation procedure documented | Medium | [ ] |

### 8.2 Token Lifecycle

| Item | Priority | Done |
|---|---|---|
| Tokens cached by `(target_did, tool_name)` | High | [ ] |
| Cache checks `expires_at` before reusing a token | High | [ ] |
| 403 responses trigger cache eviction and token re-request | High | [ ] |
| Tokens revoked when no longer needed | Medium | [ ] |
| Proactive refresh 5 minutes before expiry for long-running tasks | Medium | [ ] |
| OCSP checks used before critical operations if token may have aged | Low | [ ] |

### 8.3 Error Handling

| Item | Priority | Done |
|---|---|---|
| All QASP API calls wrapped in try/except or equivalent | Critical | [ ] |
| HTTP 429 handled with exponential backoff (start 1s, cap 60s) | High | [ ] |
| HTTP 403 triggers token cache clear and single retry | High | [ ] |
| HTTP 404 raises a non-retryable error with clear message | High | [ ] |
| HTTP 500/503 from authority retried with backoff (max 3 attempts) | Medium | [ ] |
| Callback handler returns HTTP 500 on internal error (not crashes) | High | [ ] |
| Callback handler enforces 30-second processing timeout | High | [ ] |

### 8.4 Rate Limit Awareness

| Item | Priority | Done |
|---|---|---|
| Agent does not exceed 10 calls per 60 seconds on any single token | Critical | [ ] |
| Concurrent callers use separate tokens per goroutine/thread/task | High | [ ] |
| Backoff logic present for 429 responses | High | [ ] |
| Rate limit headroom monitored in high-throughput scenarios | Medium | [ ] |

### 8.5 Trust Reporting

| Item | Priority | Done |
|---|---|---|
| `report_interaction` called after every tool call (success or failure) | High | [ ] |
| Failure reports include meaningful `details` string | Medium | [ ] |
| Disputes opened for persistent service failures | Medium | [ ] |
| Trust score of target agents checked before high-value operations | Medium | [ ] |

### 8.6 Logging and Observability

| Item | Priority | Done |
|---|---|---|
| Every tool call logged with receipt_id | High | [ ] |
| All inbound `X-QASP-Caller-DID` values logged | High | [ ] |
| Token issuance and revocation events logged | Medium | [ ] |
| Dispute IDs logged when disputes are opened | Medium | [ ] |
| API key never appears in any log line | Critical | [ ] |
| Token string never appears in any log line | High | [ ] |

### 8.7 Graceful Degradation

| Item | Priority | Done |
|---|---|---|
| Agent handles authority server unavailability without crashing | High | [ ] |
| Discovery cache used during authority downtime | Medium | [ ] |
| Agent exposes health endpoint that reflects QASP connectivity status | Medium | [ ] |
| Fallback behavior documented if preferred agent is unavailable | Medium | [ ] |

### 8.8 Callback Server Hardening (Provider Agents Only)

| Item | Priority | Done |
|---|---|---|
| Maximum request body size configured on HTTP server | High | [ ] |
| All input fields validated regardless of `input_schema` | High | [ ] |
| Callback URL uses HTTPS in production | High | [ ] |
| IP allowlist or path-based secret implemented | Medium | [ ] |
| 401/403 never returned from callback (use 400 or 503 instead) | Medium | [ ] |

---

## 9. Testing Your Integration

### 9.1 Local Server Setup

The QASP Authority Server can be run locally for integration testing. The server requires Python 3.11+ and the `qasp` package dependencies.

```bash
# Install dependencies
pip install httpx uvicorn fastapi pydantic

# Start the authority server on default port 8080
python scripts/qasp_server.py --host 127.0.0.1 --port 8080

# Verify the server is running
curl http://127.0.0.1:8080/
# {"name": "QASP Authority", "version": "...", "did": "did:qasp:..."}

# Check available features
curl http://127.0.0.1:8080/features
```

Set your environment variable for tests:

```bash
export QASP_AUTHORITY_URL=http://127.0.0.1:8080
```

### 9.2 Testing Registration

```python
# test_registration.py
import os
from scripts.qasp_client import QASPClient, QASPError

def test_registration():
    qasp = QASPClient(os.environ["QASP_AUTHORITY_URL"])

    reg = qasp.register(
        name="TestAgent",
        tools=[{"name": "ping", "description": "Returns pong"}]
    )

    assert "api_key" in reg, "api_key missing from registration response"
    assert "did" in reg, "did missing from registration response"
    assert reg["did"].startswith("did:qasp:"), f"Unexpected DID format: {reg['did']}"
    assert len(reg["api_key"]) > 0, "api_key must not be empty"
    assert "public_key" in reg, "public_key missing"

    # Verify DID is queryable
    trust = qasp.get_trust(reg["did"])
    assert abs(trust["score"] - 0.5) < 0.01, f"New agent trust score should be ~0.5, got {trust['score']}"
    assert trust["interaction_count"] == 0

    print(f"Registration test passed. DID: {reg['did']}")

test_registration()
```

### 9.3 Testing Discovery

```python
# test_discovery.py
import os
from scripts.qasp_client import QASPClient

def test_discovery():
    qasp = QASPClient(os.environ["QASP_AUTHORITY_URL"])

    # Register two agents
    qasp.register("ProviderA", tools=[{"name": "analyze", "description": "Analyze data"}])
    api_key_a = qasp._api_key
    did_a = qasp._did

    qasp2 = QASPClient(os.environ["QASP_AUTHORITY_URL"])
    qasp2.register("ProviderB", tools=[{"name": "summarize", "description": "Summarize text"}])

    # Consumer discovers both
    qasp3 = QASPClient(os.environ["QASP_AUTHORITY_URL"])
    qasp3.register("Consumer", tools=[])

    all_agents = qasp3.discover()
    assert len(all_agents) >= 2, "Should find at least 2 registered agents"

    # Filter by capability
    analyzers = qasp3.discover(capability="qasp://*/tools/analyze")
    assert any(
        any(t["name"] == "analyze" for t in a["tools"])
        for a in analyzers
    ), "Should find ProviderA via capability filter"

    # Filter by trust (all new agents have 0.5)
    high_trust = qasp3.discover(min_trust=0.9)
    assert len(high_trust) == 0, "No agents should have trust >= 0.9 at start"

    print("Discovery test passed.")

test_discovery()
```

### 9.4 Testing Token Acquisition and Tool Calls

```python
# test_token_and_call.py
import os
from scripts.qasp_client import QASPClient, QASPError

def test_token_flow():
    authority = os.environ["QASP_AUTHORITY_URL"]

    # Register provider
    provider = QASPClient(authority)
    provider.register(
        name="EchoProvider",
        tools=[{"name": "echo", "description": "Echo input"}],
        callback_url=""  # No callback — authority will echo arguments
    )

    # Register consumer
    consumer = QASPClient(authority)
    consumer.register("EchoConsumer", tools=[])

    # Request token
    token_info = consumer.request_token(provider._did, "echo")
    assert "token" in token_info
    assert "token_id" in token_info
    assert "expires_at" in token_info
    assert token_info["verbs"] == ["exec"]

    # Check token status via OCSP
    status = consumer.check_token(token_info["token_id"])
    assert status["status"] == "GOOD"

    # Call the tool
    result = consumer.call_tool(
        target_did=provider._did,
        tool_name="echo",
        arguments={"message": "hello"},
        token=token_info["token"]
    )
    assert "result" in result
    assert "receipt_id" in result
    assert "metering" in result
    print(f"Tool call succeeded. Receipt: {result['receipt_id']}")

    # Revoke the token
    revoke = consumer.revoke_token(token_info["token_id"])
    assert revoke.get("revoked") is True

    # Verify revocation via OCSP
    status = consumer.check_token(token_info["token_id"])
    assert status["status"] == "REVOKED"

    # Attempt to use revoked token
    try:
        consumer.call_tool(provider._did, "echo", {"message": "test"}, token_info["token"])
        assert False, "Should have raised QASPError 403"
    except QASPError as e:
        assert e.status_code == 403, f"Expected 403, got {e.status_code}"

    print("Token and call test passed.")

test_token_flow()
```

### 9.5 Testing Trust and Disputes

```python
# test_trust_and_disputes.py
import os
from scripts.qasp_client import QASPClient

def test_trust():
    authority = os.environ["QASP_AUTHORITY_URL"]

    reporter = QASPClient(authority)
    reporter.register("Reporter", tools=[])

    subject = QASPClient(authority)
    subject.register("Subject", tools=[])
    subject_did = subject._did

    # Initial trust
    trust = reporter.get_trust(subject_did)
    assert abs(trust["score"] - 0.5) < 0.01

    # Report a success — score should increase slightly
    reporter.report_interaction(subject_did, "success")
    trust2 = reporter.get_trust(subject_did)
    assert trust2["interaction_count"] == 1

    # Report a failure
    reporter.report_interaction(subject_did, "failure", details="Timeout")
    trust3 = reporter.get_trust(subject_did)
    assert trust3["interaction_count"] == 2

    print(f"Trust after 1 success, 1 failure: {trust3['score']:.4f}")

    # Open a dispute
    dispute = reporter.open_dispute(
        respondent_did=subject_did,
        dispute_type="service_failure",
        description="Repeated timeouts. Test dispute."
    )
    assert "dispute_id" in dispute
    assert dispute["status"] == "OPEN"

    # Retrieve dispute
    record = reporter.get_dispute(dispute["dispute_id"])
    assert record["respondent_did"] == subject_did
    assert record["type"] == "service_failure"

    print(f"Dispute test passed. Dispute ID: {dispute['dispute_id']}")

test_trust()
```

### 9.6 Complete End-to-End Test Script

The following script runs all integration phases against a live authority server in sequence. It is suitable as a smoke test in CI/CD pipelines.

```python
#!/usr/bin/env python3
"""
e2e_test.py — Complete QASP integration smoke test.

Usage:
    QASP_AUTHORITY_URL=http://localhost:8080 python e2e_test.py
"""
import os
import sys
import datetime
import traceback
from scripts.qasp_client import QASPClient, QASPError

AUTHORITY = os.environ.get("QASP_AUTHORITY_URL", "http://localhost:8080")
PASS = "PASS"
FAIL = "FAIL"
results = []

def check(name: str, fn):
    try:
        fn()
        results.append((PASS, name))
        print(f"  [PASS] {name}")
    except Exception as exc:
        results.append((FAIL, name))
        print(f"  [FAIL] {name}: {exc}")
        traceback.print_exc()

print(f"\nQASP End-to-End Test Suite")
print(f"Authority: {AUTHORITY}")
print("=" * 50)

# ---- Setup ----
provider = QASPClient(AUTHORITY)
consumer = QASPClient(AUTHORITY)
token_info = {}

# 1. Server health
def test_health():
    info = consumer.info()
    assert "name" in info or "did" in info

check("Server health check", test_health)

# 2. Provider registration
def test_provider_reg():
    reg = provider.register(
        name="E2EProvider",
        tools=[{"name": "echo", "description": "Echo arguments back to caller"}],
        callback_url=""
    )
    assert reg["did"].startswith("did:qasp:")
    assert len(reg["api_key"]) > 0

check("Provider registration", test_provider_reg)

# 3. Consumer registration
def test_consumer_reg():
    reg = consumer.register("E2EConsumer", tools=[])
    assert reg["did"].startswith("did:qasp:")

check("Consumer registration", test_consumer_reg)

# 4. Discovery
def test_discovery():
    agents = consumer.discover()
    assert len(agents) >= 1
    dids = [a["did"] for a in agents]
    assert provider._did in dids

check("Discovery finds provider", test_discovery)

# 5. Capability-filtered discovery
def test_capability_filter():
    agents = consumer.discover(capability="qasp://*/tools/echo")
    assert any(
        any(t["name"] == "echo" for t in a["tools"])
        for a in agents
    )

check("Capability-filtered discovery", test_capability_filter)

# 6. Token request
def test_token_request():
    global token_info
    token_info = consumer.request_token(provider._did, "echo")
    assert "token" in token_info
    assert "token_id" in token_info
    assert "expires_at" in token_info
    expires = datetime.datetime.fromisoformat(token_info["expires_at"])
    now = datetime.datetime.now(datetime.timezone.utc)
    assert (expires - now).total_seconds() > 3000  # > 50 minutes remaining

check("Token request", test_token_request)

# 7. OCSP check — GOOD
def test_ocsp_good():
    status = consumer.check_token(token_info["token_id"])
    assert status["status"] == "GOOD"

check("OCSP status GOOD", test_ocsp_good)

# 8. Tool call
def test_tool_call():
    result = consumer.call_tool(
        target_did=provider._did,
        tool_name="echo",
        arguments={"hello": "world"},
        token=token_info["token"]
    )
    assert "receipt_id" in result
    assert "metering" in result

check("Tool call with valid token", test_tool_call)

# 9. Trust reporting
def test_trust_report():
    consumer.report_interaction(provider._did, "success")
    trust = consumer.get_trust(provider._did)
    assert trust["interaction_count"] >= 1

check("Trust interaction report", test_trust_report)

# 10. Token revocation
def test_revocation():
    rev = consumer.revoke_token(token_info["token_id"])
    assert rev.get("revoked") is True
    status = consumer.check_token(token_info["token_id"])
    assert status["status"] == "REVOKED"

check("Token revocation", test_revocation)

# 11. Revoked token rejected
def test_revoked_rejected():
    try:
        consumer.call_tool(provider._did, "echo", {}, token_info["token"])
        raise AssertionError("Should have raised QASPError")
    except QASPError as e:
        assert e.status_code == 403

check("Revoked token rejected with 403", test_revoked_rejected)

# 12. Dispute open
def test_dispute():
    dispute = consumer.open_dispute(
        respondent_did=provider._did,
        dispute_type="service_failure",
        description="E2E test dispute"
    )
    assert "dispute_id" in dispute
    record = consumer.get_dispute(dispute["dispute_id"])
    assert record["status"] == "OPEN"

check("Dispute open and retrieve", test_dispute)

# ---- Summary ----
print("\n" + "=" * 50)
passed = sum(1 for s, _ in results if s == PASS)
failed = sum(1 for s, _ in results if s == FAIL)
print(f"Results: {passed} passed, {failed} failed out of {len(results)} tests")

if failed > 0:
    print("INTEGRATION TEST SUITE FAILED")
    sys.exit(1)
else:
    print("All tests passed.")
    sys.exit(0)
```

Run this script against a local server before any production deployment:

```bash
QASP_AUTHORITY_URL=http://localhost:8080 python e2e_test.py
```

---

## 10. Security Best Practices for Agents

### 10.1 API Key Security

The API key is the single credential that authenticates your agent to the QASP authority. Treat it with the same care as a private key.

**Storage:**
- Store in environment variables injected at runtime, not in application config files
- For Kubernetes: use a Secret object mounted as an environment variable, not a ConfigMap
- For AWS: use Secrets Manager or Parameter Store (SecureString)
- For HashiCorp Vault: use KV v2 with a policy scoped to your agent's path only

**Rotation:**
- If you suspect the API key has been exposed, re-register immediately. Re-registration creates a new DID, so coordinate with peers who may have cached your old DID in their token requests.
- Store the registration timestamp so you can audit how long a potentially compromised key was active.

**What never to do:**
- Never pass the API key as a URL query parameter (it appears in server logs)
- Never include the API key in error messages or stack traces
- Never write the API key to application logs at any log level
- Never store the API key in browser localStorage or sessionStorage

### 10.2 Token Security

Tokens are bearer credentials scoped to a single tool. A leaked token allows the holder to call that specific tool at the rate specified in the token until it expires or is revoked.

**Minimise exposure window:**
- Request tokens only when you are ready to use them
- Revoke tokens immediately after use for one-off operations
- Use the 5-minute refresh window rather than holding tokens for hours

**Scope minimisation:**
- Never request a token with a wider scope than needed. The `verbs` parameter defaults to `["exec"]`; this is already the minimum meaningful scope.
- If you need to call multiple tools on the same agent, request separate tokens — one per tool.

**Token strings in logs:**
- The `token` field in a `call_tool` request body is a base64-encoded signed blob. Never log it. If your HTTP client logs all request bodies by default, configure it to redact the `token` field before writing to log.

### 10.3 Transport Security

- Always use HTTPS for production authority server connections. The authority URL should start with `https://`.
- Verify TLS certificates. Do not disable certificate verification (`verify=False` in Python httpx, `rejectUnauthorized: false` in Node.js) in any environment other than isolated local development.
- If the authority is on an internal network accessible only via VPN or private network, that is an acceptable substitute for public TLS but document this decision explicitly.

### 10.4 Input Validation in Callbacks

Your callback server must validate all inputs independently of what the QASP authority has verified. The authority validates the token and the caller's identity; it does not validate the semantic content of the arguments.

```python
@app.post("/tools/generate_report")
async def generate_report(request: Request):
    args = await request.json()

    # Validate presence
    if "dataset_id" not in args:
        raise HTTPException(400, "Missing required field: dataset_id")

    # Validate type
    if not isinstance(args["dataset_id"], str):
        raise HTTPException(400, "dataset_id must be a string")

    # Validate range
    max_rows = args.get("max_rows", 1000)
    if not isinstance(max_rows, int) or not (1 <= max_rows <= 10000):
        raise HTTPException(400, "max_rows must be an integer between 1 and 10000")

    # Validate against injection
    dataset_id = args["dataset_id"]
    if not dataset_id.replace("-", "").replace("_", "").isalnum():
        raise HTTPException(400, "dataset_id contains invalid characters")

    # Proceed with validated inputs
    ...
```

### 10.5 Logging and Audit

Structure your logs to support both security audits and operational troubleshooting:

```python
import logging
import json

def log_tool_call(caller_did: str, tool_name: str, receipt_id: str, outcome: str):
    """Structured log entry for every tool invocation."""
    logging.info(json.dumps({
        "event": "tool_call",
        "caller_did": caller_did,
        "tool": tool_name,
        "receipt_id": receipt_id,
        "outcome": outcome,
        # Do NOT include: api_key, token, arguments (may contain sensitive data)
    }))
```

Retain tool call logs for at least 90 days to support dispute resolution. The authority's receipt IDs correlate authority-side records with your application logs.

### 10.6 Callback Endpoint Hardening

Beyond the defenses described in Section 5.5, apply these additional hardening measures for production callback servers:

- Set `Content-Security-Policy`, `X-Content-Type-Options`, and `X-Frame-Options` headers even on API-only endpoints (defense-in-depth against misconfigured load balancers)
- Limit maximum request body size to a reasonable ceiling for your tool (e.g., 1 MB for text processing, 10 MB for file operations)
- Use connection timeouts on any downstream calls your tool makes to prevent cascading slowdowns
- Rate-limit inbound requests per `X-QASP-Caller-DID` if a single caller is generating excessive load

---

## 11. Operational Guidance

### 11.1 Health Checks

Implement a health check endpoint that verifies QASP authority connectivity:

```python
@app.get("/health")
async def health():
    import httpx
    import os

    authority = os.environ.get("QASP_AUTHORITY_URL", "")
    status = {"agent": "ok", "qasp_authority": "unknown"}

    try:
        resp = httpx.get(f"{authority}/", timeout=5.0)
        if resp.status_code == 200:
            status["qasp_authority"] = "ok"
        else:
            status["qasp_authority"] = f"degraded (HTTP {resp.status_code})"
    except Exception as e:
        status["qasp_authority"] = f"unreachable ({type(e).__name__})"

    overall = "ok" if all(v == "ok" for v in status.values()) else "degraded"
    return {"status": overall, "components": status}
```

Kubernetes liveness and readiness probes should call this endpoint. Configure the readiness probe to fail if `qasp_authority` is unreachable for more than 30 seconds, which will temporarily remove the pod from service rotation rather than accepting requests it cannot fulfill.

### 11.2 Monitoring Metrics

The following metrics are worth instrumenting in your agent:

| Metric | Type | Description |
|---|---|---|
| `qasp_tool_calls_total` | Counter | Total outbound tool calls, labelled by tool_name and outcome |
| `qasp_tool_call_duration_seconds` | Histogram | Latency of outbound tool calls |
| `qasp_token_requests_total` | Counter | Total token requests, labelled by outcome |
| `qasp_token_cache_hits_total` | Counter | Token cache hits vs misses |
| `qasp_rate_limit_hits_total` | Counter | Number of 429 responses received |
| `qasp_inbound_calls_total` | Counter | Inbound callback calls by tool_name and caller_did |
| `qasp_trust_score` | Gauge | Your agent's current trust score (poll periodically) |

### 11.3 Handling Authority Server Restarts

The QASP reference authority server is stateful in memory. If it restarts, all registrations, tokens, and trust scores are lost. In this scenario:

1. All API key authentications will return 401
2. All token verifications will return 403 or 404
3. Discovery will return an empty list

Your agent should detect this condition (a 401 on any authenticated request) and trigger re-registration:

```python
def authenticated_request_with_reregister(qasp, method, path, **kwargs):
    """Attempt request; re-register and retry once on 401."""
    try:
        return qasp._request(method, path, **kwargs)
    except QASPError as e:
        if e.status_code == 401:
            # Authority may have restarted — attempt re-registration
            import os
            qasp.register(
                name=os.environ.get("AGENT_NAME", "Agent"),
                tools=get_my_tool_definitions(),
                callback_url=os.environ.get("CALLBACK_URL", "")
            )
            # Retry original request
            return qasp._request(method, path, **kwargs)
        raise
```

For production environments with a persistent authority server (database-backed state), this scenario should not occur. The above pattern is primarily relevant for development and staging environments running the in-memory reference server.

### 11.4 Token Expiry at Scale

In high-throughput deployments where an agent holds many tokens simultaneously (one per unique `(target_did, tool_name)` pair), manage the token cache actively:

```python
import datetime
import threading

class TokenCache:
    """Thread-safe token cache with automatic expiry eviction."""

    def __init__(self):
        self._cache: dict[tuple, dict] = {}
        self._lock = threading.Lock()
        # Start background cleanup thread
        self._start_cleanup()

    def get(self, target_did: str, tool_name: str) -> dict | None:
        with self._lock:
            entry = self._cache.get((target_did, tool_name))
            if entry is None:
                return None
            expires = datetime.datetime.fromisoformat(entry["expires_at"])
            now = datetime.datetime.now(datetime.timezone.utc)
            if (expires - now).total_seconds() < 300:
                del self._cache[(target_did, tool_name)]
                return None
            return entry

    def set(self, target_did: str, tool_name: str, token_info: dict):
        with self._lock:
            self._cache[(target_did, tool_name)] = token_info

    def evict(self, target_did: str, tool_name: str):
        with self._lock:
            self._cache.pop((target_did, tool_name), None)

    def _cleanup(self):
        """Remove expired entries every 5 minutes."""
        while True:
            threading.Event().wait(300)
            now = datetime.datetime.now(datetime.timezone.utc)
            with self._lock:
                expired = [
                    k for k, v in self._cache.items()
                    if datetime.datetime.fromisoformat(v["expires_at"]) <= now
                ]
                for k in expired:
                    del self._cache[k]

    def _start_cleanup(self):
        t = threading.Thread(target=self._cleanup, daemon=True)
        t.start()
```

### 11.5 Metering and Cost Tracking

Every successful tool call returns a `metering` object:

```json
{
  "units": 1,
  "cost": 10,
  "currency": "credits"
}
```

Track cumulative cost per target agent to detect anomalous billing:

```python
from collections import defaultdict

_cost_tracker: dict[str, int] = defaultdict(int)

def call_tool_tracked(qasp, target_did, tool_name, arguments, token):
    result = qasp.call_tool(target_did, tool_name, arguments, token)
    cost = result.get("metering", {}).get("cost", 0)
    _cost_tracker[target_did] += cost

    # Alert if a single agent has accumulated unusually high cost
    if _cost_tracker[target_did] > 10000:
        import logging
        logging.warning(
            "High accumulated cost for DID %s: %d credits",
            target_did, _cost_tracker[target_did]
        )

    return result
```

---

## 12. Migration Guide

### 12.1 Migrating from Direct Agent-to-Agent HTTP

If your agents currently call each other's HTTP endpoints directly with shared API keys or bearer tokens:

**Before (direct call):**
```python
response = httpx.post(
    "https://agent-b.internal/api/analyze",
    headers={"Authorization": f"Bearer {SHARED_SECRET}"},
    json={"data": payload}
)
```

**After (via QASP):**
```python
token_info = consumer.request_token(agent_b_did, "analyze")
result = consumer.call_tool(
    target_did=agent_b_did,
    tool_name="analyze",
    arguments={"data": payload},
    token=token_info["token"]
)
response_body = result["result"]
```

**Migration steps:**

1. Deploy the QASP authority server in your environment
2. Register all agents against the authority (can run in parallel with existing direct calls)
3. For each agent pair, implement QASP token acquisition and tool invocation
4. Update provider agents to implement the callback endpoint
5. Once all agent pairs are using QASP, decommission the shared secrets
6. Retire direct agent-to-agent network paths if the architecture permits

### 12.2 Migrating from MCP (Model Context Protocol)

MCP and QASP serve different layers. MCP is a protocol for LLMs to call tools; QASP is a security and trust layer for agent-to-agent interactions. They are complementary rather than competing.

**Bridging MCP and QASP:**

If you have an MCP server exposing tools, you can wrap it with a QASP callback layer without modifying the MCP server itself:

```python
# qasp_mcp_bridge.py — wrap an existing MCP server with QASP callbacks
from fastapi import FastAPI, Request
import httpx
import os

app = FastAPI()
MCP_SERVER = os.environ["MCP_SERVER_URL"]

@app.post("/tools/{tool_name}")
async def forward_to_mcp(tool_name: str, request: Request):
    """Receive QASP-authenticated call, forward to MCP server."""
    caller_did = request.headers.get("X-QASP-Caller-DID", "")
    args = await request.json()

    # Forward to your existing MCP server
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{MCP_SERVER}/tools/{tool_name}",
            json=args,
            timeout=25.0
        )

    return resp.json()
```

Register this bridge as your QASP callback URL. The MCP server continues to operate unchanged; the bridge adds QASP authentication and discovery on top.

### 12.3 Integrating Alongside Existing Protocols

QASP does not require exclusive use. Your agent can simultaneously:
- Call QASP-registered tools via the authority for operations requiring post-quantum security and trust scoring
- Maintain direct HTTP connections to internal microservices that do not need QASP
- Use other authentication mechanisms (OAuth2, mTLS) for human-facing APIs

The key discipline is to route all agent-to-agent calls that cross trust boundaries through QASP, while keeping internal same-trust-zone calls on existing protocols.

### 12.4 Gradual Rollout Strategy

For large deployments, use this phased rollout sequence to minimise risk:

**Phase 1 — Shadow mode (weeks 1–2):**
Register all agents with the authority. Implement QASP calls alongside existing calls. Compare results. Do not yet depend on QASP responses.

**Phase 2 — QASP primary, existing fallback (weeks 3–4):**
Use QASP responses for production logic. Fall back to existing direct calls if QASP returns an error. Log all fallbacks.

**Phase 3 — QASP only (week 5+):**
Remove fallback paths. Monitor error rates for 2 weeks.

**Phase 4 — Decommission (week 7+):**
Remove direct agent-to-agent credentials and network paths.

---

## 13. FAQ and Troubleshooting

### 13.1 Frequently Asked Questions

**Q: Do I need to implement ML-DSA-65 or any post-quantum cryptography in my agent?**

No. The authority server handles all cryptographic operations. Your agent never generates keys, signs data, or verifies signatures. You interact with QASP entirely through HTTP and JSON.

**Q: Can I register the same agent name multiple times?**

Yes. Agent names are not unique identifiers — DIDs are. Each registration call produces a new DID and API key regardless of the name provided. If you register twice accidentally, you will have two separate agent identities with separate trust scores. Persist credentials from the first registration and reuse them.

**Q: What happens if I lose my API key?**

There is no recovery mechanism — the API key is not stored in a retrievable form. You must call `/register` again to obtain a new API key and DID. Your previous DID's trust score will be lost. This underscores the importance of persisting credentials to durable storage immediately after registration.

**Q: Can two agents share the same API key?**

No. API keys are issued one per registration and identify a specific agent identity. Sharing an API key between two agents conflates their identities in the trust system and audit logs. Register each agent separately.

**Q: How do I call a tool that my agent registered itself?**

You cannot call your own tools through the authority — tokens are issued for one agent to call another's tools. If you need to test your own callback, call it directly without going through the authority, or register a second "tester" agent.

**Q: What does a trust score of 0.5 mean for a new agent?**

It means the trust system has no evidence for or against this agent. The Beta distribution prior is symmetric at 0.5. This is intentionally neutral; new agents are neither trusted nor distrusted by default. Your agent should decide whether to interact with 0.5-trust agents based on the sensitivity of the operation.

**Q: How quickly does the trust score change?**

The Bayesian update is incremental but subject to anti-gaming caps. With anti-gaming caps in place: scores above 0.7 require at least 10 interactions, above 0.8 require 50, and above 0.9 require 200. A single success from a new agent moves the score modestly; a single failure also has limited impact. Consistent behaviour over many interactions drives meaningful score changes.

**Q: Can I set the rate limit on a token I request?**

The rate limit is set by the authority based on the token's default constraints (10 calls per 60 seconds). The `verbs` parameter in the token request controls which operations are permitted but not the rate. Rate limit overrides may be available in future versions for privileged agents.

**Q: Do tokens survive authority server restarts?**

Not with the in-memory reference authority server. If the authority restarts, all tokens are invalidated. In production environments with a persistent authority (database-backed), tokens survive restarts within their original expiry window.

**Q: Can I discover agents on other authority servers?**

Not in the current release. Discovery is scoped to the authority server you are registered with. Cross-authority discovery is planned for a future federation release.

**Q: What should I put in the `callback_url` field if I don't want to receive calls?**

Pass an empty string: `"callback_url": ""`. The authority will return an echo response for any tool calls directed at your agent, using your registered tool definitions as the template. You can register as a consumer-only agent with an empty tools list and empty callback URL.

**Q: How do I find out what tool a token was issued for?**

The token request response includes `resource_uri`, which has the form `qasp://agents/{did_short}/tools/{tool_name}`. Parse the last segment to extract the tool name. Alternatively, your application should track which tool a cached token was issued for by the cache key `(target_did, tool_name)`.

**Q: Is there a test/sandbox authority server I can use for development?**

Run the reference server locally: `python scripts/qasp_server.py --host 127.0.0.1 --port 8080`. There is no shared public sandbox; each team runs its own instance for development.

**Q: What is the ARM URI format and do I need to construct them manually?**

ARM URIs have the form `qasp://agents/{did_short}/tools/{tool_name}`. You never need to construct them manually — the server generates them at registration and returns them in discovery results and token responses. You use them only as values passed to the `capability` filter on `/discover` if you want to match a specific tool pattern.

**Q: Can I update my tool definitions after registration?**

Not in the current API. To update tool definitions, re-register with a new set of tools. This creates a new DID. In production systems, treat tool definitions as immutable per agent identity and plan version migrations accordingly.

**Q: What are valid values for `dispute_type`?**

Common values are `overcharge`, `service_failure`, `unauthorized_access`, and `data_quality`. The field is a free-form string; use values that clearly describe the category of the dispute for audit and resolution purposes.

**Q: Can the authority itself be compromised, and what are the consequences?**

The authority is the root of trust in the current single-authority model. A compromised authority can issue fraudulent tokens, modify trust scores, or expose registered agent metadata. Mitigate this risk by running the authority in a hardened, network-isolated environment, restricting access to the authority's admin interfaces, and monitoring authority logs for anomalous token issuance patterns.

### 13.2 Error Reference Table

| HTTP Status | When Returned | Action |
|---|---|---|
| 400 Bad Request | Malformed JSON, missing required field, invalid DID format | Fix request body; check field names and types |
| 401 Unauthorized | Missing or invalid `X-API-Key` header | Check API key; re-register if authority restarted |
| 403 Forbidden | Token expired, token revoked, scope mismatch, verb not permitted | Evict token from cache; request new token; check tool name matches token scope |
| 404 Not Found | DID not registered, tool not found, dispute not found, token not found | Verify target DID and tool name; check registration status |
| 429 Too Many Requests | Token bucket exhausted (> 10 calls / 60 s per token) | Back off exponentially; consider separate tokens for concurrent callers |
| 500 Internal Server Error | Authority-side processing error | Retry with backoff; report to authority operator if persistent |
| 503 Service Unavailable | Authority or target callback temporarily unavailable | Retry with backoff; check authority health endpoint |

### 13.3 Debug Checklist

Work through this checklist in order when an integration issue is not immediately obvious:

```
[ ] 1. Can you reach the authority server at all?
        curl http://<authority>/
        Expected: JSON with "name" or "did" field

[ ] 2. Is your API key valid?
        curl -H "X-API-Key: <your_key>" http://<authority>/discover
        Expected: JSON array (may be empty)
        If 401: API key is wrong or authority restarted

[ ] 3. Does your target DID exist?
        curl http://<authority>/trust/<target_did>
        Expected: JSON with "score" field
        If 404: Target agent is not registered

[ ] 4. Does the target agent have the tool you want?
        curl -H "X-API-Key: <your_key>" http://<authority>/discover
        Look for agent with matching DID and matching tool name

[ ] 5. Is your token valid?
        curl http://<authority>/tokens/status/<token_id>
        Expected: {"status": "GOOD"}
        If REVOKED or UNKNOWN: request a new token

[ ] 6. Does the token scope match the call?
        Check that token's resource_uri ends with the tool_name you are calling
        Mismatch: 403 "Resource URI mismatch"

[ ] 7. Are you within the rate limit?
        Default: 10 calls per 60 seconds per token
        If 429: wait and retry with backoff

[ ] 8. Is the callback reachable from the authority server?
        The authority must be able to POST to {callback_url}/tools/{tool_name}
        Test: curl -X POST {callback_url}/tools/{tool_name} -H "Content-Type: application/json" -d '{}'
        Expected: some JSON response (even an error is acceptable for this test)

[ ] 9. Does the callback respond within 30 seconds?
        If it takes longer, the authority will time out and return an error

[ ] 10. Are you sending Content-Type: application/json on POST requests?
         Missing Content-Type causes 400 errors on most requests
```

---

## 14. Appendix A: Complete Python Integration Example

The following script is a complete, runnable Python agent that demonstrates every major QASP operation end-to-end. It runs as both a provider (with a live callback server) and a consumer.

```python
#!/usr/bin/env python3
"""
qasp_full_agent.py — Complete QASP agent demonstrating all integration phases.

Requirements:
    pip install httpx fastapi uvicorn

Usage:
    # Terminal 1: Start the authority server
    python scripts/qasp_server.py --host 0.0.0.0 --port 8080

    # Terminal 2: Start this agent (it acts as both provider and consumer)
    QASP_AUTHORITY_URL=http://localhost:8080 python qasp_full_agent.py
"""
from __future__ import annotations

import datetime
import logging
import os
import sys
import threading
import time
from typing import Any

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Request

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)
logger = logging.getLogger("qasp_agent")

AUTHORITY_URL = os.environ.get("QASP_AUTHORITY_URL", "http://localhost:8080")
CALLBACK_PORT = int(os.environ.get("CALLBACK_PORT", "9100"))
CALLBACK_URL = os.environ.get("CALLBACK_URL", f"http://localhost:{CALLBACK_PORT}")

# ============================================================================
# Lightweight QASP client (no external dependency beyond httpx)
# ============================================================================

class QASPError(Exception):
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"HTTP {status_code}: {detail}")

class QASPAgent:
    """Self-contained QASP agent with token caching."""

    def __init__(self, authority: str):
        self._authority = authority.rstrip("/")
        self._api_key: str | None = None
        self._did: str | None = None
        self._token_cache: dict[tuple, dict] = {}

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self._api_key:
            h["X-API-Key"] = self._api_key
        return h

    def _req(self, method: str, path: str,
             body: dict | None = None,
             params: dict | None = None) -> Any:
        with httpx.Client(timeout=30.0) as client:
            resp = client.request(
                method,
                f"{self._authority}{path}",
                json=body,
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

    def register(self, name: str, tools: list[dict], callback_url: str = "") -> dict:
        result = self._req("POST", "/register", {
            "name": name,
            "tools": tools,
            "callback_url": callback_url,
        })
        self._api_key = result["api_key"]
        self._did = result["did"]
        logger.info("Registered agent '%s' with DID: %s", name, self._did)
        return result

    def discover(self, capability: str = "*", min_trust: float = 0.0) -> list:
        return self._req("GET", "/discover", params={
            "capability": capability,
            "min_trust": min_trust,
        })

    def get_token(self, target_did: str, tool_name: str) -> str:
        """Return a cached token or request a fresh one."""
        key = (target_did, tool_name)
        cached = self._token_cache.get(key)
        if cached:
            expires = datetime.datetime.fromisoformat(cached["expires_at"])
            now = datetime.datetime.now(datetime.timezone.utc)
            if (expires - now).total_seconds() > 300:
                return cached["token"]

        token_info = self._req("POST", "/tokens/request", {
            "target_did": target_did,
            "tool_name": tool_name,
        })
        self._token_cache[key] = token_info
        logger.info("Acquired token for %s/%s (expires %s)",
                    target_did[:20], tool_name, token_info["expires_at"])
        return token_info["token"]

    def _current_token_id(self, target_did: str, tool_name: str) -> str | None:
        entry = self._token_cache.get((target_did, tool_name))
        return entry["token_id"] if entry else None

    def call_tool(self, target_did: str, tool_name: str,
                  arguments: dict, max_retries: int = 3) -> dict:
        """Call a tool with automatic retry on rate limits and token expiry."""
        delay = 1.0
        for attempt in range(max_retries):
            token = self.get_token(target_did, tool_name)
            try:
                result = self._req("POST", "/tools/call", {
                    "target_did": target_did,
                    "tool_name": tool_name,
                    "arguments": arguments,
                    "token": token,
                })
                logger.info("Tool call %s/%s succeeded. Receipt: %s",
                            target_did[:20], tool_name, result.get("receipt_id"))
                return result

            except QASPError as e:
                if e.status_code == 429:
                    logger.warning("Rate limited on attempt %d. Waiting %.1fs", attempt + 1, delay)
                    time.sleep(delay)
                    delay = min(delay * 2, 60)
                    continue
                elif e.status_code == 403:
                    logger.warning("Token rejected (403). Clearing cache and retrying.")
                    self._token_cache.pop((target_did, tool_name), None)
                    continue
                else:
                    raise

        raise RuntimeError(f"Tool call failed after {max_retries} attempts")

    def revoke_token(self, target_did: str, tool_name: str) -> None:
        token_id = self._current_token_id(target_did, tool_name)
        if token_id:
            self._req("POST", "/tokens/revoke", {"token_id": token_id})
            self._token_cache.pop((target_did, tool_name), None)
            logger.info("Revoked token %s", token_id)

    def check_token(self, token_id: str) -> dict:
        return self._req("GET", f"/tokens/status/{token_id}")

    def report(self, did: str, outcome: str, details: str = "") -> None:
        self._req("POST", f"/trust/{did}/report", {
            "outcome": outcome,
            "details": details,
        })
        logger.info("Reported %s interaction with %s", outcome, did[:20])

    def get_trust(self, did: str) -> dict:
        return self._req("GET", f"/trust/{did}")

    def open_dispute(self, respondent_did: str,
                     dispute_type: str, description: str = "") -> dict:
        return self._req("POST", "/disputes/open", {
            "respondent_did": respondent_did,
            "type": dispute_type,
            "description": description,
        })

    def get_dispute(self, dispute_id: str) -> dict:
        return self._req("GET", f"/disputes/{dispute_id}")


# ============================================================================
# Callback server (provider side)
# ============================================================================

app = FastAPI(title="QASP Full Agent Callback")

@app.post("/tools/echo")
async def handle_echo(request: Request):
    """Echo tool: return all arguments back to caller."""
    caller = request.headers.get("X-QASP-Caller-DID", "unknown")
    logger.info("echo called by %s", caller)
    try:
        args = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON body")
    return {"echo": args, "caller": caller}

@app.post("/tools/word_count")
async def handle_word_count(request: Request):
    """Word count tool: count words in a text string."""
    caller = request.headers.get("X-QASP-Caller-DID", "unknown")
    try:
        args = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON body")

    text = args.get("text")
    if not isinstance(text, str):
        raise HTTPException(400, "Missing or invalid field: text (must be string)")

    words = text.split()
    return {
        "word_count": len(words),
        "char_count": len(text),
        "called_by": caller,
    }

@app.get("/health")
def health():
    return {"status": "ok"}


# ============================================================================
# Main: register, run demo interactions, shut down
# ============================================================================

def run_callback_server():
    """Run the FastAPI callback server in a background thread."""
    uvicorn.run(app, host="0.0.0.0", port=CALLBACK_PORT, log_level="warning")

def main():
    # Start callback server in background
    server_thread = threading.Thread(target=run_callback_server, daemon=True)
    server_thread.start()
    time.sleep(1.5)  # Give server time to bind
    logger.info("Callback server ready on port %d", CALLBACK_PORT)

    # Create two agent instances (simulating two distinct agents)
    provider = QASPAgent(AUTHORITY_URL)
    consumer = QASPAgent(AUTHORITY_URL)

    # Phase 1: Registration
    print("\n--- Phase 1: Registration ---")
    provider.register(
        name="DemoProvider",
        tools=[
            {"name": "echo", "description": "Echo all arguments back to the caller"},
            {
                "name": "word_count",
                "description": "Count words and characters in a text string. Returns word_count and char_count integers.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string", "description": "Text to analyse"}
                    },
                    "required": ["text"]
                }
            },
        ],
        callback_url=CALLBACK_URL,
    )
    consumer.register("DemoConsumer", tools=[], callback_url="")
    print(f"Provider DID: {provider._did}")
    print(f"Consumer DID: {consumer._did}")

    # Phase 2: Discovery
    print("\n--- Phase 2: Discovery ---")
    agents = consumer.discover()
    print(f"Found {len(agents)} registered agent(s):")
    for a in agents:
        tools_list = ", ".join(t["name"] for t in a["tools"])
        print(f"  {a['name']} (trust: {a['trust_score']:.2f}) tools: {tools_list}")

    # Phase 3: Token acquisition (implicit via get_token)
    print("\n--- Phase 3: Token Acquisition ---")
    token = consumer.get_token(provider._did, "echo")
    print(f"Token acquired (first 30 chars): {token[:30]}...")

    # Phase 4: Tool invocation — echo
    print("\n--- Phase 4: Tool Invocation (echo) ---")
    result = consumer.call_tool(
        target_did=provider._did,
        tool_name="echo",
        arguments={"greeting": "hello", "number": 42}
    )
    print(f"Echo result: {result['result']}")
    print(f"Receipt ID: {result['receipt_id']}")
    print(f"Cost: {result['metering']['cost']} {result['metering']['currency']}")

    # Tool invocation — word_count
    print("\n--- Phase 4b: Tool Invocation (word_count) ---")
    result2 = consumer.call_tool(
        target_did=provider._did,
        tool_name="word_count",
        arguments={"text": "The quick brown fox jumps over the lazy dog"}
    )
    print(f"Word count result: {result2['result']}")

    # Phase 5: OCSP check
    print("\n--- Phase 5: Token Status (OCSP) ---")
    token_id = consumer._token_cache[(provider._did, "echo")]["token_id"]
    status = consumer.check_token(token_id)
    print(f"Token status: {status['status']}")

    # Phase 5b: Revocation
    print("\n--- Phase 5b: Token Revocation ---")
    consumer.revoke_token(provider._did, "echo")
    status_after = consumer.check_token(token_id)
    print(f"Token status after revocation: {status_after['status']}")

    # Phase 6: Trust reporting
    print("\n--- Phase 6: Trust Reporting ---")
    consumer.report(provider._did, "success")
    consumer.report(provider._did, "success")
    trust = consumer.get_trust(provider._did)
    print(f"Provider trust score: {trust['score']:.4f} (interactions: {trust['interaction_count']})")

    # Phase 7: Dispute (demonstration only)
    print("\n--- Phase 7: Dispute Resolution (demo) ---")
    dispute = consumer.open_dispute(
        respondent_did=provider._did,
        dispute_type="data_quality",
        description="Demonstration dispute — not a real issue."
    )
    record = consumer.get_dispute(dispute["dispute_id"])
    print(f"Dispute opened: {record['dispute_id']} status={record['status']}")

    print("\nAll phases completed successfully.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
    except Exception as exc:
        logger.error("Fatal error: %s", exc, exc_info=True)
        sys.exit(1)
```

---

## 15. Appendix B: Complete JavaScript Integration Example

The following Node.js script demonstrates all QASP operations using only the built-in `fetch` API (Node.js 18+). No third-party HTTP library is required.

```javascript
#!/usr/bin/env node
/**
 * qasp_full_agent.js — Complete QASP agent in Node.js
 *
 * Requirements: Node.js 18+ (fetch built-in)
 *
 * Usage:
 *   QASP_AUTHORITY_URL=http://localhost:8080 node qasp_full_agent.js
 */

"use strict";

const AUTHORITY = process.env.QASP_AUTHORITY_URL || "http://localhost:8080";

// ============================================================================
// QASP Client
// ============================================================================

class QASPError extends Error {
    constructor(statusCode, detail) {
        super(`HTTP ${statusCode}: ${detail}`);
        this.statusCode = statusCode;
        this.detail = detail;
    }
}

class QASPAgent {
    constructor(authorityUrl) {
        this._authority = authorityUrl.replace(/\/$/, "");
        this._apiKey = null;
        this._did = null;
        this._tokenCache = new Map(); // key: "did:tool" -> token_info
    }

    async _request(method, path, body = null, params = null) {
        let url = `${this._authority}${path}`;
        if (params) {
            url += "?" + new URLSearchParams(params).toString();
        }

        const headers = { "Content-Type": "application/json" };
        if (this._apiKey) headers["X-API-Key"] = this._apiKey;

        const options = { method, headers };
        if (body !== null) options.body = JSON.stringify(body);

        const resp = await fetch(url, options);
        let data;
        try {
            data = await resp.json();
        } catch {
            data = { detail: await resp.text() };
        }

        if (!resp.ok) {
            throw new QASPError(resp.status, data.detail || JSON.stringify(data));
        }
        return data;
    }

    async register(name, tools, callbackUrl = "") {
        const data = await this._request("POST", "/register", {
            name, tools, callback_url: callbackUrl
        });
        this._apiKey = data.api_key;
        this._did = data.did;
        console.log(`Registered '${name}' with DID: ${data.did}`);
        return data;
    }

    async discover(capability = "*", minTrust = 0.0) {
        return this._request("GET", "/discover", null, {
            capability, min_trust: minTrust
        });
    }

    async _getToken(targetDid, toolName) {
        const cacheKey = `${targetDid}:${toolName}`;
        const cached = this._tokenCache.get(cacheKey);

        if (cached) {
            const expiresAt = new Date(cached.expires_at);
            const remaining = (expiresAt - Date.now()) / 1000;
            if (remaining > 300) return cached;
        }

        const tokenInfo = await this._request("POST", "/tokens/request", {
            target_did: targetDid,
            tool_name: toolName,
        });
        this._tokenCache.set(cacheKey, tokenInfo);
        console.log(`Token acquired for ${toolName} (expires ${tokenInfo.expires_at})`);
        return tokenInfo;
    }

    async callTool(targetDid, toolName, args, maxRetries = 3) {
        let delay = 1000; // ms

        for (let attempt = 0; attempt < maxRetries; attempt++) {
            const tokenInfo = await this._getToken(targetDid, toolName);
            try {
                const result = await this._request("POST", "/tools/call", {
                    target_did: targetDid,
                    tool_name: toolName,
                    arguments: args,
                    token: tokenInfo.token,
                });
                console.log(`Tool '${toolName}' succeeded. Receipt: ${result.receipt_id}`);
                return result;

            } catch (err) {
                if (err.statusCode === 429) {
                    console.warn(`Rate limited. Retrying in ${delay}ms...`);
                    await new Promise(r => setTimeout(r, delay));
                    delay = Math.min(delay * 2, 60000);
                    continue;
                } else if (err.statusCode === 403) {
                    console.warn("Token rejected (403). Clearing cache.");
                    this._tokenCache.delete(`${targetDid}:${toolName}`);
                    continue;
                }
                throw err;
            }
        }
        throw new Error(`Tool call failed after ${maxRetries} attempts`);
    }

    async revokeToken(targetDid, toolName) {
        const cacheKey = `${targetDid}:${toolName}`;
        const cached = this._tokenCache.get(cacheKey);
        if (cached) {
            await this._request("POST", "/tokens/revoke", {
                token_id: cached.token_id
            });
            this._tokenCache.delete(cacheKey);
            console.log(`Revoked token ${cached.token_id}`);
        }
    }

    async checkToken(tokenId) {
        return this._request("GET", `/tokens/status/${tokenId}`);
    }

    async report(did, outcome, details = "") {
        await this._request("POST", `/trust/${did}/report`, { outcome, details });
        console.log(`Reported ${outcome} interaction with ${did.slice(0, 20)}`);
    }

    async getTrust(did) {
        return this._request("GET", `/trust/${did}`);
    }

    async openDispute(respondentDid, type, description = "") {
        return this._request("POST", "/disputes/open", {
            respondent_did: respondentDid, type, description
        });
    }

    async getDispute(disputeId) {
        return this._request("GET", `/disputes/${disputeId}`);
    }
}

// ============================================================================
// Main demo
// ============================================================================

async function main() {
    console.log(`\nQASP Full Agent Demo (Node.js)`);
    console.log(`Authority: ${AUTHORITY}`);
    console.log("=".repeat(50));

    const provider = new QASPAgent(AUTHORITY);
    const consumer = new QASPAgent(AUTHORITY);

    // Phase 1: Registration
    console.log("\n--- Phase 1: Registration ---");
    await provider.register("JSProvider", [
        { name: "echo", description: "Echo all arguments back to the caller" },
        {
            name: "reverse",
            description: "Reverse a string. Returns reversed_text (string).",
            input_schema: {
                type: "object",
                properties: {
                    text: { type: "string", description: "Text to reverse" }
                },
                required: ["text"]
            }
        }
    ], "");  // No callback — authority echoes

    await consumer.register("JSConsumer", [], "");
    console.log(`Provider DID: ${provider._did}`);
    console.log(`Consumer DID: ${consumer._did}`);

    // Phase 2: Discovery
    console.log("\n--- Phase 2: Discovery ---");
    const agents = await consumer.discover();
    console.log(`Found ${agents.length} agent(s):`);
    for (const a of agents) {
        const toolNames = a.tools.map(t => t.name).join(", ");
        console.log(`  ${a.name} (trust: ${a.trust_score.toFixed(2)}) tools: ${toolNames}`);
    }

    // Filtered discovery
    const echoAgents = await consumer.discover("qasp://*/tools/echo", 0.0);
    console.log(`Agents with 'echo' tool: ${echoAgents.length}`);

    // Phase 3 + 4: Token acquisition and tool call
    console.log("\n--- Phases 3 & 4: Token + Tool Call (echo) ---");
    const echoResult = await consumer.callTool(
        provider._did, "echo",
        { message: "hello from JavaScript", value: 99 }
    );
    console.log("Echo result:", JSON.stringify(echoResult.result, null, 2));
    console.log("Cost:", echoResult.metering.cost, echoResult.metering.currency);

    // Phase 5: OCSP check
    console.log("\n--- Phase 5: Token Status (OCSP) ---");
    const echoTokenInfo = consumer._tokenCache.get(`${provider._did}:echo`);
    const ocspStatus = await consumer.checkToken(echoTokenInfo.token_id);
    console.log(`Token status: ${ocspStatus.status}`);

    // Revoke
    await consumer.revokeToken(provider._did, "echo");
    const afterRevoke = await consumer.checkToken(echoTokenInfo.token_id);
    console.log(`Token status after revocation: ${afterRevoke.status}`);

    // Verify revoked token rejected
    try {
        await consumer._request("POST", "/tools/call", {
            target_did: provider._did,
            tool_name: "echo",
            arguments: {},
            token: echoTokenInfo.token,
        });
        console.error("ERROR: Revoked token should have been rejected");
    } catch (err) {
        if (err.statusCode === 403) {
            console.log("Revoked token correctly rejected with 403");
        } else {
            throw err;
        }
    }

    // Phase 6: Trust reporting
    console.log("\n--- Phase 6: Trust Reporting ---");
    await consumer.report(provider._did, "success");
    await consumer.report(provider._did, "success");
    const trust = await consumer.getTrust(provider._did);
    console.log(`Provider trust: ${trust.score.toFixed(4)} (${trust.interaction_count} interactions)`);

    // Phase 7: Dispute
    console.log("\n--- Phase 7: Dispute Resolution ---");
    const dispute = await consumer.openDispute(
        provider._did, "data_quality", "JS demo dispute"
    );
    const record = await consumer.getDispute(dispute.dispute_id);
    console.log(`Dispute ${record.dispute_id}: status=${record.status}`);

    console.log("\nAll phases completed successfully.");
}

main().catch(err => {
    console.error("Fatal:", err.message);
    process.exit(1);
});
```

---

## 16. Appendix C: API Quick Reference Card

### Unauthenticated Endpoints

| Method | Path | Description | Key Response Fields |
|---|---|---|---|
| GET | `/` | Server info and health | `name`, `version`, `did` |
| GET | `/features` | Feature flags and protocol version | `features`, `version` |
| GET | `/tokens/status/{token_id}` | OCSP token status check | `status` (GOOD/REVOKED/UNKNOWN), `revoked_at` |
| GET | `/trust/{did}` | Agent trust score | `score`, `interaction_count`, `components` |
| GET | `/disputes/{dispute_id}` | Dispute record | `dispute_id`, `status`, `claimant_did`, `respondent_did` |

### Authenticated Endpoints (Require X-API-Key Header)

| Method | Path | Description | Key Request Fields | Key Response Fields |
|---|---|---|---|---|
| POST | `/register` | Register agent, get credentials | `name`, `tools`, `callback_url` | `api_key`, `did`, `agent_id`, `public_key` |
| GET | `/discover` | Find registered agents | `capability` (query), `min_trust` (query) | Array of `{did, name, tools, trust_score}` |
| POST | `/tokens/request` | Request capability token | `target_did`, `tool_name`, `verbs` | `token`, `token_id`, `resource_uri`, `expires_at` |
| POST | `/tokens/revoke` | Revoke a token | `token_id` | `revoked`, `token_id`, `entries_created` |
| POST | `/tools/call` | Invoke a tool on another agent | `target_did`, `tool_name`, `arguments`, `token` | `result`, `metering`, `receipt_id` |
| POST | `/trust/{did}/report` | Report interaction outcome | `outcome`, `details` | Updated trust record |
| POST | `/disputes/open` | Open a dispute | `respondent_did`, `type`, `description` | `dispute_id`, `status` |

### Common Request/Response Shapes

**Register request:**
```json
{
  "name": "AgentName",
  "tools": [{"name": "tool_name", "description": "...", "input_schema": {...}}],
  "callback_url": "https://your-agent.example.com"
}
```

**Token request:**
```json
{"target_did": "did:qasp:...", "tool_name": "tool_name", "verbs": ["exec"]}
```

**Tool call request:**
```json
{
  "target_did": "did:qasp:...",
  "tool_name": "tool_name",
  "arguments": {"key": "value"},
  "token": "<base64-token>"
}
```

**Tool call response:**
```json
{
  "result": {"...": "..."},
  "metering": {"units": 1, "cost": 10, "currency": "credits"},
  "receipt_id": "f47ac10b..."
}
```

### Rate Limits and Constraints

| Parameter | Default | Notes |
|---|---|---|
| Token lifetime | 1 hour | From `expires_at` field in token request response |
| Rate limit per token | 10 calls / 60 seconds | Token bucket algorithm; 429 on exhaustion |
| Callback timeout | 30 seconds | Authority times out relay if callback does not respond |
| Trust score initial | 0.5 | Beta distribution prior, symmetric |
| Trust cap: score > 0.7 | Requires 10+ interactions | Anti-gaming cap |
| Trust cap: score > 0.8 | Requires 50+ interactions | Anti-gaming cap |
| Trust cap: score > 0.9 | Requires 200+ interactions | Anti-gaming cap |

---

## 17. Appendix D: Token Lifecycle State Diagram

```
                        +-------------+
                        |  Requested  |
                        | (not yet    |
                        |  issued)    |
                        +------+------+
                               |
                   POST /tokens/request succeeds
                               |
                               v
                        +------+------+
              +-------->+    GOOD     +<---------+
              |         |  (active)   |          |
              |         +----+-+------+          |
              |              | |                 |
              |    Time      | |  POST           |
              |    passes    | |  /tokens/revoke |
              |    (refill)  | |                 |
              |              | |                 |
              |         +----v-+------+          |
              |         |  GOOD       |          |
     Rate     |         |  (bucket    |          |
     refills  |         |   depleted) |          |
              |         +----+--------+          |
              |              |                   |
              |    429 Too   |                   |
              |    Many      |                   |
              |    Requests  |                   |
              +--------------+     +---------+   |
                                   | REVOKED |<--+
                             +---->+         |
                             |     +---------+
                             |
                     expires_at reached
                             |
                             v
                        +---------+
                        | EXPIRED |
                        | (token  |
                        |  gone)  |
                        +---------+
                             |
                    Attempt to use expired token
                             |
                             v
                    HTTP 403 Forbidden
                    "Token has expired"


State Summary:
  GOOD (bucket full)   — Token is valid; rate limit headroom available
  GOOD (bucket low)    — Token is valid; approaching rate limit
  429 Rate Limited     — Too many calls; wait for bucket refill (~6s per token)
  REVOKED              — POST /tokens/revoke was called; token permanently invalid
  EXPIRED              — expires_at has passed; token permanently invalid
  UNKNOWN              — Token ID not found in OCSP; may never have been valid

Agent Obligations:
  On 403 from /tools/call  → Evict from cache; request new token
  On 429 from /tools/call  → Exponential backoff; do NOT request new token
  On task completion       → Optionally revoke via POST /tokens/revoke
  On 5-min-to-expiry       → Proactively request new token; optionally revoke old
```

---

## 18. Appendix E: Agent Capability Checklist (Printable)

Use this checklist when onboarding a new agent or conducting a periodic integration review.

### Agent Identity

```
Agent name:        ___________________________________
Agent DID:         ___________________________________
Authority URL:     ___________________________________
Registration date: ___________________________________
Credentials store: ___________________________________
```

### Minimum Requirements (All Must Be Checked)

```
[ ] HTTP POST with JSON body to HTTPS endpoint
[ ] HTTP GET with query string parameters
[ ] Custom header support: X-API-Key, Content-Type
[ ] Persistent storage for api_key and did
[ ] At least one tool definition (name + description)
[ ] api_key never stored in source code or logs
```

### Reliability Features

```
[ ] Token cache implemented (key: target_did + tool_name)
[ ] expires_at checked before token reuse
[ ] HTTP 403 triggers token cache eviction and re-request
[ ] HTTP 429 handled with exponential backoff
[ ] HTTP 5xx retried with backoff (max 3 attempts)
[ ] Discovery results cached with TTL <= 300 seconds
```

### Provider Features (If Exposing Tools)

```
[ ] Callback HTTP server running and reachable
[ ] Routes: POST /tools/{tool_name} for each registered tool
[ ] Content-Type: application/json on all responses
[ ] Responds within 30 seconds on all routes
[ ] X-QASP-Caller-DID logged for all inbound calls
[ ] HTTP 401/403 NOT returned from callback routes
[ ] Input validation on all callback arguments
[ ] Maximum body size limit configured
[ ] Callback URL registered matches actual server URL
```

### Trust Participation

```
[ ] report_interaction called after each tool call
[ ] "success" reported on clean tool responses
[ ] "failure" reported with descriptive details string
[ ] Trust score of targets checked before high-value operations
[ ] Disputes opened for persistent failures (3+ consecutive)
```

### Security Posture

```
[ ] api_key stored in secrets manager or environment variable
[ ] api_key never appears in log output
[ ] token strings never appear in log output
[ ] HTTPS used for all authority connections in production
[ ] TLS certificate verification enabled (no verify=False)
[ ] Callback URL uses HTTPS in production
[ ] Callback server has IP allowlist or path secret
```

### Operational Readiness

```
[ ] Health endpoint checks QASP authority connectivity
[ ] Monitoring metrics instrumented (calls, errors, latency)
[ ] Re-registration procedure documented (for authority restart)
[ ] Token refresh handled for operations > 55 minutes
[ ] Cost tracking against metering.cost field implemented
[ ] Receipt IDs retained in logs for dispute evidence
[ ] End-to-end test script passing against staging authority
```

### Integration Review Sign-Off

```
Reviewed by:  ___________________________________
Date:         ___________________________________
Authority:    ___________________________________
Notes:        ___________________________________
              ___________________________________
```

---

*QASP Agent Adoption and Integration Guide — Version 1.0.0 — 2026-03-10*
*QASP Platform Team — Public Engineering Reference*
