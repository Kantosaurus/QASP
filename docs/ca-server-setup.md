# QASP Authority Server Setup Guide

This guide walks you through deploying and operating the QASP Authority Server — the root of trust for any QASP network. By the end, you will have a running server that agents can register with, obtain cryptographic tokens from, and use to securely call each other's tools.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
3. [Quick Start with Docker](#3-quick-start-with-docker)
4. [Local Development Setup](#4-local-development-setup)
5. [Configuration](#5-configuration)
6. [Verifying the Server](#6-verifying-the-server)
7. [Security Architecture](#7-security-architecture)
8. [API Reference Summary](#8-api-reference-summary)
9. [Deployment Considerations](#9-deployment-considerations)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Overview

The QASP Authority Server (`scripts/qasp_server.py`) is a FastAPI-based REST API that acts as the certificate authority and trust registry for the entire QASP network. Every registered agent, every issued token, and every tool call flows through or is verified against this server.

### What it does

- **Issues decentralized identities.** Each agent that registers receives a `did:qasp` identifier backed by an ML-DSA-65 keypair generated server-side.
- **Signs capability tokens.** When agent A wants to call agent B's tool, the server issues a CBOR-encoded token signed with its own ML-DSA-65 authority key. The token is scoped to one specific tool, carries a rate limit, and expires after one hour.
- **Verifies all tool calls.** Before relaying a tool call to its target, the server performs a seven-step verification: signature check, expiry check, revocation check, ARM URI scope check, verb check, rate limit check, and metering.
- **Manages trust scores.** After each tool call, the server updates a Bayesian trust score for the target agent. Scores can also be reported manually and queried by anyone.
- **Tracks revocations.** Tokens can be revoked at any time via a Certificate Revocation List (CRL). The `/tokens/status/{token_id}` endpoint acts as an OCSP responder.
- **Handles disputes.** Agents can file disputes against each other. Dispute records are stored in-server memory.

### Role in the QASP ecosystem

```
  Agent A                 QASP Authority Server              Agent B
     |                           |                              |
     |--- POST /register ------->|                              |
     |<-- api_key, did, pub_key--|                              |
     |                           |                              |
     |--- POST /tokens/request ->|                              |
     |<-- signed capability tok--|                              |
     |                           |                              |
     |--- POST /tools/call ------>|                              |
     |     (with token)          |--- POST /tools/analyze ----->|
     |                           |<-- { result } ---------------|
     |<-- { result, receipt } ---|                              |
```

The server is the **only** component that handles cryptography. Agents do not need ML-DSA-65 libraries, CBOR parsing, or DID resolution logic. They communicate exclusively via JSON over HTTP.

### In-memory state

All server state — registered agents, issued tokens, revocation records, trust scores, disputes — is held in memory. Restarting the server clears everything. See [Section 9](#9-deployment-considerations) for persistence strategies.

---

## 2. Prerequisites

### Docker path (recommended)

| Requirement | Version | Notes |
|-------------|---------|-------|
| Docker or Podman | 20.10+ / 4.0+ | Podman with `docker` alias works |
| Internet access | — | Required during build to clone liboqs from GitHub |
| Free port | 8080 | Configurable |

No other local dependencies are needed. The Dockerfile builds everything, including the `liboqs` C library, inside the container.

### Local path (development)

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.12+ | `python3 --version` to verify |
| pip | 24.0+ | `pip --version` to verify |
| git | Any | To clone liboqs source |
| CMake | 3.16+ | Required to build liboqs |
| Ninja | 1.10+ | Build system used by liboqs CMake config |
| gcc / clang | Any recent | C compiler for liboqs |
| libssl-dev | Any | OpenSSL headers for liboqs |

On Ubuntu / Debian, install build tools with:

```bash
sudo apt-get update && sudo apt-get install -y \
    cmake ninja-build git gcc g++ \
    ca-certificates libssl-dev python3.12 python3.12-dev python3-pip
```

On macOS with Homebrew:

```bash
brew install cmake ninja openssl python@3.12
```

---

## 3. Quick Start with Docker

This is the recommended path for both development and production. It requires no local Python or C toolchain setup.

### Step 1: Clone the repository

```bash
git clone <your-repo-url> qasp
cd qasp
```

### Step 2: Run the server script

The `scripts/run_server.sh` script builds the Docker image and starts the container in one command:

```bash
chmod +x scripts/run_server.sh
./scripts/run_server.sh
```

The script does the following:

1. Builds the `dev` stage of the multi-stage Dockerfile with `docker build --target dev -t qasp:dev .`
2. Starts a detached container named `qasp-server` that restarts automatically unless stopped
3. Binds port 8080 on the host to port 8080 in the container
4. Mounts the `scripts/` directory so server changes are reflected without rebuilding

The build takes 3-8 minutes the first time because it compiles `liboqs` from source. Subsequent builds use Docker's layer cache and complete in seconds.

**Expected output:**

```
=== Building QASP dev image ===
[+] Building 187.3s (14/14) FINISHED
=== Starting QASP Authority Server on port 8080 ===
abc123def456...

Server running! Test with:
  curl http://localhost:8080/

Stop with:
  docker stop qasp-server && docker rm qasp-server
```

### Step 3: Confirm it is running

```bash
curl http://localhost:8080/
```

You should see a JSON response like:

```json
{
  "name": "QASP Authority",
  "version": "0.1.0",
  "did": "did:qasp:2ZTp9sZY...",
  "agents_registered": 0,
  "features": [
    "ML-DSA-65 post-quantum signatures",
    "DID-based agent identity",
    ...
  ]
}
```

The `did` value is the server's own authority DID, freshly generated on startup. It will be different every time the server restarts.

### Step 4: View logs

```bash
docker logs -f qasp-server
```

### Step 5: Stop and remove the container

```bash
docker stop qasp-server && docker rm qasp-server
```

---

### Building the image manually

If you want more control over the build process, build and run the image directly:

```bash
# Build only the dev stage
docker build --target dev -t qasp:dev .

# Run the server
docker run -d \
  --name qasp-server \
  --restart unless-stopped \
  -p 8080:8080 \
  -v "$(pwd)/scripts:/app/scripts" \
  qasp:dev -c \
  "pip install fastapi uvicorn httpx && python scripts/qasp_server.py --host 0.0.0.0 --port 8080"
```

### Using Docker Compose

The project includes `compose.yaml` with `dev`, `test`, and `lint` service definitions. To start the dev environment:

```bash
docker compose up dev
```

---

## 4. Local Development Setup

Use this path if you need to iterate quickly without Docker, or if you are developing the server itself.

### Step 1: Build and install liboqs

The `liboqs-python` package requires the `liboqs` C shared library to be installed on the host. There is no pip-installable binary for all platforms, so you must build it from source.

```bash
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_BUILD_ONLY_LIB=ON \
    ..
ninja
sudo ninja install
sudo ldconfig   # Linux only — refreshes the shared library cache
```

On macOS, `ldconfig` is not needed. Set `DYLD_LIBRARY_PATH` if the linker cannot find the library:

```bash
export DYLD_LIBRARY_PATH="/usr/local/lib:$DYLD_LIBRARY_PATH"
```

### Step 2: Create a virtual environment

```bash
python3.12 -m venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate
```

### Step 3: Install QASP and server dependencies

```bash
pip install -e ".[dev]"
pip install fastapi uvicorn httpx
```

The `.[dev]` extra includes all runtime dependencies (from `pyproject.toml`) plus development tools. The three additional packages are server-only and are not in the package's standard dependency list.

**Runtime dependencies installed by `.[dev]`:**

| Package | Purpose |
|---------|---------|
| `liboqs-python>=0.10.0` | ML-DSA-65 and other post-quantum algorithms |
| `cryptography>=43.0.0` | Supporting cryptographic primitives |
| `cbor2>=5.6.0` | CBOR encoding/decoding for capability tokens |
| `aioquic>=1.0.0` | QUIC transport layer |
| `mcp>=1.26.0` | Model Context Protocol bridge |
| `a2a-python>=0.0.1` | Agent-to-agent protocol bridge |
| `base58>=2.1.0` | Base58 encoding for DID identifiers |
| `aiohttp>=3.9.0` | Async HTTP client |
| `zeroconf>=0.131.0` | mDNS-based service discovery |

### Step 4: Start the server

```bash
python scripts/qasp_server.py --host 0.0.0.0 --port 8080 --log-level info
```

**Expected startup output:**

```
2026-03-10 12:00:00,000 [INFO] qasp.server: Authority DID: did:qasp:2ZTp9sZY...

============================================================
  QASP Authority Server
  DID:  did:qasp:2ZTp9sZYwN3KmhJq...
  URL:  http://0.0.0.0:8080
============================================================

INFO:     Started server process [12345]
INFO:     Waiting for startup complete.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8080 (Press CTRL+C to quit)
```

---

## 5. Configuration

The server is configured entirely through command-line flags. There is no configuration file.

### CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `0.0.0.0` | Network interface to bind to. Use `127.0.0.1` to restrict to localhost. |
| `--port` | `8080` | TCP port to listen on. |
| `--log-level` | `info` | Logging verbosity. Accepts `debug`, `info`, `warning`, `error`, `critical`. |

**Examples:**

```bash
# Bind only to localhost for development
python scripts/qasp_server.py --host 127.0.0.1 --port 8080

# Run on a non-standard port
python scripts/qasp_server.py --port 9000

# Enable debug logging to see all request details
python scripts/qasp_server.py --log-level debug

# Full production-style invocation
python scripts/qasp_server.py --host 0.0.0.0 --port 8080 --log-level info
```

### Token constraints (hardcoded defaults)

The following values are set in the server source and cannot currently be changed via flags. They apply to every issued token:

| Constraint | Value | Description |
|-----------|-------|-------------|
| `rate_limit` | `10` | Maximum tool calls per rate period |
| `rate_period_seconds` | `60` | Rate period window in seconds |
| `validity_seconds` | `3600` | Token lifetime (1 hour) |

### Logging format

The server configures Python's standard logging with this format:

```
%(asctime)s [%(levelname)s] %(name)s: %(message)s
```

Example output at `info` level:

```
2026-03-10 12:01:23,450 [INFO] qasp.server: Registered agent Alice  DID=did:qasp:...  tools=2
2026-03-10 12:01:45,112 [INFO] uvicorn.access: 127.0.0.1:54321 - "POST /tokens/request HTTP/1.1" 200
```

---

## 6. Verifying the Server

These checks confirm the server is running correctly and that all major subsystems are functional.

### 6.1 Health check

```bash
curl -s http://localhost:8080/ | python3 -m json.tool
```

Verify the response contains a `did` field (the authority DID) and `agents_registered: 0`.

### 6.2 Feature list

```bash
curl -s http://localhost:8080/features | python3 -m json.tool
```

Expect ten feature objects covering: `did`, `capability`, `arm`, `rate_limit`, `revocation`, `ocsp`, `trust`, `dispute`, `relay`, `metering`.

### 6.3 Agent registration

Register a test agent:

```bash
curl -s -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "TestAgent",
    "tools": [
      {"name": "echo", "description": "Echo the input back"}
    ]
  }' | python3 -m json.tool
```

Expected response:

```json
{
  "agent_id": "a1b2c3d4...",
  "did": "did:qasp:AbCdEf...",
  "api_key": "f47ac10b...",
  "public_key": "base64encodedkey..."
}
```

Save the `api_key` and `did` values for the subsequent checks.

### 6.4 Agent discovery

```bash
export API_KEY="<api_key from above>"

curl -s http://localhost:8080/discover \
  -H "X-API-Key: $API_KEY" | python3 -m json.tool
```

You should see the TestAgent in the results with a `trust_score` of `0.5` (the Bayesian prior for a new agent).

### 6.5 Token request

```bash
export TARGET_DID="<did from registration>"

curl -s -X POST http://localhost:8080/tokens/request \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"target_did\": \"$TARGET_DID\", \"tool_name\": \"echo\"}" \
  | python3 -m json.tool
```

Expected response:

```json
{
  "token": "base64encodedCBORtoken...",
  "token_id": "hexencodedid...",
  "resource_uri": "qasp://agents/AbCdEf123456/tools/echo",
  "verbs": ["exec"],
  "expires_at": "2026-03-10T13:00:00+00:00"
}
```

### 6.6 Token status (OCSP)

```bash
export TOKEN_ID="<token_id from above>"

curl -s http://localhost:8080/tokens/status/$TOKEN_ID | python3 -m json.tool
```

Expected response:

```json
{
  "token_id": "...",
  "status": "GOOD"
}
```

### 6.7 Tool call relay

```bash
export TOKEN="<token from above>"

curl -s -X POST http://localhost:8080/tools/call \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"target_did\": \"$TARGET_DID\",
    \"tool_name\": \"echo\",
    \"arguments\": {\"message\": \"hello world\"},
    \"token\": \"$TOKEN\"
  }" | python3 -m json.tool
```

Because TestAgent has no `callback_url`, the server echoes the arguments:

```json
{
  "result": {
    "echo": {"message": "hello world"},
    "tool": "echo",
    "handled_by": "TestAgent",
    "note": "No callback_url configured; echoing arguments"
  },
  "metering": {"units": 1, "cost": 10, "currency": "credits"},
  "receipt_id": "hex..."
}
```

### 6.8 Token revocation

```bash
curl -s -X POST http://localhost:8080/tokens/revoke \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"token_id\": \"$TOKEN_ID\"}" | python3 -m json.tool
```

Subsequent status check confirms revocation:

```bash
curl -s http://localhost:8080/tokens/status/$TOKEN_ID | python3 -m json.tool
```

```json
{
  "token_id": "...",
  "status": "REVOKED",
  "revoked_at": "2026-03-10T12:05:00+00:00"
}
```

---

## 7. Security Architecture

### 7.1 Post-quantum cryptography

The server uses **ML-DSA-65** (defined in FIPS 204), the NIST-standardized lattice-based digital signature algorithm. This replaces RSA and ECDSA, providing security against both classical and quantum adversaries.

All signatures — authority keypair, capability tokens, OCSP responses — use ML-DSA-65. The underlying implementation is provided by the `liboqs` C library (Open Quantum Safe project) via the `liboqs-python` binding.

### 7.2 Authority identity initialization

When the server starts, `AuthorityState.__init__` runs the following sequence:

1. Generates an ML-DSA-65 keypair (`public_key`, `secret_key`).
2. Derives a `did:qasp` DID and DID document from the public key.
3. Registers the authority's DID document in the in-memory DID registry.
4. Initializes the `TrustRegistry`, `TrustScorer`, `CertificateRevocationList`, `OCSPResponder`, and `RateLimiterRegistry`.
5. Logs the authority DID.

The authority's secret key never leaves the server process. It is used exclusively to sign capability tokens and OCSP responses.

### 7.3 Agent identity and authentication

When an agent calls `POST /register`, the server generates a fresh ML-DSA-65 keypair for that agent, derives a `did:qasp` DID, and returns the public key alongside a random API key (`uuid4().hex`). The agent's secret key is also held server-side — agents do not manage their own cryptographic material.

Authentication on all protected endpoints uses the `X-API-Key` HTTP header. The server looks up the agent record by API key. If the key is missing or unknown, the request fails with HTTP 401.

### 7.4 Capability token lifecycle

A capability token is a CBOR-encoded structure signed by the authority's ML-DSA-65 key. It contains:

| Field | Description |
|-------|-------------|
| `token_id` | 16 random bytes, unique identifier |
| `issuer_did` | The authority's DID |
| `subject_did` | The calling agent's DID |
| `audience_did` | The target agent's DID |
| `resource_uri` | ARM URI of the specific tool, e.g. `qasp://agents/{did_short}/tools/{tool_name}` |
| `verbs` | Set of permitted operations, default `{"exec"}` |
| `constraints.not_after` | Expiry timestamp (now + 3600 seconds) |
| `constraints.rate_limit` | 10 |
| `constraints.rate_period_seconds` | 60 |

Token issuance flow:

1. Caller calls `POST /tokens/request` with `target_did` and `tool_name`.
2. Server resolves the target agent, finds the tool, and constructs the ARM resource URI.
3. Server signs a new `CapabilityToken` with its ML-DSA-65 secret key.
4. Token is registered in the CRL for future revocation tracking.
5. Token is CBOR-serialized, base64-encoded, and returned to the caller.

### 7.5 Tool call verification (7-step sequence)

Every `POST /tools/call` request goes through this sequence before the call is relayed:

1. **Decode.** Base64-decode the token, then CBOR-decode the `CapabilityToken`.
2. **Signature and expiry.** Verify the ML-DSA-65 signature using the authority's public key. Check that `not_after` has not passed.
3. **Revocation.** Check the CRL. If the token ID appears in the revocation list, reject with HTTP 403.
4. **ARM URI scope.** Confirm that the token's `resource_uri` matches the tool's resource URI using the ARM matching rules (exact, wildcard, or prefix).
5. **Verb check.** Confirm the token carries the `exec` verb.
6. **Rate limiting.** Look up or create a `TokenBucketRateLimiter` for this token ID. Attempt to consume one token from the bucket. If the bucket is empty, reject with HTTP 429.
7. **Relay.** If the target agent has a `callback_url`, POST to `{callback_url}/tools/{tool_name}` with the arguments and an `X-QASP-Caller-DID` header. Otherwise, echo the arguments.

After a successful call, the server appends a usage receipt to the caller's metering log and updates the target's trust score.

### 7.6 ARM resource URIs

Tools are identified by ARM-style URIs of the form:

```
qasp://agents/{did_short}/tools/{tool_name}
```

Where `{did_short}` is the first 12 characters of the agent's DID identifier.

The ARM matching rules (in order):

- **Exact match**: `qasp://agents/AbCdEf123456/tools/echo` matches only that URI.
- **Wildcard match**: `qasp://agents/AbCdEf123456/tools/*` matches any single tool on that agent.
- **Prefix match**: `qasp://agents/AbCdEf123456` matches all tools on that agent.

Wildcards may only appear as the last path segment.

### 7.7 Rate limiting

Each token has its own `TokenBucketRateLimiter`. The bucket starts full at `rate_limit` capacity (10 by default). Each tool call consumes one token. The bucket refills continuously at `rate_limit / rate_period_seconds` tokens per second (approximately 0.167 tokens/second for the defaults). If the bucket is empty when a call arrives, the server returns HTTP 429 with a `retry_after` estimate.

Rate limiter state is per-process and in-memory. Restarting the server resets all buckets.

### 7.8 Trust scoring

Each agent has a trust score between 0.0 and 1.0. New agents start at 0.5 (the Bayesian prior). Scores update after each tool call and when agents explicitly submit reports via `POST /trust/{did}/report`.

The scorer uses a Beta distribution model with anti-gaming caps: the weight of any single report decreases as the interaction count grows, preventing rapid score manipulation.

Trust score components:

| Component | Description |
|-----------|-------------|
| `reputation` | Derived from success/failure interaction history |
| `certification` | Audit certification score (if set externally) |
| `behavioral` | Behavioral pattern score |
| `witness` | Third-party witness attestations |
| `confidence` | Grows with `min(1.0, interaction_count / 50)` |

### 7.9 What is NOT protected

Be aware of the following by-design limitations:

- **No TLS at the server.** The server itself speaks plain HTTP. You must place it behind a TLS-terminating reverse proxy in production. See [Section 9](#9-deployment-considerations).
- **No persistent storage.** All state is lost on restart. Tokens, registrations, trust scores, disputes — all gone.
- **API keys are not rotatable.** There is no endpoint to rotate an API key. If a key is compromised, re-registering is the only option (which creates a new agent identity).
- **No rate limiting on registration.** Any client can call `POST /register` without authentication. Add application-layer controls in production.
- **No DID resolution from external sources.** DIDs are only resolved within the server's in-memory registry. Agents outside the server cannot verify tokens independently.

---

## 8. API Reference Summary

All endpoints except `GET /` and `GET /tokens/status/{token_id}` that require authentication expect the `X-API-Key` header. Endpoints that require authentication are marked with `(auth)`.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/` | No | Server info: version, authority DID, registered agent count, feature list |
| `GET` | `/features` | No | Detailed list of server capabilities |
| `POST` | `/register` | No | Register a new agent. Returns `agent_id`, `did`, `api_key`, `public_key` |
| `GET` | `/discover` | Yes | List registered agents. Query params: `capability` (URI pattern), `min_trust` (float) |
| `POST` | `/tokens/request` | Yes | Request a capability token. Body: `target_did`, `tool_name`, `verbs` (optional) |
| `POST` | `/tokens/revoke` | Yes | Revoke a token by ID. Body: `token_id` |
| `GET` | `/tokens/status/{token_id}` | No | OCSP status check. Returns `GOOD`, `REVOKED`, or `UNKNOWN` |
| `POST` | `/tools/call` | Yes | Relay a tool call. Body: `target_did`, `tool_name`, `arguments`, `token` |
| `GET` | `/trust/{did}` | No | Get trust score for a DID |
| `POST` | `/trust/{did}/report` | Yes | Report interaction outcome. Body: `outcome` ("success"/"failure"), `details` |
| `POST` | `/disputes/open` | Yes | Open a dispute. Body: `respondent_did`, `type`, `description` |
| `GET` | `/disputes/{dispute_id}` | No | Get dispute record by ID |

### Request and response bodies

**POST /register**

```json
{
  "name": "AgentName",
  "tools": [
    {
      "name": "tool_name",
      "description": "What this tool does",
      "input_schema": { "type": "object" }
    }
  ],
  "callback_url": "https://my-agent.example.com"
}
```

Response:
```json
{
  "agent_id": "hex...",
  "did": "did:qasp:...",
  "api_key": "hex...",
  "public_key": "base64..."
}
```

**POST /tokens/request**

```json
{
  "target_did": "did:qasp:...",
  "tool_name": "echo",
  "verbs": ["exec"]
}
```

Response:
```json
{
  "token": "base64...",
  "token_id": "hex...",
  "resource_uri": "qasp://agents/.../tools/echo",
  "verbs": ["exec"],
  "expires_at": "2026-03-10T13:00:00+00:00"
}
```

**POST /tools/call**

```json
{
  "target_did": "did:qasp:...",
  "tool_name": "echo",
  "arguments": { "key": "value" },
  "token": "base64..."
}
```

Response:
```json
{
  "result": { ... },
  "metering": { "units": 1, "cost": 10, "currency": "credits" },
  "receipt_id": "hex..."
}
```

### Error responses

All errors use the standard FastAPI format:

```json
{ "detail": "Human-readable error message" }
```

| HTTP Status | Condition |
|-------------|-----------|
| `400` | Invalid token encoding, token already revoked |
| `401` | Missing or invalid `X-API-Key` header |
| `403` | Token expired, signature invalid, token revoked, wrong ARM scope, missing `exec` verb |
| `404` | Agent, tool, or dispute not found |
| `429` | Token bucket rate limit exhausted |

---

## 9. Deployment Considerations

The server in its current form is suitable for development and demonstration. For production use, apply the following hardening measures.

### 9.1 TLS and reverse proxy

The server listens on plain HTTP. Never expose it directly on a public network without TLS. Use a reverse proxy to terminate TLS:

**nginx example:**

```nginx
server {
    listen 443 ssl;
    server_name qasp.example.com;

    ssl_certificate     /etc/letsencrypt/live/qasp.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/qasp.example.com/privkey.pem;

    location / {
        proxy_pass         http://127.0.0.1:8080;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 35s;
    }
}
```

**Caddy example** (automatic HTTPS via Let's Encrypt):

```
qasp.example.com {
    reverse_proxy localhost:8080
}
```

### 9.2 Binding to localhost only

When running behind a reverse proxy on the same machine, bind the server to `127.0.0.1` so it is not directly reachable from the network:

```bash
python scripts/qasp_server.py --host 127.0.0.1 --port 8080
```

In the Docker run command, change the port binding from `-p 8080:8080` to `-p 127.0.0.1:8080:8080`.

### 9.3 Persistent state

The server currently holds all state in-memory. For any production deployment where agent registrations and tokens must survive restarts, you have two options:

**Option A — Checkpoint and restore.** Add a startup hook that serializes `AuthorityState` to disk (JSON or SQLite) and a shutdown hook that writes it out. This requires extending the server.

**Option B — Keep the server always running.** In a containerized deployment with `--restart unless-stopped` (or a systemd service), the server only restarts on crashes or explicit operator action. For short-lived outages, this is often acceptable if the authority keypair is persisted separately.

Important: The authority's keypair is regenerated on every startup. Any tokens issued before a restart become unverifiable after it, because the verification key changes. If persistence matters, serialize and reload the authority keypair.

### 9.4 Authority keypair persistence

To persist the authority keypair across restarts, you would need to:

1. On first startup, generate the keypair and write it to a secrets store (file, Vault, AWS Secrets Manager, etc.).
2. On subsequent startups, load the keypair from that store instead of generating a new one.

This requires modifying `AuthorityState.__init__`. A minimal approach using a local file:

```python
import os, json, base64
from qasp.crypto.signatures import generate_keypair

KEY_FILE = os.environ.get("QASP_KEY_FILE", "/data/authority_keys.json")

def load_or_generate_keypair():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE) as f:
            data = json.load(f)
        pub = base64.b64decode(data["public_key"])
        sec = base64.b64decode(data["secret_key"])
        return pub, sec
    pub, sec = generate_keypair()
    os.makedirs(os.path.dirname(KEY_FILE), exist_ok=True)
    with open(KEY_FILE, "w") as f:
        json.dump({
            "public_key": base64.b64encode(pub).decode(),
            "secret_key": base64.b64encode(sec).decode(),
        }, f)
    return pub, sec
```

Protect this file with strict filesystem permissions (`chmod 600`). The secret key is the root of trust for the entire network.

### 9.5 Rate limiting registration

The `POST /register` endpoint requires no authentication. In production, protect it with one or more of the following:

- **IP-based rate limiting** at the reverse proxy layer (nginx `limit_req`, Caddy `rate_limit` plugin).
- **Network-layer access control.** Restrict `/register` to internal networks or a VPN.
- **Pre-shared registration token.** Extend the endpoint to require a one-time registration secret in the request body.

### 9.6 Resource limits

In its current form, the server has no limits on:

- Number of registered agents
- Number of tokens per agent
- Size of tool argument payloads
- Size of callback responses (capped by the 30-second httpx timeout)

For multi-tenant deployments, add application-layer guards or use the reverse proxy to enforce request body size limits.

### 9.7 Monitoring

The server emits structured log lines via Python's standard logging. For production monitoring:

- Ship logs to a central aggregator (Loki, CloudWatch, Datadog).
- Alert on elevated rates of HTTP 403 (potential token abuse) and HTTP 429 (rate limit exhaustion).
- Track the `agents_registered` count from `GET /` as a basic health metric.
- Monitor callback relay latency: the 30-second `httpx` timeout is the max, but p99 should be far lower.

### 9.8 Horizontal scaling

The server cannot currently be horizontally scaled because all state is in-memory and per-process. All requests must be routed to a single instance. Use a single-instance deployment with vertical scaling (more CPU/RAM) or implement shared state (Redis, PostgreSQL) before attempting horizontal scaling.

---

## 10. Troubleshooting

### The `run_server.sh` script fails during `docker build`

**Symptom:** The build hangs or fails during the liboqs compile step.

**Causes and fixes:**

- **No internet access.** The `liboqs-builder` stage clones from GitHub. Ensure `git.github.com` is reachable from the build host. If behind a proxy, set `--build-arg` for `HTTP_PROXY` and `HTTPS_PROXY`.
- **Out of disk space.** The build uses approximately 2 GB of disk space. Check with `df -h`.
- **Build cache corrupted.** Run `docker build --no-cache --target dev -t qasp:dev .` to rebuild from scratch.

---

### `ImportError: liboqs.so not found` on local setup

**Symptom:** When running `python scripts/qasp_server.py` locally, Python raises an ImportError for `oqs` or `liboqs`.

**Fix:** The liboqs shared library was not found by the dynamic linker. Confirm the library was installed:

```bash
ls /usr/local/lib/liboqs*
```

If it exists but the error persists, refresh the linker cache:

```bash
sudo ldconfig
```

On macOS, set the library path explicitly:

```bash
export DYLD_LIBRARY_PATH="/usr/local/lib:$DYLD_LIBRARY_PATH"
python scripts/qasp_server.py
```

---

### `Port 8080 already in use`

**Symptom:** Uvicorn fails to start with `[Errno 98] Address already in use`.

**Fix:** Find and stop the process using the port:

```bash
# Find the process
lsof -i :8080

# Or with ss
ss -tlnp | grep 8080

# Kill it
kill -9 <PID>
```

Or start the server on a different port:

```bash
python scripts/qasp_server.py --port 9090
```

If using Docker, there may be a leftover container:

```bash
docker ps -a | grep qasp-server
docker rm -f qasp-server
```

---

### HTTP 401: Missing or invalid `X-API-Key`

**Symptom:** Requests to authenticated endpoints return `{"detail": "Invalid API key"}` or `{"detail": "Missing X-API-Key header"}`.

**Causes and fixes:**

- The `X-API-Key` header was not included. Add it to every request that requires authentication.
- The API key was copied incorrectly (extra whitespace, truncated). Re-copy the full hex string from the registration response.
- The server was restarted since registration. All agent records are in-memory and are lost on restart. Re-register the agent.

---

### HTTP 403: Token expired

**Symptom:** `POST /tools/call` returns `{"detail": "Token ... has expired"}`.

**Fix:** Tokens expire after one hour. Request a new token via `POST /tokens/request`. In long-running agents, implement token refresh logic: check `expires_at` before each call and request a new token if it will expire within the next 60 seconds.

---

### HTTP 403: Resource URI mismatch

**Symptom:** `{"detail": "Resource URI mismatch: token grants '...', tool requires '...'"}`

**Cause:** The token was issued for a different tool or a different agent than the one being called. This can happen if `target_did` or `tool_name` values are mixed up.

**Fix:** Ensure the same `target_did` and `tool_name` are used in both `POST /tokens/request` and `POST /tools/call`. The token is scoped at issuance time and cannot be used for any other tool.

---

### HTTP 403: Token has been revoked

**Symptom:** A call that previously worked returns `{"detail": "Token ... has been revoked"}`.

**Fix:** The token was revoked, either by the calling agent or by the authority. Check the token status via `GET /tokens/status/{token_id}`. If revoked, request a new token.

---

### HTTP 429: Rate limit exceeded

**Symptom:** `{"detail": "Rate limit exceeded (10 calls per 60s). Retry after X.Xs"}`.

**Fix:** The token bucket for this token is empty. Wait the specified number of seconds before retrying. If you need a higher rate limit, this requires modifying the server's `Constraints` in `POST /tokens/request` (currently hardcoded to 10/60s). Alternatively, request a new token — each new token gets a fresh, full bucket.

---

### Callback relay fails: `{"error": "Callback failed: ..."}`

**Symptom:** `POST /tools/call` succeeds (HTTP 200) but the `result` object contains `{"error": "Callback failed: ..."}`.

**Causes and fixes:**

- The target agent's callback server is not running or is unreachable from the QASP server. Verify the callback URL is correct and the agent's HTTP server is running.
- The callback took longer than 30 seconds. Optimize the tool handler or increase the timeout in the server source (`httpx.AsyncClient(timeout=30)`).
- The callback returned a non-200 status. The server currently treats any `httpx` exception as a failure but does not check the HTTP status of the callback response. Add status checking to your callback implementation.

If no callback is needed, omit `callback_url` at registration time. The server echoes arguments as a placeholder, which is useful for testing.

---

### Server consumes excessive memory over time

**Symptom:** The server process memory grows unboundedly.

**Cause:** In-memory state accumulates: registered agents, tokens, rate limiter buckets, metering records, and disputes are never cleaned up.

**Mitigation:** The `RateLimiterRegistry` exposes a `cleanup_expired(max_age_seconds)` method that removes limiters older than a threshold. You could call this periodically from a background task. For the other state (tokens, metering, disputes), periodic server restarts are the simplest option for long-running demo deployments.

---

### `docker logs` shows no output after startup

**Symptom:** The container appears to be running but `docker logs qasp-server` shows nothing after the startup banner.

**Cause:** Python's stdout buffering. The `PYTHONUNBUFFERED=1` environment variable is set in the Dockerfile, which should prevent this. If you are using a custom run command, add `-e PYTHONUNBUFFERED=1` explicitly:

```bash
docker run -e PYTHONUNBUFFERED=1 ...
```

---

### `did:qasp:` DID changes on every restart

**Symptom:** The authority DID printed at startup is different each time.

**Cause:** This is expected behavior. The server generates a new ML-DSA-65 keypair on every startup, which produces a new DID. All tokens issued in a previous session are no longer verifiable because the public key no longer matches.

**Fix for production:** Persist the authority keypair across restarts. See [Section 9.4](#94-authority-keypair-persistence).
