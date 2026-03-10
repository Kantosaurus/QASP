# QASP Authority Server — Enterprise Deployment Guide

---

## Document Control

| Field | Value |
|---|---|
| Document Title | QASP Authority Server Enterprise Deployment Guide |
| Version | 1.0.0 |
| Status | Released |
| Date | 2026-03-10 |
| Classification | Internal — Infrastructure / SRE |
| Maintained By | Platform Engineering / SRE |

### Revision History

| Version | Date | Author | Summary of Changes |
|---|---|---|---|
| 0.1.0 | 2026-01-15 | Platform Engineering | Initial draft |
| 0.2.0 | 2026-02-01 | SRE Team | Added HA and TLS sections |
| 0.3.0 | 2026-02-20 | Security Team | Security hardening review |
| 1.0.0 | 2026-03-10 | Platform Engineering | First production release |

---

## Table of Contents

1. [Overview and Scope](#1-overview-and-scope)
2. [Infrastructure Requirements](#2-infrastructure-requirements)
3. [Pre-Deployment Checklist](#3-pre-deployment-checklist)
4. [Deployment Option A: Docker (Recommended)](#4-deployment-option-a-docker-recommended)
5. [Deployment Option B: Bare Metal / Virtual Machine](#5-deployment-option-b-bare-metal--virtual-machine)
6. [TLS Termination and Reverse Proxy](#6-tls-termination-and-reverse-proxy)
7. [Authority Keypair Management](#7-authority-keypair-management)
8. [State Persistence Strategy](#8-state-persistence-strategy)
9. [Security Hardening](#9-security-hardening)
10. [Monitoring and Observability](#10-monitoring-and-observability)
11. [Scaling and High Availability](#11-scaling-and-high-availability)
12. [Backup and Disaster Recovery](#12-backup-and-disaster-recovery)
13. [Upgrade and Rollback Procedures](#13-upgrade-and-rollback-procedures)
14. [Troubleshooting](#14-troubleshooting)
15. [Appendix A: Complete Configuration Reference](#appendix-a-complete-configuration-reference)
16. [Appendix B: Complete systemd Unit File](#appendix-b-complete-systemd-unit-file)
17. [Appendix C: Complete nginx Configuration](#appendix-c-complete-nginx-configuration)
18. [Appendix D: Docker Compose Production Template](#appendix-d-docker-compose-production-template)
19. [Appendix E: Runbook Quick Reference Card](#appendix-e-runbook-quick-reference-card)

---

## 1. Overview and Scope

### 1.1 Purpose of This Document

This guide provides complete, production-grade deployment instructions for the QASP Authority Server. It is intended for DevOps engineers, SREs, and infrastructure architects responsible for bringing the Authority Server from source code to a running, hardened, observable production service.

This document covers Docker-based deployment (the recommended path), bare-metal and virtual machine deployment, TLS termination, keypair persistence, security hardening, monitoring, backup, disaster recovery, upgrade procedures, and troubleshooting. It does not cover QASP protocol concepts in depth — for protocol details, refer to the QASP Agent Integration Specification in `docs/agent-integration-spec.md`.

### 1.2 QASP Authority Server Role and Responsibilities

The QASP Authority Server is the root of trust for any QASP network deployment. Every cryptographic identity, capability token, revocation decision, and trust score in the network originates from or is validated against this single server. Its responsibilities are:

**Identity issuance.** When an agent calls `POST /register`, the server generates an ML-DSA-65 keypair (public key: 1952 bytes, secret key: 4032 bytes) on behalf of the agent, derives a `did:qasp` decentralized identifier (DID), and returns the agent's API key and public key. The authority's own ML-DSA-65 keypair is generated at startup and used to sign all capability tokens.

**Capability token issuance and verification.** Tokens are CBOR-encoded, ML-DSA-65 signed bearer credentials that grant an agent the right to call a specific tool on a specific target agent. Each token encodes the resource as an ARM URI (`qasp://agents/{did_short}/tools/{tool_name}`), the permitted verbs (default: `exec`), rate limits (10 calls per 60 seconds), and a 1-hour validity window. These values are hardcoded in the current implementation.

**Token lifecycle management.** Tokens can be revoked via `POST /tokens/revoke`, which writes to the in-memory Certificate Revocation List (CRL). Real-time revocation status is available via `GET /tokens/status/{token_id}`, which is backed by an OCSP responder that itself signs its responses with the authority's ML-DSA-65 key.

**Trust scoring.** Each registered agent has a Bayesian trust score composed of reputation, certification, behavioral, and witness components. Scores are updated after successful tool calls and via the `POST /trust/{did}/report` endpoint.

**Tool call relay.** The `POST /tools/call` endpoint performs a 7-step verified relay: decode token, verify ML-DSA-65 signature and expiry, check CRL, verify ARM URI scope, verify `exec` verb, consume a token-bucket rate limit token, then forward the call to the target agent's `callback_url` via HTTPX with a 30-second timeout.

**Dispute management.** Agents can open formal disputes against other agents via `POST /disputes/open`. Disputes are stored in memory and retrievable via `GET /disputes/{dispute_id}`.

Because the Authority Server is the root of trust, its availability directly determines whether any agents in the network can exchange capability tokens or make verified tool calls. Treat this server with the same operational priority as a PKI CA or identity provider.

### 1.3 Deployment Architecture Options

**Option A — Single Node (Minimum viable production).** One server instance behind a TLS-terminating reverse proxy. Suitable for internal tooling, development environments, and small deployments where downtime during upgrades is acceptable. This is the simplest path and the one this guide treats as the primary deployment pattern.

```
Internet / Internal Network
         |
    [ nginx / Caddy ]  (TLS termination, port 443)
         |
    [ QASP Authority Server ]  (port 8080, localhost-only bind)
```

**Option B — Multi-Node Behind Load Balancer (Limited HA).** Multiple server instances behind a load balancer. This topology is constrained by the in-memory state model: because each instance has a different authority DID and independent agent registries, agents registered on node A cannot be discovered or served by node B. Sticky sessions keyed on the agent's API key partially mitigate this, but the topology does not provide true horizontal scalability. It does provide redundancy in the sense that a new node can accept new registrations if the active node fails. See Section 11 for a full discussion.

```
Internet / Internal Network
         |
  [ Load Balancer ]  (sticky sessions by X-API-Key)
     /        \
[Node A]    [Node B]
(memory)    (memory)
```

**Option C — High-Availability with Shared State (Future architecture).** A planned architecture where all in-memory state (agents, tokens, CRL, trust scores, disputes, rate limiters) is externalised to a shared Redis cluster and a PostgreSQL database. In this model, any node can handle any request. This architecture is not implemented in the current codebase but is the correct long-term path. See Sections 8, 9, and 11 for implementation guidance.

### 1.4 Audience and Prerequisites

This guide assumes the reader:

- Is comfortable operating Linux servers (Ubuntu 22.04+ or equivalent)
- Understands Docker and Docker Compose at an intermediate level
- Has working knowledge of nginx or a similar reverse proxy
- Understands PKI concepts (TLS certificates, certificate chains)
- Has read-access to the QASP repository

Before proceeding, ensure you have access to:

- The QASP source repository
- A domain name or internal DNS entry for the server
- A TLS certificate (or the ability to obtain one via Let's Encrypt)
- An infrastructure environment (cloud VM, bare metal, or Kubernetes node) meeting the requirements in Section 2

---

## 2. Infrastructure Requirements

### 2.1 Hardware Specifications

The following tables give minimum and recommended specifications. "Minimum" refers to the smallest configuration under which the server will function. "Recommended" refers to the configuration appropriate for a production workload with tens of registered agents and sustained tool call traffic.

**CPU**

| Tier | Specification | Notes |
|---|---|---|
| Minimum | 2 vCPU / 2 physical cores | ML-DSA-65 signing is CPU-intensive at startup |
| Recommended | 4 vCPU / 4 physical cores | Handles burst tool call relay concurrency |
| High traffic | 8+ vCPU | Required if serving 100+ concurrent relay requests |

ML-DSA-65 (FIPS 204) key generation requires approximately 2–5 ms per keypair on modern hardware. Each `POST /register` call triggers one keypair generation on behalf of the registering agent (plus the authority keypair at startup). At 100 registrations per second sustained, CPU usage from key generation alone can saturate a single core.

**RAM**

| Tier | Specification | Notes |
|---|---|---|
| Minimum | 512 MB | Sufficient for the Python process with ~50 agents |
| Recommended | 2 GB | Comfortable for 1,000 agents with token history |
| Production headroom | 4 GB | Allows for agent growth without retuning |

Memory consumption is dominated by the in-memory state: each `AgentRecord` stores two ML-DSA-65 keys (1952 + 4032 = 5984 bytes of key material) plus issued tokens, metering records, and trust entries. At 1,000 agents with 100 tokens each, expect approximately 200–400 MB of heap usage. Python's allocator overhead and the liboqs shared library add another 100–200 MB baseline.

**Disk**

| Tier | Specification | Notes |
|---|---|---|
| Minimum | 10 GB available | OS + Docker images + logs |
| Recommended | 50 GB | Accommodates log retention and image history |

The QASP Docker image (multi-stage build including liboqs compilation) is approximately 500–800 MB. Log volume depends on traffic; at `info` level with 100 tool calls per minute, expect 1–5 MB/hour.

**Network**

| Requirement | Specification |
|---|---|
| Inbound bandwidth | 10 Mbps sustained minimum |
| Outbound bandwidth | 10 Mbps sustained minimum (relay traffic to agent callbacks) |
| Network latency to agent callbacks | Under 100 ms recommended (30-second relay timeout is generous) |
| Network interface | Single NIC sufficient; bonded NIC for HA environments |

### 2.2 Operating System Requirements

| Component | Requirement |
|---|---|
| OS | Ubuntu 22.04 LTS or 24.04 LTS (primary support target) |
| Kernel | 5.15+ (Ubuntu 22.04 default); 6.8+ (Ubuntu 24.04 default) |
| Alternative OS | RHEL 9, Debian 12, Amazon Linux 2023 (community supported) |
| Architecture | x86_64 (amd64); ARM64 supported but not tested |
| Containerization | Docker Engine 24.0+ or Podman 4.6+ |

The Dockerfile Stage 1 builds liboqs from source on Ubuntu 24.04. The final runtime image uses `python:3.12-slim-bookworm` (Debian 12 Bookworm). The host OS only needs to run Docker; the build and runtime dependencies are fully containerized.

For bare-metal deployments (Section 5), the host must be Ubuntu 22.04+ or Debian 12+ because the liboqs build script is Ubuntu/Debian-oriented.

### 2.3 Network Requirements

**Inbound ports that must be open at the host firewall:**

| Port | Protocol | Purpose | Source |
|---|---|---|---|
| 443 | TCP | HTTPS (TLS-terminated reverse proxy) | Any (agents, admin) |
| 80 | TCP | HTTP to HTTPS redirect only | Any |
| 22 | TCP | SSH administrative access | Management CIDR only |

**Internal ports (must be reachable from the reverse proxy but not from the internet):**

| Port | Protocol | Purpose |
|---|---|---|
| 8080 | TCP | QASP Authority Server (Uvicorn) |

**Outbound requirements:**

| Destination | Port | Purpose |
|---|---|---|
| Agent callback URLs (variable) | Typically 80/443 or custom | Tool call relay (httpx, 30s timeout) |
| package registries (pip, GitHub) | 443 | During image build only |
| github.com/open-quantum-safe/liboqs | 443 | liboqs source clone during image build |

**Docker internal network:** The server container must be on a bridge network to allow the reverse proxy container to reach it. The default Docker bridge (`docker0`) is acceptable; a named bridge is preferred for clarity.

### 2.4 DNS and Certificate Requirements for TLS Termination

The QASP Authority Server must be reachable over HTTPS in production. Plain HTTP deployments are only acceptable in isolated lab environments.

Requirements:

- A fully qualified domain name (FQDN) resolving to the host's public IP address. Example: `authority.qasp.example.com`
- A TLS certificate for that FQDN, issued by a trusted CA. Let's Encrypt is recommended for internet-facing deployments; an internal CA is appropriate for intranet deployments.
- The certificate must cover the exact FQDN. Wildcard certificates (`*.example.com`) are acceptable.
- The certificate must have a validity period and an automated renewal mechanism (Certbot, cert-manager, or equivalent). Let's Encrypt certificates expire after 90 days.
- The reverse proxy must terminate TLS and forward plain HTTP to `localhost:8080` or the container's internal address.

### 2.5 Dependency Matrix

| Dependency | Version | Where Used | Notes |
|---|---|---|---|
| Python | 3.12+ | Runtime | 3.12 is the tested version |
| liboqs | 0.12.0+ (built from source) | ML-DSA-65 crypto | Cloned from GitHub at build time |
| liboqs-python | 0.10.0+ | Python binding to liboqs | `oqs` module |
| FastAPI | 0.115.0+ | HTTP framework | Installed separately (not in pyproject extras) |
| Uvicorn | 0.30.0+ | ASGI server | Installed separately |
| httpx | 0.27.0+ | Relay HTTP client | Installed separately |
| cryptography | 43.0.0+ | X.509 and symmetric crypto utilities | pyproject.toml runtime dep |
| cbor2 | 5.6.0+ | CBOR token encoding/decoding | pyproject.toml runtime dep |
| base58 | 2.1.0+ | DID identifier encoding | pyproject.toml runtime dep |
| aioquic | 1.0.0+ | QUIC transport (optional paths) | pyproject.toml runtime dep |
| mcp | 1.26.0+ | MCP bridge integration | pyproject.toml runtime dep |
| a2a-python | 0.0.1+ | A2A protocol integration | pyproject.toml runtime dep |
| aiohttp | 3.9.0+ | Async HTTP (non-relay paths) | pyproject.toml runtime dep |
| zeroconf | 0.131.0+ | mDNS service discovery | pyproject.toml runtime dep |
| Docker Engine | 24.0+ | Container runtime | Host requirement |
| cmake | 3.20+ | liboqs build system | Build stage only |
| ninja-build | 1.11+ | liboqs build system | Build stage only |
| gcc/g++ | 11+ | liboqs compilation | Build stage only |
| nginx | 1.24+ | Reverse proxy / TLS termination | Host or container |

---

## 3. Pre-Deployment Checklist

Complete every item in this checklist before starting the server in production. Mark each item before proceeding to the deployment sections.

**Infrastructure readiness**

- [ ] 1. Host meets minimum hardware specifications (Section 2.1): 2 vCPU, 512 MB RAM, 10 GB disk
- [ ] 2. Operating system is Ubuntu 22.04 LTS or 24.04 LTS (or approved alternative)
- [ ] 3. Host kernel is 5.15 or later (`uname -r`)
- [ ] 4. Docker Engine 24.0+ is installed and the daemon is running (`docker version`)
- [ ] 5. The user account running Docker commands is in the `docker` group, or operations will use `sudo`
- [ ] 6. Port 8080 is not in use on the host (`ss -tlnp | grep 8080`)
- [ ] 7. Port 443 is not in use on the host, or the reverse proxy container/process will own it
- [ ] 8. Firewall is configured to allow inbound 443/TCP and 22/TCP, block inbound 8080/TCP from external

**DNS and TLS**

- [ ] 9. FQDN for the authority server is provisioned and resolves to this host's IP (`dig authority.qasp.example.com`)
- [ ] 10. TLS certificate and private key are available on the host filesystem
- [ ] 11. Certificate chain is complete (intermediate CA included if applicable)
- [ ] 12. Certificate expiry date is more than 30 days away (`openssl x509 -in cert.pem -noout -dates`)
- [ ] 13. Automated certificate renewal is configured (Certbot timer, cert-manager CRD, etc.)

**Source and image**

- [ ] 14. QASP repository is cloned to the host at a known path (e.g., `/opt/qasp`)
- [ ] 15. The working branch/tag is correct for the intended production version
- [ ] 16. Docker can reach the internet to clone liboqs from GitHub during the build (or an offline image is prepared)
- [ ] 17. The container image builds without errors (`docker build --target dev -t qasp:dev .`)
- [ ] 18. Build duration and final image size are recorded for baseline comparison

**Keypair persistence (critical)**

- [ ] 19. You have read Section 7 (Authority Keypair Management) in full
- [ ] 20. A decision has been made on keypair persistence strategy (mounted volume, environment variable, or HSM)
- [ ] 21. If using a mounted volume: the volume path exists, has correct permissions, and is backed up
- [ ] 22. The authority keypair is NOT stored in the Docker image or the git repository

**Security**

- [ ] 23. The server will bind to `0.0.0.0:8080` inside the container, but port 8080 is NOT exposed directly to the internet
- [ ] 24. A non-root user is configured in the container (or a security-reviewed exception is documented)
- [ ] 25. Container will not run with `--privileged`
- [ ] 26. Resource limits (CPU and memory) are set in the run command or Compose file
- [ ] 27. Secret management strategy is documented (how are TLS private keys and any future secrets stored?)

**Monitoring**

- [ ] 28. Log destination is configured (stdout to journald, or file with rotation)
- [ ] 29. A health check monitoring the `GET /` endpoint is in place
- [ ] 30. Alerting for process restart and HTTP 5xx rate is configured
- [ ] 31. Disk usage monitoring is in place for the log volume

**Runbook**

- [ ] 32. On-call engineers have been given access to this document
- [ ] 33. The Appendix E Quick Reference Card is printed or bookmarked
- [ ] 34. Rollback procedure (Section 13.3) has been tested in a staging environment

---

## 4. Deployment Option A: Docker (Recommended)

Docker deployment is the recommended production path because it packages the liboqs C library build, Python runtime, and all Python dependencies into a reproducible, portable image. This eliminates the fragility of native library path management on the host.

### 4.1 Building the Container Image

The Dockerfile uses a five-stage multi-stage build. Only the `dev` stage is used for server deployment (the `test` and `lint` stages are for CI pipelines). The build sequence is:

1. **liboqs-builder** (Ubuntu 24.04): Clones the Open Quantum Safe `liboqs` repository and compiles the shared library with cmake + ninja. The install prefix is `/liboqs-install`.
2. **python-base** (python:3.12-slim-bookworm): Copies the compiled liboqs shared libraries from stage 1, runs `ldconfig` to register them, and sets Python environment variables to suppress bytecode caching and buffered output.
3. **dev**: Installs git, copies all project files, installs the full dev dependency set plus `fastapi`, `uvicorn`, and `httpx`, and sets the entrypoint to `/bin/bash`.

Build the production image from the repository root:

```bash
cd /opt/qasp

# Standard build (requires internet access to clone liboqs)
docker build --target dev -t qasp:dev .

# Tag with a version for registry push
docker build --target dev -t qasp:dev -t qasp:1.0.0 .

# Build with BuildKit for improved caching and parallel stage execution
DOCKER_BUILDKIT=1 docker build --target dev -t qasp:dev .
```

Expected build time: 5–15 minutes on first build (liboqs compilation is the bottleneck). Subsequent builds with a warm layer cache complete in under 60 seconds if only Python files changed.

> **Note on build caching:** The liboqs `git clone --depth 1` command in Stage 1 will invalidate the Docker layer cache every time the liboqs HEAD changes. For reproducible builds in CI, pin the clone to a specific commit hash or tag:
>
> ```dockerfile
> RUN git clone --depth 1 --branch 0.12.0 https://github.com/open-quantum-safe/liboqs.git
> ```

### 4.2 Container Runtime Configuration

The server process inside the container runs:

```bash
python scripts/qasp_server.py --host 0.0.0.0 --port 8080 --log-level info
```

The `--host 0.0.0.0` flag makes the server listen on all interfaces inside the container, which is correct — Docker's network isolation means this is only reachable through explicitly published ports. The `--log-level` accepts `debug`, `info`, `warning`, `error`, or `critical`.

The container's entrypoint is `/bin/bash`. To run the server, the `docker run` command passes a shell command as the argument:

```bash
docker run ... qasp:dev -c "python scripts/qasp_server.py --host 0.0.0.0 --port 8080"
```

### 4.3 Resource Limits

Always set explicit CPU and memory limits on the production container. Without limits, a single misbehaving request (e.g., a tool call relay to a slow callback) can exhaust host resources and affect other workloads.

```bash
--memory="1g"           # Hard limit: container OOM-killed if exceeded
--memory-reservation="512m"  # Soft limit: kernel reclaims memory under pressure
--cpus="2.0"            # Limit to 2.0 CPU cores
--cpu-shares=1024        # Relative weight (default is 1024)
```

For environments with many concurrent `POST /tools/call` requests (each spawning an async httpx connection), 2 CPU cores and 1 GB of RAM is the minimum. The Python process itself is single-interpreter but Uvicorn uses asyncio concurrency for I/O-bound operations.

Uvicorn's default worker model is a single process. If you need to saturate multiple CPU cores for CPU-bound paths (token verification involves ML-DSA-65 signature verification which calls into liboqs), consider running Uvicorn with `--workers 4` (one worker per CPU core). Note that multiple workers means multiple independent `AuthorityState` objects in memory — this is safe only if you have implemented keypair persistence (Section 7) and do NOT rely on in-memory agent state being shared across workers.

### 4.4 Volume Mounts and Data Persistence Strategy

The current server implementation holds all state in memory. A container restart with no volume mounts results in total state loss: new authority DID, all agents lost, all tokens invalidated, all trust scores reset.

The minimum viable persistence strategy for production involves two mounts:

**Keypair volume** — Persists the authority's ML-DSA-65 keypair across restarts so the DID remains stable. See Section 7.2 for the implementation pattern.

**Log volume** — Persists logs independently of the container lifecycle.

```bash
# Create host directories
mkdir -p /opt/qasp/data/keypair
mkdir -p /opt/qasp/data/logs
chmod 700 /opt/qasp/data/keypair  # Restrict keypair directory

# Mount in run command
-v /opt/qasp/data/keypair:/app/data/keypair:ro  # Read-only after loading
-v /opt/qasp/data/logs:/app/logs:rw
```

> **Warning:** The keypair directory contains the ML-DSA-65 secret key (4032 bytes), which is the root signing key for all capability tokens issued by this authority. Anyone who obtains this key can forge valid QASP capability tokens. Restrict filesystem permissions to the process owner only (`chmod 700`), encrypt the volume at rest, and back it up to secure storage.

### 4.5 Environment Variables

The server reads no environment variables directly in the current implementation (configuration is via CLI arguments). However, the following environment variables are relevant to the Python/Docker runtime and should be set explicitly:

| Variable | Value | Purpose |
|---|---|---|
| `PYTHONDONTWRITEBYTECODE` | `1` | Prevents `.pyc` file creation in the image |
| `PYTHONUNBUFFERED` | `1` | Forces stdout/stderr to flush immediately (critical for log capture) |
| `PIP_NO_CACHE_DIR` | `1` | Reduces image size by not caching pip downloads |
| `QASP_LOG_LEVEL` | `info` | Optional: can be read by a wrapper entrypoint script |
| `QASP_PORT` | `8080` | Optional: can be read by a wrapper entrypoint script |

These are already set in the Dockerfile's `python-base` stage. For a production hardened entrypoint script that reads these variables, see Section 4.6.

### 4.6 Starting the Server

**Minimal production run command:**

```bash
docker run -d \
  --name qasp-authority \
  --restart unless-stopped \
  --memory="1g" \
  --memory-reservation="512m" \
  --cpus="2.0" \
  -p 127.0.0.1:8080:8080 \
  -v /opt/qasp/data/keypair:/app/data/keypair \
  -v /opt/qasp/data/logs:/app/logs \
  -v /opt/qasp/scripts:/app/scripts:ro \
  qasp:dev \
  -c "python scripts/qasp_server.py --host 0.0.0.0 --port 8080 --log-level info"
```

Key flags explained:

- `-p 127.0.0.1:8080:8080` — Binds port 8080 on `127.0.0.1` only (loopback). The server is reachable from nginx on the same host but not from external networks. Do NOT use `-p 0.0.0.0:8080:8080` or `-p 8080:8080` in production.
- `--restart unless-stopped` — Automatically restarts the container if it exits, unless explicitly stopped by `docker stop`.
- `-v /opt/qasp/scripts:/app/scripts:ro` — Mounts the scripts directory as read-only so the server script is available without rebuilding.

**Verify the server started successfully:**

```bash
# Check container is running
docker ps --filter name=qasp-authority

# Check startup logs (should show "Authority DID: did:qasp:...")
docker logs qasp-authority --tail 20

# Test the health endpoint
curl -s http://127.0.0.1:8080/ | python3 -m json.tool
```

Expected output from `GET /`:

```json
{
  "name": "QASP Authority",
  "version": "0.1.0",
  "did": "did:qasp:...",
  "agents_registered": 0,
  "features": [...]
}
```

### 4.7 Health Check Configuration

Configure Docker's built-in health check to monitor the server:

```bash
docker run -d \
  --name qasp-authority \
  --health-cmd='curl -f http://localhost:8080/ || exit 1' \
  --health-interval=30s \
  --health-timeout=10s \
  --health-retries=3 \
  --health-start-period=60s \
  ...
```

The `--health-start-period=60s` gives the server time to complete `AuthorityState.__init__()`, which includes ML-DSA-65 key generation. On a cold-cache host, key generation and `ldconfig` initialization can take several seconds.

Check health status:

```bash
docker inspect --format='{{.State.Health.Status}}' qasp-authority
# Expected: healthy
```

### 4.8 Docker Compose Deployment

For single-node deployments that include the reverse proxy, use Docker Compose. See Appendix D for a complete production Compose template. A summary of the key service definition:

```yaml
services:
  qasp-authority:
    image: qasp:dev
    entrypoint: ["/bin/bash"]
    command:
      - "-c"
      - "python scripts/qasp_server.py --host 0.0.0.0 --port 8080 --log-level info"
    restart: unless-stopped
    ports:
      - "127.0.0.1:8080:8080"
    volumes:
      - keypair_data:/app/data/keypair
      - log_data:/app/logs
      - ./scripts:/app/scripts:ro
    deploy:
      resources:
        limits:
          cpus: "2.0"
          memory: 1G
        reservations:
          memory: 512M
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s
    networks:
      - qasp-internal
```

### 4.9 Container Registry and CI/CD Pipeline Integration

For teams using a container registry (AWS ECR, GitHub Container Registry, Harbor, etc.), the recommended CI/CD pipeline is:

1. **On commit to main:** Run `docker build --target test` to execute the test suite inside the container.
2. **On tag push (e.g., `v1.0.0`):** Build the `dev` target, tag with the version and `latest`, push to registry.
3. **Deployment:** Pull the tagged image on the production host, update the Compose service, perform a rolling restart.

Example GitHub Actions workflow fragment:

```yaml
- name: Build and push production image
  run: |
    docker build --target dev \
      -t $REGISTRY/qasp-authority:${{ github.ref_name }} \
      -t $REGISTRY/qasp-authority:latest \
      .
    docker push $REGISTRY/qasp-authority:${{ github.ref_name }}
    docker push $REGISTRY/qasp-authority:latest
```

For air-gapped environments, export the image as a tarball and transfer it manually:

```bash
# Export
docker save qasp:dev | gzip > qasp-dev-1.0.0.tar.gz

# Import on target host
docker load < qasp-dev-1.0.0.tar.gz
```

---

## 5. Deployment Option B: Bare Metal / Virtual Machine

Use this section if Docker is not available or not permitted in your environment. Bare-metal deployment requires manually replicating what the Dockerfile automates: compiling liboqs, configuring the Python environment, and installing all dependencies.

### 5.1 Building liboqs from Source

liboqs is the C library that provides the ML-DSA-65 (Dilithium3 / FIPS 204) algorithm. It must be compiled from source because no prebuilt packages are available in standard apt/rpm repositories.

```bash
# Install build dependencies
sudo apt-get update
sudo apt-get install -y cmake ninja-build git gcc g++ ca-certificates libssl-dev

# Clone liboqs
cd /tmp
git clone --depth 1 --branch 0.12.0 https://github.com/open-quantum-safe/liboqs.git
cd liboqs

# Build
mkdir build && cd build
cmake -GNinja \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_BUILD_ONLY_LIB=ON \
    ..
ninja
sudo ninja install

# Register the shared library
sudo ldconfig

# Verify
ls /usr/local/lib/liboqs*
# Expected: liboqs.so, liboqs.so.0, liboqs.so.0.12.0 (version may vary)
```

> **Warning:** Do not skip `sudo ldconfig` after installation. Without it, the `oqs` Python binding will fail at import with `ImportError: liboqs.so.0: cannot open shared object file`.

### 5.2 Python Environment Setup

```bash
# Install Python 3.12 (Ubuntu 22.04 requires the deadsnakes PPA)
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt-get update
sudo apt-get install -y python3.12 python3.12-venv python3.12-dev

# Create a dedicated service user
sudo useradd --system --shell /bin/false --home /opt/qasp --create-home qasp

# Set up the virtual environment
sudo -u qasp python3.12 -m venv /opt/qasp/venv
```

### 5.3 Installing QASP and Server Dependencies

```bash
# Clone the repository
sudo git clone https://github.com/your-org/qasp.git /opt/qasp/src
sudo chown -R qasp:qasp /opt/qasp/src

# Install all dependencies
sudo -u qasp /opt/qasp/venv/bin/pip install --upgrade pip
sudo -u qasp /opt/qasp/venv/bin/pip install \
    fastapi \
    uvicorn \
    httpx

# Install QASP itself in editable mode (includes all runtime deps from pyproject.toml)
sudo -u qasp /opt/qasp/venv/bin/pip install -e /opt/qasp/src

# Verify the oqs module loads
sudo -u qasp /opt/qasp/venv/bin/python -c "import oqs; print(oqs.get_enabled_sig_mechanisms())"
# Expected: list including 'ML-DSA-65'
```

### 5.4 systemd Service Unit File

Create the systemd unit file at `/etc/systemd/system/qasp-authority.service`. See Appendix B for the complete file. The key fields are:

- `User=qasp` / `Group=qasp` — Run as the non-privileged service user
- `WorkingDirectory=/opt/qasp/src` — Required because the server imports from the local `src/qasp` package
- `ExecStart` — Invokes the Uvicorn/FastAPI server via the venv Python
- `Restart=on-failure` — Restarts on crash but not on clean exit
- `RestartSec=5s` — 5-second delay between restart attempts
- `StandardOutput=journal` / `StandardError=journal` — Routes output to journald

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable qasp-authority
sudo systemctl start qasp-authority
sudo systemctl status qasp-authority
```

### 5.5 Process Management

systemd is the recommended process manager for bare-metal deployments. The unit file in Appendix B configures the following restart policies:

| systemd Directive | Value | Effect |
|---|---|---|
| `Restart` | `on-failure` | Restart if process exits non-zero |
| `RestartSec` | `5s` | Wait 5 seconds before restart |
| `StartLimitIntervalSec` | `60s` | Window for counting start attempts |
| `StartLimitBurst` | `5` | Stop restarting after 5 failures in 60 seconds |

The `StartLimitBurst` setting prevents a crash-loop from spinning indefinitely. After 5 rapid failures, systemd will stop restarting and trigger an alert (via your monitoring integration).

To reset the failure counter manually (e.g., after fixing a bug):

```bash
sudo systemctl reset-failed qasp-authority
sudo systemctl start qasp-authority
```

### 5.6 Log Management (journald Integration)

With `StandardOutput=journal` in the unit file, all server logs are written to journald. Access them with:

```bash
# Live tail
sudo journalctl -u qasp-authority -f

# Last 100 lines
sudo journalctl -u qasp-authority -n 100

# Since a specific time
sudo journalctl -u qasp-authority --since "2026-03-10 08:00:00"

# JSON output for log forwarding
sudo journalctl -u qasp-authority -o json | head -5
```

The server logs in the format:

```
2026-03-10 09:15:23,441 [INFO] qasp.server: Authority DID: did:qasp:...
2026-03-10 09:15:25,102 [INFO] qasp.server: Registered agent Alice  DID=did:qasp:...  tools=3
```

For log aggregation to Elasticsearch or Loki, configure a journald forwarder (e.g., `vector`, `fluentd`, or `promtail`) to read from the systemd journal and forward JSON-structured log entries.

Log retention is controlled by `/etc/systemd/journald.conf`. Set `SystemMaxUse=2G` to cap total journal size.

---

## 6. TLS Termination and Reverse Proxy

### 6.1 Why TLS Is Mandatory for Production

The QASP Authority Server transmits API keys in every authenticated request via the `X-API-Key` header, and issues base64-encoded capability tokens in response bodies. Over plain HTTP, any network observer can:

- Capture an agent's API key and impersonate that agent
- Capture a capability token and replay it (tokens are valid for 1 hour)
- Observe agent discovery results and map the network topology

All production deployments must terminate TLS at the reverse proxy. The server itself does not implement TLS; this is a deliberate separation-of-concerns design. The reverse proxy handles the TLS handshake and certificate lifecycle, while the server focuses on protocol logic.

### 6.2 nginx Configuration

The complete nginx configuration is in Appendix C. Key features of the configuration:

- Listens on 443 with TLS 1.2/1.3 only (TLS 1.0 and 1.1 disabled)
- Uses modern cipher suites (ECDHE + AES-GCM + CHACHA20)
- Enforces HTTP Strict Transport Security (HSTS) with a 1-year max-age
- Adds security headers: `X-Frame-Options`, `X-Content-Type-Options`, `X-XSS-Protection`, `Referrer-Policy`
- Proxies to `http://127.0.0.1:8080` with appropriate proxy headers
- Redirects all HTTP (port 80) to HTTPS
- Limits request body size to 1 MB (sufficient for all QASP requests)
- Includes rate limiting at the nginx layer as a second line of defense

Install nginx and test the configuration:

```bash
sudo apt-get install -y nginx
sudo cp /opt/qasp/config/nginx/qasp-authority.conf /etc/nginx/sites-available/qasp-authority
sudo ln -s /etc/nginx/sites-available/qasp-authority /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 6.3 Caddy Configuration

Caddy is an alternative that handles TLS certificate procurement and renewal automatically via Let's Encrypt. No external Certbot configuration is needed.

Create `/etc/caddy/Caddyfile`:

```
authority.qasp.example.com {
    # Caddy automatically obtains and renews TLS certificates
    tls admin@example.com

    # Security headers
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Frame-Options "DENY"
        X-Content-Type-Options "nosniff"
        X-XSS-Protection "1; mode=block"
        Referrer-Policy "strict-origin-when-cross-origin"
        Content-Security-Policy "default-src 'none'; frame-ancestors 'none'"
        -Server
    }

    # Request size limit (1 MB)
    request_body {
        max_size 1MB
    }

    # Rate limiting (requires caddy-ratelimit plugin or external solution)
    # rate_limit {
    #     zone registration {
    #         match path /register
    #         key {remote_host}
    #         events 10
    #         window 1m
    #     }
    # }

    # Reverse proxy to QASP server
    reverse_proxy 127.0.0.1:8080 {
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
        header_up X-Real-IP {remote_host}
        transport http {
            dial_timeout 10s
            response_header_timeout 35s
        }
    }

    # Access logging
    log {
        output file /var/log/caddy/qasp-authority-access.log {
            roll_size 100mb
            roll_keep 10
        }
        format json
    }
}

# HTTP to HTTPS redirect
http://authority.qasp.example.com {
    redir https://authority.qasp.example.com{uri} permanent
}
```

Reload Caddy after editing:

```bash
sudo systemctl reload caddy
# Verify certificate was issued
sudo caddy trust --ca https://acme-v02.api.letsencrypt.org/directory
```

### 6.4 HAProxy Configuration

HAProxy is appropriate for environments that require TCP-level load balancing or fine-grained ACL-based routing. The following configuration terminates TLS and forwards to a single backend:

```
global
    log /dev/log local0
    log /dev/log local1 notice
    maxconn 4096
    user haproxy
    group haproxy
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256

defaults
    log global
    mode http
    option httplog
    option dontlognull
    timeout connect 5s
    timeout client 30s
    timeout server 35s
    option forwardfor
    option http-server-close

frontend qasp_https
    bind *:443 ssl crt /etc/haproxy/certs/authority.qasp.example.com.pem
    http-request set-header X-Forwarded-Proto https
    http-request set-header X-Real-IP %[src]
    default_backend qasp_authority

frontend qasp_http
    bind *:80
    http-request redirect scheme https unless { ssl_fc }

backend qasp_authority
    balance roundrobin
    option httpchk GET /
    http-check expect status 200
    server authority1 127.0.0.1:8080 check inter 30s rise 2 fall 3
```

### 6.5 Certificate Management

**Let's Encrypt with Certbot (nginx):**

```bash
sudo apt-get install -y certbot python3-certbot-nginx
sudo certbot --nginx -d authority.qasp.example.com --non-interactive --agree-tos -m admin@example.com

# Verify auto-renewal timer
sudo systemctl status certbot.timer

# Test renewal
sudo certbot renew --dry-run
```

**Let's Encrypt with Certbot (standalone, for non-nginx setups):**

```bash
sudo certbot certonly --standalone \
    -d authority.qasp.example.com \
    --non-interactive \
    --agree-tos \
    -m admin@example.com

# Certificates stored at:
# /etc/letsencrypt/live/authority.qasp.example.com/fullchain.pem
# /etc/letsencrypt/live/authority.qasp.example.com/privkey.pem
```

**Internal CA (for intranet deployments):**

```bash
# Generate certificate from internal CA
openssl req -new -newkey rsa:2048 -keyout authority.key -out authority.csr \
    -subj "/CN=authority.qasp.internal/O=Your Org/C=US"
# Submit CSR to internal CA for signing
# Distribute the CA certificate to all agent clients as a trusted root
```

### 6.6 mTLS Considerations

The current server implementation does not enforce mutual TLS (mTLS) at the transport layer. Authentication is application-layer (API keys in `X-API-Key` headers). If your threat model requires network-layer client authentication, configure the reverse proxy to require and verify client certificates:

**nginx mTLS configuration addition:**

```nginx
ssl_client_certificate /etc/nginx/certs/client-ca.pem;
ssl_verify_client on;
ssl_verify_depth 2;

# Pass client certificate info to application
proxy_set_header X-Client-Certificate $ssl_client_cert;
proxy_set_header X-Client-Certificate-DN $ssl_client_s_dn;
```

mTLS is recommended for environments where agents are pre-provisioned and the certificate authority can issue client certificates to each agent before registration.

---

## 7. Authority Keypair Management

### 7.1 The Keypair Regeneration Problem

> **Critical operational warning:** Every time the QASP Authority Server starts, it calls `generate_keypair()` in `AuthorityState.__init__()`. This generates a new, random ML-DSA-65 keypair. A new keypair means a new `did:qasp` DID, which means:
>
> - All previously issued capability tokens become invalid (signature verification fails because the authority public key has changed)
> - All registered agents' DIDs are orphaned (the DID registry that knew about them was in the old process's memory)
> - Any external system that cached the authority's DID document now holds stale data
> - OCSP responses signed by the old key cannot be verified
>
> Without keypair persistence, every restart is functionally equivalent to deploying a brand-new authority server.

This is the single most critical operational concern for the QASP Authority Server. Every other in-memory state loss can be tolerated or worked around; a new keypair means zero backward compatibility with any previously registered agent.

### 7.2 Persisting the Authority Keypair

The current implementation does not include keypair persistence. The following pattern implements persistence by loading keys from disk on startup and generating new keys only if no persisted keys exist.

Create `/opt/qasp/src/scripts/qasp_server_persistent.py` as a modified entrypoint, or modify `AuthorityState.__init__()` directly. The recommended approach is to add a persistence layer to `AuthorityState`:

```python
import os
import pathlib

KEYPAIR_DIR = pathlib.Path(os.environ.get("QASP_KEYPAIR_DIR", "/app/data/keypair"))
PUBKEY_PATH = KEYPAIR_DIR / "authority.pub"
SECKEY_PATH = KEYPAIR_DIR / "authority.sec"

class AuthorityState:
    def __init__(self) -> None:
        # Load or generate the authority keypair
        if PUBKEY_PATH.exists() and SECKEY_PATH.exists():
            logger.info("Loading persisted authority keypair from %s", KEYPAIR_DIR)
            self.public_key = PUBKEY_PATH.read_bytes()
            self.secret_key = SECKEY_PATH.read_bytes()
            # Validate sizes
            if len(self.public_key) != 1952 or len(self.secret_key) != 4032:
                raise RuntimeError(
                    "Persisted keypair has invalid sizes. "
                    "Delete the keypair files to generate a new one."
                )
        else:
            logger.info("Generating new authority keypair (first run)")
            self.public_key, self.secret_key = generate_keypair()
            KEYPAIR_DIR.mkdir(parents=True, exist_ok=True)
            # Write with restrictive permissions
            PUBKEY_PATH.write_bytes(self.public_key)
            SECKEY_PATH.write_bytes(self.secret_key)
            os.chmod(SECKEY_PATH, 0o600)  # Owner read/write only
            os.chmod(PUBKEY_PATH, 0o644)  # World-readable public key
            logger.info("Keypair persisted to %s", KEYPAIR_DIR)

        self.did, self.did_doc = create_did(self.public_key)
        # ... rest of __init__ unchanged ...
```

The volume mount that delivers these files to the container is:

```bash
-v /opt/qasp/data/keypair:/app/data/keypair
```

Set the environment variable to point to the mount:

```bash
-e QASP_KEYPAIR_DIR=/app/data/keypair
```

On first start, the server generates and saves the keypair. On subsequent starts, it loads the saved keypair and derives the same DID as before.

### 7.3 Key Backup and Disaster Recovery

The authority keypair files (`authority.pub` and `authority.sec`) must be backed up to at least two independent, encrypted storage locations.

**Backup procedure:**

```bash
# Create encrypted backup
tar -czf - /opt/qasp/data/keypair/ | \
    gpg --symmetric --cipher-algo AES256 \
    -o /opt/qasp/backups/keypair-$(date +%Y%m%d).tar.gz.gpg

# Copy to off-site storage (S3 example)
aws s3 cp /opt/qasp/backups/keypair-$(date +%Y%m%d).tar.gz.gpg \
    s3://your-secure-backup-bucket/qasp-authority/keypair/

# Verify backup integrity
gpg --decrypt /opt/qasp/backups/keypair-$(date +%Y%m%d).tar.gz.gpg | tar -tzf -
```

Backup frequency: The keypair only needs to be backed up once (it never changes once generated). However, re-run the backup after any intentional key rotation (Section 7.4).

Backup verification: Periodically verify that you can decrypt the backup and that the key files have the correct sizes (1952 bytes public, 4032 bytes secret).

### 7.4 Key Rotation Procedures

> **Warning:** Key rotation in the current architecture is a breaking operation. It changes the authority DID, invalidates all issued tokens, and requires all agents to re-register. Plan key rotation as a maintenance window with advance notice to all agent operators.

Pre-rotation steps:
1. Notify all agent operators of the planned rotation date and time
2. Ask all agents to complete any in-flight tool calls before the window
3. Back up the existing keypair to a separate location (for forensic/audit purposes)
4. Prepare the new deployment with a clean keypair directory

Rotation procedure:
1. Stop the running server: `docker stop qasp-authority`
2. Archive the old keypair: `cp -r /opt/qasp/data/keypair /opt/qasp/backups/keypair-old-$(date +%Y%m%d)/`
3. Delete the old keypair files: `rm /opt/qasp/data/keypair/authority.pub /opt/qasp/data/keypair/authority.sec`
4. Start the server: `docker start qasp-authority` — it will generate a new keypair on startup
5. Verify the new DID: `curl http://127.0.0.1:8080/ | jq .did`
6. Distribute the new DID and public key to all agent operators
7. All agents must re-register to obtain new DIDs and tokens under the new authority

Post-rotation: Monitor for `403 Forbidden` responses on `/tools/call` from agents that have not yet re-registered. These agents hold tokens signed by the old authority key.

### 7.5 HSM Integration Considerations

For the highest security posture, the authority secret key should be stored in a Hardware Security Module (HSM) rather than on the filesystem. This prevents the secret key from being exported even if the host is compromised.

Current implementation constraint: The `generate_keypair()` and `sign()` functions in `qasp/crypto/signatures.py` use the `oqs.Signature` API from liboqs-python. liboqs does not currently have a native PKCS#11 interface, which is the standard way to delegate signing operations to an HSM.

Practical HSM integration options:

1. **Cloud KMS wrapping:** Generate the keypair in software, then encrypt the secret key with a KMS key (AWS KMS, Azure Key Vault, GCP Cloud KMS). The secret key is stored encrypted on disk; decryption requires a live call to the KMS service on startup.

2. **SoftHSM2 for testing:** For environments that want to simulate HSM workflows without hardware, SoftHSM2 provides a PKCS#11 interface that can be used to test the integration pattern before deploying with real hardware.

3. **Future native HSM support:** When liboqs adds PKCS#11 support or when a FIPS 204 implementation is available in a PKCS#11-compatible library, the `sign()` function should be refactored to call the HSM API rather than using the in-process liboqs binding.

---

## 8. State Persistence Strategy

### 8.1 What State Is Lost on Restart

The following table enumerates every piece of server state, its storage location, and the consequence of loss:

| State Component | Storage | Loss Consequence |
|---|---|---|
| Authority keypair | In-memory (unless persisted per Section 7.2) | New DID; all tokens invalidated |
| Agent registry (`agents_by_api_key`, `agents_by_did`) | In-memory | All agents must re-register; their API keys become invalid |
| DID registry | In-memory | Cannot resolve any previously registered DID |
| Capability tokens (`state.tokens`) | In-memory | Token history lost; existing tokens still valid if authority keypair persisted |
| Certificate Revocation List | In-memory | All previously revoked tokens become effectively valid again |
| OCSP responder cache | In-memory | Cache cold; responses regenerated on demand (no data loss, just latency) |
| Trust registry entries | In-memory | All trust scores reset to default (0.5); interaction history lost |
| Trust scorer state | In-memory | Scoring engine reset |
| Rate limiter registry | In-memory | All token buckets reset to full; burst traffic possible immediately after restart |
| Disputes | In-memory | All open and resolved disputes lost |
| Agent metering records | In-memory (per AgentRecord) | Billing/audit trail lost |

**The most operationally dangerous state loss is the CRL.** If the server restarts and the CRL is empty, any tokens that were revoked before the restart are no longer revoked. Agents that obtained those tokens after revocation (e.g., by replaying a captured token) can make tool calls until the 1-hour token expiry elapses. Implement CRL persistence as a high priority.

### 8.2 Checkpoint/Restore Approach

As an interim measure before a full database-backed architecture, implement periodic state checkpointing to disk. The checkpoint writes all serializable state to JSON files in the persistence volume.

A minimal checkpoint implementation would serialize:

```python
import json
import pathlib

def checkpoint_state(state: AuthorityState, checkpoint_dir: pathlib.Path) -> None:
    """Write recoverable state to disk."""
    checkpoint_dir.mkdir(parents=True, exist_ok=True)

    # Agents (omit secret keys from checkpoint — keys should come from re-registration)
    agents_data = [
        {
            "agent_id": a.agent_id,
            "name": a.name,
            "did": a.did_str,
            "public_key": base64.b64encode(a.public_key).decode(),
            "api_key": a.api_key,
            "callback_url": a.callback_url,
            "tools": a.tools,
        }
        for a in state.agents_by_did.values()
    ]
    (checkpoint_dir / "agents.json").write_text(json.dumps(agents_data, indent=2))

    # CRL (revoked token IDs and reasons)
    crl_data = state.crl.export_entries()  # requires adding this method to CRL
    (checkpoint_dir / "crl.json").write_text(json.dumps(crl_data, indent=2))

    # Disputes
    (checkpoint_dir / "disputes.json").write_text(
        json.dumps(state.disputes, indent=2, default=str)
    )

    logger.info("State checkpoint written to %s", checkpoint_dir)
```

Schedule checkpoint calls using a background asyncio task (e.g., every 60 seconds) or as an OS-level cron job that sends a `SIGUSR1` signal to the server process.

Recovery on startup loads the checkpoint and reconstructs state. Note that agent secret keys cannot be recovered from the checkpoint (they should not be stored in checkpoints for security reasons). Agents whose sessions survive a restart will need to re-register.

### 8.3 Database-Backed State (Future Architecture)

The definitive solution is to replace in-memory data structures with a database backend. The recommended architecture is:

| State Component | Target Storage | Rationale |
|---|---|---|
| Agent registry | PostgreSQL | Relational, transactional, queryable |
| Trust registry | PostgreSQL | Relational with rich query support |
| Disputes | PostgreSQL | Relational, transactional |
| Capability tokens (issued) | PostgreSQL | Auditable ledger |
| CRL entries | PostgreSQL | Critical; must survive restarts |
| Rate limiter state | Redis | High-throughput counter operations |
| OCSP response cache | Redis | Short-lived cache (TTL-based) |
| Metering records | PostgreSQL or append-only log | Billing audit trail |

The DID registry and authority keypair would remain on disk (filesystem or KMS), as described in Section 7.2.

### 8.4 Redis Session Cache (Future Architecture)

Rate limiter state is the most time-sensitive component. The token bucket algorithm requires sub-millisecond read-modify-write operations on counters keyed by token ID. Redis's atomic `INCR` and `EXPIRE` commands make it ideal for this role.

Replacing the in-memory `RateLimiterRegistry` with a Redis-backed implementation:

```python
import redis.asyncio as redis

class RedisRateLimiterRegistry:
    def __init__(self, redis_url: str) -> None:
        self.client = redis.from_url(redis_url)

    async def consume(self, token_id: bytes, rate_limit: int, period_seconds: int) -> bool:
        key = f"rate:{token_id.hex()}"
        count = await self.client.incr(key)
        if count == 1:
            await self.client.expire(key, period_seconds)
        return count <= rate_limit
```

This approach also makes rate limiting work correctly across multiple server processes or replicas, which the current in-memory `RateLimiterRegistry` cannot do.

---

## 9. Security Hardening

### 9.1 Network Security

**Bind the server to loopback only.** The Uvicorn server should only be reachable from the reverse proxy. When using Docker with `-p 127.0.0.1:8080:8080`, port 8080 is only accessible from the Docker host's loopback interface. In bare-metal deployments, ensure Uvicorn is launched with `--host 127.0.0.1` if there is no reverse proxy on a separate host.

**Firewall rules.** On Ubuntu, use `ufw`:

```bash
# Allow SSH from management network only
sudo ufw allow from 10.0.0.0/8 to any port 22

# Allow HTTPS from anywhere
sudo ufw allow 443/tcp

# Allow HTTP for Let's Encrypt renewal redirect
sudo ufw allow 80/tcp

# Deny direct access to server port from outside
sudo ufw deny 8080/tcp

# Enable firewall
sudo ufw enable
sudo ufw status verbose
```

**Network segmentation.** In cloud environments (AWS, GCP, Azure), place the QASP Authority Server in a private subnet. The reverse proxy (or load balancer) lives in the public subnet and forwards traffic to the private subnet. Agent callback URLs must be reachable from the private subnet for tool call relay to work.

### 9.2 Container Security

Run the container with the following security flags:

```bash
docker run \
  --user 1000:1000 \
  --read-only \
  --tmpfs /tmp:size=100m,noexec,nosuid \
  --tmpfs /app/logs:size=500m \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  ...
```

Explanation:

- `--user 1000:1000` — Run as a non-root UID/GID. The container's entrypoint is `/bin/bash` and the server is launched via `-c "python ..."`, so no root privileges are needed.
- `--read-only` — Mount the container filesystem as read-only. Use `--tmpfs` for directories that require write access.
- `--security-opt no-new-privileges:true` — Prevents the process from gaining additional privileges via setuid binaries.
- `--cap-drop ALL` — Drop all Linux capabilities. The server does not need any special kernel capabilities.
- `--cap-add NET_BIND_SERVICE` — Required only if binding to a port below 1024 (not needed for port 8080).

**Add a non-root user to the Dockerfile** for production builds. Add to the `dev` stage in the Dockerfile:

```dockerfile
# Add non-root user
RUN groupadd --gid 1000 qasp && \
    useradd --uid 1000 --gid 1000 --no-create-home --shell /bin/false qasp

# Fix permissions
RUN chown -R qasp:qasp /app

USER qasp
```

### 9.3 Rate Limiting the Registration Endpoint

`POST /register` is unauthenticated and creates a new keypair on every call. An adversary can exhaust CPU and memory by flooding this endpoint with registrations. Add rate limiting at the reverse proxy layer.

**nginx rate limiting for `/register`:**

```nginx
# In the http block
limit_req_zone $binary_remote_addr zone=register_limit:10m rate=5r/m;

# In the server block
location /register {
    limit_req zone=register_limit burst=3 nodelay;
    limit_req_status 429;
    proxy_pass http://127.0.0.1:8080;
}
```

This limits each IP address to 5 registration requests per minute with a burst allowance of 3.

For more sophisticated limiting (e.g., by organization or API key range), use a WAF or application-layer middleware.

### 9.4 API Key Management

API keys are generated as `uuid.uuid4().hex` — 32 hexadecimal characters (128 bits of entropy). This is cryptographically adequate for bearer token use.

Operational policies:

- API keys are returned once at registration and not stored in plaintext by the server (the server stores the key in the `AgentRecord` mapping). If an agent loses its API key, it must re-register to obtain a new one.
- API keys should be treated as secrets: stored in secret management systems (not in environment variables, not in git repositories, not in log files).
- The server logs registration events including the agent name and DID, but NOT the API key. Verify this holds if you add custom logging.
- There is no API key rotation mechanism in the current implementation. If an API key is compromised, the agent must re-register (which creates a new DID and invalidates all existing tokens for that agent).

### 9.5 Secret Management

For secrets used by the deployment infrastructure (TLS private keys, future database passwords, etc.), use a dedicated secrets manager rather than environment variables or files on disk.

| Platform | Recommended Tool |
|---|---|
| Kubernetes | Kubernetes Secrets (external-secrets-operator for sync from Vault/AWS) |
| AWS | AWS Secrets Manager or AWS Parameter Store |
| GCP | GCP Secret Manager |
| Azure | Azure Key Vault |
| On-premises | HashiCorp Vault |
| Docker Compose (dev) | Docker Secrets (Swarm mode) or `.env` files with strict permissions |

For the authority keypair secret key, the ideal integration is described in Section 7.5. As an interim measure, inject the secret key as a Docker secret:

```bash
# Create Docker secret
echo -n "$(cat /opt/qasp/data/keypair/authority.sec)" | \
    docker secret create qasp-authority-secret-key -

# Reference in Compose
secrets:
  qasp-authority-secret-key:
    external: true
```

### 9.6 Request Size Limits

The QASP API request bodies are small (registration payloads are typically under 2 KB; tool call arguments should be bounded by the tool's design). Set a maximum request size of 1 MB at the reverse proxy to prevent memory exhaustion from oversized bodies.

**nginx:**
```nginx
client_max_body_size 1m;
```

**FastAPI/Starlette (application layer):**

```python
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.gzip import GZipMiddleware

app.add_middleware(GZipMiddleware, minimum_size=1000)

# Limit body size via middleware
from starlette.middleware.base import BaseHTTPMiddleware

class LimitBodySizeMiddleware(BaseHTTPMiddleware):
    MAX_BODY_SIZE = 1 * 1024 * 1024  # 1 MB

    async def dispatch(self, request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.MAX_BODY_SIZE:
            from fastapi.responses import JSONResponse
            return JSONResponse(
                {"detail": "Request body too large"},
                status_code=413,
            )
        return await call_next(request)

app.add_middleware(LimitBodySizeMiddleware)
```

### 9.7 CORS Configuration

The QASP Authority Server API is a machine-to-machine API. It should NOT be called directly from browser JavaScript. Configure CORS to deny cross-origin requests by default, or explicitly whitelist only known origins:

```python
from fastapi.middleware.cors import CORSMiddleware

# For pure machine-to-machine APIs: deny all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=[],  # No origins allowed
    allow_methods=[],
    allow_headers=[],
)

# If a browser-based admin UI will call the API, whitelist it explicitly:
# allow_origins=["https://admin.qasp.example.com"],
```

### 9.8 Security Headers

Add the following HTTP response headers via the reverse proxy (the Appendix C nginx config includes these):

| Header | Recommended Value | Purpose |
|---|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` | Forces HTTPS for 1 year |
| `X-Frame-Options` | `DENY` | Prevents clickjacking |
| `X-Content-Type-Options` | `nosniff` | Prevents MIME sniffing |
| `X-XSS-Protection` | `1; mode=block` | Legacy XSS filter |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Controls referrer leakage |
| `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'` | Restrictive CSP for API |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` | Disables browser APIs |
| `Cache-Control` | `no-store` | Prevents caching of API responses |
| `Server` | (remove or set to empty string) | Hides server software version |

---

## 10. Monitoring and Observability

### 10.1 Log Aggregation

The QASP Authority Server emits structured log lines via Python's `logging` module. The format configured in `main()` is:

```
%(asctime)s [%(levelname)s] %(name)s: %(message)s
```

Example log lines at `info` level:

```
2026-03-10 09:15:23,441 [INFO] qasp.server: Authority DID: did:qasp:AbCdEf...
2026-03-10 09:15:25,102 [INFO] qasp.server: Registered agent Alice  DID=did:qasp:XyZ...  tools=3
2026-03-10 09:15:30,521 [INFO] qasp.server: Dispute opened: abc123 (did:qasp:X vs did:qasp:Y)
```

Uvicorn also emits access logs (HTTP method, path, status code, response time) when `--log-level info` or lower is set.

**Recommended log stack:** Forward logs from Docker stdout to a log aggregator:

- **Loki + Grafana:** Lightweight, well-suited for container log aggregation. Use the Docker Loki logging driver or `promtail` agent.
- **Elasticsearch + Kibana:** Full-text search across log lines; appropriate if the organization already runs the ELK stack.
- **Splunk:** Enterprise search and alerting; appropriate for regulated industries.

**Docker Loki logging driver configuration:**

```yaml
# In docker-compose.yml
logging:
  driver: loki
  options:
    loki-url: "http://loki:3100/loki/api/v1/push"
    loki-labels: "service=qasp-authority,env=production"
```

### 10.2 Health Check Endpoints

The server exposes two effective health check endpoints:

| Endpoint | Auth | Use |
|---|---|---|
| `GET /` | None | Liveness check. Returns 200 with DID and agent count. |
| `GET /features` | None | Deep liveness check. Returns 200 with feature list. |

Neither endpoint is a proper `/health` or `/metrics` endpoint. For production, add a dedicated health endpoint that checks internal component readiness:

```python
@app.get("/health")
def health():
    return {
        "status": "ok",
        "did": str(state.did),
        "agents": len(state.agents_by_did),
        "tokens_issued": len(state.tokens),
        "crl_entries": len(state.crl),
        "uptime_seconds": (datetime.now(UTC) - startup_time).total_seconds(),
    }
```

Configure your load balancer or uptime monitor to poll `GET /` every 30 seconds and alert on non-200 responses or response times exceeding 2 seconds.

### 10.3 Metrics to Collect

| Metric | Type | Collection Method | Alert Threshold |
|---|---|---|---|
| `qasp_agents_registered_total` | Gauge | Scrape `GET /` `.agents_registered` | > 10,000 (memory concern) |
| `qasp_tokens_issued_total` | Counter | Count 200 responses on `/tokens/request` | - |
| `qasp_tokens_revoked_total` | Counter | Count 200 responses on `/tokens/revoke` | - |
| `qasp_tool_calls_total` | Counter | Count 200 responses on `/tools/call` | - |
| `qasp_tool_call_rate_limited_total` | Counter | Count 429 responses on `/tools/call` | > 100/min (adversarial) |
| `qasp_http_4xx_rate` | Rate | nginx access log | > 50/min |
| `qasp_http_5xx_rate` | Rate | nginx access log | > 5/min |
| `qasp_relay_latency_ms` | Histogram | Custom middleware timing | p99 > 5000 ms |
| `qasp_process_memory_mb` | Gauge | Docker stats | > 800 MB |
| `qasp_process_cpu_percent` | Gauge | Docker stats | > 80% sustained |
| `qasp_container_restarts_total` | Counter | Docker events | Any (alert immediately) |

For a Prometheus metrics endpoint, add `prometheus-fastapi-instrumentator` to the server:

```python
from prometheus_fastapi_instrumentator import Instrumentator

instrumentator = Instrumentator()
instrumentator.instrument(app).expose(app, endpoint="/metrics")
```

### 10.4 Alerting Rules

The following alert rules should be configured in your alerting platform (Prometheus Alertmanager, Grafana Alerting, Datadog, PagerDuty):

**Critical alerts (page on-call immediately):**

```yaml
- alert: QASPAuthorityDown
  expr: up{job="qasp-authority"} == 0
  for: 1m
  severity: critical
  message: "QASP Authority Server is unreachable. All agents are unable to obtain tokens."

- alert: QASPContainerRestarted
  expr: increase(container_start_total{name="qasp-authority"}[5m]) > 0
  severity: critical
  message: "QASP Authority container restarted. ALL IN-MEMORY STATE IS LOST. Agents must re-register."

- alert: QASP5xxRate
  expr: rate(nginx_http_requests_total{status=~"5.."}[5m]) > 1
  for: 2m
  severity: critical
  message: "QASP Authority returning 5xx errors at rate > 1/s for 2 minutes."
```

**Warning alerts (notify but do not page):**

```yaml
- alert: QASPHighMemory
  expr: container_memory_usage_bytes{name="qasp-authority"} > 800 * 1024 * 1024
  for: 5m
  severity: warning
  message: "QASP Authority memory usage > 800 MB. Consider restarting or increasing limits."

- alert: QASPHighRateLimitRate
  expr: rate(http_requests_total{path="/tools/call",status="429"}[5m]) > 1
  for: 5m
  severity: warning
  message: "High rate of 429 responses on /tools/call. Possible misbehaving agent or token exhaustion."

- alert: QASPCertExpirySoon
  expr: probe_ssl_earliest_cert_expiry - time() < 86400 * 14
  severity: warning
  message: "TLS certificate expires in less than 14 days."
```

### 10.5 Distributed Tracing

For environments with multiple services interacting with the QASP Authority Server, add OpenTelemetry tracing to trace requests from agent through the authority to the tool callback:

```python
from opentelemetry import trace
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

provider = TracerProvider()
provider.add_span_processor(
    BatchSpanProcessor(OTLPSpanExporter(endpoint="http://jaeger:4317"))
)
trace.set_tracer_provider(provider)
FastAPIInstrumentor.instrument_app(app)
```

This adds trace context (`traceparent` header) to outbound relay requests, allowing end-to-end tracing of a tool call from the agent through the authority to the callback URL.

---

## 11. Scaling and High Availability

### 11.1 Vertical Scaling Guidance

The most straightforward scaling path for the QASP Authority Server is vertical scaling — adding more CPU and RAM to the host or container.

**When to scale up:**

- Container CPU usage sustained above 70% during normal traffic
- Container memory usage above 70% of the configured limit
- `POST /tokens/request` latency (p95) exceeds 500 ms (indicates CPU contention during ML-DSA-65 signing)
- `POST /tools/call` relay latency exceeds 10 seconds p95 (indicates asyncio event loop saturation)

**Scaling increments:**

| Current Capacity | Scale Up To |
|---|---|
| 2 vCPU, 1 GB RAM | 4 vCPU, 2 GB RAM |
| 4 vCPU, 2 GB RAM | 8 vCPU, 4 GB RAM |
| 8 vCPU, 4 GB RAM | 16 vCPU, 8 GB RAM |

To scale a running Docker container, stop and recreate it with new resource limits (Docker does not support live resource limit changes on non-cgroup-v2 hosts):

```bash
docker stop qasp-authority
docker rm qasp-authority
docker run -d --memory="2g" --cpus="4.0" ... qasp:dev ...
```

### 11.2 Horizontal Scaling Constraints

> **Warning:** The QASP Authority Server cannot be horizontally scaled in its current form without significant architectural changes. The following constraints prevent straightforward scale-out:
>
> 1. **Independent authority DIDs.** Each instance generates its own keypair at startup, producing a different DID. Tokens issued by instance A cannot be verified by instance B (different public keys).
> 2. **Independent agent registries.** An agent registered on instance A does not exist in instance B's memory. The `/discover` endpoint on instance B will return no results for that agent.
> 3. **Independent CRLs.** Revoking a token on instance A does not revoke it on instance B. A revoked token can be replayed against instance B.
> 4. **Independent rate limiters.** An agent that is rate-limited on instance A is not rate-limited on instance B.

These constraints make naive horizontal scaling (adding more instances behind a load balancer without shared state) incorrect — it violates the security properties of the protocol.

The only correct path to horizontal scaling is the shared-state architecture described in Sections 8.3 and 8.4: all state must be externalised before multiple instances can serve the same agent population.

### 11.3 Load Balancer Configuration with Sticky Sessions

If you deploy multiple instances to improve availability (accepting the limitation that each instance serves its own agent population), use sticky sessions keyed on the `X-API-Key` header to ensure an agent's requests always reach the instance that knows about it.

**nginx sticky sessions (requires `nginx-sticky-module` or upstream hash):**

```nginx
upstream qasp_backends {
    # Hash based on X-API-Key header for stickiness
    hash $http_x_api_key consistent;
    server 10.0.0.1:8080;
    server 10.0.0.2:8080;
}
```

**HAProxy consistent hashing:**

```
backend qasp_authority
    balance hdr(X-API-Key)
    hash-type consistent
    server authority1 10.0.0.1:8080 check
    server authority2 10.0.0.2:8080 check
```

With consistent hashing on `X-API-Key`, a given agent's requests always reach the same instance (unless that instance fails). On instance failure, the hashing algorithm remaps affected agents to surviving instances — but those agents will need to re-register because the surviving instance has no record of them.

### 11.4 Future: Shared-State Architecture

The target architecture for true horizontal scaling:

```
                    [ Load Balancer ]
                   /                \
          [ Instance A ]      [ Instance B ]
                   \                /
            [ PostgreSQL Primary ]
            [ Redis Cluster ]
            [ Shared Keypair (KMS or Vault) ]
```

In this architecture:
- All instances load the same authority keypair from KMS/Vault at startup, producing the same DID
- Agent registrations are written to PostgreSQL and readable by all instances
- CRL entries are written to PostgreSQL and replicated immediately
- Rate limiter state is maintained in Redis with atomic operations
- The load balancer can use round-robin (no sticky sessions needed) because all instances share state

---

## 12. Backup and Disaster Recovery

### 12.1 What to Back Up

| Artifact | Backup Priority | Backup Frequency | Retention |
|---|---|---|---|
| Authority keypair (`authority.pub`, `authority.sec`) | Critical | After any rotation; otherwise static | Indefinite |
| QASP source code and configuration | High | Each release tag | Per release |
| Docker image | High | Each release | Last 10 releases |
| nginx / reverse proxy configuration | Medium | On change | 12 months |
| TLS certificates | Medium | On renewal | Current + previous |
| systemd unit file | Low | On change | 12 months |
| Server logs | Low | Daily rotation | 90 days |

In-memory state (agents, tokens, CRL, trust scores, disputes) is NOT backed up under the current architecture. Backups of this state require implementing the checkpoint mechanism described in Section 8.2.

### 12.2 Recovery Procedure

**Scenario: Container crashed and will not restart**

```bash
# 1. Check logs for the crash cause
docker logs qasp-authority --tail 50

# 2. Ensure the keypair volume is intact
ls -la /opt/qasp/data/keypair/

# 3. Force-remove the stopped container
docker rm qasp-authority

# 4. Restart with the original run command
docker run -d --name qasp-authority ... qasp:dev ...

# 5. Verify recovery
curl http://127.0.0.1:8080/
# DID should be the same as before (if keypair persisted)
```

**Scenario: Host failed; migrating to a new host**

```bash
# On the new host:

# 1. Install Docker
curl -fsSL https://get.docker.com | bash

# 2. Clone the QASP repository
git clone https://github.com/your-org/qasp.git /opt/qasp

# 3. Restore the keypair from backup
mkdir -p /opt/qasp/data/keypair
gpg --decrypt keypair-20260310.tar.gz.gpg | tar -xzf - -C /opt/qasp/data/

# 4. Build the image
docker build --target dev -t qasp:dev /opt/qasp

# 5. Start the server
docker run -d --name qasp-authority ...

# 6. Update DNS to point to the new host's IP
# (propagation may take up to 48 hours depending on TTL)

# 7. Verify via FQDN
curl https://authority.qasp.example.com/
```

### 12.3 RTO and RPO Considerations

| Metric | Current Architecture | With Keypair Persistence | With Full State Persistence |
|---|---|---|---|
| RPO (data loss tolerance) | Total loss on restart | Keypair preserved; all else lost | Near-zero with checkpoint |
| RTO (time to restore service) | 2–5 minutes (restart) | 2–5 minutes (restart) | 5–10 minutes (restore + restart) |
| Agent re-registration required after restart? | Yes | Yes | No (if checkpoint restored) |

For many QASP deployments, a 5-minute RTO and full agent re-registration after failover is acceptable. Agents re-register by calling `POST /register` with their original parameters, which is a single API call.

The hardest constraint is the CRL: if it cannot be restored, previously revoked tokens become valid again for up to 1 hour (the token validity window). Design your incident response procedures to account for this window.

### 12.4 Failover Procedures

**Primary failure with manual failover to standby:**

1. Alert fires: `QASPAuthorityDown` (server unreachable for 1 minute)
2. On-call engineer SSHs to the primary host and checks `docker ps` and `docker logs`
3. If the primary cannot be recovered within 5 minutes, initiate failover
4. SSH to the standby host; verify the standby has the latest keypair backup
5. Start the QASP server on the standby host using the same keypair
6. Update the DNS A record or load balancer target to point to the standby host
7. Monitor `GET /` on the standby to confirm it is healthy
8. Notify agent operators that a failover occurred and they must re-register if their sessions are lost

---

## 13. Upgrade and Rollback Procedures

### 13.1 Blue-Green Deployment

Blue-green deployment is the recommended upgrade strategy because it minimizes downtime and provides an instant rollback path. The procedure:

1. **Prepare the green environment.** On a separate host (or port), build and start the new server version. Do not switch traffic yet.

   ```bash
   # On green host (or different port on same host)
   docker build --target dev -t qasp:1.1.0 .
   docker run -d --name qasp-authority-green \
     -p 127.0.0.1:8081:8080 \
     -v /opt/qasp/data/keypair:/app/data/keypair \
     qasp:1.1.0 \
     -c "python scripts/qasp_server.py --host 0.0.0.0 --port 8080"
   ```

2. **Verify the green environment.** Run smoke tests against the green instance on port 8081.

   ```bash
   # Register a test agent
   curl -s -X POST http://127.0.0.1:8081/register \
     -H "Content-Type: application/json" \
     -d '{"name": "smoke-test-agent"}' | jq .

   # Verify /features
   curl -s http://127.0.0.1:8081/features | jq length
   # Expected: 10
   ```

3. **Switch traffic.** Update the nginx upstream to point to the green instance.

   ```nginx
   upstream qasp_authority {
       server 127.0.0.1:8081;  # Changed from 8080 to 8081
   }
   ```

   ```bash
   sudo nginx -t && sudo systemctl reload nginx
   ```

4. **Monitor.** Watch error rates, latency, and health check status for 15 minutes after the switch.

5. **Decommission blue.** Once green is stable, stop and remove the blue container.

   ```bash
   docker stop qasp-authority && docker rm qasp-authority
   ```

> **Warning about state loss during blue-green:** Because state is in-memory, the green instance starts with zero agents. Agents registered on the blue instance will not be present in the green instance. Coordinate upgrades with agent operators so they re-register during the maintenance window, or implement the state checkpoint/restore mechanism (Section 8.2) to migrate state from blue to green before the traffic switch.

### 13.2 Rolling Upgrade (Not Supported)

Rolling upgrades (gradually replacing old instances with new ones while serving traffic) are not supported by the current architecture. The reason is the same as the horizontal scaling constraint: each instance has independent state. As old instances are replaced by new ones, agents registered on old instances will receive 401 or 404 errors on new instances.

Do not attempt rolling upgrades without first implementing shared-state architecture.

### 13.3 Rollback Procedure

If a deployment introduces a regression:

```bash
# 1. Re-tag or re-pull the previous image
docker pull $REGISTRY/qasp-authority:1.0.0
# or rebuild from the previous tag
git checkout v1.0.0 && docker build --target dev -t qasp:1.0.0 .

# 2. Stop the failing container
docker stop qasp-authority && docker rm qasp-authority

# 3. Start with the old image
docker run -d --name qasp-authority \
  -v /opt/qasp/data/keypair:/app/data/keypair \
  ... \
  qasp:1.0.0 \
  -c "python scripts/qasp_server.py --host 0.0.0.0 --port 8080"

# 4. Verify rollback
curl http://127.0.0.1:8080/ | jq .version
# Expected: "0.1.0" (or whatever the previous version was)
```

### 13.4 Breaking Change Considerations

| Change Type | Migration Required | Risk |
|---|---|---|
| New endpoint added | None | Low — existing clients unaffected |
| Endpoint response field added | None | Low — existing clients ignore unknown fields |
| Endpoint response field removed | Agent code update required | Medium — agents may fail if they depend on removed field |
| Token format change (CBOR schema) | All agents must re-register | High — existing tokens unverifiable |
| Keypair algorithm change | All agents must re-register | Critical — all tokens invalid |
| Token validity period change | No migration (applies to new tokens) | Low |
| Rate limit parameter change | No migration | Low |
| DID method change | All agents must re-register | Critical |

For High and Critical changes, always coordinate with agent operators and schedule a maintenance window with full state reset.

---

## 14. Troubleshooting

### 14.1 Common Deployment Failures

**Failure 1: Container exits immediately after start**

Symptom: `docker ps` shows the container in `Exited` state seconds after `docker run`.

Diagnosis:
```bash
docker logs qasp-authority
```

Common causes:
- `ImportError: liboqs.so.0: cannot open shared object file` — The liboqs shared library is not found. In the Docker deployment this should not happen (ldconfig runs during build). If seen, rebuild the image: `docker build --no-cache --target dev -t qasp:dev .`
- `ModuleNotFoundError: No module named 'fastapi'` — The `run_server.sh` script installs `fastapi uvicorn httpx` at container startup with `pip install`. If the pip install step failed (network issue), fastapi is missing. Rebuild the image with fastapi pre-installed.
- `FileNotFoundError: scripts/qasp_server.py` — The scripts volume is not mounted or the mount path is wrong. Verify `-v /path/to/scripts:/app/scripts`.

**Failure 2: `oqs.MechanismNotEnabledError` on startup**

Symptom: Server crashes at `AuthorityState.__init__()` with an error about `ML-DSA-65` not being enabled.

Cause: The liboqs build did not include the ML-DSA algorithms. This can happen if the cmake configuration was incorrect or if an older version of liboqs was used (ML-DSA was added in liboqs 0.10.0 as a separate algorithm from Dilithium3).

Fix: Pin the liboqs clone to version 0.10.0 or later in the Dockerfile. Verify with:
```bash
docker run --rm qasp:dev -c "python -c \"import oqs; print([m for m in oqs.get_enabled_sig_mechanisms() if 'ML-DSA' in m])\""
```

**Failure 3: Reverse proxy returns 502 Bad Gateway**

Symptom: `curl https://authority.qasp.example.com/` returns HTTP 502.

Diagnosis:
```bash
# Check if the QASP container is running
docker ps --filter name=qasp-authority

# Check if port 8080 is listening
ss -tlnp | grep 8080

# Test the upstream directly (bypassing nginx)
curl http://127.0.0.1:8080/
```

Common causes:
- The QASP container is not running or has crashed (fix: restart the container)
- The container is running but bound to `0.0.0.0:8080` inside Docker but not published to the host (fix: add `-p 127.0.0.1:8080:8080`)
- nginx `proxy_pass` is pointing to the wrong address (fix: verify `proxy_pass http://127.0.0.1:8080;`)

**Failure 4: All authenticated endpoints return 401 after restart**

Symptom: Every call to `/discover`, `/tokens/request`, etc. returns `{"detail": "Invalid API key"}`.

Cause: The in-memory agent registry was cleared by a server restart. All registered agents' API keys are lost.

Fix: There is no quick fix short of agents re-registering. This is the expected behavior of the in-memory architecture. Implement keypair persistence (Section 7.2) and state checkpointing (Section 8.2) to prevent this.

**Failure 5: `POST /tools/call` returns 403 with "Signature verification failed"**

Symptom: A valid-looking capability token is rejected with a signature verification error.

Cause: The server restarted since the token was issued. The new server instance has a different ML-DSA-65 keypair and therefore cannot verify tokens signed by the old keypair.

Fix: Implement keypair persistence (Section 7.2) so the authority keypair survives restarts. Until then, agents must obtain new tokens after every server restart.

**Failure 6: `POST /tools/call` returns 403 with "Resource URI mismatch"**

Symptom: A capability token is rejected because the token's `resource_uri` does not match the tool's expected URI.

Cause: The token was issued for a different tool or a different agent's version of the same tool name. The ARM URI includes the first 12 characters of the DID (`did_short`), so even the same tool name on a different agent produces a different URI.

Fix: Verify the token was issued for the correct `target_did` and `tool_name` combination. The token's `resource_uri` and the tool's `resource_uri` must satisfy the ARM `uri_matches()` check.

**Failure 7: `POST /register` returns 500 Internal Server Error**

Symptom: Registration fails with a 500 error.

Diagnosis:
```bash
docker logs qasp-authority --tail 20
```

Common cause: `KeyGenerationError` from liboqs during `generate_keypair()`. This can occur if the liboqs library is in an inconsistent state (rare) or if memory is exhausted.

Fix: Check available memory on the host (`free -h`). If memory is low, increase the container's memory limit or scale up the host. If memory is adequate, restart the container and check for repeated failures.

**Failure 8: Extremely slow response on `POST /tokens/request`**

Symptom: Token request takes more than 2 seconds to respond.

Cause: ML-DSA-65 signing is computationally intensive. Under high concurrency (many simultaneous token requests), the single-process Uvicorn server serializes these operations on the asyncio event loop if they are not offloaded to a thread pool.

Fix: The `create_token()` call involves ML-DSA-65 signing, which is a blocking operation. For high-throughput environments, run Uvicorn with multiple workers (`uvicorn ... --workers 4`) or add `asyncio.get_event_loop().run_in_executor()` around the signing call. See Section 4.3 for worker configuration notes.

**Failure 9: `GET /tokens/status/{token_id}` returns `UNKNOWN` for a known token**

Symptom: OCSP check returns `UNKNOWN` status for a token ID that exists in the system.

Cause: The token was never registered in the CRL via `state.crl.register_token(token)` in the `request_token()` handler. This should not happen in the normal flow, but could occur if the server was patched or if the token was created outside the `/tokens/request` endpoint.

Fix: Ensure all capability tokens are issued exclusively through `POST /tokens/request`. Tokens created by other means will not be tracked in the CRL and will always return `UNKNOWN` from the OCSP endpoint.

**Failure 10: `POST /tools/call` returns 429 Rate Limit Exceeded immediately**

Symptom: The first tool call with a freshly issued token is immediately rate-limited.

Cause: This should not happen with a fresh token (the token bucket starts full). It can occur if the rate limiter registry is shared between a previous token with the same ID (extremely unlikely with UUIDs) or if the token was replayed from before a restart and the rate limiter state was not cleared.

Fix: Check if the token_id is being reused. If the server restarted since the token was issued, the rate limiter should be empty for that token_id. If the issue persists, check for token_id collisions in `state.tokens` and `state.rate_limiters`.

### 14.2 Runtime Errors

**`httpx.ConnectTimeout` in tool call relay logs**

The relay to a target agent's `callback_url` timed out after 30 seconds. The target agent is not responding within the timeout window.

Actions:
1. Verify the target agent's callback URL is reachable from the server: `curl -v {callback_url}/tools/{tool_name}`
2. Check the target agent's health
3. Consider reducing the relay timeout for latency-sensitive deployments

**`httpx.ConnectError` in tool call relay logs**

The relay connection was refused. The target agent's callback endpoint is down.

Actions:
1. Check if the target agent's callback service is running
2. Verify there are no firewall rules blocking outbound connections from the server to the agent callback network

**Memory growth over time**

Each registered agent accumulates metering records in `agent.metering` (an unbounded `list`). At high call volumes, this list grows indefinitely. Monitor `docker stats qasp-authority` for steadily increasing memory usage.

Fix: Add a periodic cleanup job that trims `agent.metering` to the last 1,000 entries per agent:

```python
async def cleanup_metering():
    while True:
        await asyncio.sleep(3600)  # Every hour
        for agent in state.agents_by_did.values():
            if len(agent.metering) > 1000:
                agent.metering = agent.metering[-1000:]
```

### 14.3 Performance Degradation

If you observe general latency increase across all endpoints:

1. Check CPU usage: `docker stats qasp-authority --no-stream`
2. Check if the event loop is blocked: enable `debug` log level and look for `Executing <Task>` taking > 100 ms
3. Check the number of registered agents: `curl http://127.0.0.1:8080/ | jq .agents_registered`. The `GET /discover` endpoint iterates all agents; at 10,000+ agents, this O(n) scan becomes noticeable.
4. Check outbound connectivity to agent callback URLs: slow DNS lookups or TCP connections to callback hosts can block relay workers

### 14.4 Debug Mode Usage

Enable debug logging to see detailed information about each request:

```bash
# For a running container
docker stop qasp-authority && docker rm qasp-authority
docker run -d --name qasp-authority \
  ... \
  qasp:dev \
  -c "python scripts/qasp_server.py --host 0.0.0.0 --port 8080 --log-level debug"
```

> **Warning:** Debug logging will include full request/response details. Do NOT use `--log-level debug` in production for extended periods — it exposes sensitive information in logs (token contents, agent names, DID values) and significantly increases log volume.

Use debug mode only during a maintenance window to diagnose a specific issue. Revert to `--log-level info` immediately after.

---

## Appendix A: Complete Configuration Reference

### A.1 Server CLI Arguments

| Argument | Default | Valid Values | Description |
|---|---|---|---|
| `--host` | `0.0.0.0` | Any IP address | Bind address for the Uvicorn server |
| `--port` | `8080` | 1–65535 | Bind port |
| `--log-level` | `info` | `debug`, `info`, `warning`, `error`, `critical` | Python logging level |

### A.2 Hardcoded Protocol Parameters

These values are hardcoded in `scripts/qasp_server.py` and in `qasp/crypto/signatures.py`. Changing them requires editing the source code and rebuilding the image.

| Parameter | Value | Location | Description |
|---|---|---|---|
| ML-DSA algorithm | `ML-DSA-65` | `qasp/crypto/signatures.py` | Post-quantum signature algorithm (FIPS 204, NIST Level 3) |
| Public key size | `1952 bytes` | `qasp/crypto/signatures.py` | ML-DSA-65 public key size |
| Secret key size | `4032 bytes` | `qasp/crypto/signatures.py` | ML-DSA-65 secret key size |
| Max signature size | `3309 bytes` | `qasp/crypto/signatures.py` | ML-DSA-65 maximum signature size |
| Token rate limit | `10 calls` | `scripts/qasp_server.py:367` | Calls per rate period per token |
| Token rate period | `60 seconds` | `scripts/qasp_server.py:367` | Rate limiting window |
| Token validity | `3600 seconds` | `scripts/qasp_server.py:369` | Token lifetime (1 hour) |
| Relay timeout | `30 seconds` | `scripts/qasp_server.py:491` | httpx timeout for callback relay |
| Metering cost | `10 credits` | `scripts/qasp_server.py:511` | Cost per tool call |
| Default verb | `exec` | `scripts/qasp_server.py:357` | Default ARM verb granted in tokens |

### A.3 Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PYTHONDONTWRITEBYTECODE` | `1` | Disable .pyc generation |
| `PYTHONUNBUFFERED` | `1` | Disable output buffering |
| `PIP_NO_CACHE_DIR` | `1` | Disable pip cache |
| `PIP_DISABLE_PIP_VERSION_CHECK` | `1` | Suppress pip version warnings |
| `QASP_KEYPAIR_DIR` | `/app/data/keypair` | Directory for persisted keypair (requires code change) |

### A.4 API Endpoint Reference Summary

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/` | None | Server info, DID, agent count |
| GET | `/features` | None | Feature list |
| POST | `/register` | None | Register agent, returns agent_id/did/api_key/public_key |
| GET | `/discover` | X-API-Key | Agent discovery, supports `?capability=&min_trust=` |
| POST | `/tokens/request` | X-API-Key | Issue capability token |
| POST | `/tokens/revoke` | X-API-Key | Revoke token by ID |
| GET | `/tokens/status/{token_id}` | None | OCSP status check |
| POST | `/tools/call` | X-API-Key | Verified tool call relay |
| GET | `/trust/{did}` | None | Trust score query |
| POST | `/trust/{did}/report` | X-API-Key | Report interaction outcome |
| POST | `/disputes/open` | X-API-Key | Open dispute |
| GET | `/disputes/{dispute_id}` | None | Dispute status |

---

## Appendix B: Complete systemd Unit File

Save to `/etc/systemd/system/qasp-authority.service`:

```ini
[Unit]
Description=QASP Authority Server
Documentation=https://github.com/your-org/qasp
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
# Service identity
User=qasp
Group=qasp
WorkingDirectory=/opt/qasp/src

# Runtime environment
Environment=PYTHONDONTWRITEBYTECODE=1
Environment=PYTHONUNBUFFERED=1
Environment=QASP_KEYPAIR_DIR=/opt/qasp/data/keypair

# Process execution
ExecStart=/opt/qasp/venv/bin/python scripts/qasp_server.py \
    --host 127.0.0.1 \
    --port 8080 \
    --log-level info

# Restart policy
Restart=on-failure
RestartSec=5s

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=qasp-authority

# Filesystem security
ReadWritePaths=/opt/qasp/data
ReadOnlyPaths=/opt/qasp/src

# Process security hardening
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RemoveIPC=true
LockPersonality=true
RestrictRealtime=true
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
CapabilityBoundingSet=

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096
MemoryMax=1G
CPUQuota=200%

# Timeouts
TimeoutStartSec=120
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
```

After creating the file:

```bash
sudo systemctl daemon-reload
sudo systemctl enable qasp-authority.service
sudo systemctl start qasp-authority.service
sudo journalctl -u qasp-authority -f
```

---

## Appendix C: Complete nginx Configuration

Save to `/etc/nginx/sites-available/qasp-authority`:

```nginx
# Rate limiting zones (defined at http block level)
# Include these in /etc/nginx/nginx.conf inside the http block,
# or in a separate file included by nginx.conf.
# limit_req_zone $binary_remote_addr zone=qasp_register:10m rate=5r/m;
# limit_req_zone $binary_remote_addr zone=qasp_global:10m rate=60r/m;

# HTTP -> HTTPS redirect
server {
    listen 80;
    listen [::]:80;
    server_name authority.qasp.example.com;

    # Allow Let's Encrypt ACME challenges
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    # Redirect all other traffic to HTTPS
    location / {
        return 301 https://$host$request_uri;
    }
}

# HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name authority.qasp.example.com;

    # TLS configuration
    ssl_certificate     /etc/letsencrypt/live/authority.qasp.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/authority.qasp.example.com/privkey.pem;
    ssl_trusted_certificate /etc/letsencrypt/live/authority.qasp.example.com/chain.pem;

    # TLS protocols and ciphers (Mozilla Intermediate compatibility, 2024)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;

    # OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 1.1.1.1 8.8.8.8 valid=300s;
    resolver_timeout 5s;

    # Diffie-Hellman parameters (generate once with: openssl dhparam -out /etc/nginx/dhparam.pem 4096)
    # ssl_dhparam /etc/nginx/dhparam.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'none'; frame-ancestors 'none'" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
    add_header Cache-Control "no-store" always;

    # Remove server header to avoid version disclosure
    server_tokens off;
    more_clear_headers Server;

    # Request size limit
    client_max_body_size 1m;
    client_body_timeout 30s;
    client_header_timeout 30s;

    # Proxy timeouts (must be longer than the relay timeout of 30s)
    proxy_connect_timeout 10s;
    proxy_send_timeout 40s;
    proxy_read_timeout 40s;

    # Access log
    access_log /var/log/nginx/qasp-authority-access.log combined;
    error_log  /var/log/nginx/qasp-authority-error.log warn;

    # === Rate limiting for registration endpoint ===
    # Uncomment after adding limit_req_zone to http block in nginx.conf
    # location /register {
    #     limit_req zone=qasp_register burst=3 nodelay;
    #     limit_req_status 429;
    #     include /etc/nginx/qasp-proxy.conf;
    # }

    # === Health check endpoint (for load balancer probes) ===
    location = /health {
        proxy_pass http://127.0.0.1:8080/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        access_log off;
    }

    # === Main proxy to QASP Authority Server ===
    location / {
        # Pass to upstream
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;

        # Standard proxy headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;

        # Disable buffering for streaming responses (if added in future)
        proxy_buffering off;
        proxy_request_buffering off;

        # Remove any X-Powered-By headers from upstream
        proxy_hide_header X-Powered-By;

        # Pass WebSocket upgrades (for future WebSocket support)
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # === Deny access to internal paths ===
    location ~ ^/internal/ {
        return 404;
    }

    # === Deny access to dotfiles ===
    location ~ /\. {
        deny all;
        return 404;
    }
}
```

After saving, validate and reload:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

---

## Appendix D: Docker Compose Production Template

Save to `/opt/qasp/docker-compose.production.yml`:

```yaml
---
version: "3.9"

# Production Docker Compose configuration for QASP Authority Server
# Usage: docker compose -f docker-compose.production.yml up -d

services:
  # ============================================================
  # QASP Authority Server
  # ============================================================
  qasp-authority:
    image: qasp:dev
    build:
      context: .
      target: dev
    container_name: qasp-authority
    restart: unless-stopped
    entrypoint: ["/bin/bash"]
    command:
      - "-c"
      - >
        python scripts/qasp_server.py
        --host 0.0.0.0
        --port 8080
        --log-level ${QASP_LOG_LEVEL:-info}

    # Expose only on loopback (nginx handles external access)
    ports:
      - "127.0.0.1:8080:8080"

    # Persistent volumes
    volumes:
      - keypair_data:/app/data/keypair
      - log_data:/app/logs
      - ./scripts:/app/scripts:ro

    # Environment
    environment:
      PYTHONDONTWRITEBYTECODE: "1"
      PYTHONUNBUFFERED: "1"
      QASP_KEYPAIR_DIR: /app/data/keypair
      QASP_LOG_LEVEL: ${QASP_LOG_LEVEL:-info}

    # Resource limits
    deploy:
      resources:
        limits:
          cpus: "2.0"
          memory: 1G
        reservations:
          cpus: "0.5"
          memory: 512M

    # Health check
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s

    # Security options
    security_opt:
      - no-new-privileges:true

    # Logging
    logging:
      driver: json-file
      options:
        max-size: "100m"
        max-file: "10"
        labels: "service,env"

    labels:
      service: "qasp-authority"
      env: "production"

    networks:
      - qasp-internal

  # ============================================================
  # nginx Reverse Proxy (TLS Termination)
  # ============================================================
  nginx:
    image: nginx:1.26-alpine
    container_name: qasp-nginx
    restart: unless-stopped

    ports:
      - "80:80"
      - "443:443"

    volumes:
      - ./config/nginx/qasp-authority.conf:/etc/nginx/sites-enabled/qasp-authority.conf:ro
      - /etc/letsencrypt:/etc/letsencrypt:ro
      - /var/www/certbot:/var/www/certbot:ro
      - nginx_logs:/var/log/nginx

    depends_on:
      qasp-authority:
        condition: service_healthy

    healthcheck:
      test: ["CMD", "nginx", "-t"]
      interval: 60s
      timeout: 10s
      retries: 3

    logging:
      driver: json-file
      options:
        max-size: "100m"
        max-file: "10"

    networks:
      - qasp-internal
      - qasp-external

  # ============================================================
  # Certbot (Certificate Renewal)
  # ============================================================
  certbot:
    image: certbot/certbot:latest
    container_name: qasp-certbot
    restart: unless-stopped
    volumes:
      - /etc/letsencrypt:/etc/letsencrypt
      - /var/www/certbot:/var/www/certbot
    entrypoint: "/bin/sh -c 'trap exit TERM; while :; do certbot renew --quiet; sleep 12h & wait $${!}; done;'"
    networks:
      - qasp-external

# ============================================================
# Networks
# ============================================================
networks:
  qasp-internal:
    driver: bridge
    internal: true  # No direct internet access for internal network

  qasp-external:
    driver: bridge

# ============================================================
# Volumes
# ============================================================
volumes:
  keypair_data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /opt/qasp/data/keypair

  log_data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /opt/qasp/data/logs

  nginx_logs:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /opt/qasp/data/nginx-logs
```

Usage:

```bash
# Create required host directories
mkdir -p /opt/qasp/data/{keypair,logs,nginx-logs}
mkdir -p /opt/qasp/config/nginx

# Copy nginx config
cp /opt/qasp/docs/nginx-config.conf /opt/qasp/config/nginx/qasp-authority.conf

# Start all services
docker compose -f docker-compose.production.yml up -d

# Check status
docker compose -f docker-compose.production.yml ps

# View logs
docker compose -f docker-compose.production.yml logs -f qasp-authority

# Stop all services
docker compose -f docker-compose.production.yml down
```

---

## Appendix E: Runbook Quick Reference Card

This page is designed to be printed or bookmarked as a one-page reference for on-call engineers.

---

### QASP Authority Server — On-Call Quick Reference

**Service:** `qasp-authority` container on `authority.qasp.example.com:443`
**Health endpoint:** `https://authority.qasp.example.com/` (GET, no auth)
**Internal endpoint:** `http://127.0.0.1:8080/` (from server host)

---

**CHECK: Is the server up?**
```bash
curl -sf https://authority.qasp.example.com/ | jq .did
docker ps --filter name=qasp-authority --format "{{.Status}}"
```

**CHECK: How many agents are registered?**
```bash
curl -sf http://127.0.0.1:8080/ | jq .agents_registered
```

**CHECK: Container health status**
```bash
docker inspect --format='{{.State.Health.Status}}' qasp-authority
```

**CHECK: Recent logs (last 50 lines)**
```bash
docker logs qasp-authority --tail 50
```

**ACTION: Restart the container**

> Warning: All in-memory state is lost. All registered agents must re-register.
```bash
docker restart qasp-authority
sleep 10
curl -sf http://127.0.0.1:8080/ | jq .did
```

**ACTION: Stop the container cleanly**
```bash
docker stop --time 30 qasp-authority
```

**ACTION: Start the container (after stop)**
```bash
docker start qasp-authority
```

**ACTION: View startup errors**
```bash
docker logs qasp-authority 2>&1 | head -30
```

**ACTION: Reload nginx (after config change)**
```bash
sudo nginx -t && sudo systemctl reload nginx
```

**ACTION: Check TLS certificate expiry**
```bash
echo | openssl s_client -servername authority.qasp.example.com \
  -connect authority.qasp.example.com:443 2>/dev/null \
  | openssl x509 -noout -dates
```

**ACTION: Check disk space**
```bash
df -h /opt/qasp
docker system df
```

**ACTION: Emergency key rotation (breaks all existing agent sessions)**

> Warning: All existing tokens become invalid. All agents must re-register.
```bash
docker stop qasp-authority
cp -r /opt/qasp/data/keypair /opt/qasp/data/keypair-backup-$(date +%Y%m%d-%H%M%S)
rm /opt/qasp/data/keypair/authority.{pub,sec}
docker start qasp-authority
curl -sf http://127.0.0.1:8080/ | jq .did  # New DID
```

**ACTION: Test registration**
```bash
curl -sf -X POST http://127.0.0.1:8080/register \
  -H "Content-Type: application/json" \
  -d '{"name":"smoke-test"}' | jq .api_key
```

**ACTION: Check the authority DID**
```bash
curl -sf http://127.0.0.1:8080/ | jq -r .did
```

---

**Key file locations**

| Item | Path |
|---|---|
| Authority keypair | `/opt/qasp/data/keypair/` |
| Server logs (Docker) | `docker logs qasp-authority` |
| Server logs (bare metal) | `journalctl -u qasp-authority` |
| nginx config | `/etc/nginx/sites-available/qasp-authority` |
| nginx logs | `/var/log/nginx/qasp-authority-*.log` |
| Docker Compose file | `/opt/qasp/docker-compose.production.yml` |
| Keypair backup | `/opt/qasp/data/keypair-backup-*/` |

**Escalation**

- L1 (on-call): Restart container, check logs, verify DNS/TLS
- L2 (SRE): Investigate CRL loss, state inconsistency, performance issues
- L3 (Platform Engineering): Key rotation, architecture changes, liboqs issues

---

*QASP Authority Server Deployment Guide v1.0.0 — 2026-03-10*
