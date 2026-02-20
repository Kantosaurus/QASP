# QASP: 6-Week Build Plan (5 People)

## Team Roles

| Person | Role | Focus |
|--------|------|-------|
| **P1** | Crypto Lead | PQ crypto layer, handshake, key management |
| **P2** | Protocol Engineer | State machine, CBOR framing, message flow |
| **P3** | Trust & Identity | Trust scoring engine, DIDs, Verifiable Credentials |
| **P4** | Transport & Discovery | TCP/QUIC transport, QASP-Discover, bridges |
| **P5** | Integration & Testing | Conformance tests, demo scenarios, docs, CI/CD |

---

## Week 1 — Scaffolding + Crypto Foundation

**Goal:** Repo structure, CI pipeline, and a validated PQ crypto module that everyone else can build on.

### P1 — Crypto Layer
- Set up `src/qasp/crypto/` module
- Implement ML-KEM-768 wrapper using `oqs-python` (liboqs 0.15.0)
  - `kem.py`: keygen, encapsulate, decapsulate with context managers for key zeroization
- Implement ML-DSA-65 wrapper
  - `signatures.py`: keygen, sign, verify
- Implement hybrid mode
  - `hybrid.py`: X25519 (via `cryptography` lib) + ML-KEM-768 combined KEM
  - `kdf.py`: HKDF-SHA-384 key derivation — `SS = HKDF(ML-KEM_ss ∥ X25519_ss, nonces, "QASP-v1")`
- Implement `aead.py`: AES-256-GCM encryption/decryption using session keys
- Validate all primitives against **NIST ACVP Known Answer Test vectors** (75 KeyGen, 75 Encaps, 30 Decaps for ML-KEM; 75 KeyGen, 420 SigGen, 180 SigVer for ML-DSA)

### P2 — Protocol Skeleton
- Set up `src/qasp/protocol/` with sans-I/O architecture:
  ```
  connection.py   — main QASPConnection class (no socket references)
  states.py       — protocol state enum (IDLE → HELLO_SENT → AUTHENTICATED → ESTABLISHED → CLOSED → ERROR)
  events.py       — typed event classes (HandshakeComplete, DataReceived, TokenIssued, etc.)
  ```
- Define all QASP message type IDs (Table IV from the paper: 0x01–0x14)
- Implement CBOR message framing in `src/qasp/framing/`:
  - `codec.py`: encode/decode using `cbor2`, binary frame = magic (0x5141) + version + type + length + payload + HMAC-SHA-384
  - `messages.py`: Python dataclasses for each message type

### P3 — Identity Skeleton
- Set up `src/qasp/identity/` and `src/qasp/trust/`
- Implement `did.py`: `did:qasp` identifier generation — `did:qasp:<base58btc(SHA-384(ML-DSA-65-PK)[0:32])>`
- Build DID Document creation following W3C DID Core spec (JSON-LD structure with `MLDSAVerificationKey2025` type)
- Implement X.509-PQ certificate profile in `src/qasp/crypto/certificates.py` using ML-DSA-65 OID `2.16.840.1.101.3.4.3.18`
- Define owner-binding: owner signs `⟨agent_did, owner_did, permissions, expiry⟩`

### P4 — Transport Skeleton
- Set up `src/qasp/transport/`
- Implement `tcp.py`: asyncio TCP client/server wrapping the sans-I/O protocol core
- Set up basic connection lifecycle: connect → exchange bytes → close
- Stub `discover.py` interface for QASP-Discover

### P5 — Project Infrastructure
- Initialize repo: `pyproject.toml`, dependency management, `src/` layout
- Configure GitHub Actions CI:
  - Linting: `ruff` + `mypy` (strict) + `bandit`
  - Tests: `pytest` across Python 3.12/3.13
  - Dependency audit: `pip-audit`
- Set up `tests/` structure mirroring `src/`
- Write initial property-based tests with Hypothesis for CBOR roundtrips
- Create `SECURITY.md`, `CONTRIBUTING.md`, `LICENSE` (Apache 2.0)
- Set up development environment documentation

### Week 1 Checkpoint
✅ `pip install -e .` works  
✅ ML-KEM-768 + ML-DSA-65 passing ACVP test vectors  
✅ Hybrid KEM producing shared secrets  
✅ CBOR encoding/decoding all 20 message types  
✅ Basic TCP echo server running  
✅ CI pipeline green  

---

## Week 2 — Handshake + Capability Tokens

**Goal:** Two agents can complete a PQ-authenticated handshake and issue/verify capability tokens.

### P1 — QASP-Shake Handshake
- Implement the 3-message handshake in `protocol/handshake.py`:
  1. **ClientHello** → protocol version, ML-KEM-768 encapsulation key, cipher suites, client nonce, (optional X25519 PK)
  2. **ServerHello** → selected suite, ML-KEM-768 ciphertext, server nonce, server cert/DID, ML-DSA-65 signature over transcript
  3. **ClientAuth** → client cert/DID, ML-DSA-65 signature over transcript
- Implement key derivation: `SS = HKDF(ML-KEM_ss ∥ X25519_ss, Nc ∥ Ns, "QASP-v1")`
- Wire handshake into `connection.py` state machine (Table III from paper: 8 states, 14 transitions)
- Handle error cases: VERSION_MISMATCH, SUITE_MISMATCH, AUTH_FAILED, timeout with exponential backoff

### P2 — Capability Token Engine
- Implement `protocol/capability.py`:
  - Token structure: CBOR-encoded, ML-DSA-65 signed, containing issuer/subject/audience DIDs, ARM resource URI, verb set, constraints (time, quantity, rate, spend, data-scope, purpose), parent ref, delegation chain
  - Token creation: owner issues token to agent with specified scope
  - Token verification: check signature, expiry, constraint compliance
  - **Attenuation**: `att(T, Δ)` produces T' where `V_T' ⊆ V_T` and every constraint is tighter
  - **Splitting**: partition quantity constraints (e.g., 2 vCPU-h → 1 + 1 vCPU-h)
- Implement delegation chain verification: walk the chain, verify aggregate attenuation is monotonically decreasing, check `maxDelegationDepth`

### P3 — Trust Scoring: Pillar 1 (Audit Certification)
- Define `qasp-audit-v1` Verifiable Credential schema (W3C VC Data Model v2.0):
  - Fields: agent DID, audit scope, code version hash, audit result, SLSA level (1–3), auditor DID, expiry
  - ML-DSA-65 proof signature
- Implement `trust/certification.py`: VC issuance and verification
- Implement `trust/registry.py`: in-memory trust registry storing DIDs, VCs, and trust scores

### P4 — Transport Integration
- Wire TCP transport to handshake: full ClientHello → ServerHello → ClientAuth flow over the wire
- Implement encrypted data exchange post-handshake (AES-256-GCM with session key)
- Add connection multiplexing support for concurrent capability streams

### P5 — Handshake Test Suite
- Write integration tests for the full handshake:
  - Happy path: mutual auth succeeds, session key derived
  - Version mismatch → Alert → retry
  - Invalid signature → AUTH_FAILED
  - Timeout → exponential backoff
- Write unit tests for token creation, attenuation, splitting, chain verification
- Property-based tests: `att(T, Δ)` always produces `T' ⪯ T` (Hypothesis)
- Fuzz CBOR message parsing with Atheris

### Week 2 Checkpoint
✅ Two agents complete a PQ handshake over TCP  
✅ Encrypted messages exchanged post-handshake  
✅ Capability tokens: create, sign, verify, attenuate, split  
✅ Delegation chain up to depth 3 verified correctly  
✅ Audit VCs issued and verified  

---

## Week 3 — Trust Scoring Engine + Metering

**Goal:** The full three-pillar trust system is operational, and resource usage is tracked with signed receipts.

### P1 — Metering & Receipts
- Implement `protocol/accounting.py`:
  - `MeterReport` (server → agent): cumulative units consumed, cost, ML-DSA-65 signature
  - `MeterAck` (agent → server): counter-signature
  - Hash-chained receipts: each receipt includes `prev_hash = SHA-384(previous_receipt)` — tampering breaks the chain
  - `ResourceSuspend` when constraints exceeded
- Implement the Request-Grant-Revoke flow: ResourceRequest → ResourceGrant/ResourceDeny → MeterReport/MeterAck → ResourceRelease

### P2 — Revocation System
- Implement token revocation in `protocol/capability.py`:
  - `TokenRevocation` (0x05): owner/server broadcasts revocation
  - `RevocationNotice` (0x06): cascading notification
  - Revocation cascade: revoking any token revokes ALL descendants in the delegation chain
  - Three urgency levels: `critical` (immediate), `normal` (5-min grace), `planned` (scheduled)
- Build in-memory CRL (Certificate Revocation List) for the reference implementation

### P3 — Trust Scoring: Pillar 2 & 3
- **Pillar 2 — Bayesian Reputation** (`trust/reputation.py`):
  - Beta Reputation System: model trust as Beta(α, β), expected value = α/(α+β)
  - Update rule: successful interaction → α+1, failed → β+1
  - Time decay: λ(t) = e^(−δ·Δt) weighting recent interactions more
  - Witness aggregation: TRAVOS credibility filtering — weight third-party reports by demonstrated historical accuracy
- **Pillar 3 — Behavioral Verification** (`trust/behavioral.py`):
  - Signed Capability Manifest: agent publishes declared behaviors, signed with ML-DSA-65
  - FSM conformance engine: define permitted behavior as a finite state machine, flag unpermitted transitions
  - Rolling compliance score: (permitted_actions / total_actions) over sliding window, 10× penalty for severe violations
- **Composite score** (`trust/scoring.py`):
  ```
  T(agent) = 0.35 × T_interaction + 0.25 × T_witness + 0.20 × T_certified + 0.20 × T_behavioral
  ```
  - Cold-start handling: new agents with SLSA Level 3 audit cert enter with meaningful initial trust
  - Anti-gaming: monotonically increasing cooperation requirements, cluster-based collusion detection

### P4 — QASP-Discover Service
- Implement `transport/discover.py`:
  - Well-known endpoint: agents publish at `/.well-known/qasp-agent.json`
  - DNS-SD/mDNS for local network discovery (service type `_qasp._tcp`)
  - PQ-signed Capability Advertisement: CBOR-encoded structure with agent DID, endpoints, ARM capabilities, TTL, ML-DSA-65 signature
- Discovery-to-handshake pipeline: verify ad signature → extract DID → check capabilities → initiate QASP-Shake

### P5 — Trust + Metering Tests
- Integration test: two agents interact, reputation updates correctly after each interaction
- Test cold-start: new agent with audit VC gets boosted trust score
- Test behavioral violation: agent exceeds declared capabilities → compliance score drops → trust score penalized
- Test metering: resource consumption tracked, receipt chain validated, budget exhaustion triggers suspend
- Test revocation cascade: revoke root token → all descendants invalidated across servers

### Week 3 Checkpoint
✅ Full trust scoring engine: audit VCs + Bayesian reputation + behavioral FSM  
✅ Composite trust score computed and updated in real-time  
✅ Metered resource accounting with hash-chained dual-signed receipts  
✅ Token revocation with cascade propagation  
✅ Service discovery via well-known endpoint and mDNS  

---

## Week 4 — Interoperability Bridges + Economic Layer

**Goal:** QASP agents can interoperate with MCP and A2A ecosystems, and payments work.

### P1 — Payment Channels (QASP-Settle)
- Implement `protocol/settlement.py`:
  - **Price negotiation**: PriceRequest → PriceOffer → PriceAccept, signed price schedule embedded in token
  - **Payment channels**: bidirectional Lightning-style channels
    - Channel Open (0x11): both parties commit initial balances
    - Off-chain updates: co-signed state increments `Si = ⟨agent_balance − Σcost, server_balance + Σcost⟩`
    - Channel Close (0x12): latest co-signed state submitted, 1-hour challenge period
    - Unilateral close: timeout fallback for unresponsive parties
  - All state updates ML-DSA-65 signed + hash-chained to receipt chain

### P2 — Dispute Resolution
- Implement dispute protocol:
  - `DisputeOpen` (0x0D): submit contested receipt range + local receipt chain to Auditor
  - `DisputeEvidence` (0x0E): both parties submit receipt chains and replayable traces
  - `DisputeVerdict` (0x0F): Auditor replays traces, issues binding verdict with payment adjustment
- Implement the Auditor as a standalone service that verifies receipt chains and token constraints

### P3 — MCP Bridge
- Implement `bridges/mcp_bridge.py` (using `mcp` Python SDK v1.26.0):
  - **QASP → MCP**: Expose QASP agent capabilities as MCP tools. On `tools/call`, verify QASP capability token, execute, return result
  - **MCP → QASP**: Wrap MCP servers as QASP agents. Auto-generate QASP DID and capability tokens from MCP tool declarations
  - Token injection via MCP `_meta` field: `{"qasp_token_id": "...", "qasp_token": "<base64 CBOR>"}`
  - Authorization mapping: OAuth scope → ARM resource URI + verb set, client credentials → Agent DID + ML-DSA-65

### P4 — A2A Bridge
- Implement `bridges/a2a_bridge.py` (using `a2a-python` SDK):
  - **Agent Card ↔ QASP DID**: translate A2A skills to QASP capability declarations
  - **Task ↔ Session**: map A2A task lifecycle (submitted → working → completed) to QASP session states
  - A2A `qasp` extension section in Agent Cards: agent DID, QASP endpoint, supported cipher suites
  - Delegation mapping: A2A sub-task delegation → QASP token attenuation for the delegate

### P5 — Bridge Integration Tests
- MCP bridge test: MCP client → QASP-secured channel → MCP server, capability token enforced on each `tools/call`
- A2A bridge test: A2A Agent Card discovery → QASP-Shake upgrade → task execution with PQ auth
- Cross-protocol test: A2A agent delegates to MCP tool via QASP, full delegation chain verified
- Payment test: agent consumes resources, micropayments settled via payment channel

### Week 4 Checkpoint
✅ MCP bridge: QASP agents accessible as MCP servers and vice versa  
✅ A2A bridge: QASP agents discoverable via Agent Cards, tasks flow through QASP  
✅ Payment channels operational with signed state updates  
✅ Dispute resolution Auditor service working  

---

## Week 5 — Demo Scenarios + Security Hardening

**Goal:** All four paper demo scenarios working end-to-end, security gaps closed.

### P1 — Crypto Agility + Downgrade Resistance
- Implement cipher suite negotiation with mandatory downgrade resistance:
  - Suite registry with 16-bit IDs: `PQ-Strict` (ML-KEM-768 + ML-DSA-65), `Hybrid-Transition` (+ X25519 + Ed25519), `Classical-Compat` (X25519 + Ed25519 only)
  - Server MUST reject if it supports PQ but client advertises only classical → `UPGRADE_REQUIRED`
  - Selected suite ID included in transcript hash — any downgrade attempt is detected by signature
- Implement key rotation for DID Documents: pre-committed next-key hash, dual-signature rotation

### P2 — Tool-Chaining Security
- Implement capability firebreaks in `protocol/capability.py`:
  - Capabilities are non-transitive across tool boundaries by default
  - Sub-invocations require fresh attenuated token from the originating agent
  - `purpose` binding: structured label that servers MAY enforce (e.g., "data-analysis", "model-training")
  - `allowed_toolchain`: ordered list of tool/service classes the token may traverse
- Implement multi-owner tokens with `authority_chains` array — all chains must validate, constraints intersected

### P3 — Demo: Scenarios 1 & 2
- **Scenario 1 (Direct Resource Request)**:
  - Owner Alice creates Agent Alpha with ML-DSA-65 keys and did:qasp
  - Alpha discovers Server Beta via QASP-Discover
  - QASP-Shake handshake → pricing negotiation → capability token issued
  - Alpha uses resource with periodic metering + micropayment settlement
  - Release with final usage summary and receipt chain
- **Scenario 2 (Delegation Chain)**:
  - Alpha holds token T0 from Scenario 1
  - Alpha creates sub-agent Gamma, delegates T1 = att(T0, Δ) — fewer hours, lower spend
  - Gamma connects to Server Beta, presents full chain, uses resource metered against T1

### P4 — Demo: Scenarios 3 & 4
- **Scenario 3 (Tool-Chain with Firebreak)**:
  - Alpha invokes Tool 1 on Server Beta
  - Needs to chain into Tool 2 on Server Gamma
  - Alpha re-mints attenuated, purpose-bound token T' for Tool 2
  - Demonstrates capability firebreaks and context binding
- **Scenario 4 (MCP-over-QASP)**:
  - MCP client connects to MCP server via QASP-Shake
  - Each `tools/call` wrapped in QASP capability token
  - Full authorization, metering, and PQ encryption on MCP traffic

### P5 — Security Test Suite
- Test downgrade resistance: MITM attempts to force Classical-Compat → detected via transcript hash
- Test token replay: resubmit a used token → rejected via server-side token-use log
- Test privilege escalation: attempt to widen delegation → algebraically impossible, verified
- Test MITM on handshake: modify any handshake message → transcript signature fails
- Test metering fraud: tamper with receipt → hash chain broken → detectable
- Performance benchmarks: handshake latency, token create/verify time, delegation chain depth vs. verification time

### Week 5 Checkpoint
✅ All 4 demo scenarios running end-to-end  
✅ Downgrade resistance enforced  
✅ Tool-chaining firebreaks working  
✅ Security test suite passing  
✅ Performance benchmarks documented  

---

## Week 6 — Formal Verification + Documentation + Release

**Goal:** Formal security models, complete documentation, and a tagged v0.1.0 release.

### P1 — Formal Verification: Handshake
- Model QASP-Shake in **ProVerif** (applied pi-calculus):
  - ML-KEM as custom function symbols: `kempk()`, `kemencaps()`, `kemdecaps()` equational theories
  - Verify: mutual authentication (injective agreement), session key secrecy, forward secrecy
  - This typically runs in minutes and has caught real bugs in Signal's PQXDH
- Begin **Tamarin** model for capability delegation properties:
  - Encode token algebra as multiset rewriting rules
  - Verify: no escalation (∀ chain, T' ⪯ T_root)

### P2 — Protocol Specification Document
- Write the formal spec using RFC 2119 language (MUST, SHOULD, MAY):
  - CDDL schemas for all message types and token structures
  - ABNF grammar for ARM resource URIs
  - State machine diagrams for QASP-Shake (8 states, 14 transitions), token verification (5 states, 8 transitions), payment channel (4 states, 6 transitions)
  - Error code table with recovery procedures (Table V)
  - Complete cipher suite registry

### P3 — Trust Scoring Specification + DID Method Spec
- Formalize the trust scoring algorithm: equations, weights, update rules, anti-gaming measures
- Write `did:qasp` method specification following W3C DID method registry requirements:
  - Method syntax, CRUD operations, security considerations, privacy considerations
  - Resolution: direct exchange in handshake → QASP-Discover → DHT/VDR fallback
- Document VC schema for audit attestation

### P4 — Packaging + Examples
- Package for PyPI: `qasp` with extras (`pip install qasp[quic,bridges]`)
- Signed releases via sigstore/cosign
- Create `examples/` directory:
  - `basic_handshake.py` — two agents connect and authenticate
  - `delegation_chain.py` — owner → agent → sub-agent delegation
  - `mcp_bridge_demo.py` — MCP tool call over QASP
  - `trust_scoring_demo.py` — reputation evolution over multiple interactions
- Write README with architecture diagram, quickstart, and API overview

### P5 — Conformance Tests + Release
- Build conformance test suite:
  - Handshake: success/failure per cipher suite profile, version mismatch, timeout recovery
  - Tokens: creation, attenuation, splitting, aggregation, temporal evolution
  - Receipts: chain validation, dispute replay
  - Revocation: cascade across multiple servers
  - Discovery: advertisement verification, discovery-to-handshake pipeline
  - Bridges: MCP-over-QASP and A2A-over-QASP interop
- Docker-based test harness: two independent instances run conformance suite against each other
- Generate test coverage report (target: >85% on crypto + protocol layers)
- Tag `v0.1.0`, push to PyPI, publish documentation

### Week 6 Checkpoint
✅ ProVerif model verifying authentication, secrecy, forward secrecy  
✅ Tamarin model verifying delegation safety  
✅ Complete protocol specification document  
✅ did:qasp method specification  
✅ Trust scoring specification  
✅ PyPI package published  
✅ Conformance test suite with Docker harness  
✅ All 4 demo scenarios as runnable examples  

---

## Dependencies & Setup (Day 1)

```bash
# Core
pip install liboqs-python cryptography cbor2 hypothesis atheris

# Transport
pip install aioquic  # QUIC support

# Bridges
pip install mcp a2a-python

# Dev tools
pip install ruff mypy bandit pytest pytest-asyncio
```

---

## Risk Mitigation

| Risk | Mitigation |
|------|-----------|
| liboqs build issues on team machines | Provide a Docker dev container with pre-built liboqs |
| CBOR/ML-DSA signature sizes cause bandwidth issues | CBOR already compact; add token ID caching for repeat requests |
| Trust scoring tuning takes too long | Ship with sensible defaults (w_i=0.35, w_w=0.25, w_c=0.20, w_b=0.20), make configurable |
| Formal verification tools have steep learning curve | P1 focuses only on ProVerif (simpler); Tamarin as stretch goal |
| Bridge SDKs may have breaking changes | Pin exact versions in pyproject.toml, vendor if needed |
| Scope creep | Each week has a hard checkpoint — features not passing tests by Friday get cut |

---

## Weekly Standup Schedule

- **Monday**: 30-min planning — each person states their 3 top deliverables for the week
- **Wednesday**: 30-min sync — flag blockers, adjust if someone is ahead/behind
- **Friday**: 1-hour checkpoint — run test suite together, demo what works, tag weekly build
