# QASP Rust Migration Plan

**Status:** Draft for management review  
**Prepared:** 2026-05-25  
**Scope:** Migration of the Python QASP library, authority service, clients, bridges,
tests, deployment artifacts, and examples to Rust without breaking protocol or API
compatibility.

## 1. Executive Summary

QASP should be migrated incrementally, with the Python implementation retained as
the compatibility oracle until Rust passes bidirectional interoperability tests.
This is a security protocol and service migration, not a syntax translation:
signed byte encodings, handshake transcripts, capability attenuation rules,
revocation behavior, persisted authority state, HTTP/WebSocket APIs, and external
bridge behavior are the product contracts.

The recommended route is:

1. Freeze and reconcile the existing contracts before writing production Rust.
2. Establish a Rust workspace and Python/Rust interoperability harness.
3. Port foundational cryptography and wire encoding first.
4. Port identity, capability authorization, revocation, and trust primitives.
5. Deliver a Rust authority server that remains compatible with existing agents.
6. Port the sans-I/O protocol, transports, relay, and advanced protocol features.
7. Port MCP/A2A bridges, the client SDK, scripts, examples, and operations.
8. Cut traffic over gradually and retire Python only after rollback windows pass.

With a dedicated team of three Rust-capable engineers plus security review support,
the initial estimate is 8 to 11 two-week sprints for complete feature parity and
controlled cutover. The estimate should be re-baselined after Phase 0 exposes the
true protocol and test baseline.

## 2. Migration Objectives

### Goals

- Produce a memory-safe Rust implementation of the complete QASP surface.
- Preserve current agent interoperability throughout the migration.
- Maintain ML-KEM-768, ML-DSA-65, X25519, Ed25519, AES-256-GCM, HKDF, and
  SHA/HMAC behavior at the byte-contract level.
- Preserve or explicitly version HTTP, WebSocket, CBOR, frame, token, DID, and
  persistent-data contracts.
- Improve deployment reliability through explicit key and state persistence.
- Make conformance, security, fuzz, and benchmark suites release gates.

### Non-goals During Parity Delivery

- Redesigning the protocol while porting it.
- Replacing post-quantum algorithms or parameters without a separately approved
  cryptographic change proposal.
- Breaking the Python client or currently integrated agents to simplify Rust code.
- Replacing SQLite or changing API semantics before a versioned compatibility
  decision is approved.

## 3. Current System Inventory

The present repository is a Python 3.12 implementation with approximately 31,860
lines in `src/qasp/`, 6,566 lines in scripts/examples, and a large pytest suite
covering cryptography, protocol behavior, identity, transports, trust, bridges,
security, conformance, and integration behavior.

| Domain | Current Source | Responsibility | Migration Risk |
| --- | --- | --- | --- |
| Cryptographic foundation | `src/qasp/crypto/` | PQ and hybrid keys, signatures, AEAD, KDF, certificates, Merkle/Pedersen/Bulletproofs, threshold/DKG | Critical |
| Wire format | `src/qasp/framing/` | CBOR payloads, frame header, message registry, HMAC protection | Critical |
| Identity | `src/qasp/identity/` | `did:qasp`, DID documents, resolution, rotation, bindings, groups, SPIFFE | High |
| Authorization | `src/qasp/protocol/capability.py`, `arm.py`, `revocation.py`, `ocsp.py` | Capability tokens, constraints, attenuation, delegation, ARM matching, revocation | Critical |
| Secure protocol | `src/qasp/protocol/handshake.py`, `connection.py`, `states.py`, `events.py`, `stream.py` | QASP-Shake and sans-I/O secure connections | Critical |
| Economic/audit features | `src/qasp/protocol/` and `src/qasp/auditor/` | Metering, accounting, privacy, reconciliation, settlement, disputes, audit | High |
| Advanced delegation | `src/qasp/protocol/` | Aggregation, threshold delegation, cross-domain, SPIFFE attestation, selective/zero-knowledge disclosure | High |
| Relay | `src/qasp/protocol/relay/` | CapFlow sessions, SCM, forwarded data, receipt chains and metering | High |
| Network transport/discovery | `src/qasp/transport/` | TCP, QUIC, discovery, registry advertisements | High |
| Trust | `src/qasp/trust/` | Reputation, behavioral scoring, certification and trust registry | Medium/High |
| Bridges | `src/qasp/bridges/` | MCP and A2A adaptation | Medium/High |
| Authority application | `scripts/qasp_server.py` | REST/WebSocket authority, registration, token issuance, calls, messaging, admin, SQLite partial persistence | Critical |
| Client/tooling | `scripts/qasp_client.py`, other scripts, `examples/` | REST/WebSocket use, demos, benchmark tooling | Medium |
| Verification | `tests/`, `formal/` | Unit, integration, conformance, security, fuzz/property tests and formal models | Critical |

### Authority Surface That Must Be Preserved

The authority server currently exposes:

- Service and registration: `/`, `/features`, `/metrics`, `/register`,
  `/unregister`, `/agents/update`, `/discover`.
- Token and invocation: `/tokens/request`, `/tokens/revoke`,
  `/tokens/status/{token_id}`, `/tools/call`.
- Trust and disputes: `/trust/{did}`, `/trust/{did}/report`,
  `/disputes/open`, `/disputes/{dispute_id}`.
- Messaging: `/conversations/open`, `/messages/send`, `/conversations`,
  `/conversations/{conversation_id}/messages`,
  `/conversations/{conversation_id}/transcript`,
  `/conversations/{conversation_id}/close`, `/messages/inbox`,
  `/messages/acknowledge`.
- Live connections: `/ws`, `/ws/register`.
- Administration: `/admin/agents`, metering, receipts, tokens, token history,
  and disputes routes.

### Current Persistence Boundary

The authority server uses SQLite tables for metering records, token events,
disputes, conversations, messages, relay sessions, and relay receipts. Important
authority state remains in process memory, including authority key generation at
startup, registered agents, issued token objects, CRL state, rate limiters, and
default trust registries. Migration cannot claim operational equivalence without
an explicit decision on restart and multi-instance behavior.

## 4. Phase 0 Findings Requiring Decisions

These are not reasons to delay migration. They are contracts that must be settled
before Rust becomes authoritative.

| Finding | Why It Matters | Required Phase 0 Decision |
| --- | --- | --- |
| The protocol draft documents 22 message types, but Python framing includes additional codes through relay messages at `0x26`. | Rust may implement the wrong registry or reject live messages. | Reconcile the spec with executable behavior and publish the authoritative v1 registry. |
| Signed CBOR payloads are emitted with `cbor2.dumps()` and deterministic field construction, but no explicit canonical encoding rule is declared in key token paths. | A different Rust map ordering can make valid signatures fail. | Freeze exact v1 signing bytes using golden vectors; decide whether a future v2 introduces canonical CBOR. |
| `scripts/qasp_server.py` is operationally central but outside the packaged library, and server dependencies are not all in `pyproject.toml`. | Baseline deployment and reproducible test environments are fragile. | Define the supported service packaging and dependency manifest before parallel implementation. |
| Local `pytest --collect-only -q` currently fails because `hypothesis` is not installed in the active environment. | We do not yet have a measured clean baseline in this checkout. | Run a clean dependency-installed baseline in CI/container and retain the report as the migration baseline. |
| Identity, token, CRL, and authority key lifetime differs from SQLite-stored data lifetime. | A Rust service preserving only HTTP shape could still change restart security behavior. | Choose either exact existing behavior for first parity or persistence hardening as an approved, versioned prerequisite. Recommendation: harden before production Rust cutover. |

## 5. Migration Principles

1. **Compatibility before replacement.** Every migrated component must interoperate
   with Python before its Python equivalent can be retired.
2. **Golden bytes are APIs.** Signed content, hashes, frame payloads, transcripts,
   DIDs, certificates, and SQLite records require immutable fixtures and
   bidirectional tests.
3. **Keep the algorithms stable.** Initially use `liboqs` from Rust for ML-KEM and
   ML-DSA to match the existing implementation and ACVP expectations; evaluate a
   pure Rust replacement only after parity and security review.
4. **Move vertically when deployable.** A Rust authority that supports real
   existing clients is more valuable than disconnected ports of every library
   module.
5. **Security gates block release.** Fuzzing, negative token tests, downgrade/MITM
   tests, replay tests, secret handling review, and dependency auditing are release
   requirements.
6. **Preserve rollback.** Python and Rust must coexist until service migration,
   data restoration, and authority identity rollback have been demonstrated.

## 6. Proposed Rust Workspace

Create the Rust implementation alongside Python during migration so conformance
can run against both implementations.

```text
rust/
  Cargo.toml                    # workspace manifest
  crates/
    qasp-crypto/                # algorithms, key types, KDF, AEAD, certs, proofs
    qasp-wire/                  # frame/message encoding and CBOR contracts
    qasp-identity/              # DID, resolution, rotation, binding, SPIFFE
    qasp-authz/                 # ARM, capability, revocation, OCSP, delegation
    qasp-trust/                 # scoring, reputation, behavior, certification
    qasp-protocol/              # handshake, sans-I/O connection, streams, events
    qasp-metering/              # receipts, accounting, settlement, disputes
    qasp-relay/                 # CapFlow relay sessions and receipts
    qasp-transport/             # TCP, QUIC, discovery and registry
    qasp-auditor/               # auditor and fault attribution
    qasp-bridge-mcp/            # MCP adapter
    qasp-bridge-a2a/            # A2A adapter
    qasp-authority/             # REST/WebSocket authority service
    qasp-client/                # Rust HTTP/WebSocket SDK and CLI support
  conformance/
    vectors/                    # Python-generated frozen byte fixtures
    interop/                    # Python <-> Rust executable integration tests
```

### Candidate Rust Technology Choices

| Concern | Initial Choice | Rationale |
| --- | --- | --- |
| Async/application runtime | `tokio` | Mature networking, task, and shutdown primitives |
| HTTP/WebSocket authority | `axum` and `tower` | Typed handlers and operational middleware |
| JSON models | `serde`, `serde_json` | Stable API serialization |
| CBOR | `ciborium` or an evaluated equivalent with explicit signing encoder | Must pass byte-vector tests before selection is final |
| SQLite | `sqlx` with migrations | Async support and explicit schema migration discipline |
| PQC | `oqs`/`liboqs` binding initially | Closest behavior match to Python `liboqs-python` |
| Classical crypto | RustCrypto crates, subject to vector verification | Widely reviewed primitives and explicit key types |
| Secret memory | `zeroize`, `secrecy` | Reduce secret-key lifetime in memory |
| HTTP callback/client | `reqwest` | Async callback forwarding and SDK client |
| QUIC | Evaluate `quinn` against current `aioquic` ALPN and test behavior | Interoperability must be proven, not assumed |
| Metrics/tracing | `tracing`, `metrics`/Prometheus exporter | Replaces optional logging/metrics path with observable service behavior |

This crate split is a planning boundary, not a mandate for excessive abstraction.
Crates can be combined during implementation where the dependency graph and
ownership are clearer.

## 7. Component Migration Map

| Migration Component | Includes | Depends On | Deliverable / Gate | Target Wave |
| --- | --- | --- | --- | --- |
| Contract and vector harness | Specs, message IDs, token/receipt/framing vectors, HTTP fixtures, SQLite fixtures | Existing Python | Frozen v1 contract and executable cross-language runner | 0 |
| Basic cryptography | ML-KEM/ML-DSA, hybrid X25519, Ed25519, AES-GCM, HKDF, suites | Contract harness, `liboqs` | ACVP and Python/Rust round trips | 1 |
| Wire encoding | CBOR messages, frame header/HMAC, error/message enum | Basic crypto for protected frames | Byte-identical frame vectors; malformed-frame fuzzing | 1 |
| Identity core | DID, DID document, registry, resolver, rotation, binding | Crypto, encoding | Python-created DIDs/documents verified by Rust and reverse | 2 |
| Authorization kernel | ARM, capability tokens, constraints, attenuation, token aggregation, CRL/OCSP | Crypto, identity, wire | Cross-language signed token verification and privilege-escalation negatives | 2 |
| Trust kernel | scoring, reputation, behavioral checks, certification registry | Identity, crypto | Score fixtures and persistence compatibility | 2 |
| Authority service | all REST/WebSocket/admin routes, API key auth, callback dispatch, store | Identity, authz, trust, relay pieces | Existing Python client passes against Rust service; data migration/rollback test | 3 |
| Handshake/connection | QASP-Shake, events/states, encryption, streams | Crypto, wire, identity | Python/Rust secure-session handshake and security tests | 4 |
| Transport/discovery | TCP, QUIC, mDNS/DNS-SD, registry advertisement | Connection, identity | Mixed-language TCP/QUIC/discovery runs | 4 |
| Metering/economics/auditor | accounting, budgets, settlement, disputes, privacy, reconciliation, auditor | Authz, protocol, identity | Receipt/dispute/evidence interoperability and fraud tests | 5 |
| Advanced security | threshold/DKG, proofs, selective/zero-knowledge disclosure, cross-domain, SPIFFE attestation | Crypto, identity, authz | Specialized conformance and security review | 5 |
| Relay | session FSM, SCM keys, receipt chains, forwarding | Authz, metering, WebSocket service | CapFlow end-to-end mixed-language tests and throughput benchmark | 5 |
| Bridges and clients | MCP, A2A, Rust client/CLI, Python client compatibility, examples | Authority and protocol | Agent scenarios pass with each side independently swapped | 6 |
| Delivery and retirement | CI, Docker images, deployment docs, formal model linkage, release | All | Canary, rollback, audit sign-off, Python retirement | 7 |

## 8. Delivery Phases

Effort ranges assume three engineers working in parallel where dependencies allow,
with a security reviewer available at phase gates. They are estimates, not a
commitment until the baseline is clean.

### Phase 0: Baseline and Contract Freeze

**Estimated duration:** 1 to 2 sprints

**Work**

- Install and pin a reproducible Python development/server environment, including
  PQC, server, and Hypothesis dependencies.
- Run and archive unit, integration, security, conformance, property, fuzz-smoke,
  and benchmark baselines.
- Reconcile the protocol docs with the message enum and currently deployed service
  features, including relay and agent messaging.
- Capture OpenAPI/JSON and WebSocket event contracts for the authority service.
- Freeze golden fixtures for frames, token signable bytes, signed tokens, DIDs,
  capability attenuation chains, revocations, OCSP, receipts, trust scoring,
  handshake transcripts, and SQLite records.
- Decide authority key/state persistence policy and whether it ships before or as
  part of Rust service replacement.

**Exit criteria**

- A signed-off v1 compatibility contract exists.
- Python baseline is green or every exception is explicitly documented and
  approved.
- Golden-vector generation is reproducible and checked into conformance fixtures.
- Management has approved persistence and API versioning decisions.

### Phase 1: Rust Foundation, Crypto, and Wire Format

**Estimated duration:** 2 sprints

**Work**

- Create the Cargo workspace, linting, testing, vulnerability audit, formatting,
  coverage, and CI jobs alongside existing Python CI.
- Implement typed secret/public key wrappers and zeroization policy.
- Port core cryptographic primitives used by all other components.
- Initially bind to `liboqs` for ML-KEM-768 and ML-DSA-65 parity.
- Port the CBOR message structs and binary frame codec/HMAC verification.
- Add Rust fuzz targets for frame and token decoding.

**Exit criteria**

- Rust passes cryptographic known-answer/ACVP tests applicable to the current code.
- Python encodes and Rust decodes/verifies frames, and Rust encodes and Python
  decodes/verifies them.
- No unresolved signing-byte or transcript differences remain for foundation
  fixtures.

### Phase 2: Identity, Authorization, Revocation, and Trust

**Estimated duration:** 2 to 3 sprints

**Work**

- Port `did:qasp` derivation, DID documents, registry/resolver, key rotation,
  owner binding, and foundational SPIFFE models.
- Port ARM URI semantics and the complete capability token model, including
  constraints, attenuation, delegation, temporal rules, aggregation, and replay
  protection.
- Port CRL/OCSP and rate-limit authorization enforcement.
- Port trust scoring, reputation, behavioral verification, certification, and
  registry persistence.
- Build cross-language token lifecycle tests: issue, verify, attenuate, revoke,
  query, and reject escalation.

**Exit criteria**

- Python and Rust verify each other's identities and tokens.
- Existing privilege-escalation, token replay, revocation, and trust behavior is
  represented as passing Rust tests and cross-language tests.
- The authorization kernel is approved for use by an authority service.

### Phase 3: Rust Authority Service Vertical Slice

**Estimated duration:** 2 to 3 sprints

**Work**

- Implement `qasp-authority` with HTTP/WebSocket routes matching the frozen API.
- Implement database migrations and persistence for currently stored SQLite data.
- Apply the Phase 0 decision for authority keys, agents, issued tokens, CRL,
  trust/rate-limit state, and restart behavior.
- Implement registration, discovery, token lifecycle, tool callback forwarding,
  trust updates, conversations/messages, admin endpoints, metrics, and health.
- Preserve existing Python client usability and callback behavior.
- Introduce shadow or isolated staging comparison: same scenario input, compared
  Python/Rust externally visible results.

**Exit criteria**

- `scripts/qasp_client.py` and HTTP-only agents work unchanged against Rust.
- WebSocket registration, message delivery, inbox fallback, and relay-dependent
  routes pass end-to-end tests.
- Authority restart, key restoration, persisted state, and rollback procedures are
  tested.
- A staging canary is approved; Python authority remains a rollback option.

### Phase 4: Secure Session Protocol, Transport, and Discovery

**Estimated duration:** 2 to 3 sprints

**Work**

- Port the sans-I/O connection state machine, QASP-Shake, events, stream
  multiplexing, application encryption, timeouts, and downgrade handling.
- Implement TCP adapter and then QUIC adapter after TCP interop stabilizes.
- Port discovery advertisements, signature validation, registry queries, and
  local discovery behavior.
- Run Python-to-Rust and Rust-to-Python connection, transport, and discovery
  scenarios.

**Exit criteria**

- Mixed-language handshake and encrypted data transfer passes all supported cipher
  suites.
- MITM, downgrade, malformed-frame, retry/timeout, and transport failure cases
  match the frozen behavior.
- TCP, QUIC, and discovery interop are demonstrated in CI or an approved test
  environment.

### Phase 5: Advanced Protocol, Metering, Auditor, and Relay

**Estimated duration:** 2 to 3 sprints

**Work**

- Port accounting, metering, budgets, privacy traces/proofs of execution,
  reconciliation, settlement, dispute resolution, and auditor/fault attribution.
- Port token aggregation, threshold delegation, cross-domain behavior,
  selective disclosure, zero-knowledge disclosure, and SPIFFE attestation.
- Port advanced cryptographic support required by these modules: certificate
  behavior, Merkle/Pedersen/Bulletproof work, Shamir/DKG/threshold functionality.
- Complete CapFlow relay sessions, SCM epoch behavior, receipt persistence,
  forwarding, session accounting, and failure recovery.
- Review any custom cryptographic implementation with specialist security review;
  do not quietly translate experimental crypto into a production assurance claim.

**Exit criteria**

- Receipt, settlement, dispute, privacy, advanced delegation, and relay
  cross-language tests pass.
- Security tests for fraud, tampering, privilege escalation, and replay pass.
- Security review records the production status of advanced/experimental crypto.

### Phase 6: Bridges, SDK, Tooling, and Operational Packaging

**Estimated duration:** 1 to 2 sprints

**Work**

- Port MCP and A2A bridges and verify their token/metadata mapping contracts.
- Provide a Rust client/CLI while preserving the Python client during transition.
- Port or retire scripts and examples explicitly; every current workflow must have
  a maintained Rust equivalent or a recorded retirement decision.
- Build Rust container targets, deployment configuration, metrics/logging, and
  operational runbooks.
- Update formal verification linkage and protocol documentation for the Rust
  implementation where relevant.

**Exit criteria**

- Demo and bridge scenarios run against the Rust authority and Rust libraries.
- Deployment images, CI, observability, and runbooks are ready for canary traffic.
- No unassigned Python production functionality remains.

### Phase 7: Canary Cutover and Python Retirement

**Estimated duration:** 1 to 2 sprints plus an observation window

**Work**

- Deploy Rust as a canary with stable authority identity and backed-up persisted
  state.
- Compare latency, error rate, callback delivery, WebSocket stability, token
  verification, trust updates, and relay/metering correctness.
- Exercise rollback using restored keys and state before expanding traffic.
- Move from canary to production in controlled stages.
- Mark Python implementation reference-only after the rollback window, retaining
  golden fixture generation capability for protocol version maintenance.

**Exit criteria**

- Production success criteria are achieved for the agreed observation period.
- Security and operations sign off on cutover and recovery evidence.
- Python production service is removed only after rollback obligations are met.

## 9. Verification Strategy

### Test Pyramid

| Level | Purpose | Migration Requirement |
| --- | --- | --- |
| Golden vectors | Preserve signed bytes, hashes, frames, DIDs, receipts and transcripts | Run in both languages on every change |
| Rust unit/property tests | Establish module correctness and invariants | Cover every migrated rule and negative path |
| Cross-language interoperability | Prove rolling migration compatibility | Required before each component substitution |
| HTTP/WebSocket contract tests | Preserve agent-visible authority behavior | Required before authority canary |
| Persistence migration tests | Preserve identity and operational data across restart/cutover | Required before deployment |
| Security tests | Catch MITM, downgrade, replay, escalation, tampering and fraud regressions | Blocking release gate |
| Fuzzing | Harden CBOR, frame, token and network parsers | Continuous smoke plus scheduled extended runs |
| Benchmarks | Measure PQC, handshake, token verification, relay and server behavior | Establish budgets in Phase 0; enforce tolerances later |
| Formal artifacts | Retain protocol-model traceability | Reconcile models when contract changes are approved |

### Mandatory Bidirectional Interop Cases

- Python signs and encodes; Rust verifies and decodes.
- Rust signs and encodes; Python verifies and decodes.
- Python client against Rust authority and Rust client against Python authority.
- Python QASP connection to Rust QASP connection over supported transports.
- Mixed-language delegation, attenuation, revocation, receipts, disputes, MCP,
  A2A, messaging, and relay sessions.

## 10. Release and Rollout Controls

| Control | Requirement |
| --- | --- |
| Protocol versioning | No externally visible encoding or semantics change without an explicit version decision and migration story. |
| Authority keys | Back up and restore the authority secret key before any canary; changing it invalidates trust continuity. |
| State migration | Use repeatable migrations and rollback-tested snapshots; do not rely on process memory for cutover state. |
| Feature flags | Gate new Rust service features and advanced modules independently where feasible. |
| Shadow validation | Compare Rust results to Python for deterministic operations before routing authoritative writes. |
| Observability | Measure endpoint error/latency, signature/verification failures, revocations, callbacks, WebSockets, message delivery, relay sessions, metering, and persistence failures. |
| Incident rollback | Keep Python deployment artifacts and compatible state restoration available through the agreed observation window. |

## 11. Resourcing and Ownership Proposal

### Minimum Effective Team

| Role | Primary Ownership |
| --- | --- |
| Rust protocol/crypto lead | Crypto wrapper, wire contracts, handshake, security gates |
| Rust service/data engineer | Authority API, WebSockets, SQLite migrations, rollout and observability |
| Rust integration engineer | Identity/authz/trust, SDK, bridges, transport, interop harness |
| Security reviewer, part-time but scheduled | Crypto/API threat review, advanced crypto disposition, pre-canary sign-off |
| Product/manager representative | Contract freeze, compatibility policy, deployment acceptance and prioritization |

### Recommended Parallel Workstreams

- **Security kernel:** crypto, frames, identity, authorization, conformance vectors.
- **Authority product:** API contracts, persistence design, service implementation,
  operational migration.
- **Protocol ecosystem:** secure sessions, transports, relay, bridges, SDK and
  demonstrations.

The security kernel is the dependency gate for the other two. The authority API
and persistence contract discovery can proceed during early kernel work.

## 12. Management Decisions Needed to Start

1. Confirm that compatibility-first staged migration is preferred over a clean
   break and protocol v2 rewrite.
2. Approve `liboqs` continuity for initial Rust parity, with any pure Rust PQC
   replacement considered separately.
3. Decide whether Rust authority cutover must include persistent authority keys,
   agents, tokens, CRL, trust, and rate-limit state. Recommendation: yes for any
   production cutover.
4. Approve the Phase 0 contract-freeze sprint before feature implementation.
5. Assign target deployment priority: authority service first, protocol library
   first, or equal priority. Recommendation: deliver the interoperable Rust
   authority vertical slice as the first externally useful milestone after the
   security kernel.
6. Confirm staffing and desired calendar deadline so estimates can become a
   committed roadmap.

## 13. Immediate Next Actions After Approval

| Action | Owner | Output |
| --- | --- | --- |
| Establish clean Python/server baseline environment and execute full suite | Engineering | Baseline report and failing-test disposition |
| Reconcile message registry, signed encodings, HTTP/WS APIs and persistence behavior | Protocol + product | Approved v1 compatibility document |
| Generate fixture corpus from Python | Protocol engineer | Versioned golden vectors |
| Choose Rust crate dependency set through vector spikes | Rust lead | Architecture decision records |
| Implement Cargo workspace and interop CI skeleton | Rust team | First migration PR |
| Design authority state/key persistence and rollback | Service/data engineer + security | Cutover-safe data plan |

## 14. Definition of Done

The QASP Rust migration is complete only when:

- Every retained Python production capability has a Rust implementation or an
  explicitly approved retirement decision.
- All approved v1 interop, conformance, security, persistence, and API contract
  tests pass against Rust.
- Existing supported agents can migrate without an unplanned protocol/API break.
- Authority identity and persistent state survive restart, deployment and rollback
  according to the approved policy.
- CI, container packaging, monitoring, deployment, incident response and security
  audit artifacts cover the Rust system.
- Rust has completed controlled production cutover and Python has passed its
  defined rollback observation window.
