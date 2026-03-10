# QASP Enterprise Documentation
## Quantum-Aware Secure Protocol — Technical Reference v0.1.0

**Classification:** Public Technical Documentation
**Version:** 0.1.0-alpha
**Date:** 2026-03-10
**License:** Apache 2.0
**Minimum Runtime:** Python 3.12

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Architecture](#2-system-architecture)
   - 2.1 [Layered Architecture](#21-layered-architecture)
   - 2.2 [Component Dependency Graph](#22-component-dependency-graph)
   - 2.3 [Data Flow Diagrams](#23-data-flow-diagrams)
   - 2.4 [Threading and Concurrency Model](#24-threading-and-concurrency-model)
3. [Cryptographic Foundation](#3-cryptographic-foundation)
   - 3.1 [Algorithm Selection Rationale](#31-algorithm-selection-rationale)
   - 3.2 [NIST Compliance](#32-nist-compliance-fips-203-and-fips-204)
   - 3.3 [Key Management Lifecycle](#33-key-management-lifecycle)
   - 3.4 [X.509-PQ Certificate Infrastructure](#34-x509-pq-certificate-infrastructure)
   - 3.5 [Hybrid Cryptography Strategy](#35-hybrid-cryptography-strategy)
   - 3.6 [Key Sizes and Performance](#36-key-sizes-and-performance)
4. [Identity and Access Control](#4-identity-and-access-control)
   - 4.1 [did:qasp Method Specification](#41-didqasp-method-specification)
   - 4.2 [DID Document Structure](#42-did-document-structure)
   - 4.3 [Capability Token Architecture](#43-capability-token-architecture)
   - 4.4 [ARM Resource URI Model](#44-arm-resource-uri-model)
   - 4.5 [Token Attenuation and Delegation](#45-token-attenuation-and-delegation)
   - 4.6 [Multi-Owner Tokens](#46-multi-owner-tokens)
5. [Trust and Reputation Framework](#5-trust-and-reputation-framework)
   - 5.1 [Bayesian Trust Scoring](#51-bayesian-trust-scoring)
   - 5.2 [Component Weights and Cold-Start](#52-component-weights-and-cold-start)
   - 5.3 [Anti-Gaming Caps](#53-anti-gaming-caps)
   - 5.4 [Collusion Detection](#54-collusion-detection)
   - 5.5 [SLSA Certification Integration](#55-slsa-certification-integration)
6. [Revocation and Status](#6-revocation-and-status)
   - 6.1 [Certificate Revocation List](#61-certificate-revocation-list)
   - 6.2 [BFS Cascade Revocation](#62-bfs-cascade-revocation)
   - 6.3 [OCSP Responder](#63-ocsp-responder)
   - 6.4 [OCSP Stapling](#64-ocsp-stapling)
   - 6.5 [Grace Periods and Urgency](#65-grace-periods-and-urgency)
7. [Rate Limiting and Metering](#7-rate-limiting-and-metering)
   - 7.1 [Token Bucket Algorithm](#71-token-bucket-algorithm)
   - 7.2 [Per-Token Enforcement](#72-per-token-enforcement)
   - 7.3 [Usage Metering](#73-usage-metering)
8. [Transport Layer](#8-transport-layer)
   - 8.1 [TCP Transport](#81-tcp-transport)
   - 8.2 [QUIC Transport](#82-quic-transport)
   - 8.3 [Service Discovery](#83-service-discovery)
   - 8.4 [Protocol Bridges](#84-protocol-bridges)
9. [Authority Server API Reference](#9-authority-server-api-reference)
   - 9.1 [Authentication Model](#91-authentication-model)
   - 9.2 [Endpoint Reference](#92-endpoint-reference)
   - 9.3 [Error Codes](#93-error-codes)
   - 9.4 [7-Step Tool Call Verification](#94-7-step-tool-call-verification)
10. [Security Considerations](#10-security-considerations)
    - 10.1 [Threat Model](#101-threat-model)
    - 10.2 [Attack Surface Analysis](#102-attack-surface-analysis)
    - 10.3 [Known Limitations](#103-known-limitations)
    - 10.4 [Security Best Practices](#104-security-best-practices)
11. [Compliance and Standards](#11-compliance-and-standards)
12. [Operational Characteristics](#12-operational-characteristics)
13. [Integration Patterns](#13-integration-patterns)
14. [Glossary](#14-glossary)
15. [Appendix A: Configuration Reference](#appendix-a-configuration-reference)
16. [Appendix B: Error Code Registry](#appendix-b-error-code-registry)
17. [Appendix C: OID Registry](#appendix-c-oid-registry)

---

## 1. Executive Summary

### 1.1 The Quantum Threat to AI Agent Infrastructure

Enterprise AI deployments are accelerating the adoption of autonomous agent-to-agent (A2A) communication: pipelines where LLM-driven agents invoke tools, delegate subtasks, and exchange sensitive data with one another programmatically and at scale. These interactions rely on cryptographic authentication — typically RSA or ECDSA — to verify identity and authorize access.

Cryptographically relevant quantum computers (CRQCs) pose a direct threat to this trust foundation. Shor's algorithm running on a sufficiently large quantum processor will break RSA-2048 in polynomial time and render elliptic-curve cryptography (ECC) similarly obsolete. NIST projects that CRQCs capable of this may emerge within the next decade. The immediate risk is "harvest now, decrypt later" (HNDL): an adversary intercepting today's agent-to-agent traffic can store it and decrypt it retroactively once quantum hardware matures. For AI agents handling intellectual property, financial instructions, or regulated personal data, this exposure is unacceptable.

Existing agent frameworks — MCP, Google A2A, LangChain tool servers — were not designed with post-quantum cryptography in mind. They inherit the vulnerability of their underlying TLS stacks and API key schemes.

### 1.2 What QASP Delivers

QASP (Quantum-Aware Secure Protocol) is a Python 3.12+ library and authority server that provides a complete post-quantum security substrate for AI agent-to-agent communication. It replaces classical cryptographic primitives throughout the agent interaction lifecycle with NIST-standardized post-quantum algorithms.

Key capabilities:

| Capability | Implementation | Standard |
|---|---|---|
| Post-quantum signatures | ML-DSA-65 (Dilithium3) | FIPS 204 |
| Post-quantum key encapsulation | ML-KEM-768 (Kyber768) | FIPS 203 |
| Hybrid key exchange | X25519 + ML-KEM-768 | Harvest-now protection |
| Authenticated encryption | AES-256-GCM | FIPS 197 |
| Key derivation | HKDF-SHA-384 | RFC 5869 |
| Agent identity | did:qasp DID method | W3C DID Core 1.0 |
| Access control | CBOR capability tokens | Object Capabilities model |
| Credential verification | W3C Verifiable Credentials | W3C VC Data Model 2.0 |
| Real-time revocation | OCSP with stapling | RFC 6960 profile |
| Reputation | Bayesian trust scoring | Beta distribution |

### 1.3 Target Audiences

This document is written for three primary audiences:

**CTOs and CISOs** should focus on Sections 1, 10, and 11 to understand the threat model, compliance posture, and decision rationale for adopting QASP.

**Security architects** should read Sections 3, 4, 5, 6, and 10 for detailed cryptographic design, access control architecture, and threat analysis.

**Platform engineers** should focus on Sections 2, 7, 8, 9, 12, and 13 for integration, deployment, and operational guidance.

### 1.4 Version and Maturity

QASP v0.1.0 is an alpha release. The cryptographic core (ML-DSA-65, ML-KEM-768, hybrid KEM, AEAD, certificates) is complete and implements published NIST standards. The protocol layer (handshake, capability tokens, revocation, trust scoring, rate limiting) is feature-complete for the described use cases. The authority server is a fully functional reference implementation suitable for development, staging, and controlled production deployments. In-memory state (no persistent storage) is a known limitation of v0.1.0.

**Stability commitments for v0.1.0:**
- Cryptographic wire formats are stable and will not change without a major version bump.
- REST API endpoints and response schemas are stable.
- Python API may have breaking changes between minor versions during alpha.

---

## 2. System Architecture

### 2.1 Layered Architecture

QASP is organized into five layers, each with a well-defined responsibility boundary. Higher layers depend on lower layers; lower layers have no knowledge of higher layers.

```
+===========================================================================+
|                         INTEGRATION LAYER                                 |
|   Protocol Bridges (MCP, A2A)  |  Authority Server REST API               |
|   Client SDK (qasp_client.py)  |  LLM Agent Loop Adapters                 |
+===========================================================================+
|                          PROTOCOL LAYER                                   |
|  Capability Tokens  |  ARM URI Model  |  Rate Limiting  |  Token Aggreg.  |
|  QASP-Shake Handshake  |  Connection State Machine  |  Metering           |
|  Revocation (CRL)   |  OCSP Responder  |  Settlement  |  Reconciliation   |
|  Selective Disclosure  |  ZK Disclosure  |  Threshold Delegation          |
+===========================================================================+
|                          TRUST LAYER                                      |
|  Bayesian Trust Scoring  |  Trust Registry  |  W3C VC Audit Certs         |
+===========================================================================+
|                         IDENTITY LAYER                                    |
|  did:qasp DID Method  |  DID Document Registry  |  Identity Binding       |
|  Group DID Management  |  X.509-PQ Certificates                          |
+===========================================================================+
|                     CRYPTOGRAPHIC FOUNDATION                              |
|  ML-DSA-65 (FIPS 204)  |  ML-KEM-768 (FIPS 203)  |  AES-256-GCM          |
|  X25519+ML-KEM-768 Hybrid  |  HKDF-SHA-384  |  SHA-384                   |
+===========================================================================+
|                         TRANSPORT LAYER                                   |
|  TCP (asyncio, 4-byte prefix, 16 MB max)  |  QUIC (aioquic, port 4443)   |
|  mDNS Service Discovery (zeroconf)  |  Agent Registry                    |
+===========================================================================+
```

**Cryptographic Foundation** (`src/qasp/crypto/`) provides all primitives with no external protocol dependencies. This layer is independently auditable and testable.

**Transport Layer** (`src/qasp/transport/`) implements network I/O. It is intentionally decoupled from the protocol layer via the sans-I/O pattern: transport implementations pass raw bytes to the protocol state machine and receive bytes to send back, with no shared state.

**Identity Layer** (`src/qasp/identity/`, `src/qasp/crypto/certificates.py`) maps cryptographic public keys to decentralized identifiers and manages X.509-PQ certificate lifecycle. The `did:qasp` method is defined entirely within this layer.

**Trust Layer** (`src/qasp/trust/`) maintains reputation scores for registered agents. It depends only on identity (to resolve DIDs) and has no dependency on protocol or transport layers.

**Protocol Layer** (`src/qasp/protocol/`) is the largest and most complex layer. It implements the full QASP protocol: handshake, capability tokens, access control, revocation, metering, settlement, and advanced disclosure features. All cryptographic operations are delegated to the cryptographic foundation.

**Integration Layer** (`src/qasp/bridges/`, `scripts/`) provides bridges to external agent protocols (MCP, A2A) and the REST authority server that external agents use as their entry point.

### 2.2 Component Dependency Graph

The following diagram shows import-level dependencies between the major modules. Arrows represent "depends on" relationships.

```
qasp_server.py (FastAPI)
    |
    +---> qasp.protocol.capability
    |         |---> qasp.crypto.signatures
    |         |---> qasp.identity.did
    |         +---> qasp.protocol.states
    |
    +---> qasp.protocol.arm
    |
    +---> qasp.protocol.ocsp
    |         |---> qasp.protocol.revocation
    |         +---> qasp.crypto.signatures
    |
    +---> qasp.protocol.revocation
    |         +---> qasp.crypto.signatures
    |
    +---> qasp.protocol.rate_limiter  (no crypto deps)
    |
    +---> qasp.trust.registry
    |         +---> qasp.identity.did
    |
    +---> qasp.trust.scoring          (no crypto deps)
    |
    +---> qasp.identity.did
              |---> qasp.crypto.signatures
              +---> base58

qasp.transport.quic
    |---> aioquic
    +---> qasp.protocol.connection

qasp.transport.tcp
    +---> qasp.protocol.connection

qasp.transport.discover
    |---> zeroconf
    +---> qasp.crypto.signatures

qasp.bridges.mcp_bridge
    +---> mcp (external)

qasp.bridges.a2a_bridge
    +---> a2a-python (external)
```

### 2.3 Data Flow Diagrams

#### 2.3.1 Agent Registration Flow

```
Agent                   Authority Server
  |                           |
  |-- POST /register -------->|
  |   {name, tools,           |
  |    callback_url}          |
  |                           |-- generate_keypair() [ML-DSA-65]
  |                           |-- create_did(pub_key)
  |                           |     SHA-384(pubkey)[0:32]
  |                           |     Base58btc encode -> did:qasp:<id>
  |                           |-- did_registry.register(did_doc)
  |                           |-- trust_registry.register(did)
  |                           |-- map tools -> ARM URIs
  |                           |     qasp://agents/{did_short}/tools/{name}
  |                           |-- generate api_key (uuid4.hex)
  |                           |
  |<-- 200 OK ---------------|
  |   {agent_id, did,         |
  |    api_key, public_key}   |
  |                           |
```

The agent receives its DID and API key. The server retains the ML-DSA-65 keypair on behalf of the agent. The agent never needs to handle cryptographic material directly.

#### 2.3.2 Token Issuance Flow

```
Caller Agent            Authority Server          Target Agent (implicit)
     |                        |                          |
     |-- POST /tokens/request->|                          |
     |   {target_did,          |                          |
     |    tool_name,           |                          |
     |    verbs}               |                          |
     |                         |-- resolve target agent   |
     |                         |-- find tool -> ARM URI   |
     |                         |-- create_token(          |
     |                         |     issuer=authority,    |
     |                         |     subject=caller,      |
     |                         |     audience=target,     |
     |                         |     resource_uri,        |
     |                         |     constraints{         |
     |                         |       rate_limit=10,     |
     |                         |       rate_period=60s,   |
     |                         |       validity=3600s})   |
     |                         |-- ML-DSA-65 sign         |
     |                         |-- CBOR encode            |
     |                         |-- crl.register_token()   |
     |                         |                          |
     |<-- 200 OK -------------|                          |
     |   {token (base64),      |                          |
     |    token_id (hex),      |                          |
     |    resource_uri,        |                          |
     |    verbs,               |                          |
     |    expires_at}          |                          |
```

#### 2.3.3 Tool Call Flow (7-Step Verification)

```
Caller Agent            Authority Server          Target Agent
     |                        |                        |
     |-- POST /tools/call ---->|                        |
     |   {target_did,          |                        |
     |    tool_name,           |                        |
     |    arguments,           |                        |
     |    token (base64)}      |                        |
     |                         |                        |
     |                         |-- [1] decode token     |
     |                         |-- [2] verify_token()   |
     |                         |       ML-DSA-65 sig    |
     |                         |       expiry check     |
     |                         |       CRL check        |
     |                         |-- [3] ARM URI scope    |
     |                         |       uri_matches()    |
     |                         |-- [4] verb check       |
     |                         |       ARM_EXEC in verbs|
     |                         |-- [5] rate limit       |
     |                         |       bucket.consume() |
     |                         |-- [6] relay to target  |
     |                         |       POST /tools/name |
     |                         |       X-QASP-Caller-DID|
     |                         +----------------------->|
     |                         |                        |-- execute tool
     |                         |<-----------------------+
     |                         |       {result}         |
     |                         |-- [7] trust update     |
     |                         |       metering record  |
     |                         |                        |
     |<-- 200 OK -------------|                        |
     |   {result,              |                        |
     |    metering,            |                        |
     |    receipt_id}          |                        |
```

#### 2.3.4 Revocation Flow

```
Revoker Agent           Authority Server          Any Agent (checking)
     |                        |                        |
     |-- POST /tokens/revoke ->|                        |
     |   {token_id}            |                        |
     |                         |-- crl.revoke(          |
     |                         |     token_id,          |
     |                         |     reason=OWNER_REQ,  |
     |                         |     urgency=CRITICAL)  |
     |                         |-- BFS cascade check    |
     |                         |   (child tokens also   |
     |                         |    revoked)            |
     |                         |-- ocsp.invalidate()    |
     |                         |   (clear OCSP cache)   |
     |<-- 200 OK -------------|                        |
     |   {revoked: true,       |                        |
     |    entries_created}     |                        |
     |                         |                        |
     |                         |         GET /tokens/status/{id}
     |                         |<-----------------------|
     |                         |-- ocsp.handle_request()|
     |                         |-- sign OCSP response   |
     |                         +----------------------->|
     |                         |   {status: REVOKED,    |
     |                         |    revoked_at}         |
```

### 2.4 Threading and Concurrency Model

QASP uses a mixed threading model appropriate for its components:

**Authority Server (asyncio + Uvicorn):** The FastAPI application runs in a single-threaded asyncio event loop. Async handlers (`async def`) use `await` for I/O-bound operations (HTTP relay via `httpx.AsyncClient`). Synchronous handlers execute inline on the event loop. Because all server state (`AuthorityState`) is accessed only from within the event loop, no locking is required for server-level state.

**Rate Limiter (`TokenBucketRateLimiter`, `RateLimiterRegistry`):** Both classes are explicitly thread-safe. Every mutation to bucket state is guarded by `threading.Lock`. The `RateLimiterRegistry` uses a separate lock for registry mutations. This design allows the rate limiter to be used safely from both asyncio tasks (via `asyncio.run_in_executor`) and from threading-based WSGI applications.

**QUIC Transport (`QASPQuicClient`, `QASPQuicServer`):** Built on top of `aioquic`, which is an asyncio-native library. All operations are non-blocking coroutines. The `asyncio.timeout` context manager is used for all timeout-sensitive operations.

**TCP Transport:** Asyncio-based with `asyncio.StreamReader` and `asyncio.StreamWriter`. Frame boundaries are enforced at the I/O level before passing data to the protocol state machine.

**Protocol State Machine (`QASPConnection`):** The connection state machine is implemented in the sans-I/O pattern: it is a pure in-memory object with no I/O operations. It receives bytes as input, produces events and bytes-to-send as output, and is driven by whichever transport adapter holds a reference to it. This makes the state machine independently testable without any network infrastructure.

---

## 3. Cryptographic Foundation

### 3.1 Algorithm Selection Rationale

QASP's algorithm choices are grounded in three criteria: NIST standardization status, security level appropriateness for the threat model, and implementation availability through audited open-source libraries.

**ML-DSA-65 for signatures (FIPS 204):** Also known as Dilithium3, ML-DSA-65 is one of three signature algorithms standardized by NIST in August 2024. Level 3 security (roughly equivalent to AES-192 or SHA-384 collision resistance) was selected over Level 2 (ML-DSA-44) because agent identity and capability tokens must remain trustworthy beyond the token's validity period. A compromised signature on a delegation chain has long-term consequences. Level 5 (ML-DSA-87) was considered excessive for the operational lifetime of agent tokens (maximum 1 hour in the current authority server configuration).

**ML-KEM-768 for key encapsulation (FIPS 203):** Also known as Kyber768, ML-KEM-768 provides Level 3 security for key agreement. It is used in the hybrid KEM for session key establishment. Level 768 balances security margin against the performance requirements of frequent connection establishment in multi-agent systems.

**X25519 for hybrid classical component:** Retaining X25519 in a hybrid KEM provides defense-in-depth: if ML-KEM-768 were discovered to have a weakness, the X25519 component ensures classical security properties are preserved. The hybrid also protects against HNDL attacks on currently intercepted traffic, because breaking the session key requires breaking both components simultaneously.

**AES-256-GCM for AEAD:** The standard for authenticated encryption. FIPS 197 compliant. Provides both confidentiality and integrity for data in transit after key establishment.

**HKDF-SHA-384 for key derivation:** SHA-384 is the hash function consistent with the Level 3 security target used throughout QASP. HKDF (RFC 5869) provides context-bound key derivation from the shared secrets produced by the hybrid KEM.

**SHA-384 for DID derivation:** The `did:qasp` identifier is derived as `Base58btc(SHA-384(public_key)[0:32])`. SHA-384 was chosen over SHA-256 to maintain consistency with the overall Level 3 security posture. The first 32 bytes (256 bits) of the SHA-384 digest provide the identifier, giving sufficient collision resistance for the anticipated scale of agent registries.

All algorithms are implemented via `liboqs-python`, the Python wrapper for the Open Quantum Safe project's `liboqs` C library. This is the same implementation used in OpenSSL's OQS fork and has received significant academic and industry scrutiny.

### 3.2 NIST Compliance: FIPS 203 and FIPS 204

| Standard | Algorithm | QASP Module | Security Level | Status |
|---|---|---|---|---|
| FIPS 203 | ML-KEM-768 | `src/qasp/crypto/kem.py` | Level 3 | Final (Aug 2024) |
| FIPS 204 | ML-DSA-65 | `src/qasp/crypto/signatures.py` | Level 3 | Final (Aug 2024) |
| FIPS 197 | AES-256-GCM | `src/qasp/crypto/aead.py` | — | Final |
| FIPS 180-4 | SHA-384 | `src/qasp/crypto/kdf.py`, `did.py` | — | Final |
| RFC 5869 | HKDF-SHA-384 | `src/qasp/crypto/kdf.py` | — | Informational |

FIPS 205 (SLH-DSA, SPHINCS+) is not currently used by QASP. SLH-DSA is significantly slower for signing operations, making it unsuitable for high-frequency capability token issuance. QASP's architecture accommodates future algorithm agility through its OID-tagged certificate format; SLH-DSA could be added as an alternative in a future release.

NIST's post-quantum migration guidance (NIST SP 800-208, IR 8413) recommends beginning migration to post-quantum algorithms for long-lived secrets immediately, and completing migration for all systems by 2030. QASP positions organizations to meet this timeline for their AI agent infrastructure.

### 3.3 Key Management Lifecycle

QASP implements a three-tier key hierarchy:

```
Tier 1: Authority Root Keypair
    ML-DSA-65 keypair
    Generated at server startup
    Used to sign all capability tokens
    Signs OCSP responses
    Never transmitted to agents
    Lifecycle: server process lifetime (v0.1.0: in-memory only)

Tier 2: Agent Identity Keypairs
    ML-DSA-65 keypair per registered agent
    Generated by authority on behalf of agent
    Public key embedded in DID document
    Used for identity verification
    Private key held by authority in-memory
    Lifecycle: agent session (until server restart)

Tier 3: Session Keys
    Derived via X25519 + ML-KEM-768 hybrid KEM
    Ephemeral per QASP-Shake handshake
    Used for channel encryption (AES-256-GCM)
    Never persisted
    Lifecycle: single connection
```

**Key generation:** `generate_keypair()` in `src/qasp/crypto/signatures.py` calls `liboqs.Signature("Dilithium3").generate_keypair()`. The returned public key is 1952 bytes; the secret key is 4032 bytes.

**Key storage in v0.1.0:** All keys are held in-memory in `AuthorityState` and per-`AgentRecord` instances. This is appropriate for development and controlled demonstrations. Production deployments require integration with a secrets management system (see Section 10.4).

**Key rotation:** v0.1.0 does not implement automated key rotation. When the authority server restarts, all agent registrations and tokens are lost (in-memory state). Key rotation for a persistent deployment requires storing agent records in a database and implementing a token migration path; this is on the roadmap for v0.2.0.

### 3.4 X.509-PQ Certificate Infrastructure

QASP defines a custom X.509 profile for post-quantum certificates, implemented in `src/qasp/crypto/certificates.py`.

**Certificate structure:**

```
QASPCertificate (DER-encoded X.509v3)
├── tbsCertificate
│   ├── version: v3
│   ├── serialNumber: random 128-bit
│   ├── signature: OID 2.16.840.1.101.3.4.3.18 (id-ml-dsa-65)
│   ├── issuer: authority DID
│   ├── validity: notBefore / notAfter
│   ├── subject: agent DID
│   ├── subjectPublicKeyInfo
│   │   ├── algorithm: OID 2.16.840.1.101.3.4.3.18
│   │   └── subjectPublicKey: ML-DSA-65 public key (1952 bytes)
│   └── extensions
│       ├── qasp-did: OID 1.3.6.1.4.1.59999.1 (subject DID)
│       ├── qasp-capabilities: OID 1.3.6.1.4.1.59999.2 (capability list)
│       └── basicConstraints: cA=FALSE
└── signatureValue: ML-DSA-65 signature (max 3309 bytes)
```

The OID `2.16.840.1.101.3.4.3.18` is the NIST-assigned OID for ML-DSA-65 (id-ml-dsa-65) as specified in the NIST PQC Algorithm OIDs document. The QASP-specific OID arc `1.3.6.1.4.1.59999` is used for custom extensions; see Appendix C for the full OID registry.

These certificates are intended for QASP-internal use (agent identity binding and OCSP responses). They are not designed to chain to public certificate authorities, which do not yet support ML-DSA-65. For TLS termination at the HTTP layer, standard TLS certificates from a CA are used as the outer transport layer; QASP certificates provide application-layer authentication.

### 3.5 Hybrid Cryptography Strategy

The hybrid KEM in `src/qasp/crypto/hybrid.py` combines classical and post-quantum key agreement:

```
shared_secret = HKDF-SHA-384(
    ikm = X25519_shared_secret || ML-KEM-768_shared_secret,
    info = "qasp-hybrid-kem-v1",
    length = 32
)
```

The XOR-like concatenation of both shared secrets before KDF input ensures that the security of the combined scheme requires breaking both component algorithms. An attacker with only a classical computer cannot break X25519 but also cannot leverage that to attack the channel, because the ML-KEM-768 component still provides quantum-safe confidentiality. Symmetrically, a hypothetical break of ML-KEM-768 does not compromise sessions protected by X25519.

This hybrid approach is consistent with the NIST recommendation (NIST IR 8413) and the IETF draft on hybrid key exchange (draft-ietf-tls-hybrid-design). It is used during the QASP-Shake handshake for establishing per-session symmetric keys.

The hybrid strategy addresses the HNDL threat: traffic encrypted today remains confidential even if a CRQC becomes available in the future, because breaking the X25519 component provides no advantage to a quantum adversary (Shor's algorithm targets discrete logarithm and integer factorization, which are both classical algorithms; the ML-KEM-768 component is not vulnerable to Shor's algorithm).

### 3.6 Key Sizes and Performance

| Parameter | ML-DSA-65 | ML-KEM-768 | X25519 | AES-256-GCM |
|---|---|---|---|---|
| Public key | 1952 bytes | 1184 bytes | 32 bytes | N/A |
| Secret key | 4032 bytes | 2400 bytes | 32 bytes | 32 bytes |
| Signature / ciphertext | 3309 bytes (max) | 1088 bytes | 32 bytes | +16 bytes tag |
| Encapsulated key | N/A | 1088 bytes | N/A | N/A |

**Capability token size:** A signed CBOR capability token is approximately 3600–4000 bytes (CBOR-encoded fields + 3309-byte ML-DSA-65 signature). When transmitted base64-encoded over HTTP, tokens are approximately 4900–5400 bytes. This is larger than JWT tokens but within the acceptable range for HTTP request headers and bodies.

**Signature performance:** ML-DSA-65 signing and verification is measurably slower than ECDSA but faster than RSA-4096. On a modern server CPU (e.g., AWS c6i.xlarge), expect approximately:

| Operation | Approximate throughput |
|---|---|
| ML-DSA-65 key generation | ~5,000 ops/sec |
| ML-DSA-65 sign | ~3,000 ops/sec |
| ML-DSA-65 verify | ~4,000 ops/sec |
| ML-KEM-768 encapsulate | ~8,000 ops/sec |
| ML-KEM-768 decapsulate | ~8,000 ops/sec |

These figures are from the liboqs benchmark suite. Actual performance depends on hardware, platform, and whether the CPU supports AVX2 optimizations (which liboqs uses automatically when available).

**Handshake overhead:** The QASP-Shake handshake adds approximately one round-trip (2 × ML-DSA-65 verify + 1 × ML-KEM-768 encapsulate + 1 × ML-KEM-768 decapsulate) to connection establishment. For TCP, this adds roughly 1–5 ms of computation latency on typical server hardware.

---

## 4. Identity and Access Control

### 4.1 did:qasp Method Specification

The `did:qasp` DID method provides a self-sovereign, cryptographically bound identifier for each agent. It is implemented in `src/qasp/identity/did.py` and conforms to the W3C DID Core 1.0 specification.

**Method name:** `qasp`

**Identifier generation algorithm:**

```
1. Generate ML-DSA-65 keypair: (public_key, secret_key)
2. Compute digest = SHA-384(public_key)        # 48 bytes
3. Compute identifier_bytes = digest[0:32]     # first 32 bytes
4. Encode identifier = Base58btc(identifier_bytes)
5. DID = "did:qasp:" + identifier
```

Example DID: `did:qasp:2ZTp9sZYkJmQxR8nVwFdHcPbGeLyXuAo`

**Properties of the did:qasp identifier:**

- **Deterministic:** Given the same public key, the DID is always the same.
- **Collision-resistant:** SHA-384 with 256-bit output provides 128-bit collision resistance, sufficient for any anticipated registry size.
- **Self-verifying:** The DID document contains the public key; possession of the corresponding secret key proves control.
- **Compact:** Base58btc encoding of 32 bytes produces a ~43-character identifier, practical for HTTP paths and headers.

**DID resolution:** The `DIDRegistry` class maintains an in-memory mapping from DID string to DID document. Resolution is performed by `DIDRegistry.resolve(did_str)`, which returns the `DIDDocument` or raises `DIDNotFoundError`.

**Comparison with other DID methods:**

| DID Method | Key Algorithm | Persistence | QASP Compatible |
|---|---|---|---|
| did:key | Multiple (classical) | None (derived) | No (no PQ) |
| did:web | Classical PKI | DNS + HTTPS | No (no PQ) |
| did:ion | Classical PKI | Bitcoin | No (no PQ) |
| did:qasp | ML-DSA-65 | Authority registry | Native |

### 4.2 DID Document Structure

A QASP DID document conforms to W3C DID Core 1.0 and is serialized as JSON-LD. The following example shows the structure for a registered agent.

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://qasp.example.com/ns/qasp/v1"
  ],
  "id": "did:qasp:2ZTp9sZYkJmQxR8nVwFdHcPbGeLyXuAo",
  "verificationMethod": [
    {
      "id": "did:qasp:2ZTp9sZYkJmQxR8nVwFdHcPbGeLyXuAo#key-1",
      "type": "MldSa65VerificationKey2024",
      "controller": "did:qasp:2ZTp9sZYkJmQxR8nVwFdHcPbGeLyXuAo",
      "publicKeyBase64": "<base64-encoded ML-DSA-65 public key, 1952 bytes>"
    }
  ],
  "authentication": [
    "did:qasp:2ZTp9sZYkJmQxR8nVwFdHcPbGeLyXuAo#key-1"
  ],
  "assertionMethod": [
    "did:qasp:2ZTp9sZYkJmQxR8nVwFdHcPbGeLyXuAo#key-1"
  ],
  "service": [
    {
      "id": "did:qasp:2ZTp9sZYkJmQxR8nVwFdHcPbGeLyXuAo#qasp-authority",
      "type": "QASPAuthorityService",
      "serviceEndpoint": "https://qasp.example.com"
    }
  ]
}
```

The `verificationMethod` type `MldSa65VerificationKey2024` is a QASP-defined type for ML-DSA-65 verification keys. The public key is base64-encoded due to its size (1952 bytes); multibase encoding with the base64url prefix could be used in future versions for standards alignment.

### 4.3 Capability Token Architecture

QASP capability tokens are CBOR-encoded, ML-DSA-65 signed data structures that grant a specific agent (the subject) the right to perform specific actions (verbs) on specific resources (ARM URIs), subject to constraints, for a bounded time period.

The token model is derived from the Object Capabilities (OCap) security model, which provides unforgeable, composable, and attenuable access grants.

**Token fields:**

| Field | Type | Description |
|---|---|---|
| `token_id` | bytes (16) | Random 128-bit unique identifier |
| `issuer_did` | DID | Authority or parent token holder issuing this token |
| `subject_did` | DID | Agent who may use this token |
| `audience_did` | DID (optional) | Agent against whose resources this token is valid |
| `resource_uri` | str | ARM URI defining the resource scope |
| `verbs` | VerbSet | Set of permitted actions |
| `constraints` | Constraints | Rate limits, time bounds, purpose, quantity limits |
| `delegation_depth` | int | How many more levels of delegation are permitted |
| `authority_chain` | list | Chain of `AuthorityChainEntry` objects for delegation verification |
| `parent_token_id` | bytes (optional) | ID of the parent token in a delegation chain |
| `signature` | bytes | ML-DSA-65 signature over the CBOR-serialized token fields |

**Verbs:** The `VerbSet` is an ordered set drawn from the following defined verbs:

| Verb | Constant | Meaning |
|---|---|---|
| `exec` | `ARM_EXEC` | Execute a tool or function |
| `read` | `ARM_READ` | Read data from a resource |
| `write` | `ARM_WRITE` | Write data to a resource |
| `delegate` | `ARM_DELEGATE` | Delegate this capability to another agent |
| `attenuate` | `ARM_ATTENUATE` | Issue a narrower version of this capability |
| `revoke` | `ARM_REVOKE` | Revoke this token or its children |
| `charge` | `ARM_CHARGE` | Initiate a metered charge against this token |

**Constraints:**

```python
@dataclass
class Constraints:
    rate_limit: int | None          # Max operations per rate_period_seconds
    rate_period_seconds: int | None # Period for rate limit (default 60)
    not_before: datetime | None     # Token not valid before this time
    not_after: datetime | None      # Token expires at this time
    max_uses: int | None            # Maximum total uses
    purpose: str | None             # Semantic purpose tag
    quantity_limit: float | None    # Maximum quantity (e.g., tokens, bytes)
    quantity_unit: str | None       # Unit for quantity_limit
    spend_limit: float | None       # Maximum spend
    spend_currency: str | None      # Currency for spend_limit
    toolchain: list[str] | None     # Allowed toolchain identifiers
    temporal_schedule: TemporalSchedule | None  # Calendar-based validity
    temporal_threshold: TemporalThreshold | None # Time-window threshold
```

**CBOR encoding:** Tokens are serialized using `cbor2` with deterministic encoding. The CBOR representation is signed over (not the JSON or string form), ensuring canonical encoding for signature verification. The `to_cbor_with_signature()` method returns the full serialized token including the signature, ready for transmission. `from_cbor()` parses and reconstructs the token object without verifying the signature (verification requires the issuer's public key and is performed separately by `verify_token()`).

**Token verification (`verify_token()`):**

```python
def verify_token(
    token: CapabilityToken,
    issuer_public_key: bytes,
    check_expiry: bool = True,
    crl: RevocationChecker | None = None,
) -> None:
    # 1. Verify ML-DSA-65 signature over CBOR-encoded fields
    # 2. If check_expiry: verify not_before <= now <= not_after
    # 3. If crl: check token_id not in revocation list
    # Raises: InvalidTokenError, TokenExpiredError,
    #         TokenNotYetValidError, TokenRevokedError
```

### 4.4 ARM Resource URI Model

QASP defines a URI scheme for identifying agent resources, implemented in `src/qasp/protocol/arm.py`. The scheme follows an Access Rights Model (ARM) design where URIs identify resources and matching rules determine access scope.

**URI grammar (ABNF):**

```
arm-uri    = "qasp://" provider *("/" segment)
provider   = 1*(ALPHA / DIGIT / "-" / ".")
segment    = 1*(ALPHA / DIGIT / "-" / "_" / "." / "*")
```

**Constraints on wildcard placement:** The wildcard character `*` may only appear as the final path segment. A URI like `qasp://acme/*/tools` is invalid and will raise `InvalidARMUriError`.

**Examples of valid URIs:**

```
qasp://acme                          # Provider-level scope (all resources)
qasp://acme/gpu                      # Resource group
qasp://acme/gpu/a100                 # Specific resource
qasp://acme/gpu/*                    # All resources in gpu group (wildcard)
qasp://agents/2ZTp9s/tools/analyze  # Specific tool on specific agent
qasp://agents/2ZTp9s/tools/*        # All tools on specific agent
```

**Matching rules (evaluated in order):**

1. **Exact match:** `qasp://acme/gpu/a100` matches `qasp://acme/gpu/a100`
2. **Wildcard match:** `qasp://acme/gpu/*` matches `qasp://acme/gpu/a100` (wildcard covers exactly one additional segment)
3. **Prefix match:** `qasp://acme/gpu` matches `qasp://acme/gpu/a100` (token with shorter path covers resources at deeper paths)

**Attenuation rule:** A child token's URI is a valid attenuation of a parent token's URI if and only if `uri_matches(parent_uri, child_uri)` is true. This enforces the invariant that tokens can only narrow scope, never widen it.

**URI intersection:** The `intersect_uris(uri_a, uri_b)` function computes the most specific common scope of two URIs. This is used by the token aggregation algebra to find the effective resource scope when combining permissions from multiple tokens.

```
intersect_uris("qasp://acme/gpu", "qasp://acme/gpu/a100")
    -> "qasp://acme/gpu/a100"  (more specific wins)

intersect_uris("qasp://acme/gpu/*", "qasp://acme/network/*")
    -> None  (no overlap, different resource groups)

intersect_uris("qasp://acme/gpu/a100", "qasp://acme/gpu/h100")
    -> None  (different concrete resources)
```

### 4.5 Token Attenuation and Delegation

**Attenuation** produces a new token with the same or narrower rights from an existing token. The `attenuate_token()` function enforces three invariants:

1. The child's `resource_uri` must satisfy `is_attenuation(parent_uri, child_uri)` — scope can only narrow.
2. The child's `verbs` must be a subset of the parent's `verbs` — permissions can only be removed, not added.
3. The child's `delegation_depth` must be strictly less than the parent's — delegation chains are bounded.

**Delegation** is the act of transferring a capability to another agent. When agent A holds a token granting `ARM_DELEGATE` and issues a child token to agent B, agent B holds a token whose `authority_chain` includes an entry proving the chain of custody from the original issuer to B.

**Delegation chain verification:**

```
Authority (root issuer)
    |-- issues token T1 to Agent A (delegation_depth=3)
    |
    Agent A (holds T1)
        |-- attenuates T1 -> T2 for Agent B (delegation_depth=2)
        |
        Agent B (holds T2)
            |-- attenuates T2 -> T3 for Agent C (delegation_depth=1)
            |
            Agent C (holds T3, cannot further delegate)
```

Each `AuthorityChainEntry` in the chain contains:
- The issuer's DID
- The subject's (recipient's) DID
- The issuer's ML-DSA-65 signature over the sub-delegation

Verification of a delegated token requires validating each entry in the chain against the corresponding issuer's public key. This is performed by `verify_delegation_chain()`.

**Sub-invocation tokens:** The `create_sub_invocation_token()` function creates a single-use, narrowly scoped token for sub-calls made during a tool's execution. Sub-invocation tokens automatically set `delegation_depth=0` and inherit constraints from the parent token, with rate limits further restricted.

### 4.6 Multi-Owner Tokens

Multi-owner tokens require signatures from multiple principals before the token is considered valid. This models scenarios such as:

- A tool call that requires both the requesting agent and a human approver to authorize.
- A resource that two organizations jointly own, both of whom must consent.
- M-of-N threshold authorization schemes.

**Multi-owner token semantics differ from aggregation:**

| Feature | Multi-Owner Token | Token Aggregation |
|---|---|---|
| Verb combination | Intersection (all owners must agree) | Union (any token grants) |
| Purpose | Shared resource requiring co-authorization | Single agent with multiple grants |
| Signature count | N signatures required | 1 signature per token |
| Use case | Joint resource ownership | Combining permissions from different providers |

The `create_multi_owner_token()` function creates a token structure that requires a minimum number of owner signatures. `MultiOwnerCapabilityToken.validate()` checks that the required signature threshold is met before returning a valid token.

**SPIFFE attestation integration:** The `CompositeMultiOwnerToken` (in `src/qasp/protocol/spiffe_attestation.py`) extends multi-owner tokens with platform attestation entries. Each entry records the SPIFFE SVID and platform attestation (TPM measurements, UEFI secure boot status, etc.) of the signing principal at the time of signing. This enables hardware-bound authorization that verifies not just who authorized the action, but from which attested platform.

---

## 5. Trust and Reputation Framework

### 5.1 Bayesian Trust Scoring

QASP models agent reputation using a Bayesian approach based on the Beta distribution. This approach is well-suited to the reputation domain because it:

- Produces naturally bounded scores in [0, 1].
- Quantifies uncertainty (new agents have high uncertainty, well-tested agents have lower uncertainty).
- Updates incrementally as new observations arrive.
- Converges to the true underlying success rate with sufficient data.

**Beta distribution model:**

The reputation of an agent is modeled as a Beta distribution `Beta(alpha, beta)` where:

- `alpha = 1 + successful_interactions` (successes + 1 prior)
- `beta = 1 + failed_interactions` (failures + 1 prior)

The prior `(alpha=1, beta=1)` corresponds to a uniform distribution over [0, 1] — maximum uncertainty, no initial trust or distrust. The expected value of `Beta(alpha, beta)` is `alpha / (alpha + beta)`, which is the point estimate used as the reputation score.

A new agent with zero interactions has `reputation_score = 1 / 2 = 0.5`, reflecting maximum uncertainty at the neutral midpoint. After 10 successful interactions and 0 failures, `reputation_score = 11 / 12 = 0.917`. After 5 successful and 5 failed interactions, `reputation_score = 6 / 12 = 0.5` (back to the neutral point, now with less uncertainty).

### 5.2 Component Weights and Cold-Start

The overall trust score combines four components, each weighted independently:

```
overall_score =
    w_interaction  * reputation_component     +  (0.35)
    w_witness      * witness_component        +  (0.25)
    w_cert         * certification_component  +  (0.20)
    w_behavioral   * behavioral_component        (0.20)
```

**Component descriptions:**

| Component | Weight | Source | Description |
|---|---|---|---|
| Reputation | 0.35 | Interaction outcomes | Bayesian Beta distribution over reported successes/failures |
| Witness | 0.25 | Peer observations | Third-party agents reporting on observed behavior |
| Certification | 0.20 | W3C VC audit certs | SLSA supply chain level, security audit attestations |
| Behavioral | 0.20 | Protocol analysis | Compliance with rate limits, proper error handling, protocol conformance |

**Confidence scaling:** The overall score is multiplied by a confidence factor that increases with interaction count:

```python
confidence = min(1.0, interaction_count / 50.0)
```

This means a new agent with 0 interactions has `confidence = 0.0`, and the returned score reflects the prior (0.5) scaled to zero confidence. An agent with 50+ interactions has `confidence = 1.0` and the score is fully expressed. This cold-start mechanism prevents new agents from having artificially high trust scores based on limited data.

**Score calculation:**

```python
class TrustScore:
    overall: float              # Final composite score
    reputation_component: float # Contribution from Beta distribution
    certification_component: float
    behavioral_component: float
    witness_component: float
    confidence: float           # Data reliability [0, 1]
```

### 5.3 Anti-Gaming Caps

To prevent trust score manipulation through artificial inflation, QASP applies interaction-count-based caps on the maximum achievable trust score:

| Interaction Count | Maximum Trust Score |
|---|---|
| < 10 | 0.70 |
| 10 – 49 | 0.80 |
| 50 – 199 | 0.90 |
| 200+ | 1.00 |

These caps mean that a newly registered agent cannot achieve a trust score above 0.70 regardless of the certification and behavioral components. The cap ceiling increases as the agent accumulates genuine interaction history, reaching uncapped scoring only after 200 verified interactions.

**Anti-gaming rationale:** Without these caps, an attacker could:
1. Register an agent with fraudulent W3C VC certifications.
2. Achieve a high certification component immediately.
3. Use the high trust score to access sensitive resources before any interaction history exists.

The caps ensure that trust scores above 0.70 require documented operational history.

### 5.4 Collusion Detection

QASP's trust framework includes collusion detection to identify coordinated reputation inflation, where a group of agents mutually report successful interactions to artificially inflate each other's scores.

Collusion indicators tracked:

- **Reciprocal reporting frequency:** If agent A reports success for agent B at a rate disproportionate to A's total interaction volume, and B reports success for A at a similar rate, this is flagged as potential collusion.
- **Closed-group interaction concentration:** If an agent's successful interactions come predominantly from a small set of other agents (high Gini coefficient of interaction sources), this triggers review.
- **Temporal clustering:** Multiple success reports from different agents about the same target within a short time window may indicate coordinated inflation.

When collusion is detected, the affected reports are down-weighted in the reputation calculation. The behavioral component may also be penalized. Severe collusion can trigger a dispute or administrative review.

### 5.5 SLSA Certification Integration

QASP integrates with the SLSA (Supply chain Levels for Software Artifacts) framework through W3C Verifiable Credential audit certificates, implemented in `src/qasp/trust/certification.py`.

SLSA levels relevant to QASP deployments:

| SLSA Level | Requirement | QASP Effect |
|---|---|---|
| SLSA 1 | Build process documented | Base certification score |
| SLSA 2 | Build service produces provenance | Moderate certification score |
| SLSA 3 | Source and build are verified | High certification score |
| SLSA 4 | Two-party review, hermetic builds | Maximum certification score |

An agent's SLSA certification is recorded as a W3C Verifiable Credential, signed by a SLSA auditor. The credential is submitted to the authority server, which verifies the credential signature and updates the agent's `certification_component` in the trust score.

The VC structure for a SLSA certification:

```json
{
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  "type": ["VerifiableCredential", "SLSACertification"],
  "issuer": "did:web:slsa-auditor.example.com",
  "issuanceDate": "2026-03-01T00:00:00Z",
  "expirationDate": "2027-03-01T00:00:00Z",
  "credentialSubject": {
    "id": "did:qasp:2ZTp9sZYkJmQxR8nVwFdHcPbGeLyXuAo",
    "slsaLevel": 3,
    "artifactDigest": "sha384:...",
    "builderIdentity": "https://github.com/actions/runner"
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "ecdsa-rdfc-2019",
    "verificationMethod": "did:web:slsa-auditor.example.com#key-1",
    "proofValue": "..."
  }
}
```

Note: SLSA auditor VCs currently use classical signature schemes (ECDSA) because SLSA auditors have not yet transitioned to PQ signatures. QASP accepts classically-signed VCs for certification but does not rely on them for security properties — they contribute to the certification component of the trust score, which has a 0.20 weight, and are bounded by the anti-gaming caps.

---

## 6. Revocation and Status

### 6.1 Certificate Revocation List

The `CertificateRevocationList` class in `src/qasp/protocol/revocation.py` is the authoritative store of revoked tokens. Every token issued by the authority server is registered in the CRL at issuance time, so its status can be queried independently of whether the token itself is presented.

**Revocation reasons (8 defined codes):**

| Reason Code | Constant | Description |
|---|---|---|
| 0 | `UNSPECIFIED` | General revocation, no specific reason given |
| 1 | `KEY_COMPROMISE` | Issuing key is believed to be compromised |
| 2 | `CA_COMPROMISE` | Authority key is compromised |
| 3 | `AFFILIATION_CHANGED` | Agent's organizational affiliation changed |
| 4 | `SUPERSEDED` | Token replaced by a newer token |
| 5 | `CESSATION_OF_OPERATION` | Agent permanently decommissioned |
| 6 | `CERTIFICATE_HOLD` | Temporary suspension |
| 7 | `OWNER_REQUEST` | Token holder voluntarily revoked the token |

The authority server uses `OWNER_REQUEST` with `CRITICAL` urgency when processing `POST /tokens/revoke` requests.

**RevocationEntry structure:**

```python
@dataclass
class RevocationEntry:
    token_id: bytes              # 16-byte token identifier
    reason: RevocationReason     # One of the 8 reason codes
    urgency: RevocationUrgency   # NORMAL or CRITICAL
    revoked_at: float            # Unix timestamp
    revoker_did: str             # DID of the revoking principal
    revoker_signature: bytes     # ML-DSA-65 signature over revocation data
    grace_period_ends_at: float  # When the grace period expires
    parent_token_id: bytes | None # Parent in delegation chain (for cascade)
```

Each revocation entry is signed by the revoker using ML-DSA-65. This ensures that revocation records are non-repudiable: the revoker cannot later deny having issued the revocation, and an attacker cannot fabricate revocation entries without the revoker's secret key.

**Checking revocation:** The `check_revocation(crl, token_id)` function is called during `verify_token()` when a `RevocationChecker` (the CRL) is provided. It returns the `RevocationEntry` if the token is revoked (after any applicable grace period), or `None` if the token is valid.

### 6.2 BFS Cascade Revocation

When a token in a delegation chain is revoked, all descendant tokens must also be revoked. QASP implements this using a breadth-first search (BFS) over the parent–child relationship graph maintained by the CRL.

**Algorithm:**

```
Input: token_id to revoke, reason, urgency

1. Add revocation entry for token_id
2. Initialize queue = [token_id]
3. While queue is not empty:
   a. current = queue.dequeue()
   b. children = crl.find_children(current)
      (tokens with parent_token_id == current)
   c. For each child:
      - Add revocation entry for child (inherited reason)
      - Enqueue child
4. Return all created RevocationEntry objects
```

This guarantees that revocation is complete: no orphaned child token can remain valid after its parent is revoked. The cascade is atomic within the CRL's in-memory state — either all entries are created or none are (via exception rollback).

**Cascade depth limits:** To prevent infinite loops in pathological delegation graphs (which should not occur in a correct implementation but are defended against), the BFS implementation maintains a visited set and halts if the same token ID is encountered twice.

**Example cascade:**

```
Authority issues T1 to Agent A (depth=3)
Agent A delegates T2 to Agent B (depth=2, parent=T1)
Agent B delegates T3 to Agent C (depth=1, parent=T2)

Revoking T1 triggers cascade:
  - T1 revoked (direct)
  - T2 revoked (child of T1)
  - T3 revoked (child of T2)
All three tokens are simultaneously invalid after cascade.
```

### 6.3 OCSP Responder

The `OCSPResponder` in `src/qasp/protocol/ocsp.py` provides real-time token status queries without requiring the full CRL to be transmitted. Clients query the status of a specific token by its ID, and receive a signed response indicating GOOD, REVOKED, or UNKNOWN.

**OCSP request structure:**

```python
@dataclass
class OCSPRequest:
    token_id: bytes    # 16-byte token identifier
    nonce: bytes       # Random nonce for replay protection (OCSP_NONCE_SIZE bytes)
```

**OCSP response structure:**

```python
@dataclass
class OCSPResponse:
    token_id: bytes
    status: OCSPStatus              # GOOD, REVOKED, or UNKNOWN
    this_update: float              # Response generation timestamp
    next_update: float              # When to re-check (this_update + TTL)
    revocation_time: float | None   # Set if status is REVOKED
    nonce: bytes                    # Echo of request nonce
    responder_did: str              # Signing authority's DID
    signature: bytes                # ML-DSA-65 signature over response fields
```

**Response caching:** The OCSP responder maintains a response cache with a 600-second (10-minute) TTL. When the same token ID is queried within the TTL window, the cached response is returned without re-querying the CRL. This is appropriate for GOOD responses; revocation entries immediately invalidate the cache via `OCSPResponder.invalidate(token_id)`.

**Nonce replay protection:** Each OCSP request includes a random nonce. The responder tracks recently-seen nonces in a bounded set (sliding window). Duplicate nonces within the window raise `OCSPNonceMismatchError`, preventing replay attacks where an attacker reuses a captured GOOD response.

**Response validity window:** By default, OCSP responses are valid for `DEFAULT_RESPONSE_VALIDITY_SECONDS = 600` seconds. The `next_update` field tells the client when to re-query. Clients should not cache OCSP responses beyond `next_update`.

### 6.4 OCSP Stapling

OCSP stapling allows a server (e.g., an agent offering a tool) to pre-fetch its own OCSP status and attach ("staple") it to capability tokens, eliminating the need for callers to make a separate OCSP query.

**Stapling flow:**

```
1. Agent pre-fetches OCSP response for its own token:
   request = create_ocsp_request(token_id)
   response = ocsp_responder.handle_request(request)

2. Agent creates a stapled response:
   stapled = staple_response(token, response)
   # Returns StapledOCSPResponse(token, ocsp_response)

3. Agent presents the stapled response to callers.

4. Caller verifies the stapled response:
   verify_stapled_response(stapled, authority_public_key)
   # Checks:
   #   - OCSP response signature is valid (ML-DSA-65)
   #   - OCSP response is for this specific token
   #   - OCSP response is not expired (next_update > now)
   #   - OCSP status is GOOD
```

Stapling is particularly useful in high-frequency tool call scenarios where the overhead of a separate OCSP query for every invocation is prohibitive. The stapled response is valid for up to `DEFAULT_RESPONSE_VALIDITY_SECONDS` (600s), during which the tool can serve calls without requiring callers to contact the OCSP responder.

**Stapling and QUIC 0-RTT:** When combined with QUIC transport's 0-RTT session resumption, stapled OCSP responses allow callers to resume sessions and present pre-validated tokens in the first flight of data, achieving near-zero authentication overhead for repeat interactions.

### 6.5 Grace Periods and Urgency

Revocation does not always take effect immediately. QASP defines two urgency levels that determine how quickly a revocation is enforced:

| Urgency | Constant | Grace Period | Use Case |
|---|---|---|---|
| NORMAL | `RevocationUrgency.NORMAL` | 300 seconds (5 minutes) | Routine revocations (key rotation, superseded tokens) |
| CRITICAL | `RevocationUrgency.CRITICAL` | 0 seconds (immediate) | Compromise, fraud, emergency suspension |

**Grace period semantics:** During the grace period, a revoked token is still considered valid by `check_revocation()`. After the grace period ends, the token is rejected. This gives active sessions time to complete normally before a routine revocation takes effect.

For `CRITICAL` urgency revocations (0-second grace period), `check_revocation()` returns the `RevocationEntry` immediately, causing immediate rejection of any presentation of the token.

**OCSP cache and grace periods:** When a CRITICAL revocation is issued, `OCSPResponder.invalidate()` is called immediately to purge the OCSP cache for that token. This ensures that OCSP queries made after the revocation return REVOKED status without waiting for the cache TTL to expire.

For NORMAL urgency revocations, the OCSP cache is not immediately invalidated. The cache will naturally expire within 600 seconds, and the next query will reflect the revoked status.

---

## 7. Rate Limiting and Metering

### 7.1 Token Bucket Algorithm

QASP implements the standard token bucket algorithm in `src/qasp/protocol/rate_limiter.py`. The token bucket is well-suited to the QASP use case because it permits short bursts of calls (up to the bucket capacity) while enforcing a long-term average rate (the refill rate).

**Algorithm description:**

```
State:
  tokens_available: float   # Current token count [0, capacity]
  last_refill: monotonic    # Timestamp of last refill

On each request:
  elapsed = now() - last_refill
  tokens_available = min(capacity, tokens_available + elapsed * refill_rate)
  last_refill = now()

  if tokens_available >= 1:
    tokens_available -= 1
    return ALLOWED
  else:
    retry_after = (1 - tokens_available) / refill_rate
    return DENIED (retry_after seconds)
```

**Parameters:**

- `capacity`: Maximum number of tokens in the bucket. This is set from `Constraints.rate_limit`. Default: 10 (authority server default).
- `refill_rate`: Tokens added per second. Computed as `rate_limit / rate_period_seconds`. For the default (10 per 60s), refill rate is `10/60 ≈ 0.167 tokens/second`.

**Burst behavior:** A bucket starting full allows up to `capacity` consecutive calls with no delay. For the default configuration (capacity=10, refill_rate=0.167/s), an agent can make 10 calls immediately upon receiving a token, then must wait approximately 6 seconds between subsequent calls.

**Thread safety:** `TokenBucketRateLimiter` uses `threading.Lock` around all state mutations. The `_refill()` method is called at the start of every `consume()` or `consume_or_raise()` call while the lock is held, ensuring that elapsed time is correctly accounted for under concurrent access.

**Retry-after calculation:** When a request is denied, `RateLimitExceededError.retry_after` provides the caller with the precise number of seconds to wait before the bucket will have sufficient tokens:

```python
deficit = n - self._tokens           # How many tokens are needed
retry_after = deficit / self._refill_rate  # Seconds until replenishment
```

### 7.2 Per-Token Enforcement

The `RateLimiterRegistry` maintains one `TokenBucketRateLimiter` instance per token ID. This ensures that rate limits are enforced per token, not per caller or per tool.

**Registry lifecycle:**

```python
class RateLimiterRegistry:
    _limiters: dict[bytes, _LimiterEntry]  # token_id -> LimiterEntry
    _lock: threading.Lock

    def get_or_create(
        self,
        token_id: bytes,
        rate_limit: int,
        rate_period_seconds: int = 3600,
    ) -> TokenBucketRateLimiter:
        # Creates limiter on first access; returns existing on subsequent access
        # refill_rate = rate_limit / rate_period_seconds

    def remove(self, token_id: bytes) -> bool:
        # Call when a token is revoked or expired

    def cleanup_expired(self, max_age_seconds: float = 7200.0) -> int:
        # Remove limiters older than 2 hours (GC)
```

**Per-token enforcement implications:**

- If agent A and agent B both hold tokens granting 10 calls/60s to the same tool, they each have their own bucket. A's burst does not affect B's available capacity.
- If agent A holds two different tokens to the same tool (e.g., one from the authority and one delegated), each token has its own bucket. A can potentially make calls using either token.
- Revoking a token should be accompanied by calling `registry.remove(token_id)` to free the bucket. In the authority server, revocation invalidates the token in the CRL; the rate limiter entry will be cleaned up by `cleanup_expired()` if not explicitly removed.

**Global registry:** A module-level singleton `_global_registry` is accessible via `get_rate_limiter_registry()`. This singleton is used by the authority server to maintain a single shared registry across all request handlers.

### 7.3 Usage Metering

Every successful tool call through the authority server generates a metering record. In v0.1.0, metering is stored in-memory per agent in `AgentRecord.metering`.

**Metering record structure:**

```python
{
    "receipt_id": str,      # UUID hex - unique receipt identifier
    "tool": str,            # Tool name called
    "target": str,          # Target agent DID
    "timestamp": str,       # ISO 8601 UTC timestamp
    "units": int,           # Service units consumed (currently 1 per call)
    "cost": int,            # Cost in currency units (currently 10 credits)
    "currency": str,        # Currency (currently "credits")
}
```

**Settlement integration:** The protocol layer (`src/qasp/protocol/settlement.py`) implements a full payment channel mechanism (`PaymentChannel`, `PriceNegotiator`, `PriceSchedule`) for settling metered costs between agents. This allows agents to:

1. Open a payment channel with a defined balance.
2. Negotiate per-call prices using `PriceNegotiator`.
3. Record signed `ChannelStateUpdate` objects as calls are made.
4. Close the channel cooperatively with a final signed state, or unilaterally after a challenge period.

The settlement layer is implemented in the protocol module but is not yet exposed through the authority server REST API in v0.1.0. It is available for direct use via the Python library.

**Reconciliation:** The `ReconciliationSession` in `src/qasp/protocol/reconciliation.py` provides a mechanism for two agents to compare their independently maintained ledgers and resolve divergences. It detects discrepancies using `DivergenceDetector` and resolves them via `ResolutionMethod` (automatic correction, arbitration, or manual review), with a configurable tolerance floor (`DEFAULT_TOLERANCE_FLOOR`) and tolerance percentage (`DEFAULT_TOLERANCE_PERCENT`).

---

## 8. Transport Layer

### 8.1 TCP Transport

The TCP transport in `src/qasp/transport/tcp.py` provides a reliable, ordered byte stream over standard TCP connections. It uses asyncio for non-blocking I/O.

**Framing protocol:** Messages are length-prefixed using a 4-byte big-endian unsigned integer header:

```
+--------+--------+--------+--------+----...----+
|       LENGTH (4 bytes, big-endian)  |  PAYLOAD  |
+--------+--------+--------+--------+----...----+
```

Constants:
- `LENGTH_PREFIX_SIZE = 4` bytes
- `MAX_MESSAGE_SIZE = 16 * 1024 * 1024` (16 MiB)
- `DEFAULT_READ_SIZE = 4096` bytes

The 16 MiB maximum message size prevents memory exhaustion from malformed or malicious oversized frames. Messages exceeding this limit raise `FramingError`.

**Key classes:**

- `TCPTransport`: Client-side transport. Use `connect(host, port)` to establish a connection. Provides `send(data)` and `receive()` as async methods.
- `TCPServer`: Server-side listener. Use `listen(host, port)` or `serve(host, port, handler)` to accept connections. The `handler` callback is invoked for each new connection.

**Connection to protocol state machine:** The TCP transport passes raw bytes to a `QASPConnection` state machine and sends bytes produced by the state machine. The transport has no knowledge of QASP protocol semantics; it is responsible only for reliable delivery and framing.

### 8.2 QUIC Transport

The QUIC transport in `src/qasp/transport/quic.py` provides a multiplexed, 0-RTT capable transport over UDP. It is implemented using the `aioquic` library.

**Configuration:**

| Parameter | Value | Source |
|---|---|---|
| Default port | 4443 | `DEFAULT_QUIC_PORT` |
| ALPN protocol | `"qasp/1"` | `QuicConfiguration.alpn_protocols` |
| Idle timeout | 30 seconds | `IDLE_TIMEOUT` |
| Max datagram size | 65,536 bytes | `MAX_DATAGRAM_SIZE` |
| TLS verify mode | `CERT_NONE` | QASP-level auth via DID/token |

**ALPN negotiation:** The Application-Layer Protocol Negotiation identifier `"qasp/1"` ensures that a QASP QUIC connection can be distinguished from other QUIC traffic on the same port. A server can multiplex QASP and other QUIC applications by inspecting the ALPN during handshake.

**0-RTT session resumption:** The `QASPQuicClient.connect()` method accepts an optional `session_ticket` parameter. When provided, the QUIC connection uses 0-RTT data to send the first application message immediately, without waiting for the full TLS 1.3 handshake to complete. This reduces connection setup latency from ~1 RTT to ~0 RTT for repeat connections to the same server.

**Security model:** TLS certificate verification is disabled (`ssl.CERT_NONE`) at the QUIC layer because QASP authentication is performed at the application layer via DID-bound capability tokens. This is architecturally clean but requires that QASP token verification is always performed before any application data is acted upon.

**Optional dependency:** `aioquic` is a soft dependency. The `quic.py` module can be loaded even if `aioquic` is not installed. Attempting to use `QASPQuicClient` or `QASPQuicServer` without aioquic installed raises an `ImportError` with a clear installation instruction.

**Stream management:** Each QASP connection over QUIC uses a single bidirectional stream. Multiple concurrent QASP connections (each representing a different agent interaction) are multiplexed over the same underlying QUIC connection. This eliminates head-of-line blocking (a limitation of TCP) for concurrent agent-to-agent interactions.

### 8.3 Service Discovery

The `DiscoveryClient` and `DiscoveryServer` in `src/qasp/transport/discover.py` implement mDNS-based service discovery using the `zeroconf` library.

**mDNS service type:** `_qasp._tcp.local.` (constant: `MDNS_SERVICE_TYPE`)

**Discovery flow:**

```
Agent starting up:
  1. Creates DiscoveryServer with own capabilities
  2. Broadcasts capability advertisement via mDNS
  3. Advertisement includes: DID, tools, ARM URIs, endpoint

Agent looking for peers:
  1. Creates DiscoveryClient
  2. Browses for _qasp._tcp.local. services
  3. Receives ServiceEndpoint objects for each discovered agent
  4. Verifies CapabilityAdvertisement signatures (ML-DSA-65)
  5. Filters by capability pattern or trust score

Timeouts:
  DEFAULT_DISCOVERY_TIMEOUT  # Maximum time to wait for peers
  DEFAULT_AD_TTL             # How long an advertisement is cached
```

**Capability advertisement structure:**

```python
@dataclass
class CapabilityAdvertisement:
    did: str                   # Advertising agent's DID
    endpoint: str              # Connection endpoint (host:port)
    capabilities: list[str]   # ARM URIs of advertised tools
    timestamp: float           # Advertisement creation time
    signature: bytes           # ML-DSA-65 signature over fields
```

**Advertisement verification:** Each received advertisement is verified against the advertiser's ML-DSA-65 public key (resolved from the DID document). This prevents spoofed advertisements where a malicious agent impersonates another agent's identity. `verify_advertisement()` raises `AdvertisementError` if verification fails.

**Well-known path:** For non-mDNS environments (e.g., across network segments where multicast is not available), the `WELL_KNOWN_PATH` constant defines an HTTP path (`/.well-known/qasp`) where agents can publish their capability advertisement as a JSON document. Clients can fetch this path directly if they know the agent's HTTP endpoint.

**Agent Registry:** The `AgentRegistry` in `src/qasp/transport/registry.py` provides a more structured alternative to mDNS discovery. It maintains a signed registry of agent entries with capability indexes, supports rich queries via `RegistryQuery`, and enforces TTL-based expiry (`DEFAULT_REGISTRY_TTL`). It is suitable for datacenter deployments where mDNS is not available. Results are bounded by `MAX_QUERY_RESULTS`.

### 8.4 Protocol Bridges

QASP provides two protocol bridges that allow QASP-secured communication between agents using different protocol stacks.

**MCP Bridge (`src/qasp/bridges/mcp_bridge.py`):**

The Model Context Protocol (MCP) bridge integrates QASP with the MCP tool ecosystem. It exposes MCP tools as QASP-addressable resources (ARM URIs) and enforces QASP capability token verification before forwarding MCP tool calls.

Key behaviors:
- MCP tool definitions are automatically mapped to ARM URIs: `qasp://mcp/{server_name}/tools/{tool_name}`
- Incoming tool calls present a QASP capability token; the bridge verifies the token before forwarding to the MCP server
- The bridge is bidirectional: a QASP agent can expose an MCP interface, and an MCP client can access QASP-secured tools

**A2A Bridge (`src/qasp/bridges/a2a_bridge.py`):**

The Agent-to-Agent (A2A) bridge integrates with Google's A2A protocol. It wraps A2A task execution with QASP token verification and audit logging.

Key behaviors:
- A2A tasks are represented as QASP resources: `qasp://a2a/{agent_url}/tasks/{task_type}`
- QASP capability tokens are verified before task delegation
- Metering records are generated for each delegated task
- The bridge maintains an audit trail of all A2A interactions

**Bridge security model:** Both bridges enforce the full QASP verification pipeline (signature verification, expiry check, CRL check, ARM URI scope check, verb check, rate limiting) before passing any request to the downstream protocol. The bridges act as policy enforcement points for heterogeneous agent ecosystems.

---

## 9. Authority Server API Reference

### 9.1 Authentication Model

The QASP authority server uses a two-tier authentication model:

**Tier 1 — API Key Authentication:** After registration, each agent receives a `api_key` (UUID hex string). This key must be included in the `X-API-Key` HTTP header for all authenticated endpoints. The API key is a session credential that proves the agent registered with the authority.

```
X-API-Key: f47ac10b58cc4372a5670e02b2c3d479
```

**Tier 2 — Capability Token Authorization:** For tool calls, the agent must additionally present a QASP capability token obtained from `POST /tokens/request`. This token is passed in the request body (not a header), base64-encoded. The token is cryptographically verified by the server before the call is relayed.

**Unauthenticated endpoints:** `GET /`, `GET /features`, `GET /tokens/status/{token_id}`, `GET /trust/{did}`, and `GET /disputes/{dispute_id}` do not require authentication. These are intentionally public to allow status queries without requiring registration.

**Security note:** In production, the authority server must be deployed behind HTTPS (TLS 1.3 recommended). The API key is a bearer credential and is vulnerable to interception over plain HTTP.

### 9.2 Endpoint Reference

#### GET /

Returns server identity and feature list.

```
Response 200:
{
  "name": "QASP Authority",
  "version": "0.1.0",
  "did": "did:qasp:<authority-id>",
  "agents_registered": <int>,
  "features": ["ML-DSA-65 post-quantum signatures", ...]
}
```

No authentication required.

---

#### GET /features

Returns a structured list of supported QASP features.

```
Response 200: [
  {"id": "did", "name": "Decentralised Identity", "description": "..."},
  {"id": "capability", "name": "Capability Tokens", "description": "..."},
  {"id": "arm", "name": "ARM URI Scoping", "description": "..."},
  {"id": "rate_limit", "name": "Rate Limiting", "description": "..."},
  {"id": "revocation", "name": "Token Revocation", "description": "..."},
  {"id": "ocsp", "name": "OCSP Status", "description": "..."},
  {"id": "trust", "name": "Trust Scoring", "description": "..."},
  {"id": "dispute", "name": "Dispute Resolution", "description": "..."},
  {"id": "relay", "name": "Tool Call Relay", "description": "..."},
  {"id": "metering", "name": "Usage Metering", "description": "..."}
]
```

No authentication required.

---

#### POST /register

Registers a new agent with the authority. Generates an ML-DSA-65 keypair and a `did:qasp` DID for the agent. Assigns ARM URIs to each declared tool.

```
Request body:
{
  "name": "string",           // Human-readable agent name
  "tools": [                  // Optional; can be empty []
    {
      "name": "string",       // URL-safe tool identifier
      "description": "string",
      "input_schema": {}      // Optional JSON Schema
    }
  ],
  "callback_url": "string"    // Optional; for receiving tool calls
}

Response 200:
{
  "agent_id": "hex-string",
  "did": "did:qasp:...",
  "api_key": "hex-string",    // Store securely; used as X-API-Key
  "public_key": "base64"      // ML-DSA-65 public key (1952 bytes encoded)
}
```

**Tool ARM URI assignment:** For each declared tool, the server assigns:
`qasp://agents/{did[0:12]}/tools/{tool_name}`

No authentication required. The returned `api_key` is the credential for all subsequent authenticated requests.

---

#### GET /discover

Returns a list of registered agents, sorted by trust score descending. Supports filtering by capability pattern and minimum trust score.

```
Query parameters:
  capability: string  // ARM URI pattern filter (default: "*")
  min_trust: float    // Minimum trust score filter (default: 0.0)

Request header: X-API-Key required

Response 200: [
  {
    "name": "string",
    "did": "did:qasp:...",
    "tools": [
      {
        "name": "string",
        "description": "string",
        "input_schema": {},
        "resource_uri": "qasp://..."
      }
    ],
    "trust_score": 0.0–1.0,
    "endpoint": "string"     // callback_url or "(relay via server)"
  }
]
```

The `capability` parameter uses ARM URI matching: `uri_matches(capability, tool_resource_uri)` is called for each tool. Pass `qasp://*/tools/analyze` to find all agents exposing an `analyze` tool.

---

#### POST /tokens/request

Issues a QASP capability token authorizing the caller to invoke a specific tool on a specific target agent.

```
Request header: X-API-Key required

Request body:
{
  "target_did": "did:qasp:...",
  "tool_name": "string",
  "verbs": ["exec"]           // Optional; defaults to ["exec"]
}

Response 200:
{
  "token": "base64-string",   // CBOR-encoded signed token; pass to /tools/call
  "token_id": "hex-string",   // For revocation and status queries
  "resource_uri": "qasp://...",
  "verbs": ["exec"],
  "expires_at": "ISO-8601"    // 1 hour from issuance
}
```

**Default constraints applied:**
- `rate_limit = 10` calls
- `rate_period_seconds = 60` seconds
- `validity_seconds = 3600` (1 hour)

The token is issued by the authority (not the caller). The authority signs with its root ML-DSA-65 secret key. The subject (beneficiary) is the calling agent; the audience is the target agent.

---

#### POST /tokens/revoke

Revokes a previously issued token with immediate (CRITICAL urgency) effect. Triggers BFS cascade revocation for any child tokens. Invalidates the OCSP cache.

```
Request header: X-API-Key required

Request body:
{
  "token_id": "hex-string"    // From POST /tokens/request response
}

Response 200:
{
  "revoked": true,
  "token_id": "hex-string",
  "entries_created": <int>    // Total revocation entries (1 + cascade count)
}

Error 400: Token not found, already revoked, or invalid token_id format
```

---

#### GET /tokens/status/{token_id}

Queries the real-time revocation status of a token using the OCSP responder.

```
Path parameter: token_id (hex string)

No authentication required

Response 200:
{
  "token_id": "hex-string",
  "status": "GOOD" | "REVOKED" | "UNKNOWN",
  "revoked_at": "ISO-8601"   // Only present if status is REVOKED
}
```

OCSP responses are cached for 600 seconds. The OCSP response is ML-DSA-65 signed by the authority; the raw signed response is not exposed through this endpoint (see the protocol layer OCSP API for raw signed responses suitable for stapling).

---

#### POST /tools/call

Executes a 7-step verified tool call. Verifies the capability token, enforces rate limits, relays the call to the target agent's callback URL, records metering data, and updates trust scores.

```
Request header: X-API-Key required

Request body:
{
  "target_did": "did:qasp:...",
  "tool_name": "string",
  "arguments": {},            // Arbitrary JSON arguments for the tool
  "token": "base64-string"    // Token from POST /tokens/request
}

Response 200:
{
  "result": {},               // JSON response from target agent
  "metering": {
    "units": 1,
    "cost": 10,
    "currency": "credits"
  },
  "receipt_id": "hex-string"
}

Errors:
  400: Invalid token encoding
  403: Token invalid (expired, revoked, wrong scope, missing verb)
  404: Target agent or tool not found
  429: Rate limit exceeded (includes retry_after in detail message)
```

See Section 9.4 for the detailed 7-step verification sequence.

---

#### GET /trust/{did}

Returns the computed trust score for an agent identified by DID.

```
Path parameter: did (did:qasp:... string)

No authentication required

Response 200:
{
  "score": 0.0–1.0,
  "interaction_count": <int>,
  "components": {
    "reputation": 0.0–1.0,
    "certification": 0.0–1.0,
    "behavioral": 0.0–1.0,
    "witness": 0.0–1.0,
    "confidence": 0.0–1.0
  }
}
```

An agent with no interaction history returns `{"score": 0.5, "interaction_count": 0, "components": {}}`.

---

#### POST /trust/{did}/report

Submits an interaction outcome report for an agent. Updates the target agent's Bayesian reputation score.

```
Path parameter: did (target agent DID)
Request header: X-API-Key required

Request body:
{
  "outcome": "success" | "failure",
  "details": "string"    // Optional description
}

Response 200:
{
  "did": "did:qasp:...",
  "outcome": "success",
  "updated_trust": { <same as GET /trust/{did} response> }
}
```

---

#### POST /disputes/open

Opens a dispute against another agent. Creates a dispute record with OPEN status.

```
Request header: X-API-Key required

Request body:
{
  "respondent_did": "did:qasp:...",
  "type": "overcharge" | "service_failure" | "unauthorized_access" | "other",
  "description": "string"
}

Response 200:
{
  "dispute_id": "hex-string",
  "status": "OPEN"
}
```

---

#### GET /disputes/{dispute_id}

Returns the current state of a dispute.

```
Path parameter: dispute_id (hex string)

No authentication required

Response 200:
{
  "dispute_id": "hex-string",
  "claimant_did": "did:qasp:...",
  "respondent_did": "did:qasp:...",
  "type": "string",
  "description": "string",
  "status": "OPEN" | "RESOLVED" | "DISMISSED",
  "opened_at": "ISO-8601",
  "verdict": null | "string"
}
```

### 9.3 Error Codes

All error responses follow the FastAPI default error format:

```json
{ "detail": "Human-readable error message" }
```

| HTTP Status | Meaning | Common Causes |
|---|---|---|
| 400 Bad Request | Malformed request | Invalid token encoding, hex parse failure, already-revoked token |
| 401 Unauthorized | Missing or invalid API key | No `X-API-Key` header, unrecognized key |
| 403 Forbidden | Authorization failure | Expired token, revoked token, ARM scope mismatch, missing verb |
| 404 Not Found | Resource not found | Unknown agent DID, unknown tool name, unknown dispute ID |
| 429 Too Many Requests | Rate limit exceeded | Token bucket exhausted; `detail` includes retry-after seconds |
| 500 Internal Server Error | Server error | Unexpected exceptions; check server logs |

### 9.4 7-Step Tool Call Verification

The `POST /tools/call` endpoint executes the following verification sequence. Each step is a gate: failure at any step returns an error response and terminates the call without relaying to the target.

```
Step 1: DECODE TOKEN
  token_cbor = base64.b64decode(body.token)
  token = CapabilityToken.from_cbor(token_cbor)
  Failure -> HTTP 400: "Invalid token encoding: ..."

Step 2: CRYPTOGRAPHIC VERIFICATION
  verify_token(
      token=token,
      issuer_public_key=authority.public_key,  # ML-DSA-65
      check_expiry=True,
      crl=authority.crl
  )
  Checks:
    a) ML-DSA-65 signature valid over CBOR-encoded token fields
    b) datetime.utcnow() is within [not_before, not_after]
    c) token.token_id not in CRL (or past grace period)
  Failure -> HTTP 403: "Token signature invalid" | "Token expired" | "Token revoked"

Step 3: ARM URI SCOPE CHECK
  uri_matches(token.resource_uri, tool["resource_uri"])
  Example: token grants qasp://agents/abc/tools/*
           tool requires qasp://agents/abc/tools/analyze
  Failure -> HTTP 403: "Resource URI mismatch: ..."

Step 4: VERB CHECK
  ARM_EXEC in token.verbs
  Failure -> HTTP 403: "Token missing 'exec' verb"

Step 5: RATE LIMITING
  limiter = registry.get_or_create(
      token_id=token.token_id,
      rate_limit=token.constraints.rate_limit or 10,
      rate_period_seconds=token.constraints.rate_period_seconds or 60
  )
  limiter.consume()  # Returns False if bucket empty
  Failure -> HTTP 429: "Rate limit exceeded ... Retry after Xs"

Step 6: RELAY TO TARGET
  POST {callback_url}/tools/{tool_name}
  Headers: X-QASP-Caller-DID: {caller.did}
  Body: body.arguments (JSON)
  Timeout: 30 seconds
  If no callback_url: echo arguments (demo mode)

Step 7: METERING AND TRUST UPDATE
  Record: {receipt_id, tool, target, timestamp, units=1, cost=10, currency="credits"}
  trust_registry.update_reputation(target_did, success=True)
  Return: {result, metering, receipt_id}
```

Steps 2–5 are ordered by cost. The cheapest checks (CBOR decode, URI match, verb lookup) occur before the rate limiter state mutation, which in turn occurs before the external HTTP call. This ordering minimizes wasted work on invalid requests.

---

## 10. Security Considerations

### 10.1 Threat Model

QASP is designed to protect against the following threat categories:

**Quantum adversary (future):** An attacker with access to a cryptographically relevant quantum computer capable of running Shor's algorithm against RSA and ECC. QASP's ML-DSA-65 signatures and ML-KEM-768 key encapsulation are believed to be secure against quantum attacks (NIST Level 3).

**Classical network adversary (present):** An attacker who can intercept, modify, and replay network traffic. QASP's ML-DSA-65 signatures provide authentication; the hybrid KEM provides session confidentiality; OCSP with nonce replay protection prevents replay attacks.

**Malicious agent:** An agent within the QASP ecosystem that attempts to exceed its granted permissions, forge tokens, or manipulate trust scores. QASP's capability token model (unforgeable ML-DSA-65 signatures, strict ARM URI matching, verb checks) prevents unauthorized access. Anti-gaming caps and collusion detection limit trust score manipulation.

**Compromised authority server:** An attacker who obtains the authority server's ML-DSA-65 secret key can issue arbitrary tokens. This is the most critical single point of failure. Mitigations include key management practices (Section 10.4) and the planned v0.2.0 distributed authority model.

**Harvest-now, decrypt-later:** An adversary storing current encrypted traffic for future decryption when quantum computing becomes available. The X25519 + ML-KEM-768 hybrid KEM provides protection: breaking future session encryption requires breaking both the classical and post-quantum components.

**Assets protected by QASP:**

| Asset | Protection Mechanism |
|---|---|
| Agent identity | ML-DSA-65 signatures; did:qasp binding |
| Tool invocation authorization | Capability token signature verification |
| Session confidentiality | Hybrid KEM + AES-256-GCM |
| Access scope | ARM URI matching; verb checks |
| Rate enforcement | Token bucket per token ID |
| Reputation integrity | Anti-gaming caps; BFS cascade revocation |
| Audit trail | Metering records; signed OCSP responses; PoE chain |

### 10.2 Attack Surface Analysis

**REST API endpoints:** The authority server exposes 12 HTTP endpoints. The most sensitive are:
- `POST /register`: Creates a new identity. Not rate-limited in v0.1.0. Potential for spam registration.
- `POST /tokens/request`: Issues capability tokens. Requires valid API key. Token validity is bounded (1 hour).
- `POST /tools/call`: Highest-value endpoint. Protected by 7-step verification (Section 9.4).

**API key exposure:** API keys are 32-character hex strings (128 bits of entropy). They are bearer tokens and must be transmitted over HTTPS. In v0.1.0, they are not rotatable; a leaked API key remains valid until the server restarts.

**Token base64 transmission:** Capability tokens are transmitted base64-encoded in HTTP request bodies. At 4900–5400 bytes, they are well within HTTP body size limits but larger than typical JWT tokens. They should not be placed in URL query parameters (size and logging concerns).

**OCSP nonce replay window:** The nonce replay protection window is bounded. If a very old OCSP response is replayed after the nonce has aged out of the tracking window, replay protection fails. The `next_update` field mitigates this: clients should reject responses where `now > next_update`.

**mDNS spoofing:** In network environments where multicast DNS is accessible to untrusted parties, a malicious host could attempt to inject capability advertisements. This is mitigated by ML-DSA-65 signature verification on each advertisement, but only if the verifier can obtain the advertiser's public key from a trusted source (the authority DID registry).

**In-memory state (v0.1.0):** All server state is in-memory. A server restart clears all agent registrations, tokens, and revocations. This is a denial-of-service vulnerability in production: a forced restart invalidates all active agent sessions.

### 10.3 Known Limitations

| Limitation | Impact | Planned Fix |
|---|---|---|
| In-memory state only | No persistence across restarts | v0.2.0: database backend |
| Single authority server | Single point of failure for token issuance | v0.2.0: distributed authority |
| No API key rotation | Leaked keys valid until restart | v0.2.0: key rotation endpoint |
| No registration rate limiting | Spam registration possible | v0.2.0: CAPTCHA or pre-shared secret |
| No mutual TLS at HTTP layer | Authority server identity not cryptographically verified | v0.2.0: authority certificate pinning |
| SLSA VCs use classical signatures | Certification component relies on ECDSA | v0.2.0: PQ VC support when standardized |
| Dispute resolution is manual | No automated verdict enforcement | v0.2.0: arbitration protocol |
| QUIC requires self-signed cert | Browser clients cannot verify | Accept or deploy with CA-signed cert |
| Settlement not exposed via REST | Payment channels require Python SDK | v0.2.0: REST settlement endpoints |

### 10.4 Security Best Practices

**Authority server deployment:**

1. Deploy the authority server behind a reverse proxy (nginx, Caddy) with a valid TLS certificate from a public CA. QASP provides application-layer post-quantum security; TLS provides transport-layer confidentiality.

2. In production, integrate the authority's ML-DSA-65 secret key with a hardware security module (HSM) or cloud KMS (AWS KMS, Azure Key Vault, HashiCorp Vault). The v0.1.0 in-memory key storage is not suitable for production.

3. Set environment variables or use a secrets manager for any sensitive configuration. Do not hardcode keys or API keys in source code or Docker images.

4. Restrict `POST /register` access using network policies or a pre-shared registration secret. An open registration endpoint allows any party to create agent identities.

5. Deploy behind an API gateway with request size limits, IP-based rate limiting, and DDoS protection.

6. Configure structured logging and forward logs to a SIEM. Key events to alert on: repeated 403 errors (potential token abuse), 429 storms (rate limit saturation), unusual registration bursts.

**Agent deployment:**

1. Store the API key as a secret, not in application code or configuration files committed to source control.

2. Cache capability tokens for their validity period (up to 1 hour) rather than requesting a new token for every tool call. The `expires_at` field in the token response indicates when to refresh.

3. Check OCSP status before reusing a cached token, particularly for high-value operations. A token may have been revoked between issuance and use.

4. Implement exponential backoff with jitter when receiving HTTP 429 responses. Use the retry-after value from the error message as the minimum wait time.

5. Report interaction outcomes (`POST /trust/{did}/report`) consistently. Selective reporting (only reporting failures, or only reporting successes) distorts the trust model for other agents.

6. Implement callback endpoint authentication: verify the `X-QASP-Caller-DID` header and consider checking the OCSP status of the caller's token before executing the tool.

---

## 11. Compliance and Standards

### 11.1 NIST Post-Quantum Cryptography Standards

QASP is compliant with the following NIST standards published in August 2024:

| Standard | Full Title | QASP Implementation |
|---|---|---|
| FIPS 203 | Module-Lattice-Based Key-Encapsulation Mechanism Standard | `src/qasp/crypto/kem.py` (ML-KEM-768) |
| FIPS 204 | Module-Lattice-Based Digital Signature Standard | `src/qasp/crypto/signatures.py` (ML-DSA-65) |

**FIPS 203 (ML-KEM):** QASP uses the ML-KEM-768 parameter set, which provides NIST security Level 3 (equivalent to AES-192 brute force). The implementation uses `liboqs-python`, which wraps the reference implementation from the NIST submission package. The reference implementation is the normative definition in FIPS 203.

**FIPS 204 (ML-DSA):** QASP uses the ML-DSA-65 parameter set (Level 3). The implementation derives from the same Dilithium3 specification. All signatures produced by QASP are compliant with FIPS 204's API requirements.

**Algorithm agility:** QASP's certificate format uses OID-tagged algorithm identifiers. If NIST publishes updates or corrections to FIPS 203/204, or if FIPS 205 (SLH-DSA) support is required, the certificate and signature modules can be extended without breaking existing token formats, provided backward compatibility is maintained via OID negotiation.

**NIST SP 800-131A Rev 3:** NIST's algorithm transition guidance recommends disallowing RSA and ECC for new systems in the post-quantum transition period. QASP's exclusive use of ML-DSA-65 and ML-KEM-768 for agent authentication and key agreement is consistent with the strictest interpretation of this guidance.

### 11.2 W3C DID Core 1.0

The `did:qasp` method is implemented in conformance with the W3C Decentralized Identifier (DID) Core specification v1.0 (W3C Recommendation, July 2022).

**DID Core conformance:**

| Requirement | Status | Notes |
|---|---|---|
| DID syntax: `did:method:identifier` | Compliant | `did:qasp:<base58btc-encoded-id>` |
| DID document mandatory fields | Compliant | `id`, `@context`, `verificationMethod` |
| Verification method representation | Compliant | Custom type `MldSa65VerificationKey2024` |
| DID resolution protocol | Partial | Local registry only; no HTTP DID resolver in v0.1.0 |
| DID deactivation | Not implemented | Deactivation = revocation of all tokens in v0.1.0 |
| DID update | Not implemented | Planned v0.2.0 |

**DID URL resolution:** The current implementation supports DID URL fragment resolution for `#key-1` verification method references. Full DID URL path/query resolution is not yet implemented.

### 11.3 W3C Verifiable Credentials Data Model 2.0

The trust and certification layer (`src/qasp/trust/certification.py`) produces and consumes W3C Verifiable Credentials conformant with the W3C VC Data Model 2.0 specification.

**VC use cases in QASP:**

1. **SLSA certification credentials:** Record an agent's supply chain security level, issued by an auditor and presented to the authority server to influence the certification component of the trust score.

2. **Audit certificates:** The `W3CVCAuditCert` structure records the outcome of a QASP protocol compliance audit, signed by the QASP auditor's DID.

3. **Behavioral attestations:** Automated behavioral monitoring can produce VCs attesting to observed protocol conformance patterns.

**VC Data Model 2.0 alignment:**
- Uses `@context: ["https://www.w3.org/ns/credentials/v2"]`
- `credentialSubject.id` is a `did:qasp` DID
- `proof` is a `DataIntegrityProof` with `cryptosuite: ecdsa-rdfc-2019` (classical) or the forthcoming `mldsa-rdfc-2024` (PQ, planned)

### 11.4 OWASP API Security Top 10 Alignment

QASP's authority server design addresses the OWASP API Security Top 10 (2023):

| OWASP Risk | ID | QASP Mitigation |
|---|---|---|
| Broken Object Level Authorization | API1 | ARM URI matching ensures tokens only grant access to explicitly scoped resources |
| Broken Authentication | API2 | ML-DSA-65 signed tokens; API key bearer authentication over HTTPS |
| Broken Object Property Level Authorization | API3 | Token verb set constrains which properties (read/write/exec) can be accessed |
| Unrestricted Resource Consumption | API4 | Token bucket rate limiting per token ID; 16 MiB message size limit |
| Broken Function Level Authorization | API5 | Capability tokens scope to specific tools; ARM URI prevents lateral movement |
| Unrestricted Access to Sensitive Business Flows | API6 | Token validity period (1 hour); OCSP revocation for emergency termination |
| Server Side Request Forgery | API7 | Callback URL is registered at agent creation; not taken from request body |
| Security Misconfiguration | API8 | ALPN negotiation; structured configuration constants; no default credentials |
| Improper Inventory Management | API9 | DID registry maintains authoritative agent inventory; `/discover` exposes it |
| Unsafe Consumption of APIs | API10 | Callback relay uses `httpx` with 30-second timeout; response is opaque to caller |

**Open gaps (v0.1.0):**
- API4 (partial): No registration rate limiting. Remediated in v0.2.0.
- API7 (partial): Callback URL validation (format check only, no SSRF filtering). Remediated in v0.2.0.

### 11.5 RFC Compliance

| RFC | Title | QASP Usage | Compliance |
|---|---|---|---|
| RFC 5869 | HKDF | Session key derivation in hybrid KEM | Full |
| RFC 6960 | OCSP | Token status protocol (profile) | Partial (no HTTP transport binding) |
| RFC 7519 | JWT | N/A (QASP uses CBOR, not JWT) | N/A |
| RFC 8949 | CBOR | Capability token encoding | Full |
| RFC 9000 | QUIC | QUIC transport | Full (via aioquic) |
| RFC 9001 | TLS 1.3 for QUIC | QUIC security | Full (via aioquic) |

---

## 12. Operational Characteristics

### 12.1 Performance Characteristics

**Registration throughput:** Each registration generates one ML-DSA-65 keypair and one SHA-384 hash. Benchmarked at approximately 4,000–5,000 registrations per second on a 4-core server. In practice, registration is a one-time operation per agent; throughput is not a concern.

**Token issuance throughput:** Each token request requires one ML-DSA-65 signing operation. Benchmarked at approximately 2,500–3,000 tokens per second on a 4-core server.

**Tool call throughput (no relay):** Each tool call requires one CBOR decode, one ML-DSA-65 verify, one CRL lookup (hash map), one rate limiter check (in-memory), and one trust registry update. Benchmarked at approximately 1,500–2,000 calls per second for calls with no callback relay.

**Tool call throughput (with relay):** When `callback_url` is configured, the tool call throughput is dominated by the latency of the HTTP relay call to the target agent. With a 10 ms callback round-trip, throughput is approximately 100 calls per second per worker.

**Memory per registered agent:** Each `AgentRecord` holds two ML-DSA-65 keys (4032 + 1952 = 5984 bytes), a tool list, a token dictionary, and a metering list. Baseline memory per agent is approximately 10–15 KB excluding token and metering accumulation.

**Total memory for authority server:** At 1,000 registered agents with no token or metering history, estimated memory usage is approximately 50–100 MB for agent records plus Python interpreter overhead. With metering records accumulating (1,000 agents × 1,000 calls = 1M records), memory grows accordingly.

### 12.2 Memory Management

**Rate limiter cleanup:** `RateLimiterRegistry.cleanup_expired(max_age_seconds=7200)` removes limiter entries for tokens older than 2 hours. This should be called periodically (e.g., every 30 minutes via a background task) to prevent unbounded memory growth from expired tokens.

**Metering records:** In v0.1.0, metering records accumulate indefinitely in `AgentRecord.metering`. For long-running deployments, implement periodic rotation: archive records older than 24 hours to persistent storage or an observability platform, then clear them from memory.

**OCSP nonce tracking:** The nonce replay window is bounded by the `DEFAULT_RESPONSE_VALIDITY_SECONDS` (600s) window. Nonces older than this are automatically eligible for expiry. The implementation should include periodic cleanup of the nonce tracking set.

### 12.3 Scalability

**Vertical scaling:** The authority server is a single-process Uvicorn application. Vertical scaling (more CPU cores) is achieved by increasing the Uvicorn worker count: `uvicorn qasp_server:app --workers 4`. Note that with multiple workers, the in-memory `AuthorityState` is not shared between workers. A shared-state backend (Redis for rate limiter state, a database for agent records) is required for multi-worker deployments; this is the primary motivation for the v0.2.0 persistence layer.

**Horizontal scaling:** Not supported in v0.1.0 due to in-memory state. v0.2.0 will decouple state from the server process.

**Transport layer scaling:** TCP and QUIC transports scale independently of the authority server. Multiple QASP agents can maintain direct peer-to-peer QASP connections without routing through the authority server; the authority is only required for token issuance and OCSP status.

### 12.4 Monitoring and Observability

**Logging:** The authority server uses Python's standard `logging` module. The logger name is `qasp.server`. Key log events:

| Event | Level | Message Pattern |
|---|---|---|
| Agent registered | INFO | `Registered agent {name} DID={did} tools={count}` |
| Authority startup | INFO | `Authority DID: {did}` |
| Dispute opened | INFO | `Dispute opened: {id} ({claimant} vs {respondent})` |
| Token issued | (implicit) | Via HTTP access log |
| Revocation | (implicit) | Via HTTP access log |

**Structured logging:** For production deployments, configure a JSON log formatter for ingestion into ELK stack, Datadog, or Splunk. The `%(asctime)s [%(levelname)s] %(name)s: %(message)s` format is suitable for development; production should use `python-json-logger` or equivalent.

**Metrics to track:**
- `agents_registered` (from `GET /` response)
- Tool call success rate (HTTP 200 vs 403/429)
- Trust score distribution across registered agents
- Rate limit saturation events (HTTP 429 rate)
- Revocation events per time period
- Token issuance rate

**Health check:** `GET /` returns a 200 response with basic server status. This endpoint can serve as a Kubernetes liveness and readiness probe. A more detailed health check endpoint (checking CRL integrity, OCSP responder availability) is planned for v0.2.0.

### 12.5 Container Deployment

The multi-stage Dockerfile provides four build targets:

| Stage | Purpose | Entry Point |
|---|---|---|
| `liboqs-builder` | Build liboqs C library from source | (build only) |
| `python-base` | Base Python 3.12-slim with liboqs libraries | (base only) |
| `dev` | Full development environment | `/bin/bash` |
| `test` | Test runner | `pytest -v --tb=short` |
| `lint` | Static analysis (ruff, mypy, bandit) | `/app/run-lint.sh` |

**Building the development image:**

```bash
docker build --target dev -t qasp:dev .
docker run -it --rm -p 8080:8080 qasp:dev
# Inside container:
python scripts/qasp_server.py --host 0.0.0.0 --port 8080
```

**Building and running tests:**

```bash
docker build --target test -t qasp:test .
docker run --rm qasp:test
```

**Running linters:**

```bash
docker build --target lint -t qasp:lint .
docker run --rm qasp:lint
```

**liboqs compilation:** The `liboqs-builder` stage clones and builds `liboqs` from the Open Quantum Safe GitHub repository using CMake and Ninja. The build uses `-DBUILD_SHARED_LIBS=ON` to produce shared libraries, which are then copied into the `python-base` stage. The `ldconfig` call in `python-base` registers the shared libraries with the dynamic linker.

**Platform compatibility:** The Dockerfile targets `linux/amd64`. Building for `linux/arm64` (e.g., AWS Graviton, Apple Silicon) requires adding `-DOQS_DIST_BUILD=ON` to the CMake flags to disable architecture-specific optimizations that may not be available on all ARM variants.

---

## 13. Integration Patterns

### 13.1 Python SDK Integration

The `qasp_client.py` script in `scripts/` provides a synchronous Python client for the authority server REST API. It requires only `httpx` as a dependency, making it lightweight for agents that do not need the full QASP protocol library.

**Installation:**

```bash
pip install httpx
```

**Basic usage pattern:**

```python
from scripts.qasp_client import QASPClient, QASPError

# Initialize client pointing at the authority server
client = QASPClient("https://qasp.example.com")

# Register this agent
identity = client.register(
    name="DataProcessor",
    tools=[
        {"name": "process", "description": "Process a data payload"},
        {"name": "summarize", "description": "Summarize a dataset"},
    ],
    callback_url="https://my-agent.example.com",
)
# identity = {"agent_id": "...", "did": "did:qasp:...",
#              "api_key": "...", "public_key": "..."}

# Discover agents with a specific capability
peers = client.discover(
    capability="qasp://*/tools/analyze",
    min_trust=0.3,
)

# Obtain a token for a specific tool
token_info = client.request_token(
    target_did=peers[0]["did"],
    tool_name="analyze",
)

# Execute the tool call
try:
    result = client.call_tool(
        target_did=peers[0]["did"],
        tool_name="analyze",
        arguments={"dataset": "q1_sales.csv", "metric": "revenue"},
        token=token_info["token"],
    )
    client.report_interaction(peers[0]["did"], "success")
    print(result["result"])
except QASPError as e:
    client.report_interaction(peers[0]["did"], "failure", details=str(e))
    print(f"Error {e.status_code}: {e.detail}")
```

**Error handling:** `QASPClient` raises `QASPError` for any non-2xx HTTP response. `QASPError.status_code` contains the HTTP status code; `QASPError.detail` contains the server's error message.

**Token caching pattern:**

```python
import time

class CachingQASPClient:
    def __init__(self, authority_url: str):
        self._client = QASPClient(authority_url)
        self._token_cache: dict[tuple, dict] = {}

    def get_token(self, target_did: str, tool_name: str) -> str:
        key = (target_did, tool_name)
        cached = self._token_cache.get(key)
        if cached:
            # Re-use if more than 60 seconds remain before expiry
            expires = cached["expires_at"]
            if expires and time.time() < (expires - 60):
                return cached["token"]
        token_info = self._client.request_token(target_did, tool_name)
        self._token_cache[key] = token_info
        return token_info["token"]
```

### 13.2 HTTP Integration (Language-Agnostic)

Any HTTP client can integrate with QASP. The complete lifecycle using raw HTTP:

```bash
# 1. Register
RESULT=$(curl -s -X POST https://qasp.example.com/register \
  -H "Content-Type: application/json" \
  -d '{"name": "ShellAgent", "tools": [{"name": "echo", "description": "Echo input"}]}')

API_KEY=$(echo $RESULT | jq -r '.api_key')
MY_DID=$(echo $RESULT | jq -r '.did')

# 2. Discover
curl -s -H "X-API-Key: $API_KEY" https://qasp.example.com/discover | jq .

# 3. Request token
TARGET_DID="did:qasp:..."
TOKEN_RESPONSE=$(curl -s -X POST https://qasp.example.com/tokens/request \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"target_did\": \"$TARGET_DID\", \"tool_name\": \"echo\"}")

TOKEN=$(echo $TOKEN_RESPONSE | jq -r '.token')
TOKEN_ID=$(echo $TOKEN_RESPONSE | jq -r '.token_id')

# 4. Call tool
curl -s -X POST https://qasp.example.com/tools/call \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"target_did\": \"$TARGET_DID\", \"tool_name\": \"echo\",
       \"arguments\": {\"msg\": \"hello\"}, \"token\": \"$TOKEN\"}"

# 5. Check token status (no auth required)
curl -s https://qasp.example.com/tokens/status/$TOKEN_ID

# 6. Revoke token
curl -s -X POST https://qasp.example.com/tokens/revoke \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"token_id\": \"$TOKEN_ID\"}"
```

### 13.3 LLM Agent Loop Integration

QASP integrates naturally into LLM agent tool-use loops. The following pattern illustrates integration with a generic function-calling LLM framework:

```python
from scripts.qasp_client import QASPClient, QASPError

# Initialize once at agent startup
qasp = QASPClient("https://qasp.example.com")
identity = qasp.register(
    name="AssistantAgent",
    tools=[{"name": "query_database", "description": "Query enterprise database"}],
)

# Token cache (avoid requesting a new token for every LLM tool call)
_token_cache: dict[str, dict] = {}


def qasp_tool_dispatcher(tool_name: str, arguments: dict) -> dict:
    """Dispatch a tool call through QASP. Called by the LLM framework."""

    # Find the agent offering this tool
    peers = qasp.discover(capability=f"qasp://*/tools/{tool_name}")
    if not peers:
        return {"error": f"No agent found offering tool '{tool_name}'"}

    # Select highest-trust agent
    target = max(peers, key=lambda p: p["trust_score"])
    target_did = target["did"]

    # Obtain or reuse token
    cache_key = f"{target_did}:{tool_name}"
    if cache_key not in _token_cache:
        _token_cache[cache_key] = qasp.request_token(target_did, tool_name)
    token_info = _token_cache[cache_key]

    try:
        result = qasp.call_tool(
            target_did=target_did,
            tool_name=tool_name,
            arguments=arguments,
            token=token_info["token"],
        )
        qasp.report_interaction(target_did, "success")
        return result["result"]

    except QASPError as e:
        qasp.report_interaction(target_did, "failure", details=e.detail)
        # If token expired or revoked, clear cache and retry once
        if e.status_code in (403, 429):
            _token_cache.pop(cache_key, None)
        return {"error": f"Tool call failed: {e.detail}"}
```

### 13.4 Service Agent Pattern (Exposing Tools)

Agents that expose tools to other agents must run an HTTP server to receive callback requests:

```python
from fastapi import FastAPI, Request, HTTPException
from scripts.qasp_client import QASPClient

app = FastAPI()
qasp = QASPClient("https://qasp.example.com")

@app.on_event("startup")
async def startup():
    identity = qasp.register(
        name="EmbeddingService",
        tools=[{"name": "embed", "description": "Generate text embeddings"}],
        callback_url="https://embedding.internal.example.com",
    )
    print(f"Registered as {identity['did']}")

@app.post("/tools/embed")
async def embed_tool(request: Request):
    # Verify the caller identity
    caller_did = request.headers.get("X-QASP-Caller-DID", "unknown")

    args = await request.json()
    text = args.get("text", "")
    if not text:
        raise HTTPException(status_code=400, detail="text argument required")

    # Execute the actual tool logic
    embedding = generate_embedding(text)  # Your implementation

    return {
        "embedding": embedding,
        "dimensions": len(embedding),
        "model": "text-embedding-v1",
        "caller": caller_did,
    }
```

### 13.5 Multi-Language Integration

QASP's REST API is language-agnostic. The following JavaScript example illustrates integration from a Node.js agent:

```javascript
const QASP_URL = "https://qasp.example.com";

class QASPAgent {
    constructor(url) {
        this.url = url;
        this.apiKey = null;
        this.did = null;
    }

    async register(name, tools = [], callbackUrl = "") {
        const response = await fetch(`${this.url}/register`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name, tools, callback_url: callbackUrl }),
        });
        if (!response.ok) throw new Error(`Registration failed: ${response.status}`);
        const data = await response.json();
        this.apiKey = data.api_key;
        this.did = data.did;
        return data;
    }

    async discover(capability = "*", minTrust = 0.0) {
        const params = new URLSearchParams({ capability, min_trust: minTrust });
        const response = await fetch(`${this.url}/discover?${params}`, {
            headers: { "X-API-Key": this.apiKey },
        });
        return response.json();
    }

    async requestToken(targetDid, toolName) {
        const response = await fetch(`${this.url}/tokens/request`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-API-Key": this.apiKey,
            },
            body: JSON.stringify({ target_did: targetDid, tool_name: toolName }),
        });
        if (!response.ok) {
            const err = await response.json();
            throw new Error(`Token request failed (${response.status}): ${err.detail}`);
        }
        return response.json();
    }

    async callTool(targetDid, toolName, args, token) {
        const response = await fetch(`${this.url}/tools/call`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-API-Key": this.apiKey,
            },
            body: JSON.stringify({
                target_did: targetDid,
                tool_name: toolName,
                arguments: args,
                token: token,
            }),
        });
        if (!response.ok) {
            const err = await response.json();
            throw new Error(`Tool call failed (${response.status}): ${err.detail}`);
        }
        return response.json();
    }
}

// Usage
const agent = new QASPAgent("https://qasp.example.com");
await agent.register("JSAgent", [{ name: "fetch_data", description: "Fetch external data" }]);
const peers = await agent.discover("qasp://*/tools/analyze");
const tokenInfo = await agent.requestToken(peers[0].did, "analyze");
const result = await agent.callTool(peers[0].did, "analyze", { query: "test" }, tokenInfo.token);
console.log(result);
```

---

## 14. Glossary

| Term | Definition |
|---|---|
| **A2A** | Agent-to-Agent protocol. Google's open protocol for autonomous agent delegation and task execution. |
| **AEAD** | Authenticated Encryption with Associated Data. A symmetric cipher mode that provides both confidentiality (encryption) and integrity (authentication). QASP uses AES-256-GCM. |
| **ALPN** | Application-Layer Protocol Negotiation. A TLS extension that identifies the application protocol during handshake. QASP uses `qasp/1`. |
| **ARM** | Access Rights Model. QASP's resource URI scheme and matching algebra using `qasp://` URIs. |
| **ARM URI** | A `qasp://provider/resource/subresource` URI that identifies a specific resource within the QASP ecosystem. |
| **Attenuation** | The act of producing a new capability token with the same or narrower permissions than the parent token. Attenuation can only narrow scope, never widen it. |
| **Authority** | The trusted third party that issues capability tokens, maintains the CRL, runs the OCSP responder, and manages the agent registry. In v0.1.0, this is the QASP authority server. |
| **Bayesian trust** | A probabilistic trust model using the Beta distribution to represent uncertainty in an agent's reliability. Updated incrementally with each interaction outcome. |
| **BFS cascade** | Breadth-First Search cascade revocation. When a token is revoked, all descendant tokens (child, grandchild, etc.) are also revoked by traversing the delegation graph. |
| **CBOR** | Concise Binary Object Representation (RFC 8949). A binary data format used by QASP for capability token encoding. More compact than JSON; supports binary data natively. |
| **Capability token** | A CBOR-encoded, ML-DSA-65 signed data structure granting a specific agent the right to perform specific actions on specific resources within defined constraints. |
| **CRQC** | Cryptographically Relevant Quantum Computer. A quantum computer large enough to run Shor's algorithm against RSA-2048 or ECDSA-256. |
| **CRL** | Certificate Revocation List. An authoritative list of revoked tokens maintained by the authority server. |
| **DID** | Decentralized Identifier (W3C). A persistent, resolvable identifier that does not require a centralized registry. QASP uses the `did:qasp` method. |
| **DID document** | A JSON-LD document associated with a DID, containing the DID's public key(s) and service endpoints. |
| **Delegation** | Transferring a capability to another agent by issuing a child capability token. The delegating agent must hold the `ARM_DELEGATE` verb. |
| **did:qasp** | QASP's custom DID method. Identifiers are derived as `Base58btc(SHA-384(ML-DSA-65_public_key)[0:32])`. |
| **FIPS 203** | Federal Information Processing Standard 203. The NIST standard for ML-KEM (Module-Lattice-Based Key Encapsulation). |
| **FIPS 204** | Federal Information Processing Standard 204. The NIST standard for ML-DSA (Module-Lattice-Based Digital Signature). |
| **Grace period** | A time window after revocation during which a token is still considered valid. Normal revocations have a 300-second grace period; critical revocations have 0 seconds (immediate effect). |
| **HKDF** | HMAC-based Key Derivation Function (RFC 5869). Used by QASP to derive session keys from hybrid KEM shared secrets. |
| **HNDL** | Harvest Now, Decrypt Later. An attack strategy where an adversary records encrypted traffic today, intending to decrypt it with quantum computing power in the future. |
| **Hybrid KEM** | A key encapsulation mechanism combining classical (X25519) and post-quantum (ML-KEM-768) algorithms. Breaking the hybrid requires breaking both components. |
| **liboqs** | Open Quantum Safe's C library implementing post-quantum cryptographic algorithms. Used by QASP via the `liboqs-python` wrapper. |
| **MCP** | Model Context Protocol. Anthropic's open protocol for connecting LLM systems to external tools and data sources. |
| **ML-DSA** | Module-Lattice-Based Digital Signature Algorithm (formerly Dilithium). NIST-standardized in FIPS 204. QASP uses ML-DSA-65 (Level 3). |
| **ML-KEM** | Module-Lattice-Based Key Encapsulation Mechanism (formerly Kyber). NIST-standardized in FIPS 203. QASP uses ML-KEM-768 (Level 3). |
| **mDNS** | Multicast DNS. A zero-configuration networking protocol used by QASP for local service discovery. |
| **NIST Level 3** | A security level in NIST's post-quantum security parameter sets, targeting security equivalent to AES-192 (roughly 192 bits of classical security). |
| **OCap** | Object Capabilities. A security model where access rights are represented as unforgeable, transferable tokens. QASP's capability token model is based on OCap principles. |
| **OCSP** | Online Certificate Status Protocol (RFC 6960). A protocol for querying the revocation status of a specific token or certificate in real time. |
| **OCSP stapling** | The practice of a server pre-fetching its own OCSP status and attaching the signed response to tokens, eliminating the need for clients to contact the OCSP responder directly. |
| **PQ** | Post-Quantum. Refers to cryptographic algorithms believed to be secure against attacks by quantum computers. |
| **PoE** | Proof of Execution. A cryptographic chain of evidence that a specific tool was called with specific arguments, producing specific output. Used for dispute resolution. |
| **QASP** | Quantum-Aware Secure Protocol. This protocol. |
| **QASP-Shake** | The QASP handshake protocol combining ML-DSA-65 identity authentication with X25519+ML-KEM-768 hybrid key establishment. |
| **Rate limiter registry** | A per-token-ID registry of token bucket rate limiters, ensuring each capability token is independently rate-limited. |
| **Sans-I/O** | A design pattern where protocol logic is implemented as a pure state machine that processes bytes and produces events, with no direct I/O operations. Makes the protocol independently testable. |
| **Selective disclosure** | A privacy-preserving feature allowing a token holder to reveal only specific fields of a capability token to a verifier, using a Merkle tree structure. |
| **SLSA** | Supply chain Levels for Software Artifacts. A NIST/Google framework for software supply chain security. QASP integrates SLSA levels into the trust scoring certification component. |
| **SPIFFE** | Secure Production Identity Framework for Everyone. A standard for workload identity in cloud-native environments. QASP's composite multi-owner tokens support SPIFFE SVID attestation. |
| **Token aggregation** | Combining multiple capability tokens held by the same agent into a single `AggregatedPermission`. Verbs are unioned; resource URIs are unioned; constraints are intersected. |
| **Token bucket** | A rate limiting algorithm where a bucket holds up to `capacity` tokens, refills at `refill_rate` per second, and each request consumes one token. |
| **Trust score** | A composite score in [0, 1] representing an agent's reliability, computed from four weighted components: reputation (0.35), witness (0.25), certification (0.20), behavioral (0.20). |
| **VerbSet** | The set of actions a capability token grants: `exec`, `read`, `write`, `delegate`, `attenuate`, `revoke`, `charge`. |
| **W3C VC** | W3C Verifiable Credential. A tamper-evident credential whose authorship can be cryptographically verified. Used in QASP for SLSA certification and audit records. |
| **X25519** | An elliptic-curve Diffie-Hellman function over Curve25519. Used as the classical component in QASP's hybrid KEM. |
| **ZK disclosure** | Zero-knowledge selective disclosure. A feature allowing token holders to prove properties of token fields (range, equality, verb membership) without revealing the actual values. |

---

## Appendix A: Configuration Reference

This appendix lists all configurable constants and parameters in QASP v0.1.0. In the current release, configuration is via source code constants and command-line arguments. A YAML/TOML configuration file is planned for v0.2.0.

### A.1 Authority Server (qasp_server.py)

| Parameter | Flag | Default | Description |
|---|---|---|---|
| Host | `--host` | `0.0.0.0` | Bind address for the HTTP server |
| Port | `--port` | `8080` | Bind port for the HTTP server |
| Log level | `--log-level` | `info` | Python logging level (debug/info/warning/error) |

### A.2 Token Issuance Defaults

These values are hardcoded in the authority server and represent the default constraints applied to every issued token:

| Parameter | Value | Module Location |
|---|---|---|
| `rate_limit` | 10 calls | `qasp_server.py:368` |
| `rate_period_seconds` | 60 seconds | `qasp_server.py:368` |
| `validity_seconds` | 3600 seconds (1 hour) | `qasp_server.py:369` |

### A.3 OCSP Responder

| Constant | Value | Module Location | Description |
|---|---|---|---|
| `DEFAULT_RESPONSE_VALIDITY_SECONDS` | 600 | `protocol/ocsp.py` | OCSP response cache TTL |
| `OCSP_NONCE_SIZE` | 16 bytes | `protocol/ocsp.py` | Nonce size for replay protection |

### A.4 Revocation

| Constant | Value | Module Location | Description |
|---|---|---|---|
| `NORMAL_GRACE_PERIOD_SECONDS` | 300 | `protocol/revocation.py` | Grace period for NORMAL urgency revocations |
| Critical grace period | 0 | `protocol/revocation.py` | Immediate effect for CRITICAL revocations |

### A.5 Rate Limiter

| Constant | Value | Module Location | Description |
|---|---|---|---|
| `cleanup_expired` default | 7200 seconds | `protocol/rate_limiter.py` | Default max age before limiter entry GC |

### A.6 TCP Transport

| Constant | Value | Module Location | Description |
|---|---|---|---|
| `LENGTH_PREFIX_SIZE` | 4 bytes | `transport/tcp.py` | Size of frame length prefix |
| `MAX_MESSAGE_SIZE` | 16,777,216 bytes (16 MiB) | `transport/tcp.py` | Maximum allowed frame payload |
| `DEFAULT_READ_SIZE` | 4096 bytes | `transport/tcp.py` | Socket read buffer size |

### A.7 QUIC Transport

| Constant | Value | Module Location | Description |
|---|---|---|---|
| `DEFAULT_QUIC_PORT` | 4443 | `transport/quic.py` | Default QUIC server port |
| `MAX_DATAGRAM_SIZE` | 65,536 bytes | `transport/quic.py` | Maximum QUIC datagram size |
| `IDLE_TIMEOUT` | 30.0 seconds | `transport/quic.py` | QUIC idle connection timeout |
| ALPN protocol | `"qasp/1"` | `transport/quic.py` | QUIC ALPN identifier |

### A.8 Trust Scoring

| Constant | Value | Module Location | Description |
|---|---|---|---|
| Interaction weight | 0.35 | `trust/scoring.py` | Weight for reputation component |
| Witness weight | 0.25 | `trust/scoring.py` | Weight for witness component |
| Certification weight | 0.20 | `trust/scoring.py` | Weight for certification component |
| Behavioral weight | 0.20 | `trust/scoring.py` | Weight for behavioral component |
| Confidence denominator | 50 | `qasp_server.py:188` | Interactions for full confidence |
| Anti-gaming cap (<10) | 0.70 | `trust/scoring.py` | Max score with < 10 interactions |
| Anti-gaming cap (<50) | 0.80 | `trust/scoring.py` | Max score with 10–49 interactions |
| Anti-gaming cap (<200) | 0.90 | `trust/scoring.py` | Max score with 50–199 interactions |
| Anti-gaming cap (200+) | 1.00 | `trust/scoring.py` | No cap with 200+ interactions |

### A.9 Reconciliation

| Constant | Value | Module Location | Description |
|---|---|---|---|
| `DEFAULT_TOLERANCE_FLOOR` | — | `protocol/reconciliation.py` | Minimum tolerance for divergence |
| `DEFAULT_TOLERANCE_PERCENT` | — | `protocol/reconciliation.py` | Percentage tolerance for divergence |
| `GRACE_PERIOD_SECONDS` | — | `protocol/reconciliation.py` | Reconciliation grace period |
| `MAX_EVIDENCE_SIZE_BYTES` | — | `protocol/reconciliation.py` | Max evidence payload |
| `MAX_RECEIPT_RANGE` | — | `protocol/reconciliation.py` | Max receipt sequence range |
| `MAX_TRACE_ENTRIES_PER_TOKEN` | — | `protocol/reconciliation.py` | Max trace entries per token |

### A.10 Settlement

| Constant | Value | Module Location | Description |
|---|---|---|---|
| `CHALLENGE_PERIOD_SECONDS` | — | `protocol/settlement.py` | Channel close challenge period |
| `CLOSE_REASON_COOPERATIVE` | — | `protocol/settlement.py` | Cooperative close reason code |
| `CLOSE_REASON_TIMEOUT` | — | `protocol/settlement.py` | Timeout close reason code |
| `CLOSE_REASON_UNILATERAL` | — | `protocol/settlement.py` | Unilateral close reason code |

---

## Appendix B: Error Code Registry

### B.1 HTTP Status Codes (Authority Server)

| Status | Code | Condition |
|---|---|---|
| 200 | OK | Request succeeded |
| 400 | Bad Request | Malformed request body, invalid hex token ID, already-revoked token |
| 401 | Unauthorized | Missing `X-API-Key` header or unrecognized API key |
| 403 | Forbidden | Token signature invalid, token expired, token revoked, ARM URI mismatch, missing verb |
| 404 | Not Found | Agent DID not found, tool name not found, dispute ID not found |
| 422 | Unprocessable Entity | Pydantic validation failure (missing required fields, wrong types) |
| 429 | Too Many Requests | Token bucket rate limit exhausted |
| 500 | Internal Server Error | Unhandled exception in request handler |

### B.2 QASP Protocol Error Codes (QASPErrorCode enum)

These codes are used in the QASP-Shake handshake and protocol alert messages:

| Code | Name | Description |
|---|---|---|
| 0 | OK | No error |
| 1 | PROTOCOL_VERSION_MISMATCH | Incompatible protocol version |
| 2 | UNSUPPORTED_CIPHER_SUITE | Proposed cipher suite not supported |
| 3 | HANDSHAKE_TIMEOUT | Handshake did not complete within time limit |
| 4 | AUTHENTICATION_FAILED | DID-based authentication failed |
| 5 | KEM_FAILURE | Key encapsulation mechanism error |
| 10 | INVALID_TOKEN | Token signature verification failed |
| 11 | TOKEN_EXPIRED | Token validity period exceeded |
| 12 | TOKEN_NOT_YET_VALID | Token `not_before` constraint not satisfied |
| 13 | TOKEN_REVOKED | Token appears in CRL |
| 14 | VERB_NOT_PERMITTED | Required verb not in token's VerbSet |
| 15 | RESOURCE_NOT_PERMITTED | ARM URI scope check failed |
| 20 | RATE_LIMIT_EXCEEDED | Token bucket exhausted |
| 21 | CONSTRAINT_VIOLATED | Generic token constraint violation |
| 30 | ATTENUATION_VIOLATION | Child token exceeds parent scope |
| 31 | DELEGATION_DEPTH_EXCEEDED | Delegation chain too deep |
| 32 | INVALID_DELEGATION_CHAIN | Delegation chain verification failed |
| 40 | OCSP_SIGNATURE_INVALID | OCSP response signature does not verify |
| 41 | OCSP_RESPONSE_EXPIRED | OCSP response `next_update` exceeded |
| 42 | OCSP_NONCE_MISMATCH | OCSP response nonce does not match request |
| 50 | DISCOVERY_TIMEOUT | mDNS discovery did not find peers within timeout |
| 51 | ADVERTISEMENT_INVALID | Capability advertisement signature invalid |
| 54 | CONSTRAINT_CONFLICT | Irreconcilable constraint during token aggregation |
| 55 | TOKEN_AGGREGATION_ERROR | Structural error during token aggregation |

### B.3 Capability Module Exceptions

| Exception Class | Alert Code | Raised When |
|---|---|---|
| `CapabilityError` | (base) | Base class for capability errors |
| `InvalidTokenError` | 10 | Signature verification failed |
| `TokenExpiredError` | 11 | `not_after` in the past |
| `TokenNotYetValidError` | 12 | `not_before` in the future |
| `TokenRevokedError` | 13 | Token in CRL past grace period |
| `TokenConstraintViolation` | 21 | General constraint check failed |
| `AttenuationError` | 30 | Child scope exceeds parent scope |
| `DelegationDepthExceeded` | 31 | `delegation_depth` would go below 0 |
| `InvalidDelegationChainError` | 32 | Chain entry signature invalid |
| `TemporalScheduleError` | 21 | Temporal schedule constraint violated |
| `ToolchainViolationError` | 21 | Toolchain constraint violated |
| `MultiOwnerValidationError` | 10 | Insufficient owner signatures |
| `ConstraintConflictError` | 54 | Irreconcilable aggregation constraint |
| `TokenAggregationError` | 55 | Aggregation structural error |

### B.4 Transport Exceptions

| Exception Class | Raised When |
|---|---|
| `TransportError` | Base class for transport errors |
| `ConnectionTimeoutError` | Connection did not complete within timeout |
| `ConnectionRefusedError` | Connection actively refused by remote |
| `ConnectionClosedError` | Attempted operation on closed connection |
| `SendError` | Failed to send data |
| `ReceiveError` | Failed to receive data |
| `FramingError` | Message exceeded `MAX_MESSAGE_SIZE` or malformed length prefix |
| `DiscoveryError` | mDNS discovery error |
| `DiscoveryTimeoutError` | No peers found within timeout |
| `AdvertisementError` | Advertisement signature invalid or malformed |
| `RegistryEntryError` | Registry entry is malformed or invalid |
| `RegistryQueryError` | Query to agent registry failed |
| `RegistrySignatureError` | Registry entry signature invalid |

---

## Appendix C: OID Registry

QASP uses two OID arcs: the NIST-assigned OIDs for ML-DSA-65 and ML-KEM-768, and a QASP-specific private enterprise arc.

### C.1 NIST PQC Algorithm OIDs

These OIDs are assigned by NIST in the "Computer Security Objects Register" (CSOR) for the algorithms standardized in FIPS 203 and FIPS 204.

| OID | Algorithm | Usage in QASP |
|---|---|---|
| `2.16.840.1.101.3.4.3.17` | id-ml-dsa-44 | Not used (Level 2) |
| `2.16.840.1.101.3.4.3.18` | id-ml-dsa-65 | Certificate signature algorithm; verification method type |
| `2.16.840.1.101.3.4.3.19` | id-ml-dsa-87 | Not used (Level 5) |
| `2.16.840.1.101.3.4.4.1` | id-ml-kem-512 | Not used (Level 1) |
| `2.16.840.1.101.3.4.4.2` | id-ml-kem-768 | KEM component in hybrid key exchange |
| `2.16.840.1.101.3.4.4.3` | id-ml-kem-1024 | Not used (Level 5) |

The OID `2.16.840.1.101.3.4.3.18` appears in:
- `tbsCertificate.signature` field of QASP X.509-PQ certificates
- `subjectPublicKeyInfo.algorithm` field of QASP X.509-PQ certificates

### C.2 QASP Private Enterprise OID Arc

QASP uses the private enterprise arc `1.3.6.1.4.1.59999` for QASP-specific X.509 extensions.

```
1.3.6.1.4.1.59999          (QASP root arc)
├── .1                      qasp-extensions arc
│   ├── .1                  qasp-did-extension
│   │                       OID: 1.3.6.1.4.1.59999.1
│   │                       Usage: X.509v3 extension containing the subject's
│   │                              did:qasp DID as a UTF8String
│   │
│   └── .2                  qasp-capabilities-extension
│                           OID: 1.3.6.1.4.1.59999.2
│                           Usage: X.509v3 extension containing a CBOR-encoded
│                                  list of ARM URI capabilities advertised by
│                                  the certificate subject
│
└── .2                      qasp-protocols arc (reserved for future use)
```

**OID 1.3.6.1.4.1.59999.1 (qasp-did-extension):**

```
Extension {
  extnID: 1.3.6.1.4.1.59999.1
  critical: FALSE
  extnValue: DER OCTET STRING wrapping UTF8String "did:qasp:..."
}
```

This extension binds the X.509 certificate to the holder's `did:qasp` identity, enabling verifiers to correlate certificate-based authentication with DID-based identity resolution.

**OID 1.3.6.1.4.1.59999.2 (qasp-capabilities-extension):**

```
Extension {
  extnID: 1.3.6.1.4.1.59999.2
  critical: FALSE
  extnValue: DER OCTET STRING wrapping CBOR array of UTF8String ARM URIs
             e.g., ["qasp://agents/abc/tools/analyze",
                    "qasp://agents/abc/tools/embed"]
}
```

This extension allows the certificate itself to advertise the resources the subject is authorized to offer, without requiring a separate capability token lookup.

### C.3 W3C DID Context URIs

| URI | Purpose |
|---|---|
| `https://www.w3.org/ns/did/v1` | W3C DID Core 1.0 context |
| `https://qasp.example.com/ns/qasp/v1` | QASP DID context (defines `MldSa65VerificationKey2024`) |

### C.4 W3C VC Context URIs

| URI | Purpose |
|---|---|
| `https://www.w3.org/ns/credentials/v2` | W3C VC Data Model 2.0 context |
| `https://www.w3.org/ns/credentials/examples/v2` | VC examples context (development only) |

---

*End of QASP Enterprise Documentation v0.1.0*

*This document was generated for QASP commit 239e2c2 (functionality completed).*
*For questions, refer to the project repository or open an issue.*
