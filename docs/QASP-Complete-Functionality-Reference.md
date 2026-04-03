# QASP: Complete Functionality Reference
## Quantum-Armored Service Protocol — Every Feature Explained

---

# 1. Protocol Overview

QASP (Quantum-Armored Service Protocol) is an application-layer protocol (Layer 7) that provides identity, authorization, metering, economic settlement, and post-quantum security for autonomous AI agent communication. It sits on top of TCP or QUIC and beneath agent orchestration protocols like Google A2A and Anthropic MCP.

QASP does not define what agents do — it defines who they are, what they are allowed to do, how usage is tracked, how payments are settled, and how disputes are resolved. All cryptographic operations use NIST-standardized post-quantum algorithms.

## 1.1. Protocol Stack

```
┌─────────────────────────────────────────────┐
│  Application Layer                          │
│  (A2A tasks, MCP tool calls, native QASP)   │
├─────────────────────────────────────────────┤
│  QASP Sub-Protocols                         │
│  ┌─────────┬───────────┬──────────────────┐ │
│  │ QASP-ID │ QASP-Cap  │ QASP-Settle      │ │
│  │ QASP-   │ QASP-     │ QASP-Discover    │ │
│  │ Shake   │ Meter     │                  │ │
│  └─────────┴───────────┴──────────────────┘ │
├─────────────────────────────────────────────┤
│  CBOR Framing Layer                         │
├─────────────────────────────────────────────┤
│  Transport Layer (TCP or QUIC)              │
└─────────────────────────────────────────────┘
```

## 1.2. Protocol Entities

There are four types of entities in the QASP system:

**Owners** are humans or organizations that hold root ML-DSA-65 keypairs. They are the ultimate source of authority and the accountability anchor. Every chain of trust traces back to an owner. An owner creates agents, defines their permissions, and can revoke their credentials at any time.

**Agents** are autonomous software entities (AI agents) that act on behalf of their owners. Each agent has its own ML-DSA-65 keypair and an identity (certificate or DID). Agents can only act within the bounds set by their owner. They can delegate subsets of their authority to other agents but can never escalate beyond what they were granted.

**Servers** are resource providers — GPU clusters, API endpoints, data stores, compute services. They accept capability tokens, verify authorization against the token's scope, meter resource usage, and collect payment.

**Certificate Authorities (optional)** are used in enterprise deployments to anchor the trust hierarchy. In decentralized mode, direct owner-to-agent binding replaces the CA entirely.

## 1.3. Cryptographic Foundation

All cryptographic operations in QASP use the following algorithms:

| Purpose | Algorithm | NIST Level | Key/Signature Size |
|---------|-----------|------------|-------------------|
| Digital signatures | ML-DSA-65 (FIPS 204) | Level 3 | 1,952B public key / 3,309B signature |
| Key encapsulation | ML-KEM-768 (FIPS 203) | Level 3 | 1,184B public key / 1,088B ciphertext / 32B shared secret |
| Hybrid signatures | ML-DSA-65 + Ed25519 | Level 3+ | Combined classical + PQ |
| Hybrid KEM | ML-KEM-768 + X25519 | Level 3+ | Combined classical + PQ |
| Hashing | SHA-384 / SHA3-384 | 192-bit | 48 bytes |
| Symmetric encryption | AES-256-GCM | 256-bit | — |
| Key derivation | HKDF-SHA-384 | — | — |

NIST Security Level 3 provides the equivalent of AES-192 security against quantum attacks. Level 5 (ML-DSA-87) signatures are 40% larger (4,627B vs 3,309B) with no practical benefit — Level 3 is considered sufficient against all known quantum attacks through at least 2060+.

## 1.4. Wire Format

All QASP messages share a common binary frame:

```
┌──────────┬─────────┬──────────┬────────────────┬──────────────────┬─────────────────┐
│ Magic    │ Version │ Msg Type │ Payload Length │ CBOR Payload     │ HMAC-SHA-384    │
│ 2 bytes  │ 1 byte  │ 1 byte   │ 4 bytes (BE)   │ Variable         │ 48 bytes        │
│ 0x5141   │         │          │                │                  │                 │
│ ("QA")   │         │          │                │                  │                 │
└──────────┴─────────┴──────────┴────────────────┴──────────────────┴─────────────────┘
```

The HMAC-SHA-384 integrity tag is computed over the header and payload using the session key established during QASP-Shake. All payloads use CBOR (Concise Binary Object Representation) encoding for compactness — critical because PQ artifacts are significantly larger than classical equivalents.

## 1.5. Message Types

QASP defines 28 message types (as implemented in `framing/messages.py`):

| ID | Message | Direction | Purpose |
|----|---------|-----------|---------|
| 0x01 | ClientHello | Initiator → Responder | Begin handshake |
| 0x02 | ServerHello | Responder → Initiator | Handshake response |
| 0x03 | ClientAuth | Initiator → Responder | Complete handshake |
| 0x04 | ApplicationData | Any → Any | Encrypted application data |
| 0x05 | TokenRevocation | Owner/Server → All | Revoke a capability token |
| 0x06 | RevocationNotice | Any → Any | Notify of cascading revocation |
| 0x07 | ResourceRequest | Agent → Server | Request access to a resource |
| 0x08 | ResourceGrant | Server → Agent | Approve resource access |
| 0x09 | MeterAck | Agent → Server | Acknowledge metering report |
| 0x0A | ResourceSuspend | Server → Agent | Suspend resource for constraint violation |
| 0x0B | ResourceDeny | Server → Agent | Reject resource request |
| 0x0C | ResourceRelease | Agent → Server | Release resource when done |
| 0x0D | DisputeOpen | Agent → Auditor | Open a usage/billing dispute |
| 0x0E | DisputeEvidence | Any → Auditor | Submit evidence for dispute |
| 0x0F | DisputeVerdict | Auditor → All | Issue binding dispute resolution |
| 0x10 | MeterReport | Server → Agent | Report resource consumption |
| 0x11 | ChannelOpen | Agent ↔ Server | Open payment channel |
| 0x12 | ChannelClose | Agent/Server → All | Close payment channel |
| 0x13 | PriceRequest | Agent → Server | Request pricing terms |
| 0x14 | Alert | Any → Any | Protocol-level alert |
| 0x15 | PriceOffer | Server → Agent | Offer pricing terms |
| 0x16 | PriceAccept | Agent → Server | Accept pricing terms |
| 0x17 | DelegationRequest | Agent₁ → Agent₂ | Request cross-domain delegation |
| 0x18 | DelegationGrant | Agent₂ → Agent₁ | Approve cross-domain delegation |
| 0x19 | ReconciliationRequest | Any → Any | Request metering reconciliation |
| 0x1A | ReconciliationResponse | Any → Any | Respond to reconciliation |
| 0x1B | OCSPRequest | Server → Issuer | Request token revocation status |
| 0x1C | OCSPResponse | Issuer → Server | Return token revocation status |

## 1.6. Error Codes

| Code | Name | Recovery Action |
|------|------|-----------------|
| 0x01 | VERSION_MISMATCH | Retry with offered version |
| 0x02 | SUITE_MISMATCH | Retry with common cipher suite |
| 0x03 | AUTH_FAILED | Re-authenticate |
| 0x04 | TOKEN_EXPIRED | Request new token |
| 0x05 | TOKEN_REVOKED | Request new delegation |
| 0x06 | DEPTH_EXCEEDED | Flatten delegation chain |
| 0x07 | CONSTRAINT_VIOLATED | Attenuate request to fit constraints |
| 0x08 | BUDGET_EXHAUSTED | Top up budget or close session |
| 0x09 | RATE_LIMITED | Backoff and retry |
| 0x0A | UPGRADE_REQUIRED | Use PQ cipher suite |
| 0x0B | DISPUTE_PENDING | Await auditor verdict |
| 0x0C | CHANNEL_CLOSED | Open new payment channel |
| 0xFF | INTERNAL_ERROR | Retry or abort |

Every error response includes a `retry_after` field (seconds) and a `detail` string. Clients MUST implement exponential backoff for retryable errors with a maximum of 5 retries.

**Implementation**: The `QASPErrorCode` enum (`protocol/exceptions.py`) defines all 13 wire-level error codes as an `IntEnum`. The `error_code_for_exception()` function maps Python exception types (e.g., `HandshakeVersionError` → `VERSION_MISMATCH`, `HandshakeAuthError` → `AUTH_FAILED`) to their wire codes, returning `INTERNAL_ERROR` (0xFF) for unmapped exceptions.

---

# 2. QASP-ID: Identity and PKI Management

QASP-ID handles how every entity in the system proves who it is. It supports two complementary identity models that produce equivalent trust chains — the rest of the QASP stack doesn't care which one you use.

## 2.1. PKI Mode (Centralized)

In PKI mode, identity follows a traditional certificate hierarchy:

```
Root CA (optional)
  └── Owner Certificate (ML-DSA-65 signed)
        └── Agent Certificate (ML-DSA-65 signed)
              └── Ephemeral Session Key (per-session via ML-KEM-768)
```

Each certificate contains:
- Agent ID (UUID v7 or DID)
- Issuer reference (owner's public key fingerprint or owner DID)
- ML-DSA-65 public key (1,952 bytes)
- Validity period (not-before / not-after timestamps)
- Owner-binding proof (owner's signature over the agent's identity)
- Permitted capability classes (what categories of resources this agent may access)
- Maximum delegation depth (how many times this agent can re-delegate authority)
- Spending limits (maximum monetary authority)

The certificate profile follows RFC 9881 (published October 2025) which defines the standard X.509 profile for ML-DSA. The assigned OID for ML-DSA-65 is `2.16.840.1.101.3.4.3.18`. Certificates MUST use pure ML-DSA (not HashML-DSA), and keyUsage MUST include `digitalSignature` but MUST NOT include `keyEncipherment`.

## 2.2. DID Mode (Decentralized)

In DID mode, identity is self-sovereign. The `did:qasp` method enables agents to have cryptographically verifiable identity without any centralized authority.

### 2.2.1. DID Generation

A `did:qasp` identifier is derived deterministically from the agent's ML-DSA-65 public key:

```
did:qasp:<base58btc(SHA-384(ML-DSA-65-PK)[0:32])>
```

This is a one-way derivation — you can verify that a DID belongs to a specific public key, but you cannot derive the public key from the DID alone (the SHA-384 hash is truncated to 32 bytes).

### 2.2.2. DID Document

The DID Document follows the W3C DID Core specification and contains:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/pq-2025"
  ],
  "id": "did:qasp:z6MkhaXgBZD...",
  "verificationMethod": [{
    "id": "did:qasp:z6MkhaXgBZD...#key-1",
    "type": "MLDSAVerificationKey2025",
    "controller": "did:qasp:z6MkhaXgBZD...",
    "publicKeyMultibase": "z4BWwf..."
  }],
  "authentication": [
    "did:qasp:z6MkhaXgBZD...#key-1"
  ],
  "capabilityDelegation": [
    "did:qasp:z6MkhaXgBZD...#key-1"
  ],
  "service": [{
    "id": "did:qasp:z6MkhaXgBZD...#qasp",
    "type": "QASPEndpoint",
    "serviceEndpoint": "qasp://example.com:4433"
  }],
  "ownerBinding": {
    "ownerDID": "did:qasp:z6MkownerXYZ...",
    "delegationProof": "<ML-DSA-65 signature>"
  }
}
```

### 2.2.3. DID Resolution

DID Documents are resolved via a multi-tier resolution architecture (implemented in `identity/resolver.py`):

**Tier 1 — L1 Cache**: An in-process LRU cache with configurable TTL provides instant resolution for recently-seen DIDs. Cache hits avoid all network and registry lookups.

**Tier 2 — L2 DIDRegistry**: An in-memory registry (`identity/did.py`) populated during QASP-Shake handshake exchanges. Thread-safe with Lock-based concurrent access.

**Tier 3 — L3 Backend (DHT/VDR)**: A pluggable resolver backend (conforming to the `ResolverBackend` protocol) for persistent storage. The reference implementation uses SQLite. Each entry is a signed `DHTEntry` structure with version-based replay prevention — a newer `version` field must strictly exceed the stored version to accept an update. The entry is signed by the agent's ML-DSA-65 key, ensuring only the key holder can publish or update it.

Resolution proceeds through tiers in order (L1 → L2 → L3), with successful lookups populating higher-tier caches for subsequent requests.

DID Documents are also available through two additional channels:
1. **Direct exchange**: During QASP-Shake, peers include their DID Documents in handshake messages — fully decentralized, no infrastructure needed.
2. **QASP-Discover**: DID Documents are embedded in PQ-signed capability advertisements broadcast via DNS-SD/mDNS.

### 2.2.4. Owner Binding

The `ownerBinding` field links the agent DID to its owner's DID via a cross-signed proof. The owner signs the tuple `⟨agent_did, owner_did, permissions, expiry⟩` with their ML-DSA-65 key. This replaces the centralized CA chain with a verifiable delegation from owner to agent while preserving the same security guarantees: every agent traces back to a responsible human or organization.

### 2.2.5. Optional CA Anchoring

Enterprise deployments MAY anchor `did:qasp` identities to a traditional CA by including a `caAttestation` field containing an ML-DSA-65-signed certificate from the organization's CA. This provides a migration path: organizations start with CA-anchored DIDs and optionally transition to fully self-sovereign operation.

### 2.2.6. Key Rotation

DID Documents include a `keyRotation` section specifying the hash of the next public key. This enables pre-committed key rotation. The rotation is performed by publishing an updated DID Document signed by BOTH the current and next keys. This prevents hostile takeover even if the current key is compromised — the attacker would also need the pre-committed next key.

---

# 3. QASP-Discover: Service Discovery

Before agents can handshake, they need to find each other. QASP-Discover provides PQ-secured service discovery.

## 3.1. Discovery Modes

### 3.1.1. Local Discovery (mDNS/DNS-SD)

Agents on the same network segment broadcast DNS-SD service records with service type `_qasp._tcp`. The TXT record contains a PQ-signed capability advertisement. This enables zero-configuration discovery in LAN and edge environments — no external infrastructure required.

### 3.1.2. Wide-Area Discovery (DNS)

Agents publish SRV and TXT records under their domain:

```
_qasp._tcp.agent.example.com
```

DNSSEC provides transport integrity. The PQ-signed content in the TXT payload provides content integrity. This enables internet-scale discovery through existing DNS infrastructure.

### 3.1.3. Registry Discovery

A QASP registry service (analogous to a service mesh control plane) maintains a directory of agent DIDs, capabilities, and endpoints. The registry is queried via QASP-Shake-protected channels, and all entries are PQ-signed by the advertising agent. This mode provides structured, queryable discovery for large-scale deployments.

## 3.2. PQ-Signed Capability Advertisement

Every discovery advertisement is a CBOR-encoded, ML-DSA-65-signed structure:

```
CapabilityAd = {
  version:      uint,           -- protocol version
  agent_did:    tstr,           -- did:qasp identifier
  endpoints:    [+ Endpoint],   -- transport addresses
  capabilities: [+ CapEntry],   -- ARM resource/verb pairs
  constraints:  ConstraintSet,  -- global limits
  did_document: bytes,          -- embedded DID Document
  timestamp:    uint,           -- Unix epoch
  ttl:          uint,           -- cache lifetime in seconds
  signature:    bytes           -- ML-DSA-65 over all fields above
}

CapEntry = {
  resource: tstr,       -- ARM URI (e.g., "qasp://acme/gpu/a100")
  verbs:    [+ tstr]    -- ARM verb set (e.g., ["exec", "read"])
}
```

The ML-DSA-65 signature prevents advertisement spoofing — a quantum adversary cannot forge a valid advertisement without the agent's private key. The TTL enables cache expiry. The timestamp prevents replay of stale advertisements.

## 3.3. Discovery-to-Handshake Pipeline

When a client agent receives a valid capability advertisement:

1. **Verify** the ML-DSA-65 signature over the advertisement
2. **Extract** the DID Document and resolve the owner binding
3. **Check** that the advertised capabilities match the client's needs
4. **Initiate** QASP-Shake to the advertised endpoint, including the advertisement hash in the ClientHello for binding

The advertisement hash in the ClientHello cryptographically ties the discovery phase to the handshake — an attacker cannot redirect a client to a different server after discovery without being detected.

---

# 4. QASP-Shake: Handshake and Secure Channel Establishment

QASP-Shake establishes a mutually authenticated, quantum-resistant encrypted channel between two parties through a three-message exchange.

## 4.1. The Three-Message Exchange

### Message 1 — ClientHello (Initiator → Responder)

The initiating agent sends:
- Protocol version
- ML-KEM-768 encapsulation key (public key for the key exchange)
- List of supported cipher suites (in preference order)
- Client nonce (random, for key derivation)
- (Optional) X25519 public key for hybrid mode
- (Optional) QASP-Discover advertisement hash for discovery binding

### Message 2 — ServerHello (Responder → Initiator)

The responding agent sends:
- Selected cipher suite
- ML-KEM-768 ciphertext (encapsulated shared secret using the client's public key — only the client can decapsulate this)
- Server nonce
- Server identity (certificate chain or DID Document)
- (Optional) X25519 public key for hybrid mode
- ML-DSA-65 signature over the entire transcript up to this point

### Message 3 — ClientAuth (Initiator → Responder)

The initiating agent sends:
- Client identity (certificate chain or DID Document)
- ML-DSA-65 signature over the full transcript
- (Optional) capability token request (to pipeline authorization with the handshake)

## 4.2. Key Derivation

Both sides derive the session key using HKDF:

```
SS = HKDF(ML-KEM_shared_secret ∥ X25519_shared_secret, Nc ∥ Ns, "QASP-v1")
```

Where:
- `ML-KEM_shared_secret` = 32-byte shared secret from ML-KEM-768 encapsulation/decapsulation
- `X25519_shared_secret` = 32-byte shared secret from X25519 key exchange (omitted in PQ-only mode)
- `Nc` = client nonce
- `Ns` = server nonce
- `"QASP-v1"` = context string

The resulting symmetric key protects all subsequent communication using AES-256-GCM or ChaCha20-Poly1305.

In hybrid mode, an attacker must break BOTH the lattice problem (ML-KEM) AND the elliptic curve problem (X25519) to recover the session key. In PQ-only mode, the X25519 component is simply omitted.

## 4.3. State Machine

The handshake is specified as a deterministic finite state machine with 8 states and 14 transitions:

```
            ┌──────────────────────────────────────────┐
            │                                          │
    ┌───────▼───────┐    connect()    ┌──────────────┐ │
    │     IDLE      │───────────────▶│  HELLO_SENT  │ │
    │               │◀─ recv(CH)──── │              │ │
    └───────┬───────┘                └──────┬───────┘ │
            │                               │         │
      recv(CH)                         recv(SH)       │
      validate ok                     verify ok       │
            │                               │         │
    ┌───────▼───────┐                ┌──────▼───────┐ │
    │ HELLO_RECVD   │                │   AUTHING    │ │
    │               │                │              │ │
    └───────┬───────┘                └──────┬───────┘ │
            │                               │         │
      validate ok                     verify ok       │
      send SH                               │         │
            │                               │         │
    ┌───────▼───────┐                       │         │
    │   SH_SENT     │                       │         │
    │               │                       │         │
    └───────┬───────┘                       │         │
            │                               │         │
      recv(CA)                              │         │
      verify ok                             │         │
            │                               │         │
    ┌───────▼───────────────────────────────▼───────┐ │
    │              ESTABLISHED                      │ │
    │         (secure channel ready)                 │ │
    └───────────────────┬───────────────────────────┘ │
                        │ close()                     │
                        └─────────────────────────────┘

    Any state ──timeout/verify_fail──▶ ERROR ──▶ IDLE
```

### Timeout and Retransmission

- Default handshake timeout: 30 seconds
- Over unreliable transports (UDP/QUIC): retransmit with exponential backoff (1s, 2s, 4s, max 3 retries)
- `message_seq` counter in each handshake message enables deduplication

### Version Mismatch Handling

If the server does not support the client's proposed version, it responds with `Alert(version_mismatch, supported_versions=[...])`. The client may retry with a compatible version. Maximum negotiation rounds: 2. Failure after that terminates with `Alert(fatal_version_mismatch)`.

## 4.4. Cipher Suite Profiles

QASP defines three named profiles for different deployment scenarios:

| Profile | KEM Algorithm | Signature Algorithm | Use Case |
|---------|---------------|--------------------| ---------|
| **PQ-Strict** | ML-KEM-768 | ML-DSA-65 | High-security, government deployments |
| **Hybrid-Transition** | ML-KEM-768 + X25519 | ML-DSA-65 + Ed25519 | Recommended default (2025–2035) |
| **Classical-Compat** | X25519 | Ed25519 | Legacy interop only |

Tokens issued under Classical-Compat carry a `pq_warning` flag and a maximum validity of 24 hours (vs. 30 days for PQ profiles).

## 4.5. Crypto Agility

QASP maintains a versioned cipher suite registry (analogous to TLS cipher suites). Each entry specifies a KEM algorithm, signature algorithm, hash function, and AEAD cipher, identified by a 16-bit suite ID. New suites can be added via registry updates without changing the protocol framing or handshake structure.

## 4.6. Mandatory Downgrade Resistance

During QASP-Shake:
- The selected suite MUST be the highest-security suite supported by both parties (server preference breaks ties)
- If the server supports any PQ suite and the client advertises only classical suites, the server MUST reject with `UPGRADE_REQUIRED` (unless explicitly configured for Classical-Compat)
- The selected suite ID is included in the transcript hash — any downgrade attempt by an attacker is detected by the transcript signature

## 4.7. Performance Characteristics

| Operation | Classical | PQ-Only | Hybrid |
|-----------|-----------|---------|--------|
| Certificate size | ~300B | ~5.6KB | ~5.9KB |
| Token size | ~200B | ~3.8KB | ~4.1KB |
| Handshake bandwidth | ~1KB | ~12KB | ~13KB |
| Sign time | ~50μs | ~1.5ms | ~1.6ms |
| Verify time | ~120μs | ~0.8ms | ~0.9ms |
| KEM encaps time | ~100μs | ~0.6ms | ~0.7ms |

## 4.8. Connection Management

The `QASPConnection` class (`protocol/connection.py`) implements a sans-I/O connection manager that separates protocol logic from transport:

- **`receive_bytes(data)`**: Feed incoming bytes from the transport layer
- **`bytes_to_send()`**: Retrieve outgoing bytes to send on the transport
- **`send_data(payload)`**: Queue application data for encrypted transmission

The connection manages handshake timeout with exponential backoff and generates typed events (from `protocol/events.py`) for state changes. The sans-I/O design enables use with any transport (TCP, QUIC, in-memory) and simplifies testing.

## 4.9. Stream Multiplexing

The `StreamManager` (`protocol/stream.py`) provides HTTP/2-style stream multiplexing over a single QASP connection:

- **Stream ID convention**: Odd IDs for client-initiated streams, even IDs for server-initiated
- **`StreamFrame`**: Carries stream ID, payload, and flags (including `END_STREAM`)
- **`StreamState`** FSM: `OPEN` → `HALF_CLOSED_LOCAL` / `HALF_CLOSED_REMOTE` → `CLOSED`
- **`Stream`**: Individual stream with send/receive buffers and state tracking

This enables concurrent, independent request-response flows over a single authenticated channel without head-of-line blocking.

---

# 5. Universal Agent Resource Model (ARM)

ARM is a canonical ontology for expressing what an agent can do with a resource. It is intentionally decoupled from the QASP wire format — ARM can serve as a ground-truth vocabulary for any agent ecosystem, even those that do not use QASP's handshake or framing. If two systems agree on ARM semantics, capability tokens and authorization policies become interoperable regardless of the underlying transport.

## 5.1. Resource Identifiers

Every resource is named by a structured URI:

```
qasp://{provider}/{resource}/{subresource}
```

Examples:
- `qasp://acme-cloud/gpu/a100` — a specific GPU type on Acme Cloud
- `qasp://data-co/dataset/medical-records/row-level` — row-level access to a specific dataset
- `qasp://acme-cloud/gpu/*` — wildcard covering all GPU sub-resources

The hierarchical structure enables prefix-based attenuation: a token scoped to `qasp://acme-cloud/gpu/*` covers all GPU sub-resources. A token attenuated to `qasp://acme-cloud/gpu/a100` covers only A100s.

The URI grammar in ABNF:
```
qasp-uri    = "qasp://" provider "/" resource ["/" subresource]
provider    = 1*( ALPHA / DIGIT / "-" / "." )
resource    = 1*( ALPHA / DIGIT / "-" / "_" )
subresource = 1*( ALPHA / DIGIT / "-" / "_" / "/" )
```

## 5.2. Action Verbs

ARM defines seven canonical verbs spanning the full lifecycle of agent-resource interaction:

| Verb | Purpose | Example |
|------|---------|---------|
| `read` | Data-plane read access | Read a dataset, fetch an API response |
| `write` | Data-plane write access | Store results, update a record |
| `exec` | Invoke a computation or tool | Run a GPU job, call an API endpoint |
| `delegate` | Pass a subset of rights to another agent | Sub-delegate compute authority |
| `charge` | Bill against a spending budget | Debit from allocated funds |
| `attenuate` | Narrow an existing token's scope | Reduce spending limit on a delegated token |
| `revoke` | Invalidate a token and its descendants | Cancel a compromised credential |

Every capability token contains a subset of these verbs. The server enforces that the requested action is in the token's verb set. An agent with `[exec, read]` cannot `write` or `delegate`.

**Implementation**: The seven canonical verbs are defined as constants (`ARM_READ` through `ARM_REVOKE`) in `protocol/capability.py`, with an `ARM_VERBS` frozenset containing all seven. These constants ensure consistent verb usage across the codebase and can be used directly with `VerbSet(ARM_VERBS)` for token construction.

## 5.3. First-Class Constraints

ARM elevates six constraint dimensions to first-class citizens of every token. These are structurally typed and machine-comparable, which means the token algebra can compute intersections and detect escalation attempts purely by comparing constraint fields — no policy-engine side-channel is needed.

| Constraint | Semantics | Example |
|------------|-----------|---------|
| `time` | Validity window (not-before / not-after) | Valid from 2026-02-21T10:00Z to 2026-02-21T12:00Z |
| `quantity` | Maximum units consumable | 2 vCPU-hours, 1000 API calls, 50GB storage |
| `rate` | Maximum units per time window | 100 requests per minute, 10 vCPU-hours per day |
| `spend` | Monetary ceiling in base currency | $2.50 maximum, €100 per session |
| `data-scope` | Row/column/partition restrictions | Rows where region='EU', columns excluding PII |
| `purpose` | Free-text or enum binding | "audit", "research", "model-training", "data-analysis" |

Constraint CDDL schema:
```
constraint-set = {
  ? time:       [uint, uint],        -- [not-before, not-after] as Unix timestamps
  ? quantity:   decimal,             -- max consumable units
  ? rate:       [decimal, uint],     -- [max-units, window-seconds]
  ? spend:      decimal,             -- monetary ceiling
  ? data_scope: tstr,               -- scope expression
  ? purpose:    tstr                 -- declared intent
}
```

## 5.4. ARM as Ground Truth

ARM is designed to be a portable, auditable representation that bridges different authorization systems. Even if an ecosystem uses OAuth scopes, XACML, or ad-hoc JSON policies internally, mapping those policies to and from ARM yields an interoperable representation.

ARM registries (analogous to IANA media-type registries) allow providers to publish their resource hierarchies and supported verbs, enabling automated capability discovery across heterogeneous agent platforms.

---

# 6. QASP-Cap: Capability Tokens and Authorization

Capability tokens are the core authorization primitive in QASP. They are signed, scoped, time-bound, and attenuable.

## 6.1. Token Structure

Each token is CBOR-encoded and ML-DSA-65-signed. It contains:

```
capability-token = {
  version:               uint,
  token_id:              bytes .size 16,     -- UUID v7
  issued_at:             uint,               -- Unix timestamp
  expires_at:            uint,               -- Unix timestamp
  issuer:                tstr / bytes,       -- DID or key fingerprint
  subject:               tstr / bytes,       -- agent receiving the token
  audience:              tstr / bytes,       -- server that will verify
  resource:              tstr,               -- ARM URI
  verbs:                 [+ tstr],           -- ARM verb set
  constraints:           constraint-set,     -- ARM constraints (Table above)
  parent_ref:            bytes / null,       -- parent token ID (for delegation)
  chain:                 [* delegation-link],-- full delegation chain
  purpose:               tstr / null,        -- context binding
  toolchain:             [* tstr] / null,    -- allowed service classes
  authority_chains:      [* authority-entry] / null, -- multi-owner
  temporal_attenuation:  attenuation-schedule / null,
  pricing:               price-schedule / null,
  signature:             bytes               -- ML-DSA-65 over all above
}
```

Example token in plain language: "Agent Alpha may `exec` up to 2 vCPU-hours on `qasp://acme-cloud/gpu/a100`, spending at most $2.50, valid for 2 hours, purpose=training, delegation permitted up to depth 2."

## 6.2. Token Algebra

The token algebra defines three operations that make the authorization system formally safe. These operations ensure least privilege by construction — every derived token is provably no more powerful than its ancestor.

### 6.2.1. Attenuation

```
T' = att(T, Δ)
```

Produces a new token T' where:
- The verb set of T' is a subset of T's verb set: `V_T' ⊆ V_T`
- Every constraint in T' is at most as permissive as in T
- Δ specifies the narrowing

**Escalation is algebraically impossible**: for all Δ, `att(T, Δ) ⪯ T`. This is proved by structural induction on the chain depth, using the monotonicity of constraint intersection.

Example: Token T allows `[exec, read, delegate]` on `qasp://acme/gpu/*` with $5 spend limit. Attenuating with Δ = {verbs: [exec], resource: "qasp://acme/gpu/a100", spend: 2.50} produces T' allowing only `exec` on only A100s with only $2.50.

### 6.2.2. Splitting

```
T → T₁, T₂
```

Partitions a quantitative constraint such that `q_T₁ + q_T₂ ≤ q_T`. This enables parallel sub-delegation without over-committing resources.

Example: Token T allows 2 vCPU-hours. Split into T₁ (1 vCPU-hour for Agent Beta) and T₂ (1 vCPU-hour for Agent Gamma). Neither agent can exceed their allocation, and the total cannot exceed the original 2 hours.

### 6.2.3. Intersection

```
T_result = T_a ∩ T_b
```

Produces a token whose:
- Verb set is `V_a ∩ V_b` (only verbs in both)
- Constraints are the component-wise minimum (tightest) of both parents

Used when two authorization paths must both agree (e.g., multi-owner tokens where corporate policy and employee authorization must both validate).

## 6.3. Token Aggregation Algebra

Agents may present multiple capability tokens simultaneously to compose permissions. The aggregation follows a union-with-constraint-intersection algebra:

```
Agg(T₁, T₂) = {
  V = V₁ ∪ V₂                       -- verb sets are unioned
  R = R₁ ∪ R₂                       -- resource sets are unioned
  C = C₁ ⊓ C₂ (on shared dimensions) -- constraints are intersected
}
```

Unshared constraint dimensions are inherited from the token that defines them. The server verifies each token independently and then computes the aggregation — no single token need authorize the full request.

Example: Agent holds Token A (exec on GPUs, $3 spend) and Token B (read on datasets, 1000 rows). Aggregation allows both exec-on-GPUs and read-on-datasets in a single session.

## 6.4. Delegation Chains

Delegation allows an agent to grant a subset of its capabilities to another agent. QASP formalizes this as a chain of attenuations.

### 6.4.1. Chain Construction

```
Owner Alice ──issues──▶ T₀ (Agent Alpha: 2 vCPU-h, $2.50, depth=2)
Agent Alpha ──att(T₀,Δ₁)──▶ T₁ (Agent Beta: 1 vCPU-h, $1.00, depth=1)
Agent Beta  ──att(T₁,Δ₂)──▶ T₂ (Agent Gamma: 0.5 vCPU-h, $0.50, depth=0)
```

Each delegation link is a CBOR structure:
```
delegation-link = {
  delegator:   tstr / bytes,        -- DID or fingerprint of delegator
  token_ref:   bytes .size 16,      -- token ID of the delegated token
  attenuation: constraint-set,      -- how permissions were narrowed
  signature:   bytes                -- ML-DSA-65 signature
}
```

### 6.4.2. Delegation Rules

1. **Attenuation only**: A delegatee's permissions must be a strict subset of the delegator's. Escalation is impossible by the token algebra.
2. **Depth limit**: `maxDelegationDepth` in the original token limits chain length. When depth reaches 0, the token is non-delegatable.
3. **Chain verification**: The server verifies the aggregate signature covering the full chain. Individual verification is possible as a fallback.
4. **Revocation cascades**: Revoking any token in the chain revokes ALL descendants.

### 6.4.3. Signature Aggregation for Deep Chains

A delegation chain of depth d naively requires d separate ML-DSA-65 signature verifications. To reduce overhead, QASP supports aggregate signatures using a sequential aggregation construction: each delegator signs the concatenation of the previous aggregate and the new token, yielding a single final signature that implicitly covers every link.

Verification cost: O(1) signature checks + O(d) hash computations (vs. O(d) signature checks without aggregation).

## 6.5. M-of-N Threshold Delegation

For high-value capabilities, QASP supports M-of-N threshold authorization. An owner group (O₁, ..., O_N) collectively issues a token requiring M signatures for activation.

The construction uses Shamir secret sharing over the ML-DSA-65 signing key: each owner holds a key share sk_i, and M owners produce partial signatures that are combined into a single valid ML-DSA-65 signature. The resulting token is indistinguishable from a single-signer token to verifiers, but required distributed authorization to create.

Example: A $1M compute budget requires 3-of-5 board members to sign the token. No individual can unilaterally authorize the expenditure.

**Implementation**: The `identity/group.py` module provides `ThresholdGroup` for managing group DIDs created from distributed key generation (DKG) results. Key functions include `create_threshold_group()` (creates a group DID from DKG output), `is_threshold_did()` (checks if a DID represents a threshold group), and `get_threshold_policy()` (retrieves M-of-N policy from the DID Document service endpoint). The threshold policy is encoded in the group's DID Document service endpoint metadata.

## 6.6. Temporal Capability Evolution

Tokens may include a `temporal_attenuation` schedule that automatically reduces permissions over time:

```
temporal_attenuation: {
  schedule: [
    { at: "T+1h", spend_limit: 0.75 },
    { at: "T+2h", spend_limit: 0.50 },
    { at: "T+3h", spend_limit: 0.25 }
  ],
  policy: "linear_decay"    -- or "step", "exponential"
}
```

The server evaluates the schedule at each request, applying the most restrictive constraint whose time threshold has been reached. This enables "use it or lose it" patterns where tokens naturally attenuate as they approach expiry.

Supported policies:
- **linear_decay**: Permissions decrease linearly over time
- **step**: Permissions drop at discrete thresholds
- **exponential**: Permissions decay exponentially (aggressive attenuation)

## 6.7. Cross-Domain Delegation

When Agent Alpha (owned by Alice) needs to delegate to Agent Beta (owned by Bob), a trust boundary crossing occurs. QASP handles this via a cross-domain delegation token that carries:

1. Alice's original token T_A authorizing Alpha
2. Alpha's attenuation T_{A→B} = att(T_A, Δ) scoped for Beta
3. A cross-domain endorsement: Alice signs ⟨T_{A→B}, Bob's DID⟩, explicitly authorizing a foreign-owner agent to exercise a subset of capabilities
4. Bob's countersignature accepting accountability for Beta's actions under this token

The server verifies the full chain: Alice → Alpha → Beta, with both owner signatures covering the cross-domain boundary. This prevents unauthorized cross-domain delegation while enabling legitimate multi-party workflows.

## 6.8. Multi-Owner and Organizational Delegation

Enterprise environments require capabilities governed by multiple authorities simultaneously.

### 6.8.1. Authority Chains

A multi-owner token carries an `authority_chains` array, each entry being an independent delegation chain:

```
authority_chains: [
  { role: "employee",   chain: [T_employee] },
  { role: "department", chain: [T_dept_policy] },
  { role: "corporate",  chain: [T_corp_spending] }
],
composition: "all"    -- all chains must validate
```

The server verifies each chain independently and computes the intersection of all constraints. A request is authorized only if it falls within the intersection of ALL authority chains.

### 6.8.2. Corporate Travel Agent Example

A travel-booking agent authorized by three authorities:

1. **Employee (Alice)**: "Book flights for me, up to $2,000/trip"
2. **Department policy**: "Marketing employees may book economy class only, max 3 trips/month"
3. **Corporate spending cap**: "Total Q1 travel budget: $50,000 remaining: $12,340"

The agent presents a token with three authority chains. The server intersects: the agent may book economy flights, up to min($2,000, $12,340) = $2,000 per trip, max 3/month, charged against both Alice's personal limit and the corporate budget.

### 6.8.3. SPIFFE/SPIRE Integration

For workload identity in cloud-native environments, QASP authority chains can include SPIFFE Verifiable Identity Documents (SVIDs) as an authority chain entry. The SVID provides platform attestation ("this agent is running in namespace X on cluster Y"), while QASP provides the capability authorization.

## 6.9. Selective Disclosure

In privacy-sensitive contexts, a delegate may need to prove "I am authorized to exec on this resource" without revealing the full token (which may disclose spending limits, the delegator's identity, or other constraints).

QASP supports selective disclosure via two mechanisms:

1. **Hash-based commitment**: The full token is Merkle-ized. The delegate reveals only the Merkle tree branches relevant to the verifier's query.

2. **Zero-knowledge proof of inclusion**: The delegate proves that the presented verb/resource pair is contained within a validly signed token without revealing remaining fields.

This balances authorization verification with data minimization, aligning with privacy regulations such as GDPR.

## 6.10. Tool-Chaining Security

In multi-agent workflows, an agent often invokes a chain of tools. Without safeguards, a capability granted for Tool 1 could be implicitly exercised against Tool 2.

### 6.10.1. Capability Firebreaks

Capabilities are non-transitive across tool boundaries by default. When Agent A's tool invocation triggers a sub-invocation on a different service, the sub-invocation requires a fresh token explicitly re-minted (attenuated) from Agent A's original token:

1. Agent A attenuates its token T to T' = att(T, Δ_tool2), restricting the resource URI, verb set, and constraints to exactly what Tool 2 needs
2. T' is signed by Agent A and includes a `parent_ref` pointing to T
3. The server hosting Tool 2 verifies the chain T → T' and confirms that T' is appropriately scoped

### 6.10.2. Context Binding

Every capability token includes two additional ARM fields for tool-chain confinement:

- **`purpose`**: A structured label (e.g., "data-analysis", "model-training") that binds the token to a declared intent. Servers MAY reject tokens whose purpose does not match the service category.

- **`allowed_toolchain`**: An ordered list of tool/service classes (e.g., ["compute", "storage"]) that the token may traverse. If a tool invocation would exit the allowed toolchain, the server rejects the request.

Together, firebreaks and context binding confine the blast radius of any single compromised agent or tool within a multi-step workflow.

## 6.11. Token Replay Prevention

The `TokenUseLog` (`protocol/token_use_log.py`) provides thread-safe single-use enforcement for capability tokens:

- **`mark_used(token_id)`**: Atomically marks a token ID as used. Raises `TokenReplayError` if already used.
- **`is_used(token_id)`**: Check whether a token has been consumed.

This prevents replay attacks where an attacker captures and re-submits a valid capability token. The log is checked at token verification time, before any resource access is granted.

---

# 7. QASP-Meter: Metering and Accounting

Resource usage is tracked via periodic exchanges that produce a tamper-evident audit trail.

## 7.1. Metering Flow

```
Agent                           Server
  │                               │
  │──── ResourceRequest ────────▶│
  │                               │
  │◀──── ResourceGrant ──────────│  (includes capability token)
  │                               │
  │     [Agent uses resource]     │
  │                               │
  │◀──── MeterReport ────────────│  (cumulative units, cost, ML-DSA-65 sig)
  │                               │
  │──── MeterAck ────────────────▶│  (counter-signature)
  │                               │
  │     [repeated periodically]   │
  │                               │
  │──── ResourceRelease ─────────▶│
  │                               │
```

### MeterReport (Server → Agent)

Contains cumulative units consumed, cost accrued, and an ML-DSA-65 signature. Sent periodically during resource consumption.

### MeterAck (Agent → Server)

The agent's signed acknowledgment of the metering report. Contains the agent's ML-DSA-65 counter-signature.

### ResourceSuspend

If any constraint is exceeded (budget exhausted, rate limit hit, time window expired), the server issues a ResourceSuspend. The agent must either close the session or request a new/upgraded token.

## 7.2. Hash-Chained Usage Receipts

Each metering exchange produces a usage receipt in canonical CBOR form:

```
Receipt = {
  token_id:   bytes,     -- UUID of the capability token
  seq:        uint,      -- monotonic sequence number
  window:     [t_start, t_end],  -- time window of this report
  units:      decimal,   -- cumulative consumption
  cost:       decimal,   -- cumulative spend
  prev_hash:  bytes,     -- SHA-384 of previous receipt
  server_sig: bytes,     -- ML-DSA-65 signature by server
  agent_sig:  bytes      -- ML-DSA-65 counter-signature by agent
}
```

The `prev_hash` field creates a hash chain: tampering with any receipt invalidates all subsequent hashes, providing tamper-evidence without requiring a blockchain. Both parties retain the full chain. Either can present it to a third-party auditor.

## 7.3. Non-Repudiation with Privacy

Dual-signed receipts provide non-repudiation, but tool arguments may contain private data (medical queries, proprietary prompts). QASP addresses this tension:

**Argument hashing**: Trace entries include `H(args)` rather than raw arguments. The full arguments are revealed only during dispute resolution and only to the Auditor under NDA/smart-contract terms.

**Auditor-only decryption**: Sensitive argument fields are encrypted to the Auditor's public key at trace time. Neither the server nor the agent can read each other's private arguments post-hoc, but the Auditor can reconstruct the full trace if needed for dispute resolution.

## 7.4. Budget Enforcement

The `BudgetMeter` (`protocol/budget.py`) enforces budget ceilings on resource consumption:

- **Budget ceiling**: A maximum spend amount set at session creation
- **`MeterStatus` enum**: `ACTIVE` (under budget) or `SUSPENDED` (budget exhausted)
- **`BudgetExhaustedError`**: Raised when a metering update would exceed the ceiling
- **Automatic suspension**: When remaining budget falls below a threshold, the meter transitions to `SUSPENDED` and the server issues a `ResourceSuspend` message

This ensures agents cannot overspend, with enforcement at the protocol layer rather than relying on server-side billing.

---

# 8. QASP-Settle: Economic Settlement

QASP-Settle provides the economic layer for agents to agree on prices and settle payments without requiring trust.

## 8.1. Pricing Negotiation Protocol

Before resource consumption begins:

```
Agent                           Server
  │                               │
  │──── PriceRequest ────────────▶│  (ARM resource/verb/constraint tuple)
  │                               │
  │◀──── PriceOffer ─────────────│  (per-unit rate, min commitment, discounts)
  │                               │
  │──── PriceCounterOffer ───────▶│  (optional: alternative terms)
  │                               │
  │◀──── PriceAccept ────────────│  (both parties sign the agreed schedule)
  │                               │
```

The signed price schedule is binding — neither party can unilaterally change pricing during the token's validity window. The schedule is embedded in the capability token's `pricing` field:

```
price-schedule = {
  currency:   tstr,           -- e.g., "USD", "EUR"
  per_unit:   decimal,        -- cost per unit of consumption
  ? min_commit: decimal,      -- minimum commitment
  ? discounts:  [* volume-discount]  -- volume discount tiers
}
```

Price disputes are handled by the same Auditor mechanism as metering disputes, with the signed schedule as evidence.

## 8.2. Payment Channels for Micropayments

Inspired by the Lightning Network, QASP-Settle supports bidirectional payment channels for high-frequency, low-value agent transactions:

### Step 1 — Channel Open (0x11)

Agent and server each deposit a commitment (signed balance allocation) establishing an initial channel state:

```
S₀ = ⟨agent_balance, server_balance⟩
```

### Step 2 — Off-Chain Updates

As the agent consumes resources, both parties co-sign incremental state updates:

```
Sᵢ = ⟨agent_balance − Σcostᵢ, server_balance + Σcostᵢ⟩
```

Each update carries a monotonically increasing sequence number. All state updates are ML-DSA-65 signed by both parties and hash-chained to the receipt chain via `prev_hash`, unifying metering and payment into a single tamper-evident log.

This enables thousands of micropayments per second without on-chain overhead.

### Step 3 — Channel Close (0x12)

Either party submits the latest co-signed state S_n for settlement. A challenge period (default: 1 hour) allows the counterparty to submit a higher-sequence state if the closer attempted to use a stale (more favorable) state.

### Step 4 — Unilateral Close

If one party is unresponsive, the other submits its latest co-signed state after the timeout. The challenge period protects against fraud.

## 8.3. Dispute Resolution Protocol

When agent and server disagree on usage, QASP defines a structured escalation:

### Step 1 — Divergence Detection

Either party detects that the counterparty's signed MeterReport/MeterAck disagrees with its local state by more than a configurable tolerance threshold ε.

### Step 2 — Grace Period (60 seconds)

Both parties exchange their full receipt chains and attempt automatic resolution. If chains agree except for rounding, the higher-sequence receipt wins.

### Step 3 — Formal Dispute

If reconciliation fails, the disputing party opens a DisputeOpen (0x0D) with:
- Both receipt chains (agent's and server's view)
- The divergence point (first receipt where chains disagree)
- Replayable trace logs for the disputed window

### Step 4 — Evidence Submission

Both parties submit DisputeEvidence (0x0E): full receipt chains and replayable traces. Evidence is bounded — each party submits at most k receipts and n trace entries (configurable per-token) to prevent denial-of-service via evidence flooding.

### Step 5 — Auditor Analysis

The Auditor (a mutually agreed third party) independently replays the trace against the agreed price schedule and token constraints, producing a computed usage figure.

### Step 6 — Binding Verdict

The Auditor issues DisputeVerdict (0x0F) containing:
- The authoritative usage and cost
- A payment adjustment directive (refund or additional charge)
- Optionally, a fault attribution (if one party's metering is systematically inaccurate, they may be penalized)

### Step 7 — Enforcement

The payment channel state is updated to reflect the verdict. If either party refuses, the Auditor's verdict serves as evidence for out-of-band enforcement (reputation systems, legal recourse).

### Implementation: Reconciliation Engine

The reconciliation subsystem (`protocol/reconciliation.py`) implements the dispute resolution flow:

- **`DivergenceDetector`**: Compares receipt chains with configurable tolerance (default: 5% or 100-unit floor). Detects the first receipt where agent and server views diverge.
- **`ReconciliationSession`**: An FSM managing the reconciliation lifecycle with a 60-second grace period. States: `PENDING` → `EXCHANGING` → `RESOLVED` / `FAILED`.
- **Resolution methods**: `AGREED` (chains match), `HIGHER_SEQ_WINS` (use the receipt with the higher sequence number), `USE_AVERAGE` (split the difference when within tolerance).
- **Evidence bounds**: Configurable `MAX_RECEIPT_RANGE` and `MAX_TRACE_ENTRIES_PER_TOKEN` prevent denial-of-service via evidence flooding.

### Implementation: Fault Attribution

The `FaultAttributor` (`auditor/fault.py`) performs systematic fault analysis:

- **Fault types**: `METERING_ERROR`, `BILLING_ERROR`, `CONSTRAINT_VIOLATION`, `SIGNATURE_INVALID`, `CHAIN_BROKEN`
- **Attribution rules**: Each fault type maps to systematic rules determining which party is responsible
- **`AuditorService`**: The `auditor/service.py` module provides an integrated auditor with trace decryption capability (using the auditor's ML-KEM-768 key pair) for full-chain replay analysis

---

# 9. Revocation Architecture

Revoking credentials in a system with deep delegation chains and many active sessions requires careful engineering.

## 9.1. Push vs. Pull Revocation

**Push (proactive)**: The revoker broadcasts TokenRevocation (0x05) messages to all known holders and servers. QASP-Discover's advertisement infrastructure doubles as the revocation broadcast channel. Fast propagation, but requires maintaining a distribution list.

**Pull (on-demand)**: Servers check revocation status before accepting a token, via two mechanisms:

- **QASP-CRL**: A periodically published Certificate Revocation List, ML-DSA-65 signed by the issuer, distributed as a CBOR array of revoked token IDs with revocation timestamps. Servers cache CRLs with a configurable refresh interval (default: 5 minutes).

- **QASP-OCSP**: An online status check where the server sends a token ID to the issuer's OCSP responder and receives a signed "good" / "revoked" / "unknown" response. The response includes a `nextUpdate` timestamp for stapling: servers cache the response and present it to agents as proof of status, avoiding repeated round-trips.

Both CRL and OCSP responses use ML-DSA-65 signatures, maintaining PQ security throughout the revocation infrastructure.

**Implementation**: The `OCSPResponder` (`protocol/ocsp.py`) provides a full OCSP implementation:

- **`OCSPRequest`**: Contains token ID and a random nonce for replay prevention
- **`OCSPResponse`**: Signed response with status (`GOOD`, `REVOKED`, `UNKNOWN`), validity window (`thisUpdate`/`nextUpdate`), and nonce echo
- **`StapledOCSPResponse`**: Pre-fetched response bundled with a token for offline verification — servers cache responses and present them to agents without repeated round-trips
- **Response caching**: Configurable validity period (default defined by `DEFAULT_RESPONSE_VALIDITY_SECONDS`)
- **Nonce validation**: Request nonces are echoed in responses to prevent replay attacks (`OCSPNonceMismatchError` on mismatch)

## 9.2. Revocation Urgency Levels

| Level | Behavior | Use Case |
|-------|----------|----------|
| **critical** | Token invalid upon receipt. In-flight transactions terminated. | Key compromise |
| **normal** (default) | 5-minute grace period. New transactions rejected immediately; ongoing ones may finish within grace window. Server MUST NOT extend grace beyond original token expiry. | Standard revocation |
| **planned** | Revocation takes effect at a specified future time. | Scheduled credential rotation |

## 9.3. Revocation Cascade

When an owner revokes Agent Alpha's certificate and Alpha has 50 active delegation chains across 20 servers:

1. **Owner signs revocation**: `Revoke(Alpha's cert/DID, urgency, reason)` signed by owner's ML-DSA-65 key

2. **Broadcast phase**: The revocation is pushed to:
   - All servers Alpha has active sessions with (via the session registry maintained during QASP-Shake)
   - The QASP-CRL distribution point
   - The DID resolver network (if using did:qasp)

3. **Server-side cascade**: Each server, upon receiving Alpha's revocation:
   - Identifies all tokens where Alpha appears in the delegation chain (via `issuer` and `parent_ref` fields in its token store)
   - Marks those tokens AND all their descendants as revoked
   - Sends RevocationNotice (0x06) to all agents holding affected tokens

4. **Convergence**: Servers that missed the push revocation discover it at their next CRL refresh or OCSP check. Maximum propagation delay is bounded by `max(CRL_refresh_interval, push_delivery_timeout)`.

5. **Audit trail**: Each revocation event (original and cascaded) is logged with timestamp, affected token IDs, and the revocation chain, enabling post-hoc verification that the cascade completed correctly.

---

# 10. Trust Scoring System

The trust scoring system is QASP's key differentiator. No existing protocol combines all three pillars — code audit certification, dynamic reputation, and behavioral verification — in a single cryptographically verifiable framework. The trust score determines whether an agent is permitted to connect, what level of capabilities it may receive, and how much other agents should rely on it.

## 10.1. Composite Trust Score

The overall trust score for an agent is computed as a weighted sum of four components:

```
T(agent) = w_i × T_interaction + w_w × T_witness + w_c × T_certified + w_b × T_behavioral
```

Default weights:
- w_i = 0.35 (interaction trust — direct experience)
- w_w = 0.25 (witness reputation — third-party reports)
- w_c = 0.20 (certified reputation — audit attestations)
- w_b = 0.20 (behavioral compliance — capability boundary adherence)

Weights are tunable per deployment. A high-security environment might weight certified reputation more heavily; a community deployment might weight interaction trust more.

The score is a value between 0.0 and 1.0. Servers enforce minimum trust thresholds for different capability levels (e.g., trust > 0.3 for read access, trust > 0.7 for exec with delegation).

## 10.2. Pillar 1 — Interaction Trust (Direct Experience)

### 10.2.1. Beta Reputation System

Trust from direct interactions is modeled as a Beta probability distribution with parameters α (successful interactions) and β (failed interactions). The expected trust value is:

```
T_interaction = α / (α + β)
```

After each interaction:
- Successful completion → α += 1
- Failed or violated → β += 1

The Beta distribution provides a principled way to handle uncertainty: with few observations, the distribution is wide (high uncertainty); with many observations, it narrows (high confidence). A new agent starts at α=1, β=1 (uniform prior, T=0.5).

### 10.2.2. Time Decay

Recent behavior should weigh more heavily than distant past behavior. A recency decay function is applied:

```
λ(t) = e^(−δ × Δt)
```

Where:
- δ is the decay rate (configurable; higher = faster forgetting)
- Δt is the time elapsed since the interaction

Each historical interaction's contribution to α and β is weighted by λ(t). An agent that was trustworthy a year ago but has no recent history will see its trust naturally decay toward the prior.

### 10.2.3. What Counts as Success/Failure

- **Success**: Agent completed the authorized operation within all token constraints (time, quantity, rate, spend), responded to metering reports promptly, and released resources cleanly.
- **Failure**: Agent exceeded constraints, failed to acknowledge metering, caused a dispute, attempted privilege escalation, or produced results inconsistent with its declared purpose.

## 10.3. Pillar 2 — Witness Reputation (Third-Party Reports)

### 10.3.1. Why Witnesses Matter

Direct experience is limited — an agent may interact with only a few counterparts. Witness reputation aggregates the experiences of other agents to inform trust decisions for agents you haven't interacted with directly. This is especially valuable for new relationships.

### 10.3.2. TRAVOS Credibility Filtering

Not all witnesses are equally reliable. Some may be colluding with the agent being evaluated, or may simply have bad judgment. QASP uses TRAVOS-style credibility filtering:

1. Divide the trust space into n equal intervals (e.g., [0.0–0.2], [0.2–0.4], ..., [0.8–1.0])
2. For each witness, compare their historical reports against YOUR OWN direct observations in each interval
3. Witnesses whose past reports consistently match your experience in a given interval are weighted highly for that interval
4. Witnesses whose reports diverge significantly from your observations are down-weighted

This eliminates unreliable witnesses without requiring any global consensus mechanism. Each agent makes its own witness credibility assessment based on its own experience.

### 10.3.3. Aggregation

```
T_witness = Σ(credibility_w × report_w) / Σ(credibility_w)
```

Where `credibility_w` is the witness's reliability weight (computed via TRAVOS filtering) and `report_w` is the witness's reported trust value for the target agent.

### 10.3.4. Anti-Collusion

Cluster-based collusion detection: if a group of witnesses consistently provides identical (or near-identical) reports that diverge from independent witnesses, the group's reports are down-weighted as potential collusion.

## 10.4. Pillar 3 — Certified Reputation (Audit Attestation)

### 10.4.1. Verifiable Credentials for Audit Attestation

When a trusted auditor reviews an agent's code, architecture, or behavior, they issue a W3C Verifiable Credential (VC Data Model v2.0) containing:

- **Agent's DID**: The `did:qasp` identifier of the audited agent
- **Audit scope**: Code version hash, functionality boundaries, what was examined
- **Audit result**: Pass/fail with specific findings
- **SLSA level**: Supply chain Levels for Software Artifacts (1–3)
  - Level 1: Documented build process
  - Level 2: Hosted build, version controlled
  - Level 3: Isolated builds from verified source (highest)
- **Auditor's DID**: The identity of the auditing entity
- **ML-DSA-65 proof signature**: PQ-secure signature over the credential
- **Expiry date**: When the certification expires (requiring re-audit)

### 10.4.2. VC Schema

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/security/suites/pq-2025"
  ],
  "type": ["VerifiableCredential", "QASPAuditAttestation"],
  "issuer": "did:qasp:z6Mk_auditor...",
  "validFrom": "2026-02-21T00:00:00Z",
  "validUntil": "2026-08-21T00:00:00Z",
  "credentialSubject": {
    "id": "did:qasp:z6Mk_agent...",
    "auditScope": "full-code-review",
    "codeVersionHash": "sha384:abc123...",
    "auditResult": "pass",
    "slsaLevel": 3,
    "findings": [],
    "capabilities": ["compute-exec", "data-read"]
  },
  "proof": {
    "type": "MLDSASignature2025",
    "verificationMethod": "did:qasp:z6Mk_auditor...#key-1",
    "proofValue": "z..."
  }
}
```

### 10.4.3. Trust Score from Certification

Active, unexpired audit certifications from issuers in the trust registry contribute a configurable boost:

| Certification | T_certified Value |
|---------------|-------------------|
| SLSA Level 3, active, from trusted auditor | 0.90 |
| SLSA Level 2, active, from trusted auditor | 0.70 |
| SLSA Level 1, active, from trusted auditor | 0.50 |
| Expired certification | 0.20 (decaying) |
| No certification | 0.00 |

### 10.4.4. Cold-Start Solution

Certified reputation directly solves the cold-start problem. A newly deployed agent with zero interaction history and zero witness reports would normally have an uninformative trust score. But if it holds a valid SLSA Level 3 audit attestation from a trusted auditor, it enters the network with a meaningful initial trust score (e.g., ~0.18 from T_certified alone, boosted further if the deployment environment provides additional attestation).

### 10.4.5. VC Lifecycle

- **Issuance**: Auditor examines agent, issues VC signed with ML-DSA-65
- **Presentation**: During QASP-Shake, agents optionally present audit VCs. The verifier checks the VC signature, validates the auditor's DID against the trust registry, and confirms the VC has not expired
- **Refresh**: Agents must periodically undergo re-audit and obtain fresh VCs. Expired VCs provide diminishing trust value
- **Revocation**: Auditors can revoke VCs if a vulnerability is discovered post-audit. Revocation uses the same QASP revocation infrastructure (CRL/OCSP)

## 10.5. Pillar 4 — Behavioral Compliance (Runtime Verification)

### 10.5.1. Signed Capability Manifest

Each agent publishes a cryptographically signed manifest declaring its capabilities, permitted API calls, data access scope, and behavioral constraints. This manifest is included in the agent's DID Document and signed with ML-DSA-65.

The manifest is the agent's promise: "I will only do these things." Behavioral monitoring verifies whether the agent keeps this promise.

### 10.5.2. FSM-Based Conformance Engine

Each agent's permitted behavior is defined as a finite state machine (FSM). The protocol layer monitors all agent actions against the FSM and flags transitions not in the permitted set.

```
Example FSM for a "document summarizer" agent:

  IDLE ──receive_document──▶ PROCESSING
  PROCESSING ──read_content──▶ PROCESSING
  PROCESSING ──generate_summary──▶ SUMMARIZING
  SUMMARIZING ──return_result──▶ IDLE

  Any state ──attempt_network_call──▶ VIOLATION
  Any state ──attempt_file_write──▶ VIOLATION
  Any state ──attempt_delegation──▶ VIOLATION
```

The engine operates at the QASP protocol layer, monitoring capability token usage. Computational cost is sub-20ms per check, enabling real-time enforcement without meaningful latency impact.

### 10.5.3. Goal-Conditioned Drift Detection

Beyond discrete FSM violations, QASP detects gradual behavioral drift. For each declared capability, establish distributional baselines of "normal" behavior patterns (e.g., what API call patterns look like for an agent claiming to be a "document summarizer").

Statistical divergence measures detect when an agent's behavior drifts beyond its declared scope:

- **KL-divergence**: Measures how different the agent's current behavior distribution is from its baseline
- **Wasserstein distance**: Measures the "earth mover's distance" between distributions, more robust to support differences

If divergence exceeds a threshold, the behavioral compliance score drops. This catches subtle capability violations that discrete FSM rules might miss — for example, a "document summarizer" that gradually starts making more and more API calls to external services.

**Implementation**: The `DriftDetector` class (`trust/behavioral.py`) provides:

- **`BehaviorDistribution`**: A frozen dataclass representing a normalized probability distribution over `BehaviorType` values (REQUEST, RESPONSE, ERROR, TIMEOUT, RATE_LIMIT, POLICY_VIOLATION)
- **`kl_divergence(p, q)`**: KL(P || Q) with Laplace smoothing to handle zero probabilities
- **`wasserstein_distance(p, q)`**: Wasserstein-1 (earth mover's) distance over the canonical BehaviorType ordering
- **`compute_drift_score(current)`**: Weighted combination of normalized KL and Wasserstein scores, clamped to [0.0, 1.0]. Configurable thresholds (default: KL=2.0, W=1.0) and weights (default: KL=0.6, W=0.4).
- **`distribution_from_events(events)`**: Builds a `BehaviorDistribution` from a list of `BehaviorEvent` records
- **`BehavioralVerifier.detect_drift()`**: Convenience method that splits recorded events into baseline (first half) and current (second half) for automatic drift assessment

### 10.5.4. Compliance Score Computation

```
T_behavioral = (permitted_actions / total_actions) over sliding window
```

With exponential penalties for severe violations:
- Minor boundary violation (e.g., briefly exceeded rate limit): 1× penalty
- Moderate violation (e.g., accessed resource outside declared scope): 5× penalty
- Severe violation (e.g., attempted privilege escalation, attempted delegation without authority): 10× penalty

### 10.5.5. Cryptographic Proof of Execution (PoE)

Every agent action that passes through the QASP protocol layer produces a signed, timestamped log entry — a Proof of Execution. These PoEs form the tamper-evident audit trail stored in the reputation system and available for third-party verification.

```
PoE = {
  agent_did:     tstr,
  action:        tstr,       -- ARM verb
  resource:      tstr,       -- ARM URI
  token_id:      bytes,      -- capability token authorizing this action
  timestamp:     uint,
  result:        tstr,       -- "success" / "failure" / "violation"
  args_hash:     bytes,      -- SHA-384 of action arguments (privacy)
  prev_poe_hash: bytes,      -- hash chain
  signature:     bytes       -- ML-DSA-65 by the monitoring layer
}
```

**Implementation**: The `ProofOfExecution` frozen dataclass and `PoEChain` class (`protocol/privacy.py`) provide:

- **Result constants**: `POE_SUCCESS`, `POE_FAILURE`, `POE_VIOLATION`
- **`create_proof_of_execution()`**: Creates a signed PoE with SHA-384 argument hashing and ML-DSA-65 signature
- **`verify_proof_of_execution()`**: Verifies the ML-DSA-65 signature on a PoE
- **`PoEChain`**: An ordered, hash-chained list of PoEs following the same pattern as `ReceiptChain` in `protocol/accounting.py`:
  - `append(poe)` validates `prev_poe_hash` linkage (first entry must have empty hash)
  - `verify(signer_pk)` verifies all signatures and hash chain integrity
  - `latest_hash` property returns the SHA-384 hash of the most recent entry
  - Full CBOR serialization/deserialization via `to_cbor()` / `from_cbor()`

## 10.6. Anti-Gaming Defenses

### 10.6.1. Monotonically Increasing Cooperation Requirements

To prevent cyclical exploitation (cooperate for N interactions to build trust, then defect on a high-value transaction, then rebuild trust), QASP implements monotonically increasing cooperation requirements. Each successive trust level requires MORE consistent cooperation than the previous one. The cost of "burning" trust and rebuilding it increases geometrically.

### 10.6.2. Cluster-Based Collusion Detection

Groups of agents that coordinate their witness reports to inflate each other's trust scores are detected via statistical clustering. If a set of agents consistently report identical trust values for each other that diverge from independent observers, their mutual reports are down-weighted or excluded.

### 10.6.3. Proof-of-Stake-Style Minimum Reputation Burn

For high-value operations (e.g., requesting a large compute budget), agents must have maintained a trust score above a threshold for a minimum duration. This prevents an attacker from rapidly inflating trust (even through legitimate interactions) to gain access to high-value resources.

## 10.7. Trust Registry

The trust registry is the central directory linking agent DIDs to their trust data. It supports three operations:

- **Register**: Anchor a new agent DID with initial credentials (audit VCs, owner binding)
- **Attest**: Issue or revoke Verifiable Credentials
- **Query**: Retrieve an agent's current trust score, VCs, behavioral compliance history, and interaction statistics

The registry uses ML-DSA-65-signed responses for all queries. For the reference implementation, it's a REST API; production deployments can plug in blockchain backends for immutability of audit attestations.

## 10.8. Trust Score Integration with QASP-Cap

Trust scores directly influence capability token issuance:

- **Minimum trust thresholds**: Servers define minimum trust levels for different capability tiers. An agent with trust 0.3 might get read-only access; an agent with trust 0.8 might get exec + delegate.
- **Trust-based constraint tightening**: Lower-trust agents receive tokens with tighter constraints (shorter validity, lower spend limits, shallower delegation depth).
- **Trust-based rate limiting**: Lower-trust agents are subject to more aggressive rate limits.
- **Automatic attenuation**: If an agent's trust drops below a threshold during an active session, its existing tokens may be automatically attenuated or suspended.

---

# 11. Interoperability with A2A and MCP

QASP is a security and authorization layer that complements, not replaces, existing agent orchestration protocols.

## 11.1. Architectural Position

```
┌─────────────────────────────────────────┐
│ Application: A2A task orchestration /   │  ← unchanged
│              MCP tool invocation        │
├─────────────────────────────────────────┤
│ Authorization: QASP-Cap tokens          │  ← QASP adds this
│               authorize each operation  │
├─────────────────────────────────────────┤
│ Security: QASP-Shake provides           │  ← QASP adds this
│           PQ-authenticated channel      │
├─────────────────────────────────────────┤
│ Transport: TCP / QUIC                   │  ← unchanged
└─────────────────────────────────────────┘
```

Existing A2A and MCP implementations require only a thin adapter to operate over QASP-secured channels.

## 11.2. MCP-over-QASP

### Mapping

| MCP Concept | QASP Equivalent |
|-------------|-----------------|
| OAuth 2.0 token | QASP capability token |
| OAuth scope | ARM resource URI + verb set |
| Token refresh | Token re-issuance (attenuated) |
| Client credentials | Agent DID + ML-DSA-65 signature |
| Authorization server | Owner's delegation authority |
| Token introspection | QASP-OCSP status check |

### How It Works

1. **Resource mapping**: MCP tool name → ARM resource URI: `mcp://{server}/tool/{tool_name}`. MCP operation `tools/call` → ARM verb `exec`.

2. **Token wrapping**: Before sending an MCP `tools/call` request, the client constructs a QASP capability token scoped to the target tool, with constraints derived from the agent's authorization.

3. **Transport**: The MCP JSON-RPC message is sent as the payload of a QASP data frame over the QASP-Shake-secured channel. The QASP token is included in MCP's `_meta` field:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "web_search",
    "arguments": { "query": "..." },
    "_meta": {
      "qasp_token_id": "019...",
      "qasp_token": "<base64 CBOR token>"
    }
  }
}
```

4. **Enforcement**: The MCP server validates the QASP token before executing the tool — checking resource match, verb authorization, and constraint compliance.

This adds authorization to MCP without modifying the MCP specification — the `_meta` field is explicitly reserved for extensions.

## 11.3. A2A-over-QASP

### Agent Card Extension

A2A Agent Cards include a `qasp` section with the agent's DID, QASP endpoint, and supported cipher suites. Agents discovering each other via A2A Agent Cards can upgrade to QASP-secured communication.

### Task Authorization

Each A2A `tasks/send` or `tasks/sendSubscribe` carries a QASP token authorizing the task. The token's ARM resource URI is `a2a://{agent}/task/{skill}`, and the verb is `exec`.

### Streaming

A2A's SSE-based streaming maps to QASP's data frame stream. Each streamed artifact update is metered against the token's constraints.

### Delegation

When an A2A agent delegates a sub-task to another agent, it attenuates its QASP token for the delegate — providing cryptographic delegation tracking that A2A currently lacks.

---

# 12. Formal Security Properties

QASP's security claims are backed by formal adversary games and verification approaches.

## 12.1. Threat Model

Five threat actors are considered:

1. **Quantum Adversary**: Has access to a cryptographically relevant quantum computer (CRQC). Can break RSA/ECDSA/ECDH but not lattice-based problems.
2. **Network Attacker**: Has man-in-the-middle (MITM) capability on the network.
3. **Malicious Agent**: Compromised agent software attempting to exceed its authorized scope.
4. **Rogue Owner**: Legitimate owner credentials used maliciously.
5. **Compromised Server**: Server controlling resource infrastructure acting dishonestly.

## 12.2. Security Properties

1. **IND-CCA2 key exchange**: ML-KEM-768 is IND-CCA2 secure under Module-LWE. In hybrid mode, the construction is secure if EITHER ML-KEM-768 or X25519 is unbroken.

2. **EUF-CMA signatures**: ML-DSA-65 is existentially unforgeable under chosen-message attacks, based on the Module-SIS hardness assumption.

3. **Forward secrecy**: Ephemeral KEM keys per session ensure that compromise of long-term keys does not reveal past session keys.

4. **Capability safety**: The token algebra ensures no delegation chain can escalate permissions (monotonic attenuation), proved by structural induction.

5. **Non-repudiation**: Hash-chained dual-signed receipts and signed capability tokens.

6. **Tool-chain confinement**: Capability firebreaks prevent transitive authority leakage across tool boundaries.

7. **Downgrade resistance**: Transcript-bound suite negotiation prevents forced algorithm downgrade.

8. **Economic fairness**: Payment channels with challenge periods prevent unilateral fraud; Auditor verdicts provide binding dispute resolution.

## 12.3. Formal Verification Approach

- **ProVerif** (applied pi-calculus): Verifies authentication, secrecy, and forward secrecy for unbounded sessions. ML-KEM modeled as custom function symbols.
- **Tamarin** (multiset rewriting rules): Verifies stateful properties including delegation chain safety and reputation score integrity.
- **CryptoVerif** (computational model): Provides game-based proofs with concrete probability bounds. Post-quantum sound.

---

# 13. Comparison with Existing Protocols

| Feature | A2A | MCP | ANP | AGP | QASP |
|---------|-----|-----|-----|-----|------|
| Agent-specific PKI | ✗ | ✗ | ~ | ✗ | ✓ |
| Owner-binding certs | ✗ | ✗ | ✗ | ✗ | ✓ |
| Capability tokens | ✗ | ✗ | ✗ | ✗ | ✓ |
| Delegation chains | ✗ | ✗ | ✗ | ✗ | ✓ |
| Resource metering | ✗ | ✗ | ✗ | ✗ | ✓ |
| Post-quantum crypto | ✗ | ✗ | ✗ | ✗ | ✓ |
| Peer-to-peer | ✓ | ✗ | ✓ | ✗ | ✓ |
| Hybrid PQ/classical | ✗ | ✗ | ✗ | ✗ | ✓ |
| Crypto agility | ✗ | ✗ | ✗ | ✗ | ✓ |
| Universal ARM | ✗ | ✗ | ✗ | ✗ | ✓ |
| DID identity | ✗ | ✗ | ✓ | ✗ | ✓ |
| Service discovery | ✓ | ✗ | ~ | ✗ | ✓ |
| Economic settlement | ✗ | ✗ | ✗ | ✗ | ✓ |
| Trust scoring | ✗ | ✗ | ✗ | ✗ | ✓ |
| Audit certification | ✗ | ✗ | ✗ | ✗ | ✓ |
| Behavioral verification | ✗ | ✗ | ✗ | ✗ | ✓ |

---

# 14. Transport Layer

QASP includes a pluggable transport layer for actual network communication.

## 14.1. TCP Transport

The `transport/tcp.py` module provides a TCP-based transport implementation:

- Async server and client using Python's `asyncio` streams
- Automatic integration with `QASPConnection` for handshake and encryption
- Configurable bind address, port, and connection limits

## 14.2. Service Discovery

The `transport/discover.py` module implements QASP-Discover at the transport level:

- DNS-SD/mDNS advertisement and browsing for local network discovery
- Service registration with PQ-signed capability advertisements
- Configurable TTL and refresh intervals

## 14.3. Transport Registry

The `transport/registry.py` module provides a pluggable transport registry:

- Register transport implementations by name (e.g., "tcp", "quic")
- Lookup and instantiate transports dynamically
- Enables new transport backends without modifying protocol code

---

# 15. Reference Implementations

## 15.1. ML-DSA-65 Pure Python Reference

The `crypto/dilithium.py` module provides a pure-Python implementation of ML-DSA-65 (Dilithium) for educational and verification purposes. This reference implementation follows the FIPS 204 specification directly and is suitable for:

- Algorithm comprehension and auditing
- Cross-validation against the `oqs` (liboqs) production implementation
- Environments where native library installation is impractical

**Note**: The pure-Python implementation is significantly slower than the liboqs-backed implementation and should not be used in production.

---

# 16. Protocol Events System

The `protocol/events.py` module defines 50+ typed event classes covering all protocol phases. Events are emitted by `QASPConnection` and transport components, enabling reactive programming patterns:

- **Handshake events**: `HandshakeInitiated`, `HandshakeComplete`, `HandshakeFailed`
- **Data events**: `DataReceived`, `DataSent`
- **Connection events**: `ConnectionClosed`, `ConnectionError`
- **Token events**: `TokenIssued`, `TokenRevoked`, `TokenVerified`
- **Resource events**: `ResourceRequested`, `ResourceGranted`, `ResourceDenied`, `ResourceSuspended`, `ResourceReleased`
- **Metering events**: `MeterReportReceived`, `MeterAckSent`
- **Settlement events**: `ChannelOpened`, `ChannelClosed`, `ChannelDisputed`, `PriceOfferReceived`, `PriceAccepted`
- **Reconciliation events**: `ReconciliationStarted`, `ReconciliationSucceeded`, `ReconciliationFailed`, `DivergenceDetected`
- **Dispute events**: `DisputeOpened`, `DisputeEvidenceReceived`, `DisputeResolved`, `FaultAttributed`, `VerdictEnforced`
- **Revocation events**: `RevocationCascadeComplete`, `RevocationGracePeriodStarted`
- **Stream events**: `StreamOpened`, `StreamClosed`, `StreamDataReceived`
- **Cross-domain events**: `CrossDomainDelegationRequested`, `CrossDomainDelegationGranted`, `CrossDomainDelegationRejected`, `CrossDomainDelegationRevoked`
- **OCSP events**: `OCSPRequestReceived`, `OCSPResponseGenerated`
- **Alert events**: `AlertReceived`

All events inherit from the base `Event` class and carry a timestamp. This enables protocol-level observability, logging, and integration with monitoring systems.

---

# 17. Conversational Messaging

QASP provides a conversational messaging layer that enables agents to communicate using natural language rather than structured JSON payloads. This section describes the design philosophy, message lifecycle, NLP convenience API, and bilateral conversation logging.

## 17.1. Design Philosophy

Agent-to-agent messaging in QASP is modeled after human conversation, not machine-to-machine RPC. The core principles are:

**Natural language first.** Messages are plain-text sentences that read like something a person would say. Instead of `{"action": "request_weather", "params": {"city": "NYC"}}`, an agent says: *"Could you look up the weather data for New York City?"*

**Intent as metadata, not routing.** Every message carries an optional `intent` tag (e.g., `question`, `greeting`, `request`). This is informational metadata for logging and observability — it never affects routing, authorization, or delivery. A message with `intent: "question"` follows the same code path as one with `intent: "statement"`.

**Bilateral logging.** Both the sender and receiver maintain a local conversation log. The sender logs every outgoing message; the receiver logs every incoming message (whether received via WebSocket push, HTTP callback, or inbox polling). The server retains the authoritative record in its SQLite message store.

**Additive, not breaking.** The NLP convenience methods (`say`, `ask`, `reply`, `greet`, `farewell`) are wrappers on top of the existing `send_message()` call. Existing code that uses `send_message()` directly continues to work unchanged.

## 17.2. Conversation Lifecycle

A typical conversational exchange follows this lifecycle:

```
Agent A                          Server                          Agent B
   │                               │                               │
   │── open_conversation() ───────>│                               │
   │<── conversation_id + token ───│── conversation_opened ──────>│
   │                               │                               │
   │── greet() ──────────────────>│── message (WebSocket/cb) ───>│
   │<── delivered ─────────────────│                               │
   │                               │                               │
   │── ask() ────────────────────>│── message ──────────────────>│
   │<── delivered ─────────────────│                               │
   │                               │                               │
   │                               │<── reply() ───────────────────│
   │<── message (WebSocket/cb) ────│── delivered ────────────────>│
   │                               │                               │
   │── say() ────────────────────>│── message ──────────────────>│
   │                               │                               │
   │── farewell() ───────────────>│── message + close ──────────>│
   │<── conversation CLOSED ───────│                               │
```

**Opening**: Agent A calls `open_conversation(target_did, topic)`. The server creates a conversation record, issues a capability token with `ARM_MESSAGE` verb, and notifies Agent B via WebSocket or callback.

**Exchange**: Agents send messages using NLP convenience methods. Each message is stored in the server's database, delivered via the 3-tier system (WebSocket > callback > inbox polling), and auto-logged on both sides.

**Closing**: Either agent calls `farewell()` (which sends a farewell message and closes the conversation) or `close_conversation()` directly.

## 17.3. Natural Language Message Format

### Content

Messages use `content_type: "text/plain"` by default. Content is always a human-readable string:

| Instead of this... | ...agents say this |
|--------------------|--------------------|
| `{"action": "get_data", "type": "weather"}` | "Could you pull the latest weather data for me?" |
| `{"status": "ok", "result": 42}` | "Sure, the answer is 42." |
| `{"error": "not_found"}` | "I couldn't find what you're looking for, sorry." |
| `{"ack": true}` | "Got it, thanks!" |

### Intent Classification

Every message carries an optional `intent` field. The client auto-classifies intent using a rule-based classifier (no ML dependencies required):

| Intent | Detection Rule | Example |
|--------|---------------|---------|
| `question` | Ends with `?` | "What's the current temperature?" |
| `greeting` | Starts with greeting words (hi, hello, hey, etc.) | "Hello! How are you doing?" |
| `farewell` | Contains farewell words (goodbye, bye, see you, etc.) | "Thanks for the help, goodbye!" |
| `request` | Contains request phrases (could you, please, can you, etc.) | "Could you send me the report?" |
| `response` | Starts with response words (sure, yes, no, okay, etc.) | "Sure, here's what I found." |
| `notification` | Contains notification words (alert, update, fyi, etc.) | "FYI, the deployment completed." |
| `statement` | Default (none of the above) | "The server is running on port 8080." |

Intent is stored in the `messages` database table and included in relay payloads, but never affects delivery or authorization.

## 17.4. Bilateral Conversation Logging

### Client-Side: ConversationLog

The `QASPClient` maintains an in-memory `ConversationLog` for each active conversation. Logs are created automatically when a conversation is opened (by either side) and populated as messages are sent and received.

```python
class ConversationLog:
    conversation_id: str     # Conversation identifier
    agent_name: str          # This agent's name
    partner_name: str        # Other agent's name
    partner_did: str         # Other agent's DID
    topic: str               # Conversation topic
    entries: list[LogEntry]  # Ordered list of sent/received messages
```

Each `LogEntry` records:
- **direction**: `SENT` or `RECEIVED`
- **sender_name**: Who sent the message
- **content**: The natural language text
- **intent**: Classified intent tag
- **timestamp**: ISO-8601 timestamp
- **message_id**: Unique message identifier
- **reply_to**: Optional reference to a previous message

**Auto-logging points:**
- `send_message()` / `say()` / `ask()` / `reply()` / `greet()` — logs outgoing
- WebSocket `on_message` — logs incoming before user callback fires
- `get_inbox()` — logs each polled message as received
- `conversation_opened` WebSocket event — creates a new ConversationLog

### Server-Side: SQLite Message Store

The server stores every message in its `messages` table with the `intent` field:

```sql
CREATE TABLE messages (
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
```

### Transcript Access

Both sides can produce human-readable transcripts:

**Local transcript** (client-side, from ConversationLog):
```python
transcript = client.get_transcript(conversation_id)
print(transcript)
```

Output:
```
Topic: Weather data request
Participants: WeatherBot, DataAgent

  >> [2026-04-03T14:00:01Z] WeatherBot [greeting]: Hello from WeatherBot! How can I help you today?
  << [2026-04-03T14:00:03Z] DataAgent [question]: Could you look up the forecast for NYC?
  >> [2026-04-03T14:00:05Z] WeatherBot [response]: Sure, NYC forecast: sunny, high of 72F.
  << [2026-04-03T14:00:07Z] DataAgent [statement]: Great, thanks for the info.
  >> [2026-04-03T14:00:09Z] WeatherBot [farewell]: Thanks for the conversation! Goodbye from WeatherBot.
```

**Server transcript** (authoritative record):
```python
result = client.get_server_transcript(conversation_id)
print(result["transcript"])
```

The server transcript endpoint (`GET /conversations/{id}/transcript`) returns the same conversation formatted from the authoritative database, including agent names resolved from their DIDs.

## 17.5. NLP Convenience API

The `QASPClient` provides these conversational methods on top of `send_message()`:

### say(conversation_id, message, token, reply_to=None)

Send a general natural-language message. Intent is auto-classified.

```python
client.say(conv_id, "The deployment finished successfully.", token)
```

### ask(conversation_id, question, token, reply_to=None)

Ask a question. Appends `?` if missing. Intent is set to `question`.

```python
client.ask(conv_id, "What's the current CPU usage", token)
# Sends: "What's the current CPU usage?"
```

### reply(conversation_id, message, token, to_message_id)

Reply to a specific message. Creates a threaded reply via the `reply_to` field.

```python
client.reply(conv_id, "It's at 42% right now.", token, msg_id)
```

### greet(conversation_id, token, greeting="")

Send a greeting. Uses a default if no custom text is provided.

```python
client.greet(conv_id, token)
# Sends: "Hello from MyAgent! How can I help you today?"

client.greet(conv_id, token, "Hey there! Ready to get started?")
```

### farewell(conversation_id, token, message="")

Send a farewell message and close the conversation in one call.

```python
result = client.farewell(conv_id, token)
# Sends farewell message, then closes the conversation
# Returns: {"conversation_id": ..., "status": "CLOSED", ...}
```

### get_transcript(conversation_id)

Get the formatted local transcript.

```python
print(client.get_transcript(conv_id))
```

### get_server_transcript(conversation_id)

Fetch the authoritative transcript from the server.

```python
result = client.get_server_transcript(conv_id)
print(result["transcript"])
```

## 17.6. Example: Two-Agent Conversation

This example shows two agents having a natural conversation, with transcripts from both perspectives.

```python
from scripts.qasp_client import QASPClient

# Set up two agents
alice = QASPClient("http://localhost:8080")
alice.register("Alice", [{"name": "research", "description": "Research assistant"}])

bob = QASPClient("http://localhost:8080")
bob.register("Bob", [{"name": "data", "description": "Data provider"}])

# Alice opens a conversation with Bob
conv = alice.open_conversation(bob._did, topic="Q3 revenue analysis")
token = conv["token"]

# Alice greets Bob
alice.greet(conv["conversation_id"], token)

# Alice asks a question
alice.ask(conv["conversation_id"], "Do you have the Q3 revenue numbers ready", token)

# Bob gets the messages from his inbox and responds
inbox = bob.get_inbox()
bob_token = bob.request_message_token(alice._did)["token"]
msg_id = inbox["messages"][-1]["message_id"]

bob.reply(
    conv["conversation_id"],
    "Yes, Q3 revenue was $4.2M, up 15% from Q2.",
    bob_token,
    msg_id,
)

bob.say(
    conv["conversation_id"],
    "I can also pull the breakdown by region if you need it.",
    bob_token,
)

# Alice wraps up
alice.say(conv["conversation_id"], "That would be great, please send it over.", token)
alice.farewell(conv["conversation_id"], token, "Thanks Bob, this is exactly what I needed!")

# Both sides can view their transcripts
print("=== Alice's transcript ===")
print(alice.get_transcript(conv["conversation_id"]))

print("\n=== Bob's transcript ===")
print(bob.get_transcript(conv["conversation_id"]))
```

**Alice's local transcript:**
```
Topic: Q3 revenue analysis
Participants: Alice, Bob

  >> [2026-04-03T14:00:01Z] Alice [greeting]: Hello from Alice! How can I help you today?
  >> [2026-04-03T14:00:02Z] Alice [question]: Do you have the Q3 revenue numbers ready?
  >> [2026-04-03T14:00:06Z] Alice [request]: That would be great, please send it over.
  >> [2026-04-03T14:00:07Z] Alice [farewell]: Thanks Bob, this is exactly what I needed!
```

**Bob's local transcript** (populated via `get_inbox()` auto-logging):
```
Topic: Q3 revenue analysis
Participants: Bob, Alice

  << [2026-04-03T14:00:01Z] Alice [greeting]: Hello from Alice! How can I help you today?
  << [2026-04-03T14:00:02Z] Alice [question]: Do you have the Q3 revenue numbers ready?
  >> [2026-04-03T14:00:04Z] Bob [response]: Yes, Q3 revenue was $4.2M, up 15% from Q2.
  >> [2026-04-03T14:00:05Z] Bob [statement]: I can also pull the breakdown by region if you need it.
```

**Server transcript** (authoritative, shows all messages from both sides):
```
Topic: Q3 revenue analysis

[2026-04-03T14:00:01Z] Alice [greeting]: Hello from Alice! How can I help you today?
[2026-04-03T14:00:02Z] Alice [question]: Do you have the Q3 revenue numbers ready?
[2026-04-03T14:00:04Z] Bob [response]: Yes, Q3 revenue was $4.2M, up 15% from Q2.
[2026-04-03T14:00:05Z] Bob [statement]: I can also pull the breakdown by region if you need it.
[2026-04-03T14:00:06Z] Alice [request]: That would be great, please send it over.
[2026-04-03T14:00:07Z] Alice [farewell]: Thanks Bob, this is exactly what I needed!
```

## 17.7. WebSocket Real-Time Logging

When agents use the `QASPWebSocketListener` for real-time communication, conversation logging happens automatically:

**Incoming messages**: When a `message` event arrives via WebSocket, the listener:
1. Looks up (or creates) the `ConversationLog` for the conversation
2. Logs the message as `RECEIVED` with sender name, content, intent, and timestamp
3. Fires the user's `on_message` callback

**New conversations**: When a `conversation_opened` event arrives, the listener:
1. Creates a new `ConversationLog` with the initiator's name and DID
2. Fires the user's `on_conversation` callback

This means agents using WebSocket listeners get a complete conversation log without any extra code — all incoming messages are logged before callbacks fire, ensuring the log is always up to date.

```python
# WebSocket listener auto-logs everything
listener = client.create_websocket_listener(
    on_message=lambda msg: print(f"New message from {msg['sender_name']}"),
    on_conversation=lambda conv: print(f"New conversation: {conv['topic']}"),
)

# After messages arrive, the transcript is already populated
print(client.get_transcript(some_conversation_id))
```

### Messaging Events

The protocol events system (Section 16) includes messaging-specific events that are emitted alongside conversation logging:

- `MessageSent` — fired when a message is sent
- `MessageReceived` — fired when a message is received
- `MessageDelivered` — fired when delivery is confirmed
- `MessageRejected` — fired if a message is rejected (with reason)
- `ConversationOpened` — fired when a new conversation is created
- `ConversationClosed` — fired when a conversation is closed (with message count)
