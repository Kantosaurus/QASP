# QASP Protocol — Complete Technical Reference

> **Quantum-Aware Secure Protocol (QASP) v1.0**
> A post-quantum cryptographic protocol for AI agent-to-agent communication with capability-based access control, real-time metering, and decentralized identity.

---

## Table of Contents

1. [Protocol Overview](#1-protocol-overview)
2. [Architecture Stack](#2-architecture-stack)
3. [Wire Format & Framing](#3-wire-format--framing)
4. [Message Types](#4-message-types)
5. [Cipher Suites](#5-cipher-suites)
6. [Connection State Machine](#6-connection-state-machine)
7. [Handshake (QASP-Shake)](#7-handshake-qasp-shake)
8. [Session Key Derivation](#8-session-key-derivation)
9. [Application Data Encryption](#9-application-data-encryption)
10. [Stream Multiplexing](#10-stream-multiplexing)
11. [Capability Token Model](#11-capability-token-model)
12. [Resource Management](#12-resource-management)
13. [Metering & Accounting](#13-metering--accounting)
14. [Payment Channels & Settlement](#14-payment-channels--settlement)
15. [Pricing Negotiation](#15-pricing-negotiation)
16. [Reconciliation](#16-reconciliation)
17. [Dispute Resolution](#17-dispute-resolution)
18. [Token Revocation](#18-token-revocation)
19. [OCSP Stapling](#19-ocsp-stapling)
20. [Trust Scoring System](#20-trust-scoring-system)
21. [Decentralized Identity (did:qasp)](#21-decentralized-identity-didqasp)
22. [Alert System & Error Codes](#22-alert-system--error-codes)
23. [Cross-Domain Delegation](#23-cross-domain-delegation)
24. [Server-Side Specification](#24-server-side-specification)
25. [Client-Side Specification](#25-client-side-specification)
26. [MCP Bridge Integration](#26-mcp-bridge-integration)
27. [End-to-End Protocol Flow](#27-end-to-end-protocol-flow)
28. [Security Properties](#28-security-properties)
29. [Constants Reference](#29-constants-reference)

---

## 1. Protocol Overview

QASP is a binary, post-quantum secure protocol designed for machine-to-machine (specifically AI agent-to-AI agent) communication. It combines:

- **Post-quantum key exchange** (ML-KEM-768 / FIPS 203) and **post-quantum signatures** (ML-DSA-65 / FIPS 204) at NIST Level 3 security.
- **Capability-based access control** — scoped, time-limited, delegable, revocable tokens govern every resource interaction.
- **Bilateral forward secrecy** — both client and server contribute independent shared secrets via KEM encapsulation.
- **Real-time metering** — hash-chained, ML-DSA-65 signed receipts track usage with per-unit granularity.
- **Pre-dispute reconciliation** — automated divergence detection and resolution before escalation to formal arbitration.
- **Decentralized identity** — `did:qasp` method with deterministic derivation from ML-DSA-65 public keys.

### Entity Model

| Entity | Description | Key Material |
|--------|-------------|--------------|
| **Owner** | Human or organization; root of trust | ML-DSA-65 root keypair |
| **Agent** | AI software; acts on behalf of an owner | Own ML-DSA-65 keypair, bound to owner via delegation |
| **Server** | Resource provider; accepts tokens, meters usage | ML-DSA-65 keypair + server certificate |
| **Authority** | PKI root (optional in DID mode, required in cert mode) | CA-level ML-DSA-65 keypair |

---

## 2. Architecture Stack

```
┌─────────────────────────────────────────────────────────────────────┐
│  Integration Layer    Protocol bridges (MCP, A2A), REST API, SDK   │
├─────────────────────────────────────────────────────────────────────┤
│  Protocol Layer       Handshakes, tokens, metering, settlement     │
├─────────────────────────────────────────────────────────────────────┤
│  Trust Layer          Bayesian scoring, registry, audit certs      │
├─────────────────────────────────────────────────────────────────────┤
│  Identity Layer       DID method, certificates, key rotation       │
├─────────────────────────────────────────────────────────────────────┤
│  Crypto Foundation    ML-DSA-65, ML-KEM-768, AES-256-GCM, HKDF    │
├─────────────────────────────────────────────────────────────────────┤
│  Transport Layer      TCP / QUIC, asyncio, service discovery       │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 3. Wire Format & Framing

Every QASP message is transmitted inside a **framed binary envelope**.

### Frame Layout

```
Offset  Size    Field               Encoding
──────  ──────  ──────────────────  ──────────────────────────────
0–1     2 B     Magic               0x51 0x41 (ASCII "QA")
2       1 B     Version             0x01 (QASP v1.0)
3       1 B     Type                MessageType enum (0x01–0x1C)
4–7     4 B     Payload Length      Big-endian uint32
8..N    var     Payload             CBOR-encoded message body
N..N+48 48 B    HMAC                HMAC-SHA-384(key, header‖payload)
```

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Magic  0x51  0x41         |   Version     |     Type      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Payload Length (uint32 BE)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                    CBOR Payload (variable)                     +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                   HMAC-SHA-384 (48 bytes)                     +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Header size:** 8 bytes (fixed)
- **Frame overhead:** 56 bytes (8 header + 48 HMAC)
- **Payload encoding:** CBOR (RFC 8949), standard types only — no custom tags.
- **HMAC key:** Pre-shared temporary key during handshake; HKDF-derived session key after handshake completes.
- **HMAC verification:** Constant-time comparison (timing-safe).

### Receiver Validation Sequence

1. Read and assert magic bytes = `0x5141`
2. Read and assert version = `0x01`
3. Read type byte; reject if not in `0x01–0x1C`
4. Read 4-byte payload length (big-endian uint32)
5. Read exactly `payload_length` bytes of CBOR data
6. Read 48-byte HMAC trailer
7. Compute expected HMAC over `[header ‖ payload]`
8. Constant-time compare; reject frame on mismatch

---

## 4. Message Types

22 message types defined. Codes `0x1D–0xFF` are **RESERVED**; implementations MUST reject unknown types.

| Code | Name | Group | Direction |
|------|------|-------|-----------|
| `0x01` | `CLIENT_HELLO` | Handshake | Client → Server |
| `0x02` | `SERVER_HELLO` | Handshake | Server → Client |
| `0x03` | `CLIENT_AUTH` | Handshake | Client → Server |
| `0x04` | `APPLICATION_DATA` | Data | Bidirectional |
| `0x05` | `TOKEN_REVOCATION` | Revocation | Bidirectional |
| `0x06` | `REVOCATION_NOTICE` | Revocation | Bidirectional |
| `0x07` | `RESOURCE_REQUEST` | Resource Mgmt | Client → Server |
| `0x08` | `RESOURCE_GRANT` | Resource Mgmt | Server → Client |
| `0x09` | `METER_ACK` | Resource Mgmt | Client → Server |
| `0x0A` | `RESOURCE_SUSPEND` | Resource Mgmt | Server → Client |
| `0x0B` | `RESOURCE_DENY` | Resource Mgmt | Server → Client |
| `0x0C` | `RESOURCE_RELEASE` | Resource Mgmt | Client → Server |
| `0x0D` | `DISPUTE_OPEN` | Dispute | Bidirectional |
| `0x0E` | `DISPUTE_EVIDENCE` | Dispute | Bidirectional |
| `0x0F` | `DISPUTE_VERDICT` | Dispute | Arbiter → Peers |
| `0x10` | `METER_REPORT` | Metering | Server → Client |
| `0x11` | `CHANNEL_OPEN` | Channels | Bidirectional |
| `0x12` | `CHANNEL_CLOSE` | Channels | Bidirectional |
| `0x13` | `PRICE_REQUEST` | Pricing | Client → Server |
| `0x14` | `ALERT` | Alerts | Bidirectional |
| `0x15` | `PRICE_OFFER` | Pricing | Server → Client |
| `0x16` | `PRICE_ACCEPT` | Pricing | Client → Server |
| `0x17` | `DELEGATION_REQUEST` | Delegation | Bidirectional |
| `0x18` | `DELEGATION_GRANT` | Delegation | Bidirectional |
| `0x19` | `RECONCILIATION_REQUEST` | Reconciliation | Bidirectional |
| `0x1A` | `RECONCILIATION_RESPONSE` | Reconciliation | Bidirectional |
| `0x1B` | `OCSP_REQUEST` | OCSP | Bidirectional |
| `0x1C` | `OCSP_RESPONSE` | OCSP | Bidirectional |

---

## 5. Cipher Suites

Three cipher suites are defined, identified by 16-bit IDs:

| ID | Name | KEM | Signature | AEAD | KDF |
|----|------|-----|-----------|------|-----|
| `0x0001` | **PQ-Strict** | ML-KEM-768 | ML-DSA-65 | AES-256-GCM | HKDF-SHA-384 |
| `0x0002` | **Hybrid-Transition** | X25519 + ML-KEM-768 | Ed25519 + ML-DSA-65 | AES-256-GCM | HKDF-SHA-384 |
| `0x0003` | **Classical-Compat** | X25519 | Ed25519 | AES-256-GCM | HKDF-SHA-384 |

### Suite Selection Rules

- Client sends ordered list of supported suites in `CLIENT_HELLO`.
- Server selects the strongest mutually-supported suite.
- **Downgrade resistance:** A PQ-capable server MUST reject a client that only offers `0x0003` (Classical-Compat) and respond with `UPGRADE_REQUIRED` alert (code 72).

---

## 6. Connection State Machine

8 states with 14 valid transitions.

```
                          ┌──────────────┐
                          │     IDLE     │
                          └──────┬───────┘
                     ┌──────────┼──────────┐
                     ▼                     ▼
              ┌─────────────┐      ┌───────────────┐
              │ HELLO_SENT  │      │ HELLO_RECEIVED│
              │  (client)   │      │   (server)    │
              └──────┬──────┘      └───────┬───────┘
                     └──────────┬──────────┘
                                ▼
                       ┌────────────────┐
                       │ AUTHENTICATED  │
                       └───────┬────────┘
                               ▼
                       ┌────────────────┐
                       │  ESTABLISHED   │◄──── Application data flows here
                       └───────┬────────┘
                               ▼
                       ┌────────────────┐
                       │    CLOSING     │
                       └───────┬────────┘
                               ▼
                       ┌────────────────┐
                       │    CLOSED      │
                       └────────────────┘

     Any state ──────► ERROR ──────► CLOSED or IDLE
```

### Valid Transitions Table

| From | Valid Next States |
|------|-------------------|
| `IDLE` | `HELLO_SENT`, `HELLO_RECEIVED`, `ERROR` |
| `HELLO_SENT` | `AUTHENTICATED`, `ERROR`, `CLOSED` |
| `HELLO_RECEIVED` | `AUTHENTICATED`, `ERROR`, `CLOSED` |
| `AUTHENTICATED` | `ESTABLISHED`, `ERROR`, `CLOSED` |
| `ESTABLISHED` | `CLOSING`, `ERROR`, `CLOSED` |
| `CLOSING` | `CLOSED`, `ERROR` |
| `CLOSED` | `IDLE` (connection reuse) |
| `ERROR` | `CLOSED`, `IDLE` |

### Retry & Timeout Behavior

- Auth failures (`AUTH_FAILED`, `KEM_FAILED`) — **do not retry**
- Version/timeout errors — retryable with exponential backoff
- Backoff formula: `new_timeout = current_timeout × 2.0`
- Max retries: 3 (configurable)
- Max timeout: 60,000 ms

---

## 7. Handshake (QASP-Shake)

A 3-message mutual authentication and key exchange protocol.

### Message Flow

```
Client                                          Server
━━━━━━                                          ━━━━━━
[IDLE]                                          [IDLE]
  │                                               │
  │──── ClientHello (0x01) ──────────────────────►│
  │     protocol_version: [1, 0]                  │
  │     client_random: 32 bytes                   │
  │     kem_public_key: ML-KEM-768 pk             │
  │     sig_public_key: ML-DSA-65 pk (1952 B)     │
  │     cipher_suites: [0x0001, 0x0002, ...]      │
  │     extensions: bytes                         │
  │                                               │
[HELLO_SENT]                            [HELLO_RECEIVED]
  │                                               │
  │◄──── ServerHello (0x02) ─────────────────────│
  │      protocol_version: [1, 0]                 │
  │      server_random: 32 bytes                  │
  │      kem_ciphertext: KEM.Encap(client_pk)     │
  │      kem_public_key: ML-KEM-768 pk            │
  │      sig_public_key: ML-DSA-65 pk             │
  │      selected_cipher_suite: 0x0001            │
  │      signature: ML-DSA-65(transcript)         │
  │      certificate_chain: optional              │
  │                                               │
  │  Client verifies server signature             │
  │  Client decapsulates: SS_s                    │
  │                                               │
  │──── ClientAuth (0x03) ──────────────────────►│
  │     kem_ciphertext: KEM.Encap(server_pk)      │
  │     signature: ML-DSA-65(full_transcript)      │
  │     certificate: optional                      │
  │                                               │
  │  Server verifies client signature             │
  │  Server decapsulates: SS_c                    │
  │                                               │
[ESTABLISHED]                            [ESTABLISHED]
  │           ◄ session key derived ►             │
```

### Transcript Building

The `TranscriptBuilder` accumulates handshake material for signature binding:

```
ClientHello transcript:
    version ‖ client_nonce ‖ kem_pk ‖ sig_pk ‖ cipher_suites

ServerHello transcript (pre-signature):
    version ‖ server_nonce ‖ kem_ct ‖ kem_pk ‖ sig_pk ‖ selected_suite

Full transcript (for ClientAuth signature):
    ClientHello_transcript ‖ ServerHello_transcript ‖ server_signature

Session ID:
    SHA-384(full_transcript)[:32]
```

### CBOR Payloads

**ClientHello (0x01):**
```cbor
{
  "protocol_version": [1, 0],           // Array [major, minor]
  "client_random": h'...',              // 32-byte bstr
  "kem_public_key": h'...',             // ML-KEM-768 public key
  "sig_public_key": h'...',             // ML-DSA-65 public key (1952 bytes)
  "cipher_suites": [1, 2],              // Array of uint16 suite IDs
  "extensions": h''                     // Reserved
}
```

**ServerHello (0x02):**
```cbor
{
  "protocol_version": [1, 0],
  "server_random": h'...',              // 32-byte bstr
  "kem_ciphertext": h'...',             // KEM.Encapsulate(client_kem_pk)
  "kem_public_key": h'...',             // Server's ML-KEM-768 public key
  "sig_public_key": h'...',             // Server's ML-DSA-65 public key
  "selected_cipher_suite": 1,           // uint16
  "signature": h'...',                  // ML-DSA-65 over transcript
  "extensions": h'',
  "certificate_chain": h'...'           // Optional
}
```

**ClientAuth (0x03):**
```cbor
{
  "kem_ciphertext": h'...',             // KEM.Encapsulate(server_kem_pk)
  "signature": h'...',                  // ML-DSA-65 over full transcript
  "certificate": h'...'                 // Optional client certificate
}
```

---

## 8. Session Key Derivation

After the 3-message handshake, both sides independently derive identical session keys.

### Shared Secret Computation

Both parties perform KEM encapsulation in opposite directions:

```
Server → Client:  CT_s, SS_s = KEM.Encapsulate(client_kem_pk)
Client verifies:  SS_s'      = KEM.Decapsulate(CT_s, client_sk)

Client → Server:  CT_c, SS_c = KEM.Encapsulate(server_kem_pk)
Server verifies:  SS_c'      = KEM.Decapsulate(CT_c, server_sk)

Combined:         combined_shared = SS_s ‖ SS_c
```

This bilateral contribution provides **forward secrecy** — compromising one side's long-term key alone does not reveal session keys.

### Key Derivation Function

**For Hybrid-Transition (suite 0x0002):**
```
x25519_ss       = combined_shared[0:32]
mlkem_ss        = combined_shared[32:64]
x25519_ss_c     = combined_shared[64:96]
mlkem_ss_c      = combined_shared[96:128]

mlkem_combined  = mlkem_ss ‖ mlkem_ss_c
x25519_combined = x25519_ss ‖ x25519_ss_c

mlkem_for_kdf   = SHA-256(mlkem_combined)
x25519_for_kdf  = SHA-256(x25519_combined)

IKM = mlkem_for_kdf ‖ x25519_for_kdf
```

**For PQ-Strict (suite 0x0001):**
```
mlkem_for_kdf   = SHA-256(combined_shared)
x25519_for_kdf  = 0x00 × 32              // 32 zero bytes (padding)

IKM = mlkem_for_kdf ‖ x25519_for_kdf
```

**Final Session Key:**
```
session_key = HKDF-SHA-384(
    IKM  = IKM,
    salt = client_nonce ‖ server_nonce,
    info = "QASP-v1",
    L    = 32                             // AES-256 key length
)
```

**Nonce IV Derivation (for AES-GCM):**
```
nonce_iv = HKDF-SHA-384(
    IKM  = session_key,
    info = "qasp_nonce_iv",
    L    = 4                              // 4-byte IV prefix
)
```

---

## 9. Application Data Encryption

Once the session is `ESTABLISHED`, application data (type `0x04`) is encrypted with AES-256-GCM.

### ApplicationData CBOR Payload

```cbor
{
  "encrypted_data": h'...',              // AES-256-GCM ciphertext + tag
  "sequence_number": 42                  // Monotonic uint64 counter
}
```

### Encryption Parameters

| Parameter | Construction |
|-----------|-------------|
| **Key** | 32-byte `session_key` from HKDF |
| **Nonce** (12 B) | `nonce_iv (4 B) ‖ sequence_number (8 B big-endian)` |
| **AAD** (9 B) | `0x04 ‖ sequence_number (8 B big-endian)` |
| **Algorithm** | AES-256-GCM (AEAD) |

### Replay Protection

- Each side maintains a `send_seq` and `recv_seq` counter.
- Sender increments `send_seq` after each ApplicationData frame.
- Receiver rejects any frame whose `sequence_number ≠ recv_seq`; increments `recv_seq` on success.
- The sequence number is bound into both the nonce and the AAD, preventing reordering and replay.

---

## 10. Stream Multiplexing

Multiple concurrent capability streams are multiplexed over a single QASP connection.

### StreamFrame (embedded in ApplicationData payload)

```
Offset  Size   Field
──────  ─────  ──────────────
0–3     4 B    stream_id        (big-endian uint32)
4       1 B    flags            (bitmask: END_STREAM = 0x01)
5–8     4 B    payload_length   (big-endian uint32)
9..N    var    payload          (stream data)
```

### Stream ID Allocation

- **Client-initiated:** odd IDs (1, 3, 5, ...)
- **Server-initiated:** even IDs (2, 4, 6, ...)

### Stream State Machine

```
OPEN ──► HALF_CLOSED_LOCAL ──► CLOSED
  │                               ▲
  └──► HALF_CLOSED_REMOTE ────────┘
```

| State | Can Send | Can Receive |
|-------|----------|-------------|
| `OPEN` | Yes | Yes |
| `HALF_CLOSED_LOCAL` | No | Yes |
| `HALF_CLOSED_REMOTE` | Yes | No |
| `CLOSED` | No | No |

---

## 11. Capability Token Model

Every resource interaction in QASP is authorized by a **capability token** — a CBOR-encoded, ML-DSA-65 signed credential.

### Token Structure

```cbor
{
  "token_id":                h'...',       // 32 bytes: SHA-384(issuer_did ‖ nonce)[:32]
  "issuer_did":              "did:qasp:...",
  "subject_did":             "did:qasp:...",
  "audience_did":            "did:qasp:..." | null,
  "resource_uri":            "arm://provider/type/id",
  "verbs":                   ["read", "write", "execute"],
  "issued_at":               "2026-03-11T00:00:00Z",
  "nonce":                   h'...',       // 16 bytes
  "signature":               h'...',       // ML-DSA-65 over canonical CBOR

  // Constraints
  "constraints": {
    "not_before":            "2026-03-11T00:00:00Z" | null,
    "not_after":             "2026-03-12T00:00:00Z" | null,
    "quantity_limit":        1000 | null,
    "quantity_unit":         "requests",
    "rate_limit":            10 | null,
    "rate_period_seconds":   60,
    "max_spend":             5000 | null,
    "spend_currency":        "credits",
    "data_scope":            ["public", "internal"] | null,
    "purpose":               "analytics" | null,
    "allowed_toolchain":     ["tool_a", "tool_b"] | null
  },

  // Delegation chain fields
  "parent_token_hash":       h'...' | null,  // SHA-384(parent ‖ parent_sig)
  "max_delegation_depth":    3,
  "delegation_chain_length": 1,
  "toolchain_position":      0
}
```

### ARM Resource URI

Syntax: `arm://provider/type/id[/sub-path]`

Examples:
```
arm://cloud-compute/gpu/a100/instance-1
arm://storage/blob/dataset-7
arm://llm-provider/inference/gpt-4o
```

### Available Verbs

`read` · `write` · `execute` · `delegate` · `attenuate` · `charge` · `revoke`

### Token Verification Steps

1. Verify ML-DSA-65 signature against issuer's public key
2. Check `not_after >= now` (expiration)
3. Check `not_before <= now` (activation)
4. Query CRL / OCSP for revocation status
5. Validate resource URI match (prefix, exact, or wildcard)
6. Confirm required verbs are present in token's verb set
7. Enforce constraint limits (budget, rate, quantity, temporal)
8. If delegated: verify `parent_token_hash` chain, check `max_delegation_depth > 0`

### Delegation & Attenuation

A token holder with `delegate` or `attenuate` verbs can create child tokens with **tighter** constraints:

| Field | Attenuation Rule |
|-------|-----------------|
| `not_before` | Must be `>=` parent's |
| `not_after` | Must be `<=` parent's |
| `quantity_limit` | Must be `<=` parent's |
| `rate_limit` | Must be `<=` parent's |
| `max_spend` | Must be `<=` parent's |
| `data_scope` | Must be a subset of parent's |
| `purpose` | Must match parent's |
| `allowed_toolchain` | Must be a contiguous sublist of parent's |
| `verbs` | Must be a subset of parent's |

The child token records `parent_token_hash = SHA-384(parent_cbor ‖ parent_signature)` for chain verification.

### Token Aggregation

Multiple tokens can be combined:
- **Verbs:** Union (OR) of all token verb sets
- **Constraints:** Intersection (AND) — most restrictive wins
- Use case: multi-signer authorization for sensitive operations

---

## 12. Resource Management

### Lifecycle

```
RESOURCE_REQUEST (0x07) ──► RESOURCE_GRANT (0x08)
                         or RESOURCE_DENY (0x0B)
                              │
                    ┌─────────┴──────────┐
                    ▼                    ▼
             METER_REPORT (0x10)   RESOURCE_SUSPEND (0x0A)
                    │
                    ▼
              METER_ACK (0x09)
                    │
                    ▼
           RESOURCE_RELEASE (0x0C)
```

### ResourceRequest (0x07)

```cbor
{
  "request_id":          h'...',         // 16 bytes
  "resource_type":       "compute",
  "resource_id":         h'...',         // 32 bytes
  "permissions":         7,              // Bitmask (read=1, write=2, execute=4)
  "duration":            3600,           // Seconds requested
  "payment_offer":       h'...',         // Optional
  "capability_tokens":   [h'...', ...],  // CBOR-encoded tokens for aggregation
  "disclosure_mode":     "full",         // "full" | "selective_disclosure"
  "selective_proof":     h'...'          // ZK proof for selective disclosure
}
```

### ResourceGrant (0x08)

```cbor
{
  "request_id":          h'...',
  "token":               h'...',         // CBOR-encoded CapabilityToken
  "granted_permissions": 5,              // Bitmask (may be subset of requested)
  "expiration":          1741824000,     // Unix timestamp
  "meter_id":            h'...'          // 32 bytes — links to metering
}
```

### ResourceSuspend (0x0A)

```cbor
{
  "token_id":    h'...',
  "reason":      1,                      // SuspendReason enum
  "resume_time": 0                       // 0 = indefinite
}
```

**Suspension Reason Codes:**

| Code | Name | Trigger |
|------|------|---------|
| 1 | `BUDGET_EXHAUSTED` | `cumulative_cost > max_spend` |
| 2 | `QUANTITY_EXCEEDED` | `cumulative_units > quantity_limit` |
| 3 | `RATE_LIMIT_HIT` | Token bucket depleted |
| 4 | `TIME_EXPIRED` | `now > not_after` |
| 5 | `MANUAL` | Operator-initiated suspension |

### ResourceDeny (0x0B)

Sent when the server cannot or will not grant the requested resource.

### ResourceRelease (0x0C)

```cbor
{
  "token_id":    h'...',
  "final_usage": 42,                    // Final unit count
  "signature":   h'...'                 // ML-DSA-65 over (token_id ‖ final_usage)
}
```

### ManagedResource States

`PENDING` → `ACTIVE` → `SUSPENDED` or `RELEASED` or `DENIED`

---

## 13. Metering & Accounting

### Receipt Chain

Every usage event produces a **signed receipt** linked into a hash chain:

```
Receipt[n]:
    sequence_number: n
    prev_hash:       SHA-384(Receipt[n-1])
    total_units:     cumulative units
    total_cost:      cumulative cost
    meter_id:        32-byte resource identifier
    issuer:          DID of receipt issuer
    signature:       ML-DSA-65(prev_hash ‖ seq ‖ units ‖ cost)
```

Chain verification walks backwards, checking `prev_hash` continuity and signature validity at each step.

### MeterReport (0x10) — Server → Client

```cbor
{
  "meter_id":        h'...',
  "sequence_number": 5,
  "usage_count":     150,                // Cumulative units
  "usage_bytes":     1048576,            // Cumulative bytes
  "cost":            300,                // Cumulative cost
  "timestamp":       1741824000,
  "signature":       h'...'             // ML-DSA-65 over all above fields
}
```

### MeterAck (0x09) — Client → Server

```cbor
{
  "meter_id":       h'...',
  "acked_sequence": 5,
  "acked_usage":    150,
  "signature":      h'...'              // ML-DSA-65 over (meter_id ‖ seq ‖ usage)
}
```

### Constraint Enforcement at Metering Time

On each `MeterReport`, the client checks:

| Condition | Result |
|-----------|--------|
| `cumulative_units > quantity_limit` | `QUANTITY_EXCEEDED` → suspend |
| `cumulative_cost > max_spend` | `BUDGET_EXHAUSTED` → suspend |
| `now > not_after` | `TIME_EXPIRED` → suspend |
| Rate limiter depleted | `RATE_LIMIT_HIT` → suspend |

---

## 14. Payment Channels & Settlement

Off-chain micropayment channels for batched settlement.

### Channel States

```
OPENING ──► OPEN ◄──► CLOSING ──► CLOSED
               │                     ▲
               └──► DISPUTED ────────┘
```

### ChannelOpen (0x11)

```cbor
{
  "channel_id":      h'...',
  "counterparty_did": "did:qasp:...",
  "initial_balance": 10000,
  "expiration":      1741910400,
  "signature":       h'...'            // ML-DSA-65 over all fields
}
```

### ChannelClose (0x12)

```cbor
{
  "channel_id":        h'...',
  "final_balance":     8500,
  "close_reason":      "cooperative",   // "cooperative" | "unilateral" | "timeout"
  "closing_party_did": "did:qasp:...",
  "closing_signature": h'...'
}
```

### Settlement Flow

1. **Open:** Both parties exchange `ChannelOpen` with initial balances.
2. **State Updates:** Off-chain signed state updates transfer balance (each incrementing a sequence number).
3. **Cooperative Close:** Both parties sign final state → `CLOSED`.
4. **Unilateral Close:** One party publishes latest state → 300-second **challenge period**.
5. **Challenge:** Counterparty may submit a newer state (higher sequence) during the challenge window.
6. **Finalization:** After challenge period expires → `CLOSED` with the highest-sequence state.

---

## 15. Pricing Negotiation

### PriceRequest (0x13) — Client → Server

```cbor
{
  "resource_uri":    "arm://llm-provider/inference/gpt-4o",
  "requested_units": 1000
}
```

### PriceOffer (0x15) — Server → Client

```cbor
{
  "request_id":        h'...',
  "unit_price":        5,
  "total_cost":        5000,
  "validity_seconds":  300,
  "supplier_signature": h'...'          // ML-DSA-65
}
```

### PriceAccept (0x16) — Client → Server

```cbor
{
  "offer_id":             h'...',
  "acceptance_signature": h'...'        // ML-DSA-65
}
```

The `PriceNegotiator` helper supports min/max price bounds and tracks historical accepted prices.

---

## 16. Reconciliation

Pre-dispute mechanism for resolving metering divergences without formal arbitration.

### Divergence Detection

```
tolerance = max(0.01 × total_cost, 1 unit)

if |reported_cost − local_cost| > tolerance:
    trigger reconciliation
```

### ReconciliationSession States

```
IDLE ──► REQUESTED ──► CHAIN_EXCHANGE ──► AUTO_RESOLVED
                                       or FAILED ──► (escalate to Dispute)
```

Grace period: **60 seconds** before escalation.

### ReconciliationRequest (0x19)

```cbor
{
  "meter_id":   h'...',
  "start_seq":  1,
  "end_seq":    5,
  "chain_cbor": h'...',                 // CBOR-encoded ReceiptChain
  "signature":  h'...'                  // ML-DSA-65
}
```

### ReconciliationResponse (0x1A)

```cbor
{
  "meter_id":              h'...',
  "resolution_method":     2,           // ResolutionMethod enum
  "agreed_cost":           1500,        // If AGREED or USE_AVERAGE
  "counterparty_chain_cbor": h'...',
  "signature":             h'...'
}
```

### Resolution Methods

| Code | Method | Description |
|------|--------|-------------|
| 1 | `AGREED` | Both sides agree on final cost |
| 2 | `HIGHER_SEQ_WINS` | Accept the receipt chain with higher sequence number |
| 3 | `USE_AVERAGE` | Use the mean of reported vs. local cost |
| 4 | `FAILED` | Unable to reconcile; escalate to formal dispute |

---

## 17. Dispute Resolution

Formal, evidence-based arbitration when reconciliation fails.

### DisputeOpen (0x0D)

```cbor
{
  "dispute_id":    h'...',              // 32-byte random ID
  "token_id":      h'...',             // Related token
  "dispute_type":  1,                   // DisputeType enum
  "claimed_value": 500,                 // Units or cost claimed
  "evidence_hash": h'...'              // SHA-384 of evidence
}
```

### Dispute Types

| Code | Name |
|------|------|
| 1 | `USAGE_MISMATCH` |
| 2 | `OVERCHARGE` |
| 3 | `UNAUTHORIZED_ACCESS` |
| 4 | `SERVICE_FAILURE` |
| 5 | `RECONCILIATION_FAILURE` |

### DisputeEvidence (0x0E)

```cbor
{
  "dispute_id":    h'...',
  "evidence_type": 1,                   // EvidenceType enum
  "evidence_data": h'...',
  "signature":     h'...'              // ML-DSA-65 over evidence_data
}
```

**Evidence Types:** `RECEIPT_CHAIN` (1), `CAPABILITY_TOKEN` (2), `REPLAY_TRACE` (3)

### DisputeVerdict (0x0F)

```cbor
{
  "dispute_id":       h'...',
  "verdict":          1,               // VerdictCode enum
  "fault_attribution": "server",
  "awarded_amount":   500,
  "arbiter_signature": h'...'
}
```

**Verdict Codes:** `CLAIMANT_WINS` (1), `RESPONDENT_WINS` (2), `SPLIT` (3), `DISMISSED` (4)

### Dispute Lifecycle

```
OPEN ──► EVIDENCE_SUBMISSION ──► UNDER_REVIEW ──► RESOLVED
```

Both agent and server receipt chains are stored; the `divergence_point_seq` records the first disagreeing sequence number.

---

## 18. Token Revocation

### Revocation Mechanisms

| Mechanism | Description |
|-----------|-------------|
| **CRL** | In-memory Certificate Revocation List of revoked token IDs |
| **BFS Cascade** | Revoking a parent token cascades to all descendants via BFS traversal |
| **OCSP Responder** | Real-time status queries via `OCSP_REQUEST`/`OCSP_RESPONSE` |
| **OCSP Stapling** | Pre-computed revocation proofs bundled with tokens |

### TokenRevocation (0x05)

```cbor
{
  "token_id":        h'...',
  "revocation_time": 1741824000,
  "reason":          3,                 // RevocationReason code
  "signature":       h'...',            // ML-DSA-65
  "urgency":         0,                 // 0=critical, 1=normal, 2=planned
  "scheduled_time":  0,                 // For planned revocations
  "issuer_did":      "did:qasp:..."
}
```

### RevocationNotice (0x06)

Broadcast notification. Includes `cascade_token_ids` — list of all descendant token IDs also revoked.

### Revocation Reasons

| Code | Name |
|------|------|
| 0 | `UNSPECIFIED` |
| 1 | `KEY_COMPROMISE` |
| 2 | `PRIVILEGE_WITHDRAWN` |
| 3 | `TOKEN_SUPERSEDED` |
| 4 | `DELEGATION_REVOKED` |
| 5 | `OWNER_REQUEST` |
| 6 | `CONSTRAINT_VIOLATION` |
| 7 | `CROSS_DOMAIN_REVOKED` |

### Urgency & Grace Periods

| Urgency | Level | Effective Time |
|---------|-------|---------------|
| 0 | `CRITICAL` | Immediate (`effective = revocation_time`) |
| 1 | `NORMAL` | Grace: `revocation_time + 300 seconds` |
| 2 | `PLANNED` | Scheduled: `scheduled_time` (future) |

### Token Use Log

Thread-safe in-memory log of consumed token IDs. `mark_used()` raises `TokenReplayError` if the token has already been consumed — preventing replay attacks.

---

## 19. OCSP Stapling

Real-time revocation status for capability tokens.

### OCSPRequest (0x1B)

```cbor
{
  "token_id": h'...',
  "nonce":    h'...'                    // 32 bytes — replay protection
}
```

### OCSPResponse (0x1C)

```cbor
{
  "status":            0,               // OCSPStatus: GOOD=0, REVOKED=1, UNKNOWN=2
  "token_id":          h'...',
  "this_update":       1741824000,      // When status was determined
  "next_update":       1741827600,      // When response expires
  "responder_id":      "did:qasp:...",
  "nonce":             h'...',          // Echo of request nonce
  "signature":         h'...',          // ML-DSA-65 — fresh per request
  "revocation_reason": 3 | null,        // If revoked
  "revocation_time":   1741820000 | null
}
```

### Stapled Responses

`StapledOCSPResponse` bundles an OCSP response with pre-computed CBOR encoding, enabling offline verification in delegation chains without re-encoding.

---

## 20. Trust Scoring System

Bayesian reputation system with anti-gaming measures.

### Composite Formula

```
T_raw   = 0.35 × T_interaction
        + 0.25 × T_witness
        + 0.20 × T_certified
        + 0.20 × T_behavioral

T_capped = min(T_raw, cap(interaction_count))
T_final  = confidence × T_capped + (1 - confidence) × 0.5
```

### Trust Caps (Anti-Escalation)

| Interactions | Maximum Trust |
|--------------|---------------|
| < 10 | 0.7 |
| 10–49 | 0.8 |
| 50–199 | 0.9 |
| ≥ 200 | 1.0 |

### Four Pillars

#### 1. Interaction Reputation (35%)

Beta distribution: `Beta(α, β)` with uniform prior `Beta(1, 1)`.
- Success → α += 1
- Failure → β += 1
- Confidence: `1 − 2/(α + β)`
- Expected value: `α / (α + β)`

#### 2. Witness Reputation (25%)

TRAVOS credibility filtering:
- Compute witness agreement probability within tolerance window (ε = 0.2)
- Filter witnesses below credibility threshold (0.8)
- Aggregate credible reports only

#### 3. Certification Score (20%)

SLSA audit level mapping:
| SLSA Level | Score |
|------------|-------|
| Level 1 | 0.3 |
| Level 2 | 0.6 |
| Level 3 | 0.9 |

#### 4. Behavioral Compliance (20%)

FSM with 7 states: `IDLE` → `REQUESTING` → `PROCESSING` → `RESPONDING` → `ERROR_HANDLING` → `RATE_LIMITED` → `SUSPENDED`

- Sliding window of 100 events
- Score: `1.0 − (violation_weight / total_weight)`

### Cold-Start Boost

When `reputation_confidence < 0.3` and certification score exists:

```
cert >= 0.9  →  effective_reputation = max(reputation, 0.7)
cert >= 0.6  →  effective_reputation = max(reputation, 0.5)
cert >= 0.3  →  effective_reputation = max(reputation, 0.3)
```

### Anti-Gaming Measures

- **Interaction-count caps** prevent rapid trust escalation
- **Collusion detection** clusters witnesses with suspiciously similar scores
- **Confidence blending** pulls new agents toward neutral (0.5)
- **Time decay** applies exponential decay to old evidence

---

## 21. Decentralized Identity (did:qasp)

W3C DID Core-compliant method for self-sovereign agent identifiers.

### Identifier Derivation

```
identifier = Base58btc(SHA-384(ML-DSA-65_public_key)[0:32])
DID        = "did:qasp:" + identifier
```

Example: `did:qasp:2ZTp9sZYQnVTQzGK8hA5zUQvZk7DhY4zRvJpPvjnL7bE`

### DID Document

```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://qasp.dev/security/v1"],
  "id": "did:qasp:2ZTp9sZYQnVTQzGK8hA5zUQvZk7DhY4zRvJpPvjnL7bE",
  "verificationMethod": [{
    "id": "#key-0",
    "type": "MLDSAVerificationKey2025",
    "controller": "did:qasp:...",
    "publicKeyMultibase": "z..."
  }],
  "authentication": ["#key-0"],
  "assertionMethod": ["#key-0"],
  "keyVersion": 1,
  "nextKeyHash": "SHA-384(next_public_key)"
}
```

### CRUD Operations

| Operation | Method |
|-----------|--------|
| **Create** | Generate ML-DSA-65 keypair → compute identifier → publish DID document |
| **Read** | Three-tier resolution: direct exchange → well-known endpoint → DHT (future) |
| **Update** | Key rotation with pre-commitment and dual-signature proof |
| **Deactivate** | Remove from all registries |

### Key Rotation Security

1. **Pre-commitment:** `nextKeyHash = SHA-384(new_public_key)` — announced before rotation
2. **Dual-signature proof:** Rotation request signed by both old and new keys
3. **Version increment:** `keyVersion` monotonically increases
4. **Protection:** An attacker who compromises the key after pre-commitment cannot produce a valid rotation (would need to match the committed hash)

### Owner-Agent Binding

```
Root binding:      signed by owner
Delegated binding: signed by agent (under owner authority)

Permissions:
  resource:request, resource:delegate,
  comm:initiate, comm:accept,
  token:*, identity:*

Attenuation:
  - Subset of parent permissions
  - Shorter validity periods
  - Lower delegation depth
  - parent_binding_hash for chain verification
```

---

## 22. Alert System & Error Codes

### Alert Message (0x14)

```cbor
{
  "level":                1,            // 1=warning, 2=fatal
  "description":          50,           // Alert code
  "message":              "KEM decapsulation failed",
  "related_message_type": 2             // Which message caused the alert
}
```

### Alert Levels

| Level | Meaning | Action |
|-------|---------|--------|
| 1 | Warning | Informational; connection stays open |
| 2 | Fatal | Connection MUST close immediately |

### Alert Codes

**Handshake & Crypto:**

| Code | Name | Level | Recovery |
|------|------|-------|----------|
| 0 | `close_notify` | — | Normal shutdown |
| 50 | `decode_error` | Fatal | KEM failure; don't retry |
| 51 | `decrypt_error` | Fatal | Signature verification failed |
| 70 | `protocol_version` | Fatal | Version mismatch; retry with negotiated version |
| 71 | `insufficient_security` | Fatal | Cipher suite mismatch |
| 72 | `upgrade_required` | Fatal | Client must upgrade to PQ suite |

**Protocol:**

| Code | Name |
|------|------|
| 54 | Token replay detected |
| 56–59 | Revocation errors |
| 60–63 | Metering errors |
| 64–68 | OCSP errors |

### QASP Error Codes (Programmatic)

```
0x01  VERSION_MISMATCH         0x07  PERMISSION_DENIED
0x02  SUITE_MISMATCH           0x08  RATE_LIMITED
0x03  AUTH_FAILED               0x09  RESOURCE_UNAVAILABLE
0x04  KEM_FAILED                0x0A  BUDGET_EXHAUSTED
0x05  TOKEN_EXPIRED             0x0B  RECONCILIATION_FAILED
0x06  TOKEN_REVOKED             0x0C  CHANNEL_CLOSED
                                0xFF  INTERNAL_ERROR
```

### Exception Hierarchy

- `HandshakeVersionError` — version negotiation fails
- `HandshakeSuiteError` — cipher suite negotiation fails
- `HandshakeAuthError` — signature verification fails (includes stage info)
- `HandshakeKEMError` — KEM encap/decap fails (includes operation info)
- `HandshakeUpgradeRequiredError` — server requires PQ-capable client
- `HandshakeTimeoutError` — timeout with stage and elapsed_ms tracking

---

## 23. Cross-Domain Delegation

Enables cross-organizational token issuance with full audit trail.

### DelegationRequest (0x17)

```cbor
{
  "delegation_id": h'...',
  "subject_did":   "did:qasp:...",       // Delegatee
  "resource_uri":  "arm://provider/type/id",
  "verbs":         ["read", "execute"],
  "constraints":   { ... }               // Optional Constraints
}
```

### DelegationGrant (0x18)

```cbor
{
  "delegation_id": h'...',
  "token":         h'...'               // CBOR-encoded CapabilityToken
}
```

Delegation chains are cryptographically verifiable: each child token records its `parent_token_hash`, and the full chain can be walked and validated.

---

## 24. Server-Side Specification

### Authority State

The QASP authority server maintains:

| Component | Purpose |
|-----------|---------|
| **Agent Registry** | Per-agent records: name, DID, public/secret keys, API key, callback URL, registered tools |
| **DID Registry** | Identity resolution for all known DIDs |
| **Trust Registry** | Bayesian reputation scores per agent |
| **CRL** | Certificate Revocation List for all tokens |
| **OCSP Responder** | Real-time revocation status |

### REST API Endpoints

| Method | Endpoint | Description | Response |
|--------|----------|-------------|----------|
| `POST` | `/register` | Register new agent | `{ api_key, did, public_key }` |
| `GET` | `/discover` | Find agents by capability URI + min trust | `[{ agent }, ...]` |
| `POST` | `/tokens/request` | Request capability token for a tool | `{ token, token_id, expires_at }` |
| `GET` | `/tokens/status/{id}` | Check token status via OCSP | `{ status }` |
| `POST` | `/tokens/revoke` | Revoke token with cascade | `{}` |
| `POST` | `/tools/call` | Relay tool call to target agent's callback | `{ result, metering, receipt_id }` |
| `POST` | `/disputes/open` | Open formal dispute | `{ dispute_id }` |

### Server Responsibilities

1. **Handshake participation** — respond to ClientHello with ServerHello, verify ClientAuth
2. **Token issuance** — mint capability tokens with appropriate constraints
3. **Token verification** — validate tokens on every resource request
4. **Metering** — track usage per meter_id, generate signed MeterReports
5. **Revocation management** — maintain CRL, process revocation requests, cascade
6. **Trust scoring** — update behavioral reputation on outcomes
7. **Discovery** — serve agent discovery filtered by trust score and capability
8. **Dispute arbitration** — collect evidence, render verdicts
9. **Settlement** — manage payment channel lifecycle

### Rate Limiting

Token-bucket algorithm per `meter_id` and per-connection, enforced server-side. Global rate limit registry across all connections.

---

## 25. Client-Side Specification

### QASPClient Interface

```python
qasp = QASPClient("http://localhost:8080")

# 1. Register
me = qasp.register("MyAgent", [{"name": "echo", "description": "Echo tool"}])
# Returns: { api_key, did, public_key }

# 2. Discover peers
agents = qasp.discover(capability="arm://tools/*", min_trust=0.7)
# Returns: [{ did, name, tools, trust_score }, ...]

# 3. Request token
token = qasp.request_token(target_did, tool_name="echo")
# Returns: { token, token_id, expires_at }

# 4. Call tool
result = qasp.call_tool(target_did, "echo", {"msg": "hello"}, token["token"])
# Returns: { result, metering, receipt_id }

# 5. Report outcome
qasp.report_outcome(target_did, success=True)

# 6. Revoke token
qasp.revoke_token(token["token_id"])

# 7. Open dispute
qasp.open_dispute(token["token_id"], dispute_type=2, claimed_value=500)
```

### Client Responsibilities

1. **Handshake initiation** — generate ClientHello, verify ServerHello signature, send ClientAuth
2. **Key material management** — store API key, DID, keypair securely
3. **Token management** — request, store, present, and release tokens
4. **Meter verification** — verify MeterReport signatures, check constraints, send MeterAck
5. **Divergence detection** — compare local accounting vs. server MeterReports
6. **Reconciliation initiation** — trigger when divergence exceeds tolerance
7. **Dispute filing** — escalate when reconciliation fails

### State to Maintain

| State | Source | Lifetime |
|-------|--------|----------|
| `api_key` | `POST /register` | Persistent |
| `did` | `POST /register` | Persistent |
| `keypair` | Generated at registration | Persistent; rotate per DID spec |
| `tokens` | `POST /tokens/request` | Until expiry or revocation |
| `session_key` | Derived during handshake | Per-session |
| `send_seq / recv_seq` | Initialized at 0 | Per-session |
| `receipt_chain` | Built from MeterReports | Per-resource |

---

## 26. MCP Bridge Integration

Bidirectional bridge between QASP and the Model Context Protocol (MCP).

### Token Injection (Client → MCP)

```python
# Inject QASP token into MCP tool call _meta
meta = {
    "qasp_token_id": token.token_id.hex(),
    "qasp_token": base64.b64encode(token.to_cbor_with_signature()).decode()
}
```

### Token Extraction (MCP → QASP)

```python
# Extract and verify QASP token from MCP _meta
token_b64 = meta["qasp_token"]
token_cbor = base64.b64decode(token_b64)
token = CapabilityToken.from_cbor(token_cbor)
assert token.token_id.hex() == meta["qasp_token_id"]
```

### Tool Name → Resource URI Mapping

```
Tool "read_file"   → arm://mcp/tools/read_file    → verbs: {execute, read}
Tool "write_file"  → arm://mcp/tools/write_file   → verbs: {execute, write}
Tool "delete_file" → arm://mcp/tools/delete_file  → verbs: {execute, delete}
Tool "search"      → arm://mcp/tools/search       → verbs: {execute}
```

### Authorization Flow

```
MCP Client                    MCPBridge                    MCP Server
    │                             │                             │
    │── tool call + qasp_token ──►│                             │
    │                             │── extract token             │
    │                             │── verify signature          │
    │                             │── check expiry              │
    │                             │── check revocation          │
    │                             │── check verbs + resource    │
    │                             │                             │
    │                             │── forward tool call ───────►│
    │                             │◄── result ──────────────────│
    │◄── wrapped result ─────────│                             │
```

### MCPServerIdentity

Auto-generated identity for wrapped MCP servers. Contains a DID, public/secret keypair — enabling the wrapped server to issue and verify tokens within the QASP trust model.

---

## 27. End-to-End Protocol Flow

Complete connection lifecycle from initiation to teardown:

```
Phase 1: HANDSHAKE
═══════════════════
Client                                              Server
  │                                                    │
  │  1. Generate ML-KEM-768 + ML-DSA-65 keypairs       │
  │  2. Create ClientHello                             │
  │──── ClientHello (0x01) ──────────────────────────►│
  │                                                    │  3. Verify version, select suite
  │                                                    │  4. KEM.Encapsulate(client_pk) → SS_s
  │                                                    │  5. Sign transcript
  │◄──── ServerHello (0x02) ─────────────────────────│
  │  6. Verify server signature                        │
  │  7. KEM.Decapsulate(CT_s) → SS_s                   │
  │  8. KEM.Encapsulate(server_pk) → SS_c              │
  │  9. Sign full transcript                           │
  │──── ClientAuth (0x03) ──────────────────────────►│
  │                                                    │ 10. Verify client signature
  │                                                    │ 11. KEM.Decapsulate(CT_c) → SS_c
  │                                                    │
  │  ◄── Both derive session_key via HKDF-SHA-384 ──► │
  │  ◄── session_id = SHA-384(transcript)[:32] ──────► │
  │                                                    │
  [ESTABLISHED]                              [ESTABLISHED]

Phase 2: RESOURCE ACQUISITION
══════════════════════════════
  │                                                    │
  │──── ResourceRequest (0x07) ─────────────────────►│
  │     capability_tokens: [aggregated tokens]         │
  │                                                    │ 12. Verify tokens
  │                                                    │ 13. Create CapabilityToken
  │◄──── ResourceGrant (0x08) ──────────────────────│
  │      token + meter_id                              │
  │                                                    │

Phase 3: USAGE & METERING
══════════════════════════
  │                                                    │
  │──── ApplicationData (0x04, encrypted) ──────────►│
  │◄──── ApplicationData (0x04, encrypted) ─────────│
  │      ...                                           │
  │                                                    │ 14. Record usage
  │◄──── MeterReport (0x10, signed) ────────────────│
  │ 15. Verify signature                               │
  │ 16. Check constraints                              │
  │──── MeterAck (0x09, signed) ────────────────────►│
  │                                                    │

Phase 4: RECONCILIATION (if divergence detected)
═════════════════════════════════════════════════
  │                                                    │
  │──── ReconciliationRequest (0x19) ───────────────►│
  │     receipt chain range                            │
  │◄──── ReconciliationResponse (0x1A) ─────────────│
  │      resolution_method + agreed_cost               │
  │                                                    │

Phase 5: DISPUTE (if reconciliation fails)
══════════════════════════════════════════
  │                                                    │
  │──── DisputeOpen (0x0D) ─────────────────────────►│
  │──── DisputeEvidence (0x0E) ─────────────────────►│
  │◄──── DisputeEvidence (0x0E) ────────────────────│
  │◄──── DisputeVerdict (0x0F) ─────────────────────│
  │                                                    │

Phase 6: RESOURCE RELEASE & CLOSE
══════════════════════════════════
  │                                                    │
  │──── ResourceRelease (0x0C, signed) ─────────────►│
  │──── Alert: close_notify (0x14) ─────────────────►│
  │                                                    │
  [CLOSED]                                    [CLOSED]
```

---

## 28. Security Properties

| Property | Mechanism |
|----------|-----------|
| **Post-Quantum Security** | ML-KEM-768 (IND-CCA2, NIST Level 3), ML-DSA-65 (EUF-CMA, NIST Level 3) |
| **Bilateral Forward Secrecy** | Both client and server contribute independent KEM shared secrets |
| **Mutual Authentication** | Both sides sign the handshake transcript with ML-DSA-65 |
| **Session Uniqueness** | `session_id = SHA-384(full_transcript)[:32]` |
| **Replay Protection** | Monotonic sequence numbers bound into nonce + AAD; token use log |
| **Downgrade Resistance** | PQ-capable servers reject classical-only clients (UPGRADE_REQUIRED) |
| **Transcript Binding** | All signatures cover cumulative transcript hash |
| **Delegation Transparency** | Unbroken `parent_token_hash` chain with ML-DSA-65 signatures |
| **Revocation Cascading** | BFS traversal ensures parent revocation cascades to all descendants |
| **OCSP Stapling** | Offline revocation verification without network round-trips |
| **Timing-Safe Verification** | HMAC comparison uses constant-time algorithm |
| **Anti-Gaming Trust** | Interaction caps, collusion detection, confidence blending, time decay |
| **Reconciliation Before Dispute** | 60-second grace period minimizes formal arbitration |
| **DID Binding** | Deterministic derivation from ML-DSA-65 public key; pre-commitment key rotation |

---

## 29. Constants Reference

```
Protocol Constants
──────────────────
FRAME_MAGIC                = 0x5141        (2 bytes, ASCII "QA")
FRAME_VERSION              = 0x01
HEADER_SIZE                = 8 bytes       (magic + version + type + length)
HMAC_SIZE                  = 48 bytes      (HMAC-SHA-384 output)

Cryptographic Sizes
───────────────────
SESSION_KEY_SIZE           = 32 bytes      (AES-256)
NONCE_SIZE                 = 32 bytes      (client/server random)
NONCE_IV_SIZE              = 4 bytes       (AES-GCM IV prefix)
TOKEN_NONCE_SIZE           = 16 bytes
ML_DSA_65_PUBLIC_KEY_SIZE  = 1952 bytes
MULTICODEC_MLDSA65         = 0x1318
HKDF_SHA384_HASH_SIZE      = 48 bytes
TOKEN_ID_SIZE              = 32 bytes      (SHA-384 truncated)
SESSION_ID_SIZE            = 32 bytes      (SHA-384 truncated)

Timing
──────
CHALLENGE_PERIOD           = 300 seconds   (payment channel)
RECONCILIATION_GRACE       = 60 seconds
NORMAL_REVOCATION_GRACE    = 300 seconds
MAX_HANDSHAKE_TIMEOUT      = 60,000 ms
MAX_HANDSHAKE_RETRIES      = 3

Trust Scoring
─────────────
INTERACTION_WEIGHT         = 0.35
WITNESS_WEIGHT             = 0.25
CERTIFICATION_WEIGHT       = 0.20
BEHAVIORAL_WEIGHT          = 0.20
WITNESS_EPSILON            = 0.2
WITNESS_CREDIBILITY_THRESH = 0.8
BEHAVIORAL_WINDOW_SIZE     = 100 events
COLD_START_CONFIDENCE_THRESH = 0.3
```

---

## Source Code Reference

| File | Purpose |
|------|---------|
| `src/qasp/framing/codec.py` | Frame encode/decode, HMAC computation |
| `src/qasp/framing/messages.py` | All 22+ message dataclasses, `MessageType` enum |
| `src/qasp/protocol/connection.py` | Sans-I/O connection handler, state machine, encryption |
| `src/qasp/protocol/states.py` | Connection state enum and valid transitions |
| `src/qasp/protocol/handshake.py` | QASP-Shake handshake, transcript builder |
| `src/qasp/crypto/keys.py` | ML-KEM-768 / ML-DSA-65 / X25519 key operations |
| `src/qasp/crypto/kdf.py` | HKDF-SHA-384 session key derivation |
| `src/qasp/tokens/capability.py` | Capability token model, verification, delegation |
| `src/qasp/tokens/token_aggregation.py` | Token aggregation logic |
| `src/qasp/tokens/token_use_log.py` | Token replay prevention |
| `src/qasp/metering/accounting.py` | Usage tracking, receipt chain, signed receipts |
| `src/qasp/metering/metering.py` | MeterReport/MeterAck handling |
| `src/qasp/settlement/settlement.py` | Payment channel lifecycle |
| `src/qasp/dispute/dispute.py` | Dispute open/evidence/verdict handling |
| `src/qasp/reconciliation/reconciliation.py` | Divergence detection, reconciliation sessions |
| `src/qasp/revocation/revocation.py` | CRL, cascade revocation, revocation entries |
| `src/qasp/revocation/ocsp.py` | OCSP responder and stapled responses |
| `src/qasp/trust/scoring.py` | Bayesian trust scoring system |
| `src/qasp/identity/did.py` | `did:qasp` method, DID documents, key rotation |
| `src/qasp/bridges/mcp_bridge.py` | MCP ↔ QASP bridge |
| `src/qasp/protocol/stream.py` | Stream multiplexing |
| `src/qasp/protocol/rate_limiter.py` | Token-bucket rate limiting |
| `src/qasp/server/qasp_server.py` | Authority server (REST API) |
| `src/qasp/client/qasp_client.py` | Client SDK |
