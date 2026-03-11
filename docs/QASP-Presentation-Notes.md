# QASP Protocol — Presentation Speaker Notes

> These are your speaking notes for each section of the Technical Reference.
> The audience sees the Technical Reference on screen. You read from these notes.
> Each section covers: **What it is**, **Why it matters**, **How it works**, and **When it is used**.

---

## Section 1: Protocol Overview

**What it is:**
QASP stands for Quantum-Aware Secure Protocol. It is a binary communication protocol designed specifically for AI agents to talk to each other securely. Think of it as the HTTPS of the AI agent world, but built from the ground up for a post-quantum future. It handles not just encryption, but also identity, permissions, billing, and trust — all in one protocol.

**Why it matters:**
Today's encryption — RSA, elliptic curves — will be broken by quantum computers. QASP is designed to be secure against both classical and quantum attacks from day one. But beyond just encryption, AI agents have unique needs that traditional protocols don't address: they need fine-grained permissions for every action, they need to track and bill for resource usage in real time, and they need to establish trust with agents they've never interacted with before. QASP solves all of these problems in a single unified protocol.

**How it works:**
QASP uses ML-KEM-768 for key exchange and ML-DSA-65 for digital signatures — both are NIST-approved post-quantum algorithms at Security Level 3. On top of that cryptographic foundation, it layers a capability token model for access control, a metering system for usage tracking, a Bayesian trust scoring system for reputation, and a decentralized identity system based on the W3C DID standard. All of this runs over a compact binary wire format using CBOR encoding.

**When it is used:**
Whenever an AI agent needs to securely communicate with another AI agent — requesting a tool, accessing a dataset, calling an inference API, delegating a task to a sub-agent. Any machine-to-machine interaction where you need authentication, authorization, metering, and post-quantum security.

---

## Section 2: Architecture Stack

**What it is:**
This is the layered architecture of QASP. Like the OSI model for networking, QASP is built in layers, each with a distinct responsibility. From bottom to top: Transport, Crypto Foundation, Identity, Trust, Protocol, and Integration.

**Why it matters:**
Layered architecture means each concern is isolated. You can swap the transport from TCP to QUIC without touching the crypto layer. You can upgrade cipher suites without changing the token model. It also makes the protocol easier to reason about, implement, and audit — each layer has a clear contract with the layers above and below it.

**How it works:**
The Transport Layer handles raw bytes over TCP or QUIC. The Crypto Foundation provides the primitives — ML-DSA-65 signatures, ML-KEM-768 key exchange, AES-256-GCM encryption, HKDF-SHA-384 key derivation. The Identity Layer builds on that with the did:qasp decentralized identifier method and certificate management. The Trust Layer adds Bayesian reputation scoring. The Protocol Layer implements the actual handshake, token lifecycle, metering, and settlement. Finally, the Integration Layer provides bridges to existing ecosystems like MCP and A2A, plus REST APIs and SDKs.

**When it is used:**
This architecture governs every interaction in QASP. When you trace any operation — say, a tool call — it flows through all six layers: the integration layer receives the request, the protocol layer validates the token, the trust layer checks the agent's reputation, the identity layer resolves the DID, the crypto layer verifies the signature, and the transport layer delivers the bytes.

---

## Section 3: Wire Format & Framing

**What it is:**
This defines how every single QASP message looks on the wire — the actual bytes that flow over the network. Every message is wrapped in a fixed-format frame: an 8-byte header, a variable-length CBOR payload, and a 48-byte HMAC trailer.

**Why it matters:**
The framing layer is the first line of defense. Before any message is parsed or processed, the receiver can verify its integrity. The magic bytes prevent accidentally processing non-QASP traffic. The HMAC ensures that not a single bit has been tampered with. The fixed header size makes parsing efficient and deterministic — you always know exactly where to find each field.

**How it works:**
The first 2 bytes are always 0x51 0x41 — the ASCII letters "QA" — acting as a magic number to identify QASP traffic. Byte 3 is the version, currently 0x01. Byte 4 is the message type. Bytes 5 through 8 encode the payload length as a big-endian 32-bit unsigned integer. Then comes the CBOR-encoded payload, and finally a 48-byte HMAC-SHA-384 computed over the entire header plus payload. The receiver validates the magic, version, type, reads the payload, and then performs a constant-time HMAC comparison. If anything fails, the frame is rejected immediately.

**When it is used:**
Every single message in QASP goes through this framing — handshake messages, application data, token operations, meter reports, alerts, everything. There are no unframed messages. This is the universal envelope.

---

## Section 4: Message Types

**What it is:**
QASP defines 22 distinct message types, each identified by a single byte code from 0x01 to 0x1C. These cover every operation the protocol supports: handshake, data transfer, token management, resource lifecycle, metering, payment, pricing, reconciliation, disputes, revocation, OCSP, and alerts.

**Why it matters:**
Having a well-defined, finite set of message types means implementations can be exhaustive — you can handle every possible message. Reserved codes (0x1D through 0xFF) allow future extensibility without breaking existing implementations. Implementations MUST reject unknown types, which prevents protocol confusion attacks.

**How it works:**
Messages are grouped by function. Codes 0x01 through 0x03 handle the handshake. 0x04 is application data. 0x05 and 0x06 handle revocation. 0x07 through 0x0C manage resources. 0x0D through 0x0F handle disputes. 0x10 is metering. 0x11 and 0x12 manage channels. 0x13, 0x15, and 0x16 handle pricing. 0x14 is alerts. 0x17 and 0x18 handle delegation. 0x19 and 0x1A handle reconciliation. 0x1B and 0x1C handle OCSP. Each message has a defined direction — some are client-to-server only, some server-to-client only, and many are bidirectional.

**When it is used:**
The message type byte in the frame header determines how the payload is decoded and processed. The connection state machine dictates which message types are valid at any given point — for example, you cannot send APPLICATION_DATA before the handshake is complete.

---

## Section 5: Cipher Suites

**What it is:**
A cipher suite is a bundle of cryptographic algorithms that work together. QASP defines three suites: PQ-Strict which is fully post-quantum, Hybrid-Transition which combines classical and post-quantum algorithms for defense-in-depth, and Classical-Compat for legacy interoperability.

**Why it matters:**
Not every deployment can go fully post-quantum overnight. The three suites provide a migration path. You start with Classical-Compat if you need to interoperate with legacy systems, move to Hybrid-Transition for belt-and-suspenders security, and eventually migrate to PQ-Strict for pure post-quantum protection. Crucially, QASP enforces downgrade resistance — a server that supports post-quantum suites will reject clients that only offer classical crypto, sending an UPGRADE_REQUIRED alert.

**How it works:**
Each suite specifies four algorithms: a KEM for key exchange, a signature scheme for authentication, an AEAD cipher for data encryption, and a KDF for key derivation. Suite 0x0001 PQ-Strict uses ML-KEM-768, ML-DSA-65, AES-256-GCM, and HKDF-SHA-384. Suite 0x0002 Hybrid combines X25519 with ML-KEM-768 and Ed25519 with ML-DSA-65. Suite 0x0003 Classical uses only X25519 and Ed25519. The client proposes an ordered list in ClientHello, and the server selects the strongest mutually-supported suite.

**When it is used:**
Suite negotiation happens during the handshake — specifically in the ClientHello and ServerHello messages. Once selected, the suite governs all cryptographic operations for the entire session.

---

## Section 6: Connection State Machine

**What it is:**
The connection state machine defines the 8 possible states a QASP connection can be in, and the 14 valid transitions between them. It is a strict finite state machine — any attempt to transition outside the defined paths is an error.

**Why it matters:**
The state machine prevents protocol confusion. You cannot send application data before authentication. You cannot re-handshake on an established connection. Every state has a defined set of valid next states, and the implementation enforces this rigorously. This is critical for security — many protocol vulnerabilities come from unexpected state transitions.

**How it works:**
A connection starts in IDLE. The client moves to HELLO_SENT when it sends ClientHello; the server moves to HELLO_RECEIVED when it receives one. Both converge on AUTHENTICATED after the 3-message handshake, then transition to ESTABLISHED when the session key is ready. From ESTABLISHED, either side can initiate CLOSING, which leads to CLOSED. Any state can transition to ERROR, and from ERROR you can go to CLOSED or back to IDLE for connection reuse. The implementation also handles retries — authentication failures are not retried, but timeouts use exponential backoff up to 3 retries with a maximum of 60 seconds.

**When it is used:**
The state machine governs the entire lifecycle of every QASP connection. Every incoming and outgoing message is validated against the current state before processing.

---

## Section 7: Handshake (QASP-Shake)

**What it is:**
QASP-Shake is the 3-message mutual authentication and key exchange protocol. It establishes a shared session key and mutually authenticates both parties using post-quantum cryptography. Three messages: ClientHello, ServerHello, and ClientAuth.

**Why it matters:**
The handshake is the foundation of every secure session. It achieves three critical goals simultaneously: mutual authentication — both sides prove their identity using ML-DSA-65 signatures; key agreement — both sides contribute to the session key via KEM encapsulation, providing bilateral forward secrecy; and transcript binding — every signature covers the cumulative handshake transcript, preventing man-in-the-middle attacks and ensuring both sides see the same conversation.

**How it works:**
The client starts by sending ClientHello with its KEM public key, signature public key, supported cipher suites, and a 32-byte random nonce. The server responds with ServerHello containing its own keys, a KEM ciphertext encapsulated to the client's public key, the selected cipher suite, and crucially, an ML-DSA-65 signature over the handshake transcript so far. The client verifies this signature, decapsulates the server's KEM ciphertext to obtain a shared secret, then encapsulates its own KEM ciphertext to the server's public key and signs the full transcript. The server verifies the client's signature and decapsulates. Now both sides have two independent shared secrets — one from each direction — and derive the same session key.

**When it is used:**
At the very beginning of every QASP connection. No data can flow until the handshake completes. The handshake transitions the connection from IDLE through HELLO_SENT/HELLO_RECEIVED and AUTHENTICATED to ESTABLISHED.

---

## Section 8: Session Key Derivation

**What it is:**
After the handshake exchanges two shared secrets — one from each direction — this section defines how those raw secrets are combined and processed through HKDF-SHA-384 to produce the final 32-byte AES-256 session key and a 4-byte nonce IV prefix.

**Why it matters:**
Raw shared secrets from KEM should never be used directly as encryption keys. Key derivation adds cryptographic separation, domain binding, and uniform randomness extraction. The "QASP-v1" info string in HKDF ensures these keys can only be used for QASP sessions. Using both nonces as salt ensures session uniqueness. The bilateral design means compromising one party's long-term key alone is not sufficient to recover session keys — you need both sides' ephemeral contributions.

**How it works:**
For the Hybrid-Transition suite, there are four components: X25519 and ML-KEM shared secrets from both directions. These are grouped by algorithm, each group is hashed with SHA-256, and the results are concatenated to form the input keying material. For PQ-Strict, the ML-KEM shared secrets are hashed and the X25519 portion is zero-padded. This IKM is then fed into HKDF-SHA-384 with the concatenated client and server nonces as salt and "QASP-v1" as the info string, producing 32 bytes for the session key. A separate HKDF call with "qasp_nonce_iv" as info produces the 4-byte nonce IV prefix used in AES-GCM encryption.

**When it is used:**
Immediately after the handshake completes, before any application data is sent. Both sides perform this derivation independently and arrive at the same key, which is then used for all subsequent encrypted communication in the session.

---

## Section 9: Application Data Encryption

**What it is:**
Once the session is established, all application data is encrypted with AES-256-GCM. This section defines the ApplicationData message format and the precise construction of the nonce and additional authenticated data.

**Why it matters:**
AES-256-GCM provides both confidentiality and integrity for every byte of application data. The nonce construction — combining the fixed 4-byte IV prefix with an 8-byte sequence number — guarantees that no two messages ever reuse a nonce, which would be catastrophic for GCM security. The sequence number is also bound into the AAD along with the message type byte, which means any attempt to reorder, replay, or re-type messages will fail authentication.

**How it works:**
Each ApplicationData message contains encrypted_data and a sequence_number. The 12-byte AES-GCM nonce is constructed as the 4-byte nonce_iv concatenated with the 8-byte big-endian sequence number. The AAD is 9 bytes: the message type byte 0x04 followed by the 8-byte sequence number. Both sides maintain send and receive sequence counters. The sender increments send_seq after each message. The receiver rejects any message whose sequence number does not match recv_seq and increments on success. This provides strict ordering and replay protection.

**When it is used:**
For every message carrying actual application payload after the handshake. This is how agents exchange tool calls, tool results, data, and any other content during a session.

---

## Section 10: Stream Multiplexing

**What it is:**
Stream multiplexing allows multiple independent, concurrent data streams to share a single QASP connection. Each stream has its own ID and its own state machine. Stream data is embedded inside ApplicationData payloads.

**Why it matters:**
Without multiplexing, an agent that needs to interact with multiple resources simultaneously would need multiple connections — each requiring its own handshake, its own session keys, and its own overhead. Multiplexing lets you run many concurrent operations over one connection efficiently. This is especially important for AI agents that often make parallel tool calls.

**How it works:**
Each stream frame contains a 4-byte stream ID, a 1-byte flags field, a 4-byte payload length, and the stream payload. Client-initiated streams use odd IDs — 1, 3, 5 — and server-initiated streams use even IDs — 2, 4, 6. Each stream has four states: OPEN, HALF_CLOSED_LOCAL, HALF_CLOSED_REMOTE, and CLOSED. The END_STREAM flag signals the sender is done sending on that stream. This is conceptually similar to HTTP/2 streams.

**When it is used:**
When an agent needs to perform multiple operations concurrently — for example, reading from one resource while writing to another, or making parallel tool calls to different providers, all over the same authenticated connection.

---

## Section 11: Capability Token Model

**What it is:**
This is the heart of QASP's access control system. A capability token is a CBOR-encoded, ML-DSA-65 signed credential that grants specific permissions on a specific resource to a specific agent. It is the digital equivalent of a scoped, time-limited, revocable key card.

**Why it matters:**
Traditional access control uses identity-based models — "this user has admin role." Capability-based access is fundamentally more secure for agent systems because the token itself carries the permissions. An agent can only do what its token explicitly allows. Tokens can be attenuated when delegated — you can give a sub-agent a token that has fewer permissions than your own. Tokens can be revoked instantly. And every token is cryptographically signed, so they cannot be forged or tampered with.

**How it works:**
A token contains: who issued it, who holds it, which resource it grants access to using an ARM URI, which verbs are allowed — read, write, execute, delegate, attenuate, charge, revoke — and a rich constraints object that can limit time windows, quantity, rate, budget, data scope, purpose, and toolchain. The token is signed with the issuer's ML-DSA-65 key. Verification checks the signature, expiration, activation time, revocation status, URI matching, verb permissions, and constraint satisfaction. Delegation creates a child token with a hash pointer to the parent, and constraints can only be tightened — never loosened. Multiple tokens can be aggregated by taking the union of verbs and the intersection of constraints.

**When it is used:**
Every resource interaction in QASP requires a valid capability token. When you request access to a resource, you receive a token. When you call a tool, you present a token. When you delegate access to a sub-agent, you attenuate your token. When access should be revoked, the token is revoked.

---

## Section 12: Resource Management

**What it is:**
This section defines the complete lifecycle of a resource interaction — from requesting access, through receiving a grant or denial, to active use with metering, suspension if constraints are violated, and finally release when the agent is done.

**Why it matters:**
AI agents consume real resources — compute, storage, API calls, inference tokens. Without lifecycle management, there's no way to control who uses what, for how long, or at what cost. Resource management ties the capability token model to actual resource usage, with server-side enforcement of constraints and a clear release mechanism.

**How it works:**
The client sends a ResourceRequest with a resource type, ID, desired permissions as a bitmask, duration, optional payment offer, and any capability tokens for aggregation. The server responds with either a ResourceGrant containing a new capability token and a meter_id, or a ResourceDeny. During active use, the server monitors constraints and can send a ResourceSuspend with a specific reason — budget exhausted, quantity exceeded, rate limit hit, time expired, or manual suspension. When the agent is done, it sends a ResourceRelease with final usage counts and an ML-DSA-65 signature for non-repudiation.

**When it is used:**
Whenever an agent needs to access a managed resource. This is the operational backbone of QASP — every tool call, every data access, every compute allocation goes through this lifecycle.

---

## Section 13: Metering & Accounting

**What it is:**
Metering provides cryptographically verifiable, real-time usage tracking. The server generates signed meter reports, the client acknowledges them, and all receipts are linked in a hash chain for tamper-proof audit trails.

**Why it matters:**
When AI agents consume resources that cost real money, you need provable accounting. The hash-chained receipt model means neither side can retroactively alter usage records — every receipt links to the previous one via SHA-384. The ML-DSA-65 signatures provide non-repudiation — the server cannot deny it reported certain usage, and the client cannot deny it acknowledged it. If there's a billing dispute, the receipt chain is the cryptographic evidence.

**How it works:**
The server records usage events and periodically sends a MeterReport containing the meter ID, a sequence number, cumulative usage counts, cumulative cost, a timestamp, and an ML-DSA-65 signature over all of these fields. The client verifies the signature, checks the reported values against its own tracking and the token's constraints, and sends a MeterAck containing the acknowledged sequence and usage with its own signature. Each receipt includes a prev_hash — the SHA-384 of the previous receipt — creating an append-only, tamper-evident chain. The client enforces constraints at each report: if cumulative units exceed the quantity limit, or cumulative cost exceeds the budget, or the time has expired, the resource is suspended.

**When it is used:**
Throughout the active phase of any resource interaction. From the moment a resource is granted until it is released, meter reports flow from server to client at regular intervals or after significant usage changes.

---

## Section 14: Payment Channels & Settlement

**What it is:**
Payment channels enable off-chain micropayment settlement between agents. Rather than settling every individual transaction, agents open a channel, exchange state updates off-chain, and settle the final balance when the channel closes.

**Why it matters:**
AI agents may make thousands of small resource requests — each costing fractions of a credit. Settling every one individually would be prohibitively expensive and slow. Payment channels batch these into a single settlement, dramatically reducing overhead. The challenge period mechanism ensures that even if one party tries to cheat by publishing an outdated state, the counterparty can submit a more recent state to correct it.

**How it works:**
Both parties exchange ChannelOpen messages with initial balances and expiration times, signed with ML-DSA-65. During operation, they exchange signed state updates off-chain, each incrementing a sequence number. To close, there are three options: cooperative close where both sign the final state, unilateral close where one party publishes and a 300-second challenge period begins, or timeout close when the channel expires. During the challenge period, the counterparty can submit a state with a higher sequence number to override the submitted one.

**When it is used:**
For high-frequency resource interactions where per-transaction settlement would be impractical. Particularly useful for inference API calls, streaming data access, or any scenario where many small payments accumulate over a session.

---

## Section 15: Pricing Negotiation

**What it is:**
A simple three-message protocol for agents to negotiate resource prices before committing. The client requests a quote, the server offers a price, and the client accepts.

**Why it matters:**
In a marketplace of AI agents and resource providers, prices are not always fixed. Different providers may offer different rates for the same resource. Pricing negotiation allows agents to compare offers, set budget constraints, and make economically rational decisions before committing resources.

**How it works:**
The client sends a PriceRequest specifying the resource URI and requested number of units. The server responds with a PriceOffer containing the unit price, total cost, how long the offer is valid, and an ML-DSA-65 signature. The client sends a PriceAccept with its own signature to lock in the price. A PriceNegotiator helper supports configurable min/max bounds and tracks historical prices for reference.

**When it is used:**
Before committing to a resource that has variable pricing. An agent might query multiple providers, compare PriceOffers, and accept the best one before proceeding to ResourceRequest.

---

## Section 16: Reconciliation

**What it is:**
Reconciliation is an automated pre-dispute mechanism for resolving metering disagreements. When the client's local accounting diverges from the server's meter reports beyond a tolerance threshold, reconciliation kicks in to resolve the discrepancy without formal arbitration.

**Why it matters:**
Disputes are expensive — they involve evidence collection, review, and arbitration. Most metering disagreements are minor and caused by timing differences, rounding, or network delays. Reconciliation provides a 60-second grace period to resolve these automatically. This keeps the system efficient and reduces friction between agents that generally act in good faith.

**How it works:**
The DivergenceDetector compares reported costs against local costs. The tolerance is the greater of 1% of total cost or 1 unit. If the difference exceeds this, a ReconciliationSession starts. The client sends a ReconciliationRequest with its receipt chain for the disputed range. The server responds with its own chain and a proposed resolution. Four resolution methods are available: AGREED if both sides converge on a number, HIGHER_SEQ_WINS if one side has more recent receipts, USE_AVERAGE to split the difference, or FAILED if no automatic resolution is possible — at which point the dispute is escalated.

**When it is used:**
Automatically, whenever the client detects that the server's MeterReport diverges from its own accounting beyond the tolerance threshold. This happens transparently during normal resource usage.

---

## Section 17: Dispute Resolution

**What it is:**
Formal, evidence-based arbitration for when reconciliation fails. One party opens a dispute, both submit cryptographically signed evidence, and an arbiter renders a verdict.

**Why it matters:**
In any system where money changes hands, there must be a mechanism for resolving disagreements. QASP's dispute system is designed to be fair, transparent, and cryptographically verifiable. All evidence is signed, all receipt chains can be independently verified, and the verdict includes fault attribution. This creates accountability and deters malicious behavior.

**How it works:**
A dispute is opened with a DisputeOpen message specifying the dispute type — usage mismatch, overcharge, unauthorized access, service failure, or reconciliation failure — along with the claimed value and a hash of the evidence. Both parties submit DisputeEvidence messages containing signed evidence — receipt chains, capability tokens, or replay traces. An arbiter reviews the evidence and issues a DisputeVerdict with one of four outcomes: claimant wins, respondent wins, split, or dismissed. The dispute lifecycle flows from OPEN to EVIDENCE_SUBMISSION to UNDER_REVIEW to RESOLVED. The system tracks the divergence point — the first sequence number where the receipt chains disagree — and records fault attribution.

**When it is used:**
When reconciliation fails, or when a serious violation is detected — such as unauthorized access or service failure. Disputes are the exception, not the norm, but they provide essential accountability.

---

## Section 18: Token Revocation

**What it is:**
The revocation system provides four mechanisms to invalidate capability tokens: an in-memory Certificate Revocation List, BFS cascade revocation that propagates from parent to child tokens, real-time OCSP queries, and OCSP stapling for offline verification.

**Why it matters:**
Tokens have lifetimes and can be compromised. When a key is compromised, when permissions are withdrawn, or when an agent misbehaves, you need to revoke tokens immediately and ensure the revocation propagates to all delegated tokens. Without effective revocation, a compromised token could be used indefinitely until its natural expiration. The cascade mechanism is particularly important — if you revoke a parent token, every child token derived from it must also be revoked automatically.

**How it works:**
A TokenRevocation message specifies the token ID, revocation time, reason code, urgency, and the revoker's signature. Urgency levels control timing: CRITICAL takes effect immediately, NORMAL has a 300-second grace period, and PLANNED takes effect at a scheduled future time. The CRL stores all revoked token IDs and maintains parent-child relationships. When a parent is revoked, BFS cascade traverses the tree and revokes all descendants, generating a RevocationNotice that lists all cascade_token_ids. Seven revocation reasons are defined: unspecified, key compromise, privilege withdrawn, token superseded, delegation revoked, owner request, constraint violation, and cross-domain revoked. A thread-safe TokenUseLog tracks consumed token IDs to prevent replay attacks.

**When it is used:**
Whenever a token must be invalidated before its natural expiry — key compromise, permission changes, agent decommissioning, or detected abuse. Revocation checks happen during every token verification.

---

## Section 19: OCSP Stapling

**What it is:**
OCSP — Online Certificate Status Protocol — adapted for QASP capability tokens. It allows real-time queries about a token's revocation status. Stapling means pre-computing and bundling the OCSP response with the token itself for offline verification.

**Why it matters:**
Checking revocation status against a CRL requires network access to the authority server. In distributed or latency-sensitive environments, this may not be practical. OCSP stapling allows a token holder to carry a signed proof of non-revocation, enabling the verifier to confirm status without making a network call. Each response includes a nonce to prevent replay and has a defined validity window.

**How it works:**
An OCSPRequest contains the token_id and a 32-byte nonce. The OCSPResponse contains the status — GOOD, REVOKED, or UNKNOWN — along with timestamps, the responder's DID, the echoed nonce, and a fresh ML-DSA-65 signature. If the token is revoked, the response includes the revocation reason and time. The responder maintains an internal cache of status determinations but generates a fresh signature for each request. StapledOCSPResponses bundle the response with pre-computed CBOR encoding for efficient offline use in delegation chains.

**When it is used:**
When verifying a token in environments where the CRL might not be available, or when low-latency verification is required. Particularly valuable in multi-hop delegation chains where each link needs independent verification.

---

## Section 20: Trust Scoring System

**What it is:**
A Bayesian reputation system that computes a composite trust score for every agent based on four pillars: direct interaction history, witness reports from other agents, third-party certification audits, and behavioral protocol compliance.

**Why it matters:**
In an open ecosystem of AI agents, you need to know who to trust. A new agent with no history is different from a well-established agent with hundreds of successful interactions. Trust scoring quantifies this. It influences discovery — agents can filter by minimum trust score — and resource allocation decisions. The system is designed with strong anti-gaming measures because in an AI agent ecosystem, gaming reputation is a real and scalable threat.

**How it works:**
The composite score is a weighted average: 35% interaction reputation, 25% witness reputation, 20% certification score, and 20% behavioral compliance. Interaction reputation uses a Beta distribution with Bayesian updates — each success increments alpha, each failure increments beta. Witness reputation uses the TRAVOS algorithm to filter out unreliable witnesses based on credibility thresholds. Certification score maps SLSA audit levels to fixed scores. Behavioral compliance tracks protocol state machine adherence over a sliding window of 100 events. The raw score is capped based on interaction count — fewer than 10 interactions caps at 0.7, and you need 200+ for the full 1.0 range. Finally, confidence blending pulls new agents toward 0.5 — the neutral midpoint. Cold-start boost lets certification score compensate for lack of interaction history.

**When it is used:**
During agent discovery, when deciding whether to grant resource access, and when evaluating delegation requests. Trust scores are updated after dispute outcomes, service success or failure reports, and behavioral observations.

---

## Section 21: Decentralized Identity (did:qasp)

**What it is:**
A W3C DID Core-compliant decentralized identifier method for QASP agents. Each agent's DID is deterministically derived from their ML-DSA-65 public key, creating a self-sovereign identity that doesn't depend on any central authority.

**Why it matters:**
Centralized identity systems create single points of failure and trust bottlenecks. With did:qasp, an agent's identity is cryptographically bound to its key material — no one can impersonate an agent without its private key, and no central authority can revoke an agent's identity unilaterally. The DID document format is standards-compliant, enabling interoperability with the broader decentralized identity ecosystem.

**How it works:**
The identifier is derived as Base58btc encoding of the first 32 bytes of SHA-384 of the agent's ML-DSA-65 public key. The DID document contains the verification method, authentication references, and key management metadata. Resolution follows a three-tier approach: first direct exchange, then well-known endpoints, then DHT for future decentralized resolution. Key rotation uses a pre-commitment mechanism — you announce the hash of your next key before rotating, so an attacker who compromises your current key cannot produce a valid rotation without knowing the pre-committed key. Rotation requires dual signatures — both old and new keys must sign the rotation request. Owner-agent binding allows an owner to delegate specific permissions to an agent, with attenuation constraints for subset permissions and lower delegation depth.

**When it is used:**
Identity is used everywhere in QASP — every token references issuer, subject, and audience by DID. Every signature is verified against a DID's public key. Discovery returns agent DIDs. The DID is the universal identifier for all protocol participants.

---

## Section 22: Alert System & Error Codes

**What it is:**
The alert system provides structured error signaling within QASP. Alerts have two severity levels — warning and fatal — and carry a numeric code, a human-readable message, and a reference to the message type that caused the problem. The protocol also defines 13 programmatic error codes for application-level error handling.

**Why it matters:**
Clear, structured error signaling is essential for robust protocol implementations. Warning alerts let agents know something is off without killing the connection. Fatal alerts force immediate connection closure for security reasons — for example, when a KEM failure or authentication failure is detected. The error code taxonomy ensures implementations can programmatically handle specific failure modes with appropriate retry logic.

**How it works:**
An alert message contains a level — 1 for warning, 2 for fatal — a numeric description code, a human-readable message, and the related message type. Fatal alerts like KEM failure or authentication failure must not be retried — they indicate potential security issues. Version mismatch and timeout errors are retryable with exponential backoff. The error code range covers version and suite mismatches, authentication and KEM failures, token expiration and revocation, permission denial, rate limiting, resource unavailability, budget exhaustion, reconciliation failure, and channel closure, plus a catch-all internal error code 0xFF.

**When it is used:**
Whenever an error condition is detected — during handshake negotiation, token verification, resource management, or any other protocol operation. Alerts flow bidirectionally and can be sent at any point after the connection is established.

---

## Section 23: Cross-Domain Delegation

**What it is:**
Cross-domain delegation allows a token from one organization's trust domain to authorize actions in another organization's domain. It enables inter-organizational collaboration while maintaining a full audit trail.

**Why it matters:**
Real-world AI agent deployments span organizational boundaries. An agent from Company A might need to access a resource hosted by Company B on behalf of Company C. Cross-domain delegation makes this possible without requiring a pre-existing trust relationship between all parties — the delegation chain provides the cryptographic evidence of authorization.

**How it works:**
A DelegationRequest specifies the target DID, resource URI, desired verbs, and optional constraints. The granting authority responds with a DelegationGrant containing a new capability token. The token's parent_token_hash links it to the original authorization, creating a verifiable chain that spans domains. Each delegation level can only attenuate — never escalate — permissions.

**When it is used:**
When AI agents from different organizations need to collaborate — supply chain orchestration, federated learning, multi-provider tool pipelines, or any scenario where access needs to cross trust domain boundaries.

---

## Section 24: Server-Side Specification

**What it is:**
This section defines what a QASP authority server must implement: the components it maintains, the REST API it exposes, and its operational responsibilities.

**Why it matters:**
The server is the trust anchor in many QASP deployments. It issues tokens, verifies identities, tracks trust scores, manages revocations, mediates disputes, and provides discovery. A correct and complete server implementation is essential for the security guarantees of the entire system.

**How it works:**
The server maintains five core components: an Agent Registry with per-agent records including name, DID, keys, API key, callback URL, and registered tools; a DID Registry for identity resolution; a Trust Registry for Bayesian reputation scores; a Certificate Revocation List; and an OCSP Responder. It exposes REST endpoints for registration, discovery, token requests, revocation, status checks, tool call relay, and dispute filing. The server's responsibilities include participating in handshakes, minting tokens with appropriate constraints, verifying tokens on every request, generating signed meter reports, managing revocations with cascade, updating trust scores, and arbitrating disputes.

**When it is used:**
The server is always running, handling requests from client agents. It is the central coordination point for the QASP ecosystem, though the DID system allows for more decentralized deployments as well.

---

## Section 25: Client-Side Specification

**What it is:**
This section defines the client agent's interface, responsibilities, and the state it must maintain across sessions.

**Why it matters:**
The client is where agent developers interact with QASP. A well-defined client specification ensures that agents can be implemented correctly and interoperably. The client carries significant responsibility — it must verify server signatures, check metering reports against constraints, detect divergences, initiate reconciliation, and maintain its own receipt chains.

**How it works:**
The QASPClient provides methods for the full lifecycle: register to create an identity, discover to find peers filtered by capability and trust score, request_token to get authorization, call_tool to invoke remote tools, report_outcome to update trust scores, revoke_token to invalidate access, and open_dispute for formal complaints. The client must persistently store its API key, DID, and keypair. Per-session state includes the session key, send/receive sequence counters, and receipt chains per resource. Critically, the client is responsible for verifying MeterReport signatures and enforcing constraint checks locally — it does not blindly trust the server.

**When it is used:**
Every AI agent that participates in the QASP ecosystem runs a client. The client SDK abstracts the protocol complexity into simple method calls while handling all the cryptographic verification under the hood.

---

## Section 26: MCP Bridge Integration

**What it is:**
The MCP Bridge provides bidirectional interoperability between QASP and the Model Context Protocol. It wraps existing MCP servers with QASP's security layer, gating every tool call with capability token verification.

**Why it matters:**
MCP is already widely adopted as a standard for connecting AI models to tools. Rather than requiring the entire ecosystem to migrate to QASP, the bridge lets existing MCP tools benefit from QASP's post-quantum security, capability-based access control, and metering — without any changes to the MCP server itself. This dramatically lowers the adoption barrier.

**How it works:**
When an MCP client makes a tool call, it includes a QASP token in the _meta field — base64-encoded CBOR with the token ID. The bridge extracts this token, verifies the signature, checks expiration and revocation status, validates that the token grants the required verbs for the requested tool — with tool names mapped to resource URIs and verbs inferred from naming conventions like read_, write_, delete_. If verification passes, the bridge forwards the call to the underlying MCP server and returns the result. The bridge auto-generates an MCPServerIdentity with its own DID and keypair, enabling it to issue and verify tokens within the QASP trust model.

**When it is used:**
When deploying QASP security on top of existing MCP tool servers. This is the primary adoption path — wrap your existing MCP infrastructure with the QASP bridge and immediately gain post-quantum security, fine-grained access control, and usage metering.

---

## Section 27: End-to-End Protocol Flow

**What it is:**
This section shows the complete lifecycle of a QASP interaction from connection initiation through handshake, resource acquisition, usage with metering, reconciliation if needed, dispute if reconciliation fails, and finally resource release and connection close.

**Why it matters:**
Understanding the end-to-end flow is essential for seeing how all the individual pieces fit together. Each section we've discussed is one piece of a larger puzzle. This flow diagram shows the complete picture — the order of operations, the decision points, and the escalation paths.

**How it works:**
Phase 1 is the handshake — three messages establish mutual authentication and a session key. Phase 2 is resource acquisition — the client requests access and receives a capability token with a meter ID. Phase 3 is active usage — encrypted application data flows bidirectionally while the server generates periodic signed meter reports that the client acknowledges after checking constraints. Phase 4 is reconciliation — triggered automatically if metering diverges beyond tolerance, with a 60-second window for automatic resolution. Phase 5 is dispute — formal arbitration if reconciliation fails, with evidence submission and a binding verdict. Phase 6 is cleanup — the client releases the resource with a signed final usage count, and the connection closes gracefully with a close_notify alert.

**When it is used:**
This is the complete flow for every QASP session. Not every session will go through all phases — most will complete at Phase 3 with successful usage. Reconciliation and dispute are exception paths, but they are always available as safety nets.

---

## Section 28: Security Properties

**What it is:**
A summary of the 14 security properties that QASP guarantees, from post-quantum cryptography and forward secrecy to anti-gaming trust scoring and pre-dispute reconciliation.

**Why it matters:**
This is the "why you should trust this protocol" section. Each property addresses a specific threat. Post-quantum security protects against future quantum computers. Forward secrecy protects past sessions if long-term keys are compromised. Mutual authentication prevents impersonation. Replay protection prevents message reuse. Downgrade resistance prevents forcing weaker crypto. Delegation transparency prevents hidden privilege escalation. Revocation cascading prevents orphaned permissions. Every property is backed by a specific cryptographic or protocol mechanism.

**How it works:**
Each property maps directly to a protocol mechanism we've discussed. Post-quantum security comes from ML-KEM-768 and ML-DSA-65. Forward secrecy comes from bilateral KEM encapsulation. Mutual authentication comes from transcript-binding signatures. Replay protection comes from sequence numbers in nonces and AAD. Downgrade resistance comes from the UPGRADE_REQUIRED alert. Delegation transparency comes from the parent_token_hash chain. Revocation cascading comes from the BFS traversal. OCSP stapling enables offline revocation checks. Timing-safe verification prevents side-channel attacks. Anti-gaming trust uses caps, collusion detection, and confidence blending. Reconciliation before dispute reduces unnecessary arbitration.

**When it is used:**
These properties hold for every QASP session, from the first handshake byte to the final close. They are not optional features — they are inherent guarantees of the protocol design.

---

## Section 29: Constants Reference

**What it is:**
A quick-reference table of all numeric constants used throughout the protocol — magic values, cryptographic sizes, timing parameters, and trust scoring weights.

**Why it matters:**
Implementers need exact values. A wrong constant means an incompatible implementation. This section ensures that every implementation agrees on the precise byte sizes, timeout values, and scoring weights. It also serves as a useful summary for anyone reviewing or auditing the protocol.

**How it works:**
The constants are grouped by category. Protocol constants define the frame format — the 2-byte magic, version byte, 8-byte header, 48-byte HMAC. Cryptographic sizes define key and nonce lengths — 32-byte session keys, 32-byte nonces, 4-byte nonce IV, 1952-byte ML-DSA-65 public keys. Timing constants define operational parameters — 300-second challenge period, 60-second reconciliation grace, 300-second normal revocation grace, 60-second max handshake timeout, 3 max retries. Trust scoring constants define the weights and thresholds for the Bayesian system.

**When it is used:**
During implementation, testing, and interoperability verification. This is the definitive reference for all magic numbers in the protocol.

---

## Closing Remarks (Suggested)

> QASP brings together post-quantum cryptography, capability-based access control, real-time metering, and decentralized identity into a single protocol purpose-built for AI agent communication. It is designed to be secure against both today's threats and tomorrow's quantum computers, while providing the fine-grained control and accountability that AI agent ecosystems require. The layered architecture and standards-based approach — W3C DID, NIST PQC, CBOR — mean it can evolve and interoperate with the broader ecosystem. And the MCP bridge provides a practical adoption path that doesn't require ripping out existing infrastructure.
