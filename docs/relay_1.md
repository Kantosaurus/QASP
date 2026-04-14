# Capability-gated relay architectures for real-time agent communication

**No existing relay system combines per-message capability-token enforcement, active metering, and post-quantum cryptography — this is a genuine, publishable gap.** After surveying relay architectures (TURN, MQTT, NATS, libp2p), capability-based networking (SCION, TVA, Macaroons), programmable dataplanes (P4, eBPF, DPDK), secure group relay (MLS, OHTTP, Matrix), economic routing (Lightning Network, Filecoin), and content-addressable networking (NDN), the research reveals that while individual building blocks exist, their combination into an actively-participating capability-enforcing relay for autonomous agent communication is unexplored territory. The critical performance insight driving all viable designs: **ML-DSA-65 signature verification at ~50–90µs per operation caps throughput at ~11–21K verifications/sec/core**, making per-message PQC verification infeasible at scale and demanding a split-plane architecture with amortized verification and HMAC-based fast-path tokens. Three novel architectures emerge from this synthesis, each targeting a different dimension of novelty for top-venue publication.

---

## The relay landscape has a capability-shaped hole

Existing relay and broker architectures handle pieces of the puzzle but none address the full problem. **TURN** relays WebRTC media but operates as a "dumb pipe" — all application data is DTLS+SRTP encrypted, and the relay cannot inspect, meter, or enforce policies on individual messages. Authorization is connection-level via shared secrets, with only coarse bandwidth quotas (Cloudflare enforces ~50–100 Mbps per allocation). **MQTT brokers** like EMQX (benchmarked at **100M+ concurrent connections**) and HiveMQ (**200M connections**) offer the richest extensible auth models — TLS/mTLS, JWT/OAuth, topic-level RBAC — but their authorization is topic-based, not per-message capability-token-based. The broker routes by topic subscription, not by embedded capability.

**NATS** provides sophisticated multi-tenant isolation with subject-level permissions and account-level JetStream quotas, but permissions are static per-user configurations, not dynamic per-message tokens. **libp2p Circuit Relay v2** comes closest to the desired model: it features an `ACLFilter` interface for per-peer authorization, explicit resource reservation with signed vouchers, per-connection data caps (default 128KB), and a `MetricsTracer` for relay accounting. However, it lacks capability-token semantics — its ACL is binary allow/deny by peer ID, vouchers don't encode fine-grained permissions, and it's designed for NAT traversal bootstrapping, not sustained high-throughput relay. **Tor** is architecturally antithetical: anonymity requires that no relay knows both source and destination, precluding capability enforcement entirely.

The gap is clear: no production system or recent academic paper at SIGCOMM, NSDI, or CoNEXT (2023–2026) proposes a relay architecture where the intermediary actively validates capability tokens on every forwarded message, meters usage against token constraints, and attenuates tokens during delegation — all while supporting thousands of concurrent agent-to-agent sessions.

---

## Building blocks from capability networking, macaroons, and SCION

Three strands of prior work provide the theoretical foundation for capability-gated relay. The first is **network capabilities** from Anderson, Wetherall, and Roscoe's Traffic Validation Architecture (TVA, IEEE/ACM ToN 2008), which introduced cryptographic tokens that grant "permission to send." TVA demonstrated **~660K packets/sec** forwarding with capability verification on commodity hardware, proving that per-packet authorization is feasible at moderate scale. The second is **SCION's path authorization** (draft-dekater-scion-dataplane-13, April 2026), which embeds MAC-authenticated hop fields directly in packet headers. Each SCION router recalculates a 48-bit AES-CMAC for its hop field and compares it against the packet's MAC — an **O(1) per-hop operation** enabled by an XOR-chained accumulator that avoids recomputing the full chain. This is the gold standard for efficient in-path authorization.

The third and most directly relevant building block is **Macaroons** (Birgisson et al., NDSS 2014). Macaroons are bearer credentials based on nested HMAC chains where anyone holding a token can add caveats (restrictions) to create a derived token with strictly less authority — the **monotonic attenuation invariant**. Verification requires only the root key and is ~1000x faster than public-key operations. Fly.io uses macaroons in production for cloud platform permissions; the Lightning Network uses them for micropayment authorization. Critically, the March 2026 IETF draft on **Attenuating Authorization Tokens (AATs)** for agentic delegation chains (draft-niyikiza-oauth-attenuating-agent-tokens-00) explicitly adapts macaroon-style attenuation to JWT-based tokens for AI agent delegation, with a typed constraint vocabulary and offline verification — directly aligned with QASP's capability-token model.

The convergence of these three approaches — TVA's per-packet capability verification, SCION's efficient per-hop MAC validation, and macaroons' attenuated delegation chains — provides the theoretical substrate for a capability-gated relay. The relay can validate HMAC-based session tokens at each hop with SCION-like efficiency, while supporting macaroon-style attenuation when forwarding messages between agents.

---

## The PQC performance cliff demands a split-plane architecture

The most critical engineering constraint is **post-quantum signature verification throughput**. ML-DSA-65 (FIPS 204, NIST Level 3) produces **3,309-byte signatures** and verification takes **~50–90µs** on modern x86 with AVX2 (wolfSSL benchmarks: 11,544 verify ops/sec; TechRxiv study: ~47.9µs). Even with 16 cores, this yields only **~170–330K verifications/sec** — while a 100Gbps link with 1KB messages generates ~12.5M messages/sec. Per-message PQC verification is **37–73x too slow** for line-rate processing. FPGA IP cores for ML-DSA exist (KiviPQC-DSA, Xiphera XIP6220B), but even dedicated hardware cannot close a gap this large for per-message verification.

This constraint forces a **tiered verification architecture** that amortizes PQC costs:

- **Tier 1 — eBPF/XDP fast path (~100ns):** Hash-table lookup of pre-validated HMAC session tokens in eBPF maps. XDP achieves **24–26 Mpps/core** for simple lookups. Cilium proves this model works: it caches authenticated identities in eBPF maps and drops unauthenticated packets in the kernel, performing expensive mTLS handshakes out-of-band in userspace. Rate limiting and metering counters live in eBPF maps, updated atomically per packet.

- **Tier 2 — DPDK stateful processing (~1–10µs):** New sessions, token parsing, and HMAC derivation. The FAJITA framework (CoNEXT 2024, KTH) achieves **178M 64-byte packets/sec with 16 cores** using optimized batching, software prefetching, and Cuckoo hash tables for per-flow state. This tier handles capability token deserialization, constraint checking (time-to-live, message quotas, byte budgets), and derives the fast-path HMAC token from the verified capability chain.

- **Tier 3 — Userspace PQC verification (~50–90µs):** Full ML-DSA-65 signature verification for initial capability token presentation. Results are cached as HMAC-based session tokens pushed to Tier 1. At **~21K verifications/sec/core × 16 cores = ~330K new sessions/sec** — more than sufficient for thousands of concurrent agent sessions.

This tiered design reduces effective per-message verification cost by **500–1000x** compared to naive per-message PQC verification, while preserving the security guarantee that every capability token is cryptographically validated before any messages are relayed.

---

## MLS and OHTTP prove active intermediary enforcement works

The MLS Delivery Service (RFC 9420, July 2023; architecture RFC 9750, April 2025) is the closest existing model to a capability-enforcing active relay in a standardized protocol. The DS ensures **in-order delivery** of MLS messages (critical for group state synchronization), stores and distributes KeyPackages for asynchronous joining, and — crucially — Section 16.11 of RFC 9420 explicitly defines **"Additional Policy Enforcement"**: the DS can reject invalid commits, enforce access control policies, and rate-limit operations on handshake messages. Application messages remain encrypted (PrivateMessage), but handshake messages can be sent as PublicMessage so the DS can inspect and enforce group structure policies. This demonstrates that an active intermediary can enforce rich policies on group operations while being cryptographically excluded from reading message content.

**OHTTP** (RFC 9458, January 2024) demonstrates a complementary pattern: relay-mediated communication with **blind signature tokens** for anonymous-yet-authenticated access. Apple's Private Relay uses RSA blind signatures to create daily-rotating anonymous tokens that prove device/account validity without identifying the user. The relay verifies the token, enforces rate limits, and forwards — but cannot link requests to specific users. This mechanism maps directly to capability tokens: a relay verifies the token's validity and constraints without needing to know the full identity of the presenting agent.

**Matrix**'s homeserver adds another relevant model: power-level-based authorization on a **DAG of events**. Each event is checked against room authorization rules; events failing current-state auth are "soft-failed" — accepted into the DAG for consistency but not relayed to clients. The homeserver actively validates, filters, and orders events while being cryptographically excluded from E2EE content via Olm/Megolm (now migrating to MLS). These three systems — MLS, OHTTP, and Matrix — collectively prove that active intermediary enforcement with encrypted content, policy validation, metering, and ordering is both theoretically sound and deployable at scale.

---

## Economic routing and Lightning Network parallels illuminate metering design

Lightning Network's **Hash Time-Locked Contracts (HTLCs)** function as capability-like constructs with embedded economic incentives. Each HTLC encodes conditional authority — time-bounded, hash-locked, chained across intermediaries — with atomicity guarantees: payment either completes across all hops or fails entirely. Intermediary nodes charge a **two-part fee** (base fee + proportional rate in parts-per-million), creating a competitive marketplace for routing services. Spider (NSDI 2020, Sivaraman et al.) demonstrated rate-controlled multi-path routing that maintains network balance, routing **95%+ transactions with 25% of the capacity** required by standard LND.

The parallel to QASP metering is direct: capability tokens encode conditional authority (message quotas, byte budgets, time-to-live) that must be enforced at each relay hop, with metering accounting that credits/debits token budgets atomically. The Tor micropayment proposal (IACR ePrint 2014/1011) provides an even closer model: proof-of-work shares serve as anonymous micropayments for relay services, with a **Hierarchical Token Bucket** algorithm dividing bandwidth between paid and free service classes. This mechanism — tickets that purchase priority relay bandwidth, metered via token buckets — maps directly onto QASP's capability tokens with metering constraints.

Filecoin's proof-and-slashing model suggests a verification mechanism for honest relay behavior: storage providers must submit daily cryptographic proofs of continued storage, with collateral slashed for failures. An analogous mechanism could require relay nodes to produce **hash-chain receipts** proving they faithfully forwarded messages, enabling agents to verify the relay's metering claims without trusting it.

---

## What wins at SIGCOMM and NSDI

Analysis of best papers from 2023–2026 reveals consistent patterns. **Systems novelty combined with real-world deployment** earns the highest recognition: NAssim (SIGCOMM 2022) deployed at Huawei, DOTE (NSDI 2023) and Autothrottle (NSDI 2024) deployed at Microsoft, B4 (Test of Time 2023) at Google. **Programmable dataplane work** is a dominant theme: ActiveRMT won SIGCOMM 2023 Best Paper for dynamic resource management on programmable switches; P4 received the 2024 Test of Time award (3,000+ citations); the CoNEXT 2023 Best Paper demonstrated millions of low-latency insertions on ASIC switches.

**Formal methods and verification** are growing rapidly: Network Decision Diagrams won NSDI 2025 Outstanding Paper; Expresso received SIGCOMM 2024 Honorable Mention for symbolic simulation of external routes; Bedrock won NSDI 2024 for BFT protocol analysis platforms. **Rigorous evaluation** is non-negotiable: real traces, production deployments, or large-scale experiments. NSDI explicitly awards a Community Award for open code/data. Acceptance rates are severe — NSDI 2025 accepted 83/666 submissions (**12.5%**).

For a QASP relay architecture paper, the winning formula would combine: (1) a novel system architecture with formal security properties, (2) a programmable dataplane implementation demonstrating per-message capability enforcement, (3) evaluation at scale with thousands of concurrent sessions and real cryptographic operations, and (4) comparison against TURN, MQTT, NATS, and libp2p relay baselines.

---

## Three novel architecture proposals

### Proposal 1: CapFlow — Split-plane capability-gated relay with HMAC fast-path

**Core novelty:** A relay architecture that formalizes "capability-gated forwarding" as a first-class dataplane abstraction, combining SCION-style per-hop MAC verification with macaroon-style token attenuation, implemented on a three-tier programmable dataplane.

**Architecture:** When Agent A wants to communicate with Agent B, it presents its QASP capability token (ML-DSA-65 signed, containing delegation chain, constraints, and metering budget) to the relay via a session establishment handshake. The relay's **Tier 3 (userspace)** verifies the full PQC signature chain (~50–90µs), validates all capability constraints, and derives a 256-bit **Session Capability MAC (SCM)** using HMAC-SHA256 over the session ID, capability hash, and a server-side rotating key. This SCM is pushed to the **Tier 1 eBPF/XDP fast path** as a hash-table entry alongside metering state (remaining message count, byte budget, expiration timestamp). Subsequent messages from Agent A carry the SCM in a fixed-offset header field. The XDP program verifies the SCM via hash-table lookup (~100ns), decrements metering counters atomically, and forwards to Agent B's connection — or drops if the budget is exhausted.

**Active participation:** When the relay forwards a message from A to B, it performs **token attenuation** in the Tier 2 DPDK layer: it creates a derived capability token for B that includes only the permissions B should see (e.g., reply-only, reduced quota), using macaroon-style HMAC chaining to add caveats. B receives a token it can verify (proving A's authorization) but cannot escalate. The relay logs every forwarded message to an append-only metering ledger with hash-chain integrity, enabling post-hoc auditing.

**Key metrics (estimated):** Fast-path throughput of **20+ Mpps/core** for token-validated message forwarding; **~330K new sessions/sec** for PQC verification with 16 cores; sub-microsecond added latency on the fast path; support for **100K+ concurrent sessions** via eBPF map capacity. Formal security property: **capability confinement** — no message transits the relay without a valid, non-exhausted capability token, provable via the HMAC binding between session token and capability chain.

**Why it's publishable:** Formalizes a new dataplane abstraction (capability-gated forwarding), provides the first quantitative analysis of PQC verification bottlenecks in relay architectures, demonstrates a practical split-plane solution, and evaluates against TURN/MQTT/NATS/libp2p baselines. Aligns with SIGCOMM's programmable dataplane theme and NSDI's systems-with-evaluation criteria.

### Proposal 2: CapRoute — Capability-addressed agent routing via named capabilities

**Core novelty:** Agents address each other not by IP address or connection identifier but by **capability namespace**, merging NDN's name-based forwarding with capability tokens as routing primitives. This creates a new routing paradigm where capabilities are both authorization credentials and addressing mechanisms.

**Architecture:** The relay maintains three data structures inspired by NDN but redesigned for capability-mediated routing:

- **Capability Forwarding Table (CFT):** Maps capability-service name prefixes (e.g., `/qasp/translate/en-fr`, `/qasp/agents/agent-b/invoke`) to active agent sessions. Populated when agents register their offered capabilities with the relay. Supports longest-prefix matching, enabling hierarchical capability namespaces.

- **Pending Capability Table (PCT):** Tracks outstanding capability-authorized requests, analogous to NDN's PIT. When Agent A sends a request for capability `/qasp/translate/en-fr` with a valid token, the PCT records the pending request. If Agent C sends an identical request with compatible capabilities, the PCT **aggregates** it — only one request is forwarded to the serving agent, and the response is multicast to both requestors. This provides natural load reduction for popular services.

- **Capability Store (CS):** Caches responses from capability-serving agents, keyed by capability name and response hash. Agents with compatible capability tokens can be served from cache without re-invoking the serving agent, with the relay verifying that the requesting agent's token permits access to the cached content class.

**Capability-as-address:** An agent's capability token encodes both what it is authorized to access and how to route to it. The token's capability namespace (`/qasp/agents/agent-b/translate`) simultaneously identifies the destination service, proves authorization, and specifies constraints. The relay's CFT performs longest-prefix matching against registered capabilities, routing the request to the appropriate serving agent. This eliminates the need for separate service discovery — **routing IS capability resolution**.

**Why it's publishable:** This is a genuinely novel paradigm combination. NDN has never been combined with capability tokens for agent-to-agent communication. The PCT aggregation and CS caching mechanisms create efficiency properties absent from conventional relay architectures. The formal contribution would define the capability-addressed routing algebra and prove properties like capability confinement, routing correctness, and aggregation safety. The ICN community (ACM ICN conference) and SIGCOMM would find this compelling as a new application of information-centric principles to the emerging agent communication domain.

### Proposal 3: CapProof — Verifiably metered relay with atomic capability accounting

**Core novelty:** Drawing from Lightning Network's HTLC atomicity and Filecoin's proof-based verification, this architecture provides **cryptographic guarantees of honest metering** — agents can verify that the relay's accounting claims are accurate without trusting it, solving the "honest intermediary" problem that plagues all existing relay designs.

**Architecture:** Capability tokens in CapProof encode a **metering commitment**: a hash-chain seed from which the relay derives per-message receipts. When the relay forwards message *i* from Agent A to Agent B, it computes receipt *r_i = H(r_{i-1} || msg_hash_i || timestamp_i)* and returns it to A. Agent A can verify receipt integrity by checking the hash chain. Agent B receives a corresponding **delivery proof** *d_i = H(r_i || B_id)* that it can present to the relay (or a third-party auditor) to confirm delivery.

**Atomic capability consumption:** Inspired by HTLCs, capability budget consumption is **conditional on delivery confirmation**. Agent A's token budget is decremented only when Agent B's delivery acknowledgment arrives at the relay within a timeout window. If B doesn't acknowledge (timeout, disconnect, or rejection), A's budget is restored. This prevents the relay from falsely claiming to have relayed messages to inflate metering. The relay must produce a valid hash-chain receipt for every claimed relay operation.

**Verifiable metering ledger:** The relay maintains a **Merkle-tree-based metering ledger** where each agent's usage is a leaf. Agents can request a Merkle proof of their current usage, enabling them to verify their metering state against the relay's claims. Periodic checkpoints are signed with the relay's ML-DSA-65 key and published, creating an auditable trail. A dishonest relay that over-counts usage would be detectable: the hash-chain receipts held by agents would contradict the Merkle proofs.

**Economic enforcement layer (optional):** Staking and slashing semantics borrowed from Filecoin: relay operators deposit collateral (in a QASP metering escrow), and agents that detect dishonest metering can submit fraud proofs to slash the relay's stake. This creates strong economic incentives for honest behavior without requiring trust in the relay.

**Why it's publishable:** No existing relay architecture provides cryptographic metering verification. The combination of hash-chain receipts, conditional (HTLC-style) budget consumption, and Merkle-tree metering creates a formally verifiable accounting system. The paper would prove three properties: (1) **metering integrity** — the relay cannot over-count usage without detection, (2) **relay liveness** — the relay cannot silently drop messages without detection (delivery proofs), and (3) **atomic accounting** — budget consumption is atomic with successful delivery. This targets NSDI's growing interest in formal methods applied to systems, or SIGCOMM's interest in verifiable network infrastructure.

---

## Conclusion: Combining the proposals into a unified QASP-Relay architecture

The strongest path to a top-venue paper lies in **combining CapFlow's split-plane performance architecture with CapProof's verifiable metering**, creating a system that is both fast enough for thousands of concurrent sessions and provably honest in its accounting. CapRoute's capability-addressed routing could serve as a compelling standalone contribution for a second paper targeting the ICN community.

The critical insight across all three proposals is the same: **the relay's active participation is not a liability but an architectural feature**. Unlike systems that minimize intermediary involvement (Tor, E2E encryption), QASP's relay maximizes it — validating capability tokens, enforcing constraints, metering usage, and attenuating delegations. This "maximally active intermediary" paradigm is unexplored in the networking literature and directly motivated by the emerging agent-to-agent communication domain, where autonomous AI agents require strong authorization guarantees that endpoint-only security cannot provide.

The technical foundation is sound: SCION proves per-hop authorization is efficient, Cilium proves identity-aware kernel-bypass networking scales, MLS proves active intermediary enforcement is compatible with encrypted communication, and Lightning Network proves conditional metered relay with economic incentives works in production. What remains is the synthesis — and that synthesis, properly formalized and evaluated, constitutes a genuine contribution to the networking research community.