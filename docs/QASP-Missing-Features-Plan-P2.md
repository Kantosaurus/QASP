# QASP: Missing & Underspecified Features Plan
## All features assigned to P2 — with purpose, usage, and implementation guidance

---

# Overview

This document covers 13 features that are specified in the QASP paper but are either absent from or underspecified in the 6-week build plan. Each feature includes: what it is, why it matters, how it should be used in practice, where it slots into the existing plan, estimated effort, dependencies on other team members, and implementation guidance.

Features are ordered by implementation dependency (build earlier features first, as later features depend on them).

---

# Feature 1: Signature Aggregation for Deep Chains

## What it is

A sequential aggregation construction where each delegator in a delegation chain signs the concatenation of the previous aggregate signature and the new token, yielding a single final signature that implicitly covers every link in the chain. Verification cost drops from O(d) full ML-DSA-65 signature verifications to O(1) signature checks plus O(d) hash computations, where d is the chain depth.

## Why it matters

Without signature aggregation, a delegation chain of depth 5 requires 5 separate ML-DSA-65 verifications. Each ML-DSA-65 verification takes ~0.8ms and the signature is 3,309 bytes. At depth 10, that is 8ms of verification time and 33KB of signatures per token presentation. This is the difference between delegation chains being practical and being a performance bottleneck. Every demo scenario involving delegation (Scenarios 2, 3, and 4) will be visibly slower without this.

## How it should be used

When Agent Alpha delegates to Agent Beta, Alpha does not simply sign its attenuated token independently. Instead:

1. Alpha takes its own token T₀ (which includes the owner's original signature σ₀)
2. Alpha computes the aggregate: `agg₁ = Sign(Alpha_sk, H(σ₀ ∥ T₁))` where T₁ is the attenuated token for Beta
3. The delegation link stores `agg₁` instead of a standalone signature
4. When Beta further delegates to Gamma: `agg₂ = Sign(Beta_sk, H(agg₁ ∥ T₂))`
5. The server receiving T₂ verifies only `agg₂` against the full chain, confirming every link

The verifier reconstructs the hash chain (O(d) hashes) and checks the single final signature (O(1) verification). If any link was tampered with, the hash chain breaks and the final signature is invalid.

**Usage in the protocol**: Every `DelegationGrant` (0x08) message should include the aggregate signature rather than an independent signature. The `delegation-link` CDDL structure's `signature` field carries the aggregate, not a standalone sig. Servers MUST support both aggregate and individual verification (individual as fallback for debugging and for chains of depth 1).

## Where it slots in

**Week 2**, alongside P2's existing capability token engine work. It modifies `protocol/capability.py` — specifically the delegation chain construction and verification functions. Must be in place before Week 5's demo scenarios, which involve chains of depth 2–3.

## Effort estimate

3 days. The cryptographic primitive (ML-DSA-65 sign/verify) already exists from P1's Week 1 work. The complexity is in the sequential hash-then-sign construction and ensuring the verification logic handles both aggregated and non-aggregated chains.

## Dependencies

- P1's ML-DSA-65 wrapper (Week 1) must be complete
- P5 should add property-based tests: for any chain of depth d, aggregate verification must produce the same accept/reject result as individual verification of each link

## Implementation guidance

```python
def aggregate_sign(signer_sk, previous_aggregate: bytes, new_token: bytes) -> bytes:
    """Sequential aggregate: sign H(prev_agg ∥ new_token)."""
    digest = sha384(previous_aggregate + cbor_encode(new_token))
    return ml_dsa_65_sign(signer_sk, digest)

def aggregate_verify(chain: list[DelegationLink], root_token: Token) -> bool:
    """Verify a full chain via sequential aggregate reconstruction."""
    current_agg = root_token.signature  # owner's original signature
    for i, link in enumerate(chain):
        expected_digest = sha384(current_agg + cbor_encode(link.token))
        if i == len(chain) - 1:
            # Final link: verify the aggregate signature
            if not ml_dsa_65_verify(link.delegator_pk, link.signature, expected_digest):
                return False
        else:
            # Intermediate: reconstruct what the next signer should have seen
            current_agg = link.signature
    return True
```

---

# Feature 2: Token Aggregation Algebra

## What it is

The ability for an agent to present multiple capability tokens simultaneously to compose permissions for a single request. The aggregation follows a union-with-constraint-intersection algebra:

```
Agg(T₁, T₂) = {
  V = V₁ ∪ V₂                        (verb sets are unioned)
  R = R₁ ∪ R₂                        (resource sets are unioned)
  C = C₁ ⊓ C₂ on shared dimensions   (constraints are intersected)
}
```

Unshared constraint dimensions are inherited from the token that defines them. The server verifies each token independently, then computes the aggregation.

## Why it matters

Real-world agent workflows often require permissions from multiple independent authorities. An agent might hold a token from its owner granting GPU access and a separate token from a data provider granting dataset access. Without aggregation, the agent must make two separate requests. With aggregation, it presents both tokens and the server computes the effective permission set — enabling single-request workflows that span multiple authorization sources.

This is also the foundation for multi-owner tokens (Feature 7). If you cannot aggregate constraint sets from multiple tokens, you cannot compute the intersection of multiple authority chains.

## How it should be used

**Scenario**: Agent Alpha needs to run a training job that reads from a dataset AND uses GPU compute. It holds:
- Token A from the compute provider: `exec` on `qasp://acme/gpu/a100`, spend ≤ $5, valid 2 hours
- Token B from the data provider: `read` on `qasp://data-co/dataset/training`, quantity ≤ 10GB, valid 4 hours

Alpha presents both tokens in its `ResourceRequest`. The server computes:
- Verbs: {exec} ∪ {read} = {exec, read}
- Resources: {qasp://acme/gpu/a100} ∪ {qasp://data-co/dataset/training}
- Time constraint: intersection of [now, now+2h] and [now, now+4h] = [now, now+2h] (tighter window wins)
- Spend: $5 (only Token A defines spend)
- Quantity: 10GB (only Token B defines quantity)

The server grants a session with the aggregated permissions. Each token is verified independently (valid signature, not expired, not revoked), then the aggregation is computed.

**Usage in the protocol**: The `ResourceRequest` (0x01) message's payload should accept an array of token IDs/tokens, not just a single one. The server's authorization check becomes: verify each token independently → compute Agg → check that the requested action falls within Agg.

## Where it slots in

**Week 3**, after the basic token create/verify/attenuate is working from Week 2. Modifies `protocol/capability.py` to add an `aggregate_tokens()` function, and modifies the `ResourceRequest` message definition in `framing/messages.py` to accept a token array.

## Effort estimate

2 days. The algebra is straightforward (set union for verbs/resources, component-wise min for constraints). The main work is modifying the server-side authorization check to handle multi-token requests and writing tests for edge cases (conflicting constraints, overlapping resources, one valid + one expired token).

## Dependencies

- Basic token verification (P2, Week 2) must be complete
- The constraint-set comparison functions must support component-wise minimum

## Implementation guidance

```python
def aggregate_tokens(tokens: list[CapabilityToken]) -> AggregatedPermission:
    """Compute the union-with-constraint-intersection of multiple tokens."""
    verbs = set()
    resources = set()
    constraints = {}
    
    for token in tokens:
        verbs |= set(token.verbs)
        resources.add(token.resource)
        for dim, value in token.constraints.items():
            if dim in constraints:
                constraints[dim] = constrain_min(dim, constraints[dim], value)
            else:
                constraints[dim] = value
    
    return AggregatedPermission(verbs=verbs, resources=resources, constraints=constraints)

def constrain_min(dimension: str, a, b):
    """Component-wise minimum (tightest constraint wins)."""
    match dimension:
        case "time":
            return [max(a[0], b[0]), min(a[1], b[1])]  # intersection of windows
        case "quantity" | "spend":
            return min(a, b)
        case "rate":
            return [min(a[0], b[0]), min(a[1], b[1])]
        case "data_scope":
            return intersect_scopes(a, b)  # domain-specific intersection
        case "purpose":
            if a != b:
                raise ConstraintConflictError(f"Conflicting purposes: {a} vs {b}")
            return a
```

---

# Feature 3: Temporal Capability Evolution

## What it is

A schedule embedded in a capability token that automatically reduces permissions over time. The token starts with full permissions and attenuates itself according to a predefined policy — linear decay, step function, or exponential decay.

## Why it matters

Static tokens are binary: either fully valid or expired. Temporal attenuation provides a graduated middle ground. This is critical for:

- **Budget management**: A $10 token that linearly decays over 4 hours prevents an agent from spending the full $10 in the last minute before expiry
- **Risk mitigation**: If an agent is compromised halfway through its token's validity, the damage is limited to whatever budget remains at that point — which is less than the full original allocation
- **"Use it or lose it" patterns**: Organizational budgets that should be consumed steadily, not hoarded and spent in bursts
- **Demo impact**: Visually compelling — "watch the token's power decrease in real-time"

## How it should be used

**Scenario**: Owner Alice gives Agent Alpha a 4-hour token with $4 spend authority and linear decay:

```
temporal_attenuation: {
  schedule: [
    { at: "T+1h", spend_limit: 3.00 },
    { at: "T+2h", spend_limit: 2.00 },
    { at: "T+3h", spend_limit: 1.00 }
  ],
  policy: "linear_decay"
}
```

At T+0, Alpha can spend up to $4. At T+1.5h, the server evaluates the schedule and applies the most restrictive threshold that has been reached — $3.00 (the T+1h threshold). At T+2.5h, the effective limit is $2.00. If Alpha has already spent $1.80 by T+2h, it has only $0.20 remaining ($2.00 ceiling minus $1.80 spent).

**Usage in the protocol**: The `temporal_attenuation` field is part of the `capability-token` CDDL structure. When a server receives a request, it evaluates the current time against the schedule and applies the resulting constraints BEFORE checking the request against the token's permissions. The server MUST use the most restrictive threshold whose `at` time has been reached. If a delegation includes temporal attenuation, the delegate's schedule MUST be at most as permissive as the delegator's at every point in time (monotonic attenuation still holds).

## Where it slots in

**Week 3**, after basic tokens and metering are working. Modifies the token verification path in `protocol/capability.py` to evaluate temporal schedules before constraint checking.

## Effort estimate

1.5 days. The schedule evaluation logic is simple (iterate thresholds, find the latest one that applies). The complexity is in ensuring temporal attenuation interacts correctly with delegation (attenuated temporal schedules must also be monotonically decreasing relative to the parent) and with metering (the server must re-evaluate the schedule at each metering checkpoint).

## Dependencies

- Basic token verification (P2, Week 2)
- Metering system (P1, Week 3) — the server needs to re-evaluate temporal constraints at each MeterReport

## Implementation guidance

```python
@dataclass
class TemporalSchedule:
    thresholds: list[dict]  # [{"at": relative_seconds, "spend_limit": float, ...}]
    policy: str  # "linear_decay", "step", "exponential"

def evaluate_temporal_constraints(
    token: CapabilityToken, current_time: float
) -> ConstraintSet:
    """Apply temporal attenuation to get effective constraints at current_time."""
    if token.temporal_attenuation is None:
        return token.constraints
    
    elapsed = current_time - token.issued_at
    effective = dict(token.constraints)  # start with base constraints
    
    # Apply the most restrictive threshold that has been reached
    for threshold in token.temporal_attenuation.thresholds:
        if elapsed >= threshold["at"]:
            for key, value in threshold.items():
                if key == "at":
                    continue
                if key in effective:
                    effective[key] = min(effective[key], value)
                else:
                    effective[key] = value
    
    return ConstraintSet(**effective)
```

---

# Feature 4: Cross-Domain Delegation

## What it is

The protocol mechanism for delegating capabilities across ownership boundaries — when Agent Alpha (owned by Alice) needs to delegate to Agent Beta (owned by Bob). This requires explicit authorization from both owners because it crosses a trust boundary.

## Why it matters

Single-owner delegation (Alice's agents delegating among themselves) is the simple case. The real world requires multi-party collaboration: Alice's coding agent needs to delegate a testing sub-task to Bob's testing agent, or a procurement agent owned by Company A needs to authorize a shipping agent owned by Company B to access tracking data.

Without explicit cross-domain delegation, there are two bad alternatives: either cross-owner delegation is forbidden (killing multi-party workflows), or it is unrestricted (creating a massive attack surface where any agent can re-delegate to any other agent's agents).

Cross-domain delegation is the controlled middle ground: it is permitted, but both owners must explicitly sign off.

## How it should be used

**Scenario**: Alice's Agent Alpha holds token T_A for GPU compute. Alpha needs Bob's Agent Beta to run a specific sub-computation.

1. Alpha attenuates T_A to T_{A→B} = att(T_A, Δ), scoped to exactly what Beta needs (e.g., 0.5 vCPU-hours, $1.00, purpose="sub-computation")
2. Alice signs a cross-domain endorsement: `Sign(Alice_sk, ⟨T_{A→B}, Bob's DID⟩)` — this is Alice explicitly saying "I authorize a foreign-owner agent to exercise this subset of my capabilities"
3. The endorsement and attenuated token are sent to Beta via `DelegationRequest` (0x07)
4. Bob countersigns: `Sign(Bob_sk, ⟨T_{A→B}, acceptance⟩)` — Bob is accepting accountability for Beta's actions under this token
5. Beta now holds a cross-domain token with the full chain: Alice → Alpha → Beta, with both owner signatures covering the boundary

**Usage in the protocol**: The `DelegationRequest` (0x07) message must include a `cross_domain` flag when the delegation crosses ownership boundaries. The message payload includes the attenuated token, the delegator's owner's endorsement signature, and a field for the delegatee's owner DID. The `DelegationGrant` (0x08) response includes the delegatee's owner's countersignature.

The server receiving a cross-domain token verifies:
1. The original token chain (Alice → Alpha) is valid
2. The attenuation from Alpha to Beta is monotonically decreasing
3. Alice's cross-domain endorsement signature is valid over ⟨T_{A→B}, Bob's DID⟩
4. Bob's countersignature is valid over ⟨T_{A→B}, acceptance⟩

If any of the four checks fail, the token is rejected.

## Where it slots in

**Week 4**, alongside the A2A/MCP bridge work. Cross-domain delegation is the primary mechanism that makes inter-organization agent collaboration work — it is directly relevant to bridge scenarios where agents from different ecosystems interact.

## Effort estimate

2.5 days. The token structure needs extension (cross-domain endorsement field, countersignature field). The delegation flow needs a new sub-protocol step (endorsement request to owner, countersignature exchange). The verification logic needs the four-check chain above.

## Dependencies

- Basic delegation chains (P2, Week 2) must be complete
- Signature aggregation (Feature 1) should be in place, as cross-domain chains will often be deeper
- P3's DID system (Week 1) for resolving the foreign owner's DID and public key

## Implementation guidance

```python
@dataclass
class CrossDomainDelegation:
    attenuated_token: CapabilityToken       # T_{A→B}
    delegator_owner_did: str                # Alice's DID
    delegatee_owner_did: str                # Bob's DID
    owner_endorsement: bytes                # Alice signs ⟨T_{A→B}, Bob's DID⟩
    owner_countersignature: bytes | None    # Bob signs ⟨T_{A→B}, acceptance⟩

def verify_cross_domain(delegation: CrossDomainDelegation, chain: list) -> bool:
    # 1. Verify the base delegation chain
    if not verify_delegation_chain(chain):
        return False
    
    # 2. Verify attenuation is monotonically decreasing
    if not verify_attenuation(chain[-1].token, delegation.attenuated_token):
        return False
    
    # 3. Verify owner endorsement
    endorsement_payload = cbor_encode({
        "token": delegation.attenuated_token.token_id,
        "delegatee_owner": delegation.delegatee_owner_did
    })
    owner_pk = resolve_did(delegation.delegator_owner_did).public_key
    if not ml_dsa_65_verify(owner_pk, delegation.owner_endorsement, endorsement_payload):
        return False
    
    # 4. Verify countersignature
    acceptance_payload = cbor_encode({
        "token": delegation.attenuated_token.token_id,
        "accepted": True
    })
    delegatee_owner_pk = resolve_did(delegation.delegatee_owner_did).public_key
    if not ml_dsa_65_verify(delegatee_owner_pk, delegation.owner_countersignature, acceptance_payload):
        return False
    
    return True
```

---

# Feature 5: Non-Repudiation with Privacy (Argument Hashing + Auditor-Only Encryption)

## What it is

Two mechanisms that allow metering receipts and trace entries to provide non-repudiation (neither party can deny what happened) while preserving privacy of sensitive data (tool arguments, prompts, query content):

1. **Argument hashing**: Trace entries include `H(args)` instead of raw arguments. The hash proves the arguments existed and were specific, but doesn't reveal them.
2. **Auditor-only encryption**: Sensitive argument fields are encrypted to the Auditor's ML-KEM-768 public key at trace time. Neither server nor agent can read each other's private arguments post-hoc, but the Auditor can decrypt them if a dispute arises.

## Why it matters

QASP's metering system creates a detailed audit trail of every agent action. But agent actions often involve sensitive data — medical queries, proprietary code, financial information, personal data subject to GDPR. Without privacy mechanisms, the audit trail becomes a liability: anyone who obtains the receipt chain (through a data breach, legal discovery, or a compromised auditor) gains access to every argument of every tool call.

This is not theoretical. The OpenClaw security analysis by CrowdStrike specifically flagged that agent interactions involving sensitive systems create significant data exposure risks. QASP's privacy layer ensures accountability without unnecessary data exposure.

## How it should be used

**Scenario**: Agent Alpha calls a medical API with query arguments containing patient data. The server creates a trace entry:

```
TraceEntry = {
  token_id:    "019abc...",
  action:      "exec",
  resource:    "qasp://medical-api/diagnosis/lookup",
  timestamp:   1740150000,
  args_hash:   SHA-384("patient_id=P12345&symptoms=headache,fever"),
  args_encrypted: ML-KEM-768-Encrypt(Auditor_PK, "patient_id=P12345&symptoms=headache,fever"),
  result_hash: SHA-384(result),
  signature:   <server ML-DSA-65 sig>
}
```

During normal operation, only the hashes are visible. The server cannot read the agent's original query (it only sees the hash). The agent cannot deny making the query (the hash is signed by the server and counter-signed by the agent in the receipt).

If a dispute arises (e.g., the agent claims it never queried patient P12345, but the server billed for it), the Auditor decapsulates the `args_encrypted` field using its private key, recovers the original arguments, and can definitively resolve the dispute.

**Usage in the protocol**: Modify the `Receipt` structure to include `args_hash` and `args_encrypted` fields. Modify the `MeterReport`/`MeterAck` exchange to include trace entries with hashed arguments. The Auditor's ML-KEM-768 public key is agreed upon during session setup (either embedded in the capability token or negotiated during QASP-Shake).

## Where it slots in

**Week 3**, alongside P1's metering implementation. The argument hashing is a small modification to the receipt structure. The auditor-only encryption requires P1's ML-KEM-768 wrapper and an agreed-upon Auditor public key.

## Effort estimate

2 days. Argument hashing is trivial (SHA-384 of CBOR-encoded args). Auditor-only encryption requires integrating ML-KEM-768 encapsulation into the trace entry creation, and ML-KEM-768 decapsulation into the dispute resolution flow. The main work is defining how the Auditor's public key is distributed and agreed upon.

## Dependencies

- P1's ML-KEM-768 wrapper (Week 1)
- P1's metering implementation (Week 3) — must coordinate on receipt structure
- P2's dispute protocol (Week 4) — the Auditor decryption step must be integrated

## Implementation guidance

```python
def create_private_trace_entry(
    action: str, resource: str, arguments: bytes,
    auditor_pk: bytes, server_sk: bytes
) -> TraceEntry:
    """Create a trace entry with hashed args and auditor-only encryption."""
    args_hash = sha384(arguments)
    
    # Encrypt arguments to the Auditor's public key
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        ciphertext, shared_secret = kem.encap_secret(auditor_pk)
    # Use shared_secret as AES-256-GCM key to encrypt arguments
    encrypted_args = aes_256_gcm_encrypt(shared_secret, arguments)
    auditor_envelope = cbor_encode({"kem_ct": ciphertext, "encrypted": encrypted_args})
    
    entry = TraceEntry(
        action=action, resource=resource,
        args_hash=args_hash, args_encrypted=auditor_envelope,
        timestamp=int(time.time())
    )
    entry.signature = ml_dsa_65_sign(server_sk, cbor_encode(entry))
    return entry
```

---

# Feature 6: QASP-OCSP (Online Certificate Status Protocol)

## What it is

A real-time, on-demand certificate/token revocation check. The server sends a token ID to the issuer's OCSP responder and receives an ML-DSA-65-signed response of "good", "revoked", or "unknown". The response includes a `nextUpdate` timestamp for stapling — the server caches the response and presents it to agents as proof of current status.

## Why it matters

The existing plan includes QASP-CRL (Certificate Revocation List), which is polled periodically (default: every 5 minutes). CRL has a fundamental latency problem: if a token is revoked at T+0 and the CRL refresh interval is 5 minutes, there is up to a 5-minute window where the revoked token is still accepted.

For critical revocations (key compromise, rogue agent detected), 5 minutes is too long. OCSP provides real-time status checks with sub-second latency. Additionally, OCSP stapling reduces the number of round-trips — the server fetches the OCSP response once, caches it, and presents it to agents, so agents don't need to independently contact the OCSP responder.

## How it should be used

**Scenario 1 — Server-side check**: Server Beta receives a capability token from Agent Alpha. Before executing the requested action, Beta sends the token ID to the issuer's OCSP endpoint:

```
OCSP Request:  { token_id: "019abc...", nonce: <random> }
OCSP Response: {
  status: "good",
  token_id: "019abc...",
  this_update: 1740150000,
  next_update: 1740150300,  // valid for 5 minutes
  responder_id: "did:qasp:z6Mk_issuer...",
  nonce: <echoed>,
  signature: <ML-DSA-65 over all fields>
}
```

Beta caches this response for 5 minutes (until `next_update`). During this window, it does not need to re-check.

**Scenario 2 — OCSP stapling**: When Agent Gamma presents a delegation chain to Server Beta, Beta includes its cached OCSP response for each token in the chain. Gamma can verify the chain's revocation status without contacting the OCSP responder itself. This is analogous to TLS OCSP stapling.

**Usage in the protocol**: Implement as a new endpoint on the trust registry / identity service. Servers SHOULD check OCSP for critical operations (high-value tokens, cross-domain delegations). Servers MAY fall back to CRL if the OCSP responder is unreachable. The `CapabilityQuery` (0x0B) response should include the option to request OCSP stapling.

## Where it slots in

**Week 3**, alongside the existing revocation system work. CRL is already planned; OCSP is the real-time complement. Builds on the same revocation data store.

## Effort estimate

2 days. The OCSP request/response is a simple signed CBOR exchange. The caching and stapling logic adds complexity. The main design decision is whether the OCSP responder is a standalone service or integrated into the trust registry.

## Dependencies

- P3's trust registry (Week 2–3) must expose revocation data
- P1's ML-DSA-65 wrapper (Week 1) for response signing
- P4's transport layer (Week 1) for the OCSP endpoint

---

# Feature 7: Full Arbitration Protocol (Reconciliation + Fault Attribution)

## What it is

The complete 7-step dispute resolution flow from Section III-L3 of the paper. The current plan implements only the basic 3-message exchange (DisputeOpen → DisputeEvidence → DisputeVerdict). The full protocol adds: automatic divergence detection, a 60-second reconciliation grace period, automatic resolution for rounding differences, fault attribution with penalties, and enforcement via payment channel state updates.

## Why it matters

The simplified 3-message dispute flow goes straight from "we disagree" to "auditor decides." This skips the most common resolution path: small discrepancies caused by rounding, timing differences, or network delays. Without the reconciliation step, trivial disagreements escalate to full Auditor involvement, wasting time and Auditor resources.

Fault attribution is also critical for long-term system health. If Server Beta's metering is systematically 5% higher than reality, the Auditor should identify this pattern and penalize Beta, not just resolve individual disputes. Without fault attribution, a dishonest server can slightly over-bill every agent and profit from the disputes that never get filed.

## How it should be used

**The full flow**:

**Step 1 — Divergence detection**: Either party detects that the counterparty's signed MeterReport/MeterAck disagrees with its local state by more than a configurable tolerance threshold ε (default: 1% of total cost or 0.01 units, whichever is larger). This is checked automatically at each MeterReport/MeterAck exchange.

**Step 2 — Grace period (60 seconds)**: Both parties exchange their full receipt chains and attempt automatic resolution:
- If chains agree except for the last receipt (timing issue), the higher-sequence receipt wins
- If the difference is within ε (rounding), the average is used
- If chains diverge at more than one point or the difference exceeds ε, automatic resolution fails

**Step 3 — Formal dispute**: If reconciliation fails, the disputing party opens DisputeOpen (0x0D) with:
- Both receipt chains (agent's view and server's view)
- The divergence point (first receipt where chains disagree)
- Replayable trace logs for the disputed window (bounded to k receipts and n trace entries per-token to prevent evidence flooding DoS)

**Step 4 — Evidence submission**: Both parties submit DisputeEvidence (0x0E) with their full receipt chains and replayable traces.

**Step 5 — Auditor analysis**: The Auditor independently replays the trace against the agreed price schedule and token constraints, producing a computed usage figure.

**Step 6 — Binding verdict**: The Auditor issues DisputeVerdict (0x0F) containing:
- The authoritative usage and cost
- A payment adjustment directive (refund or additional charge)
- A fault attribution: if one party's metering is systematically inaccurate, they are flagged. Repeated fault attribution triggers reputation penalties (feeds into the trust scoring Pillar 2).

**Step 7 — Enforcement**: The payment channel state is updated to reflect the verdict. If either party refuses, the verdict serves as cryptographic evidence for out-of-band enforcement.

**Usage in the protocol**: The divergence detection should be integrated into the MeterAck handler — every time an agent signs a MeterAck, it compares the server's reported values against its own local tracking. The grace period is initiated by a new `ReconciliationRequest` message (not in the current 20 message types — this is a new addition or a sub-type of DisputeOpen). Fault attribution data is stored in the trust registry and influences Pillar 2 (witness reputation) scores.

## Where it slots in

**Week 4**, replacing the simplified dispute implementation. Builds on P1's metering system (Week 3) and the basic dispute messages already defined.

## Effort estimate

2.5 days. The divergence detection and grace period logic are the main new work. Fault attribution requires a new data structure in the trust registry. The Auditor replay logic is the same as the simplified version, just with more structured input.

## Dependencies

- P1's metering system (Week 3) for receipt chain access
- P3's trust registry (Week 3) for storing fault attribution data
- P1's payment channels (Week 4) for enforcing verdicts

---

# Feature 8: Registry-Based Discovery

## What it is

QASP-Discover's third discovery mode: a directory service that maintains a searchable registry of agent DIDs, capabilities, and endpoints. Unlike mDNS (local network only) and DNS (requires domain ownership), the registry provides structured, queryable, internet-scale discovery.

## Why it matters

mDNS works for LAN demos but not for production internet deployments. DNS-based discovery requires each agent to have a domain and DNS record management — unrealistic for dynamic, short-lived agents. The registry fills the gap: any agent can register itself and be discovered by any other agent, regardless of network topology.

This is also the backbone for the trust scoring system's witness reputation (Pillar 2). To query third-party reports about an agent, you need a central or federated place to submit and retrieve those reports. The registry serves this dual purpose: discovery + reputation data store.

## How it should be used

**Registration**: When an agent bootstraps, it publishes its DID Document, capability advertisement, and initial trust credentials to the registry. The registration is signed with the agent's ML-DSA-65 key:

```
RegistryEntry = {
  agent_did:    "did:qasp:z6Mk...",
  did_document: <full DID Document>,
  capabilities: [CapEntry, ...],
  trust_score:  0.45,
  audit_vcs:    [VC, ...],
  endpoint:     "qasp://agent.example.com:4433",
  timestamp:    1740150000,
  ttl:          3600,
  signature:    <ML-DSA-65>
}
```

**Query**: An agent seeking a specific capability queries the registry:

```
RegistryQuery = {
  capability:    "qasp://*/gpu/*",
  min_trust:     0.5,
  verbs:         ["exec"],
  max_results:   10
}
```

The registry returns matching entries, each signed by the advertising agent. The querying agent then verifies signatures and initiates QASP-Shake to the selected endpoint.

**Usage in the protocol**: The registry is queried via `DiscoverQuery` (0x14) messages sent over a QASP-Shake-protected channel (the registry itself is a QASP server). Responses are `DiscoverAd` (0x13) messages. The registry MUST verify the ML-DSA-65 signature on each registration before accepting it. The registry MUST NOT modify entries — it is a passive directory, not an authority.

## Where it slots in

**Week 3**, alongside P4's existing QASP-Discover work (mDNS and well-known endpoints). The registry is the third and most complex discovery mode.

## Effort estimate

1.5 days. The registry is a REST API backed by an in-memory store (for the reference implementation). The main work is defining the query language (capability matching with wildcards, trust score filtering) and ensuring registry entries are properly signed and verified.

## Dependencies

- P4's transport layer (Week 1) for the registry's QASP-Shake endpoint
- P3's DID system (Week 1) for DID Document validation
- P3's trust scoring (Week 3) for trust score filtering in queries

---

# Feature 9: DID Resolver Network (DHT/VDR)

## What it is

A distributed resolution mechanism for `did:qasp` identifiers that works asynchronously — without requiring the target agent to be online or accessible. DID Documents are published to a distributed hash table (DHT) or Verifiable Data Registry (VDR), enabling any party to resolve a DID to its document at any time.

## Why it matters

The current plan only supports DID resolution via direct exchange (during handshake) and QASP-Discover embedding. Both require the target agent to be reachable at resolution time. But there are important scenarios where offline resolution is needed:

- **Verification of a delegation chain after the delegator has gone offline**: Server receives a token chain where link 2 was signed by an agent that is no longer running. To verify, the server needs that agent's public key from its DID Document.
- **Revocation cascade processing**: When revoking Agent Alpha's credentials, servers need to identify all tokens where Alpha appears — which requires resolving Alpha's DID to get its public key for signature matching.
- **Audit and forensics**: Post-hoc analysis of metering receipts and dispute evidence requires resolving DIDs of agents that may no longer exist.

## How it should be used

**Publishing**: When an agent's DID Document is created or updated, it is published to the DHT/VDR. The entry is signed by the agent's ML-DSA-65 key, ensuring only the key holder can update it:

```
DHTEntry = {
  did:          "did:qasp:z6Mk...",
  did_document: <full DID Document>,
  version:      3,              // monotonically increasing
  timestamp:    1740150000,
  signature:    <ML-DSA-65 over did_document + version + timestamp>
}
```

The version counter prevents replay of old DID Documents. The DHT stores only the highest-version entry for each DID.

**Resolution**: Any party can query the DHT with a DID and receive the latest DID Document. The resolver verifies the signature before returning the document.

**Usage in the protocol**: DID resolution should follow a priority chain: (1) local cache, (2) direct exchange during handshake, (3) QASP-Discover, (4) DHT/VDR. The resolver tries each in order and returns the first valid result. Cache entries expire based on the DID Document's `keyRotation` schedule or a configurable TTL.

For the reference implementation, use a simple key-value store (SQLite or in-memory dict) rather than a full DHT. The interface should be abstract enough that production deployments can swap in IPFS, a Kademlia DHT, or a blockchain-backed VDR.

## Where it slots in

**Week 3**, alongside P3's DID work. This extends the DID resolver to support a persistent store backend.

## Effort estimate

1.5 days for the reference implementation (in-memory/SQLite store with the abstract interface). A full DHT implementation would take weeks and should be deferred to post-v0.1.

## Dependencies

- P3's DID system (Week 1) — the DID Document structure and validation logic
- P4's transport layer — the DHT query endpoint

---

# Feature 10: M-of-N Threshold Delegation

## What it is

A mechanism where a group of N owners collectively issues a capability token that requires M signatures to activate. Uses Shamir secret sharing over the ML-DSA-65 signing key: each owner holds a key share, and M owners produce partial signatures that combine into a single valid ML-DSA-65 signature.

## Why it matters

High-value operations should not be unilaterally authorized by a single person. Examples:

- A $1M compute budget requires 3-of-5 board members to approve
- A cross-department data access token requires sign-off from both the data owner and the compliance officer (2-of-2)
- A government agency's agent requires authorization from multiple oversight bodies

Without threshold delegation, these scenarios require workarounds (multi-owner tokens with sequential signing, or out-of-band approval processes). Threshold delegation makes the M-of-N requirement cryptographically enforced at the token level.

## How it should be used

**Setup phase**: The N owners jointly generate a shared ML-DSA-65 keypair using a distributed key generation (DKG) protocol. Each owner receives a key share sk_i. The combined public key pk is published as the "group" identity.

**Issuance**: When an M-of-N token is needed, M owners each produce a partial signature over the token using their key share. The partial signatures are combined into a single valid ML-DSA-65 signature. The resulting token is indistinguishable from a single-signer token to any verifier.

**Verification**: The server verifies the token using the group's public key pk — exactly the same as verifying any other token. The M-of-N structure is transparent to the verifier.

**Usage in the protocol**: The token's `issuer` field contains the group's DID (derived from the combined public key). The token includes a `threshold` metadata field: `{ "m": 3, "n": 5, "group_did": "did:qasp:z6Mk_group..." }`. This metadata is informational — it tells the verifier that this token was issued by a threshold group, but verification uses the same single-signature check.

## Where it slots in

**Week 5** (stretch goal). This is the most cryptographically complex feature. Shamir secret sharing over ML-DSA-65 is active research — the Bendlin et al. 2024 paper (reference [25] in the QASP paper) describes the construction, but production-quality implementations are scarce.

## Effort estimate

4 days minimum. The Shamir secret sharing arithmetic over the ML-DSA-65 field is non-trivial. If a suitable library exists (check liboqs and lattice-threshold-sig repos), integration is faster. If P2 must implement the threshold construction from scratch, this could easily expand to a week.

**Recommendation**: Implement a simplified version first — M-of-N using independent signatures (each owner signs the token independently, and the token carries M separate signatures that the verifier checks). This achieves the authorization goal without the cryptographic complexity of true threshold signatures. The true threshold construction (single combined signature) can be added in v0.2.

## Dependencies

- P1's ML-DSA-65 wrapper (Week 1)
- Potentially a new dependency on a threshold signature library
- P3's DID system for group DID generation

---

# Feature 11: Selective Disclosure

## What it is

Two mechanisms that allow a token holder to prove specific authorization properties without revealing the full token:

1. **Hash-based commitment (Merkle tree)**: The full token is structured as a Merkle tree. The holder reveals only the branches relevant to the verifier's query (e.g., "prove you have `exec` on this resource" without revealing the spend limit or delegation chain).

2. **Zero-knowledge proof of inclusion**: The holder proves that a specific verb/resource pair is contained within a validly signed token without revealing any other fields.

## Why it matters

Capability tokens contain sensitive information: spending limits reveal budget allocations, delegation chains reveal organizational structure, purpose bindings reveal strategic intent. When presenting a token to a server, the agent currently reveals ALL of this information. Selective disclosure allows the agent to prove "I am authorized" without disclosing "how much I can spend" or "who delegated to me."

This is particularly important for cross-domain delegation (Feature 4) where the delegatee may be a competitor's agent. You want to prove authorization without revealing your internal delegation hierarchy.

## How it should be used

**Scenario — Merkle-based**: Agent Alpha needs to prove to Server Beta that it has `exec` permission on `qasp://beta/gpu/a100`. Alpha's full token also contains a $50 spend limit, a delegation chain from its owner, and a purpose binding of "competitive-analysis" — none of which Alpha wants Beta to see.

1. Alpha's token is Merkle-ized: each field (verbs, resource, constraints, chain, etc.) is a leaf node, and the root hash is what the ML-DSA-65 signature covers.
2. Alpha reveals only the `verbs` and `resource` branches, plus the Merkle path from each leaf to the root.
3. Beta verifies: the revealed leaves hash up to the root, and the root matches the ML-DSA-65 signature. Beta knows the token is valid and authorizes `exec` on the resource, but learns nothing about the hidden fields.

**Usage in the protocol**: The `ResourceRequest` (0x01) message should support a `disclosure_mode` field: "full" (default, entire token revealed) or "selective" (Merkle path + revealed fields only). Servers MAY require full disclosure for high-security operations and SHOULD accept selective disclosure for standard operations.

## Where it slots in

**Week 5** (stretch goal). Merkle-ization of the token is straightforward. The ZK proof of inclusion is research-grade and should be deferred to v0.2.

## Effort estimate

**Merkle-based selective disclosure**: 2 days. Build a Merkle tree over the token fields, modify the token structure to include the Merkle root in the signed portion, and implement reveal/verify functions.

**ZK proof of inclusion**: 2+ weeks. This requires a ZK proving system (e.g., Groth16, PLONK, or a lattice-based ZK-SNARK for PQ compatibility). Defer to post-v0.1.

**Recommendation**: Implement Merkle-based selective disclosure only. It covers 90% of the privacy use cases without the ZK complexity.

## Dependencies

- Basic token structure (P2, Week 2)
- SHA-384 hashing (available from Week 1)

## Implementation guidance

```python
def merkleize_token(token: CapabilityToken) -> MerkleToken:
    """Convert a flat token into a Merkle tree for selective disclosure."""
    fields = {
        "verbs": cbor_encode(token.verbs),
        "resource": cbor_encode(token.resource),
        "constraints": cbor_encode(token.constraints),
        "issuer": cbor_encode(token.issuer),
        "subject": cbor_encode(token.subject),
        "chain": cbor_encode(token.chain),
        "purpose": cbor_encode(token.purpose),
        "temporal": cbor_encode(token.temporal_attenuation),
    }
    leaves = {k: sha384(v) for k, v in fields.items()}
    root, tree = build_merkle_tree(list(leaves.values()))
    return MerkleToken(root=root, tree=tree, fields=fields, leaves=leaves)

def selective_reveal(merkle_token: MerkleToken, reveal_fields: list[str]) -> SelectiveProof:
    """Reveal specific fields with Merkle paths."""
    revealed = {}
    paths = {}
    for field in reveal_fields:
        revealed[field] = merkle_token.fields[field]
        paths[field] = get_merkle_path(merkle_token.tree, merkle_token.leaves[field])
    return SelectiveProof(
        root=merkle_token.root,
        revealed=revealed,
        paths=paths,
        signature=merkle_token.signature  # covers the root
    )
```

---

# Feature 12: SPIFFE/SPIRE Integration

## What it is

Support for including SPIFFE Verifiable Identity Documents (SVIDs) as an authority chain entry in multi-owner tokens. SPIFFE provides workload identity ("this agent is running in namespace X on cluster Y on platform Z"), while QASP provides capability authorization. Together, they answer both "where is this agent running?" and "what is this agent allowed to do?"

## Why it matters

In cloud-native environments, knowing an agent's cryptographic identity is not enough. You also need to know: is this agent running in a trusted environment? Is it on the production cluster or a dev sandbox? Is it running in the expected Kubernetes namespace? SPIFFE/SPIRE provides this platform attestation. Without it, a valid QASP token could be stolen and used from an untrusted environment.

For enterprise deployments, SPIFFE integration is the bridge between QASP's application-layer authorization and the infrastructure's workload identity system.

## How it should be used

**Scenario**: Company X requires that GPU compute tokens can only be used by agents running in the `production` namespace on their verified Kubernetes cluster.

1. The SPIRE agent on the Kubernetes node issues an SVID to the QASP agent: `spiffe://company-x.com/ns/production/agent/alpha`
2. The QASP token includes the SVID as an authority chain entry:

```
authority_chains: [
  { role: "owner",    chain: [T_owner_auth] },
  { role: "platform", chain: [SVID_attestation] },
  { role: "policy",   chain: [T_corp_policy] }
],
composition: "all"
```

3. The server verifies all three chains: owner authorization, platform attestation (SVID is valid and matches expected namespace), and corporate policy compliance.

**Usage in the protocol**: Define a new `authority-entry` type for SPIFFE SVIDs. The SVID is included as a CBOR-encoded X.509 certificate (SVIDs are standard X.509 certs). The verification logic checks the SVID against the SPIRE trust bundle (list of trusted SPIRE servers). This is additive — SPIFFE chain entries are optional and only relevant for enterprise deployments.

## Where it slots in

**Week 5** (stretch goal). Only relevant for enterprise demo scenarios. The integration is straightforward if you treat the SVID as an opaque authority chain entry — the QASP server doesn't need to understand SPIFFE internals, just verify the X.509 certificate against a trust bundle.

## Effort estimate

1.5 days. The SVID is an X.509 cert — verification uses standard certificate validation. The main work is defining the authority chain entry type and the trust bundle configuration.

## Dependencies

- Multi-owner token system (P2, Week 5 via Feature 7 or existing multi-owner implementation)
- A test SPIRE deployment for integration testing (P5 can set up via Docker)

---

# Feature 13: CryptoVerif Computational Model

## What it is

A computational security proof of the QASP-Shake handshake using CryptoVerif, which produces game-based proofs with concrete probability bounds. Unlike ProVerif (symbolic model, proves "no attack exists in the model") and Tamarin (symbolic model, proves state-machine properties), CryptoVerif proves "the probability of a successful attack is bounded by ε" where ε is a concrete, computable number.

Critically, CryptoVerif is post-quantum sound: when cryptographic assumptions hold against quantum adversaries, the proofs hold against quantum adversaries. This is the strongest form of security guarantee available.

## Why it matters

ProVerif and Tamarin are powerful but operate in the symbolic model — they assume cryptographic primitives are perfect black boxes. CryptoVerif works in the computational model, which accounts for the actual security reductions of ML-KEM-768 (Module-LWE) and ML-DSA-65 (Module-SIS). The result is a quantitative bound:

```
Adv^{IND-CCA2}_{QASP-Shake}(A) ≤ Adv^{MLWE}(B₁) + Adv^{CDH}(B₂) + negl(λ)
```

This kind of result is what papers at USENIX Security and ACM CCS publish. For QASP's academic credibility, this is the gold standard.

## How it should be used

Model the QASP-Shake handshake in CryptoVerif's input language (a subset of the applied pi-calculus with probabilistic semantics). The model should include:

1. The ML-KEM-768 encapsulation/decapsulation (modeled as an IND-CCA2-secure KEM under Module-LWE)
2. The X25519 key exchange (modeled as CDH-secure)
3. The HKDF key derivation (modeled as a random oracle)
4. The ML-DSA-65 signature (modeled as EUF-CMA-secure under Module-SIS)
5. The transcript hash and signature binding

Properties to verify:
- Session key secrecy (the key is computationally indistinguishable from random)
- Authentication (injective agreement — if A completes the handshake believing it spoke to B, then B indeed participated)
- Forward secrecy (compromise of long-term keys does not reveal past session keys)

The output is a proof script and a concrete security bound that can be included in the paper and protocol specification.

## Where it slots in

**Week 6**, as a parallel track to P1's ProVerif/Tamarin work. CryptoVerif models are typically written by the same person who wrote the ProVerif model, as the languages are similar. However, CryptoVerif has a steeper learning curve and models are harder to get to converge.

## Effort estimate

5+ days. CryptoVerif models typically require significant iteration to get the tool to produce a complete proof. The PQXDH verification for Signal (Bhargavan et al., USENIX Security 2024) took months of expert effort. For a simplified QASP-Shake model (fewer message types, simpler state), 1–2 weeks is realistic.

**Recommendation**: Treat this as a stretch goal. Start with the ProVerif model (P1, Week 6), and if time permits, port the core handshake to CryptoVerif. Even a partial CryptoVerif model (proving key secrecy only, not full authentication) is publishable.

## Dependencies

- ProVerif model (P1, Week 6) — use as the starting point for the CryptoVerif port
- CryptoVerif installation and familiarity (non-trivial setup)

---

# Implementation Priority Summary

## Must-have for v0.1 (implement within the 6-week plan)

| # | Feature | Week | Effort | Rationale |
|---|---------|------|--------|-----------|
| 1 | Signature aggregation | Week 2 | 3 days | Required for delegation chains deeper than 2-3 to be practical |
| 2 | Token aggregation algebra | Week 3 | 2 days | Foundation for multi-owner tokens and multi-source authorization |
| 3 | Temporal capability evolution | Week 3 | 1.5 days | High demo impact, relatively simple to implement |
| 4 | Cross-domain delegation | Week 4 | 2.5 days | Required for any multi-organization workflow |
| 5 | Non-repudiation with privacy | Week 3 | 2 days | Required for privacy-compliant metering |
| 6 | QASP-OCSP | Week 3 | 2 days | Required for real-time revocation (CRL alone is insufficient) |
| 7 | Full arbitration protocol | Week 4 | 2.5 days | The simplified version skips the most common resolution path |
| 8 | Registry-based discovery | Week 3 | 1.5 days | mDNS is demo-only; registry is production-necessary |

**Total additional effort: ~17 days across Weeks 2–4**

This is tight but feasible for P2 if the existing Week 2–4 tasks are efficiently executed. Some existing tasks may need to be streamlined or parallelized.

## Should-have for v0.1 (implement if time permits)

| # | Feature | Week | Effort | Rationale |
|---|---------|------|--------|-----------|
| 9 | DID resolver network | Week 3 | 1.5 days | Offline DID resolution is needed for revocation cascade processing |
| 11 | Selective disclosure (Merkle only) | Week 5 | 2 days | Privacy-preserving token presentation, strong differentiator |

## Defer to v0.2

| # | Feature | Effort | Rationale |
|---|---------|--------|-----------|
| 10 | M-of-N threshold delegation | 4+ days | True threshold ML-DSA-65 is research-grade; use multi-signature workaround for now |
| 12 | SPIFFE/SPIRE integration | 1.5 days | Enterprise-only; not needed for demo or academic publication |
| 13 | CryptoVerif computational model | 5+ days | Highest-value for publication but highest-risk for timeline |

---

# Updated P2 Weekly Schedule

## Week 2 (existing + Feature 1)

| Day | Task |
|-----|------|
| Mon | Capability token structure, CBOR encoding, ML-DSA-65 signing |
| Tue | Token verification, ARM constraint checking, attenuation |
| Wed | Splitting, basic delegation chains (depth ≤ 3) |
| Thu | **Feature 1**: Signature aggregation — sequential aggregate construction |
| Fri | **Feature 1**: Aggregate verification, fallback to individual verification, tests |

## Week 3 (existing + Features 2, 3, 5, 6, 8)

| Day | Task |
|-----|------|
| Mon | **Feature 2**: Token aggregation algebra — multi-token ResourceRequest, server-side aggregation |
| Tue | **Feature 3**: Temporal capability evolution — schedule evaluation, interaction with metering |
| Wed | **Feature 5**: Non-repudiation with privacy — argument hashing, auditor-only encryption in trace entries |
| Thu | **Feature 6**: QASP-OCSP — responder endpoint, request/response signing, caching + stapling |
| Fri | **Feature 8**: Registry-based discovery — registry API, registration, query with capability matching |

## Week 4 (existing + Features 4, 7)

| Day | Task |
|-----|------|
| Mon | MCP bridge — QASP capability tokens wrapping MCP tools/call |
| Tue | **Feature 4**: Cross-domain delegation — endorsement and countersignature flow |
| Wed | **Feature 4**: Cross-domain verification (4-check chain), integration with bridges |
| Thu | **Feature 7**: Full arbitration — divergence detection, grace period, reconciliation |
| Fri | **Feature 7**: Fault attribution, verdict enforcement, reputation integration |

## Week 5 (if time permits)

| Day | Task |
|-----|------|
| (any) | **Feature 9**: DID resolver network — abstract store interface + SQLite reference |
| (any) | **Feature 11**: Selective disclosure — Merkle-ize tokens, reveal/verify functions |
