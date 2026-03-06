# did:qasp DID Method Specification

**Version:** 1.0-draft

**Date:** 2026-03-06

**Status:** Draft

**Authors:** QASP Working Group

## Abstract

The `did:qasp` DID method provides decentralized identifiers for AI agents
operating within the QASP (Quantum-Authenticated Service Protocol) ecosystem.
Identifiers are derived from ML-DSA-65 (FIPS 204) post-quantum digital
signature public keys, providing resistance to both classical and quantum
computational attacks.

This specification conforms to the requirements of the
[W3C Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-core/)
specification.

## Status of This Document

This is a draft specification. It is subject to change without notice.

## Conformance

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
[BCP 14](https://www.rfc-editor.org/info/bcp14)
\[[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119)\]
\[[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)\]
when, and only when, they appear in capitalized form, as shown here.

---

## 1. Introduction

AI agents require persistent, self-sovereign identifiers that can be
verified without centralized authorities and that remain secure against
quantum adversaries. The `did:qasp` method meets these requirements by
binding each DID to an ML-DSA-65 public key through a one-way
cryptographic derivation.

### 1.1 Design Goals

1. **Quantum resistance** -- All cryptographic operations use NIST
   post-quantum standards (ML-DSA-65, FIPS 204).
2. **Self-certifying** -- The DID identifier is deterministically derived
   from the public key, allowing any party to verify the binding.
3. **Key rotation** -- Secure key rotation via a pre-commitment and
   dual-signature proof mechanism that maintains continuity of control.
4. **Delegation** -- Owner-agent bindings enable hierarchical
   authorization with attenuated permissions.
5. **Interoperability** -- JSON-LD DID documents follow W3C DID Core and
   use standard multicodec/multibase encodings.

---

## 2. DID Method Name

The method name for this DID method is `qasp`.

A DID that uses this method MUST begin with the following prefix:
`did:qasp:`. Per the DID specification, this string MUST be in lowercase.
The remainder of the DID, after the prefix, is the method-specific
identifier described below.

---

## 3. Method-Specific Identifier

### 3.1 Syntax

The `did:qasp` method-specific identifier is defined by the following
ABNF grammar:

```abnf
did-qasp        = "did:qasp:" identifier
identifier      = 1*base58btc-char
base58btc-char  = "1" / "2" / "3" / "4" / "5" / "6" / "7" / "8" / "9"
                / "A" / "B" / "C" / "D" / "E" / "F" / "G" / "H" / "J"
                / "K" / "L" / "M" / "N" / "P" / "Q" / "R" / "S" / "T"
                / "U" / "V" / "W" / "X" / "Y" / "Z"
                / "a" / "b" / "c" / "d" / "e" / "f" / "g" / "h" / "i"
                / "j" / "k" / "m" / "n" / "o" / "p" / "q" / "r" / "s"
                / "t" / "u" / "v" / "w" / "x" / "y" / "z"
```

The `identifier` is the Base58btc encoding of the first 32 bytes of the
SHA-384 digest of the ML-DSA-65 public key. Because Base58btc encodes
32 bytes, the identifier is typically 43-44 characters long.

### 3.2 Identifier Derivation

The identifier MUST be computed as follows:

```
identifier = Base58btc( SHA-384( ML-DSA-65-PK )[0:32] )
```

Where:

- `ML-DSA-65-PK` is the raw 1952-byte ML-DSA-65 public key.
- `SHA-384` is applied to the full public key, producing a 48-byte digest.
- The digest is truncated to the first 32 bytes (256 bits).
- `Base58btc` is the Bitcoin variant of Base58 encoding (alphabet excludes
  `0`, `O`, `I`, `l`).

### 3.3 Example

Given an ML-DSA-65 public key (1952 bytes), the resulting DID might be:

```
did:qasp:2ZTp9sZYQnVTQzGK8hA5zUQvZk7DhY4zRvJpPvjnL7bE
```

Implementations MUST reject any DID whose identifier does not decode to
exactly 32 bytes under Base58btc.

---

## 4. DID Document

### 4.1 JSON-LD Contexts

A `did:qasp` DID document MUST include the following `@context` values:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/mldsa-2025/v1"
  ]
}
```

The first context is the W3C DID Core context. The second context defines
the `MLDSAVerificationKey2025` verification method type and related terms.

### 4.2 Document Structure

A conforming DID document MUST contain the following properties:

| Property              | Type               | Required | Description                                            |
|-----------------------|--------------------|----------|--------------------------------------------------------|
| `@context`            | array of strings   | REQUIRED | JSON-LD contexts as specified in Section 4.1.          |
| `id`                  | string             | REQUIRED | The DID string (`did:qasp:<identifier>`).              |
| `verificationMethod`  | array of objects   | REQUIRED | At least one verification method (Section 4.3).        |
| `authentication`      | array of strings   | REQUIRED | Verification method IDs authorized for authentication. |
| `assertionMethod`     | array of strings   | REQUIRED | Verification method IDs authorized for assertions.     |
| `keyVersion`          | integer            | REQUIRED | Monotonically increasing key version (starts at 1).    |
| `service`             | array of objects   | OPTIONAL | Service endpoint descriptions.                         |
| `nextKeyHash`         | string (hex)       | OPTIONAL | SHA-384 hash of the next public key (pre-commitment).  |

### 4.3 Verification Method

Each verification method entry MUST have the following structure:

| Property              | Type   | Required | Description                                     |
|-----------------------|--------|----------|-------------------------------------------------|
| `id`                  | string | REQUIRED | `did:qasp:<identifier>#key-<version>`           |
| `type`                | string | REQUIRED | MUST be `"MLDSAVerificationKey2025"`.           |
| `controller`          | string | REQUIRED | The DID string that controls this key.          |
| `publicKeyMultibase`  | string | REQUIRED | Multibase-encoded public key (Section 4.3.1).   |

#### 4.3.1 Public Key Encoding

The `publicKeyMultibase` value MUST be encoded as:

```
"z" + Base58btc( multicodec_prefix + raw_public_key )
```

Where:

- The multibase prefix `z` indicates Base58btc encoding.
- The multicodec prefix for ML-DSA-65 is `0x1318` (two bytes: `0x13`, `0x18`).
- The raw public key is the 1952-byte ML-DSA-65 public key.

Decoders MUST:

1. Verify the multibase prefix is `z`.
2. Base58btc-decode the remaining string.
3. Verify the first two bytes are `0x13`, `0x18`.
4. Verify the remaining bytes have length exactly 1952.

#### 4.3.2 Verification Method ID

The verification method `id` MUST follow the pattern:

```
did:qasp:<identifier>#key-<version>
```

Where `<version>` is a positive integer matching the `keyVersion` of the
DID document at the time the key was active. The initial key version
is 1, yielding an `id` of `did:qasp:<identifier>#key-1`.

### 4.4 Service Endpoints

Service endpoints, when present, MUST follow the W3C DID Core service
endpoint format:

```json
{
  "id": "did:qasp:<identifier>#service-0",
  "type": "<service-type>",
  "serviceEndpoint": "<endpoint-uri>"
}
```

Service endpoints are indexed starting from 0.

### 4.5 Example DID Document

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/mldsa-2025/v1"
  ],
  "id": "did:qasp:2ZTp9sZYQnVTQzGK8hA5zUQvZk7DhY4zRvJpPvjnL7bE",
  "verificationMethod": [
    {
      "id": "did:qasp:2ZTp9sZYQnVTQzGK8hA5zUQvZk7DhY4zRvJpPvjnL7bE#key-1",
      "type": "MLDSAVerificationKey2025",
      "controller": "did:qasp:2ZTp9sZYQnVTQzGK8hA5zUQvZk7DhY4zRvJpPvjnL7bE",
      "publicKeyMultibase": "z4kBx...encoded..."
    }
  ],
  "authentication": [
    "did:qasp:2ZTp9sZYQnVTQzGK8hA5zUQvZk7DhY4zRvJpPvjnL7bE#key-1"
  ],
  "assertionMethod": [
    "did:qasp:2ZTp9sZYQnVTQzGK8hA5zUQvZk7DhY4zRvJpPvjnL7bE#key-1"
  ],
  "keyVersion": 1
}
```

---

## 5. CRUD Operations

### 5.1 Create

To create a `did:qasp` identifier, an implementation MUST perform the
following steps:

1. **Generate an ML-DSA-65 keypair.** The keypair consists of a 1952-byte
   public key and a 4032-byte secret key. The key generation algorithm
   MUST conform to FIPS 204.

2. **Compute the identifier.** Apply SHA-384 to the full public key,
   truncate the digest to 32 bytes, and Base58btc-encode the result:
   ```
   identifier = Base58btc( SHA-384(public_key)[0:32] )
   ```

3. **Construct the DID string.** The DID is `did:qasp:<identifier>`.

4. **Create the DID document.** The document MUST include:
   - A `verificationMethod` entry with the encoded public key
     (Section 4.3).
   - The verification method `id` in both `authentication` and
     `assertionMethod`.
   - `keyVersion` set to `1`.

5. **Register the DID document.** The document MUST be registered in the
   local DID registry. It MAY additionally be published to other
   resolution infrastructure (see Section 5.2).

### 5.2 Read (Resolve)

DID resolution is the process of obtaining the DID document for a given
DID. The `did:qasp` method supports a three-tier resolution strategy.
Implementations MUST support at least the first tier and SHOULD support
the second.

#### 5.2.1 Tier 1: Direct Exchange (QASP-Shake Handshake)

During the QASP-Shake handshake, peers directly exchange their
ML-DSA-65 public keys in the `ClientHello` and `ServerHello` messages.
The receiving party:

1. MUST extract the `sig_public_key` from the handshake message.
2. MUST derive the expected DID identifier from the public key.
3. MUST verify the DID matches the peer's claimed identity (if any).

This tier provides the strongest assurance because the public key is
authenticated through the handshake's signature verification.

#### 5.2.2 Tier 2: QASP-Discover Well-Known Endpoint

An agent MAY publish a PQ-signed capability advertisement at the
well-known HTTP endpoint:

```
GET /.well-known/qasp-agent.json
```

The response is a JSON document containing the agent's DID, service
endpoints, capabilities, and an ML-DSA-65 signature over the
CBOR-encoded payload. Resolvers:

1. MUST verify the advertisement signature against the agent's public key.
2. MUST check the advertisement TTL and reject expired advertisements.
3. SHOULD cache the result for the duration of the TTL.

Additionally, agents MAY register themselves via DNS-SD/mDNS using the
service type `_qasp._tcp.local.` with TXT records containing the agent's
DID and capabilities.

#### 5.2.3 Tier 3: DHT / Verifiable Data Registry (Future)

A future version of this specification MAY define resolution through a
distributed hash table or verifiable data registry. Implementations
SHOULD be designed to accommodate this extension.

#### 5.2.4 Resolution Metadata

A conforming resolver MUST return the following metadata alongside the
DID document:

- `contentType`: `"application/did+ld+json"`
- `created`: Timestamp of document creation (if known).
- `updated`: Timestamp of last key rotation (if applicable).

If a DID cannot be resolved, the resolver MUST return a
`DIDResolutionError` indicating the DID was not found.

### 5.3 Update (Key Rotation)

DID documents are updated through key rotation. The `did:qasp` method
uses a pre-commitment and dual-signature scheme that ensures continuity
of control even if the current key is compromised after pre-commitment.

The DID string itself (`did:qasp:<identifier>`) does NOT change during
key rotation. Only the verification method, authentication references,
and key version are updated.

#### 5.3.1 Pre-Commitment

Before rotation can occur, the controller MUST pre-commit the next key:

1. Generate a new ML-DSA-65 keypair (new public key, new secret key).
2. Compute the pre-commitment hash: `SHA-384(new_public_key)`.
3. Store the full 48-byte hash as the `nextKeyHash` field in the current
   DID document.

The pre-commitment MUST be registered before the rotation proof is
created. This prevents an attacker who compromises the current key from
rotating to a key of their choosing.

#### 5.3.2 Rotation Proof

A key rotation proof is a CBOR-encoded structure signed by both the old
and new keys. The proof MUST contain the following fields:

| Field              | Type   | Description                                      |
|--------------------|--------|--------------------------------------------------|
| `did`              | string | The DID being rotated.                           |
| `new_public_key`   | bytes  | The new ML-DSA-65 public key (1952 bytes).       |
| `old_key_version`  | int    | The version of the current (old) key.            |
| `new_key_version`  | int    | The version of the new key.                      |
| `timestamp`        | int    | Unix timestamp of the rotation.                  |
| `old_key_signature`| bytes  | ML-DSA-65 signature by the old key over payload. |
| `new_key_signature`| bytes  | ML-DSA-65 signature by the new key over payload. |

The signable payload is the CBOR encoding of the map containing `did`,
`new_public_key`, `old_key_version`, `new_key_version`, and `timestamp`
(excluding both signature fields).

#### 5.3.3 Rotation Proof Verification

A verifier MUST perform all of the following checks. If any check fails,
the rotation MUST be rejected.

1. **Pre-commitment check.** The current DID document MUST have a
   non-null `nextKeyHash`. The value `SHA-384(proof.new_public_key)`
   MUST equal `nextKeyHash`.

2. **Version increment check.** `proof.new_key_version` MUST equal
   `document.keyVersion + 1`. The key version MUST be monotonically
   increasing.

3. **Old key signature check.** Reconstruct the CBOR payload from the
   proof fields (excluding signatures). Verify the `old_key_signature`
   against the public key in the current DID document's verification
   method.

4. **New key signature check.** Verify the `new_key_signature` against
   `proof.new_public_key` over the same CBOR payload.

#### 5.3.4 Applying Rotation

After successful verification, the updated DID document MUST:

1. Replace the `verificationMethod` with a new entry containing the new
   public key, with `id` set to `did:qasp:<identifier>#key-<new_version>`.
2. Update `authentication` and `assertionMethod` to reference the new
   verification method `id`.
3. Set `keyVersion` to the new version.
4. Clear `nextKeyHash` to `null`.
5. Update the DID document in the registry.

### 5.4 Deactivate

To deactivate a `did:qasp` identifier, the controller MUST remove the
DID document from all registries in which it is registered.

After deactivation:

- Resolution of the DID MUST return a `DIDResolutionError`.
- The DID identifier SHOULD NOT be reused, even if a new keypair
  produces the same identifier (which is computationally infeasible).

---

## 6. Owner-Agent Binding

The `did:qasp` method defines a binding mechanism that allows a human
owner (identified by their own `did:qasp`) to authorize an AI agent to
act on their behalf with specific, attenuable permissions.

### 6.1 Binding Structure

An owner-agent binding is a CBOR-encoded structure signed with ML-DSA-65.
It MUST contain the following fields:

| Field                  | Type              | Description                                      |
|------------------------|-------------------|--------------------------------------------------|
| `agent_did`            | string            | DID of the authorized agent.                     |
| `owner_did`            | string            | DID of the authorizing owner.                    |
| `permissions`          | array of strings  | Sorted list of granted permissions.              |
| `expiry`               | string (ISO 8601) | Expiry timestamp.                                |
| `created`              | string (ISO 8601) | Creation timestamp.                              |
| `nonce`                | string (hex)      | 16-byte random nonce for uniqueness.             |
| `max_delegation_depth` | integer           | Maximum levels of further delegation allowed.    |
| `parent_binding_hash`  | string (hex)/null | SHA-384 hash of parent binding, or null for root.|
| `signature`            | bytes             | ML-DSA-65 signature over the CBOR-encoded fields.|

The `signature` is computed over the CBOR encoding of all fields except
`signature` itself. For root bindings, the owner signs with their secret
key. For delegated bindings, the delegating agent signs with their secret
key.

### 6.2 Permissions

The following standard permissions are defined:

| Permission                    | Description                                  |
|-------------------------------|----------------------------------------------|
| `resource:request`            | Request resources from other agents.         |
| `resource:delegate`           | Delegate resource access to sub-agents.      |
| `comm:initiate`               | Initiate QASP connections.                   |
| `comm:accept`                 | Accept incoming QASP connections.            |
| `token:issue`                 | Issue resource accounting tokens.            |
| `token:attenuate`             | Attenuate (reduce) token permissions.        |
| `token:revoke`                | Revoke previously issued tokens.             |
| `identity:rotate_key`         | Rotate the agent's DID key.                  |
| `identity:create_sub_agent`   | Create sub-agent identities.                 |
| `*`                           | Full access (grants all permissions).        |

When the `*` permission is present, the binding holder MUST be treated
as having all defined permissions.

### 6.3 Binding Verification

To verify an owner binding, a verifier MUST:

1. Reconstruct the CBOR-encoded payload from all fields except `signature`.
2. Verify the `signature` against the owner's ML-DSA-65 public key
   (obtained by resolving `owner_did`).
3. If checking expiry: verify that the current time is before `expiry`.

### 6.4 Binding Attenuation (Delegation)

An agent that holds a binding with `max_delegation_depth > 0` MAY create
an attenuated binding for another agent. The attenuated binding MUST
satisfy all of the following constraints:

1. **Permission subset.** The granted permissions MUST be a subset of the
   parent binding's permissions. Exception: if the parent holds `*`
   (full access), any specific permissions MAY be delegated.
2. **Shorter validity.** The `expiry` MUST NOT exceed the parent binding's
   `expiry`.
3. **Lower delegation depth.** `max_delegation_depth` MUST equal the
   parent's `max_delegation_depth - 1`.
4. **Parent hash.** `parent_binding_hash` MUST be set to
   `SHA-384(parent_cbor + parent_signature)`.
5. **Original owner.** `owner_did` MUST be set to the same `owner_did`
   as the parent binding (the root owner).

If any constraint is violated, the attenuated binding MUST be rejected.

### 6.5 Binding Chain Verification

A delegation chain is an ordered list of bindings from the root owner
to the leaf agent. To verify a binding chain, a verifier MUST:

1. Verify the root binding (index 0) has no `parent_binding_hash`.
2. Verify the root binding's signature against the root owner's public key.
3. For each subsequent binding at index `i`:
   a. Verify `parent_binding_hash` matches the hash of binding `i-1`.
   b. Verify `max_delegation_depth` equals the parent's depth minus 1.
   c. Verify `permissions` is a subset of the parent's permissions.
   d. Verify `expiry` does not exceed the parent's `expiry`.
   e. Verify the binding is not expired.

---

## 7. DID Registry

### 7.1 In-Memory Registry

The reference implementation provides a thread-safe in-memory DID
registry. The registry uses a `threading.Lock` to serialize access and
stores DID documents in a dictionary keyed by DID string.

The registry MUST support the following operations:

| Operation    | Description                                          |
|--------------|------------------------------------------------------|
| `register`   | Store a DID document, overwriting any existing entry.|
| `lookup`     | Retrieve a DID document by DID, raising `DIDResolutionError` if not found.|
| `remove`     | Remove a DID document, returning whether it existed. |
| `clear`      | Remove all DID documents.                            |
| `__contains__`| Check if a DID is registered.                       |
| `__len__`    | Return the number of registered DIDs.                |

### 7.2 Module-Level Singleton

A module-level singleton registry is provided via `get_registry()`. The
singleton uses double-checked locking to ensure thread-safe lazy
initialization.

Implementations MAY substitute an alternative registry (e.g., backed by
a distributed ledger) provided it exposes the same interface.

---

## 8. Security Considerations

### 8.1 Quantum Resistance

All cryptographic operations in the `did:qasp` method are based on
ML-DSA-65 (FIPS 204), which provides NIST Security Level 3
(approximately 192-bit classical security). This ensures that DID
identifiers, signatures, and key rotation proofs remain secure against
both classical and quantum adversaries.

**Key and signature sizes:**

| Parameter           | Size (bytes) |
|---------------------|-------------|
| ML-DSA-65 public key  | 1952      |
| ML-DSA-65 secret key  | 4032      |
| ML-DSA-65 signature   | 3309 (max)|

### 8.2 Identifier Collision Resistance

The identifier is derived from a 256-bit truncation of SHA-384. An
attacker attempting to find a collision (two distinct public keys
producing the same DID) would need approximately 2^128 operations
(birthday bound), which is computationally infeasible.

An attacker attempting to find a pre-image (a public key matching a
given DID) would need approximately 2^256 operations.

### 8.3 Key Rotation Security

The pre-commitment mechanism (Section 5.3.1) ensures that:

- An attacker who compromises the current key AFTER the pre-commitment
  has been registered cannot rotate to a key of their choosing, because
  the next key hash is already fixed.
- The dual-signature requirement (both old and new keys must sign the
  rotation proof) ensures that the entity controlling the new key is
  the same entity that created the pre-commitment.
- The monotonically increasing version number prevents replay of old
  rotation proofs.

### 8.4 Binding Security

Owner-agent bindings are secured by ML-DSA-65 signatures. The
attenuation constraints (permission subset, shorter validity, lower
delegation depth) are enforced at verification time, preventing
privilege escalation through delegation chains.

The `parent_binding_hash` field cryptographically chains each delegated
binding to its parent, preventing an attacker from transplanting a
binding into a different delegation chain.

### 8.5 Secret Key Handling

Implementations SHOULD make a best-effort attempt to zeroize secret key
material after use. However, in managed-memory languages (e.g., Python),
complete zeroization cannot be guaranteed due to garbage collection and
memory allocation behavior.

Implementations MUST NOT include secret key material in DID documents,
bindings, rotation proofs, or any other transmitted data structure.

### 8.6 Denial of Service

The in-memory DID registry is susceptible to memory exhaustion if an
attacker registers a large number of DID documents. Production
deployments SHOULD implement rate limiting and storage quotas.

---

## 9. Privacy Considerations

### 9.1 Identifier Privacy

The DID identifier is a one-way hash of the public key. Given a DID, it
is computationally infeasible to recover the public key. However, once
the public key is revealed (e.g., during a handshake or in a DID
document), the binding between the DID and the public key becomes
publicly verifiable.

### 9.2 Pairwise DIDs

To limit cross-context correlation, implementations SHOULD support
pairwise DIDs: a fresh ML-DSA-65 keypair is generated for each
relationship, producing a unique DID per peer. This prevents a third
party from linking an agent's interactions across different peers.

### 9.3 Correlation via Public Key Size

ML-DSA-65 public keys (1952 bytes) are distinctive in size. Network
observers who can inspect handshake messages MAY be able to infer that
a `did:qasp` agent is communicating, even without decrypting the
content. Implementations SHOULD use encrypted transport (e.g., TLS) for
the handshake layer to mitigate this.

### 9.4 Binding Metadata

Owner-agent bindings contain metadata (permissions, expiry, delegation
depth) that reveals the authorization structure. Implementations SHOULD
transmit bindings only over authenticated and encrypted channels.

---

## 10. Reference Implementation

The reference implementation is provided in the `qasp` Python package:

| Module                     | Description                              |
|----------------------------|------------------------------------------|
| `qasp.identity.did`        | DID creation, parsing, resolution, and registry. |
| `qasp.identity.rotation`   | Key rotation with pre-commitment and dual-signature proofs. |
| `qasp.identity.binding`    | Owner-agent bindings and delegation chains. |
| `qasp.identity.exceptions` | Exception hierarchy for identity operations. |
| `qasp.crypto.signatures`   | ML-DSA-65 keypair generation, signing, and verification. |
| `qasp.transport.discover`  | QASP-Discover service discovery (well-known endpoint, mDNS). |

### 10.1 Dependencies

- **liboqs** (via `oqs` Python binding) -- ML-DSA-65 signature operations.
- **cryptography** -- Ed25519 and X25519 operations (used in hybrid mode).
- **cbor2** -- CBOR encoding for rotation proofs and bindings.
- **base58** -- Base58btc encoding for DID identifiers and multibase keys.

---

## 11. IANA Considerations

This specification does not require any IANA registrations.

The multicodec prefix `0x1318` for ML-DSA-65 is used per the
[Multicodec table](https://github.com/multiformats/multicodec). If this
prefix is not yet formally registered, implementers SHOULD track the
multicodec registry and update accordingly.

---

## 12. References

### 12.1 Normative References

- **[DID-CORE]** W3C. "Decentralized Identifiers (DIDs) v1.0."
  W3C Recommendation, 19 July 2022.
  https://www.w3.org/TR/did-core/

- **[RFC 2119]** Bradner, S. "Key words for use in RFCs to Indicate
  Requirement Levels." BCP 14, RFC 2119, March 1997.
  https://www.rfc-editor.org/rfc/rfc2119

- **[RFC 8174]** Leiba, B. "Ambiguity of Uppercase vs Lowercase in
  RFC 2119 Key Words." BCP 14, RFC 8174, May 2017.
  https://www.rfc-editor.org/rfc/rfc8174

- **[FIPS 204]** NIST. "Module-Lattice-Based Digital Signature Standard."
  FIPS 204, August 2024.
  https://csrc.nist.gov/pubs/fips/204/final

- **[MULTIBASE]** Sporny, M., Mathieu, D. "The Multibase Data Format."
  https://datatracker.ietf.org/doc/html/draft-multiformats-multibase

- **[MULTICODEC]** Protocol Labs. "Multicodec table."
  https://github.com/multiformats/multicodec

### 12.2 Informative References

- **[BASE58]** Nakamoto, S. "Base58Check encoding." Bitcoin Wiki.
  https://en.bitcoin.it/wiki/Base58Check_encoding

- **[CBOR]** Bormann, C. and Hoffman, P. "Concise Binary Object
  Representation (CBOR)." RFC 8949, December 2020.
  https://www.rfc-editor.org/rfc/rfc8949

---

## Appendix A: Verification Method Type Definition

The `MLDSAVerificationKey2025` verification method type represents an
ML-DSA-65 public key encoded using multibase with a multicodec prefix.

```json
{
  "@context": {
    "MLDSAVerificationKey2025": "https://w3id.org/security/suites/mldsa-2025/v1#MLDSAVerificationKey2025",
    "publicKeyMultibase": "https://w3id.org/security/suites/mldsa-2025/v1#publicKeyMultibase"
  }
}
```

## Appendix B: Complete Rotation Example

The following illustrates a full key rotation sequence:

1. **Initial state.** Agent holds `did:qasp:abc...` with `keyVersion: 1`.

2. **Pre-commit.** Agent generates a new ML-DSA-65 keypair and stores
   `SHA-384(new_public_key)` as `nextKeyHash` in their DID document.

3. **Create proof.** Agent constructs the CBOR payload:
   ```cbor
   {
     "did": "did:qasp:abc...",
     "new_public_key": h'<1952 bytes>',
     "old_key_version": 1,
     "new_key_version": 2,
     "timestamp": 1709683200
   }
   ```
   Agent signs this payload with the old key (`old_key_signature`) and
   the new key (`new_key_signature`).

4. **Verify and apply.** Verifier checks pre-commitment, version
   increment, and both signatures. On success, the DID document is
   updated with the new key at `#key-2` and `keyVersion: 2`.

## Appendix C: DID URL Dereferencing

The `did:qasp` method supports DID URL fragment dereferencing to select
specific verification methods:

```
did:qasp:2ZTp9sZYQnVTQzGK8hA5zUQvZk7DhY4zRvJpPvjnL7bE#key-1
```

The fragment `#key-<version>` identifies a specific verification method
within the DID document. Implementations MUST match the fragment against
the `id` property of entries in the `verificationMethod` array.

If no fragment is provided, resolution MUST return the full DID document.
If a fragment is provided but no matching verification method exists,
resolution MUST return a `DIDResolutionError`.
