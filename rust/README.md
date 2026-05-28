# QASP Rust Implementation

This directory contains the greenfield Rust implementation of QASP. It is
developed separately from the Python reference code and assumes a new
authority deployment: existing Python-issued keys, tokens, sessions, receipts,
and persisted security state are not migrated.

## Current Foundation Slice

| Crate | Responsibility | Status |
| --- | --- | --- |
| `qasp-wire` | Message type registry and binary frame-header envelope | Initial implementation |
| `qasp-authz` | ARM resource URI parsing, matching, attenuation, and intersection | Initial implementation |
| `qasp-protocol` | Connection-state transitions and wire-level protocol errors | Initial implementation |

This slice is intentionally dependency-free so it can be compiled and tested
before selecting security-sensitive serialization and cryptographic libraries.
It does not yet sign, hash, encrypt, or authenticate payloads.

## Contract Decisions Still Required

- Define the canonical CBOR encoding used for new Rust-signed artifacts.
- Define token, DID, revocation, receipt, and handshake artifact versions.
- Decide whether provider wildcards such as `qasp://*/tools/echo` form part of
  the Rust ARM contract. The Python ARM parser does not accept wildcard
  providers even though integration documentation uses this discovery pattern.
- Select and validate the post-quantum cryptography dependency path.

## Running Tests

```bash
cd rust
cargo test --workspace
```

