# CryptoVerif Computational Proofs for QASP-Shake

## Overview

This directory contains [CryptoVerif](https://cryptoverif.inria.fr/) models that provide **computational security proofs** for the QASP-Shake handshake protocol. Unlike the symbolic ProVerif model (`formal/proverif/qasp_shake.pv`), these proofs operate in the game-based computational model and produce **concrete probability bounds**.

### What is proved

| Property | Query | Model File |
|----------|-------|------------|
| Client session key secrecy | `secret session_key_C` | `qasp_shake.ocv` |
| Server session key secrecy | `secret session_key_S` | `qasp_shake.ocv` |
| Server authentication | `ClientFinished ==> ServerStarted` | `qasp_shake.ocv` |
| Client authentication | `ServerFinished ==> ClientStarted` | `qasp_shake.ocv` |
| Injective server auth | `inj-event ClientFinished ==> inj-event ServerStarted` | `qasp_shake.ocv` |
| Injective client auth | `inj-event ServerFinished ==> inj-event ClientStarted` | `qasp_shake.ocv` |
| Key agreement | `ClientFinished(k1) && ServerFinished(k2) ==> k1=k2` | `qasp_shake.ocv` |
| Forward secrecy (client) | `secret session_key_C public_vars sig_sk_C, sig_sk_S` | `qasp_shake_forward_secrecy.ocv` |
| Forward secrecy (server) | `secret session_key_S public_vars sig_sk_C, sig_sk_S` | `qasp_shake_forward_secrecy.ocv` |

### Trust assumptions

The proofs assume standard cryptographic hardness:

- The hybrid KEM (X25519 + ML-KEM-768) is IND-CCA2 secure
- ML-DSA-65 signatures are EUF-CMA secure
- HKDF-SHA-384 is a secure PRF when keyed with random material
- SHA-384 is collision-resistant

## Prerequisites

- **CryptoVerif 2.x** — Install from https://cryptoverif.inria.fr/
- The `cryptoverif` binary must be in your `PATH`
- GNU Make

## File Organization

```
formal/cryptoverif/
├── README.md                          # This file
├── Makefile                           # Build targets
├── lib/
│   ├── hybrid_kem.ocvl               # IND-CCA2 KEM (X25519 + ML-KEM-768)
│   ├── mldsa65.ocvl                  # EUF-CMA signature (ML-DSA-65)
│   ├── hkdf_sha384.ocvl             # PRF (HKDF-SHA-384)
│   └── collision_resistant_hash.ocvl # CR hash (SHA-384)
├── qasp_shake.ocv                    # Main model: secrecy + authentication
├── qasp_shake_forward_secrecy.ocv    # Forward secrecy under key compromise
└── logs/                             # Proof output (generated)
```

## Cryptographic Assumptions

### IND-CCA2: Hybrid KEM (X25519 + ML-KEM-768)

The hybrid KEM is modeled as a **single combined IND-CCA2 KEM** rather than two separate primitives. The GHP18 hybrid combiner theorem gives a tight reduction:

```
Adv^{IND-CCA2}_{Hybrid} <= Adv^{IND-CCA2}_{X25519} + Adv^{IND-CCA2}_{ML-KEM-768}
```

This matches the approach used in Signal's PQXDH CryptoVerif model. The composition reduction (factor of 2) is handled externally to keep the CryptoVerif model tractable.

### EUF-CMA: ML-DSA-65 (Dilithium)

Standard existential unforgeability under chosen-message attack. The adversary cannot forge a valid signature without knowing the secret key, even after seeing signatures on chosen messages.

### PRF: HKDF-SHA-384

When keyed with uniformly random material (which holds after the IND-CCA2 reduction replaces KEM shared secrets with random), HKDF-SHA-384 output is indistinguishable from random.

### Collision Resistance: SHA-384

Used for transcript binding (session ID derivation). Finding two distinct transcripts with the same hash requires approximately 2^{192} work.

## Protocol Model

The model captures the 3-message QASP-Shake handshake with dual KEM:

```
Client                                          Server
  |                                               |
  |  Generate ephemeral KEM keypair               |
  |--- ClientHello(Nc, kem_pk_C, sig_pk_C, suite) -->|
  |                                               |  Generate ephemeral KEM keypair
  |                                               |  Encapsulate to kem_pk_C -> ct_S, ss_S
  |                                               |  Sign server transcript
  |<-- ServerHello(Ns, ct_S, kem_pk_S, sig_pk_S, suite, sig_S) ---|
  |  Verify server signature                      |
  |  Decapsulate ct_S -> ss_S                     |
  |  Encapsulate to kem_pk_S -> ct_C, ss_C        |
  |  Sign client transcript                        |
  |--- ClientAuth(ct_C, sig_C) ------------------>|
  |                                               |  Verify client signature
  |                                               |  Decapsulate ct_C -> ss_C
  |                                               |
  |  key = HKDF(ss_S||ss_C, Nc||Ns, "QASP-v1")   |  key = HKDF(ss_S||ss_C, Nc||Ns, "QASP-v1")
```

Key design features:
- **Dual KEM**: Both sides encapsulate, providing bidirectional key contribution
- **Ephemeral KEM keys**: Fresh keypair per session enables forward secrecy
- **Transcript signing**: Both parties sign the full handshake transcript for mutual authentication
- **Transcript binding**: Client signs over server's signature, preventing transcript mismatch

## Concrete Security Bounds

For N sessions, the concrete advantage bounds are:

```
Adv_secrecy <= N * Adv^{IND-CCA2}_{HybridKEM}
             + N * Adv^{PRF}_{HKDF}
             + N * Adv^{EUF-CMA}_{ML-DSA-65}

Adv_auth    <= N * Adv^{EUF-CMA}_{ML-DSA-65}

Adv_fs      <= N * Adv^{IND-CCA2}_{HybridKEM}
             + N * Adv^{PRF}_{HKDF}
```

### NIST hardness estimates

| Primitive | Security Level | Best Known Attack |
|-----------|---------------|-------------------|
| X25519 (CDH) | ~128-bit classical | 2^{-128} |
| ML-KEM-768 | NIST Level 3 | 2^{-164} (lattice) |
| ML-DSA-65 | NIST Level 3 | 2^{-164} (lattice) |
| HKDF-SHA-384 | 192-bit | 2^{-192} |

For N = 2^{30} sessions (~1 billion), the total advantage is approximately:

```
Adv_total ~ 2^{30} * 2^{-128} = 2^{-98}
```

This is dominated by the classical X25519 CDH hardness assumption.

## Running the Proofs

```bash
# Run all proofs
cd formal/cryptoverif
make all

# Run only secrecy + authentication
make secrecy

# Run only forward secrecy
make forward_secrecy

# Clean proof logs
make clean
```

### Verifying results

Check the log files for `RESULT ... true` for all queries:

```bash
grep "RESULT" logs/qasp_shake.log
grep "RESULT" logs/qasp_shake_forward_secrecy.log
```

Expected output:
```
RESULT secret session_key_C is true.
RESULT secret session_key_S is true.
RESULT event(ClientFinished(...)) ==> event(ServerStarted(...)) is true.
RESULT event(ServerFinished(...)) ==> event(ClientStarted(...)) is true.
RESULT inj-event(ClientFinished(...)) ==> inj-event(ServerStarted(...)) is true.
RESULT inj-event(ServerFinished(...)) ==> inj-event(ClientStarted(...)) is true.
RESULT event(ClientFinished(...,k1)) && event(ServerFinished(...,k2)) ==> k1 = k2 is true.
RESULT secret session_key_C ... public_vars ... is true.
RESULT secret session_key_S ... public_vars ... is true.
```

## Relation to ProVerif Model

| Aspect | ProVerif (`qasp_shake.pv`) | CryptoVerif (this directory) |
|--------|--------------------------|------------------------------|
| Security model | Symbolic (Dolev-Yao) | Computational (game-based) |
| Attacker | Unbounded symbolic | PPT computational |
| Forward secrecy | Phase-based | `public_vars` |
| Bounds | None (true/false) | Concrete probability |
| KEM model | Equational theory | IND-CCA2 oracle game |
| Signature model | Equational theory | EUF-CMA oracle game |
| Automation | Fully automatic | Guided (proof block) |

Both models verify the same protocol and the same security properties. The ProVerif model provides quick symbolic verification; the CryptoVerif model provides publication-grade computational guarantees with concrete bounds.

## Limitations and Future Work

1. **Hybrid composition is external**: The GHP18 combiner reduction is not mechanized in CryptoVerif. The model treats the hybrid KEM as a monolithic IND-CCA2 primitive.

2. **Simplified KDF model**: The actual implementation uses a more complex key schedule (SHA-256 mixing of sub-secrets). The model abstracts this as a single HKDF call, which is sound as long as the intermediate hashing preserves entropy.

3. **No downgrade attacks**: The model fixes `SUITE_HYBRID` and does not model cipher suite negotiation or downgrade resistance.

4. **Single key pair per role**: The model uses one client and one server identity. Multi-party settings with key registration are not modeled.

5. **No session resumption**: The model covers only the full handshake, not abbreviated session resumption.

### Potential extensions

- Model cipher suite negotiation with downgrade resistance proof
- Add session resumption (PSK-based)
- Mechanize the hybrid combiner reduction in CryptoVerif
- Model key rotation (DID document updates)
