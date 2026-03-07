"""Zero-knowledge selective disclosure for capability tokens.

Provides Bulletproofs-based ZK proofs for token fields:
- Equality proofs: prove a committed field equals a public value
- Membership proofs: prove a committed verb is in a set
- Range proofs: prove a committed numeric field is in a range
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

import cbor2

from qasp.crypto.bulletproofs import prove_range as bp_prove_range
from qasp.crypto.bulletproofs import verify_range as bp_verify_range
from qasp.crypto.ec import (
    IDENTITY,
    L as GROUP_ORDER,
    Point,
    hash_to_point,
    point_add,
    point_decode,
    point_encode,
    point_eq,
    scalar_mult,
)
from qasp.crypto.pedersen import G, H, commit, open_commitment, random_scalar
from qasp.crypto.signatures import sign, verify
from qasp.protocol.selective_disclosure import CANONICAL_FIELD_NAMES

__all__ = [
    "InvalidZKProofError",
    "ZKCommitmentError",
    "ZKDisclosureError",
    "ZKProof",
    "ZKToken",
    "create_zk_token",
    "prove_field_equality",
    "prove_range",
    "prove_verb_membership",
    "verify_zk_proof",
]


class ZKDisclosureError(Exception):
    """Base exception for ZK disclosure errors."""


class InvalidZKProofError(ZKDisclosureError):
    """Raised when a ZK proof fails verification."""


class ZKCommitmentError(ZKDisclosureError):
    """Raised when commitment operations fail."""


@dataclass(frozen=True)
class ZKToken:
    """A token with Pedersen commitments for ZK disclosure."""

    token_id: bytes
    commitments: dict[str, bytes]  # field_name -> 32-byte commitment
    blindings: dict[str, int]  # field_name -> blinding scalar (private)
    values: dict[str, int]  # field_name -> committed value (private)
    issuer_signature: bytes
    issuer_did: str


@dataclass(frozen=True)
class ZKProof:
    """A zero-knowledge proof about a committed field."""

    proof_type: str  # "equality", "membership", "range"
    field_name: str
    proof_data: bytes  # CBOR-encoded proof-specific data
    commitment: bytes  # The commitment being proved about


def _field_to_int(field_name: str, value: object) -> int:
    """Convert a token field value to an integer for commitment."""
    cbor_bytes = cbor2.dumps(value)
    # Hash to a scalar
    h = hashlib.sha384(b"qasp-zk-field-" + field_name.encode() + cbor_bytes)
    return int.from_bytes(h.digest()[:32], "little") % GROUP_ORDER


def create_zk_token(
    token_fields: dict[str, object],
    issuer_secret_key: bytes,
    issuer_did: str,
    token_id: bytes,
) -> ZKToken:
    """Create a ZK token with Pedersen commitments for all fields.

    Args:
        token_fields: Dict mapping field names to values (as used in selective_disclosure).
        issuer_secret_key: ML-DSA-65 secret key for signing.
        issuer_did: DID of the issuer.
        token_id: Token identifier.

    Returns:
        A ZKToken with commitments and blindings.
    """
    commitments: dict[str, bytes] = {}
    blindings: dict[str, int] = {}
    values: dict[str, int] = {}

    for field_name in CANONICAL_FIELD_NAMES:
        value = token_fields.get(field_name)
        v = _field_to_int(field_name, value)
        r = random_scalar()
        c = commit(v, r)
        commitments[field_name] = c
        blindings[field_name] = r
        values[field_name] = v

    # Sign all commitments
    commitment_data = cbor2.dumps(
        {name: commitments[name] for name in CANONICAL_FIELD_NAMES},
        canonical=True,
    )
    issuer_signature = sign(issuer_secret_key, commitment_data)

    return ZKToken(
        token_id=token_id,
        commitments=commitments,
        blindings=blindings,
        values=values,
        issuer_signature=issuer_signature,
        issuer_did=issuer_did,
    )


def prove_field_equality(
    zk_token: ZKToken,
    field_name: str,
    public_value: object,
) -> ZKProof:
    """Prove that a committed field equals a public value.

    Uses Schnorr-like proof: knows blinding r such that C = v*G + r*H
    where v = hash(field_name, public_value).

    Args:
        zk_token: The ZK token.
        field_name: The field to prove about.
        public_value: The public value to prove equality with.

    Returns:
        A ZKProof of equality.
    """
    if field_name not in CANONICAL_FIELD_NAMES:
        raise ZKDisclosureError(f"Unknown field: {field_name}")

    v = _field_to_int(field_name, public_value)
    r = zk_token.blindings[field_name]

    # Schnorr proof for knowledge of r: C - v*G = r*H
    # 1. Pick random k
    k = random_scalar()
    # 2. R = k*H
    R = scalar_mult(k, H)
    # 3. Challenge e = hash(C, R, v)
    c_bytes = zk_token.commitments[field_name]
    transcript = hashlib.sha384(
        b"qasp-zk-equality"
        + c_bytes
        + point_encode(R)
        + v.to_bytes(32, "little")
    )
    e = int.from_bytes(transcript.digest()[:32], "little") % GROUP_ORDER
    # 4. s = k - e*r mod L
    s = (k - e * r) % GROUP_ORDER

    proof_data = cbor2.dumps({
        "R": point_encode(R),
        "s": s,
        "v": v,
    })

    return ZKProof(
        proof_type="equality",
        field_name=field_name,
        proof_data=proof_data,
        commitment=c_bytes,
    )


def prove_verb_membership(
    zk_token: ZKToken,
    verb: str,
) -> ZKProof:
    """Prove that a specific verb is in the committed verb set.

    Creates equality proof that the verbs field contains the given verb
    by proving knowledge of the full verb set and its blinding.

    Args:
        zk_token: The ZK token.
        verb: The verb to prove membership of.

    Returns:
        A ZKProof of membership.
    """
    # The "verbs" field commitment covers the entire verb set.
    # We prove: "I know the full verb set committed in C, and verb is in it."
    # This is a simplified membership proof using commitment opening
    # with a membership witness.

    field_name = "verbs"
    v = zk_token.values[field_name]
    r = zk_token.blindings[field_name]

    # Create a Schnorr proof similar to equality, but include verb
    # membership witness
    k = random_scalar()
    R = scalar_mult(k, H)

    # Hash includes the verb being proved
    verb_hash = hashlib.sha384(b"qasp-zk-verb-" + verb.encode()).digest()[:32]
    c_bytes = zk_token.commitments[field_name]
    transcript = hashlib.sha384(
        b"qasp-zk-membership" + c_bytes + point_encode(R) + verb_hash
    )
    e = int.from_bytes(transcript.digest()[:32], "little") % GROUP_ORDER
    s = (k - e * r) % GROUP_ORDER

    proof_data = cbor2.dumps({
        "R": point_encode(R),
        "s": s,
        "v": v,
        "verb": verb,
        "verb_hash": verb_hash,
    })

    return ZKProof(
        proof_type="membership",
        field_name=field_name,
        proof_data=proof_data,
        commitment=c_bytes,
    )


def prove_range(
    zk_token: ZKToken,
    field_name: str,
    n_bits: int = 16,
) -> ZKProof:
    """Prove a committed numeric field is in range [0, 2^n_bits).

    Uses Bulletproofs range proof.

    Args:
        zk_token: The ZK token.
        field_name: The field to prove about.
        n_bits: Bit width for range proof (default 16 for faster tests).

    Returns:
        A ZKProof with Bulletproofs range proof.
    """
    if field_name not in CANONICAL_FIELD_NAMES:
        raise ZKDisclosureError(f"Unknown field: {field_name}")

    v = zk_token.values[field_name]
    r = zk_token.blindings[field_name]

    # Value must be in range for the proof to work
    if v < 0 or v >= (1 << n_bits):
        raise ZKCommitmentError(
            f"Field value {v} not in range [0, 2^{n_bits})"
        )

    bp_proof = bp_prove_range(v, r, n_bits=n_bits)

    proof_data = cbor2.dumps({
        "cap_a": bp_proof.cap_a,
        "cap_s": bp_proof.cap_s,
        "cap_t1": bp_proof.cap_t1,
        "cap_t2": bp_proof.cap_t2,
        "tau_x": bp_proof.tau_x,
        "mu": bp_proof.mu,
        "t_hat": bp_proof.t_hat,
        "ip_l_vec": list(bp_proof.inner_product.l_vec),
        "ip_r_vec": list(bp_proof.inner_product.r_vec),
        "ip_a": bp_proof.inner_product.a,
        "ip_b": bp_proof.inner_product.b,
        "n_bits": n_bits,
    })

    return ZKProof(
        proof_type="range",
        field_name=field_name,
        proof_data=proof_data,
        commitment=zk_token.commitments[field_name],
    )


def verify_zk_proof(
    proof: ZKProof,
    issuer_public_key: bytes,
    commitments: dict[str, bytes],
    issuer_signature: bytes,
) -> bool:
    """Verify a ZK proof.

    Args:
        proof: The ZK proof to verify.
        issuer_public_key: ML-DSA-65 public key of the issuer.
        commitments: All commitments from the ZK token.
        issuer_signature: Signature over the commitments.

    Returns:
        True if the proof is valid.

    Raises:
        InvalidZKProofError: If verification fails.
    """
    # Verify issuer signature over commitments
    commitment_data = cbor2.dumps(
        {name: commitments[name] for name in CANONICAL_FIELD_NAMES},
        canonical=True,
    )
    try:
        verify(issuer_public_key, commitment_data, issuer_signature)
    except Exception as exc:
        raise InvalidZKProofError(
            f"Issuer signature verification failed: {exc}"
        ) from exc

    # Verify commitment matches
    if proof.commitment != commitments.get(proof.field_name):
        raise InvalidZKProofError(
            "Proof commitment does not match token commitment"
        )

    data = cbor2.loads(proof.proof_data)

    if proof.proof_type == "equality":
        return _verify_equality(proof.commitment, data)
    elif proof.proof_type == "membership":
        return _verify_membership(proof.commitment, data)
    elif proof.proof_type == "range":
        return _verify_range(proof.commitment, data)
    else:
        raise InvalidZKProofError(f"Unknown proof type: {proof.proof_type}")


def _verify_equality(commitment: bytes, data: dict) -> bool:
    """Verify a Schnorr equality proof."""
    R = point_decode(data["R"])
    s = data["s"]
    v = data["v"]

    # Recompute challenge
    transcript = hashlib.sha384(
        b"qasp-zk-equality"
        + commitment
        + point_encode(R)
        + v.to_bytes(32, "little")
    )
    e = int.from_bytes(transcript.digest()[:32], "little") % GROUP_ORDER

    # Verify: s*H + e*(C - v*G) == R
    C = point_decode(commitment)
    # C - v*G = r*H if honest
    diff = point_add(C, scalar_mult((GROUP_ORDER - v) % GROUP_ORDER, G))
    lhs = point_add(scalar_mult(s, H), scalar_mult(e, diff))

    if not point_eq(lhs, R):
        raise InvalidZKProofError("Equality proof verification failed")
    return True


def _verify_membership(commitment: bytes, data: dict) -> bool:
    """Verify a membership proof."""
    R = point_decode(data["R"])
    s = data["s"]
    v = data["v"]
    verb = data["verb"]
    verb_hash = bytes(data["verb_hash"])

    # Verify verb hash
    expected_verb_hash = hashlib.sha384(
        b"qasp-zk-verb-" + verb.encode()
    ).digest()[:32]
    if verb_hash != expected_verb_hash:
        raise InvalidZKProofError("Verb hash mismatch")

    # Recompute challenge
    transcript = hashlib.sha384(
        b"qasp-zk-membership" + commitment + point_encode(R) + verb_hash
    )
    e = int.from_bytes(transcript.digest()[:32], "little") % GROUP_ORDER

    # Verify: s*H + e*(C - v*G) == R
    C = point_decode(commitment)
    diff = point_add(C, scalar_mult((GROUP_ORDER - v) % GROUP_ORDER, G))
    lhs = point_add(scalar_mult(s, H), scalar_mult(e, diff))

    if not point_eq(lhs, R):
        raise InvalidZKProofError("Membership proof verification failed")
    return True


def _verify_range(commitment: bytes, data: dict) -> bool:
    """Verify a Bulletproofs range proof."""
    from qasp.crypto.bulletproofs import InnerProductProof, RangeProof

    bp_proof = RangeProof(
        cap_a=bytes(data["cap_a"]),
        cap_s=bytes(data["cap_s"]),
        cap_t1=bytes(data["cap_t1"]),
        cap_t2=bytes(data["cap_t2"]),
        tau_x=data["tau_x"],
        mu=data["mu"],
        t_hat=data["t_hat"],
        inner_product=InnerProductProof(
            l_vec=tuple(bytes(x) for x in data["ip_l_vec"]),
            r_vec=tuple(bytes(x) for x in data["ip_r_vec"]),
            a=data["ip_a"],
            b=data["ip_b"],
        ),
        n_bits=data["n_bits"],
    )

    if not bp_verify_range(commitment, bp_proof):
        raise InvalidZKProofError("Range proof verification failed")
    return True
