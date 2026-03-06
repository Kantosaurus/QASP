"""Merkle-based selective disclosure for capability tokens.

Allows token holders to prove specific authorization properties without
revealing all token fields. Builds a Merkle tree over canonical token fields,
signs the root, and generates inclusion proofs for selected fields.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import cbor2

from qasp.crypto.merkle import MerkleTree, _hash_leaf, build_tree, generate_proof, verify_proof
from qasp.crypto.signatures import sign, verify
from qasp.protocol.capability import (
    CapabilityError,
    CapabilityToken,
    _constraints_to_dict,
    _temporal_schedule_to_dict,
)

__all__ = [
    "CANONICAL_FIELD_NAMES",
    "FIELD_COUNT",
    "PADDED_LEAF_COUNT",
    "FieldNotFoundError",
    "InvalidMerkleProofError",
    "MerkleSignatureError",
    "MerkleToken",
    "SelectiveDisclosureError",
    "SelectiveProof",
    "decode_revealed_field",
    "merkleize_token",
    "selective_reveal",
    "verify_selective_proof",
]

# The 15 canonical fields in alphabetical order.
CANONICAL_FIELD_NAMES: tuple[str, ...] = (
    "audience",
    "auditor_kem_pk",
    "chain_len",
    "constraints",
    "iat",
    "issuer",
    "max_depth",
    "nonce",
    "parent",
    "resource",
    "subject",
    "tc_pos",
    "temporal_attenuation",
    "token_id",
    "verbs",
)

FIELD_COUNT = 15
PADDED_LEAF_COUNT = 16


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class SelectiveDisclosureError(CapabilityError):
    alert_code: int = 60


class InvalidMerkleProofError(SelectiveDisclosureError):
    alert_code: int = 61


class FieldNotFoundError(SelectiveDisclosureError):
    alert_code: int = 62


class MerkleSignatureError(SelectiveDisclosureError):
    alert_code: int = 63


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MerkleToken:
    token_id: bytes
    merkle_root: bytes
    root_signature: bytes
    issuer_did: str
    tree: MerkleTree
    field_values: dict[str, bytes]

    def to_cbor(self) -> bytes:
        return cbor2.dumps({
            "token_id": self.token_id,
            "merkle_root": self.merkle_root,
            "root_signature": self.root_signature,
            "issuer_did": self.issuer_did,
            "field_values": self.field_values,
        })

    @classmethod
    def from_cbor(cls, data: bytes, tree: MerkleTree | None = None) -> MerkleToken:
        decoded = cbor2.loads(data)
        field_values = {k: bytes(v) for k, v in decoded["field_values"].items()}
        return cls(
            token_id=bytes(decoded["token_id"]),
            merkle_root=bytes(decoded["merkle_root"]),
            root_signature=bytes(decoded["root_signature"]),
            issuer_did=decoded["issuer_did"],
            tree=tree if tree is not None else build_tree(
                tuple(field_values[name] for name in CANONICAL_FIELD_NAMES)
            ),
            field_values=field_values,
        )


@dataclass(frozen=True)
class SelectiveProof:
    token_id: bytes
    merkle_root: bytes
    root_signature: bytes
    issuer_did: str
    revealed_fields: dict[str, bytes]
    proofs: tuple[Any, ...]  # tuple of MerkleProof

    def to_cbor(self) -> bytes:
        proof_list = []
        for p in self.proofs:
            steps = [
                {"sibling_hash": s.sibling_hash, "is_left": s.is_left}
                for s in p.steps
            ]
            proof_list.append({
                "leaf_index": p.leaf_index,
                "leaf_hash": p.leaf_hash,
                "steps": steps,
                "root": p.root,
            })
        return cbor2.dumps({
            "token_id": self.token_id,
            "merkle_root": self.merkle_root,
            "root_signature": self.root_signature,
            "issuer_did": self.issuer_did,
            "revealed_fields": self.revealed_fields,
            "proofs": proof_list,
        })

    @classmethod
    def from_cbor(cls, data: bytes) -> SelectiveProof:
        from qasp.crypto.merkle import MerkleProof, MerkleProofStep

        decoded = cbor2.loads(data)
        proofs = []
        for p in decoded["proofs"]:
            steps = tuple(
                MerkleProofStep(
                    sibling_hash=bytes(s["sibling_hash"]),
                    is_left=s["is_left"],
                )
                for s in p["steps"]
            )
            proofs.append(MerkleProof(
                leaf_index=p["leaf_index"],
                leaf_hash=bytes(p["leaf_hash"]),
                steps=steps,
                root=bytes(p["root"]),
            ))
        revealed_fields = {k: bytes(v) for k, v in decoded["revealed_fields"].items()}
        return cls(
            token_id=bytes(decoded["token_id"]),
            merkle_root=bytes(decoded["merkle_root"]),
            root_signature=bytes(decoded["root_signature"]),
            issuer_did=decoded["issuer_did"],
            revealed_fields=revealed_fields,
            proofs=tuple(proofs),
        )


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

def _token_to_field_values(token: CapabilityToken) -> dict[str, bytes]:
    constraints_dict = _constraints_to_dict(token.constraints)
    temporal_dict = (
        _temporal_schedule_to_dict(token.temporal_attenuation)
        if token.temporal_attenuation is not None
        else None
    )

    raw: dict[str, Any] = {
        "audience": str(token.audience_did) if token.audience_did else None,
        "auditor_kem_pk": token.auditor_kem_pk.hex() if token.auditor_kem_pk else None,
        "chain_len": token.delegation_chain_length,
        "constraints": constraints_dict,
        "iat": token.issued_at.isoformat(),
        "issuer": str(token.issuer_did),
        "max_depth": token.max_delegation_depth,
        "nonce": token.nonce.hex(),
        "parent": token.parent_token_hash.hex() if token.parent_token_hash else None,
        "resource": token.resource_uri,
        "subject": str(token.subject_did),
        "tc_pos": token.toolchain_position,
        "temporal_attenuation": temporal_dict,
        "token_id": token.token_id.hex(),
        "verbs": sorted(token.verbs.verbs),
    }

    return {name: cbor2.dumps(raw[name]) for name in CANONICAL_FIELD_NAMES}


def merkleize_token(
    token: CapabilityToken,
    issuer_secret_key: bytes,
) -> MerkleToken:
    field_values = _token_to_field_values(token)
    leaves = tuple(field_values[name] for name in CANONICAL_FIELD_NAMES)
    tree = build_tree(leaves)
    root_signature = sign(issuer_secret_key, tree.root)

    return MerkleToken(
        token_id=token.token_id,
        merkle_root=tree.root,
        root_signature=root_signature,
        issuer_did=str(token.issuer_did),
        tree=tree,
        field_values=field_values,
    )


def selective_reveal(
    merkle_token: MerkleToken,
    field_names: list[str],
) -> SelectiveProof:
    for name in field_names:
        if name not in CANONICAL_FIELD_NAMES:
            raise FieldNotFoundError(f"Unknown field: {name!r}")

    revealed: dict[str, bytes] = {}
    proofs = []

    for name in field_names:
        idx = CANONICAL_FIELD_NAMES.index(name)
        revealed[name] = merkle_token.field_values[name]
        proofs.append(generate_proof(merkle_token.tree, idx))

    return SelectiveProof(
        token_id=merkle_token.token_id,
        merkle_root=merkle_token.merkle_root,
        root_signature=merkle_token.root_signature,
        issuer_did=merkle_token.issuer_did,
        revealed_fields=revealed,
        proofs=tuple(proofs),
    )


def verify_selective_proof(
    proof: SelectiveProof,
    issuer_public_key: bytes,
) -> bool:
    try:
        verify(issuer_public_key, proof.merkle_root, proof.root_signature)
    except Exception as exc:
        raise MerkleSignatureError(
            f"Root signature verification failed: {exc}"
        ) from exc

    revealed_names = list(proof.revealed_fields.keys())
    for i, merkle_proof in enumerate(proof.proofs):
        # Verify the revealed value hashes to the proof's leaf
        field_name = revealed_names[i]
        expected_leaf_hash = _hash_leaf(proof.revealed_fields[field_name])
        if expected_leaf_hash != merkle_proof.leaf_hash:
            raise InvalidMerkleProofError(
                f"Revealed field {field_name!r} does not match Merkle leaf hash"
            )
        if not verify_proof(merkle_proof, proof.merkle_root):
            raise InvalidMerkleProofError(
                f"Merkle proof verification failed for leaf {merkle_proof.leaf_index}"
            )

    return True


def decode_revealed_field(field_name: str, cbor_value: bytes) -> Any:
    if field_name not in CANONICAL_FIELD_NAMES:
        raise FieldNotFoundError(f"Unknown field: {field_name!r}")
    return cbor2.loads(cbor_value)
