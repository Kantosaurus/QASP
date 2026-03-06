"""Generic SHA-384 Merkle tree with domain-separated hashing.

Provides build, prove, and verify operations for inclusion proofs.
Domain separation (``b"leaf:"`` vs ``b"node:"``) prevents second-preimage attacks.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass

__all__ = [
    "HASH_SIZE",
    "PADDING_DOMAIN_SEP",
    "MerkleProof",
    "MerkleProofStep",
    "MerkleTree",
    "build_tree",
    "generate_proof",
    "verify_proof",
]

HASH_SIZE = 48  # SHA-384
PADDING_DOMAIN_SEP = b"qasp-merkle-padding-v1"


@dataclass(frozen=True)
class MerkleProofStep:
    sibling_hash: bytes
    is_left: bool


@dataclass(frozen=True)
class MerkleProof:
    leaf_index: int
    leaf_hash: bytes
    steps: tuple[MerkleProofStep, ...]
    root: bytes


@dataclass(frozen=True)
class MerkleTree:
    leaves: tuple[bytes, ...]
    leaf_hashes: tuple[bytes, ...]
    root: bytes
    _nodes: tuple[bytes, ...]


def _hash_leaf(data: bytes) -> bytes:
    return hashlib.sha384(b"leaf:" + data).digest()


def _hash_internal(left: bytes, right: bytes) -> bytes:
    return hashlib.sha384(b"node:" + left + right).digest()


def _next_power_of_two(n: int) -> int:
    if n <= 1:
        return 1
    return 1 << math.ceil(math.log2(n))


def build_tree(leaves: tuple[bytes, ...]) -> MerkleTree:
    if not leaves:
        raise ValueError("Cannot build Merkle tree from empty leaves")

    padded_count = _next_power_of_two(len(leaves))
    leaf_hashes = list(_hash_leaf(leaf) for leaf in leaves)

    # Pad to next power of two with deterministic padding
    for i in range(len(leaves), padded_count):
        padding_data = PADDING_DOMAIN_SEP + i.to_bytes(4, "big")
        leaf_hashes.append(_hash_leaf(padding_data))

    # Build bottom-up
    nodes: list[bytes] = list(leaf_hashes)
    level_start = 0
    level_size = padded_count

    while level_size > 1:
        for i in range(0, level_size, 2):
            left = nodes[level_start + i]
            right = nodes[level_start + i + 1]
            nodes.append(_hash_internal(left, right))
        level_start += level_size
        level_size //= 2

    root = nodes[-1]

    return MerkleTree(
        leaves=leaves,
        leaf_hashes=tuple(leaf_hashes[:len(leaves)]),
        root=root,
        _nodes=tuple(nodes),
    )


def generate_proof(tree: MerkleTree, leaf_index: int) -> MerkleProof:
    if leaf_index < 0 or leaf_index >= len(tree.leaves):
        raise IndexError(
            f"Leaf index {leaf_index} out of range [0, {len(tree.leaves)})"
        )

    padded_count = _next_power_of_two(len(tree.leaves))
    nodes = tree._nodes
    steps: list[MerkleProofStep] = []

    idx = leaf_index
    level_start = 0
    level_size = padded_count

    while level_size > 1:
        if idx % 2 == 0:
            sibling_idx = idx + 1
            is_left = False  # sibling is on the right
        else:
            sibling_idx = idx - 1
            is_left = True  # sibling is on the left

        steps.append(
            MerkleProofStep(
                sibling_hash=nodes[level_start + sibling_idx],
                is_left=is_left,
            )
        )
        idx //= 2
        level_start += level_size
        level_size //= 2

    leaf_hash = nodes[leaf_index]

    return MerkleProof(
        leaf_index=leaf_index,
        leaf_hash=leaf_hash,
        steps=tuple(steps),
        root=tree.root,
    )


def verify_proof(proof: MerkleProof, root: bytes) -> bool:
    current = proof.leaf_hash
    for step in proof.steps:
        if step.is_left:
            current = _hash_internal(step.sibling_hash, current)
        else:
            current = _hash_internal(current, step.sibling_hash)
    return current == root
