"""Tests for qasp.crypto.merkle — generic SHA-384 Merkle tree."""

from __future__ import annotations

import pytest

from qasp.crypto.merkle import (
    HASH_SIZE,
    MerkleProof,
    MerkleProofStep,
    build_tree,
    generate_proof,
    verify_proof,
    _hash_leaf,
    _hash_internal,
)


class TestHashFunctions:
    def test_hash_leaf_deterministic(self):
        assert _hash_leaf(b"hello") == _hash_leaf(b"hello")

    def test_hash_leaf_size(self):
        assert len(_hash_leaf(b"data")) == HASH_SIZE

    def test_domain_separation(self):
        data = b"same-data"
        assert _hash_leaf(data) != _hash_internal(data, data)

    def test_hash_internal_non_commutative(self):
        a = _hash_leaf(b"a")
        b = _hash_leaf(b"b")
        assert _hash_internal(a, b) != _hash_internal(b, a)

    def test_hash_internal_size(self):
        a = _hash_leaf(b"a")
        b = _hash_leaf(b"b")
        assert len(_hash_internal(a, b)) == HASH_SIZE


class TestBuildTree:
    def test_single_leaf(self):
        tree = build_tree((b"only",))
        assert len(tree.root) == HASH_SIZE
        assert len(tree.leaves) == 1
        assert len(tree.leaf_hashes) == 1

    def test_two_leaves(self):
        tree = build_tree((b"a", b"b"))
        assert len(tree.root) == HASH_SIZE
        expected_root = _hash_internal(_hash_leaf(b"a"), _hash_leaf(b"b"))
        assert tree.root == expected_root

    def test_four_leaves(self):
        tree = build_tree((b"a", b"b", b"c", b"d"))
        assert len(tree.root) == HASH_SIZE

    def test_fifteen_leaves_padded(self):
        leaves = tuple(f"leaf-{i}".encode() for i in range(15))
        tree = build_tree(leaves)
        assert len(tree.root) == HASH_SIZE
        assert len(tree.leaves) == 15
        assert len(tree.leaf_hashes) == 15

    def test_sixteen_leaves(self):
        leaves = tuple(f"leaf-{i}".encode() for i in range(16))
        tree = build_tree(leaves)
        assert len(tree.root) == HASH_SIZE
        assert len(tree.leaves) == 16

    def test_deterministic(self):
        leaves = (b"x", b"y", b"z")
        t1 = build_tree(leaves)
        t2 = build_tree(leaves)
        assert t1.root == t2.root

    def test_root_size(self):
        tree = build_tree((b"a", b"b", b"c"))
        assert len(tree.root) == HASH_SIZE


class TestGenerateProof:
    def test_proof_structure(self):
        tree = build_tree((b"a", b"b", b"c", b"d"))
        proof = generate_proof(tree, 0)
        assert isinstance(proof, MerkleProof)
        assert proof.leaf_index == 0
        assert len(proof.leaf_hash) == HASH_SIZE
        assert proof.root == tree.root

    def test_step_count_power_of_two(self):
        tree = build_tree((b"a", b"b", b"c", b"d"))
        proof = generate_proof(tree, 2)
        assert len(proof.steps) == 2  # log2(4) = 2

    def test_step_count_padded(self):
        leaves = tuple(f"leaf-{i}".encode() for i in range(15))
        tree = build_tree(leaves)
        proof = generate_proof(tree, 0)
        assert len(proof.steps) == 4  # log2(16) = 4

    def test_out_of_bounds_raises(self):
        tree = build_tree((b"a", b"b"))
        with pytest.raises(IndexError):
            generate_proof(tree, 2)
        with pytest.raises(IndexError):
            generate_proof(tree, -1)


class TestVerifyProof:
    def test_valid_roundtrip(self):
        tree = build_tree((b"a", b"b", b"c", b"d"))
        for i in range(4):
            proof = generate_proof(tree, i)
            assert verify_proof(proof, tree.root) is True

    def test_all_leaves_fifteen(self):
        leaves = tuple(f"leaf-{i}".encode() for i in range(15))
        tree = build_tree(leaves)
        for i in range(15):
            proof = generate_proof(tree, i)
            assert verify_proof(proof, tree.root) is True

    def test_tampered_leaf_hash(self):
        tree = build_tree((b"a", b"b", b"c", b"d"))
        proof = generate_proof(tree, 0)
        tampered = MerkleProof(
            leaf_index=proof.leaf_index,
            leaf_hash=b"\x00" * HASH_SIZE,
            steps=proof.steps,
            root=proof.root,
        )
        assert verify_proof(tampered, tree.root) is False

    def test_tampered_sibling(self):
        tree = build_tree((b"a", b"b", b"c", b"d"))
        proof = generate_proof(tree, 0)
        bad_step = MerkleProofStep(
            sibling_hash=b"\xff" * HASH_SIZE,
            is_left=proof.steps[0].is_left,
        )
        tampered = MerkleProof(
            leaf_index=proof.leaf_index,
            leaf_hash=proof.leaf_hash,
            steps=(bad_step,) + proof.steps[1:],
            root=proof.root,
        )
        assert verify_proof(tampered, tree.root) is False

    def test_wrong_root(self):
        tree = build_tree((b"a", b"b", b"c", b"d"))
        proof = generate_proof(tree, 0)
        assert verify_proof(proof, b"\x00" * HASH_SIZE) is False

    def test_flipped_is_left(self):
        tree = build_tree((b"a", b"b", b"c", b"d"))
        proof = generate_proof(tree, 0)
        flipped = MerkleProofStep(
            sibling_hash=proof.steps[0].sibling_hash,
            is_left=not proof.steps[0].is_left,
        )
        tampered = MerkleProof(
            leaf_index=proof.leaf_index,
            leaf_hash=proof.leaf_hash,
            steps=(flipped,) + proof.steps[1:],
            root=proof.root,
        )
        assert verify_proof(tampered, tree.root) is False


class TestEdgeCases:
    def test_empty_raises(self):
        with pytest.raises(ValueError, match="empty"):
            build_tree(())

    def test_large_tree(self):
        leaves = tuple(f"item-{i}".encode() for i in range(256))
        tree = build_tree(leaves)
        assert len(tree.root) == HASH_SIZE
        proof = generate_proof(tree, 128)
        assert verify_proof(proof, tree.root) is True
        assert len(proof.steps) == 8  # log2(256) = 8
