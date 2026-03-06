"""Unit tests for DID key rotation."""

from __future__ import annotations

import hashlib

import pytest

from qasp.crypto.signatures import generate_keypair
from qasp.identity.did import DIDDocument, DIDRegistry, create_did
from qasp.identity.exceptions import KeyRotationError
from qasp.identity.rotation import (
    KeyRotationProof,
    commit_next_key,
    create_rotation_proof,
    rotate_key,
    verify_rotation_proof,
)


@pytest.fixture
def keypair_a() -> tuple[bytes, bytes]:
    """Generate keypair A (initial)."""
    return generate_keypair()


@pytest.fixture
def keypair_b() -> tuple[bytes, bytes]:
    """Generate keypair B (next)."""
    return generate_keypair()


@pytest.fixture
def keypair_c() -> tuple[bytes, bytes]:
    """Generate keypair C (second rotation)."""
    return generate_keypair()


@pytest.fixture
def did_doc_a(keypair_a: tuple[bytes, bytes]) -> DIDDocument:
    """Create a DID document with keypair A."""
    _, doc = create_did(keypair_a[0])
    return doc


class TestCommitNextKey:
    """Test pre-commitment of next key hash."""

    def test_sets_hash(
        self,
        did_doc_a: DIDDocument,
        keypair_b: tuple[bytes, bytes],
    ) -> None:
        committed = commit_next_key(did_doc_a, keypair_b[0])
        expected_hash = hashlib.sha384(keypair_b[0]).digest()
        assert committed.next_key_hash == expected_hash

    def test_preserves_fields(
        self,
        did_doc_a: DIDDocument,
        keypair_b: tuple[bytes, bytes],
    ) -> None:
        committed = commit_next_key(did_doc_a, keypair_b[0])
        assert committed.did == did_doc_a.did
        assert committed.verification_methods == did_doc_a.verification_methods
        assert committed.authentication == did_doc_a.authentication
        assert committed.key_version == did_doc_a.key_version

    def test_original_unchanged(
        self,
        did_doc_a: DIDDocument,
        keypair_b: tuple[bytes, bytes],
    ) -> None:
        commit_next_key(did_doc_a, keypair_b[0])
        assert did_doc_a.next_key_hash is None


class TestCreateRotationProof:
    """Test rotation proof creation."""

    def test_round_trip(
        self,
        did_doc_a: DIDDocument,
        keypair_a: tuple[bytes, bytes],
        keypair_b: tuple[bytes, bytes],
    ) -> None:
        committed = commit_next_key(did_doc_a, keypair_b[0])
        proof = create_rotation_proof(committed, keypair_a[1], keypair_b[0], keypair_b[1])

        assert isinstance(proof, KeyRotationProof)
        assert proof.did == did_doc_a.did
        assert proof.new_public_key == keypair_b[0]
        assert proof.old_key_version == 1
        assert proof.new_key_version == 2
        assert len(proof.old_key_signature) > 0
        assert len(proof.new_key_signature) > 0

    def test_fails_without_precommitment(
        self,
        did_doc_a: DIDDocument,
        keypair_a: tuple[bytes, bytes],
        keypair_b: tuple[bytes, bytes],
    ) -> None:
        # No commit_next_key — next_key_hash is None
        with pytest.raises(KeyRotationError, match="No pre-committed"):
            create_rotation_proof(did_doc_a, keypair_a[1], keypair_b[0], keypair_b[1])

    def test_fails_with_wrong_key(
        self,
        did_doc_a: DIDDocument,
        keypair_a: tuple[bytes, bytes],
        keypair_b: tuple[bytes, bytes],
        keypair_c: tuple[bytes, bytes],
    ) -> None:
        committed = commit_next_key(did_doc_a, keypair_b[0])
        # Try to rotate to keypair_c instead of keypair_b
        with pytest.raises(KeyRotationError, match="does not match"):
            create_rotation_proof(committed, keypair_a[1], keypair_c[0], keypair_c[1])


class TestVerifyRotationProof:
    """Test rotation proof verification."""

    def test_valid_proof(
        self,
        did_doc_a: DIDDocument,
        keypair_a: tuple[bytes, bytes],
        keypair_b: tuple[bytes, bytes],
    ) -> None:
        committed = commit_next_key(did_doc_a, keypair_b[0])
        proof = create_rotation_proof(committed, keypair_a[1], keypair_b[0], keypair_b[1])
        assert verify_rotation_proof(proof, committed) is True

    def test_tampered_old_signature(
        self,
        did_doc_a: DIDDocument,
        keypair_a: tuple[bytes, bytes],
        keypair_b: tuple[bytes, bytes],
    ) -> None:
        committed = commit_next_key(did_doc_a, keypair_b[0])
        proof = create_rotation_proof(committed, keypair_a[1], keypair_b[0], keypair_b[1])

        tampered = KeyRotationProof(
            did=proof.did,
            new_public_key=proof.new_public_key,
            old_key_version=proof.old_key_version,
            new_key_version=proof.new_key_version,
            timestamp=proof.timestamp,
            old_key_signature=b"\x00" * len(proof.old_key_signature),
            new_key_signature=proof.new_key_signature,
        )
        with pytest.raises(KeyRotationError, match="Old key signature"):
            verify_rotation_proof(tampered, committed)

    def test_tampered_new_signature(
        self,
        did_doc_a: DIDDocument,
        keypair_a: tuple[bytes, bytes],
        keypair_b: tuple[bytes, bytes],
    ) -> None:
        committed = commit_next_key(did_doc_a, keypair_b[0])
        proof = create_rotation_proof(committed, keypair_a[1], keypair_b[0], keypair_b[1])

        tampered = KeyRotationProof(
            did=proof.did,
            new_public_key=proof.new_public_key,
            old_key_version=proof.old_key_version,
            new_key_version=proof.new_key_version,
            timestamp=proof.timestamp,
            old_key_signature=proof.old_key_signature,
            new_key_signature=b"\x00" * len(proof.new_key_signature),
        )
        with pytest.raises(KeyRotationError, match="New key signature"):
            verify_rotation_proof(tampered, committed)


class TestRotateKey:
    """Test full key rotation."""

    def test_updates_verification_method(
        self,
        did_doc_a: DIDDocument,
        keypair_a: tuple[bytes, bytes],
        keypair_b: tuple[bytes, bytes],
    ) -> None:
        committed = commit_next_key(did_doc_a, keypair_b[0])
        proof = create_rotation_proof(committed, keypair_a[1], keypair_b[0], keypair_b[1])
        new_doc = rotate_key(proof, committed)

        assert len(new_doc.verification_methods) == 1
        assert new_doc.verification_methods[0].id.endswith("#key-2")
        # The new VM should contain the new public key
        decoded_pk = new_doc.get_public_key()
        assert decoded_pk == keypair_b[0]

    def test_increments_version(
        self,
        did_doc_a: DIDDocument,
        keypair_a: tuple[bytes, bytes],
        keypair_b: tuple[bytes, bytes],
    ) -> None:
        committed = commit_next_key(did_doc_a, keypair_b[0])
        proof = create_rotation_proof(committed, keypair_a[1], keypair_b[0], keypair_b[1])
        new_doc = rotate_key(proof, committed)
        assert new_doc.key_version == 2

    def test_clears_next_key_hash(
        self,
        did_doc_a: DIDDocument,
        keypair_a: tuple[bytes, bytes],
        keypair_b: tuple[bytes, bytes],
    ) -> None:
        committed = commit_next_key(did_doc_a, keypair_b[0])
        proof = create_rotation_proof(committed, keypair_a[1], keypair_b[0], keypair_b[1])
        new_doc = rotate_key(proof, committed)
        assert new_doc.next_key_hash is None

    def test_updates_authentication_and_assertion(
        self,
        did_doc_a: DIDDocument,
        keypair_a: tuple[bytes, bytes],
        keypair_b: tuple[bytes, bytes],
    ) -> None:
        committed = commit_next_key(did_doc_a, keypair_b[0])
        proof = create_rotation_proof(committed, keypair_a[1], keypair_b[0], keypair_b[1])
        new_doc = rotate_key(proof, committed)

        key_id = f"{new_doc.did}#key-2"
        assert key_id in new_doc.authentication
        assert key_id in new_doc.assertion_method


class TestDoubleRotation:
    """Test commit -> rotate -> commit -> rotate cycle."""

    def test_double_rotation(
        self,
        keypair_a: tuple[bytes, bytes],
        keypair_b: tuple[bytes, bytes],
        keypair_c: tuple[bytes, bytes],
    ) -> None:
        _, doc = create_did(keypair_a[0])

        # First rotation: A -> B
        doc1 = commit_next_key(doc, keypair_b[0])
        proof1 = create_rotation_proof(doc1, keypair_a[1], keypair_b[0], keypair_b[1])
        doc2 = rotate_key(proof1, doc1)

        assert doc2.key_version == 2
        assert doc2.next_key_hash is None

        # Second rotation: B -> C
        doc3 = commit_next_key(doc2, keypair_c[0])
        proof2 = create_rotation_proof(doc3, keypair_b[1], keypair_c[0], keypair_c[1])
        doc4 = rotate_key(proof2, doc3)

        assert doc4.key_version == 3
        assert doc4.get_public_key() == keypair_c[0]
        assert doc4.verification_methods[0].id.endswith("#key-3")


class TestRegistryUpdateOnRotation:
    """Test that rotation updates the registry."""

    def test_registry_updated(
        self,
        did_doc_a: DIDDocument,
        keypair_a: tuple[bytes, bytes],
        keypair_b: tuple[bytes, bytes],
    ) -> None:
        registry = DIDRegistry()
        registry.register(did_doc_a)

        committed = commit_next_key(did_doc_a, keypair_b[0])
        proof = create_rotation_proof(committed, keypair_a[1], keypair_b[0], keypair_b[1])
        new_doc = rotate_key(proof, committed, registry=registry)

        looked_up = registry.lookup(did_doc_a.did)
        assert looked_up.key_version == 2
        assert looked_up.get_public_key() == keypair_b[0]
