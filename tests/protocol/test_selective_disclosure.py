"""Tests for qasp.protocol.selective_disclosure — Merkle-based selective disclosure."""

from __future__ import annotations

import cbor2
import pytest

from qasp.crypto.merkle import HASH_SIZE, _hash_leaf
from qasp.crypto.signatures import generate_keypair, verify
from qasp.identity.did import DID, create_did
from qasp.protocol.capability import CapabilityToken, Constraints, create_token
from qasp.protocol.selective_disclosure import (
    CANONICAL_FIELD_NAMES,
    FIELD_COUNT,
    PADDED_LEAF_COUNT,
    FieldNotFoundError,
    InvalidMerkleProofError,
    MerkleSignatureError,
    MerkleToken,
    SelectiveProof,
    _token_to_field_values,
    decode_revealed_field,
    merkleize_token,
    selective_reveal,
    verify_selective_proof,
)


# ---------------------------------------------------------------------------
# Fixtures (reuses conftest.py fixtures for keypairs and DIDs)
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_token(
    issuer_did: DID,
    issuer_secret_key: bytes,
    subject_did: DID,
) -> CapabilityToken:
    """Create a sample token with various fields populated."""
    return create_token(
        issuer_did=issuer_did,
        issuer_secret_key=issuer_secret_key,
        subject_did=subject_did,
        resource_uri="qasp://test/resource",
        verbs={"read", "write", "exec"},
        max_delegation_depth=3,
        constraints=Constraints(
            max_spend=1000,
            spend_currency="credits",
            purpose="testing selective disclosure",
        ),
    )


@pytest.fixture
def merkle_token(
    sample_token: CapabilityToken,
    issuer_secret_key: bytes,
) -> MerkleToken:
    return merkleize_token(sample_token, issuer_secret_key)


class TestTokenToFieldValues:
    def test_field_count(self, sample_token: CapabilityToken):
        fv = _token_to_field_values(sample_token)
        assert len(fv) == FIELD_COUNT

    def test_canonical_names(self, sample_token: CapabilityToken):
        fv = _token_to_field_values(sample_token)
        assert set(fv.keys()) == set(CANONICAL_FIELD_NAMES)

    def test_optional_field_encoded_as_none(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
    ):
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/simple",
            verbs={"read"},
        )
        fv = _token_to_field_values(token)
        # audience is None for this token
        assert cbor2.loads(fv["audience"]) is None
        # parent is None (root token)
        assert cbor2.loads(fv["parent"]) is None

    def test_values_are_valid_cbor(self, sample_token: CapabilityToken):
        fv = _token_to_field_values(sample_token)
        for name, val in fv.items():
            decoded = cbor2.loads(val)
            assert decoded is not None or name in (
                "audience",
                "auditor_kem_pk",
                "parent",
                "temporal_attenuation",
            )


class TestMerkleizeToken:
    def test_type(self, merkle_token: MerkleToken):
        assert isinstance(merkle_token, MerkleToken)

    def test_root_size(self, merkle_token: MerkleToken):
        assert len(merkle_token.merkle_root) == HASH_SIZE

    def test_signature_valid(
        self,
        merkle_token: MerkleToken,
        issuer_public_key: bytes,
    ):
        verify(issuer_public_key, merkle_token.merkle_root, merkle_token.root_signature)

    def test_tree_padding(self, merkle_token: MerkleToken):
        assert len(merkle_token.tree.leaves) == FIELD_COUNT
        # Padded to 16 internally
        assert len(merkle_token.tree._nodes) > FIELD_COUNT

    def test_deterministic(
        self,
        sample_token: CapabilityToken,
        issuer_secret_key: bytes,
    ):
        mt1 = merkleize_token(sample_token, issuer_secret_key)
        mt2 = merkleize_token(sample_token, issuer_secret_key)
        assert mt1.merkle_root == mt2.merkle_root


class TestSelectiveReveal:
    def test_single_field(self, merkle_token: MerkleToken):
        proof = selective_reveal(merkle_token, ["verbs"])
        assert "verbs" in proof.revealed_fields
        assert len(proof.proofs) == 1

    def test_multi_field(self, merkle_token: MerkleToken):
        proof = selective_reveal(merkle_token, ["verbs", "resource"])
        assert len(proof.revealed_fields) == 2
        assert len(proof.proofs) == 2

    def test_all_fields(self, merkle_token: MerkleToken):
        proof = selective_reveal(merkle_token, list(CANONICAL_FIELD_NAMES))
        assert len(proof.revealed_fields) == FIELD_COUNT
        assert len(proof.proofs) == FIELD_COUNT

    def test_invalid_field_raises(self, merkle_token: MerkleToken):
        with pytest.raises(FieldNotFoundError, match="bogus"):
            selective_reveal(merkle_token, ["bogus"])

    def test_proof_count_matches(self, merkle_token: MerkleToken):
        fields = ["issuer", "subject", "verbs"]
        proof = selective_reveal(merkle_token, fields)
        assert len(proof.proofs) == len(fields)


class TestVerifySelectiveProof:
    def test_full_roundtrip(
        self,
        merkle_token: MerkleToken,
        issuer_public_key: bytes,
    ):
        proof = selective_reveal(merkle_token, ["verbs", "resource"])
        assert verify_selective_proof(proof, issuer_public_key) is True

    def test_wrong_key_raises(
        self,
        merkle_token: MerkleToken,
    ):
        wrong_pk, _ = generate_keypair()
        proof = selective_reveal(merkle_token, ["verbs"])
        with pytest.raises(MerkleSignatureError):
            verify_selective_proof(proof, wrong_pk)

    def test_tampered_field_raises(
        self,
        merkle_token: MerkleToken,
        issuer_public_key: bytes,
    ):
        proof = selective_reveal(merkle_token, ["verbs"])
        tampered_fields = dict(proof.revealed_fields)
        tampered_fields["verbs"] = cbor2.dumps(["tampered"])
        tampered = SelectiveProof(
            token_id=proof.token_id,
            merkle_root=proof.merkle_root,
            root_signature=proof.root_signature,
            issuer_did=proof.issuer_did,
            revealed_fields=tampered_fields,
            proofs=proof.proofs,
        )
        # Signature passes (root not changed), but merkle proof fails
        with pytest.raises(InvalidMerkleProofError):
            verify_selective_proof(tampered, issuer_public_key)

    def test_tampered_root_raises(
        self,
        merkle_token: MerkleToken,
        issuer_public_key: bytes,
    ):
        proof = selective_reveal(merkle_token, ["verbs"])
        tampered = SelectiveProof(
            token_id=proof.token_id,
            merkle_root=b"\x00" * HASH_SIZE,
            root_signature=proof.root_signature,
            issuer_did=proof.issuer_did,
            revealed_fields=proof.revealed_fields,
            proofs=proof.proofs,
        )
        with pytest.raises(MerkleSignatureError):
            verify_selective_proof(tampered, issuer_public_key)

    def test_tampered_signature_raises(
        self,
        merkle_token: MerkleToken,
        issuer_public_key: bytes,
    ):
        proof = selective_reveal(merkle_token, ["verbs"])
        tampered = SelectiveProof(
            token_id=proof.token_id,
            merkle_root=proof.merkle_root,
            root_signature=b"\x00" * len(proof.root_signature),
            issuer_did=proof.issuer_did,
            revealed_fields=proof.revealed_fields,
            proofs=proof.proofs,
        )
        with pytest.raises(MerkleSignatureError):
            verify_selective_proof(tampered, issuer_public_key)


class TestCBORRoundTrip:
    def test_selective_proof_roundtrip(
        self,
        merkle_token: MerkleToken,
    ):
        original = selective_reveal(merkle_token, ["verbs", "resource", "issuer"])
        data = original.to_cbor()
        restored = SelectiveProof.from_cbor(data)
        assert restored.token_id == original.token_id
        assert restored.merkle_root == original.merkle_root
        assert restored.root_signature == original.root_signature
        assert restored.issuer_did == original.issuer_did
        assert restored.revealed_fields == original.revealed_fields
        assert len(restored.proofs) == len(original.proofs)
        for orig_p, rest_p in zip(original.proofs, restored.proofs, strict=True):
            assert orig_p.leaf_index == rest_p.leaf_index
            assert orig_p.leaf_hash == rest_p.leaf_hash
            assert orig_p.root == rest_p.root

    def test_merkle_token_roundtrip(
        self,
        merkle_token: MerkleToken,
    ):
        data = merkle_token.to_cbor()
        restored = MerkleToken.from_cbor(data)
        assert restored.token_id == merkle_token.token_id
        assert restored.merkle_root == merkle_token.merkle_root
        assert restored.root_signature == merkle_token.root_signature
        assert restored.issuer_did == merkle_token.issuer_did
        assert restored.field_values == merkle_token.field_values


class TestEndToEnd:
    def test_privacy_preserving_request(
        self,
        sample_token: CapabilityToken,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
    ):
        mt = merkleize_token(sample_token, issuer_secret_key)

        # Reveal only verbs and resource — hide constraints, chain, budget
        proof = selective_reveal(mt, ["verbs", "resource"])

        # Verify succeeds
        assert verify_selective_proof(proof, issuer_public_key) is True

        # Only two fields are visible
        assert set(proof.revealed_fields.keys()) == {"verbs", "resource"}

        # Sensitive fields are NOT present
        assert "constraints" not in proof.revealed_fields
        assert "subject" not in proof.revealed_fields
        assert "max_depth" not in proof.revealed_fields

        # Revealed values decode correctly
        verbs = decode_revealed_field("verbs", proof.revealed_fields["verbs"])
        assert set(verbs) == {"read", "write", "exec"}

        resource = decode_revealed_field("resource", proof.revealed_fields["resource"])
        assert resource == "qasp://test/resource"

    def test_decode_revealed_field_unknown(self):
        with pytest.raises(FieldNotFoundError):
            decode_revealed_field("nonexistent", b"\xa0")
