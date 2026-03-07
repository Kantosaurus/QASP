"""Tests for ZK selective disclosure."""
from __future__ import annotations

import pytest

from qasp.crypto import signatures
from qasp.protocol.selective_disclosure import CANONICAL_FIELD_NAMES
from qasp.protocol.zk_disclosure import (
    InvalidZKProofError,
    ZKDisclosureError,
    create_zk_token,
    prove_field_equality,
    prove_verb_membership,
    verify_zk_proof,
)


@pytest.fixture
def issuer_keypair():
    return signatures.generate_keypair()


@pytest.fixture
def sample_token_fields():
    return {name: f"value-{name}" for name in CANONICAL_FIELD_NAMES}


class TestZKToken:
    def test_create_zk_token(self, issuer_keypair, sample_token_fields) -> None:
        pk, sk = issuer_keypair
        token = create_zk_token(
            sample_token_fields, sk, "did:qasp:issuer", b"token123"
        )
        assert token.token_id == b"token123"
        assert len(token.commitments) == len(CANONICAL_FIELD_NAMES)
        assert len(token.blindings) == len(CANONICAL_FIELD_NAMES)

    def test_equality_proof(self, issuer_keypair, sample_token_fields) -> None:
        pk, sk = issuer_keypair
        token = create_zk_token(
            sample_token_fields, sk, "did:qasp:issuer", b"token123"
        )
        proof = prove_field_equality(token, "issuer", sample_token_fields["issuer"])
        result = verify_zk_proof(
            proof, pk, token.commitments, token.issuer_signature
        )
        assert result is True

    def test_equality_proof_wrong_value(
        self, issuer_keypair, sample_token_fields
    ) -> None:
        pk, sk = issuer_keypair
        token = create_zk_token(
            sample_token_fields, sk, "did:qasp:issuer", b"token123"
        )
        # Prove equality to wrong value - this should create a valid-looking
        # proof but verification should fail
        proof = prove_field_equality(token, "issuer", "wrong-value")
        with pytest.raises(InvalidZKProofError):
            verify_zk_proof(proof, pk, token.commitments, token.issuer_signature)

    def test_membership_proof(self, issuer_keypair, sample_token_fields) -> None:
        pk, sk = issuer_keypair
        token = create_zk_token(
            sample_token_fields, sk, "did:qasp:issuer", b"token123"
        )
        proof = prove_verb_membership(token, "some-verb")
        result = verify_zk_proof(
            proof, pk, token.commitments, token.issuer_signature
        )
        assert result is True

    def test_unknown_field_raises(
        self, issuer_keypair, sample_token_fields
    ) -> None:
        pk, sk = issuer_keypair
        token = create_zk_token(
            sample_token_fields, sk, "did:qasp:issuer", b"token123"
        )
        with pytest.raises(ZKDisclosureError):
            prove_field_equality(token, "nonexistent_field", "value")

    def test_wrong_issuer_key_fails(
        self, issuer_keypair, sample_token_fields
    ) -> None:
        pk, sk = issuer_keypair
        token = create_zk_token(
            sample_token_fields, sk, "did:qasp:issuer", b"token123"
        )
        proof = prove_field_equality(
            token, "issuer", sample_token_fields["issuer"]
        )

        other_pk, _ = signatures.generate_keypair()
        with pytest.raises(InvalidZKProofError):
            verify_zk_proof(
                proof, other_pk, token.commitments, token.issuer_signature
            )
