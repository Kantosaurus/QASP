"""Tests for did:qasp DID implementation."""

from __future__ import annotations

import json

import pytest

from qasp.crypto import signatures
from qasp.crypto.exceptions import InvalidKeyError
from qasp.identity import (
    DID,
    DIDDocument,
    DIDRegistry,
    VerificationMethod,
    create_did,
    decode_public_key_multibase,
    encode_public_key_multibase,
    get_registry,
    resolve_did,
    verify_did,
    verify_did_signature,
)
from qasp.identity.exceptions import DIDResolutionError, InvalidDIDError


class TestDIDGeneration:
    """Tests for DID creation and generation."""

    def test_create_did_returns_tuple(self, agent_public_key: bytes) -> None:
        """create_did returns a tuple of (DID, DIDDocument)."""
        result = create_did(agent_public_key)
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], DID)
        assert isinstance(result[1], DIDDocument)

    def test_did_format(self, agent_public_key: bytes) -> None:
        """DID has correct format: did:qasp:<identifier>."""
        did, _ = create_did(agent_public_key)
        did_str = str(did)
        assert did_str.startswith("did:qasp:")
        assert len(did_str) > len("did:qasp:")

    def test_did_method_is_qasp(self, agent_public_key: bytes) -> None:
        """DID method is 'qasp'."""
        did, _ = create_did(agent_public_key)
        assert did.method == "qasp"

    def test_did_identifier_is_base58(self, agent_public_key: bytes) -> None:
        """DID identifier is valid Base58btc."""
        import base58

        did, _ = create_did(agent_public_key)
        # Should not raise
        decoded = base58.b58decode(did.identifier)
        assert len(decoded) == 32  # SHA-384 truncated to 32 bytes

    def test_did_is_deterministic(self, agent_public_key: bytes) -> None:
        """Same public key produces same DID."""
        did1, _ = create_did(agent_public_key)
        did2, _ = create_did(agent_public_key)
        assert str(did1) == str(did2)

    def test_different_keys_produce_different_dids(self) -> None:
        """Different public keys produce different DIDs."""
        pk1, _ = signatures.generate_keypair()
        pk2, _ = signatures.generate_keypair()
        did1, _ = create_did(pk1)
        did2, _ = create_did(pk2)
        assert str(did1) != str(did2)

    def test_create_did_validates_key_size(self) -> None:
        """create_did raises InvalidKeyError for wrong key size."""
        with pytest.raises(InvalidKeyError):
            create_did(b"too_short")

    def test_create_did_with_invalid_key_type(self) -> None:
        """create_did raises with completely wrong key size."""
        with pytest.raises(InvalidKeyError) as exc_info:
            create_did(b"\x00" * 100)
        assert "Invalid public key size" in str(exc_info.value)


class TestDIDParsing:
    """Tests for DID string parsing."""

    def test_parse_valid_did(self, agent_public_key: bytes) -> None:
        """Parse a valid DID string."""
        did, _ = create_did(agent_public_key)
        did_str = str(did)
        parsed = DID.parse(did_str)
        assert parsed == did

    def test_parse_empty_string_fails(self) -> None:
        """Parsing empty string raises InvalidDIDError."""
        with pytest.raises(InvalidDIDError) as exc_info:
            DID.parse("")
        assert "Empty DID string" in str(exc_info.value)

    def test_parse_wrong_scheme_fails(self) -> None:
        """Parsing DID with wrong scheme raises InvalidDIDError."""
        with pytest.raises(InvalidDIDError) as exc_info:
            DID.parse("uri:qasp:abc123")
        assert "Invalid DID scheme" in str(exc_info.value)

    def test_parse_wrong_method_fails(self) -> None:
        """Parsing DID with unsupported method raises InvalidDIDError."""
        with pytest.raises(InvalidDIDError) as exc_info:
            DID.parse("did:key:abc123")
        assert "Unsupported DID method" in str(exc_info.value)

    def test_parse_missing_identifier_fails(self) -> None:
        """Parsing DID without identifier raises InvalidDIDError."""
        with pytest.raises(InvalidDIDError) as exc_info:
            DID.parse("did:qasp:")
        assert "Empty DID identifier" in str(exc_info.value)

    def test_parse_too_few_parts_fails(self) -> None:
        """Parsing DID with wrong format raises InvalidDIDError."""
        with pytest.raises(InvalidDIDError) as exc_info:
            DID.parse("did:qasp")
        assert "Invalid DID format" in str(exc_info.value)

    def test_parse_invalid_base58_fails(self) -> None:
        """Parsing DID with invalid Base58 identifier raises InvalidDIDError."""
        with pytest.raises(InvalidDIDError) as exc_info:
            DID.parse("did:qasp:invalid0OIl")  # 0, O, I, l are not valid Base58
        assert "Invalid Base58btc identifier" in str(exc_info.value)


class TestDIDDocument:
    """Tests for DID document structure and serialization."""

    def test_document_has_did(self, agent_public_key: bytes) -> None:
        """DID document contains the DID."""
        did, doc = create_did(agent_public_key)
        assert doc.did == did

    def test_document_has_verification_method(self, agent_public_key: bytes) -> None:
        """DID document has verification methods."""
        _, doc = create_did(agent_public_key)
        assert len(doc.verification_methods) == 1
        vm = doc.verification_methods[0]
        assert isinstance(vm, VerificationMethod)

    def test_verification_method_type(self, agent_public_key: bytes) -> None:
        """Verification method has correct type."""
        _, doc = create_did(agent_public_key)
        vm = doc.verification_methods[0]
        assert vm.type == "MLDSAVerificationKey2025"

    def test_verification_method_has_multibase_key(self, agent_public_key: bytes) -> None:
        """Verification method has multibase-encoded public key."""
        _, doc = create_did(agent_public_key)
        vm = doc.verification_methods[0]
        assert vm.public_key_multibase.startswith("z")

    def test_document_has_authentication(self, agent_public_key: bytes) -> None:
        """DID document has authentication relationship."""
        did, doc = create_did(agent_public_key)
        assert len(doc.authentication) == 1
        assert doc.authentication[0] == f"{did}#key-1"

    def test_document_has_assertion_method(self, agent_public_key: bytes) -> None:
        """DID document has assertionMethod relationship."""
        did, doc = create_did(agent_public_key)
        assert len(doc.assertion_method) == 1
        assert doc.assertion_method[0] == f"{did}#key-1"

    def test_document_to_dict_has_context(self, agent_public_key: bytes) -> None:
        """DID document serializes with @context."""
        _, doc = create_did(agent_public_key)
        doc_dict = doc.to_dict()
        assert "@context" in doc_dict
        assert "https://www.w3.org/ns/did/v1" in doc_dict["@context"]
        assert "https://w3id.org/security/suites/mldsa-2025/v1" in doc_dict["@context"]

    def test_document_to_dict_has_id(self, agent_public_key: bytes) -> None:
        """DID document serializes with id."""
        did, doc = create_did(agent_public_key)
        doc_dict = doc.to_dict()
        assert doc_dict["id"] == str(did)

    def test_document_to_dict_has_verification_method(self, agent_public_key: bytes) -> None:
        """DID document serializes verificationMethod correctly."""
        did, doc = create_did(agent_public_key)
        doc_dict = doc.to_dict()
        assert "verificationMethod" in doc_dict
        vm = doc_dict["verificationMethod"][0]
        assert vm["id"] == f"{did}#key-1"
        assert vm["type"] == "MLDSAVerificationKey2025"
        assert vm["controller"] == str(did)
        assert "publicKeyMultibase" in vm

    def test_document_to_json(self, agent_public_key: bytes) -> None:
        """DID document serializes to valid JSON."""
        _, doc = create_did(agent_public_key)
        json_str = doc.to_json()
        # Should not raise
        parsed = json.loads(json_str)
        assert isinstance(parsed, dict)

    def test_document_get_public_key(self, agent_public_key: bytes) -> None:
        """Can extract public key from DID document."""
        _, doc = create_did(agent_public_key)
        extracted_key = doc.get_public_key()
        assert extracted_key == agent_public_key

    def test_document_get_public_key_by_id(self, agent_public_key: bytes) -> None:
        """Can extract public key by verification method ID."""
        did, doc = create_did(agent_public_key)
        key_id = f"{did}#key-1"
        extracted_key = doc.get_public_key(key_id)
        assert extracted_key == agent_public_key

    def test_document_get_public_key_not_found(self, agent_public_key: bytes) -> None:
        """Raises InvalidDIDError for unknown key ID."""
        _, doc = create_did(agent_public_key)
        with pytest.raises(InvalidDIDError) as exc_info:
            doc.get_public_key("did:qasp:unknown#key-1")
        assert "Verification method not found" in str(exc_info.value)


class TestDIDVerification:
    """Tests for DID key matching and signature verification."""

    def test_verify_did_with_matching_key(
        self, agent_public_key: bytes, sample_agent_did: DID
    ) -> None:
        """verify_did returns True for matching key."""
        assert verify_did(sample_agent_did, agent_public_key)

    def test_verify_did_with_wrong_key(self, sample_agent_did: DID) -> None:
        """verify_did returns False for wrong key."""
        other_pk, _ = signatures.generate_keypair()
        assert not verify_did(sample_agent_did, other_pk)

    def test_verify_did_with_invalid_key(self, sample_agent_did: DID) -> None:
        """verify_did returns False for invalid key size."""
        assert not verify_did(sample_agent_did, b"short")

    def test_did_verify_key_method(
        self, agent_public_key: bytes, sample_agent_did: DID
    ) -> None:
        """DID.verify_key() works correctly."""
        assert sample_agent_did.verify_key(agent_public_key)

    def test_verify_did_signature(
        self, agent_public_key: bytes, agent_secret_key: bytes
    ) -> None:
        """Can verify signatures using DID document."""
        _, doc = create_did(agent_public_key)
        message = b"test message"
        signature = signatures.sign(agent_secret_key, message)
        assert verify_did_signature(doc, message, signature)

    def test_verify_did_signature_wrong_message(
        self, agent_public_key: bytes, agent_secret_key: bytes
    ) -> None:
        """Signature verification fails for wrong message."""
        from qasp.crypto.exceptions import InvalidSignatureError

        _, doc = create_did(agent_public_key)
        message = b"test message"
        signature = signatures.sign(agent_secret_key, message)
        with pytest.raises(InvalidSignatureError):
            verify_did_signature(doc, b"different message", signature)


class TestMultibaseEncoding:
    """Tests for multibase public key encoding."""

    def test_encode_public_key_multibase(self, agent_public_key: bytes) -> None:
        """encode_public_key_multibase produces correct format."""
        encoded = encode_public_key_multibase(agent_public_key)
        assert encoded.startswith("z")  # Base58btc prefix
        assert len(encoded) > 1

    def test_decode_public_key_multibase(self, agent_public_key: bytes) -> None:
        """decode_public_key_multibase recovers original key."""
        encoded = encode_public_key_multibase(agent_public_key)
        decoded = decode_public_key_multibase(encoded)
        assert decoded == agent_public_key

    def test_roundtrip(self, agent_public_key: bytes) -> None:
        """Encode-decode roundtrip preserves key."""
        encoded = encode_public_key_multibase(agent_public_key)
        decoded = decode_public_key_multibase(encoded)
        assert decoded == agent_public_key

    def test_encode_invalid_key_size(self) -> None:
        """encode_public_key_multibase raises for wrong key size."""
        with pytest.raises(InvalidKeyError):
            encode_public_key_multibase(b"short")

    def test_decode_wrong_prefix(self) -> None:
        """decode_public_key_multibase raises for wrong multibase prefix."""
        with pytest.raises(InvalidKeyError) as exc_info:
            decode_public_key_multibase("mABC123")  # 'm' is base64
        assert "Invalid multibase prefix" in str(exc_info.value)

    def test_decode_invalid_base58(self) -> None:
        """decode_public_key_multibase raises for invalid Base58."""
        with pytest.raises(InvalidKeyError) as exc_info:
            decode_public_key_multibase("z0OIl")  # Invalid Base58 chars
        assert "Invalid Base58btc encoding" in str(exc_info.value)


class TestDIDRegistry:
    """Tests for DID registry operations."""

    def test_register_and_lookup(self, agent_public_key: bytes) -> None:
        """Can register and look up DID documents."""
        did, doc = create_did(agent_public_key)
        registry = DIDRegistry()
        registry.register(doc)
        retrieved = registry.lookup(did)
        assert retrieved == doc

    def test_lookup_string_did(self, agent_public_key: bytes) -> None:
        """Can look up by string DID."""
        did, doc = create_did(agent_public_key)
        registry = DIDRegistry()
        registry.register(doc)
        retrieved = registry.lookup(str(did))
        assert retrieved == doc

    def test_lookup_not_found(self) -> None:
        """Raises DIDResolutionError for unknown DID."""
        registry = DIDRegistry()
        with pytest.raises(DIDResolutionError) as exc_info:
            registry.lookup("did:qasp:unknown")
        assert "DID not found" in str(exc_info.value)

    def test_remove(self, agent_public_key: bytes) -> None:
        """Can remove DID from registry."""
        did, doc = create_did(agent_public_key)
        registry = DIDRegistry()
        registry.register(doc)
        assert registry.remove(did)
        with pytest.raises(DIDResolutionError):
            registry.lookup(did)

    def test_remove_not_found(self) -> None:
        """Remove returns False for unknown DID."""
        registry = DIDRegistry()
        assert not registry.remove("did:qasp:unknown")

    def test_clear(self, agent_public_key: bytes) -> None:
        """Can clear all DIDs from registry."""
        did, doc = create_did(agent_public_key)
        registry = DIDRegistry()
        registry.register(doc)
        registry.clear()
        assert len(registry) == 0

    def test_contains(self, agent_public_key: bytes) -> None:
        """Can check if DID is registered."""
        did, doc = create_did(agent_public_key)
        registry = DIDRegistry()
        assert did not in registry
        registry.register(doc)
        assert did in registry

    def test_len(self, agent_public_key: bytes) -> None:
        """Can get registry size."""
        did, doc = create_did(agent_public_key)
        registry = DIDRegistry()
        assert len(registry) == 0
        registry.register(doc)
        assert len(registry) == 1

    def test_global_registry(self, agent_public_key: bytes) -> None:
        """Global registry singleton works."""
        registry = get_registry()
        registry.clear()  # Clean state

        did, doc = create_did(agent_public_key)
        registry.register(doc)

        # Should be same registry
        retrieved = resolve_did(did)
        assert retrieved == doc

        # Cleanup
        registry.clear()
