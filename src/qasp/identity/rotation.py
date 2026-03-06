"""DID key rotation with pre-committed next-key hashes and dual-signature proofs.

This module implements secure key rotation for did:qasp identifiers.
Rotation requires:
1. Pre-commitment: hash of next public key stored in current DID document
2. Dual-signature proof: signed by both old and new keys
3. Version increment: monotonically increasing key version

The rotation flow:
    1. commit_next_key(document, next_pk) -> updated document with hash
    2. create_rotation_proof(document, old_sk, new_pk, new_sk) -> proof
    3. verify_rotation_proof(proof, document) -> bool
    4. rotate_key(proof, document, registry) -> new document
"""

from __future__ import annotations

import dataclasses
import hashlib
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

import cbor2

from qasp.crypto.signatures import sign, verify
from qasp.identity.did import (
    DIDDocument,
    VerificationMethod,
    encode_public_key_multibase,
)
from qasp.identity.exceptions import KeyRotationError

if TYPE_CHECKING:
    from qasp.identity.did import DID, DIDRegistry

__all__ = [
    "KeyRotationProof",
    "commit_next_key",
    "create_rotation_proof",
    "rotate_key",
    "verify_rotation_proof",
]


@dataclass(frozen=True)
class KeyRotationProof:
    """Proof of a DID key rotation.

    Attributes:
        did: The DID being rotated.
        new_public_key: The new public key.
        old_key_version: The version of the old key.
        new_key_version: The version of the new key.
        timestamp: Unix timestamp of the rotation.
        old_key_signature: Signature by the old key over the rotation payload.
        new_key_signature: Signature by the new key over the rotation payload.
    """

    did: DID
    new_public_key: bytes
    old_key_version: int
    new_key_version: int
    timestamp: int
    old_key_signature: bytes
    new_key_signature: bytes


def _encode_rotation_payload(
    did: DID,
    new_public_key: bytes,
    old_key_version: int,
    new_key_version: int,
    timestamp: int,
) -> bytes:
    """CBOR-encode the signable rotation payload."""
    payload = {
        "did": str(did),
        "new_public_key": new_public_key,
        "old_key_version": old_key_version,
        "new_key_version": new_key_version,
        "timestamp": timestamp,
    }
    return cbor2.dumps(payload)


def commit_next_key(document: DIDDocument, next_public_key: bytes) -> DIDDocument:
    """Pre-commit the hash of the next public key in the DID document.

    Args:
        document: The current DID document.
        next_public_key: The next public key to commit.

    Returns:
        A new DIDDocument with next_key_hash set to SHA-384(next_public_key).
    """
    key_hash = hashlib.sha384(next_public_key).digest()
    return dataclasses.replace(document, next_key_hash=key_hash)


def create_rotation_proof(
    document: DIDDocument,
    old_secret_key: bytes,
    new_public_key: bytes,
    new_secret_key: bytes,
) -> KeyRotationProof:
    """Create a dual-signed key rotation proof.

    Args:
        document: The current DID document (must have next_key_hash set).
        old_secret_key: The current (old) secret key.
        new_public_key: The new public key.
        new_secret_key: The new secret key.

    Returns:
        A KeyRotationProof with dual signatures.

    Raises:
        KeyRotationError: If pre-commitment is missing or doesn't match.
    """
    if document.next_key_hash is None:
        raise KeyRotationError("No pre-committed next key hash in document")

    # Verify pre-commitment
    expected_hash = hashlib.sha384(new_public_key).digest()
    if document.next_key_hash != expected_hash:
        raise KeyRotationError("New public key does not match pre-committed hash")

    ts = int(time.time())
    new_version = document.key_version + 1

    payload = _encode_rotation_payload(
        did=document.did,
        new_public_key=new_public_key,
        old_key_version=document.key_version,
        new_key_version=new_version,
        timestamp=ts,
    )

    old_sig = sign(old_secret_key, payload)
    new_sig = sign(new_secret_key, payload)

    return KeyRotationProof(
        did=document.did,
        new_public_key=new_public_key,
        old_key_version=document.key_version,
        new_key_version=new_version,
        timestamp=ts,
        old_key_signature=old_sig,
        new_key_signature=new_sig,
    )


def verify_rotation_proof(proof: KeyRotationProof, document: DIDDocument) -> bool:
    """Verify a key rotation proof.

    Checks:
    1. Pre-commitment hash matches
    2. Version increment is exactly +1
    3. Old key signature is valid
    4. New key signature is valid

    Args:
        proof: The rotation proof to verify.
        document: The current DID document.

    Returns:
        True if the proof is valid.

    Raises:
        KeyRotationError: If verification fails.
    """
    # Check pre-commitment
    if document.next_key_hash is None:
        raise KeyRotationError("No pre-committed next key hash in document")

    expected_hash = hashlib.sha384(proof.new_public_key).digest()
    if document.next_key_hash != expected_hash:
        raise KeyRotationError("New public key does not match pre-committed hash")

    # Check version increment
    if proof.new_key_version != document.key_version + 1:
        raise KeyRotationError(
            f"Invalid version increment: expected {document.key_version + 1}, "
            f"got {proof.new_key_version}"
        )

    # Reconstruct payload
    payload = _encode_rotation_payload(
        did=proof.did,
        new_public_key=proof.new_public_key,
        old_key_version=proof.old_key_version,
        new_key_version=proof.new_key_version,
        timestamp=proof.timestamp,
    )

    # Verify old key signature
    old_public_key = document.get_public_key()
    try:
        verify(old_public_key, payload, proof.old_key_signature)
    except Exception as e:
        raise KeyRotationError(f"Old key signature verification failed: {e}") from e

    # Verify new key signature
    try:
        verify(proof.new_public_key, payload, proof.new_key_signature)
    except Exception as e:
        raise KeyRotationError(f"New key signature verification failed: {e}") from e

    return True


def rotate_key(
    proof: KeyRotationProof,
    document: DIDDocument,
    registry: DIDRegistry | None = None,
) -> DIDDocument:
    """Apply a verified rotation proof to create an updated DID document.

    Args:
        proof: The verified rotation proof.
        document: The current DID document.
        registry: Optional DID registry to update.

    Returns:
        A new DIDDocument with the rotated key.

    Raises:
        KeyRotationError: If the proof is invalid.
    """
    verify_rotation_proof(proof, document)

    did_string = str(document.did)
    new_key_id = f"{did_string}#key-{proof.new_key_version}"

    new_vm = VerificationMethod(
        id=new_key_id,
        type="MLDSAVerificationKey2025",
        controller=did_string,
        public_key_multibase=encode_public_key_multibase(proof.new_public_key),
    )

    new_document = dataclasses.replace(
        document,
        verification_methods=(new_vm,),
        authentication=(new_key_id,),
        assertion_method=(new_key_id,),
        key_version=proof.new_key_version,
        next_key_hash=None,
    )

    if registry is not None:
        registry.register(new_document)

    return new_document
