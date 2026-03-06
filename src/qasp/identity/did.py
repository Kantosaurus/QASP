"""did:qasp decentralized identifiers.

This module implements the did:qasp DID method for AI agent identity.
DIDs are derived from ML-DSA-65 public keys using SHA-384 and Base58btc encoding.

DID Format: did:qasp:<identifier>
Where <identifier> is Base58btc(SHA-384(public_key)[0:32])

Example: did:qasp:2ZTp9sZYQnVTQzGK8hA5zUQvZk7DhY4zRvJpPvjnL7bE
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from typing import Any

import base58

from qasp.crypto.exceptions import InvalidKeyError
from qasp.crypto.signatures import (
    ML_DSA_65_PUBLIC_KEY_SIZE,
    verify,
)
from qasp.identity.exceptions import DIDResolutionError, InvalidDIDError

__all__ = [
    "DID",
    "DIDDocument",
    "DIDRegistry",
    "VerificationMethod",
    "create_did",
    "decode_public_key_multibase",
    "encode_public_key_multibase",
    "get_registry",
    "resolve_did",
    "verify_did",
    "verify_did_signature",
]

# Multicodec prefix for ML-DSA-65 public key (0x1318)
# See: https://github.com/multiformats/multicodec
MULTICODEC_MLDSA65 = bytes([0x13, 0x18])

# Multibase prefix for Base58btc encoding
MULTIBASE_BASE58BTC = "z"

# JSON-LD contexts for DID documents
DID_CONTEXT = "https://www.w3.org/ns/did/v1"
MLDSA_CONTEXT = "https://w3id.org/security/suites/mldsa-2025/v1"


def _compute_identifier(public_key: bytes) -> str:
    """Compute the DID identifier from a public key.

    Args:
        public_key: The ML-DSA-65 public key (1952 bytes).

    Returns:
        Base58btc-encoded identifier string.
    """
    hash_bytes = hashlib.sha384(public_key).digest()
    truncated = hash_bytes[:32]  # First 32 bytes
    encoded: bytes = base58.b58encode(truncated)
    return encoded.decode("ascii")


def encode_public_key_multibase(public_key: bytes) -> str:
    """Encode a public key using multibase (Base58btc with multicodec prefix).

    Args:
        public_key: The ML-DSA-65 public key (1952 bytes).

    Returns:
        Multibase-encoded string starting with 'z'.

    Raises:
        InvalidKeyError: If the public key has invalid size.
    """
    if len(public_key) != ML_DSA_65_PUBLIC_KEY_SIZE:
        raise InvalidKeyError(
            f"Invalid public key size: expected {ML_DSA_65_PUBLIC_KEY_SIZE}, "
            f"got {len(public_key)}"
        )
    encoded_bytes: bytes = base58.b58encode(MULTICODEC_MLDSA65 + public_key)
    return MULTIBASE_BASE58BTC + encoded_bytes.decode("ascii")


def decode_public_key_multibase(multibase_key: str) -> bytes:
    """Decode a multibase-encoded public key.

    Args:
        multibase_key: The multibase string (starting with 'z').

    Returns:
        The decoded public key bytes.

    Raises:
        InvalidKeyError: If the multibase encoding is invalid.
    """
    if not multibase_key.startswith(MULTIBASE_BASE58BTC):
        raise InvalidKeyError(
            f"Invalid multibase prefix: expected '{MULTIBASE_BASE58BTC}', "
            f"got '{multibase_key[0] if multibase_key else ''}'"
        )

    try:
        decoded: bytes = base58.b58decode(multibase_key[1:])
    except Exception as e:
        raise InvalidKeyError(f"Invalid Base58btc encoding: {e}") from e

    if len(decoded) < len(MULTICODEC_MLDSA65):
        raise InvalidKeyError("Decoded data too short for multicodec prefix")

    if decoded[: len(MULTICODEC_MLDSA65)] != MULTICODEC_MLDSA65:
        raise InvalidKeyError("Invalid multicodec prefix for ML-DSA-65")

    public_key = bytes(decoded[len(MULTICODEC_MLDSA65) :])

    if len(public_key) != ML_DSA_65_PUBLIC_KEY_SIZE:
        raise InvalidKeyError(
            f"Invalid public key size: expected {ML_DSA_65_PUBLIC_KEY_SIZE}, "
            f"got {len(public_key)}"
        )

    return public_key


@dataclass(frozen=True)
class DID:
    """A did:qasp decentralized identifier.

    Attributes:
        method: The DID method (always "qasp").
        identifier: The Base58btc-encoded identifier.
    """

    method: str = "qasp"
    identifier: str = ""

    def __str__(self) -> str:
        """Return the DID string representation."""
        return f"did:{self.method}:{self.identifier}"

    def __hash__(self) -> int:
        """Return hash for use in sets and dicts."""
        return hash((self.method, self.identifier))

    @classmethod
    def parse(cls, did_string: str) -> DID:
        """Parse a DID string.

        Args:
            did_string: The DID string (e.g., "did:qasp:abc123").

        Returns:
            A DID instance.

        Raises:
            InvalidDIDError: If the DID string is malformed.
        """
        if not did_string:
            raise InvalidDIDError("Empty DID string")

        parts = did_string.split(":")
        if len(parts) != 3:
            raise InvalidDIDError(
                f"Invalid DID format: expected 'did:method:identifier', got '{did_string}'"
            )

        scheme, method, identifier = parts

        if scheme != "did":
            raise InvalidDIDError(f"Invalid DID scheme: expected 'did', got '{scheme}'")

        if method != "qasp":
            raise InvalidDIDError(f"Unsupported DID method: expected 'qasp', got '{method}'")

        if not identifier:
            raise InvalidDIDError("Empty DID identifier")

        # Validate identifier is valid Base58btc
        try:
            base58.b58decode(identifier)
        except Exception as e:
            raise InvalidDIDError(f"Invalid Base58btc identifier: {e}") from e

        return cls(method=method, identifier=identifier)

    def verify_key(self, public_key: bytes) -> bool:
        """Verify that this DID was derived from the given public key.

        Args:
            public_key: The public key to verify against.

        Returns:
            True if the public key matches this DID's identifier.
        """
        if len(public_key) != ML_DSA_65_PUBLIC_KEY_SIZE:
            return False
        expected_identifier = _compute_identifier(public_key)
        return self.identifier == expected_identifier


@dataclass(frozen=True)
class VerificationMethod:
    """A DID verification method entry.

    Attributes:
        id: The verification method ID (e.g., "did:qasp:abc#key-1").
        type: The key type (e.g., "MLDSAVerificationKey2025").
        controller: The DID that controls this key.
        public_key_multibase: The multibase-encoded public key.
    """

    id: str
    type: str
    controller: str
    public_key_multibase: str

    def to_dict(self) -> dict[str, str]:
        """Convert to JSON-serializable dictionary."""
        return {
            "id": self.id,
            "type": self.type,
            "controller": self.controller,
            "publicKeyMultibase": self.public_key_multibase,
        }

    def get_public_key(self) -> bytes:
        """Extract the public key from the multibase encoding.

        Returns:
            The decoded public key bytes.

        Raises:
            InvalidKeyError: If the key cannot be decoded.
        """
        return decode_public_key_multibase(self.public_key_multibase)


@dataclass(frozen=True)
class DIDDocument:
    """A DID document containing verification methods and relationships.

    Attributes:
        did: The DID this document describes.
        verification_methods: List of verification methods.
        authentication: List of verification method IDs for authentication.
        assertion_method: List of verification method IDs for assertions.
        service_endpoints: Optional service endpoint mappings.
    """

    did: DID
    verification_methods: tuple[VerificationMethod, ...] = field(default_factory=tuple)
    authentication: tuple[str, ...] = field(default_factory=tuple)
    assertion_method: tuple[str, ...] = field(default_factory=tuple)
    service_endpoints: dict[str, str] = field(default_factory=dict)
    next_key_hash: bytes | None = None
    key_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-LD dictionary.

        Returns:
            A dictionary suitable for JSON serialization.
        """
        doc: dict[str, Any] = {
            "@context": [DID_CONTEXT, MLDSA_CONTEXT],
            "id": str(self.did),
        }

        if self.verification_methods:
            doc["verificationMethod"] = [vm.to_dict() for vm in self.verification_methods]

        if self.authentication:
            doc["authentication"] = list(self.authentication)

        if self.assertion_method:
            doc["assertionMethod"] = list(self.assertion_method)

        if self.service_endpoints:
            doc["service"] = [
                {"id": f"{self.did}#service-{i}", "type": stype, "serviceEndpoint": endpoint}
                for i, (stype, endpoint) in enumerate(self.service_endpoints.items())
            ]

        if self.next_key_hash is not None:
            doc["nextKeyHash"] = self.next_key_hash.hex()
        doc["keyVersion"] = self.key_version

        return doc

    def to_json(self, indent: int | None = 2) -> str:
        """Convert to JSON-LD string.

        Args:
            indent: JSON indentation level (None for compact).

        Returns:
            A JSON string representation.
        """
        return json.dumps(self.to_dict(), indent=indent)

    def get_public_key(self, key_id: str | None = None) -> bytes:
        """Get a public key from the document.

        Args:
            key_id: The verification method ID, or None for the first key.

        Returns:
            The public key bytes.

        Raises:
            InvalidDIDError: If the key is not found.
        """
        if not self.verification_methods:
            raise InvalidDIDError("DID document has no verification methods")

        if key_id is None:
            return self.verification_methods[0].get_public_key()

        for vm in self.verification_methods:
            if vm.id == key_id:
                return vm.get_public_key()

        raise InvalidDIDError(f"Verification method not found: {key_id}")


def create_did(public_key: bytes) -> tuple[DID, DIDDocument]:
    """Create a new did:qasp identifier and document.

    The DID identifier is computed as:
        identifier = Base58btc(SHA-384(public_key)[0:32])

    Args:
        public_key: The ML-DSA-65 public key (1952 bytes).

    Returns:
        Tuple of (DID, DIDDocument).

    Raises:
        InvalidKeyError: If the public key has invalid size.
    """
    if len(public_key) != ML_DSA_65_PUBLIC_KEY_SIZE:
        raise InvalidKeyError(
            f"Invalid public key size: expected {ML_DSA_65_PUBLIC_KEY_SIZE}, "
            f"got {len(public_key)}"
        )

    identifier = _compute_identifier(public_key)
    did = DID(method="qasp", identifier=identifier)
    did_string = str(did)

    # Create verification method
    verification_method = VerificationMethod(
        id=f"{did_string}#key-1",
        type="MLDSAVerificationKey2025",
        controller=did_string,
        public_key_multibase=encode_public_key_multibase(public_key),
    )

    # Create document
    document = DIDDocument(
        did=did,
        verification_methods=(verification_method,),
        authentication=(f"{did_string}#key-1",),
        assertion_method=(f"{did_string}#key-1",),
    )

    return did, document


def verify_did(did: DID, public_key: bytes) -> bool:
    """Verify that a DID matches a public key.

    Args:
        did: The DID to verify.
        public_key: The public key to verify against.

    Returns:
        True if the public key matches the DID.
    """
    return did.verify_key(public_key)


def verify_did_signature(
    did_document: DIDDocument,
    message: bytes,
    signature: bytes,
    key_id: str | None = None,
) -> bool:
    """Verify a signature using a DID document.

    Args:
        did_document: The signer's DID document.
        message: The signed message.
        signature: The signature to verify.
        key_id: The verification method ID, or None for the first key.

    Returns:
        True if the signature is valid.

    Raises:
        InvalidDIDError: If the key is not found in the document.
        InvalidSignatureError: If the signature is invalid.
    """
    public_key = did_document.get_public_key(key_id)
    return verify(public_key, message, signature)


class DIDRegistry:
    """Thread-safe registry for DID documents.

    Provides a simple in-memory registry for looking up DID documents.
    In production, this would be backed by a distributed ledger or DHT.
    """

    def __init__(self) -> None:
        """Initialize an empty registry."""
        self._lock = threading.Lock()
        self._documents: dict[str, DIDDocument] = {}

    def register(self, document: DIDDocument) -> None:
        """Register a DID document.

        Args:
            document: The DID document to register.
        """
        with self._lock:
            self._documents[str(document.did)] = document

    def lookup(self, did: DID | str) -> DIDDocument:
        """Look up a DID document.

        Args:
            did: The DID to look up.

        Returns:
            The DID document.

        Raises:
            DIDResolutionError: If the DID is not found.
        """
        did_string = str(did) if isinstance(did, DID) else did
        with self._lock:
            document = self._documents.get(did_string)
        if document is None:
            raise DIDResolutionError(f"DID not found: {did_string}")
        return document

    def remove(self, did: DID | str) -> bool:
        """Remove a DID document from the registry.

        Args:
            did: The DID to remove.

        Returns:
            True if the DID was removed, False if not found.
        """
        did_string = str(did) if isinstance(did, DID) else did
        with self._lock:
            if did_string in self._documents:
                del self._documents[did_string]
                return True
            return False

    def clear(self) -> None:
        """Remove all DID documents from the registry."""
        with self._lock:
            self._documents.clear()

    def __contains__(self, did: DID | str) -> bool:
        """Check if a DID is registered."""
        did_string = str(did) if isinstance(did, DID) else did
        with self._lock:
            return did_string in self._documents

    def __len__(self) -> int:
        """Return the number of registered DIDs."""
        with self._lock:
            return len(self._documents)


# Module-level singleton registry
_registry: DIDRegistry | None = None
_registry_lock = threading.Lock()


def get_registry() -> DIDRegistry:
    """Get the module-level DID registry singleton.

    Returns:
        The shared DIDRegistry instance.
    """
    global _registry
    if _registry is None:
        with _registry_lock:
            if _registry is None:
                _registry = DIDRegistry()
    return _registry


def resolve_did(did: DID | str) -> DIDDocument:
    """Resolve a DID to its document using the global registry.

    Args:
        did: The DID to resolve.

    Returns:
        The DID document.

    Raises:
        DIDResolutionError: If the DID cannot be resolved.
    """
    return get_registry().lookup(did)
