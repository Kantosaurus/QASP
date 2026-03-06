"""Non-repudiation with privacy for QASP trace entries.

Provides argument hashing (SHA-384) and auditor-only encryption
(ML-KEM-768 + AES-256-GCM) so that trace entries prove arguments
existed without revealing them. Only the auditor can decrypt
arguments during dispute resolution.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass

import cbor2

from qasp.crypto import aead, kem
from qasp.crypto.signatures import sign, verify

__all__ = [
    "PrivacyError",
    "TraceDecryptionError",
    "TraceEntry",
    "TraceVerificationError",
    "create_private_trace_entry",
    "decrypt_auditor_envelope",
    "verify_args_hash",
    "verify_trace_entry",
]


# =============================================================================
# Exceptions
# =============================================================================


class PrivacyError(Exception):
    """Base exception for privacy operations."""


class TraceVerificationError(PrivacyError):
    """Raised when trace entry signature verification fails."""


class TraceDecryptionError(PrivacyError):
    """Raised when auditor envelope decryption fails."""


# =============================================================================
# TraceEntry
# =============================================================================


@dataclass(frozen=True)
class TraceEntry:
    """An auditable trace entry with hashed and encrypted arguments.

    Fields:
        token_id: Links to the capability token.
        action: The action performed (e.g. "exec", "read").
        resource: The resource URI.
        timestamp: Unix timestamp.
        args_hash: SHA-384 digest of the original arguments (48 bytes).
        args_encrypted: CBOR-encoded auditor envelope.
        result_hash: SHA-384 digest of the result (48 bytes).
        signature: ML-DSA-65 signature over all other fields.
    """

    token_id: bytes
    action: str
    resource: str
    timestamp: int
    args_hash: bytes
    args_encrypted: bytes
    result_hash: bytes
    signature: bytes

    def signable_bytes(self) -> bytes:
        """Return CBOR-encoded bytes for signing (excludes signature)."""
        return cbor2.dumps({
            "token_id": self.token_id,
            "action": self.action,
            "resource": self.resource,
            "timestamp": self.timestamp,
            "args_hash": self.args_hash,
            "args_encrypted": self.args_encrypted,
            "result_hash": self.result_hash,
        })

    def to_cbor(self) -> bytes:
        """Serialize the full trace entry (including signature) to CBOR."""
        return cbor2.dumps({
            "token_id": self.token_id,
            "action": self.action,
            "resource": self.resource,
            "timestamp": self.timestamp,
            "args_hash": self.args_hash,
            "args_encrypted": self.args_encrypted,
            "result_hash": self.result_hash,
            "signature": self.signature,
        })

    @classmethod
    def from_cbor(cls, data: bytes) -> TraceEntry:
        """Deserialize a trace entry from CBOR."""
        d = cbor2.loads(data)
        return cls(
            token_id=bytes(d["token_id"]),
            action=d["action"],
            resource=d["resource"],
            timestamp=d["timestamp"],
            args_hash=bytes(d["args_hash"]),
            args_encrypted=bytes(d["args_encrypted"]),
            result_hash=bytes(d["result_hash"]),
            signature=bytes(d["signature"]),
        )


# =============================================================================
# Functions
# =============================================================================


def create_private_trace_entry(
    action: str,
    resource: str,
    arguments: bytes,
    result: bytes,
    auditor_kem_pk: bytes,
    signer_sk: bytes,
    token_id: bytes,
    timestamp: int | None = None,
) -> TraceEntry:
    """Create a trace entry with hashed args and auditor-encrypted envelope.

    Args:
        action: The action performed.
        resource: The resource URI.
        arguments: Raw argument bytes to hash and encrypt.
        result: Raw result bytes to hash.
        auditor_kem_pk: Auditor's ML-KEM-768 public key.
        signer_sk: Signer's ML-DSA-65 secret key.
        token_id: Capability token identifier (used as AEAD associated data).
        timestamp: Unix timestamp (defaults to current time).

    Returns:
        A signed TraceEntry.
    """
    if timestamp is None:
        timestamp = int(time.time())

    args_hash = hashlib.sha384(arguments).digest()
    result_hash = hashlib.sha384(result).digest()

    # Encrypt arguments to auditor
    kem_ct, shared_secret = kem.encapsulate(auditor_kem_pk)
    nonce, encrypted = aead.encrypt(
        shared_secret, arguments, associated_data=token_id,
    )
    args_encrypted = cbor2.dumps({
        "kem_ct": kem_ct,
        "nonce": nonce,
        "encrypted": encrypted,
    })

    # Build unsigned entry, compute signable bytes, sign
    unsigned = TraceEntry(
        token_id=token_id,
        action=action,
        resource=resource,
        timestamp=timestamp,
        args_hash=args_hash,
        args_encrypted=args_encrypted,
        result_hash=result_hash,
        signature=b"",
    )
    signature = sign(signer_sk, unsigned.signable_bytes())

    return TraceEntry(
        token_id=token_id,
        action=action,
        resource=resource,
        timestamp=timestamp,
        args_hash=args_hash,
        args_encrypted=args_encrypted,
        result_hash=result_hash,
        signature=signature,
    )


def verify_trace_entry(entry: TraceEntry, signer_pk: bytes) -> bool:
    """Verify a trace entry's ML-DSA-65 signature.

    Args:
        entry: The trace entry to verify.
        signer_pk: The signer's public key.

    Returns:
        True if valid.

    Raises:
        TraceVerificationError: If signature verification fails.
    """
    try:
        return verify(signer_pk, entry.signable_bytes(), entry.signature)
    except Exception as e:
        raise TraceVerificationError(
            f"Trace entry signature verification failed: {e}"
        ) from e


def decrypt_auditor_envelope(
    args_encrypted: bytes,
    auditor_kem_sk: bytes,
    token_id: bytes = b"",
) -> bytes:
    """Decrypt the auditor envelope to recover original arguments.

    Args:
        args_encrypted: CBOR-encoded envelope with kem_ct, nonce, encrypted.
        auditor_kem_sk: Auditor's ML-KEM-768 secret key.
        token_id: Token ID used as AEAD associated data.

    Returns:
        The original argument bytes.

    Raises:
        TraceDecryptionError: If decryption fails.
    """
    try:
        envelope = cbor2.loads(args_encrypted)
        kem_ct = bytes(envelope["kem_ct"])
        nonce = bytes(envelope["nonce"])
        encrypted = bytes(envelope["encrypted"])

        shared_secret = kem.decapsulate(auditor_kem_sk, kem_ct)
        return aead.decrypt(shared_secret, nonce, encrypted, associated_data=token_id)
    except TraceDecryptionError:
        raise
    except Exception as e:
        raise TraceDecryptionError(
            f"Failed to decrypt auditor envelope: {e}"
        ) from e


def verify_args_hash(entry: TraceEntry, original_args: bytes) -> bool:
    """Verify that original arguments match the trace entry's hash.

    Args:
        entry: The trace entry.
        original_args: The original argument bytes.

    Returns:
        True if the hash matches.
    """
    return hashlib.sha384(original_args).digest() == entry.args_hash
