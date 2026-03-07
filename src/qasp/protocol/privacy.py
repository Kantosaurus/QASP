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
    "POE_FAILURE",
    "POE_SUCCESS",
    "POE_VIOLATION",
    "PoEChain",
    "PoEChainError",
    "PrivacyError",
    "ProofOfExecution",
    "TraceDecryptionError",
    "TraceEntry",
    "TraceVerificationError",
    "create_private_trace_entry",
    "create_proof_of_execution",
    "decrypt_auditor_envelope",
    "verify_args_hash",
    "verify_proof_of_execution",
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


# =============================================================================
# Proof of Execution (Section 10.5.5)
# =============================================================================

POE_SUCCESS = "success"
POE_FAILURE = "failure"
POE_VIOLATION = "violation"


class PoEChainError(PrivacyError):
    """Raised when PoE chain validation fails."""


@dataclass(frozen=True)
class ProofOfExecution:
    """A signed proof of execution with hash-chain linkage.

    Fields:
        agent_did: The executing agent's DID.
        action: The action performed.
        resource: The resource URI.
        token_id: Capability token identifier.
        timestamp: Unix timestamp of execution.
        result: Execution result (POE_SUCCESS, POE_FAILURE, POE_VIOLATION).
        args_hash: SHA-384 digest of the arguments.
        prev_poe_hash: SHA-384 hash of the previous PoE in the chain (empty for first).
        signature: ML-DSA-65 signature over all other fields.
    """

    agent_did: str
    action: str
    resource: str
    token_id: bytes
    timestamp: int
    result: str
    args_hash: bytes
    prev_poe_hash: bytes
    signature: bytes

    def signable_bytes(self) -> bytes:
        """Return CBOR-encoded bytes for signing (excludes signature)."""
        return cbor2.dumps({
            "agent_did": self.agent_did,
            "action": self.action,
            "resource": self.resource,
            "token_id": self.token_id,
            "timestamp": self.timestamp,
            "result": self.result,
            "args_hash": self.args_hash,
            "prev_poe_hash": self.prev_poe_hash,
        })

    def compute_hash(self) -> bytes:
        """Compute SHA-384 hash of the full PoE (including signature)."""
        return hashlib.sha384(self.to_cbor()).digest()

    def to_cbor(self) -> bytes:
        """Serialize the full PoE to CBOR."""
        return cbor2.dumps({
            "agent_did": self.agent_did,
            "action": self.action,
            "resource": self.resource,
            "token_id": self.token_id,
            "timestamp": self.timestamp,
            "result": self.result,
            "args_hash": self.args_hash,
            "prev_poe_hash": self.prev_poe_hash,
            "signature": self.signature,
        })

    @classmethod
    def from_cbor(cls, data: bytes) -> ProofOfExecution:
        """Deserialize a PoE from CBOR."""
        d = cbor2.loads(data)
        return cls(
            agent_did=d["agent_did"],
            action=d["action"],
            resource=d["resource"],
            token_id=bytes(d["token_id"]),
            timestamp=d["timestamp"],
            result=d["result"],
            args_hash=bytes(d["args_hash"]),
            prev_poe_hash=bytes(d["prev_poe_hash"]),
            signature=bytes(d["signature"]),
        )


def create_proof_of_execution(
    agent_did: str,
    action: str,
    resource: str,
    token_id: bytes,
    result: str,
    arguments: bytes,
    signer_sk: bytes,
    prev_poe_hash: bytes = b"",
    timestamp: int | None = None,
) -> ProofOfExecution:
    """Create a signed Proof of Execution.

    Args:
        agent_did: The executing agent's DID.
        action: The action performed.
        resource: The resource URI.
        token_id: Capability token identifier.
        result: Execution result string.
        arguments: Raw argument bytes (will be hashed).
        signer_sk: Signer's ML-DSA-65 secret key.
        prev_poe_hash: Hash of previous PoE in chain (empty for first).
        timestamp: Unix timestamp (defaults to current time).

    Returns:
        A signed ProofOfExecution.
    """
    if timestamp is None:
        timestamp = int(time.time())

    args_hash = hashlib.sha384(arguments).digest()

    unsigned = ProofOfExecution(
        agent_did=agent_did,
        action=action,
        resource=resource,
        token_id=token_id,
        timestamp=timestamp,
        result=result,
        args_hash=args_hash,
        prev_poe_hash=prev_poe_hash,
        signature=b"",
    )
    signature = sign(signer_sk, unsigned.signable_bytes())

    return ProofOfExecution(
        agent_did=agent_did,
        action=action,
        resource=resource,
        token_id=token_id,
        timestamp=timestamp,
        result=result,
        args_hash=args_hash,
        prev_poe_hash=prev_poe_hash,
        signature=signature,
    )


def verify_proof_of_execution(poe: ProofOfExecution, signer_pk: bytes) -> bool:
    """Verify a Proof of Execution's ML-DSA-65 signature.

    Args:
        poe: The proof to verify.
        signer_pk: The signer's public key.

    Returns:
        True if valid.

    Raises:
        TraceVerificationError: If signature verification fails.
    """
    try:
        return verify(signer_pk, poe.signable_bytes(), poe.signature)
    except Exception as e:
        raise TraceVerificationError(
            f"PoE signature verification failed: {e}"
        ) from e


class PoEChain:
    """An ordered, hash-chained list of Proofs of Execution."""

    def __init__(self) -> None:
        self._entries: list[ProofOfExecution] = []

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def entries(self) -> list[ProofOfExecution]:
        return list(self._entries)

    @property
    def latest_hash(self) -> bytes:
        """Hash of the most recent entry, or empty bytes if chain is empty."""
        if not self._entries:
            return b""
        return self._entries[-1].compute_hash()

    def append(self, poe: ProofOfExecution) -> None:
        """Append a PoE, validating hash chain continuity.

        Args:
            poe: The proof to append.

        Raises:
            PoEChainError: If the prev_poe_hash doesn't match.
        """
        if self._entries:
            expected = self._entries[-1].compute_hash()
            if poe.prev_poe_hash != expected:
                raise PoEChainError(
                    "Hash chain broken: prev_poe_hash mismatch"
                )
        else:
            if poe.prev_poe_hash != b"":
                raise PoEChainError(
                    "First entry must have empty prev_poe_hash"
                )
        self._entries.append(poe)

    def verify(self, signer_pk: bytes) -> bool:
        """Verify the full chain: all signatures and hash linkage.

        Args:
            signer_pk: The signer's public key.

        Returns:
            True if the entire chain is valid.

        Raises:
            PoEChainError: If chain validation fails.
            TraceVerificationError: If a signature fails.
        """
        for i, poe in enumerate(self._entries):
            if i == 0:
                if poe.prev_poe_hash != b"":
                    raise PoEChainError("First entry must have empty prev_poe_hash")
            else:
                expected = self._entries[i - 1].compute_hash()
                if poe.prev_poe_hash != expected:
                    raise PoEChainError(
                        f"Hash chain broken at index {i}"
                    )
            verify_proof_of_execution(poe, signer_pk)
        return True

    def to_cbor(self) -> bytes:
        """Serialize the full chain to CBOR."""
        return cbor2.dumps([poe.to_cbor() for poe in self._entries])

    @classmethod
    def from_cbor(cls, data: bytes) -> PoEChain:
        """Deserialize a chain from CBOR."""
        chain = cls()
        entries = cbor2.loads(data)
        for entry_bytes in entries:
            poe = ProofOfExecution.from_cbor(entry_bytes)
            chain.append(poe)
        return chain
