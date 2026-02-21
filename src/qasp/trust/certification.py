"""Audit certification using Verifiable Credentials.

This module implements the qasp-audit-v1 Verifiable Credential schema
following W3C VC Data Model v2.0, with ML-DSA-65 proof signatures.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import IntEnum
from typing import Any

import cbor2

from qasp.crypto.exceptions import InvalidSignatureError
from qasp.crypto.signatures import sign, verify
from qasp.identity.did import DID
from qasp.trust.exceptions import (
    InvalidProofError,
    InvalidSLSALevelError,
    InvalidVCError,
    VCExpiredError,
    VCNotYetValidError,
)

__all__ = [
    "QASP_AUDIT_CONTEXT",
    "VC_CONTEXT",
    "AuditCredentialSubject",
    "AuditVC",
    "MLDSAProof",
    "SLSALevel",
    "create_audit_vc",
    "verify_audit_vc",
]

# W3C JSON-LD contexts
VC_CONTEXT = "https://www.w3.org/ns/credentials/v2"
QASP_AUDIT_CONTEXT = "https://qasp.ai/ns/audit/v1"

# SHA-384 hash size in bytes
SHA384_HASH_SIZE = 48

# Nonce size for uniqueness
NONCE_SIZE = 16


class SLSALevel(IntEnum):
    """SLSA (Supply-chain Levels for Software Artifacts) certification levels.

    See: https://slsa.dev/spec/v1.0/levels
    """

    LEVEL_1 = 1  # Basic provenance
    LEVEL_2 = 2  # Signed provenance, hosted build
    LEVEL_3 = 3  # Hardened builds, hermetic, reproducible


@dataclass(frozen=True)
class AuditCredentialSubject:
    """The credential subject for an audit VC.

    Attributes:
        agent_did: The DID of the audited agent.
        audit_scope: Description of what was audited.
        code_version_hash: SHA-384 hash of the code version (48 bytes).
        audit_result: Summary result of the audit.
        slsa_level: The SLSA certification level (1-3).
        findings: Optional detailed audit findings.
    """

    agent_did: DID
    audit_scope: str
    code_version_hash: bytes
    audit_result: str
    slsa_level: SLSALevel
    findings: dict[str, str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        """Validate the credential subject after initialization."""
        # Set default empty dict if None
        if self.findings is None:
            object.__setattr__(self, "findings", {})

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-LD dictionary.

        Returns:
            A dictionary suitable for JSON serialization.
        """
        return {
            "id": str(self.agent_did),
            "type": "QASPAuditSubject",
            "auditScope": self.audit_scope,
            "codeVersionHash": self.code_version_hash.hex(),
            "auditResult": self.audit_result,
            "slsaLevel": int(self.slsa_level),
            "findings": self.findings,
        }


@dataclass(frozen=True)
class MLDSAProof:
    """ML-DSA-65 digital signature proof.

    Attributes:
        type: The proof type (always "MLDSASignature2025").
        created: When the proof was created.
        verification_method: DID URL for the verification key.
        proof_purpose: The purpose of this proof (typically "assertionMethod").
        proof_value: The ML-DSA-65 signature bytes.
    """

    type: str
    created: datetime
    verification_method: str
    proof_purpose: str
    proof_value: bytes

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-LD dictionary.

        Returns:
            A dictionary suitable for JSON serialization.
        """
        return {
            "type": self.type,
            "created": self.created.isoformat(),
            "verificationMethod": self.verification_method,
            "proofPurpose": self.proof_purpose,
            "proofValue": self.proof_value.hex(),
        }


@dataclass(frozen=True)
class AuditVC:
    """An audit Verifiable Credential following W3C VC Data Model v2.0.

    Attributes:
        id: URN UUID identifier for this VC.
        issuer_did: The DID of the auditor who issued this VC.
        valid_from: When the VC becomes valid.
        valid_until: When the VC expires.
        credential_subject: The audit information about the agent.
        proof: The ML-DSA-65 signature proof.
        nonce: Random nonce for uniqueness (16 bytes).
    """

    id: str
    issuer_did: DID
    valid_from: datetime
    valid_until: datetime
    credential_subject: AuditCredentialSubject
    proof: MLDSAProof
    nonce: bytes

    def is_expired(self, now: datetime | None = None) -> bool:
        """Check if the VC has expired.

        Args:
            now: The current time (defaults to UTC now).

        Returns:
            True if the VC has expired.
        """
        if now is None:
            now = datetime.now(UTC)
        return now >= self.valid_until

    def is_not_yet_valid(self, now: datetime | None = None) -> bool:
        """Check if the VC is not yet valid.

        Args:
            now: The current time (defaults to UTC now).

        Returns:
            True if the VC is not yet valid.
        """
        if now is None:
            now = datetime.now(UTC)
        return now < self.valid_from

    def to_dict(self) -> dict[str, Any]:
        """Convert to W3C JSON-LD dictionary format.

        Returns:
            A dictionary suitable for JSON serialization.
        """
        return {
            "@context": [VC_CONTEXT, QASP_AUDIT_CONTEXT],
            "type": ["VerifiableCredential", "QASPAuditCredential"],
            "id": self.id,
            "issuer": str(self.issuer_did),
            "validFrom": self.valid_from.isoformat(),
            "validUntil": self.valid_until.isoformat(),
            "credentialSubject": self.credential_subject.to_dict(),
            "proof": self.proof.to_dict(),
            "nonce": self.nonce.hex(),
        }

    def to_json(self, indent: int | None = 2) -> str:
        """Convert to JSON-LD string.

        Args:
            indent: JSON indentation level (None for compact).

        Returns:
            A JSON string representation.
        """
        return json.dumps(self.to_dict(), indent=indent)

    def to_cbor(self) -> bytes:
        """Serialize to CBOR (deterministic/canonical).

        Returns:
            CBOR-encoded VC data.
        """
        return _encode_vc_data(
            vc_id=self.id,
            issuer_did=self.issuer_did,
            valid_from=self.valid_from,
            valid_until=self.valid_until,
            credential_subject=self.credential_subject,
            nonce=self.nonce,
        )

    @classmethod
    def from_cbor(cls, data: bytes) -> AuditVC:
        """Deserialize from CBOR.

        Args:
            data: CBOR-encoded VC data with proof.

        Returns:
            An AuditVC instance.

        Raises:
            InvalidVCError: If the CBOR data is malformed.
        """
        try:
            decoded = cbor2.loads(data)
            if not isinstance(decoded, dict):
                raise InvalidVCError("VC data must be a CBOR map")

            # Parse DIDs
            issuer_did = DID.parse(decoded["issuer"])
            agent_did = DID.parse(decoded["subject"]["agent_did"])

            # Parse credential subject
            subject_data = decoded["subject"]
            credential_subject = AuditCredentialSubject(
                agent_did=agent_did,
                audit_scope=subject_data["audit_scope"],
                code_version_hash=bytes.fromhex(subject_data["code_version_hash"]),
                audit_result=subject_data["audit_result"],
                slsa_level=SLSALevel(subject_data["slsa_level"]),
                findings=subject_data.get("findings", {}),
            )

            # Parse proof
            proof_data = decoded["proof"]
            proof = MLDSAProof(
                type=proof_data["type"],
                created=datetime.fromisoformat(proof_data["created"]),
                verification_method=proof_data["verification_method"],
                proof_purpose=proof_data["proof_purpose"],
                proof_value=bytes.fromhex(proof_data["proof_value"]),
            )

            return cls(
                id=decoded["id"],
                issuer_did=issuer_did,
                valid_from=datetime.fromisoformat(decoded["valid_from"]),
                valid_until=datetime.fromisoformat(decoded["valid_until"]),
                credential_subject=credential_subject,
                proof=proof,
                nonce=bytes.fromhex(decoded["nonce"]),
            )
        except (KeyError, ValueError, TypeError) as e:
            raise InvalidVCError(f"Failed to parse VC CBOR: {e}") from e


def _encode_vc_data(
    vc_id: str,
    issuer_did: DID,
    valid_from: datetime,
    valid_until: datetime,
    credential_subject: AuditCredentialSubject,
    nonce: bytes,
) -> bytes:
    """Encode VC data to CBOR for signing.

    Args:
        vc_id: VC identifier.
        issuer_did: Issuer's DID.
        valid_from: Start of validity period.
        valid_until: End of validity period.
        credential_subject: The audit subject data.
        nonce: Random nonce.

    Returns:
        CBOR-encoded bytes (deterministic ordering).
    """
    vc_data = {
        "id": vc_id,
        "issuer": str(issuer_did),
        "valid_from": valid_from.isoformat(),
        "valid_until": valid_until.isoformat(),
        "subject": {
            "agent_did": str(credential_subject.agent_did),
            "audit_scope": credential_subject.audit_scope,
            "code_version_hash": credential_subject.code_version_hash.hex(),
            "audit_result": credential_subject.audit_result,
            "slsa_level": int(credential_subject.slsa_level),
            "findings": credential_subject.findings,
        },
        "nonce": nonce.hex(),
    }
    return cbor2.dumps(vc_data)


def _encode_vc_with_proof(vc: AuditVC) -> bytes:
    """Encode full VC with proof to CBOR.

    Args:
        vc: The AuditVC to encode.

    Returns:
        CBOR-encoded bytes including proof.
    """
    vc_data = {
        "id": vc.id,
        "issuer": str(vc.issuer_did),
        "valid_from": vc.valid_from.isoformat(),
        "valid_until": vc.valid_until.isoformat(),
        "subject": {
            "agent_did": str(vc.credential_subject.agent_did),
            "audit_scope": vc.credential_subject.audit_scope,
            "code_version_hash": vc.credential_subject.code_version_hash.hex(),
            "audit_result": vc.credential_subject.audit_result,
            "slsa_level": int(vc.credential_subject.slsa_level),
            "findings": vc.credential_subject.findings,
        },
        "nonce": vc.nonce.hex(),
        "proof": {
            "type": vc.proof.type,
            "created": vc.proof.created.isoformat(),
            "verification_method": vc.proof.verification_method,
            "proof_purpose": vc.proof.proof_purpose,
            "proof_value": vc.proof.proof_value.hex(),
        },
    }
    return cbor2.dumps(vc_data)


def create_audit_vc(
    issuer_did: DID,
    issuer_secret_key: bytes,
    agent_did: DID,
    audit_scope: str,
    code_version_hash: bytes,
    audit_result: str,
    slsa_level: int | SLSALevel,
    valid_from: datetime | None = None,
    valid_until: datetime | None = None,
    findings: dict[str, str] | None = None,
) -> AuditVC:
    """Create an audit Verifiable Credential.

    Args:
        issuer_did: The auditor's DID.
        issuer_secret_key: The auditor's ML-DSA-65 secret key.
        agent_did: The audited agent's DID.
        audit_scope: Description of what was audited.
        code_version_hash: SHA-384 hash of the code version (48 bytes).
        audit_result: Summary result of the audit.
        slsa_level: The SLSA certification level (1, 2, or 3).
        valid_from: When the VC becomes valid (defaults to now).
        valid_until: When the VC expires (defaults to 1 year from valid_from).
        findings: Optional detailed audit findings.

    Returns:
        A signed AuditVC.

    Raises:
        InvalidSLSALevelError: If slsa_level is not 1, 2, or 3.
        InvalidVCError: If code_version_hash is not 48 bytes.
        InvalidKeyError: If the secret key is invalid.
        SignatureError: If signing fails.
    """
    # Validate SLSA level
    if isinstance(slsa_level, int):
        if slsa_level not in (1, 2, 3):
            raise InvalidSLSALevelError(
                f"Invalid SLSA level: {slsa_level}. Must be 1, 2, or 3."
            )
        slsa_level = SLSALevel(slsa_level)

    # Validate code_version_hash length
    if len(code_version_hash) != SHA384_HASH_SIZE:
        raise InvalidVCError(
            f"Invalid code_version_hash length: expected {SHA384_HASH_SIZE} bytes, "
            f"got {len(code_version_hash)}"
        )

    # Set default timestamps
    if valid_from is None:
        valid_from = datetime.now(UTC)
    if valid_until is None:
        # Default validity: 1 year
        from datetime import timedelta

        valid_until = valid_from + timedelta(days=365)

    # Generate unique ID and nonce
    vc_id = f"urn:uuid:{uuid.uuid4()}"
    nonce = os.urandom(NONCE_SIZE)

    # Create credential subject
    credential_subject = AuditCredentialSubject(
        agent_did=agent_did,
        audit_scope=audit_scope,
        code_version_hash=code_version_hash,
        audit_result=audit_result,
        slsa_level=slsa_level,
        findings=findings or {},
    )

    # Encode VC data for signing
    message = _encode_vc_data(
        vc_id=vc_id,
        issuer_did=issuer_did,
        valid_from=valid_from,
        valid_until=valid_until,
        credential_subject=credential_subject,
        nonce=nonce,
    )

    # Sign with ML-DSA-65
    created = datetime.now(UTC)
    signature = sign(issuer_secret_key, message)

    # Create proof
    proof = MLDSAProof(
        type="MLDSASignature2025",
        created=created,
        verification_method=f"{issuer_did}#key-1",
        proof_purpose="assertionMethod",
        proof_value=signature,
    )

    return AuditVC(
        id=vc_id,
        issuer_did=issuer_did,
        valid_from=valid_from,
        valid_until=valid_until,
        credential_subject=credential_subject,
        proof=proof,
        nonce=nonce,
    )


def verify_audit_vc(
    vc: AuditVC,
    issuer_public_key: bytes,
    check_expiry: bool = True,
) -> bool:
    """Verify an audit Verifiable Credential.

    Args:
        vc: The VC to verify.
        issuer_public_key: The issuer's ML-DSA-65 public key.
        check_expiry: Whether to check time-based constraints.

    Returns:
        True if the VC is valid.

    Raises:
        InvalidProofError: If the proof type or purpose is invalid.
        InvalidProofError: If the signature verification fails.
        VCExpiredError: If the VC has expired (when check_expiry=True).
        VCNotYetValidError: If the VC is not yet valid (when check_expiry=True).
    """
    # Validate proof type
    if vc.proof.type != "MLDSASignature2025":
        raise InvalidProofError(
            f"Invalid proof type: expected 'MLDSASignature2025', got '{vc.proof.type}'"
        )

    # Validate proof purpose
    if vc.proof.proof_purpose != "assertionMethod":
        raise InvalidProofError(
            f"Invalid proof purpose: expected 'assertionMethod', "
            f"got '{vc.proof.proof_purpose}'"
        )

    # Check time constraints
    if check_expiry:
        now = datetime.now(UTC)

        if vc.is_not_yet_valid(now):
            raise VCNotYetValidError(
                f"VC not valid until {vc.valid_from.isoformat()}"
            )

        if vc.is_expired(now):
            raise VCExpiredError(f"VC expired at {vc.valid_until.isoformat()}")

    # Reconstruct signed data and verify signature
    message = _encode_vc_data(
        vc_id=vc.id,
        issuer_did=vc.issuer_did,
        valid_from=vc.valid_from,
        valid_until=vc.valid_until,
        credential_subject=vc.credential_subject,
        nonce=vc.nonce,
    )

    try:
        verify(issuer_public_key, message, vc.proof.proof_value)
        return True
    except InvalidSignatureError as e:
        raise InvalidProofError(f"Signature verification failed: {e}") from e
