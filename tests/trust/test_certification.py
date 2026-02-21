"""Tests for trust certification module (Verifiable Credentials)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from qasp.identity import DID
from qasp.trust import (
    QASP_AUDIT_CONTEXT,
    VC_CONTEXT,
    AuditCredentialSubject,
    AuditVC,
    MLDSAProof,
    SLSALevel,
    create_audit_vc,
    verify_audit_vc,
)
from qasp.trust.exceptions import (
    InvalidProofError,
    InvalidSLSALevelError,
    InvalidVCError,
    VCExpiredError,
    VCNotYetValidError,
)

# =============================================================================
# SLSALevel Tests
# =============================================================================


class TestSLSALevel:
    """Tests for SLSALevel enum."""

    def test_slsa_level_values(self) -> None:
        """Test that SLSA levels have correct values."""
        assert SLSALevel.LEVEL_1.value == 1
        assert SLSALevel.LEVEL_2.value == 2
        assert SLSALevel.LEVEL_3.value == 3

    def test_slsa_level_is_int_enum(self) -> None:
        """Test that SLSALevel behaves like int."""
        assert int(SLSALevel.LEVEL_1) == 1
        assert int(SLSALevel.LEVEL_2) == 2
        assert int(SLSALevel.LEVEL_3) == 3

    def test_slsa_level_comparison(self) -> None:
        """Test that SLSALevel supports comparison."""
        assert SLSALevel.LEVEL_1 < SLSALevel.LEVEL_2
        assert SLSALevel.LEVEL_2 < SLSALevel.LEVEL_3
        assert SLSALevel.LEVEL_3 > SLSALevel.LEVEL_1


# =============================================================================
# VC Creation Tests
# =============================================================================


class TestCreateAuditVC:
    """Tests for create_audit_vc function."""

    def test_create_audit_vc_basic(
        self,
        auditor_did: DID,
        auditor_secret_key: bytes,
        agent_did: DID,
        sample_code_hash: bytes,
    ) -> None:
        """Test basic VC creation with all required fields."""
        vc = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_did,
            audit_scope="Full security audit of AI agent codebase",
            code_version_hash=sample_code_hash,
            audit_result="PASSED",
            slsa_level=SLSALevel.LEVEL_2,
        )

        assert vc.issuer_did == auditor_did
        assert vc.credential_subject.agent_did == agent_did
        assert vc.credential_subject.audit_scope == "Full security audit of AI agent codebase"
        assert vc.credential_subject.code_version_hash == sample_code_hash
        assert vc.credential_subject.audit_result == "PASSED"
        assert vc.credential_subject.slsa_level == SLSALevel.LEVEL_2

    def test_create_audit_vc_unique_id(
        self,
        auditor_did: DID,
        auditor_secret_key: bytes,
        agent_did: DID,
        sample_code_hash: bytes,
    ) -> None:
        """Test that each VC gets a unique URN UUID ID."""
        vc1 = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_did,
            audit_scope="Audit 1",
            code_version_hash=sample_code_hash,
            audit_result="PASSED",
            slsa_level=1,
        )
        vc2 = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_did,
            audit_scope="Audit 2",
            code_version_hash=sample_code_hash,
            audit_result="PASSED",
            slsa_level=1,
        )

        assert vc1.id != vc2.id
        assert vc1.id.startswith("urn:uuid:")
        assert vc2.id.startswith("urn:uuid:")

    def test_create_audit_vc_validity_period(
        self,
        auditor_did: DID,
        auditor_secret_key: bytes,
        agent_did: DID,
        sample_code_hash: bytes,
    ) -> None:
        """Test that validity period is set correctly."""
        now = datetime.now(UTC)
        vc = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_did,
            audit_scope="Audit",
            code_version_hash=sample_code_hash,
            audit_result="PASSED",
            slsa_level=1,
        )

        # valid_from should be close to now
        assert (vc.valid_from - now).total_seconds() < 5

        # valid_until should be approximately 1 year from valid_from
        expected_until = vc.valid_from + timedelta(days=365)
        assert abs((vc.valid_until - expected_until).total_seconds()) < 1

    def test_create_audit_vc_custom_validity(
        self,
        auditor_did: DID,
        auditor_secret_key: bytes,
        agent_did: DID,
        sample_code_hash: bytes,
    ) -> None:
        """Test custom validity period."""
        valid_from = datetime(2025, 1, 1, tzinfo=UTC)
        valid_until = datetime(2026, 1, 1, tzinfo=UTC)

        vc = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_did,
            audit_scope="Audit",
            code_version_hash=sample_code_hash,
            audit_result="PASSED",
            slsa_level=1,
            valid_from=valid_from,
            valid_until=valid_until,
        )

        assert vc.valid_from == valid_from
        assert vc.valid_until == valid_until

    def test_create_audit_vc_with_findings(
        self,
        auditor_did: DID,
        auditor_secret_key: bytes,
        agent_did: DID,
        sample_code_hash: bytes,
    ) -> None:
        """Test VC creation with detailed findings."""
        findings = {
            "security": "No critical vulnerabilities found",
            "performance": "Resource usage within acceptable limits",
            "compliance": "Meets all regulatory requirements",
        }

        vc = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_did,
            audit_scope="Comprehensive audit",
            code_version_hash=sample_code_hash,
            audit_result="PASSED",
            slsa_level=3,
            findings=findings,
        )

        assert vc.credential_subject.findings == findings

    def test_create_audit_vc_signature_present(
        self,
        auditor_did: DID,
        auditor_secret_key: bytes,
        agent_did: DID,
        sample_code_hash: bytes,
    ) -> None:
        """Test that VC has a valid signature."""
        vc = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_did,
            audit_scope="Audit",
            code_version_hash=sample_code_hash,
            audit_result="PASSED",
            slsa_level=1,
        )

        assert vc.proof is not None
        assert vc.proof.type == "MLDSASignature2025"
        assert vc.proof.proof_purpose == "assertionMethod"
        assert len(vc.proof.proof_value) > 0
        assert vc.proof.verification_method == f"{auditor_did}#key-1"


# =============================================================================
# VC Validation Tests
# =============================================================================


class TestCreateAuditVCValidation:
    """Tests for validation in create_audit_vc."""

    def test_invalid_slsa_level_zero(
        self,
        auditor_did: DID,
        auditor_secret_key: bytes,
        agent_did: DID,
        sample_code_hash: bytes,
    ) -> None:
        """Test that SLSA level 0 is rejected."""
        with pytest.raises(InvalidSLSALevelError, match="Invalid SLSA level: 0"):
            create_audit_vc(
                issuer_did=auditor_did,
                issuer_secret_key=auditor_secret_key,
                agent_did=agent_did,
                audit_scope="Audit",
                code_version_hash=sample_code_hash,
                audit_result="PASSED",
                slsa_level=0,
            )

    def test_invalid_slsa_level_four(
        self,
        auditor_did: DID,
        auditor_secret_key: bytes,
        agent_did: DID,
        sample_code_hash: bytes,
    ) -> None:
        """Test that SLSA level 4 is rejected."""
        with pytest.raises(InvalidSLSALevelError, match="Invalid SLSA level: 4"):
            create_audit_vc(
                issuer_did=auditor_did,
                issuer_secret_key=auditor_secret_key,
                agent_did=agent_did,
                audit_scope="Audit",
                code_version_hash=sample_code_hash,
                audit_result="PASSED",
                slsa_level=4,
            )

    def test_invalid_code_hash_length_too_short(
        self,
        auditor_did: DID,
        auditor_secret_key: bytes,
        agent_did: DID,
    ) -> None:
        """Test that short code hash is rejected."""
        short_hash = b"\x00" * 32  # 32 bytes instead of 48

        with pytest.raises(InvalidVCError, match="Invalid code_version_hash length"):
            create_audit_vc(
                issuer_did=auditor_did,
                issuer_secret_key=auditor_secret_key,
                agent_did=agent_did,
                audit_scope="Audit",
                code_version_hash=short_hash,
                audit_result="PASSED",
                slsa_level=1,
            )

    def test_invalid_code_hash_length_too_long(
        self,
        auditor_did: DID,
        auditor_secret_key: bytes,
        agent_did: DID,
    ) -> None:
        """Test that long code hash is rejected."""
        long_hash = b"\x00" * 64  # 64 bytes instead of 48

        with pytest.raises(InvalidVCError, match="Invalid code_version_hash length"):
            create_audit_vc(
                issuer_did=auditor_did,
                issuer_secret_key=auditor_secret_key,
                agent_did=agent_did,
                audit_scope="Audit",
                code_version_hash=long_hash,
                audit_result="PASSED",
                slsa_level=1,
            )


# =============================================================================
# VC Verification Tests
# =============================================================================


class TestVerifyAuditVC:
    """Tests for verify_audit_vc function."""

    def test_verify_valid_vc(
        self,
        auditor_did: DID,
        auditor_secret_key: bytes,
        auditor_public_key: bytes,
        agent_did: DID,
        sample_code_hash: bytes,
    ) -> None:
        """Test verification of a valid VC."""
        vc = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_did,
            audit_scope="Audit",
            code_version_hash=sample_code_hash,
            audit_result="PASSED",
            slsa_level=2,
        )

        result = verify_audit_vc(vc, auditor_public_key)
        assert result is True

    def test_verify_wrong_public_key(
        self,
        auditor_did: DID,
        auditor_secret_key: bytes,
        agent_did: DID,
        agent_public_key: bytes,  # Wrong key
        sample_code_hash: bytes,
    ) -> None:
        """Test verification fails with wrong public key."""
        vc = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_did,
            audit_scope="Audit",
            code_version_hash=sample_code_hash,
            audit_result="PASSED",
            slsa_level=2,
        )

        with pytest.raises(InvalidProofError, match="Signature verification failed"):
            verify_audit_vc(vc, agent_public_key)

    def test_verify_expired_vc(
        self,
        auditor_did: DID,
        auditor_secret_key: bytes,
        auditor_public_key: bytes,
        agent_did: DID,
        sample_code_hash: bytes,
    ) -> None:
        """Test verification fails for expired VC."""
        # Create VC that expired yesterday
        now = datetime.now(UTC)
        vc = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_did,
            audit_scope="Audit",
            code_version_hash=sample_code_hash,
            audit_result="PASSED",
            slsa_level=2,
            valid_from=now - timedelta(days=2),
            valid_until=now - timedelta(days=1),
        )

        with pytest.raises(VCExpiredError, match="VC expired"):
            verify_audit_vc(vc, auditor_public_key)

    def test_verify_not_yet_valid_vc(
        self,
        auditor_did: DID,
        auditor_secret_key: bytes,
        auditor_public_key: bytes,
        agent_did: DID,
        sample_code_hash: bytes,
    ) -> None:
        """Test verification fails for not-yet-valid VC."""
        # Create VC that becomes valid tomorrow
        now = datetime.now(UTC)
        vc = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_did,
            audit_scope="Audit",
            code_version_hash=sample_code_hash,
            audit_result="PASSED",
            slsa_level=2,
            valid_from=now + timedelta(days=1),
            valid_until=now + timedelta(days=365),
        )

        with pytest.raises(VCNotYetValidError, match="VC not valid until"):
            verify_audit_vc(vc, auditor_public_key)

    def test_verify_skip_expiry_check(
        self,
        auditor_did: DID,
        auditor_secret_key: bytes,
        auditor_public_key: bytes,
        agent_did: DID,
        sample_code_hash: bytes,
    ) -> None:
        """Test verification with check_expiry=False."""
        # Create expired VC
        now = datetime.now(UTC)
        vc = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_did,
            audit_scope="Audit",
            code_version_hash=sample_code_hash,
            audit_result="PASSED",
            slsa_level=2,
            valid_from=now - timedelta(days=2),
            valid_until=now - timedelta(days=1),
        )

        # Should succeed with check_expiry=False
        result = verify_audit_vc(vc, auditor_public_key, check_expiry=False)
        assert result is True


# =============================================================================
# Serialization Tests
# =============================================================================


class TestAuditVCSerialization:
    """Tests for VC serialization methods."""

    def test_to_dict_format(
        self,
        auditor_did: DID,
        auditor_secret_key: bytes,
        agent_did: DID,
        sample_code_hash: bytes,
    ) -> None:
        """Test to_dict returns correct W3C JSON-LD format."""
        vc = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_did,
            audit_scope="Security audit",
            code_version_hash=sample_code_hash,
            audit_result="PASSED",
            slsa_level=SLSALevel.LEVEL_3,
        )

        vc_dict = vc.to_dict()

        # Check required W3C VC fields
        assert "@context" in vc_dict
        assert VC_CONTEXT in vc_dict["@context"]
        assert QASP_AUDIT_CONTEXT in vc_dict["@context"]
        assert "type" in vc_dict
        assert "VerifiableCredential" in vc_dict["type"]
        assert "QASPAuditCredential" in vc_dict["type"]
        assert "id" in vc_dict
        assert vc_dict["id"].startswith("urn:uuid:")
        assert "issuer" in vc_dict
        assert vc_dict["issuer"] == str(auditor_did)
        assert "validFrom" in vc_dict
        assert "validUntil" in vc_dict
        assert "credentialSubject" in vc_dict
        assert "proof" in vc_dict

    def test_to_json_valid_json(
        self,
        auditor_did: DID,
        auditor_secret_key: bytes,
        agent_did: DID,
        sample_code_hash: bytes,
    ) -> None:
        """Test to_json produces valid JSON."""
        vc = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_did,
            audit_scope="Audit",
            code_version_hash=sample_code_hash,
            audit_result="PASSED",
            slsa_level=1,
        )

        json_str = vc.to_json()

        # Should be valid JSON
        parsed = json.loads(json_str)
        assert parsed["id"] == vc.id

    def test_cbor_roundtrip(
        self,
        auditor_did: DID,
        auditor_secret_key: bytes,
        agent_did: DID,
        sample_code_hash: bytes,
    ) -> None:
        """Test CBOR serialization roundtrip."""
        from qasp.trust.certification import _encode_vc_with_proof

        vc = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_did,
            audit_scope="Security audit",
            code_version_hash=sample_code_hash,
            audit_result="PASSED",
            slsa_level=SLSALevel.LEVEL_2,
            findings={"note": "All tests passed"},
        )

        # Encode to CBOR
        cbor_data = _encode_vc_with_proof(vc)

        # Decode from CBOR
        decoded_vc = AuditVC.from_cbor(cbor_data)

        # Verify fields match
        assert decoded_vc.id == vc.id
        assert decoded_vc.issuer_did == vc.issuer_did
        assert decoded_vc.valid_from == vc.valid_from
        assert decoded_vc.valid_until == vc.valid_until
        assert decoded_vc.credential_subject.agent_did == vc.credential_subject.agent_did
        assert decoded_vc.credential_subject.audit_scope == vc.credential_subject.audit_scope
        assert (
            decoded_vc.credential_subject.code_version_hash
            == vc.credential_subject.code_version_hash
        )
        assert decoded_vc.credential_subject.slsa_level == vc.credential_subject.slsa_level
        assert decoded_vc.proof.type == vc.proof.type
        assert decoded_vc.proof.proof_value == vc.proof.proof_value


# =============================================================================
# Credential Subject Tests
# =============================================================================


class TestAuditCredentialSubject:
    """Tests for AuditCredentialSubject dataclass."""

    def test_default_findings(
        self,
        agent_did: DID,
        sample_code_hash: bytes,
    ) -> None:
        """Test that findings defaults to empty dict."""
        subject = AuditCredentialSubject(
            agent_did=agent_did,
            audit_scope="Audit",
            code_version_hash=sample_code_hash,
            audit_result="PASSED",
            slsa_level=SLSALevel.LEVEL_1,
        )

        assert subject.findings == {}

    def test_to_dict(
        self,
        agent_did: DID,
        sample_code_hash: bytes,
    ) -> None:
        """Test to_dict conversion."""
        subject = AuditCredentialSubject(
            agent_did=agent_did,
            audit_scope="Security audit",
            code_version_hash=sample_code_hash,
            audit_result="PASSED",
            slsa_level=SLSALevel.LEVEL_3,
            findings={"security": "No issues"},
        )

        subject_dict = subject.to_dict()

        assert subject_dict["id"] == str(agent_did)
        assert subject_dict["type"] == "QASPAuditSubject"
        assert subject_dict["auditScope"] == "Security audit"
        assert subject_dict["codeVersionHash"] == sample_code_hash.hex()
        assert subject_dict["auditResult"] == "PASSED"
        assert subject_dict["slsaLevel"] == 3
        assert subject_dict["findings"] == {"security": "No issues"}


# =============================================================================
# MLDSAProof Tests
# =============================================================================


class TestMLDSAProof:
    """Tests for MLDSAProof dataclass."""

    def test_to_dict(self) -> None:
        """Test to_dict conversion."""
        created = datetime(2025, 6, 15, 12, 0, 0, tzinfo=UTC)
        proof = MLDSAProof(
            type="MLDSASignature2025",
            created=created,
            verification_method="did:qasp:abc123#key-1",
            proof_purpose="assertionMethod",
            proof_value=b"\x00" * 100,
        )

        proof_dict = proof.to_dict()

        assert proof_dict["type"] == "MLDSASignature2025"
        assert proof_dict["created"] == created.isoformat()
        assert proof_dict["verificationMethod"] == "did:qasp:abc123#key-1"
        assert proof_dict["proofPurpose"] == "assertionMethod"
        assert proof_dict["proofValue"] == (b"\x00" * 100).hex()


# =============================================================================
# AuditVC Method Tests
# =============================================================================


class TestAuditVCMethods:
    """Tests for AuditVC instance methods."""

    def test_is_expired_false(
        self,
        auditor_did: DID,
        auditor_secret_key: bytes,
        agent_did: DID,
        sample_code_hash: bytes,
    ) -> None:
        """Test is_expired returns False for valid VC."""
        vc = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_did,
            audit_scope="Audit",
            code_version_hash=sample_code_hash,
            audit_result="PASSED",
            slsa_level=1,
        )

        assert vc.is_expired() is False

    def test_is_expired_true(
        self,
        auditor_did: DID,
        auditor_secret_key: bytes,
        agent_did: DID,
        sample_code_hash: bytes,
    ) -> None:
        """Test is_expired returns True for expired VC."""
        now = datetime.now(UTC)
        vc = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_did,
            audit_scope="Audit",
            code_version_hash=sample_code_hash,
            audit_result="PASSED",
            slsa_level=1,
            valid_from=now - timedelta(days=2),
            valid_until=now - timedelta(days=1),
        )

        assert vc.is_expired() is True

    def test_is_not_yet_valid_false(
        self,
        auditor_did: DID,
        auditor_secret_key: bytes,
        agent_did: DID,
        sample_code_hash: bytes,
    ) -> None:
        """Test is_not_yet_valid returns False for valid VC."""
        vc = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_did,
            audit_scope="Audit",
            code_version_hash=sample_code_hash,
            audit_result="PASSED",
            slsa_level=1,
        )

        assert vc.is_not_yet_valid() is False

    def test_is_not_yet_valid_true(
        self,
        auditor_did: DID,
        auditor_secret_key: bytes,
        agent_did: DID,
        sample_code_hash: bytes,
    ) -> None:
        """Test is_not_yet_valid returns True for future VC."""
        now = datetime.now(UTC)
        vc = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_did,
            audit_scope="Audit",
            code_version_hash=sample_code_hash,
            audit_result="PASSED",
            slsa_level=1,
            valid_from=now + timedelta(days=1),
            valid_until=now + timedelta(days=365),
        )

        assert vc.is_not_yet_valid() is True
