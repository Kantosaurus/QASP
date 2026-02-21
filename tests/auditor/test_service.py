"""Tests for the Auditor service."""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest

from qasp.crypto.signatures import generate_keypair, verify
from qasp.auditor.service import AuditorService
from qasp.framing.messages import DisputeVerdict
from qasp.protocol.accounting import Meter, Receipt, ReceiptChain, ReceiptChainError
from qasp.protocol.dispute import (
    DisputeNotFoundError,
    DisputeState,
    DisputeType,
    DuplicateDisputeError,
    EvidencePackage,
    EvidenceType,
    InvalidDisputeStateError,
    VerdictCode,
)


# =============================================================================
# TestAuditorService
# =============================================================================


class TestAuditorService:
    """Tests for basic AuditorService operations."""

    def test_open_dispute(
        self,
        auditor_service: AuditorService,
        claimant_did: str,
        respondent_did: str,
    ) -> None:
        """Can open a new dispute."""
        dispute_id = os.urandom(32)
        record = auditor_service.open_dispute(
            dispute_id=dispute_id,
            token_id=os.urandom(32),
            claimant_did=claimant_did,
            respondent_did=respondent_did,
            dispute_type=DisputeType.USAGE_MISMATCH,
            claimed_value=500,
        )
        assert record.dispute_id == dispute_id
        assert record.state == DisputeState.EVIDENCE_SUBMISSION
        assert record.claimed_value == 500

    def test_duplicate_dispute_rejected(
        self,
        auditor_service: AuditorService,
        claimant_did: str,
        respondent_did: str,
    ) -> None:
        """Cannot open duplicate dispute."""
        dispute_id = os.urandom(32)
        auditor_service.open_dispute(
            dispute_id=dispute_id,
            token_id=os.urandom(32),
            claimant_did=claimant_did,
            respondent_did=respondent_did,
            dispute_type=DisputeType.OVERCHARGE,
        )
        with pytest.raises(DuplicateDisputeError):
            auditor_service.open_dispute(
                dispute_id=dispute_id,
                token_id=os.urandom(32),
                claimant_did=claimant_did,
                respondent_did=respondent_did,
                dispute_type=DisputeType.OVERCHARGE,
            )

    def test_get_dispute(
        self,
        auditor_service: AuditorService,
        claimant_did: str,
        respondent_did: str,
    ) -> None:
        """Can retrieve a dispute by ID."""
        dispute_id = os.urandom(32)
        auditor_service.open_dispute(
            dispute_id=dispute_id,
            token_id=os.urandom(32),
            claimant_did=claimant_did,
            respondent_did=respondent_did,
            dispute_type=DisputeType.SERVICE_FAILURE,
        )
        record = auditor_service.get_dispute(dispute_id)
        assert record.claimant_did == claimant_did

    def test_dispute_not_found(
        self,
        auditor_service: AuditorService,
    ) -> None:
        """get_dispute() raises for unknown dispute."""
        with pytest.raises(DisputeNotFoundError):
            auditor_service.get_dispute(os.urandom(32))

    def test_submit_evidence(
        self,
        auditor_service: AuditorService,
        claimant_did: str,
        claimant_secret_key: bytes,
        respondent_did: str,
    ) -> None:
        """Can submit evidence for a dispute."""
        dispute_id = os.urandom(32)
        auditor_service.open_dispute(
            dispute_id=dispute_id,
            token_id=os.urandom(32),
            claimant_did=claimant_did,
            respondent_did=respondent_did,
            dispute_type=DisputeType.USAGE_MISMATCH,
        )
        ep = EvidencePackage(
            evidence_type=EvidenceType.RECEIPT_CHAIN,
            data=b"receipt chain data",
            submitter_did=claimant_did,
            timestamp=datetime.now(UTC),
            signature=b"sig",
        )
        auditor_service.submit_evidence(dispute_id, ep)
        record = auditor_service.get_dispute(dispute_id)
        assert len(record.evidence) == 1

    def test_submit_evidence_wrong_state(
        self,
        auditor_service: AuditorService,
        claimant_did: str,
        respondent_did: str,
    ) -> None:
        """Cannot submit evidence after review starts."""
        dispute_id = os.urandom(32)
        auditor_service.open_dispute(
            dispute_id=dispute_id,
            token_id=os.urandom(32),
            claimant_did=claimant_did,
            respondent_did=respondent_did,
            dispute_type=DisputeType.USAGE_MISMATCH,
            claimed_value=100,
        )
        # Move to UNDER_REVIEW by reviewing
        auditor_service.review_dispute(dispute_id)
        # Now try to submit evidence — dispute is RESOLVED
        ep = EvidencePackage(
            evidence_type=EvidenceType.RECEIPT_CHAIN,
            data=b"late evidence",
            submitter_did=claimant_did,
            timestamp=datetime.now(UTC),
            signature=b"sig",
        )
        with pytest.raises(InvalidDisputeStateError):
            auditor_service.submit_evidence(dispute_id, ep)


# =============================================================================
# TestReceiptChainVerification
# =============================================================================


class TestReceiptChainVerification:
    """Tests for receipt chain verification within the auditor."""

    def _build_chain(
        self,
        secret_key: bytes,
        session_id: bytes = b"session_test____",
        count: int = 3,
        issuer: str = "did:qasp:provider",
    ) -> ReceiptChain:
        meter = Meter(session_id=session_id, meter_id=b"m1", issuer=issuer)
        chain = ReceiptChain()
        prev_hash = b""
        for i in range(count):
            meter.record("compute", "execute", units=i + 1)
            receipt = meter.generate_receipt(secret_key, prev_hash=prev_hash)
            chain.append(receipt)
            prev_hash = receipt.compute_hash()
        return chain

    def test_valid_chain_passes(
        self,
        auditor_service: AuditorService,
        claimant_secret_key: bytes,
        claimant_public_key: bytes,
    ) -> None:
        """Valid receipt chain passes auditor verification."""
        chain = self._build_chain(claimant_secret_key)
        result = auditor_service._verify_receipt_chain(chain, claimant_public_key)
        assert result is True

    def test_tampered_chain_detected(
        self,
        auditor_service: AuditorService,
        claimant_secret_key: bytes,
        claimant_public_key: bytes,
    ) -> None:
        """Tampered receipt chain is detected."""
        chain = self._build_chain(claimant_secret_key)
        # Tamper: replace a receipt
        original = chain.receipts[1]
        tampered = Receipt(
            records=original.records,
            total_units=999,
            issued_at=original.issued_at,
            issuer=original.issuer,
            signature=original.signature,
            sequence_number=original.sequence_number,
            prev_hash=original.prev_hash,
            meter_id=original.meter_id,
        )
        chain._receipts[1] = tampered
        result = auditor_service._verify_receipt_chain(chain, claimant_public_key)
        assert result is False


# =============================================================================
# TestVerdictSigning
# =============================================================================


class TestVerdictSigning:
    """Tests for verdict signing and verification."""

    def test_verdict_signed_by_auditor(
        self,
        auditor_service: AuditorService,
        auditor_public_key: bytes,
        claimant_did: str,
        respondent_did: str,
    ) -> None:
        """Verdict is signed by the auditor."""
        dispute_id = os.urandom(32)
        auditor_service.open_dispute(
            dispute_id=dispute_id,
            token_id=os.urandom(32),
            claimant_did=claimant_did,
            respondent_did=respondent_did,
            dispute_type=DisputeType.USAGE_MISMATCH,
            claimed_value=100,
        )
        verdict = auditor_service.review_dispute(dispute_id)
        assert isinstance(verdict, DisputeVerdict)
        assert verdict.dispute_id == dispute_id
        assert len(verdict.signature) > 0

    def test_verdict_verifiable_with_auditor_key(
        self,
        auditor_service: AuditorService,
        auditor_public_key: bytes,
        claimant_did: str,
        respondent_did: str,
    ) -> None:
        """Verdict signature is verifiable with auditor's public key."""
        dispute_id = os.urandom(32)
        auditor_service.open_dispute(
            dispute_id=dispute_id,
            token_id=os.urandom(32),
            claimant_did=claimant_did,
            respondent_did=respondent_did,
            dispute_type=DisputeType.OVERCHARGE,
            claimed_value=200,
        )
        verdict = auditor_service.review_dispute(dispute_id)
        # Reconstruct signed data
        verdict_data = (
            dispute_id
            + int(verdict.verdict).to_bytes(4, "big")
            + verdict.awarded_value.to_bytes(8, "big", signed=True)
        )
        assert verify(auditor_public_key, verdict_data, verdict.signature)


# =============================================================================
# TestPaymentAdjustment
# =============================================================================


class TestPaymentAdjustment:
    """Tests for payment adjustment computation."""

    def _build_chain(
        self,
        secret_key: bytes,
        units_per_receipt: list[int],
        session_id: bytes = b"session_test____",
        issuer: str = "did:qasp:test",
    ) -> ReceiptChain:
        meter = Meter(session_id=session_id, meter_id=b"m1", issuer=issuer)
        chain = ReceiptChain()
        prev_hash = b""
        for units in units_per_receipt:
            meter.record("compute", "execute", units=units)
            receipt = meter.generate_receipt(secret_key, prev_hash=prev_hash)
            chain.append(receipt)
            prev_hash = receipt.compute_hash()
        return chain

    def test_claimant_overcharged(
        self,
        auditor_service: AuditorService,
        claimant_did: str,
        claimant_secret_key: bytes,
        claimant_public_key: bytes,
        respondent_did: str,
        respondent_secret_key: bytes,
        respondent_public_key: bytes,
    ) -> None:
        """Claimant wins when respondent shows higher usage."""
        dispute_id = os.urandom(32)
        auditor_service.open_dispute(
            dispute_id=dispute_id,
            token_id=os.urandom(32),
            claimant_did=claimant_did,
            respondent_did=respondent_did,
            dispute_type=DisputeType.OVERCHARGE,
            claimed_value=50,
        )
        # Claimant recorded 10 units, respondent recorded 60
        c_chain = self._build_chain(claimant_secret_key, [10])
        r_chain = self._build_chain(respondent_secret_key, [60])

        verdict = auditor_service.review_dispute(
            dispute_id,
            claimant_chain=c_chain,
            respondent_chain=r_chain,
            claimant_public_key=claimant_public_key,
            respondent_public_key=respondent_public_key,
        )
        assert verdict.verdict == VerdictCode.CLAIMANT_WINS
        assert verdict.awarded_value == 50  # respondent_units - claimant_units = 50

    def test_respondent_wins_when_claimant_chain_invalid(
        self,
        auditor_service: AuditorService,
        claimant_did: str,
        claimant_secret_key: bytes,
        respondent_did: str,
        respondent_secret_key: bytes,
        respondent_public_key: bytes,
    ) -> None:
        """Respondent wins when claimant's chain is invalid."""
        dispute_id = os.urandom(32)
        auditor_service.open_dispute(
            dispute_id=dispute_id,
            token_id=os.urandom(32),
            claimant_did=claimant_did,
            respondent_did=respondent_did,
            dispute_type=DisputeType.USAGE_MISMATCH,
            claimed_value=100,
        )
        c_chain = self._build_chain(claimant_secret_key, [10])
        r_chain = self._build_chain(respondent_secret_key, [10])

        # Verify claimant chain with WRONG key → invalid
        wrong_pk, _ = generate_keypair()

        verdict = auditor_service.review_dispute(
            dispute_id,
            claimant_chain=c_chain,
            respondent_chain=r_chain,
            claimant_public_key=wrong_pk,  # wrong key
            respondent_public_key=respondent_public_key,
        )
        assert verdict.verdict == VerdictCode.RESPONDENT_WINS

    def test_split_when_equal_discrepancy(
        self,
        auditor_service: AuditorService,
        claimant_did: str,
        claimant_secret_key: bytes,
        claimant_public_key: bytes,
        respondent_did: str,
        respondent_secret_key: bytes,
        respondent_public_key: bytes,
    ) -> None:
        """Split verdict when chains are valid but show no net discrepancy."""
        dispute_id = os.urandom(32)
        auditor_service.open_dispute(
            dispute_id=dispute_id,
            token_id=os.urandom(32),
            claimant_did=claimant_did,
            respondent_did=respondent_did,
            dispute_type=DisputeType.OVERCHARGE,
            claimed_value=100,
        )
        # Both chains have same seq but different units that net to zero:
        # claimant has [10, 20], respondent has [20, 10] → net diff = 0
        c_chain = self._build_chain(claimant_secret_key, [10, 20])
        r_chain = self._build_chain(respondent_secret_key, [20, 10])

        verdict = auditor_service.review_dispute(
            dispute_id,
            claimant_chain=c_chain,
            respondent_chain=r_chain,
            claimant_public_key=claimant_public_key,
            respondent_public_key=respondent_public_key,
        )
        assert verdict.verdict == VerdictCode.SPLIT


# =============================================================================
# TestEndToEnd
# =============================================================================


class TestEndToEnd:
    """Full end-to-end dispute resolution test."""

    def test_full_dispute_lifecycle(
        self,
        auditor_service: AuditorService,
        auditor_public_key: bytes,
        claimant_did: str,
        claimant_secret_key: bytes,
        claimant_public_key: bytes,
        respondent_did: str,
        respondent_secret_key: bytes,
        respondent_public_key: bytes,
    ) -> None:
        """Full lifecycle: open → evidence → review → verdict."""
        # 1. Claimant meters usage
        c_meter = Meter(b"session_c_______", meter_id=b"mc", issuer=claimant_did)
        c_meter.record("compute", "execute", units=10)
        c_r1 = c_meter.generate_receipt(claimant_secret_key, prev_hash=b"")
        c_meter.record("compute", "execute", units=20)
        c_r2 = c_meter.generate_receipt(claimant_secret_key, prev_hash=c_r1.compute_hash())
        c_chain = ReceiptChain()
        c_chain.append(c_r1)
        c_chain.append(c_r2)

        # 2. Respondent meters usage (higher — overcharging)
        r_meter = Meter(b"session_r_______", meter_id=b"mr", issuer=respondent_did)
        r_meter.record("compute", "execute", units=10)
        r_r1 = r_meter.generate_receipt(respondent_secret_key, prev_hash=b"")
        r_meter.record("compute", "execute", units=50)  # overcharge
        r_r2 = r_meter.generate_receipt(respondent_secret_key, prev_hash=r_r1.compute_hash())
        r_chain = ReceiptChain()
        r_chain.append(r_r1)
        r_chain.append(r_r2)

        # 3. Open dispute
        dispute_id = os.urandom(32)
        token_id = os.urandom(32)
        auditor_service.open_dispute(
            dispute_id=dispute_id,
            token_id=token_id,
            claimant_did=claimant_did,
            respondent_did=respondent_did,
            dispute_type=DisputeType.OVERCHARGE,
            claimed_value=30,
        )

        # 4. Submit evidence
        c_evidence = EvidencePackage(
            evidence_type=EvidenceType.RECEIPT_CHAIN,
            data=c_chain.to_cbor(),
            submitter_did=claimant_did,
            timestamp=datetime.now(UTC),
            signature=b"sig_c",
        )
        r_evidence = EvidencePackage(
            evidence_type=EvidenceType.RECEIPT_CHAIN,
            data=r_chain.to_cbor(),
            submitter_did=respondent_did,
            timestamp=datetime.now(UTC),
            signature=b"sig_r",
        )
        auditor_service.submit_evidence(dispute_id, c_evidence)
        auditor_service.submit_evidence(dispute_id, r_evidence)

        # 5. Review dispute
        verdict = auditor_service.review_dispute(
            dispute_id,
            claimant_chain=c_chain,
            respondent_chain=r_chain,
            claimant_public_key=claimant_public_key,
            respondent_public_key=respondent_public_key,
        )

        # 6. Verify verdict
        assert isinstance(verdict, DisputeVerdict)
        assert verdict.verdict == VerdictCode.CLAIMANT_WINS
        assert verdict.awarded_value == 30

        # 7. Verify verdict signature
        verdict_data = (
            dispute_id
            + int(verdict.verdict).to_bytes(4, "big")
            + verdict.awarded_value.to_bytes(8, "big", signed=True)
        )
        assert verify(auditor_public_key, verdict_data, verdict.signature)

        # 8. Dispute is resolved
        record = auditor_service.get_dispute(dispute_id)
        assert record.state == DisputeState.RESOLVED
        assert record.verdict == VerdictCode.CLAIMANT_WINS
        assert record.resolved_at is not None
