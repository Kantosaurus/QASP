"""Tests for fault attribution engine."""

from __future__ import annotations

import os

import pytest

from qasp.auditor.fault import (
    FaultAttributor,
    FaultRecord,
    FaultType,
)
from qasp.auditor.service import AuditorService
from qasp.crypto.signatures import generate_keypair, sign
from qasp.protocol.accounting import Receipt, ReceiptChain
from qasp.protocol.dispute import DisputeType, VerdictCode


# =============================================================================
# Helpers
# =============================================================================


def _make_receipt(
    signing_key: bytes,
    meter_id: bytes,
    seq: int,
    total_units: int,
    total_cost: int,
    prev_hash: bytes = b"",
) -> Receipt:
    from datetime import UTC, datetime

    receipt = Receipt(
        records=[],
        total_units=total_units,
        total_cost=total_cost,
        issued_at=datetime.now(UTC),
        issuer="test",
        signature=b"",
        sequence_number=seq,
        prev_hash=prev_hash,
        meter_id=meter_id,
    )
    sig = sign(signing_key, receipt.signable_bytes())
    return Receipt(
        records=receipt.records,
        total_units=receipt.total_units,
        total_cost=receipt.total_cost,
        issued_at=receipt.issued_at,
        issuer=receipt.issuer,
        signature=sig,
        sequence_number=receipt.sequence_number,
        prev_hash=receipt.prev_hash,
        meter_id=receipt.meter_id,
    )


def _build_chain(
    signing_key: bytes, meter_id: bytes, units_list: list[int],
) -> ReceiptChain:
    chain = ReceiptChain()
    prev_hash = b""
    for i, units in enumerate(units_list, start=1):
        receipt = _make_receipt(signing_key, meter_id, i, units, units, prev_hash)
        chain.append(receipt)
        prev_hash = receipt.compute_hash()
    return chain


# =============================================================================
# TestFaultAttributor
# =============================================================================


class TestFaultAttributor:
    """Tests for FaultAttributor."""

    def test_no_fault_no_discrepancies(self) -> None:
        """No fault when there are no discrepancies."""
        fa = FaultAttributor()
        result = fa.attribute(
            discrepancies=[],
            claimant_chain_valid=True,
            respondent_chain_valid=True,
            claimant_did="did:qasp:agent",
            respondent_did="did:qasp:server",
            dispute_id=os.urandom(32),
        )
        assert result is None

    def test_evidence_tampering_claimant(self) -> None:
        """Claimant chain invalid => evidence tampering on claimant."""
        fa = FaultAttributor()
        result = fa.attribute(
            discrepancies=[(1, 100, 100)],
            claimant_chain_valid=False,
            respondent_chain_valid=True,
            claimant_did="did:qasp:agent",
            respondent_did="did:qasp:server",
            dispute_id=os.urandom(32),
        )
        assert result is not None
        assert result.fault_type == FaultType.EVIDENCE_TAMPERING
        assert result.faulty_party_did == "did:qasp:agent"
        assert result.severity == 1.0

    def test_evidence_tampering_respondent(self) -> None:
        """Respondent chain invalid => evidence tampering on respondent."""
        fa = FaultAttributor()
        result = fa.attribute(
            discrepancies=[],
            claimant_chain_valid=True,
            respondent_chain_valid=False,
            claimant_did="did:qasp:agent",
            respondent_did="did:qasp:server",
            dispute_id=os.urandom(32),
        )
        assert result is not None
        assert result.fault_type == FaultType.EVIDENCE_TAMPERING
        assert result.faulty_party_did == "did:qasp:server"

    def test_systematic_overcharge(self) -> None:
        """3+ same-direction overcharges => systematic overcharge on server."""
        fa = FaultAttributor()
        # respondent > claimant in all 3 discrepancies
        discrepancies = [(1, 100, 110), (2, 200, 220), (3, 300, 330)]
        result = fa.attribute(
            discrepancies=discrepancies,
            claimant_chain_valid=True,
            respondent_chain_valid=True,
            claimant_did="did:qasp:agent",
            respondent_did="did:qasp:server",
            dispute_id=os.urandom(32),
            total_units=630,
        )
        assert result is not None
        assert result.fault_type == FaultType.SYSTEMATIC_OVERCHARGE
        assert result.faulty_party_did == "did:qasp:server"

    def test_systematic_underreport(self) -> None:
        """3+ same-direction underreports => systematic underreport on claimant."""
        fa = FaultAttributor()
        # claimant > respondent in all 3
        discrepancies = [(1, 110, 100), (2, 220, 200), (3, 330, 300)]
        result = fa.attribute(
            discrepancies=discrepancies,
            claimant_chain_valid=True,
            respondent_chain_valid=True,
            claimant_did="did:qasp:agent",
            respondent_did="did:qasp:server",
            dispute_id=os.urandom(32),
            total_units=600,
        )
        assert result is not None
        assert result.fault_type == FaultType.SYSTEMATIC_UNDERREPORT
        assert result.faulty_party_did == "did:qasp:agent"

    def test_metering_malfunction_mixed(self) -> None:
        """Mixed discrepancies => metering malfunction (lower severity)."""
        fa = FaultAttributor()
        # Mixed: some overcharge, some underreport
        discrepancies = [(1, 100, 110), (2, 220, 200)]
        result = fa.attribute(
            discrepancies=discrepancies,
            claimant_chain_valid=True,
            respondent_chain_valid=True,
            claimant_did="did:qasp:agent",
            respondent_did="did:qasp:server",
            dispute_id=os.urandom(32),
            total_units=300,
        )
        assert result is not None
        assert result.fault_type == FaultType.METERING_MALFUNCTION

    def test_severity_computation(self) -> None:
        """Severity is clamped to [0, 1]."""
        assert FaultAttributor.compute_severity(50, 100) == 0.5
        assert FaultAttributor.compute_severity(200, 100) == 1.0
        assert FaultAttributor.compute_severity(0, 100) == 0.0
        assert FaultAttributor.compute_severity(10, 0) == 1.0  # max(0,1)=1

    def test_reputation_penalty_mapping(self) -> None:
        """Penalty scales with fault type and severity."""
        fa = FaultAttributor()
        record = FaultRecord(
            dispute_id=b"test",
            faulty_party_did="did:qasp:x",
            fault_type=FaultType.EVIDENCE_TAMPERING,
            severity=1.0,
            discrepancy_count=1,
            total_discrepancy_units=100,
            timestamp=0.0,
        )
        penalty = fa.compute_reputation_penalty(record)
        assert 0.0 < penalty <= 1.0

        # Lower severity => lower penalty
        mild = FaultRecord(
            dispute_id=b"test",
            faulty_party_did="did:qasp:x",
            fault_type=FaultType.METERING_MALFUNCTION,
            severity=0.1,
            discrepancy_count=1,
            total_discrepancy_units=10,
            timestamp=0.0,
        )
        mild_penalty = fa.compute_reputation_penalty(mild)
        assert mild_penalty < penalty


# =============================================================================
# TestEnhancedAuditorReview
# =============================================================================


class TestEnhancedAuditorReview:
    """Tests for enhanced AuditorService with fault attribution."""

    def test_review_with_fault_attribution(
        self,
        auditor_service: AuditorService,
        claimant_did: str,
        respondent_did: str,
        claimant_secret_key: bytes,
        claimant_public_key: bytes,
        respondent_secret_key: bytes,
        respondent_public_key: bytes,
    ) -> None:
        """Review produces a fault record when chains diverge."""
        dispute_id = os.urandom(32)
        token_id = os.urandom(32)
        meter_id = os.urandom(16)

        auditor_service.open_dispute(
            dispute_id=dispute_id,
            token_id=token_id,
            claimant_did=claimant_did,
            respondent_did=respondent_did,
            dispute_type=DisputeType.OVERCHARGE,
            claimed_value=100,
        )

        # Create divergent chains
        claimant_chain = _build_chain(claimant_secret_key, meter_id, [100, 200, 300])
        respondent_chain = _build_chain(respondent_secret_key, meter_id, [100, 250, 400])

        verdict = auditor_service.review_dispute(
            dispute_id=dispute_id,
            claimant_chain=claimant_chain,
            respondent_chain=respondent_chain,
            claimant_public_key=claimant_public_key,
            respondent_public_key=respondent_public_key,
        )
        assert verdict.dispute_id == dispute_id

        fault = auditor_service.get_fault_record(dispute_id)
        assert fault is not None
        assert fault.discrepancy_count > 0

    def test_review_backward_compatible(
        self,
        auditor_service: AuditorService,
        claimant_did: str,
        respondent_did: str,
    ) -> None:
        """Review still works without new optional parameters."""
        dispute_id = os.urandom(32)
        auditor_service.open_dispute(
            dispute_id=dispute_id,
            token_id=os.urandom(32),
            claimant_did=claimant_did,
            respondent_did=respondent_did,
            dispute_type=DisputeType.USAGE_MISMATCH,
            claimed_value=50,
        )
        verdict = auditor_service.review_dispute(dispute_id=dispute_id)
        assert verdict.dispute_id == dispute_id

    def test_fault_record_stored(
        self,
        auditor_service: AuditorService,
        claimant_did: str,
        respondent_did: str,
        claimant_secret_key: bytes,
        claimant_public_key: bytes,
        respondent_secret_key: bytes,
        respondent_public_key: bytes,
    ) -> None:
        """Fault record is stored and retrievable."""
        dispute_id = os.urandom(32)
        meter_id = os.urandom(16)

        auditor_service.open_dispute(
            dispute_id=dispute_id,
            token_id=os.urandom(32),
            claimant_did=claimant_did,
            respondent_did=respondent_did,
            dispute_type=DisputeType.OVERCHARGE,
            claimed_value=200,
        )

        claimant_chain = _build_chain(claimant_secret_key, meter_id, [100])
        respondent_chain = _build_chain(respondent_secret_key, meter_id, [200])

        auditor_service.review_dispute(
            dispute_id=dispute_id,
            claimant_chain=claimant_chain,
            respondent_chain=respondent_chain,
            claimant_public_key=claimant_public_key,
            respondent_public_key=respondent_public_key,
        )

        fault = auditor_service.get_fault_record(dispute_id)
        assert fault is not None
        assert fault.dispute_id == dispute_id

    def test_no_fault_record_when_no_discrepancy(
        self,
        auditor_service: AuditorService,
        claimant_did: str,
        respondent_did: str,
        claimant_secret_key: bytes,
        claimant_public_key: bytes,
    ) -> None:
        """No fault record when chains agree."""
        dispute_id = os.urandom(32)
        meter_id = os.urandom(16)

        auditor_service.open_dispute(
            dispute_id=dispute_id,
            token_id=os.urandom(32),
            claimant_did=claimant_did,
            respondent_did=respondent_did,
            dispute_type=DisputeType.USAGE_MISMATCH,
        )

        chain = _build_chain(claimant_secret_key, meter_id, [100, 200])

        auditor_service.review_dispute(
            dispute_id=dispute_id,
            claimant_chain=chain,
            respondent_chain=chain,
            claimant_public_key=claimant_public_key,
            respondent_public_key=claimant_public_key,
        )

        fault = auditor_service.get_fault_record(dispute_id)
        assert fault is None
