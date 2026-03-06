"""Fault attribution engine for dispute resolution.

This module implements fault analysis for QASP disputes:
- FaultAttributor: analyzes receipt chain discrepancies to determine
  which party is at fault and the severity of the fault
- FaultRecord: immutable record of an attribution decision
- Reputation penalty computation for trust registry integration
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import IntEnum

__all__ = [
    "FLAG_EVIDENCE_TAMPERING",
    "FLAG_METERING_FAULT",
    "FLAG_SYSTEMATIC_OVERCHARGE",
    "FLAG_SYSTEMATIC_UNDERREPORT",
    "FaultAttributor",
    "FaultRecord",
    "FaultType",
]


# =============================================================================
# Constants
# =============================================================================

FLAG_METERING_FAULT = "metering_fault"
FLAG_SYSTEMATIC_OVERCHARGE = "systematic_overcharge"
FLAG_SYSTEMATIC_UNDERREPORT = "systematic_underreport"
FLAG_EVIDENCE_TAMPERING = "evidence_tampering"


# =============================================================================
# Enums
# =============================================================================


class FaultType(IntEnum):
    """Types of fault that can be attributed."""

    NO_FAULT = 0
    SYSTEMATIC_OVERCHARGE = 1
    SYSTEMATIC_UNDERREPORT = 2
    METERING_MALFUNCTION = 3
    EVIDENCE_TAMPERING = 4


# =============================================================================
# Data Classes
# =============================================================================


@dataclass(frozen=True)
class FaultRecord:
    """Immutable record of a fault attribution decision."""

    dispute_id: bytes
    faulty_party_did: str
    fault_type: FaultType
    severity: float
    discrepancy_count: int
    total_discrepancy_units: int
    timestamp: float


# =============================================================================
# FaultAttributor
# =============================================================================


class FaultAttributor:
    """Analyzes dispute evidence to attribute fault.

    Uses receipt chain discrepancies, chain validity, and directional
    consistency to determine which party caused the metering disagreement.
    """

    SYSTEMATIC_THRESHOLD = 3

    def attribute(
        self,
        discrepancies: list[tuple[int, int, int]],
        claimant_chain_valid: bool,
        respondent_chain_valid: bool,
        claimant_did: str,
        respondent_did: str,
        dispute_id: bytes,
        total_units: int = 0,
    ) -> FaultRecord | None:
        """Attribute fault based on evidence analysis.

        Args:
            discrepancies: List of (seq, claimant_units, respondent_units).
            claimant_chain_valid: Whether the claimant's chain verified.
            respondent_chain_valid: Whether the respondent's chain verified.
            claimant_did: DID of the claimant (typically the agent).
            respondent_did: DID of the respondent (typically the server).
            dispute_id: The dispute being analyzed.
            total_units: Total units for severity computation.

        Returns:
            A FaultRecord if fault is found, None if no fault.
        """
        now = time.time()

        # Rule 1: Invalid chain = evidence tampering
        if not claimant_chain_valid and respondent_chain_valid:
            return FaultRecord(
                dispute_id=dispute_id,
                faulty_party_did=claimant_did,
                fault_type=FaultType.EVIDENCE_TAMPERING,
                severity=1.0,
                discrepancy_count=len(discrepancies),
                total_discrepancy_units=self._total_discrepancy(discrepancies),
                timestamp=now,
            )

        if not respondent_chain_valid and claimant_chain_valid:
            return FaultRecord(
                dispute_id=dispute_id,
                faulty_party_did=respondent_did,
                fault_type=FaultType.EVIDENCE_TAMPERING,
                severity=1.0,
                discrepancy_count=len(discrepancies),
                total_discrepancy_units=self._total_discrepancy(discrepancies),
                timestamp=now,
            )

        if not discrepancies:
            return None

        # Analyze direction of discrepancies
        overcharge_count = 0  # respondent claims more than claimant
        underreport_count = 0  # claimant claims more than respondent
        for _seq, claimant_units, respondent_units in discrepancies:
            if respondent_units > claimant_units:
                overcharge_count += 1
            elif claimant_units > respondent_units:
                underreport_count += 1

        total_disc = self._total_discrepancy(discrepancies)
        severity = self.compute_severity(total_disc, total_units)

        # Rule 2: Systematic same-direction discrepancies
        if overcharge_count >= self.SYSTEMATIC_THRESHOLD and underreport_count == 0:
            return FaultRecord(
                dispute_id=dispute_id,
                faulty_party_did=respondent_did,
                fault_type=FaultType.SYSTEMATIC_OVERCHARGE,
                severity=severity,
                discrepancy_count=len(discrepancies),
                total_discrepancy_units=total_disc,
                timestamp=now,
            )

        if underreport_count >= self.SYSTEMATIC_THRESHOLD and overcharge_count == 0:
            return FaultRecord(
                dispute_id=dispute_id,
                faulty_party_did=claimant_did,
                fault_type=FaultType.SYSTEMATIC_UNDERREPORT,
                severity=severity,
                discrepancy_count=len(discrepancies),
                total_discrepancy_units=total_disc,
                timestamp=now,
            )

        # Rule 3: Mixed discrepancies = metering malfunction (lower severity)
        return FaultRecord(
            dispute_id=dispute_id,
            faulty_party_did=respondent_did,
            fault_type=FaultType.METERING_MALFUNCTION,
            severity=severity * 0.5,
            discrepancy_count=len(discrepancies),
            total_discrepancy_units=total_disc,
            timestamp=now,
        )

    @staticmethod
    def compute_severity(total_discrepancy: int, total_units: int) -> float:
        """Compute fault severity as ratio of discrepancy to total.

        Returns a float in [0.0, 1.0].
        """
        return min(1.0, abs(total_discrepancy) / max(total_units, 1))

    @staticmethod
    def compute_reputation_penalty(fault: FaultRecord) -> float:
        """Compute reputation penalty multiplier for a fault.

        Returns a penalty in [0.0, 1.0] to be applied as:
            new_score = old_score * (1 - penalty)
        """
        base_penalties = {
            FaultType.NO_FAULT: 0.0,
            FaultType.EVIDENCE_TAMPERING: 0.5,
            FaultType.SYSTEMATIC_OVERCHARGE: 0.3,
            FaultType.SYSTEMATIC_UNDERREPORT: 0.3,
            FaultType.METERING_MALFUNCTION: 0.1,
        }
        base = base_penalties.get(fault.fault_type, 0.1)
        return min(1.0, base * fault.severity + base * 0.5)

    @staticmethod
    def _total_discrepancy(
        discrepancies: list[tuple[int, int, int]],
    ) -> int:
        """Sum absolute differences across all discrepancies."""
        return sum(
            abs(claimant - respondent)
            for _seq, claimant, respondent in discrepancies
        )
