"""Standalone Auditor service for dispute resolution.

The Auditor is an independent entity with its own ML-DSA-65 identity
that arbitrates disputes between claimants and respondents by verifying
receipt chains, comparing evidence, and issuing binding verdicts.
"""

from __future__ import annotations

from datetime import UTC, datetime

from qasp.crypto.signatures import sign
from qasp.framing.messages import DisputeVerdict
from qasp.protocol.accounting import ReceiptChain, ReceiptChainError
from qasp.protocol.dispute import (
    DisputeNotFoundError,
    DisputeRecord,
    DisputeState,
    DisputeType,
    DuplicateDisputeError,
    EvidencePackage,
    InvalidDisputeStateError,
    VerdictCode,
)

__all__ = ["AuditorService"]


class AuditorService:
    """Standalone auditor that arbitrates disputes.

    The auditor has its own ML-DSA-65 keypair and can:
    - Accept dispute-open requests
    - Collect signed evidence from both parties
    - Verify receipt chain integrity
    - Compare receipt chains for discrepancies
    - Issue signed, binding verdicts
    """

    def __init__(
        self,
        auditor_did: str,
        secret_key: bytes,
        public_key: bytes,
    ) -> None:
        self._auditor_did = auditor_did
        self._secret_key = secret_key
        self._public_key = public_key
        self._disputes: dict[bytes, DisputeRecord] = {}

    @property
    def auditor_did(self) -> str:
        return self._auditor_did

    @property
    def public_key(self) -> bytes:
        return self._public_key

    def open_dispute(
        self,
        dispute_id: bytes,
        token_id: bytes,
        claimant_did: str,
        respondent_did: str,
        dispute_type: DisputeType,
        claimed_value: int = 0,
    ) -> DisputeRecord:
        """Open a new dispute.

        Args:
            dispute_id: Unique dispute identifier.
            token_id: Token related to the dispute.
            claimant_did: DID of the claimant.
            respondent_did: DID of the respondent.
            dispute_type: Type of dispute.
            claimed_value: Value claimed by claimant.

        Returns:
            The created DisputeRecord.

        Raises:
            DuplicateDisputeError: If a dispute with this ID already exists.
        """
        if dispute_id in self._disputes:
            raise DuplicateDisputeError(
                f"Dispute {dispute_id.hex()} already exists"
            )
        record = DisputeRecord(
            dispute_id=dispute_id,
            token_id=token_id,
            claimant_did=claimant_did,
            respondent_did=respondent_did,
            dispute_type=dispute_type,
            claimed_value=claimed_value,
        )
        record.transition_to(DisputeState.EVIDENCE_SUBMISSION)
        self._disputes[dispute_id] = record
        return record

    def submit_evidence(
        self,
        dispute_id: bytes,
        evidence_package: EvidencePackage,
    ) -> None:
        """Submit evidence for a dispute.

        Args:
            dispute_id: The dispute to submit evidence for.
            evidence_package: The signed evidence package.

        Raises:
            DisputeNotFoundError: If the dispute doesn't exist.
            InvalidDisputeStateError: If not in evidence submission state.
        """
        record = self.get_dispute(dispute_id)
        if record.state != DisputeState.EVIDENCE_SUBMISSION:
            raise InvalidDisputeStateError(
                record.state, DisputeState.EVIDENCE_SUBMISSION
            )
        record.evidence.append(evidence_package)

    def get_dispute(self, dispute_id: bytes) -> DisputeRecord:
        """Retrieve a dispute by ID.

        Raises:
            DisputeNotFoundError: If the dispute doesn't exist.
        """
        record = self._disputes.get(dispute_id)
        if record is None:
            raise DisputeNotFoundError(
                f"Dispute {dispute_id.hex()} not found"
            )
        return record

    def review_dispute(
        self,
        dispute_id: bytes,
        claimant_chain: ReceiptChain | None = None,
        respondent_chain: ReceiptChain | None = None,
        claimant_public_key: bytes | None = None,
        respondent_public_key: bytes | None = None,
    ) -> DisputeVerdict:
        """Review a dispute and issue a verdict.

        Verifies receipt chains, compares evidence, and computes
        a binding payment adjustment.

        Args:
            dispute_id: The dispute to review.
            claimant_chain: Claimant's receipt chain.
            respondent_chain: Respondent's receipt chain.
            claimant_public_key: Claimant's public key for chain verification.
            respondent_public_key: Respondent's public key for chain verification.

        Returns:
            A signed DisputeVerdict message.
        """
        record = self.get_dispute(dispute_id)
        record.transition_to(DisputeState.UNDER_REVIEW)

        # Verify receipt chains if provided
        claimant_valid = True
        respondent_valid = True

        if claimant_chain and claimant_public_key:
            claimant_valid = self._verify_receipt_chain(
                claimant_chain, claimant_public_key
            )

        if respondent_chain and respondent_public_key:
            respondent_valid = self._verify_receipt_chain(
                respondent_chain, respondent_public_key
            )

        # Compare chains and determine verdict
        verdict_code, awarded_value = self._evaluate_dispute(
            record,
            claimant_chain,
            respondent_chain,
            claimant_valid,
            respondent_valid,
        )

        return self._issue_verdict(dispute_id, verdict_code, awarded_value)

    def _verify_receipt_chain(
        self,
        chain: ReceiptChain,
        issuer_public_key: bytes,
    ) -> bool:
        """Validate a receipt chain's integrity.

        Returns:
            True if the chain is valid, False if tampered.
        """
        try:
            return chain.verify(issuer_public_key)
        except (ReceiptChainError, Exception):
            return False

    def _compare_receipt_chains(
        self,
        chain_a: ReceiptChain,
        chain_b: ReceiptChain,
    ) -> list[tuple[int, int, int]]:
        """Find discrepancies between two receipt chains.

        Returns:
            List of (sequence_number, chain_a_units, chain_b_units)
            tuples where the chains disagree.
        """
        discrepancies: list[tuple[int, int, int]] = []
        a_by_seq = {r.sequence_number: r for r in chain_a.receipts}
        b_by_seq = {r.sequence_number: r for r in chain_b.receipts}

        all_seqs = sorted(set(a_by_seq.keys()) | set(b_by_seq.keys()))
        for seq in all_seqs:
            a_units = a_by_seq[seq].total_units if seq in a_by_seq else 0
            b_units = b_by_seq[seq].total_units if seq in b_by_seq else 0
            if a_units != b_units:
                discrepancies.append((seq, a_units, b_units))

        return discrepancies

    def _evaluate_dispute(
        self,
        record: DisputeRecord,
        claimant_chain: ReceiptChain | None,
        respondent_chain: ReceiptChain | None,
        claimant_valid: bool,
        respondent_valid: bool,
    ) -> tuple[VerdictCode, int]:
        """Evaluate the dispute and determine verdict + awarded value."""
        # If respondent's chain is invalid, claimant wins
        if not respondent_valid and claimant_valid:
            return VerdictCode.CLAIMANT_WINS, record.claimed_value

        # If claimant's chain is invalid, respondent wins
        if not claimant_valid and respondent_valid:
            return VerdictCode.RESPONDENT_WINS, 0

        # If both invalid, dismiss
        if not claimant_valid and not respondent_valid:
            return VerdictCode.DISMISSED, 0

        # Both valid — compare chains
        if claimant_chain and respondent_chain:
            discrepancies = self._compare_receipt_chains(
                claimant_chain, respondent_chain
            )
            if discrepancies:
                adjustment = self._compute_adjustment(record, discrepancies)
                if adjustment > 0:
                    return VerdictCode.CLAIMANT_WINS, adjustment
                elif adjustment < 0:
                    return VerdictCode.RESPONDENT_WINS, 0
                else:
                    return VerdictCode.SPLIT, record.claimed_value // 2

        # No discrepancies found or no chains provided
        if not claimant_chain and not respondent_chain:
            # Evidence-only dispute: use evidence count heuristic
            claimant_evidence = [
                e for e in record.evidence
                if e.submitter_did == record.claimant_did
            ]
            respondent_evidence = [
                e for e in record.evidence
                if e.submitter_did == record.respondent_did
            ]
            if len(claimant_evidence) > len(respondent_evidence):
                return VerdictCode.CLAIMANT_WINS, record.claimed_value
            elif len(respondent_evidence) > len(claimant_evidence):
                return VerdictCode.RESPONDENT_WINS, 0
            return VerdictCode.SPLIT, record.claimed_value // 2

        return VerdictCode.DISMISSED, 0

    def _compute_adjustment(
        self,
        _record: DisputeRecord,
        discrepancies: list[tuple[int, int, int]],
    ) -> int:
        """Calculate binding payment adjustment from discrepancies.

        Positive = claimant was overcharged (owes less).
        Negative = claimant under-reported (owes more).
        """
        total_diff = 0
        for _seq, claimant_units, respondent_units in discrepancies:
            total_diff += respondent_units - claimant_units
        return total_diff

    def _issue_verdict(
        self,
        dispute_id: bytes,
        verdict_code: VerdictCode,
        awarded_value: int,
    ) -> DisputeVerdict:
        """Issue a signed verdict for a dispute.

        Returns:
            A signed DisputeVerdict wire message.
        """
        record = self.get_dispute(dispute_id)
        record.verdict = verdict_code
        record.resolved_at = datetime.now(UTC)
        record.transition_to(DisputeState.RESOLVED)

        # Sign the verdict
        verdict_data = (
            dispute_id
            + int(verdict_code).to_bytes(4, "big")
            + awarded_value.to_bytes(8, "big", signed=True)
        )
        sig = sign(self._secret_key, verdict_data)

        return DisputeVerdict(
            dispute_id=dispute_id,
            verdict=int(verdict_code),
            awarded_value=awarded_value,
            arbiter_id=self._auditor_did.encode(),
            signature=sig,
        )
