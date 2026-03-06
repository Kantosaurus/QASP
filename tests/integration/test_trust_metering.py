"""Integration tests for trust + metering pipeline."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from qasp.identity import DID
from qasp.protocol.accounting import Meter, ReceiptChain
from qasp.protocol.budget import BudgetExhaustedError, BudgetMeter, MeterStatus
from qasp.protocol.capability import (
    TokenRevokedError,
    attenuate_token,
    create_token,
    verify_token,
)
from qasp.protocol.revocation import (
    CertificateRevocationList,
    RevocationReason,
    RevocationUrgency,
)
from qasp.trust.behavioral import BehavioralVerifier, BehaviorEvent, BehaviorType
from qasp.trust.certification import create_audit_vc, verify_audit_vc
from qasp.trust.registry import TrustRegistry
from qasp.trust.reputation import ReputationModel
from qasp.trust.scoring import TrustScorer

# ============================================================================
# Class 1: TestTwoAgentReputationIntegration
# ============================================================================


@pytest.mark.integration
class TestTwoAgentReputationIntegration:
    def test_reputation_updates_after_interactions(
        self,
        trust_registry: TrustRegistry,
        agent_a_did: DID,
        agent_b_did: DID,
    ) -> None:
        trust_registry.register(agent_a_did)
        trust_registry.register(agent_b_did)

        # Agent A: 3 success, 1 fail
        for _ in range(3):
            trust_registry.update_reputation(agent_a_did, success=True)
        trust_registry.update_reputation(agent_a_did, success=False)

        # Agent B: 1 success, 3 fail
        trust_registry.update_reputation(agent_b_did, success=True)
        for _ in range(3):
            trust_registry.update_reputation(agent_b_did, success=False)

        entry_a = trust_registry.get(agent_a_did)
        entry_b = trust_registry.get(agent_b_did)

        assert entry_a.reputation_score > 0.5
        assert entry_b.reputation_score < 0.5

    def test_reputation_model_score_matches_registry(
        self,
        trust_registry: TrustRegistry,
        agent_a_did: DID,
    ) -> None:
        trust_registry.register(agent_a_did)
        for _ in range(5):
            trust_registry.update_reputation(agent_a_did, success=True)
        trust_registry.update_reputation(agent_a_did, success=False)

        entry = trust_registry.get(agent_a_did)
        model = ReputationModel(entry.reputation_alpha, entry.reputation_beta)
        score = model.score()

        assert abs(score.mean - entry.reputation_score) < 1e-10

    def test_reputation_confidence_increases(
        self,
        trust_registry: TrustRegistry,
        agent_a_did: DID,
    ) -> None:
        trust_registry.register(agent_a_did)

        trust_registry.update_reputation(agent_a_did, success=True)
        entry_early = trust_registry.get(agent_a_did)
        model_early = ReputationModel(entry_early.reputation_alpha, entry_early.reputation_beta)
        conf_early = model_early.score().confidence

        for _ in range(20):
            trust_registry.update_reputation(agent_a_did, success=True)
        entry_late = trust_registry.get(agent_a_did)
        model_late = ReputationModel(entry_late.reputation_alpha, entry_late.reputation_beta)
        conf_late = model_late.score().confidence

        assert conf_late > conf_early

    def test_probability_above_threshold(self) -> None:
        model = ReputationModel()
        for _ in range(30):
            model = model.update(success=True)
        for _ in range(2):
            model = model.update(success=False)

        prob = model.probability_above(0.5)
        assert prob > 0.9


# ============================================================================
# Class 2: TestColdStartAuditVCBoost
# ============================================================================


@pytest.mark.integration
class TestColdStartAuditVCBoost:
    def test_cold_start_boost_with_audit_vc(
        self,
        trust_registry: TrustRegistry,
        agent_a_did: DID,
        agent_b_did: DID,
        auditor_did: DID,
        auditor_secret_key: bytes,
        sample_code_hash: bytes,
    ) -> None:
        trust_registry.register(agent_a_did)
        trust_registry.register(agent_b_did)

        vc = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_a_did,
            audit_scope="full",
            code_version_hash=sample_code_hash,
            audit_result="pass",
            slsa_level=3,
        )
        trust_registry.add_audit_vc(agent_a_did, vc)

        entry_a = trust_registry.get(agent_a_did)
        entry_b = trust_registry.get(agent_b_did)

        # Use low but non-zero confidence so scores aren't blended to 0.5
        scorer = TrustScorer()
        score_a = scorer.calculate(
            certification_score=entry_a.audit_certified_score,
            reputation_score=entry_a.reputation_score,
            behavioral_score=entry_a.behavioral_score,
            reputation_confidence=0.1,
        )
        score_b = scorer.calculate(
            certification_score=entry_b.audit_certified_score,
            reputation_score=entry_b.reputation_score,
            behavioral_score=entry_b.behavioral_score,
            reputation_confidence=0.1,
        )

        assert score_a.overall > score_b.overall

    def test_vc_level_affects_boost_magnitude(
        self,
        trust_registry: TrustRegistry,
        agent_a_did: DID,
        agent_b_did: DID,
        auditor_did: DID,
        auditor_secret_key: bytes,
        sample_code_hash: bytes,
    ) -> None:
        trust_registry.register(agent_a_did)
        trust_registry.register(agent_b_did)

        vc3 = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_a_did,
            audit_scope="full",
            code_version_hash=sample_code_hash,
            audit_result="pass",
            slsa_level=3,
        )
        trust_registry.add_audit_vc(agent_a_did, vc3)

        vc1 = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_b_did,
            audit_scope="full",
            code_version_hash=sample_code_hash,
            audit_result="pass",
            slsa_level=1,
        )
        trust_registry.add_audit_vc(agent_b_did, vc1)

        entry_a = trust_registry.get(agent_a_did)
        entry_b = trust_registry.get(agent_b_did)

        scorer = TrustScorer()
        score_a = scorer.calculate(
            certification_score=entry_a.audit_certified_score,
            reputation_score=entry_a.reputation_score,
            behavioral_score=1.0,
            reputation_confidence=0.1,
        )
        score_b = scorer.calculate(
            certification_score=entry_b.audit_certified_score,
            reputation_score=entry_b.reputation_score,
            behavioral_score=1.0,
            reputation_confidence=0.1,
        )

        # SLSA-3 > SLSA-1
        assert score_a.overall > score_b.overall
        # SLSA-1 > no VC (0.0 cert score)
        score_none = scorer.calculate(
            certification_score=0.0,
            reputation_score=0.5,
            behavioral_score=1.0,
            reputation_confidence=0.1,
        )
        assert score_b.overall > score_none.overall

    def test_end_to_end_vc_pipeline(
        self,
        trust_registry: TrustRegistry,
        agent_a_did: DID,
        auditor_did: DID,
        auditor_public_key: bytes,
        auditor_secret_key: bytes,
        sample_code_hash: bytes,
    ) -> None:
        trust_registry.register(agent_a_did)

        # create -> verify -> add to registry -> score
        vc = create_audit_vc(
            issuer_did=auditor_did,
            issuer_secret_key=auditor_secret_key,
            agent_did=agent_a_did,
            audit_scope="security-audit",
            code_version_hash=sample_code_hash,
            audit_result="pass",
            slsa_level=3,
        )

        assert verify_audit_vc(vc, auditor_public_key)

        trust_registry.add_audit_vc(agent_a_did, vc)
        entry = trust_registry.get(agent_a_did)

        scorer = TrustScorer()
        score = scorer.calculate(
            certification_score=entry.audit_certified_score,
            reputation_score=entry.reputation_score,
            behavioral_score=entry.behavioral_score,
            reputation_confidence=0.1,
        )

        assert score.certification_component > 0.0
        assert score.overall > 0.0


# ============================================================================
# Class 3: TestBehavioralViolationPenalty
# ============================================================================


@pytest.mark.integration
class TestBehavioralViolationPenalty:
    def test_policy_violation_drops_score(self, agent_a_did: DID) -> None:
        verifier = BehavioralVerifier(str(agent_a_did))
        now = datetime.now(UTC)

        verifier.record_event(BehaviorEvent(BehaviorType.REQUEST, now, {}))
        verifier.record_event(BehaviorEvent(BehaviorType.RESPONSE, now, {}))
        verifier.record_event(BehaviorEvent(BehaviorType.POLICY_VIOLATION, now, {}))

        assert verifier.calculate_score() < 1.0

    def test_analyze_patterns_metrics(self, agent_a_did: DID) -> None:
        verifier = BehavioralVerifier(str(agent_a_did))
        now = datetime.now(UTC)

        # Alternate request/response to follow valid FSM transitions,
        # then add error and violation
        for _ in range(5):
            verifier.record_event(BehaviorEvent(BehaviorType.REQUEST, now, {}))
            verifier.record_event(BehaviorEvent(BehaviorType.RESPONSE, now, {}))
        verifier.record_event(BehaviorEvent(BehaviorType.ERROR, now, {}))
        verifier.record_event(BehaviorEvent(BehaviorType.POLICY_VIOLATION, now, {}))
        # 12 total events: 5 requests, 5 responses, 1 error, 1 violation

        patterns = verifier.analyze_patterns()
        assert patterns["total_events"] == 12.0
        assert abs(patterns["request_rate"] - 5 / 12) < 1e-10
        assert abs(patterns["error_rate"] - 1 / 12) < 1e-10
        assert abs(patterns["policy_violation_rate"] - 1 / 12) < 1e-10

    def test_violation_penalizes_trust_score(
        self,
        agent_a_did: DID,
        agent_b_did: DID,
    ) -> None:
        now = datetime.now(UTC)

        # Agent A: clean
        clean = BehavioralVerifier(str(agent_a_did))
        for _ in range(10):
            clean.record_event(BehaviorEvent(BehaviorType.REQUEST, now, {}))
            clean.record_event(BehaviorEvent(BehaviorType.RESPONSE, now, {}))

        # Agent B: violations
        dirty = BehavioralVerifier(str(agent_b_did))
        for _ in range(10):
            dirty.record_event(BehaviorEvent(BehaviorType.REQUEST, now, {}))
            dirty.record_event(BehaviorEvent(BehaviorType.RESPONSE, now, {}))
        for _ in range(5):
            dirty.record_event(BehaviorEvent(BehaviorType.POLICY_VIOLATION, now, {}))

        scorer = TrustScorer()
        score_clean = scorer.calculate(
            certification_score=None,
            reputation_score=0.5,
            behavioral_score=clean.calculate_score(),
            reputation_confidence=0.5,
        )
        score_dirty = scorer.calculate(
            certification_score=None,
            reputation_score=0.5,
            behavioral_score=dirty.calculate_score(),
            reputation_confidence=0.5,
        )

        assert score_clean.overall > score_dirty.overall


# ============================================================================
# Class 4: TestMeteringBudgetExhaustion
# ============================================================================


@pytest.mark.integration
class TestMeteringBudgetExhaustion:
    def test_receipt_chain_validates(
        self,
        agent_a_secret_key: bytes,
        agent_a_public_key: bytes,
    ) -> None:
        meter = Meter(session_id=b"sess1", issuer="agent-a")
        chain = ReceiptChain()

        prev_hash = b""
        for _ in range(3):
            meter.record("compute", "inference", units=10)
            receipt = meter.generate_receipt(agent_a_secret_key, prev_hash)
            chain.append(receipt)
            prev_hash = receipt.compute_hash()

        assert chain.verify(agent_a_public_key)
        assert len(chain) == 3

    def test_budget_exhaustion_triggers_suspend(self) -> None:
        inner = Meter(session_id=b"sess2", issuer="agent-a")
        bm = BudgetMeter(inner, budget=100)

        assert bm.status == MeterStatus.ACTIVE

        # Record up to the budget
        for _ in range(10):
            bm.record("compute", "inference", units=10)

        assert bm.status == MeterStatus.SUSPENDED
        assert bm.cumulative_units == 100

        with pytest.raises(BudgetExhaustedError):
            bm.record("compute", "inference", units=1)

    def test_receipt_chain_with_budget_tracking(
        self,
        agent_a_secret_key: bytes,
        agent_a_public_key: bytes,
    ) -> None:
        inner = Meter(session_id=b"sess3", issuer="agent-a")
        bm = BudgetMeter(inner, budget=50)
        chain = ReceiptChain()

        prev_hash = b""
        # Record 25 units, generate receipt
        for _ in range(5):
            bm.record("compute", "inference", units=5)
        receipt1 = bm.generate_receipt(agent_a_secret_key, prev_hash)
        chain.append(receipt1)
        prev_hash = receipt1.compute_hash()

        # Record 25 more -> budget exhausted
        for _ in range(5):
            bm.record("compute", "inference", units=5)
        assert bm.status == MeterStatus.SUSPENDED

        receipt2 = bm.generate_receipt(agent_a_secret_key, prev_hash)
        chain.append(receipt2)

        assert chain.verify(agent_a_public_key)

        with pytest.raises(BudgetExhaustedError):
            bm.record("compute", "inference", units=1)

    def test_receipt_cbor_roundtrip(
        self,
        agent_a_secret_key: bytes,
    ) -> None:
        meter = Meter(session_id=b"sess4", issuer="agent-a")
        chain = ReceiptChain()

        prev_hash = b""
        for _ in range(3):
            meter.record("compute", "inference", units=10)
            receipt = meter.generate_receipt(agent_a_secret_key, prev_hash)
            chain.append(receipt)
            prev_hash = receipt.compute_hash()

        # Serialize and deserialize
        cbor_data = chain.to_cbor()
        restored = ReceiptChain.from_cbor(cbor_data)

        assert len(restored) == len(chain)
        for orig, rest in zip(chain.receipts, restored.receipts, strict=True):
            assert orig.total_units == rest.total_units
            assert orig.sequence_number == rest.sequence_number
            assert orig.prev_hash == rest.prev_hash
            assert orig.signature == rest.signature


# ============================================================================
# Class 5: TestRevocationCascadeAcrossServers
# ============================================================================


@pytest.mark.integration
class TestRevocationCascadeAcrossServers:
    def _make_chain(
        self,
        crl: CertificateRevocationList,
        issuer_did: DID,
        issuer_sk: bytes,
        subject_did: DID,
        subject_sk: bytes,
        delegate_did: DID,
    ) -> tuple:
        root = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_sk,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read", "write"},
            max_delegation_depth=3,
        )
        crl.register_token(root)

        child = attenuate_token(
            parent_token=root,
            delegator_secret_key=subject_sk,
            new_subject_did=delegate_did,
        )
        crl.register_token(child)

        grandchild = attenuate_token(
            parent_token=child,
            delegator_secret_key=subject_sk,
            new_subject_did=issuer_did,
        )
        crl.register_token(grandchild)

        return root, child, grandchild

    def test_cascade_across_two_crls(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_b_did: DID,
        agent_b_secret_key: bytes,
        auditor_did: DID,
    ) -> None:
        crl_a = CertificateRevocationList()
        crl_b = CertificateRevocationList()

        root, child, grandchild = self._make_chain(
            crl_a, agent_a_did, agent_a_secret_key,
            agent_b_did, agent_b_secret_key, auditor_did,
        )
        # Register same tokens in CRL_B
        crl_b.register_token(root)
        crl_b.register_token(child)
        crl_b.register_token(grandchild)

        # Revoke root on CRL_A
        entries_a = crl_a.revoke(
            token_id=root.token_id,
            reason=RevocationReason.KEY_COMPROMISE,
            urgency=RevocationUrgency.CRITICAL,
            revoker_did=str(agent_a_did),
            revoker_secret_key=agent_a_secret_key,
        )

        # Broadcast: revoke same entries on CRL_B
        for entry in entries_a:
            if entry.token_id not in crl_b:
                crl_b.revoke(
                    token_id=entry.token_id,
                    reason=entry.reason,
                    urgency=entry.urgency,
                    revoker_did=entry.revoker_did,
                    revoker_secret_key=agent_a_secret_key,
                )

        # All 3 revoked on both
        for token in (root, child, grandchild):
            assert crl_a.is_revoked(token.token_id)
            assert crl_b.is_revoked(token.token_id)

    def test_cascade_reason_is_delegation_revoked(
        self,
        agent_a_did: DID,
        agent_a_secret_key: bytes,
        agent_b_did: DID,
        agent_b_secret_key: bytes,
        auditor_did: DID,
    ) -> None:
        crl = CertificateRevocationList()
        root, child, grandchild = self._make_chain(
            crl, agent_a_did, agent_a_secret_key,
            agent_b_did, agent_b_secret_key, auditor_did,
        )

        crl.revoke(
            token_id=root.token_id,
            reason=RevocationReason.KEY_COMPROMISE,
            urgency=RevocationUrgency.CRITICAL,
            revoker_did=str(agent_a_did),
            revoker_secret_key=agent_a_secret_key,
        )

        root_entry = crl.get_entry(root.token_id)
        child_entry = crl.get_entry(child.token_id)
        grandchild_entry = crl.get_entry(grandchild.token_id)

        assert root_entry is not None
        assert root_entry.reason == RevocationReason.KEY_COMPROMISE
        assert child_entry is not None
        assert child_entry.reason == RevocationReason.DELEGATION_REVOKED
        assert grandchild_entry is not None
        assert grandchild_entry.reason == RevocationReason.DELEGATION_REVOKED

    def test_verify_token_raises_after_cascade(
        self,
        agent_a_did: DID,
        agent_a_public_key: bytes,
        agent_a_secret_key: bytes,
        agent_b_did: DID,
        agent_b_secret_key: bytes,
        auditor_did: DID,
    ) -> None:
        crl_a = CertificateRevocationList()
        crl_b = CertificateRevocationList()

        root, child, grandchild = self._make_chain(
            crl_a, agent_a_did, agent_a_secret_key,
            agent_b_did, agent_b_secret_key, auditor_did,
        )
        crl_b.register_token(root)
        crl_b.register_token(child)
        crl_b.register_token(grandchild)

        # Revoke on CRL_A, broadcast to CRL_B
        entries = crl_a.revoke(
            token_id=root.token_id,
            reason=RevocationReason.KEY_COMPROMISE,
            urgency=RevocationUrgency.CRITICAL,
            revoker_did=str(agent_a_did),
            revoker_secret_key=agent_a_secret_key,
        )
        for entry in entries:
            if entry.token_id not in crl_b:
                crl_b.revoke(
                    token_id=entry.token_id,
                    reason=entry.reason,
                    urgency=entry.urgency,
                    revoker_did=entry.revoker_did,
                    revoker_secret_key=agent_a_secret_key,
                )

        # verify_token should raise for all descendants on both CRLs
        for crl in (crl_a, crl_b):
            for token in (root, child, grandchild):
                with pytest.raises(TokenRevokedError):
                    verify_token(
                        token,
                        agent_a_public_key,
                        check_expiry=False,
                        crl=crl,
                    )
