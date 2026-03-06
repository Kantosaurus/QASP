"""Tests for temporal capability evolution."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from qasp.identity import DID
from qasp.protocol.capability import (
    AttenuationError,
    CapabilityToken,
    Constraints,
    InvalidDelegationChainError,
    TemporalSchedule,
    TemporalScheduleError,
    TemporalThreshold,
    TokenConstraintViolation,
    TokenUsage,
    attenuate_token,
    create_token,
    evaluate_temporal_constraints,
    exponential_decay_schedule,
    linear_decay_schedule,
    step_schedule,
    verify_delegation_chain,
    verify_token,
)
from qasp.protocol.metering import (
    Constraints as MConstraints,
    ManagedResource,
    ResourceManager,
    ResourceState,
    SuspendReason,
)


# =============================================================================
# TemporalThreshold Tests
# =============================================================================


class TestTemporalThreshold:
    """Tests for TemporalThreshold data structure."""

    def test_construction(self) -> None:
        t = TemporalThreshold(at_seconds=600, max_spend=500)
        assert t.at_seconds == 600
        assert t.max_spend == 500
        assert t.quantity_limit is None
        assert t.rate_limit is None

    def test_all_fields(self) -> None:
        t = TemporalThreshold(
            at_seconds=300, max_spend=100, quantity_limit=50, rate_limit=10,
        )
        assert t.max_spend == 100
        assert t.quantity_limit == 50
        assert t.rate_limit == 10

    def test_immutability(self) -> None:
        t = TemporalThreshold(at_seconds=60, max_spend=100)
        with pytest.raises(AttributeError):
            t.max_spend = 200  # type: ignore[misc]


# =============================================================================
# TemporalSchedule Tests
# =============================================================================


class TestTemporalSchedule:
    """Tests for TemporalSchedule data structure."""

    def test_empty_thresholds(self) -> None:
        s = TemporalSchedule(thresholds=())
        assert len(s.thresholds) == 0

    def test_sorted_thresholds(self) -> None:
        s = TemporalSchedule(thresholds=(
            TemporalThreshold(at_seconds=100),
            TemporalThreshold(at_seconds=200),
            TemporalThreshold(at_seconds=300),
        ))
        assert len(s.thresholds) == 3

    def test_unsorted_raises(self) -> None:
        with pytest.raises(TemporalScheduleError, match="sorted"):
            TemporalSchedule(thresholds=(
                TemporalThreshold(at_seconds=200),
                TemporalThreshold(at_seconds=100),
            ))

    def test_duplicate_times_raises(self) -> None:
        with pytest.raises(TemporalScheduleError):
            TemporalSchedule(thresholds=(
                TemporalThreshold(at_seconds=100),
                TemporalThreshold(at_seconds=100),
            ))

    def test_policy_label(self) -> None:
        s = TemporalSchedule(thresholds=(), policy="linear_decay")
        assert s.policy == "linear_decay"

    def test_single_threshold_valid(self) -> None:
        s = TemporalSchedule(thresholds=(TemporalThreshold(at_seconds=60),))
        assert len(s.thresholds) == 1


# =============================================================================
# Evaluate Temporal Constraints Tests
# =============================================================================


class TestEvaluateTemporalConstraints:
    """Tests for evaluate_temporal_constraints_raw and evaluate_temporal_constraints."""

    def test_no_schedule_returns_base(self) -> None:
        """Token without temporal_attenuation returns base constraints."""
        base = Constraints(max_spend=1000, quantity_limit=100)
        schedule = TemporalSchedule(thresholds=())
        issued_at = datetime.now(UTC)
        from qasp.protocol.capability import evaluate_temporal_constraints_raw
        result = evaluate_temporal_constraints_raw(base, schedule, issued_at)
        assert result.max_spend == 1000
        assert result.quantity_limit == 100

    def test_before_first_threshold(self) -> None:
        """Before any threshold, base constraints apply."""
        from qasp.protocol.capability import evaluate_temporal_constraints_raw
        base = Constraints(max_spend=1000)
        schedule = TemporalSchedule(thresholds=(
            TemporalThreshold(at_seconds=600, max_spend=500),
        ))
        issued_at = datetime.now(UTC)
        now = issued_at + timedelta(seconds=300)
        result = evaluate_temporal_constraints_raw(base, schedule, issued_at, now)
        assert result.max_spend == 1000

    def test_at_threshold_time(self) -> None:
        """At exact threshold time, threshold applies."""
        from qasp.protocol.capability import evaluate_temporal_constraints_raw
        base = Constraints(max_spend=1000)
        schedule = TemporalSchedule(thresholds=(
            TemporalThreshold(at_seconds=600, max_spend=500),
        ))
        issued_at = datetime.now(UTC) - timedelta(seconds=600)
        now = datetime.now(UTC)
        result = evaluate_temporal_constraints_raw(base, schedule, issued_at, now)
        assert result.max_spend == 500

    def test_between_thresholds(self) -> None:
        """Between thresholds, the earlier threshold applies."""
        from qasp.protocol.capability import evaluate_temporal_constraints_raw
        base = Constraints(max_spend=1000)
        schedule = TemporalSchedule(thresholds=(
            TemporalThreshold(at_seconds=300, max_spend=700),
            TemporalThreshold(at_seconds=600, max_spend=400),
        ))
        issued_at = datetime.now(UTC)
        now = issued_at + timedelta(seconds=450)
        result = evaluate_temporal_constraints_raw(base, schedule, issued_at, now)
        assert result.max_spend == 700

    def test_past_all_thresholds(self) -> None:
        """Past all thresholds, last threshold applies."""
        from qasp.protocol.capability import evaluate_temporal_constraints_raw
        base = Constraints(max_spend=1000)
        schedule = TemporalSchedule(thresholds=(
            TemporalThreshold(at_seconds=300, max_spend=700),
            TemporalThreshold(at_seconds=600, max_spend=400),
        ))
        issued_at = datetime.now(UTC)
        now = issued_at + timedelta(seconds=900)
        result = evaluate_temporal_constraints_raw(base, schedule, issued_at, now)
        assert result.max_spend == 400

    def test_min_of_base_and_threshold(self) -> None:
        """Effective = min(base, threshold)."""
        from qasp.protocol.capability import evaluate_temporal_constraints_raw
        base = Constraints(max_spend=300)
        schedule = TemporalSchedule(thresholds=(
            TemporalThreshold(at_seconds=0, max_spend=500),
        ))
        issued_at = datetime.now(UTC)
        result = evaluate_temporal_constraints_raw(base, schedule, issued_at)
        assert result.max_spend == 300  # base is smaller

    def test_none_threshold_field_preserves_base(self) -> None:
        """None on threshold field means no override."""
        from qasp.protocol.capability import evaluate_temporal_constraints_raw
        base = Constraints(max_spend=1000, quantity_limit=50)
        schedule = TemporalSchedule(thresholds=(
            TemporalThreshold(at_seconds=0, max_spend=500),
        ))
        issued_at = datetime.now(UTC)
        result = evaluate_temporal_constraints_raw(base, schedule, issued_at)
        assert result.max_spend == 500
        assert result.quantity_limit == 50  # no override

    def test_threshold_imposes_limit_when_base_none(self) -> None:
        """Threshold imposes a limit even when base is None."""
        from qasp.protocol.capability import evaluate_temporal_constraints_raw
        base = Constraints()  # max_spend=None
        schedule = TemporalSchedule(thresholds=(
            TemporalThreshold(at_seconds=0, max_spend=500),
        ))
        issued_at = datetime.now(UTC)
        result = evaluate_temporal_constraints_raw(base, schedule, issued_at)
        assert result.max_spend == 500

    def test_non_numeric_fields_preserved(self) -> None:
        """Non-numeric fields (purpose, data_scope, etc.) pass through."""
        from qasp.protocol.capability import evaluate_temporal_constraints_raw
        base = Constraints(
            max_spend=1000,
            purpose="testing",
            data_scope=frozenset({"a", "b"}),
            allowed_toolchain=("Tool1",),
        )
        schedule = TemporalSchedule(thresholds=(
            TemporalThreshold(at_seconds=0, max_spend=500),
        ))
        issued_at = datetime.now(UTC)
        result = evaluate_temporal_constraints_raw(base, schedule, issued_at)
        assert result.purpose == "testing"
        assert result.data_scope == frozenset({"a", "b"})
        assert result.allowed_toolchain == ("Tool1",)

    def test_clock_skew_returns_base(self) -> None:
        """Negative elapsed time (clock skew) returns base."""
        from qasp.protocol.capability import evaluate_temporal_constraints_raw
        base = Constraints(max_spend=1000)
        schedule = TemporalSchedule(thresholds=(
            TemporalThreshold(at_seconds=0, max_spend=500),
        ))
        issued_at = datetime.now(UTC) + timedelta(hours=1)  # Future
        now = datetime.now(UTC)
        result = evaluate_temporal_constraints_raw(base, schedule, issued_at, now)
        assert result.max_spend == 1000

    def test_evaluate_token_wrapper_no_schedule(
        self, issuer_did: DID, issuer_secret_key: bytes, subject_did: DID,
        issuer_public_key: bytes,
    ) -> None:
        """evaluate_temporal_constraints with no schedule returns base."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/test",
            verbs={"read"},
            constraints=Constraints(max_spend=1000),
        )
        result = evaluate_temporal_constraints(token)
        assert result.max_spend == 1000


# =============================================================================
# Token With Temporal Attenuation Tests
# =============================================================================


class TestTokenWithTemporalAttenuation:
    """Tests for creating and verifying tokens with temporal attenuation."""

    def test_create_token_with_schedule(
        self, issuer_did: DID, issuer_secret_key: bytes, subject_did: DID,
        issuer_public_key: bytes,
    ) -> None:
        """Can create a token with temporal_attenuation."""
        schedule = TemporalSchedule(thresholds=(
            TemporalThreshold(at_seconds=1800, max_spend=500),
        ))
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/test",
            verbs={"read"},
            constraints=Constraints(max_spend=1000),
            temporal_attenuation=schedule,
        )
        assert token.temporal_attenuation is not None
        assert len(token.temporal_attenuation.thresholds) == 1
        # Verify signature is valid
        verify_token(token, issuer_public_key, check_expiry=False)

    def test_verify_passes_before_decay(
        self, issuer_did: DID, issuer_secret_key: bytes, subject_did: DID,
        issuer_public_key: bytes,
    ) -> None:
        """Token with temporal schedule passes verification within limits."""
        schedule = TemporalSchedule(thresholds=(
            TemporalThreshold(at_seconds=1800, max_spend=500),
        ))
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/test",
            verbs={"read"},
            constraints=Constraints(max_spend=1000),
            temporal_attenuation=schedule,
        )
        # Just created, so before 1800s threshold; usage within base limits
        usage = TokenUsage(total_spend=800)
        verify_token(token, issuer_public_key, check_expiry=False, usage=usage)

    def test_backward_compat_no_schedule(
        self, issuer_did: DID, issuer_secret_key: bytes, subject_did: DID,
        issuer_public_key: bytes,
    ) -> None:
        """Token without temporal_attenuation still works identically."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/test",
            verbs={"read"},
            constraints=Constraints(max_spend=1000),
        )
        assert token.temporal_attenuation is None
        usage = TokenUsage(total_spend=500)
        verify_token(token, issuer_public_key, check_expiry=False, usage=usage)


# =============================================================================
# CBOR Roundtrip Tests
# =============================================================================


class TestTemporalCBORRoundtrip:
    """Tests for CBOR serialization of tokens with temporal attenuation."""

    def test_roundtrip_with_schedule(
        self, issuer_did: DID, issuer_secret_key: bytes, subject_did: DID,
    ) -> None:
        """Token with schedule survives CBOR roundtrip."""
        schedule = TemporalSchedule(
            thresholds=(
                TemporalThreshold(at_seconds=600, max_spend=800, quantity_limit=80),
                TemporalThreshold(at_seconds=1200, max_spend=400, rate_limit=5),
            ),
            policy="step",
        )
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/test",
            verbs={"read", "write"},
            constraints=Constraints(max_spend=1000, quantity_limit=100, rate_limit=20),
            temporal_attenuation=schedule,
        )

        cbor_data = token.to_cbor_with_signature()
        restored = CapabilityToken.from_cbor(cbor_data)

        assert restored.temporal_attenuation is not None
        assert len(restored.temporal_attenuation.thresholds) == 2
        assert restored.temporal_attenuation.policy == "step"

        t0 = restored.temporal_attenuation.thresholds[0]
        assert t0.at_seconds == 600
        assert t0.max_spend == 800
        assert t0.quantity_limit == 80
        assert t0.rate_limit is None

        t1 = restored.temporal_attenuation.thresholds[1]
        assert t1.at_seconds == 1200
        assert t1.max_spend == 400
        assert t1.rate_limit == 5
        assert t1.quantity_limit is None

    def test_roundtrip_without_schedule(
        self, issuer_did: DID, issuer_secret_key: bytes, subject_did: DID,
    ) -> None:
        """Token without schedule roundtrips with None."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/test",
            verbs={"read"},
        )
        cbor_data = token.to_cbor_with_signature()
        restored = CapabilityToken.from_cbor(cbor_data)
        assert restored.temporal_attenuation is None


# =============================================================================
# Temporal Attenuation (Delegation) Tests
# =============================================================================


class TestTemporalAttenuation:
    """Tests for temporal schedule in attenuate_token."""

    def test_inherit_parent_schedule(
        self, issuer_did: DID, issuer_secret_key: bytes,
        subject_did: DID, subject_secret_key: bytes, delegate_did: DID,
    ) -> None:
        """Child inherits parent schedule when not specified."""
        schedule = TemporalSchedule(thresholds=(
            TemporalThreshold(at_seconds=600, max_spend=500),
        ))
        parent = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/test",
            verbs={"read", "write"},
            constraints=Constraints(max_spend=1000),
            max_delegation_depth=3,
            temporal_attenuation=schedule,
        )
        child = attenuate_token(
            parent_token=parent,
            delegator_secret_key=subject_secret_key,
            new_subject_did=delegate_did,
        )
        assert child.temporal_attenuation is not None
        assert child.temporal_attenuation.thresholds == schedule.thresholds

    def test_tighter_child_schedule_passes(
        self, issuer_did: DID, issuer_secret_key: bytes,
        subject_did: DID, subject_secret_key: bytes, delegate_did: DID,
    ) -> None:
        """Child with tighter temporal schedule passes monotonicity."""
        parent_schedule = TemporalSchedule(thresholds=(
            TemporalThreshold(at_seconds=600, max_spend=500),
        ))
        parent = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/test",
            verbs={"read", "write"},
            constraints=Constraints(max_spend=1000),
            max_delegation_depth=3,
            temporal_attenuation=parent_schedule,
        )
        child_schedule = TemporalSchedule(thresholds=(
            TemporalThreshold(at_seconds=600, max_spend=300),
        ))
        child = attenuate_token(
            parent_token=parent,
            delegator_secret_key=subject_secret_key,
            new_subject_did=delegate_did,
            temporal_attenuation=child_schedule,
        )
        assert child.temporal_attenuation is not None
        assert child.temporal_attenuation.thresholds[0].max_spend == 300

    def test_looser_child_schedule_fails(
        self, issuer_did: DID, issuer_secret_key: bytes,
        subject_did: DID, subject_secret_key: bytes, delegate_did: DID,
    ) -> None:
        """Child with looser temporal schedule fails monotonicity."""
        parent_schedule = TemporalSchedule(thresholds=(
            TemporalThreshold(at_seconds=600, max_spend=500),
        ))
        parent = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/test",
            verbs={"read", "write"},
            constraints=Constraints(max_spend=1000),
            max_delegation_depth=3,
            temporal_attenuation=parent_schedule,
        )
        child_schedule = TemporalSchedule(thresholds=(
            TemporalThreshold(at_seconds=600, max_spend=800),
        ))
        with pytest.raises(AttenuationError, match="monotonicity"):
            attenuate_token(
                parent_token=parent,
                delegator_secret_key=subject_secret_key,
                new_subject_did=delegate_did,
                temporal_attenuation=child_schedule,
            )

    def test_child_adds_schedule_to_no_parent_schedule(
        self, issuer_did: DID, issuer_secret_key: bytes,
        subject_did: DID, subject_secret_key: bytes, delegate_did: DID,
    ) -> None:
        """Child can add a temporal schedule when parent has none."""
        parent = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/test",
            verbs={"read"},
            constraints=Constraints(max_spend=1000),
            max_delegation_depth=3,
        )
        child_schedule = TemporalSchedule(thresholds=(
            TemporalThreshold(at_seconds=600, max_spend=500),
        ))
        child = attenuate_token(
            parent_token=parent,
            delegator_secret_key=subject_secret_key,
            new_subject_did=delegate_did,
            temporal_attenuation=child_schedule,
        )
        assert child.temporal_attenuation is not None


# =============================================================================
# Temporal Delegation Chain Tests
# =============================================================================


class TestTemporalDelegationChain:
    """Tests for temporal monotonicity in verify_delegation_chain."""

    def test_tighter_chain_passes(
        self, issuer_did: DID, issuer_secret_key: bytes, issuer_public_key: bytes,
        subject_did: DID, subject_secret_key: bytes, delegate_did: DID,
    ) -> None:
        """Delegation chain with tighter temporal schedules passes."""
        parent_schedule = TemporalSchedule(thresholds=(
            TemporalThreshold(at_seconds=600, max_spend=500),
        ))
        root = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/test",
            verbs={"read", "write"},
            constraints=Constraints(max_spend=1000),
            max_delegation_depth=3,
            temporal_attenuation=parent_schedule,
        )
        child_schedule = TemporalSchedule(thresholds=(
            TemporalThreshold(at_seconds=600, max_spend=300),
        ))
        child = attenuate_token(
            parent_token=root,
            delegator_secret_key=subject_secret_key,
            new_subject_did=delegate_did,
            temporal_attenuation=child_schedule,
        )
        assert verify_delegation_chain(
            [root, child], issuer_public_key, check_expiry=False,
        )

    def test_looser_chain_fails_verification(
        self, issuer_did: DID, issuer_secret_key: bytes, issuer_public_key: bytes,
        subject_did: DID, subject_secret_key: bytes, delegate_did: DID,
    ) -> None:
        """verify_delegation_chain catches temporal monotonicity violation."""
        parent_schedule = TemporalSchedule(thresholds=(
            TemporalThreshold(at_seconds=600, max_spend=500),
        ))
        root = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="/test",
            verbs={"read", "write"},
            constraints=Constraints(max_spend=1000),
            max_delegation_depth=3,
            temporal_attenuation=parent_schedule,
        )
        # Manually build a child that violates monotonicity
        # We can't use attenuate_token (it would reject), so we test
        # that attenuate_token itself blocks it.
        with pytest.raises(AttenuationError, match="monotonicity"):
            attenuate_token(
                parent_token=root,
                delegator_secret_key=subject_secret_key,
                new_subject_did=delegate_did,
                temporal_attenuation=TemporalSchedule(thresholds=(
                    TemporalThreshold(at_seconds=600, max_spend=800),
                )),
            )


# =============================================================================
# Policy Helper Tests
# =============================================================================


class TestPolicyHelpers:
    """Tests for linear_decay_schedule, exponential_decay_schedule, step_schedule."""

    def test_linear_decay(self) -> None:
        schedule = linear_decay_schedule(
            initial_max_spend=1000, duration_seconds=1000, steps=5,
        )
        assert schedule.policy == "linear_decay"
        assert len(schedule.thresholds) == 5
        # First step at t=200: 1000 * (1 - 1/5) = 800
        assert schedule.thresholds[0].at_seconds == 200
        assert schedule.thresholds[0].max_spend == 800
        # Last step at t=1000: 1000 * (1 - 5/5) = 0
        assert schedule.thresholds[-1].at_seconds == 1000
        assert schedule.thresholds[-1].max_spend == 0

    def test_linear_decay_multiple_fields(self) -> None:
        schedule = linear_decay_schedule(
            initial_max_spend=1000, initial_quantity_limit=100,
            duration_seconds=1000, steps=2,
        )
        assert schedule.thresholds[0].max_spend == 500
        assert schedule.thresholds[0].quantity_limit == 50

    def test_exponential_decay(self) -> None:
        schedule = exponential_decay_schedule(
            initial_max_spend=1000,
            half_life_seconds=1000,
            duration_seconds=2000,
            steps=2,
        )
        assert schedule.policy == "exponential"
        assert len(schedule.thresholds) == 2
        # At t=1000 (one half-life): 1000 * 0.5 = 500
        assert schedule.thresholds[0].at_seconds == 1000
        assert schedule.thresholds[0].max_spend == 500
        # At t=2000 (two half-lives): 1000 * 0.25 = 250
        assert schedule.thresholds[1].at_seconds == 2000
        assert schedule.thresholds[1].max_spend == 250

    def test_step_schedule(self) -> None:
        thresholds = [
            TemporalThreshold(at_seconds=300, max_spend=700),
            TemporalThreshold(at_seconds=600, max_spend=400),
        ]
        schedule = step_schedule(thresholds)
        assert schedule.policy == "step"
        assert len(schedule.thresholds) == 2

    def test_step_schedule_unsorted_raises(self) -> None:
        with pytest.raises(TemporalScheduleError):
            step_schedule([
                TemporalThreshold(at_seconds=600, max_spend=400),
                TemporalThreshold(at_seconds=300, max_spend=700),
            ])

    def test_linear_decay_none_fields(self) -> None:
        """None initial values produce None threshold fields."""
        schedule = linear_decay_schedule(
            initial_max_spend=1000, duration_seconds=100, steps=1,
        )
        assert schedule.thresholds[0].quantity_limit is None
        assert schedule.thresholds[0].rate_limit is None


# =============================================================================
# Temporal Metering Integration Tests
# =============================================================================


class TestTemporalMetering:
    """Tests for temporal attenuation in metering check_constraints."""

    def _make_manager(self) -> ResourceManager:
        from qasp.crypto.signatures import generate_keypair
        pk, sk = generate_keypair()
        return ResourceManager(signing_key=sk, public_key=pk, is_server=True)

    def test_check_constraints_with_temporal_decay(self) -> None:
        """check_constraints respects temporally decayed limits."""
        mgr = self._make_manager()
        # Create a resource with temporal attenuation
        schedule = TemporalSchedule(thresholds=(
            TemporalThreshold(at_seconds=0, max_spend=500),
        ))
        issued_at = datetime.now(UTC)

        resource = ManagedResource(
            request_id=b"\x01" * 16,
            resource_type="compute",
            resource_id=b"\x02" * 16,
            token_id=b"\x03" * 16,
            meter_id=b"\x04" * 16,
            granted_permissions=0xFF,
            expiration=0,
            constraints=Constraints(max_spend=1000),
            temporal_attenuation=schedule,
            token_issued_at=issued_at,
            cumulative_cost=700,  # Exceeds decayed 500 but not base 1000
        )
        mgr._resources[resource.meter_id] = resource

        result = mgr.check_constraints(resource.meter_id)
        assert result is not None
        assert result.reason == int(SuspendReason.BUDGET_EXHAUSTED)

    def test_check_constraints_without_temporal(self) -> None:
        """check_constraints without temporal schedule uses base constraints."""
        mgr = self._make_manager()
        resource = ManagedResource(
            request_id=b"\x01" * 16,
            resource_type="compute",
            resource_id=b"\x02" * 16,
            token_id=b"\x03" * 16,
            meter_id=b"\x04" * 16,
            granted_permissions=0xFF,
            expiration=0,
            constraints=Constraints(max_spend=1000),
            cumulative_cost=700,
        )
        mgr._resources[resource.meter_id] = resource

        result = mgr.check_constraints(resource.meter_id)
        assert result is None  # 700 < 1000, no violation

    def test_check_constraints_temporal_quantity_limit(self) -> None:
        """Temporal decay on quantity_limit triggers suspension."""
        mgr = self._make_manager()
        schedule = TemporalSchedule(thresholds=(
            TemporalThreshold(at_seconds=0, quantity_limit=10),
        ))
        resource = ManagedResource(
            request_id=b"\x01" * 16,
            resource_type="compute",
            resource_id=b"\x02" * 16,
            token_id=b"\x03" * 16,
            meter_id=b"\x04" * 16,
            granted_permissions=0xFF,
            expiration=0,
            constraints=Constraints(quantity_limit=100),
            temporal_attenuation=schedule,
            token_issued_at=datetime.now(UTC),
            cumulative_units=50,
        )
        mgr._resources[resource.meter_id] = resource

        result = mgr.check_constraints(resource.meter_id)
        assert result is not None
        assert result.reason == int(SuspendReason.QUANTITY_EXCEEDED)
