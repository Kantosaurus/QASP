"""Property-based tests for capability token attenuation monotonicity.

These tests use Hypothesis to verify that attenuation always produces
tokens with rights that are a subset of the parent token's rights.

Properties verified:
- att(T, Delta) -> T' implies V_T' <= V_T (verb subset)
- att(T, Delta) -> T' implies constraints_T'.is_tighter_than(constraints_T)
- Delegation depth decrements by exactly 1
- Delegation at depth 0 raises DelegationDepthExceeded
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from qasp.crypto import signatures
from qasp.identity import create_did
from qasp.protocol.capability import (
    AttenuationError,
    Constraints,
    DelegationDepthExceeded,
    VerbSet,
    attenuate_token,
    create_sub_invocation_token,
    create_token,
)

# =============================================================================
# Hypothesis Strategies
# =============================================================================


# Common verbs used in capability systems
COMMON_VERBS = [
    "read",
    "write",
    "execute",
    "delete",
    "create",
    "update",
    "list",
    "admin",
    "invoke",
    "subscribe",
]


@st.composite
def verb_set_strategy(draw: st.DrawFn) -> VerbSet:
    """Generate an arbitrary VerbSet with 1-5 verbs."""
    verbs = draw(
        st.lists(
            st.sampled_from(COMMON_VERBS),
            min_size=1,
            max_size=5,
            unique=True,
        )
    )
    return VerbSet(set(verbs))


@st.composite
def subset_verb_set_strategy(draw: st.DrawFn, parent: VerbSet) -> VerbSet:
    """Generate a VerbSet that is a subset of the parent."""
    assume(len(parent) > 0)
    # Select a subset of the parent's verbs
    parent_list = list(parent.verbs)
    selected = draw(
        st.lists(
            st.sampled_from(parent_list),
            min_size=1,
            max_size=len(parent_list),
            unique=True,
        )
    )
    return VerbSet(set(selected))


@st.composite
def constraints_strategy(draw: st.DrawFn) -> Constraints:
    """Generate arbitrary Constraints."""
    now = datetime.now(UTC)

    not_before = draw(st.none() | st.just(now - timedelta(hours=1)))
    not_after = draw(st.none() | st.just(now + timedelta(hours=draw(st.integers(1, 24)))))
    quantity_limit = draw(st.none() | st.integers(1, 10000))
    rate_limit = draw(st.none() | st.integers(1, 1000))
    max_spend = draw(st.none() | st.integers(1, 100000))
    data_scope_list = draw(
        st.lists(
            st.sampled_from(["public", "internal", "private", "secret", "confidential"]),
            min_size=0,
            max_size=3,
            unique=True,
        )
    )

    return Constraints(
        not_before=not_before,
        not_after=not_after,
        quantity_limit=quantity_limit,
        quantity_unit="units" if quantity_limit else "",
        rate_limit=rate_limit,
        rate_period_seconds=3600,
        max_spend=max_spend,
        spend_currency="USD" if max_spend else "",
        data_scope=frozenset(data_scope_list) if data_scope_list else frozenset(),
    )


@st.composite
def tighter_constraints_strategy(draw: st.DrawFn, parent: Constraints) -> Constraints:
    """Generate Constraints that are tighter than the parent."""
    now = datetime.now(UTC)

    # not_before: same or later
    not_before = parent.not_before
    if parent.not_before is not None and draw(st.booleans()):
        not_before = parent.not_before + timedelta(minutes=draw(st.integers(0, 60)))

    # not_after: same or earlier
    not_after = parent.not_after
    if parent.not_after is not None and draw(st.booleans()):
        delta = timedelta(minutes=draw(st.integers(0, 60)))
        candidate = parent.not_after - delta
        # Make sure not_after is still in the future
        if candidate > now:
            not_after = candidate

    # quantity_limit: same or less
    quantity_limit = parent.quantity_limit
    if parent.quantity_limit is not None and draw(st.booleans()):
        quantity_limit = draw(st.integers(1, parent.quantity_limit))

    # rate_limit: same or less
    rate_limit = parent.rate_limit
    if parent.rate_limit is not None and draw(st.booleans()):
        rate_limit = draw(st.integers(1, parent.rate_limit))

    # max_spend: same or less
    max_spend = parent.max_spend
    if parent.max_spend is not None and draw(st.booleans()):
        max_spend = draw(st.integers(1, parent.max_spend))

    # data_scope: subset
    data_scope = parent.data_scope
    if parent.data_scope and draw(st.booleans()):
        selected = draw(
            st.lists(
                st.sampled_from(list(parent.data_scope)),
                min_size=0,
                max_size=len(parent.data_scope),
                unique=True,
            )
        )
        data_scope = frozenset(selected)

    return Constraints(
        not_before=not_before,
        not_after=not_after,
        quantity_limit=quantity_limit,
        quantity_unit=parent.quantity_unit,
        rate_limit=rate_limit,
        rate_period_seconds=parent.rate_period_seconds,
        max_spend=max_spend,
        spend_currency=parent.spend_currency,
        data_scope=data_scope,
        purpose=parent.purpose,
    )


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def issuer_keypair() -> tuple[bytes, bytes]:
    """Generate issuer keypair."""
    return signatures.generate_keypair()


@pytest.fixture
def subject_keypair() -> tuple[bytes, bytes]:
    """Generate subject keypair."""
    return signatures.generate_keypair()


@pytest.fixture
def delegate_keypair() -> tuple[bytes, bytes]:
    """Generate delegate keypair."""
    return signatures.generate_keypair()


# =============================================================================
# Property Tests for Verb Set Attenuation
# =============================================================================


@pytest.mark.property
class TestVerbSetAttenuationProperties:
    """Property tests for verb set attenuation."""

    @given(verbs=verb_set_strategy())
    @settings(max_examples=50)
    def test_attenuated_verbs_are_subset(self, verbs: VerbSet) -> None:
        """Attenuated token verbs are always a subset of parent verbs."""
        # Create keypairs
        issuer_public, issuer_secret = signatures.generate_keypair()
        subject_public, subject_secret = signatures.generate_keypair()
        delegate_public, _ = signatures.generate_keypair()

        issuer_did, _ = create_did(issuer_public)
        subject_did, _ = create_did(subject_public)
        delegate_did, _ = create_did(delegate_public)

        # Create parent token
        parent = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret,
            subject_did=subject_did,
            resource_uri="/resources/test",
            verbs=verbs,
            max_delegation_depth=2,
        )

        # Attenuate without changing verbs
        child = attenuate_token(
            parent_token=parent,
            delegator_secret_key=subject_secret,
            new_subject_did=delegate_did,
        )

        # Child verbs must be subset of parent verbs
        assert child.verbs.issubset(parent.verbs)

    @given(data=st.data())
    @settings(max_examples=50)
    def test_attenuated_verbs_cannot_expand(self, data: st.DataObject) -> None:
        """Attempting to expand verbs during attenuation raises AttenuationError."""
        # Create keypairs
        issuer_public, issuer_secret = signatures.generate_keypair()
        subject_public, subject_secret = signatures.generate_keypair()
        delegate_public, _ = signatures.generate_keypair()

        issuer_did, _ = create_did(issuer_public)
        subject_did, _ = create_did(subject_public)
        delegate_did, _ = create_did(delegate_public)

        # Generate parent verbs
        parent_verbs = data.draw(verb_set_strategy())

        # Generate verbs that include at least one verb not in parent
        all_verbs = set(COMMON_VERBS)
        extra_verbs = all_verbs - parent_verbs.verbs
        assume(len(extra_verbs) > 0)

        # Pick an extra verb to add
        extra_verb = data.draw(st.sampled_from(list(extra_verbs)))
        expanded_verbs = VerbSet(parent_verbs.verbs | {extra_verb})

        # Create parent token
        parent = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret,
            subject_did=subject_did,
            resource_uri="/resources/test",
            verbs=parent_verbs,
            max_delegation_depth=2,
        )

        # Attempting to expand verbs should raise
        with pytest.raises(AttenuationError):
            attenuate_token(
                parent_token=parent,
                delegator_secret_key=subject_secret,
                new_subject_did=delegate_did,
                reduced_verbs=expanded_verbs,
            )


# =============================================================================
# Property Tests for Constraint Tightening
# =============================================================================


@pytest.mark.property
class TestConstraintTighteningProperties:
    """Property tests for constraint tightening."""

    @given(parent_constraints=constraints_strategy())
    @settings(max_examples=50)
    def test_tightened_constraints_are_valid(
        self,
        parent_constraints: Constraints,
    ) -> None:
        """Tightened constraints pass is_tighter_than check with parent."""
        # Create keypairs
        issuer_public, issuer_secret = signatures.generate_keypair()
        subject_public, subject_secret = signatures.generate_keypair()
        delegate_public, _ = signatures.generate_keypair()

        issuer_did, _ = create_did(issuer_public)
        subject_did, _ = create_did(subject_public)
        delegate_did, _ = create_did(delegate_public)

        # Create parent token with constraints
        parent = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret,
            subject_did=subject_did,
            resource_uri="/resources/test",
            verbs={"read"},
            constraints=parent_constraints,
            max_delegation_depth=2,
        )

        # Attenuate without changing constraints
        child = attenuate_token(
            parent_token=parent,
            delegator_secret_key=subject_secret,
            new_subject_did=delegate_did,
        )

        # Child constraints must be tighter than or equal to parent
        assert child.constraints.is_tighter_than(parent.constraints)

    @given(constraints=constraints_strategy())
    @settings(max_examples=50)
    def test_tighten_produces_valid_constraints(
        self,
        constraints: Constraints,
    ) -> None:
        """Constraints.tighten() always produces valid tighter constraints."""
        # Tighten with specific values
        new_limit = 50
        if constraints.quantity_limit is not None:
            new_limit = min(50, constraints.quantity_limit)
        delta = Constraints(quantity_limit=new_limit)

        result = constraints.tighten(delta)

        # Result should be tighter than or equal to original
        # (when delta specifies values)
        if delta.quantity_limit is not None:
            assert result.quantity_limit is not None
            if constraints.quantity_limit is not None:
                assert result.quantity_limit <= constraints.quantity_limit

    @given(data=st.data())
    @settings(max_examples=50)
    def test_tighten_is_monotonic_for_quantity(
        self,
        data: st.DataObject,
    ) -> None:
        """Tightening quantity_limit never increases it."""
        original_limit = data.draw(st.integers(10, 1000))
        tighter_limit = data.draw(st.integers(1, original_limit))

        original = Constraints(quantity_limit=original_limit)
        delta = Constraints(quantity_limit=tighter_limit)

        result = original.tighten(delta)

        assert result.quantity_limit is not None
        assert result.quantity_limit <= original_limit

    @given(data=st.data())
    @settings(max_examples=50)
    def test_tighten_is_monotonic_for_not_after(
        self,
        data: st.DataObject,
    ) -> None:
        """Tightening not_after never extends it."""
        now = datetime.now(UTC)
        hours_original = data.draw(st.integers(2, 48))
        hours_delta = data.draw(st.integers(1, hours_original))

        original_not_after = now + timedelta(hours=hours_original)
        delta_not_after = now + timedelta(hours=hours_delta)

        original = Constraints(not_after=original_not_after)
        delta = Constraints(not_after=delta_not_after)

        result = original.tighten(delta)

        assert result.not_after is not None
        assert result.not_after <= original_not_after

    @given(data=st.data())
    @settings(max_examples=50)
    def test_tighten_is_monotonic_for_data_scope(
        self,
        data: st.DataObject,
    ) -> None:
        """Tightening data_scope produces intersection/subset."""
        all_scopes = ["public", "internal", "private", "secret"]

        original_scopes = data.draw(
            st.lists(st.sampled_from(all_scopes), min_size=1, max_size=4, unique=True)
        )
        delta_scopes = data.draw(
            st.lists(st.sampled_from(all_scopes), min_size=1, max_size=4, unique=True)
        )

        original = Constraints(data_scope=frozenset(original_scopes))
        delta = Constraints(data_scope=frozenset(delta_scopes))

        result = original.tighten(delta)

        # Result should be intersection
        expected = frozenset(original_scopes) & frozenset(delta_scopes)
        assert result.data_scope == expected


# =============================================================================
# Property Tests for Delegation Depth
# =============================================================================


@pytest.mark.property
class TestDelegationDepthProperties:
    """Property tests for delegation depth behavior."""

    @given(initial_depth=st.integers(1, 10))
    @settings(max_examples=30)
    def test_attenuation_decreases_delegation_depth(
        self,
        initial_depth: int,
    ) -> None:
        """Attenuation decreases max_delegation_depth by exactly 1."""
        # Create keypairs
        issuer_public, issuer_secret = signatures.generate_keypair()
        subject_public, subject_secret = signatures.generate_keypair()
        delegate_public, _ = signatures.generate_keypair()

        issuer_did, _ = create_did(issuer_public)
        subject_did, _ = create_did(subject_public)
        delegate_did, _ = create_did(delegate_public)

        # Create parent token
        parent = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret,
            subject_did=subject_did,
            resource_uri="/resources/test",
            verbs={"read"},
            max_delegation_depth=initial_depth,
        )

        # Attenuate
        child = attenuate_token(
            parent_token=parent,
            delegator_secret_key=subject_secret,
            new_subject_did=delegate_did,
        )

        # Depth should decrease by exactly 1
        assert child.max_delegation_depth == initial_depth - 1
        # Chain length should increase by exactly 1
        assert child.delegation_chain_length == parent.delegation_chain_length + 1

    def test_delegation_at_depth_zero_fails(self) -> None:
        """Attempting delegation when max_delegation_depth=0 raises DelegationDepthExceeded."""
        # Create keypairs
        issuer_public, issuer_secret = signatures.generate_keypair()
        subject_public, subject_secret = signatures.generate_keypair()
        delegate_public, _ = signatures.generate_keypair()

        issuer_did, _ = create_did(issuer_public)
        subject_did, _ = create_did(subject_public)
        delegate_did, _ = create_did(delegate_public)

        # Create parent token with depth 0
        parent = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret,
            subject_did=subject_did,
            resource_uri="/resources/test",
            verbs={"read"},
            max_delegation_depth=0,  # No delegation allowed
        )

        # Attempting to attenuate should raise
        with pytest.raises(DelegationDepthExceeded):
            attenuate_token(
                parent_token=parent,
                delegator_secret_key=subject_secret,
                new_subject_did=delegate_did,
            )

    @given(depth=st.integers(1, 5))
    @settings(max_examples=20)
    def test_chain_of_attenuations_exhausts_depth(
        self,
        depth: int,
    ) -> None:
        """A chain of attenuations eventually exhausts delegation depth."""
        # Generate keypairs for chain
        keypairs = [signatures.generate_keypair() for _ in range(depth + 2)]
        dids = [create_did(kp[0])[0] for kp in keypairs]

        # Create root token
        token = create_token(
            issuer_did=dids[0],
            issuer_secret_key=keypairs[0][1],
            subject_did=dids[1],
            resource_uri="/resources/test",
            verbs={"read"},
            max_delegation_depth=depth,
        )

        # Attenuate through the chain
        for i in range(depth):
            token = attenuate_token(
                parent_token=token,
                delegator_secret_key=keypairs[i + 1][1],
                new_subject_did=dids[i + 2],
            )

        # Now at depth 0
        assert token.max_delegation_depth == 0

        # One more attenuation should fail
        extra_public, _ = signatures.generate_keypair()
        extra_did, _ = create_did(extra_public)

        with pytest.raises(DelegationDepthExceeded):
            attenuate_token(
                parent_token=token,
                delegator_secret_key=keypairs[depth + 1][1],
                new_subject_did=extra_did,
            )


# =============================================================================
# Toolchain Strategies and Property Tests
# =============================================================================


COMMON_TOOLS = [
    "data-fetch",
    "compute",
    "model-inference",
    "storage",
    "notification",
]


@st.composite
def toolchain_strategy(draw: st.DrawFn) -> tuple[str, ...]:
    """Generate an arbitrary toolchain with 1-5 tool classes."""
    tools = draw(
        st.lists(
            st.sampled_from(COMMON_TOOLS),
            min_size=1,
            max_size=5,
        )
    )
    return tuple(tools)


@pytest.mark.property
class TestToolchainAttenuationProperties:
    """Property tests for toolchain attenuation behavior."""

    @given(data=st.data())
    @settings(max_examples=30)
    def test_position_monotonically_advances(
        self,
        data: st.DataObject,
    ) -> None:
        """Sub-invocation position always advances monotonically."""
        toolchain = data.draw(toolchain_strategy())
        num_steps = min(len(toolchain), data.draw(st.integers(1, len(toolchain))))

        # Generate enough keypairs for the chain
        keypairs = [signatures.generate_keypair() for _ in range(num_steps + 2)]
        dids = [create_did(kp[0])[0] for kp in keypairs]

        token = create_token(
            issuer_did=dids[0],
            issuer_secret_key=keypairs[0][1],
            subject_did=dids[1],
            resource_uri="/resources/test",
            verbs={"execute"},
            constraints=Constraints(allowed_toolchain=toolchain),
            max_delegation_depth=num_steps + 1,
        )

        prev_position = token.toolchain_position
        for i in range(num_steps):
            token = create_sub_invocation_token(
                parent_token=token,
                holder_secret_key=keypairs[i + 1][1],
                target_tool_class=toolchain[i],
                new_subject_did=dids[i + 2],
            )
            assert token.toolchain_position == prev_position + 1
            prev_position = token.toolchain_position

    @given(data=st.data())
    @settings(max_examples=30)
    def test_contiguous_sublist_reflexivity(
        self,
        data: st.DataObject,
    ) -> None:
        """A toolchain is always a contiguous sublist of itself."""
        toolchain = data.draw(toolchain_strategy())
        c = Constraints(allowed_toolchain=toolchain)
        assert c.is_tighter_than(c)
