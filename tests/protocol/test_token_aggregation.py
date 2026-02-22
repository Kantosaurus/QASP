"""Tests for token aggregation algebra."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from qasp.identity import DID, DIDRegistry
from qasp.protocol.capability import (
    CapabilityToken,
    Constraints,
    InvalidTokenError,
    LocalDIDResolver,
    TokenConstraintViolation,
    TokenExpiredError,
    TokenRevokedError,
    VerbSet,
    create_token,
)
from qasp.protocol.revocation import CertificateRevocationList
from qasp.protocol.token_aggregation import (
    AggregatedPermission,
    ConstraintConflictError,
    TokenAggregationError,
    aggregate_tokens,
    check_action_permitted,
)

# =============================================================================
# TestAggregateTokensBasic
# =============================================================================


class TestAggregateTokensBasic:
    """Basic aggregation behaviour: empty, single, multi-token."""

    def test_empty_list_raises(self) -> None:
        with pytest.raises(TokenAggregationError, match="empty"):
            aggregate_tokens([])

    def test_single_token_identity(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
    ) -> None:
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://gpu/v100",
            verbs={"read", "execute"},
        )
        result = aggregate_tokens(
            [token],
            issuer_public_keys={str(issuer_did): issuer_public_key},
        )
        assert set(result.verbs) == {"read", "execute"}
        assert result.resource_uris == frozenset({"qasp://gpu/v100"})
        assert result.source_token_ids == (token.token_id,)

    def test_two_tokens_verb_union(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        third_party_did: DID,
        third_party_secret_key: bytes,
        third_party_public_key: bytes,
    ) -> None:
        t1 = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://gpu/v100",
            verbs={"read"},
        )
        t2 = create_token(
            issuer_did=third_party_did,
            issuer_secret_key=third_party_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://gpu/v100",
            verbs={"write"},
        )
        result = aggregate_tokens(
            [t1, t2],
            issuer_public_keys={
                str(issuer_did): issuer_public_key,
                str(third_party_did): third_party_public_key,
            },
        )
        assert set(result.verbs) == {"read", "write"}

    def test_two_tokens_resource_union(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        third_party_did: DID,
        third_party_secret_key: bytes,
        third_party_public_key: bytes,
    ) -> None:
        t1 = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://gpu/v100",
            verbs={"read"},
        )
        t2 = create_token(
            issuer_did=third_party_did,
            issuer_secret_key=third_party_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://dataset/imagenet",
            verbs={"read"},
        )
        result = aggregate_tokens(
            [t1, t2],
            issuer_public_keys={
                str(issuer_did): issuer_public_key,
                str(third_party_did): third_party_public_key,
            },
        )
        assert result.resource_uris == frozenset(
            {"qasp://gpu/v100", "qasp://dataset/imagenet"}
        )

    def test_two_tokens_constraint_intersection(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        third_party_did: DID,
        third_party_secret_key: bytes,
        third_party_public_key: bytes,
    ) -> None:
        now = datetime.now(UTC)
        c1 = Constraints(
            not_after=now + timedelta(hours=2),
            quantity_limit=100,
        )
        c2 = Constraints(
            not_after=now + timedelta(hours=1),
            quantity_limit=50,
        )
        t1 = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://gpu/v100",
            verbs={"read"},
            constraints=c1,
        )
        t2 = create_token(
            issuer_did=third_party_did,
            issuer_secret_key=third_party_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://gpu/v100",
            verbs={"write"},
            constraints=c2,
        )
        result = aggregate_tokens(
            [t1, t2],
            issuer_public_keys={
                str(issuer_did): issuer_public_key,
                str(third_party_did): third_party_public_key,
            },
        )
        # Tighter quantity wins
        assert result.constraints.quantity_limit == 50

    def test_three_tokens(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        third_party_did: DID,
        third_party_secret_key: bytes,
        third_party_public_key: bytes,
        delegate_did: DID,
        delegate_secret_key: bytes,
        delegate_public_key: bytes,
    ) -> None:
        t1 = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://a",
            verbs={"read"},
        )
        t2 = create_token(
            issuer_did=third_party_did,
            issuer_secret_key=third_party_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://b",
            verbs={"write"},
        )
        t3 = create_token(
            issuer_did=delegate_did,
            issuer_secret_key=delegate_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://c",
            verbs={"execute"},
        )
        result = aggregate_tokens(
            [t1, t2, t3],
            issuer_public_keys={
                str(issuer_did): issuer_public_key,
                str(third_party_did): third_party_public_key,
                str(delegate_did): delegate_public_key,
            },
        )
        assert set(result.verbs) == {"read", "write", "execute"}
        assert result.resource_uris == frozenset(
            {"qasp://a", "qasp://b", "qasp://c"}
        )
        assert len(result.source_token_ids) == 3


# =============================================================================
# TestAggregateTokensVerification
# =============================================================================


class TestAggregateTokensVerification:
    """All tokens must pass independent verification."""

    def test_all_tokens_must_verify(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        third_party_did: DID,
        third_party_secret_key: bytes,
    ) -> None:
        t1 = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://a",
            verbs={"read"},
        )
        t2 = create_token(
            issuer_did=third_party_did,
            issuer_secret_key=third_party_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://b",
            verbs={"write"},
        )
        # Provide wrong key for t2's issuer -> signature failure
        with pytest.raises(InvalidTokenError):
            aggregate_tokens(
                [t1, t2],
                issuer_public_keys={
                    str(issuer_did): issuer_public_key,
                    str(third_party_did): issuer_public_key,  # wrong key!
                },
            )

    def test_one_expired_rejects_all(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        third_party_did: DID,
        third_party_secret_key: bytes,
        third_party_public_key: bytes,
    ) -> None:
        t1 = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://a",
            verbs={"read"},
        )
        # Expired token
        past = datetime.now(UTC) - timedelta(hours=2)
        t2 = create_token(
            issuer_did=third_party_did,
            issuer_secret_key=third_party_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://b",
            verbs={"write"},
            constraints=Constraints(
                not_after=past,
            ),
            validity_seconds=0,  # force the not_after we set
        )
        with pytest.raises(TokenExpiredError):
            aggregate_tokens(
                [t1, t2],
                issuer_public_keys={
                    str(issuer_did): issuer_public_key,
                    str(third_party_did): third_party_public_key,
                },
            )

    def test_one_invalid_sig_rejects_all(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        third_party_did: DID,
        third_party_secret_key: bytes,
        third_party_public_key: bytes,
    ) -> None:
        t1 = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://a",
            verbs={"read"},
        )
        t2 = create_token(
            issuer_did=third_party_did,
            issuer_secret_key=third_party_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://b",
            verbs={"write"},
        )
        # Corrupt t2 signature
        t2_bad = CapabilityToken(
            token_id=t2.token_id,
            issuer_did=t2.issuer_did,
            subject_did=t2.subject_did,
            audience_did=t2.audience_did,
            resource_uri=t2.resource_uri,
            verbs=t2.verbs,
            constraints=t2.constraints,
            issued_at=t2.issued_at,
            nonce=t2.nonce,
            signature=b"\x00" * len(t2.signature),
        )
        with pytest.raises(InvalidTokenError):
            aggregate_tokens(
                [t1, t2_bad],
                issuer_public_keys={
                    str(issuer_did): issuer_public_key,
                    str(third_party_did): third_party_public_key,
                },
            )

    def test_one_revoked_rejects_all(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        third_party_did: DID,
        third_party_secret_key: bytes,
        third_party_public_key: bytes,
        crl: CertificateRevocationList,
    ) -> None:
        t1 = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://a",
            verbs={"read"},
        )
        t2 = create_token(
            issuer_did=third_party_did,
            issuer_secret_key=third_party_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://b",
            verbs={"write"},
        )
        crl.register_token(t1)
        crl.register_token(t2)
        # Revoke t2
        from qasp.protocol.revocation import (
            RevocationReason,
            RevocationUrgency,
            revoke_token,
        )

        revoke_token(
            crl=crl,
            token_id=t2.token_id,
            reason=RevocationReason.KEY_COMPROMISE,
            urgency=RevocationUrgency.CRITICAL,
            revoker_did=str(third_party_did),
            revoker_secret_key=third_party_secret_key,
        )
        with pytest.raises(TokenRevokedError):
            aggregate_tokens(
                [t1, t2],
                issuer_public_keys={
                    str(issuer_did): issuer_public_key,
                    str(third_party_did): third_party_public_key,
                },
                crl=crl,
            )


# =============================================================================
# TestAggregateTokensSubjectValidation
# =============================================================================


class TestAggregateTokensSubjectValidation:
    """Subject and audience consistency checks."""

    def test_mismatched_subject_raises(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        delegate_did: DID,
    ) -> None:
        t1 = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://a",
            verbs={"read"},
        )
        t2 = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=delegate_did,  # different subject!
            resource_uri="qasp://b",
            verbs={"write"},
        )
        with pytest.raises(TokenAggregationError, match="subject_did"):
            aggregate_tokens(
                [t1, t2],
                issuer_public_keys={str(issuer_did): issuer_public_key},
            )

    def test_audience_consistency(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        audience_did: DID,
        delegate_did: DID,
        third_party_did: DID,
        third_party_secret_key: bytes,
        third_party_public_key: bytes,
    ) -> None:
        """Two tokens with different non-None audience_did should fail."""
        t1 = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://a",
            verbs={"read"},
            audience_did=audience_did,
        )
        t2 = create_token(
            issuer_did=third_party_did,
            issuer_secret_key=third_party_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://b",
            verbs={"write"},
            audience_did=delegate_did,  # different audience
        )
        with pytest.raises(TokenAggregationError, match="audience_did"):
            aggregate_tokens(
                [t1, t2],
                issuer_public_keys={
                    str(issuer_did): issuer_public_key,
                    str(third_party_did): third_party_public_key,
                },
            )

    def test_mixed_audience_some_none(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        audience_did: DID,
        third_party_did: DID,
        third_party_secret_key: bytes,
        third_party_public_key: bytes,
    ) -> None:
        """One token with audience, one without -> OK."""
        t1 = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://a",
            verbs={"read"},
            audience_did=audience_did,
        )
        t2 = create_token(
            issuer_did=third_party_did,
            issuer_secret_key=third_party_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://b",
            verbs={"write"},
            audience_did=None,
        )
        result = aggregate_tokens(
            [t1, t2],
            issuer_public_keys={
                str(issuer_did): issuer_public_key,
                str(third_party_did): third_party_public_key,
            },
        )
        assert set(result.verbs) == {"read", "write"}


# =============================================================================
# TestConstraintConflicts
# =============================================================================


class TestConstraintConflicts:
    """Constraint conflict detection."""

    def test_empty_time_window(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        third_party_did: DID,
        third_party_secret_key: bytes,
        third_party_public_key: bytes,
    ) -> None:
        now = datetime.now(UTC)
        # t1 valid only before now+1h, t2 valid only after now+2h
        c1 = Constraints(
            not_after=now + timedelta(hours=1),
        )
        c2 = Constraints(
            not_before=now + timedelta(hours=2),
            not_after=now + timedelta(hours=3),
        )
        t1 = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://a",
            verbs={"read"},
            constraints=c1,
        )
        t2 = create_token(
            issuer_did=third_party_did,
            issuer_secret_key=third_party_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://b",
            verbs={"write"},
            constraints=c2,
        )
        with pytest.raises(ConstraintConflictError, match="time window"):
            aggregate_tokens(
                [t1, t2],
                issuer_public_keys={
                    str(issuer_did): issuer_public_key,
                    str(third_party_did): third_party_public_key,
                },
                check_expiry=False,  # skip expiry so we reach constraint check
            )

    def test_conflicting_purposes(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        third_party_did: DID,
        third_party_secret_key: bytes,
        third_party_public_key: bytes,
    ) -> None:
        c1 = Constraints(purpose="training")
        c2 = Constraints(purpose="inference")
        t1 = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://a",
            verbs={"read"},
            constraints=c1,
        )
        t2 = create_token(
            issuer_did=third_party_did,
            issuer_secret_key=third_party_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://b",
            verbs={"write"},
            constraints=c2,
        )
        with pytest.raises(ConstraintConflictError, match="purpose"):
            aggregate_tokens(
                [t1, t2],
                issuer_public_keys={
                    str(issuer_did): issuer_public_key,
                    str(third_party_did): third_party_public_key,
                },
            )

    def test_same_purpose_ok(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        third_party_did: DID,
        third_party_secret_key: bytes,
        third_party_public_key: bytes,
    ) -> None:
        c1 = Constraints(purpose="training")
        c2 = Constraints(purpose="training")
        t1 = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://a",
            verbs={"read"},
            constraints=c1,
        )
        t2 = create_token(
            issuer_did=third_party_did,
            issuer_secret_key=third_party_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://b",
            verbs={"write"},
            constraints=c2,
        )
        result = aggregate_tokens(
            [t1, t2],
            issuer_public_keys={
                str(issuer_did): issuer_public_key,
                str(third_party_did): third_party_public_key,
            },
        )
        assert result.constraints.purpose == "training"

    def test_one_purpose_inherited(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        third_party_did: DID,
        third_party_secret_key: bytes,
        third_party_public_key: bytes,
    ) -> None:
        c1 = Constraints(purpose="training")
        c2 = Constraints()  # no purpose
        t1 = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://a",
            verbs={"read"},
            constraints=c1,
        )
        t2 = create_token(
            issuer_did=third_party_did,
            issuer_secret_key=third_party_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://b",
            verbs={"write"},
            constraints=c2,
        )
        result = aggregate_tokens(
            [t1, t2],
            issuer_public_keys={
                str(issuer_did): issuer_public_key,
                str(third_party_did): third_party_public_key,
            },
        )
        assert result.constraints.purpose == "training"

    def test_conflicting_quantity_units(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        third_party_did: DID,
        third_party_secret_key: bytes,
        third_party_public_key: bytes,
    ) -> None:
        c1 = Constraints(quantity_unit="vCPU-h", quantity_limit=10)
        c2 = Constraints(quantity_unit="GB", quantity_limit=5)
        t1 = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://a",
            verbs={"read"},
            constraints=c1,
        )
        t2 = create_token(
            issuer_did=third_party_did,
            issuer_secret_key=third_party_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://b",
            verbs={"write"},
            constraints=c2,
        )
        with pytest.raises(ConstraintConflictError, match="quantity unit"):
            aggregate_tokens(
                [t1, t2],
                issuer_public_keys={
                    str(issuer_did): issuer_public_key,
                    str(third_party_did): third_party_public_key,
                },
            )

    def test_conflicting_spend_currencies(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        third_party_did: DID,
        third_party_secret_key: bytes,
        third_party_public_key: bytes,
    ) -> None:
        c1 = Constraints(spend_currency="USD", max_spend=100)
        c2 = Constraints(spend_currency="EUR", max_spend=50)
        t1 = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://a",
            verbs={"read"},
            constraints=c1,
        )
        t2 = create_token(
            issuer_did=third_party_did,
            issuer_secret_key=third_party_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://b",
            verbs={"write"},
            constraints=c2,
        )
        with pytest.raises(ConstraintConflictError, match="spend currenc"):
            aggregate_tokens(
                [t1, t2],
                issuer_public_keys={
                    str(issuer_did): issuer_public_key,
                    str(third_party_did): third_party_public_key,
                },
            )


# =============================================================================
# TestConstraintIntersectionDetails
# =============================================================================


class TestConstraintIntersectionDetails:
    """Detailed constraint intersection behaviour."""

    def test_latest_not_before(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        third_party_did: DID,
        third_party_secret_key: bytes,
        third_party_public_key: bytes,
    ) -> None:
        now = datetime.now(UTC)
        nb1 = now - timedelta(minutes=30)
        nb2 = now - timedelta(minutes=10)
        c1 = Constraints(not_before=nb1)
        c2 = Constraints(not_before=nb2)
        t1 = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://a",
            verbs={"read"},
            constraints=c1,
        )
        t2 = create_token(
            issuer_did=third_party_did,
            issuer_secret_key=third_party_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://b",
            verbs={"write"},
            constraints=c2,
        )
        result = aggregate_tokens(
            [t1, t2],
            issuer_public_keys={
                str(issuer_did): issuer_public_key,
                str(third_party_did): third_party_public_key,
            },
        )
        assert result.constraints.not_before == nb2

    def test_earliest_not_after(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        third_party_did: DID,
        third_party_secret_key: bytes,
        third_party_public_key: bytes,
    ) -> None:
        now = datetime.now(UTC)
        na1 = now + timedelta(hours=2)
        na2 = now + timedelta(hours=1)
        c1 = Constraints(not_after=na1)
        c2 = Constraints(not_after=na2)
        t1 = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://a",
            verbs={"read"},
            constraints=c1,
        )
        t2 = create_token(
            issuer_did=third_party_did,
            issuer_secret_key=third_party_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://b",
            verbs={"write"},
            constraints=c2,
        )
        result = aggregate_tokens(
            [t1, t2],
            issuer_public_keys={
                str(issuer_did): issuer_public_key,
                str(third_party_did): third_party_public_key,
            },
        )
        assert result.constraints.not_after == na2

    def test_smallest_quantity(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        third_party_did: DID,
        third_party_secret_key: bytes,
        third_party_public_key: bytes,
    ) -> None:
        c1 = Constraints(quantity_limit=100)
        c2 = Constraints(quantity_limit=50)
        t1 = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://a",
            verbs={"read"},
            constraints=c1,
        )
        t2 = create_token(
            issuer_did=third_party_did,
            issuer_secret_key=third_party_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://b",
            verbs={"write"},
            constraints=c2,
        )
        result = aggregate_tokens(
            [t1, t2],
            issuer_public_keys={
                str(issuer_did): issuer_public_key,
                str(third_party_did): third_party_public_key,
            },
        )
        assert result.constraints.quantity_limit == 50

    def test_smallest_rate(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        third_party_did: DID,
        third_party_secret_key: bytes,
        third_party_public_key: bytes,
    ) -> None:
        c1 = Constraints(rate_limit=100)
        c2 = Constraints(rate_limit=10)
        t1 = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://a",
            verbs={"read"},
            constraints=c1,
        )
        t2 = create_token(
            issuer_did=third_party_did,
            issuer_secret_key=third_party_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://b",
            verbs={"write"},
            constraints=c2,
        )
        result = aggregate_tokens(
            [t1, t2],
            issuer_public_keys={
                str(issuer_did): issuer_public_key,
                str(third_party_did): third_party_public_key,
            },
        )
        assert result.constraints.rate_limit == 10

    def test_smallest_spend(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        third_party_did: DID,
        third_party_secret_key: bytes,
        third_party_public_key: bytes,
    ) -> None:
        c1 = Constraints(max_spend=1000)
        c2 = Constraints(max_spend=500)
        t1 = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://a",
            verbs={"read"},
            constraints=c1,
        )
        t2 = create_token(
            issuer_did=third_party_did,
            issuer_secret_key=third_party_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://b",
            verbs={"write"},
            constraints=c2,
        )
        result = aggregate_tokens(
            [t1, t2],
            issuer_public_keys={
                str(issuer_did): issuer_public_key,
                str(third_party_did): third_party_public_key,
            },
        )
        assert result.constraints.max_spend == 500

    def test_data_scope_intersection(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        third_party_did: DID,
        third_party_secret_key: bytes,
        third_party_public_key: bytes,
    ) -> None:
        c1 = Constraints(data_scope=frozenset({"a", "b", "c"}))
        c2 = Constraints(data_scope=frozenset({"b", "c", "d"}))
        t1 = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://a",
            verbs={"read"},
            constraints=c1,
        )
        t2 = create_token(
            issuer_did=third_party_did,
            issuer_secret_key=third_party_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://b",
            verbs={"write"},
            constraints=c2,
        )
        result = aggregate_tokens(
            [t1, t2],
            issuer_public_keys={
                str(issuer_did): issuer_public_key,
                str(third_party_did): third_party_public_key,
            },
        )
        assert result.constraints.data_scope == frozenset({"b", "c"})

    def test_unshared_dimension_inherited(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        third_party_did: DID,
        third_party_secret_key: bytes,
        third_party_public_key: bytes,
    ) -> None:
        """A constraint defined in one token but not the other is inherited."""
        c1 = Constraints(quantity_limit=100, quantity_unit="vCPU-h")
        c2 = Constraints()  # no quantity
        t1 = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://a",
            verbs={"read"},
            constraints=c1,
        )
        t2 = create_token(
            issuer_did=third_party_did,
            issuer_secret_key=third_party_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://b",
            verbs={"write"},
            constraints=c2,
        )
        result = aggregate_tokens(
            [t1, t2],
            issuer_public_keys={
                str(issuer_did): issuer_public_key,
                str(third_party_did): third_party_public_key,
            },
        )
        assert result.constraints.quantity_limit == 100
        assert result.constraints.quantity_unit == "vCPU-h"

    def test_toolchain_intersection(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        third_party_did: DID,
        third_party_secret_key: bytes,
        third_party_public_key: bytes,
    ) -> None:
        c1 = Constraints(allowed_toolchain=("tool_a", "tool_b", "tool_c"))
        c2 = Constraints(allowed_toolchain=("tool_b", "tool_c", "tool_d"))
        t1 = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://a",
            verbs={"read"},
            constraints=c1,
        )
        t2 = create_token(
            issuer_did=third_party_did,
            issuer_secret_key=third_party_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://b",
            verbs={"write"},
            constraints=c2,
        )
        result = aggregate_tokens(
            [t1, t2],
            issuer_public_keys={
                str(issuer_did): issuer_public_key,
                str(third_party_did): third_party_public_key,
            },
        )
        assert result.constraints.allowed_toolchain == ("tool_b", "tool_c")


# =============================================================================
# TestCheckActionPermitted
# =============================================================================


class TestCheckActionPermitted:
    """Tests for check_action_permitted."""

    def test_permitted_action(self) -> None:
        agg = AggregatedPermission(
            verbs=VerbSet({"read", "write"}),
            resource_uris=frozenset({"qasp://a", "qasp://b"}),
            constraints=Constraints(),
            source_token_ids=(b"tok1",),
        )
        assert check_action_permitted(agg, "read", "qasp://a") is True

    def test_verb_not_permitted(self) -> None:
        agg = AggregatedPermission(
            verbs=VerbSet({"read"}),
            resource_uris=frozenset({"qasp://a"}),
            constraints=Constraints(),
            source_token_ids=(b"tok1",),
        )
        with pytest.raises(TokenConstraintViolation, match="Verb"):
            check_action_permitted(agg, "write", "qasp://a")

    def test_resource_not_permitted(self) -> None:
        agg = AggregatedPermission(
            verbs=VerbSet({"read"}),
            resource_uris=frozenset({"qasp://a"}),
            constraints=Constraints(),
            source_token_ids=(b"tok1",),
        )
        with pytest.raises(TokenConstraintViolation, match="Resource"):
            check_action_permitted(agg, "read", "qasp://b")


# =============================================================================
# TestAggregationWithDIDResolver
# =============================================================================


class TestAggregationWithDIDResolver:
    """Tests for DID resolver integration."""

    def test_resolver_fallback_when_key_not_in_map(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        third_party_did: DID,
        third_party_secret_key: bytes,
        did_registry: DIDRegistry,
    ) -> None:
        """Resolver is used when a key is not in issuer_public_keys."""
        t1 = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://a",
            verbs={"read"},
        )
        t2 = create_token(
            issuer_did=third_party_did,
            issuer_secret_key=third_party_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://b",
            verbs={"write"},
        )
        resolver = LocalDIDResolver(did_registry)
        # Only provide key for t1's issuer; t2's issuer resolved via DID
        result = aggregate_tokens(
            [t1, t2],
            issuer_public_keys={str(issuer_did): issuer_public_key},
            did_resolver=resolver,
        )
        assert set(result.verbs) == {"read", "write"}

    def test_resolver_not_called_when_keys_provided(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        third_party_did: DID,
        third_party_secret_key: bytes,
        third_party_public_key: bytes,
    ) -> None:
        """When all keys are in the map, resolver is not needed."""
        t1 = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://a",
            verbs={"read"},
        )
        t2 = create_token(
            issuer_did=third_party_did,
            issuer_secret_key=third_party_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://b",
            verbs={"write"},
        )

        class FailingResolver:
            def resolve(self, _did: DID) -> bytes:
                raise AssertionError("Resolver should not be called")

        result = aggregate_tokens(
            [t1, t2],
            issuer_public_keys={
                str(issuer_did): issuer_public_key,
                str(third_party_did): third_party_public_key,
            },
            did_resolver=FailingResolver(),  # type: ignore[arg-type]
        )
        assert set(result.verbs) == {"read", "write"}
