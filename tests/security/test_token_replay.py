"""Security tests for token replay prevention.

Security property: A token can only be consumed once.
"""

from __future__ import annotations

import pytest

from qasp.crypto import signatures
from qasp.identity import DID
from qasp.protocol.capability import (
    CapabilityToken,
    VerbSet,
    attenuate_token,
    create_token,
    split_token,
    verify_token,
)
from qasp.protocol.token_use_log import TokenReplayError, TokenUseLog


@pytest.mark.security
class TestTokenUseLog:
    """Unit tests for TokenUseLog."""

    def test_first_use_succeeds(self, token_use_log: TokenUseLog) -> None:
        """mark_used does not raise on first use."""
        token_id = b"token_001"
        token_use_log.mark_used(token_id)

    def test_second_use_raises_replay_error(self, token_use_log: TokenUseLog) -> None:
        """Second mark_used with same token_id raises TokenReplayError."""
        token_id = b"token_002"
        token_use_log.mark_used(token_id)
        with pytest.raises(TokenReplayError):
            token_use_log.mark_used(token_id)

    def test_different_tokens_accepted(self, token_use_log: TokenUseLog) -> None:
        """Two different token_ids both succeed."""
        token_use_log.mark_used(b"token_a")
        token_use_log.mark_used(b"token_b")

    def test_is_used_reflects_state(self, token_use_log: TokenUseLog) -> None:
        """is_used returns False before and True after mark_used."""
        token_id = b"token_003"
        assert not token_use_log.is_used(token_id)
        token_use_log.mark_used(token_id)
        assert token_use_log.is_used(token_id)

    def test_contains_operator(self, token_use_log: TokenUseLog) -> None:
        """'in' operator works via __contains__."""
        token_id = b"token_004"
        assert token_id not in token_use_log
        token_use_log.mark_used(token_id)
        assert token_id in token_use_log

    def test_len_tracks_count(self, token_use_log: TokenUseLog) -> None:
        """len(log) increments correctly."""
        assert len(token_use_log) == 0
        token_use_log.mark_used(b"a")
        assert len(token_use_log) == 1
        token_use_log.mark_used(b"b")
        assert len(token_use_log) == 2


@pytest.mark.security
class TestTokenReplayWithRealTokens:
    """Replay prevention with real cryptographic tokens."""

    def test_verify_then_replay_rejected(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        issuer_public_key: bytes,
        subject_did: DID,
        token_use_log: TokenUseLog,
    ) -> None:
        """create_token -> verify_token -> mark_used succeeds, second mark_used raises."""
        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
            max_delegation_depth=0,
        )
        verify_token(token, issuer_public_key, check_expiry=True)
        token_use_log.mark_used(token.token_id)

        with pytest.raises(TokenReplayError):
            token_use_log.mark_used(token.token_id)

    def test_attenuated_token_has_distinct_id(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        delegate_did: DID,
        token_use_log: TokenUseLog,
    ) -> None:
        """Parent and attenuated child have different token_ids; both can be used."""
        parent = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read", "write"},
            max_delegation_depth=2,
        )
        child = attenuate_token(
            parent_token=parent,
            delegator_secret_key=subject_secret_key,
            new_subject_did=delegate_did,
            reduced_verbs=VerbSet({"read"}),
        )

        assert parent.token_id != child.token_id
        token_use_log.mark_used(parent.token_id)
        token_use_log.mark_used(child.token_id)

    def test_split_tokens_have_distinct_ids(
        self,
        issuer_did: DID,
        issuer_secret_key: bytes,
        subject_did: DID,
        subject_secret_key: bytes,
        token_use_log: TokenUseLog,
    ) -> None:
        """split_token produces tokens with unique IDs."""
        from qasp.protocol.capability import Constraints

        parent = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=issuer_secret_key,
            subject_did=subject_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
            constraints=Constraints(quantity_limit=10),
            max_delegation_depth=2,
        )
        splits = split_token(
            token=parent,
            holder_secret_key=subject_secret_key,
            split_amounts=[3, 3, 4],
        )

        ids = {t.token_id for t in splits}
        ids.add(parent.token_id)
        assert len(ids) == 4  # parent + 3 splits all unique

        for t in splits:
            token_use_log.mark_used(t.token_id)
        assert len(token_use_log) == 3
