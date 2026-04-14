"""Tests for relay-target token attenuation (PRD §4.3, §10.2)."""

from datetime import UTC, datetime, timedelta

import pytest

# Real liboqs detection: stubbed oqs returns empty bytes, which would pass an
# importorskip check but break the test. Do a real keypair probe instead.
def _real_liboqs_available() -> bool:
    try:
        from qasp.crypto.signatures import generate_keypair
        pk, sk = generate_keypair()
        return len(pk) > 0 and len(sk) > 0
    except Exception:
        return False

pytestmark = pytest.mark.skipif(
    not _real_liboqs_available(),
    reason="liboqs required for real ML-DSA-65 operations",
)

from qasp.crypto.signatures import generate_keypair
from qasp.identity.did import create_did
from qasp.protocol.capability import (
    ARM_DELEGATE,
    ARM_EXEC,
    ARM_READ,
    ARM_RELAY,
    ARM_WRITE,
    Constraints,
    VerbSet,
    create_token,
    verify_token,
)
from qasp.protocol.relay.attenuation import attenuate_for_target


@pytest.fixture
def alice():
    pk, sk = generate_keypair()
    did, _ = create_did(pk)
    return {"did": did, "pk": pk, "sk": sk}


@pytest.fixture
def relay():
    pk, sk = generate_keypair()
    did, _ = create_did(pk)
    return {"did": did, "pk": pk, "sk": sk}


@pytest.fixture
def bob():
    pk, sk = generate_keypair()
    did, _ = create_did(pk)
    return {"did": did, "pk": pk, "sk": sk}


def _make_source_token(alice, relay, *, include_relay_verb: bool = True):
    verbs = {ARM_READ, ARM_WRITE, ARM_DELEGATE, ARM_EXEC}
    if include_relay_verb:
        verbs.add(ARM_RELAY)
    return create_token(
        issuer_did=alice["did"],
        issuer_secret_key=alice["sk"],
        subject_did=relay["did"],
        resource_uri="qasp://testprovider/resource",
        verbs=VerbSet(verbs),
        constraints=Constraints(
            not_after=datetime.now(UTC) + timedelta(hours=24),
            quantity_limit=1000,
        ),
        max_delegation_depth=2,
    )


class TestAttenuateForTarget:
    def test_verbs_restricted_to_read_write(self, alice, relay, bob):
        source = _make_source_token(alice, relay)
        attenuated = attenuate_for_target(
            source_token=source,
            relay_secret_key=relay["sk"],
            target_did=bob["did"],
            session_id=b"\x01" * 16,
        )
        assert attenuated.verbs.verbs == {ARM_READ, ARM_WRITE}
        assert ARM_DELEGATE not in attenuated.verbs
        assert ARM_EXEC not in attenuated.verbs
        assert ARM_RELAY not in attenuated.verbs

    def test_new_subject_is_target(self, alice, relay, bob):
        source = _make_source_token(alice, relay)
        attenuated = attenuate_for_target(
            source_token=source,
            relay_secret_key=relay["sk"],
            target_did=bob["did"],
            session_id=b"\x01" * 16,
        )
        assert attenuated.subject_did == bob["did"]
        # When we attenuate, the delegator (relay) becomes the new issuer
        assert attenuated.issuer_did == relay["did"]

    def test_constraints_are_tighter_than_source(self, alice, relay, bob):
        source = _make_source_token(alice, relay)
        attenuated = attenuate_for_target(
            source_token=source,
            relay_secret_key=relay["sk"],
            target_did=bob["did"],
            session_id=b"\x01" * 16,
            max_duration_sec=60,
        )
        assert attenuated.constraints.is_tighter_than(source.constraints)
        assert attenuated.constraints.not_after is not None
        assert attenuated.constraints.not_after <= source.constraints.not_after

    def test_signed_by_relay(self, alice, relay, bob):
        source = _make_source_token(alice, relay)
        attenuated = attenuate_for_target(
            source_token=source,
            relay_secret_key=relay["sk"],
            target_did=bob["did"],
            session_id=b"\x01" * 16,
        )
        # Verify the attenuated token's signature using the relay's public key.
        assert verify_token(attenuated, relay["pk"]) is True

    def test_rejects_source_without_relay_verb(self, alice, relay, bob):
        bad_source = _make_source_token(alice, relay, include_relay_verb=False)
        with pytest.raises(ValueError, match="source token lacks ARM_RELAY"):
            attenuate_for_target(
                source_token=bad_source,
                relay_secret_key=relay["sk"],
                target_did=bob["did"],
                session_id=b"\x01" * 16,
            )
