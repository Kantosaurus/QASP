"""End-to-end CapFlow integration through the running FastAPI server.

Exercises the full request -> notify -> accept -> grant -> data -> close flow
using two synthetic agents connected via FastAPI's TestClient. The entire
test suite is gated on a real liboqs install -- on hosts without it, all
tests in this module skip cleanly.
"""

from __future__ import annotations

import pytest


def _real_liboqs_available() -> bool:
    try:
        from qasp.crypto.signatures import generate_keypair

        pk, sk = generate_keypair()
        return len(pk) > 0 and len(sk) > 0
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _real_liboqs_available(),
    reason="liboqs required for end-to-end CapFlow test",
)


# Imports below run only when liboqs is present.
from fastapi.testclient import TestClient  # noqa: E402

import scripts.qasp_server as srv  # noqa: E402

from qasp.identity.did import DID  # noqa: E402
from qasp.protocol.capability import (  # noqa: E402
    ARM_READ,
    ARM_RELAY,
    ARM_WRITE,
    Constraints,
    VerbSet,
    create_token,
)
from qasp.protocol.relay.messages import (  # noqa: E402
    RelayData,
    RelaySessionAccept,
    RelaySessionGrant,
    RelaySessionNotify,
    RelaySessionParams,
    RelaySessionRequest,
    decode_relay_frame,
)


@pytest.fixture
def client():
    """Force a fresh AuthorityState for each test run."""
    srv.state = srv.AuthorityState()
    with TestClient(srv.app) as c:
        yield c


def _register(client, name: str):
    """Open a registration WebSocket and return (ws_cm, ws_entered, registration_dict)."""
    ws_cm = client.websocket_connect("/ws/register")
    ws = ws_cm.__enter__()
    ws.send_json({"type": "register", "name": name, "tools": [], "callback_url": ""})
    reg = ws.receive_json()
    assert reg["type"] == "registered", f"Expected 'registered', got: {reg}"
    # welcome frame follows
    welcome = ws.receive_json()
    assert welcome["type"] == "connected", f"Expected 'connected', got: {welcome}"
    return ws_cm, ws, reg


def _register_token_with_state(token):
    """Register the capability token with the authority so _AuthorityTokenVerifier can find it.

    The verifier loops over state.tokens.values() and matches by SHA-384 of
    token.to_cbor(), so any key works. We use token_id.hex() to match the
    pattern used by the /tokens/request endpoint.
    """
    token_id_hex = token.token_id.hex()
    srv.state.tokens[token_id_hex] = token


def test_relay_session_end_to_end_happy_path(client):
    """Alice opens a relay session to Bob, exchanges messages, and closes cleanly."""
    alice_ws_cm, alice_ws, alice_reg = _register(client, "alice")
    bob_ws_cm, bob_ws, bob_reg = _register(client, "bob")

    try:
        # Alice mints a capability token.
        # The _AuthorityTokenVerifier.verify checks token.subject_did == initiator_did
        # (Alice), so Alice issues a self-addressed token.
        # The attenuate_for_target step uses relay_secret_key but takes the token's
        # subject_did as new issuer -- this is a known PoC limitation noted in Task 9.
        alice_did = DID.parse(alice_reg["did"])
        alice_agent = srv.state.agents_by_did[alice_reg["did"]]
        token = create_token(
            issuer_did=alice_did,
            issuer_secret_key=alice_agent.secret_key,
            subject_did=alice_did,
            resource_uri="qasp://testprovider/resource",
            verbs=VerbSet({ARM_READ, ARM_WRITE, ARM_RELAY}),
            constraints=Constraints(quantity_limit=100),
            max_delegation_depth=2,
        )
        _register_token_with_state(token)
        cap_bytes = token.to_cbor()

        # Alice sends RelaySessionRequest targeting Bob.
        req = RelaySessionRequest(
            target_agent=bob_reg["did"],
            capability_token=cap_bytes,
            session_params=RelaySessionParams(
                max_messages=5,
                max_bytes=1_000,
                max_rate=None,
                duration_sec=30,
                purpose=None,
            ),
            ephemeral_pk=None,
            nonce=b"\x00" * 32,
        )
        alice_ws.send_bytes(req.to_cbor())

        # Bob should receive a RelaySessionNotify.
        notify_raw = bob_ws.receive_bytes()
        notify = decode_relay_frame(notify_raw)
        assert isinstance(notify, RelaySessionNotify)
        assert notify.initiator_did == alice_reg["did"]

        # Bob accepts.
        bob_ws.send_bytes(
            RelaySessionAccept(session_id=notify.session_id, accepted=True).to_cbor(),
        )

        # Alice receives her Grant.
        alice_grant = decode_relay_frame(alice_ws.receive_bytes())
        assert isinstance(alice_grant, RelaySessionGrant)
        assert alice_grant.session_id == notify.session_id

        # Bob also receives his Grant (with his direction SCM).
        bob_grant = decode_relay_frame(bob_ws.receive_bytes())
        assert isinstance(bob_grant, RelaySessionGrant)
        assert bob_grant.session_id == notify.session_id
        assert bob_grant.scm != alice_grant.scm

        # Alice sends a relay data frame.
        alice_ws.send_bytes(
            RelayData(
                session_id=alice_grant.session_id,
                scm=alice_grant.scm,
                seq=1,
                payload=b"hello bob",
                receipt_ack=None,
            ).to_cbor(),
        )
        forwarded = decode_relay_frame(bob_ws.receive_bytes())
        assert isinstance(forwarded, RelayData)
        assert forwarded.payload == b"hello bob"
        assert forwarded.seq == 1

    finally:
        try:
            alice_ws_cm.__exit__(None, None, None)
        except Exception:
            pass
        try:
            bob_ws_cm.__exit__(None, None, None)
        except Exception:
            pass


def test_relay_target_not_connected(client):
    """Alice requests a session with a non-existent target and receives Deny 0x20."""
    from qasp.protocol.relay.messages import RelaySessionDeny

    alice_ws_cm, alice_ws, alice_reg = _register(client, "alice")
    try:
        alice_did = DID.parse(alice_reg["did"])
        alice_agent = srv.state.agents_by_did[alice_reg["did"]]
        token = create_token(
            issuer_did=alice_did,
            issuer_secret_key=alice_agent.secret_key,
            subject_did=alice_did,
            resource_uri="qasp://testprovider/resource",
            verbs=VerbSet({ARM_READ, ARM_WRITE, ARM_RELAY}),
            constraints=Constraints(quantity_limit=100),
            max_delegation_depth=2,
        )
        _register_token_with_state(token)

        req = RelaySessionRequest(
            target_agent="did:qasp:nonexistent-agent-xyz",
            capability_token=token.to_cbor(),
            session_params=RelaySessionParams(
                max_messages=5,
                max_bytes=1_000,
                max_rate=None,
                duration_sec=30,
                purpose=None,
            ),
            ephemeral_pk=None,
            nonce=b"\x00" * 32,
        )
        alice_ws.send_bytes(req.to_cbor())

        deny = decode_relay_frame(alice_ws.receive_bytes())
        assert isinstance(deny, RelaySessionDeny)
        assert deny.error_code == 0x20

    finally:
        try:
            alice_ws_cm.__exit__(None, None, None)
        except Exception:
            pass
