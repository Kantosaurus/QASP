"""M7 Demo 2: Delegation chain — Charlie relays to Bob using an attenuated token.

Three agents: Alice, Charlie, Bob.

  1. Alice mints a root token (subject=Alice, max_delegation_depth=2).
  2. Alice attenuates it for Charlie (new subject=Charlie, depth reduced to 1).
  3. Charlie registers the attenuated token with the authority.
  4. Charlie opens a relay session to Bob using the attenuated token.
  5. Bob receives the message, confirming delegation survives relay.

Uses the FastAPI TestClient (in-process server).

Run with::

    python -m scripts.demos.relay_delegation_chain

Prints ``DEMO PASS`` on success, ``DEMO FAIL`` on failure.  Exits 0 / 1.

Note (PoC limitation)
---------------------
The demo accesses ``srv.state`` to get agents' secret keys.  In a real
deployment each agent holds its own keypair; the authority never exports them.
"""

from __future__ import annotations

import sys


def _real_liboqs_available() -> bool:
    try:
        from qasp.crypto.signatures import generate_keypair

        pk, sk = generate_keypair()
        return len(pk) > 0 and len(sk) > 0
    except Exception:
        return False


def main() -> int:
    if not _real_liboqs_available():
        print("DEMO SKIP: liboqs required — install liboqs to run this demo")
        return 0

    from fastapi.testclient import TestClient

    import scripts.qasp_server as srv
    from qasp.identity.did import DID
    from qasp.protocol.capability import (
        ARM_READ,
        ARM_RELAY,
        ARM_WRITE,
        Constraints,
        VerbSet,
        attenuate_token,
        create_token,
    )
    from qasp.protocol.relay.messages import (
        RelayData,
        RelaySessionAccept,
        RelaySessionGrant,
        RelaySessionNotify,
        RelaySessionParams,
        RelaySessionRequest,
        decode_relay_frame,
    )

    srv.state = srv.AuthorityState()

    with TestClient(srv.app) as client:
        # --- register Alice, Charlie, Bob ---
        def _register(ws_cm_ref, name):
            ws = ws_cm_ref.__enter__()
            ws.send_json({"type": "register", "name": name, "tools": [], "callback_url": ""})
            reg = ws.receive_json()
            assert reg["type"] == "registered", reg
            ws.receive_json()  # connected frame
            return ws, reg

        alice_ws_cm = client.websocket_connect("/ws/register")
        alice_ws, alice_reg = _register(alice_ws_cm, "alice")

        charlie_ws_cm = client.websocket_connect("/ws/register")
        charlie_ws, charlie_reg = _register(charlie_ws_cm, "charlie")

        bob_ws_cm = client.websocket_connect("/ws/register")
        bob_ws, bob_reg = _register(bob_ws_cm, "bob")

        print(f"[trace] Alice   DID: {alice_reg['did']}")
        print(f"[trace] Charlie DID: {charlie_reg['did']}")
        print(f"[trace] Bob     DID: {bob_reg['did']}")

        # --- Step 1: Alice mints a root token (subject=Alice) ---
        alice_did = DID.parse(alice_reg["did"])
        alice_agent = srv.state.agents_by_did[alice_reg["did"]]
        root_token = create_token(
            issuer_did=alice_did,
            issuer_secret_key=alice_agent.secret_key,
            subject_did=alice_did,
            resource_uri="qasp://testprovider/resource",
            verbs=VerbSet({ARM_READ, ARM_WRITE, ARM_RELAY}),
            constraints=Constraints(quantity_limit=100),
            max_delegation_depth=2,
        )
        print(f"[trace] Alice minted root token: {root_token.token_id.hex()[:16]}…")

        # --- Step 2: Alice attenuates for Charlie (subject becomes Charlie) ---
        charlie_did = DID.parse(charlie_reg["did"])
        charlie_agent = srv.state.agents_by_did[charlie_reg["did"]]
        charlie_token = attenuate_token(
            parent_token=root_token,
            delegator_secret_key=alice_agent.secret_key,
            new_subject_did=charlie_did,
            reduced_verbs=VerbSet({ARM_READ, ARM_WRITE, ARM_RELAY}),
        )
        print(f"[trace] Alice -> Charlie token: {charlie_token.token_id.hex()[:16]}…")

        # --- Step 3: Register Charlie's token with the authority ---
        # The _AuthorityTokenVerifier checks token.subject_did == initiator_did (Charlie).
        srv.state.tokens[charlie_token.token_id.hex()] = charlie_token
        cap_bytes = charlie_token.to_cbor()

        # --- Step 4: Charlie opens relay session to Bob ---
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
            nonce=b"\x01" * 32,
        )
        charlie_ws.send_bytes(req.to_cbor())
        print("[trace] Charlie -> RelaySessionRequest")

        # --- Bob receives notify and accepts ---
        notify_raw = bob_ws.receive_bytes()
        notify = decode_relay_frame(notify_raw)
        assert isinstance(notify, RelaySessionNotify), f"expected Notify, got {type(notify)}"
        assert notify.initiator_did == charlie_reg["did"]
        print(f"[trace] Bob  <- RelaySessionNotify (initiator={notify.initiator_did[:30]}…)")

        bob_ws.send_bytes(RelaySessionAccept(session_id=notify.session_id, accepted=True).to_cbor())
        print("[trace] Bob  -> RelaySessionAccept")

        # --- Charlie receives grant ---
        charlie_grant = decode_relay_frame(charlie_ws.receive_bytes())
        assert isinstance(charlie_grant, RelaySessionGrant)
        print(f"[trace] Charlie <- RelaySessionGrant")

        # --- Bob receives grant ---
        bob_grant = decode_relay_frame(bob_ws.receive_bytes())
        assert isinstance(bob_grant, RelaySessionGrant)
        print(f"[trace] Bob     <- RelaySessionGrant")

        # --- Step 5: Charlie sends one message to Bob ---
        msg_payload = b"charlie-to-bob via delegation"
        charlie_ws.send_bytes(
            RelayData(
                session_id=charlie_grant.session_id,
                scm=charlie_grant.scm,
                seq=1,
                payload=msg_payload,
                receipt_ack=None,
            ).to_cbor()
        )
        print(f"[trace] Charlie -> RelayData payload={msg_payload!r}")

        fwd = decode_relay_frame(bob_ws.receive_bytes())
        assert isinstance(fwd, RelayData), f"expected RelayData, got {type(fwd)}"
        print(f"[trace] Bob  <- RelayData payload={fwd.payload!r}")

        # Clean up
        for ws_cm in (alice_ws_cm, charlie_ws_cm, bob_ws_cm):
            try:
                ws_cm.__exit__(None, None, None)
            except Exception:
                pass

    # --- Verify ---
    if fwd.payload == msg_payload:
        print("DEMO PASS: relay_delegation_chain — delegated relay message delivered")
        return 0
    else:
        print(f"DEMO FAIL: expected {msg_payload!r}, got {fwd.payload!r}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
