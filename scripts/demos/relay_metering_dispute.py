"""M7 Demo 3: Budget exhaustion triggers RelaySessionClose(reason_code=0x23).

Alice opens a relay session with ``max_messages=3`` and sends 3 messages
successfully.  The 4th send causes the authority to close the session with
``reason_code=0x23`` (SESSION_BUDGET_EXHAUSTED).

Uses the FastAPI TestClient (in-process server).

Run with::

    python -m scripts.demos.relay_metering_dispute

Prints ``DEMO PASS`` on success, ``DEMO FAIL`` on failure.  Exits 0 / 1.

Note (PoC limitation)
---------------------
The demo accesses ``srv.state`` directly to retrieve the agent's secret key
and register the capability token.  In a real deployment, each agent owns its
keypair and the authority never exports it.
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
        create_token,
    )
    from qasp.protocol.relay.messages import (
        RelayData,
        RelaySessionAccept,
        RelaySessionClose,
        RelaySessionGrant,
        RelaySessionNotify,
        RelaySessionParams,
        RelaySessionRequest,
        decode_relay_frame,
    )

    srv.state = srv.AuthorityState()

    with TestClient(srv.app) as client:
        # --- register Alice and Bob ---
        alice_ws_cm = client.websocket_connect("/ws/register")
        alice_ws = alice_ws_cm.__enter__()
        alice_ws.send_json({"type": "register", "name": "alice", "tools": [], "callback_url": ""})
        alice_reg = alice_ws.receive_json()
        assert alice_reg["type"] == "registered", alice_reg
        alice_ws.receive_json()  # connected

        bob_ws_cm = client.websocket_connect("/ws/register")
        bob_ws = bob_ws_cm.__enter__()
        bob_ws.send_json({"type": "register", "name": "bob", "tools": [], "callback_url": ""})
        bob_reg = bob_ws.receive_json()
        assert bob_reg["type"] == "registered", bob_reg
        bob_ws.receive_json()  # connected

        print(f"[trace] Alice DID: {alice_reg['did']}")
        print(f"[trace] Bob   DID: {bob_reg['did']}")

        # --- Alice mints a token and registers it ---
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
        srv.state.tokens[token.token_id.hex()] = token
        cap_bytes = token.to_cbor()
        print(f"[trace] Token minted: {token.token_id.hex()[:16]}…")

        # --- Alice opens session with max_messages=3 ---
        req = RelaySessionRequest(
            target_agent=bob_reg["did"],
            capability_token=cap_bytes,
            session_params=RelaySessionParams(
                max_messages=3,
                max_bytes=10_000,
                max_rate=None,
                duration_sec=60,
                purpose=None,
            ),
            ephemeral_pk=None,
            nonce=b"\x02" * 32,
        )
        alice_ws.send_bytes(req.to_cbor())
        print("[trace] Alice -> RelaySessionRequest (max_messages=3)")

        # --- Bob accepts ---
        notify_raw = bob_ws.receive_bytes()
        notify = decode_relay_frame(notify_raw)
        assert isinstance(notify, RelaySessionNotify)
        bob_ws.send_bytes(RelaySessionAccept(session_id=notify.session_id, accepted=True).to_cbor())
        print("[trace] Bob  -> RelaySessionAccept")

        # --- Both receive their grants ---
        alice_grant = decode_relay_frame(alice_ws.receive_bytes())
        assert isinstance(alice_grant, RelaySessionGrant)
        _bob_grant = decode_relay_frame(bob_ws.receive_bytes())
        assert isinstance(_bob_grant, RelaySessionGrant)
        print(f"[trace] Session established (id={alice_grant.session_id.hex()[:16]}…)")

        # --- Send 3 messages: each should be forwarded successfully ---
        for i in range(1, 4):
            alice_ws.send_bytes(
                RelayData(
                    session_id=alice_grant.session_id,
                    scm=alice_grant.scm,
                    seq=i,
                    payload=f"msg-{i}".encode(),
                    receipt_ack=None,
                ).to_cbor()
            )
            fwd = decode_relay_frame(bob_ws.receive_bytes())
            assert isinstance(fwd, RelayData), f"msg {i}: expected RelayData, got {type(fwd)}"
            print(f"[trace] Message {i} delivered: payload={fwd.payload!r}")

        # --- 4th message: expect the authority to close the session ---
        print("[trace] Sending 4th message (budget=3, expect close)…")
        alice_ws.send_bytes(
            RelayData(
                session_id=alice_grant.session_id,
                scm=alice_grant.scm,
                seq=4,
                payload=b"msg-4-over-budget",
                receipt_ack=None,
            ).to_cbor()
        )

        # The authority sends a RelaySessionClose(0x23) to Alice.
        # It also sends one to Bob; drain both sides to avoid race conditions.
        close_msg = None
        for _ in range(4):  # allow some forwarded frames to drain
            try:
                raw = alice_ws.receive_bytes()
            except Exception:
                break
            frame = decode_relay_frame(raw)
            if isinstance(frame, RelaySessionClose):
                close_msg = frame
                break

        # Drain Bob's side (close may arrive there too)
        try:
            bob_raw = bob_ws.receive_bytes()
            bob_frame = decode_relay_frame(bob_raw)
            if isinstance(bob_frame, RelaySessionClose):
                print(f"[trace] Bob  <- RelaySessionClose(reason_code={bob_frame.reason_code:#x})")
        except Exception:
            pass

        # Clean up
        for ws_cm in (alice_ws_cm, bob_ws_cm):
            try:
                ws_cm.__exit__(None, None, None)
            except Exception:
                pass

    # --- Verify ---
    if close_msg is not None and close_msg.reason_code == 0x23:
        print(
            f"DEMO PASS: relay_metering_dispute — "
            f"4th message triggered RelaySessionClose(reason_code=0x23): "
            f'"{close_msg.reason_text}"'
        )
        return 0
    else:
        if close_msg is None:
            print("DEMO FAIL: no RelaySessionClose received after 4th message")
        else:
            print(
                f"DEMO FAIL: got RelaySessionClose but wrong reason_code "
                f"{close_msg.reason_code:#x} (expected 0x23)"
            )
        return 1


if __name__ == "__main__":
    sys.exit(main())
