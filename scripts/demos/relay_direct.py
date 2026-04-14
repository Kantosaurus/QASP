"""M7 Demo 1: Alice sends 3 messages to Bob via the authority relay.

Uses the FastAPI TestClient (in-process server) so no external process is
required.  Demonstrates the full CapFlow happy path:

  Alice --[RelaySessionRequest]--> authority --> Bob [RelaySessionNotify]
  Bob   --[RelaySessionAccept]-->  authority --> Alice [RelaySessionGrant]
  Alice --[RelayData x3]-------->  authority --> Bob [RelayData x3]
  Alice --[RelaySessionClose]---> authority --> Bob [RelaySessionClose]

Run with::

    python -m scripts.demos.relay_direct

Prints ``DEMO PASS`` on success, ``DEMO FAIL`` on failure.  Exits 0 / 1.

Note (PoC limitation)
---------------------
The demo accesses ``srv.state`` directly to retrieve the agent's secret key
and register the capability token.  In a production deployment, each agent
owns its keypair and the authority never sees the secret key; the PoC
registration flow does not expose it to remote callers.
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
        # --- register Alice ---
        alice_ws_cm = client.websocket_connect("/ws/register")
        alice_ws = alice_ws_cm.__enter__()
        alice_ws.send_json({"type": "register", "name": "alice", "tools": [], "callback_url": ""})
        alice_reg = alice_ws.receive_json()
        assert alice_reg["type"] == "registered", alice_reg
        alice_ws.receive_json()  # connected

        # --- register Bob ---
        bob_ws_cm = client.websocket_connect("/ws/register")
        bob_ws = bob_ws_cm.__enter__()
        bob_ws.send_json({"type": "register", "name": "bob", "tools": [], "callback_url": ""})
        bob_reg = bob_ws.receive_json()
        assert bob_reg["type"] == "registered", bob_reg
        bob_ws.receive_json()  # connected

        print(f"[trace] Alice DID: {alice_reg['did']}")
        print(f"[trace] Bob   DID: {bob_reg['did']}")

        # --- Alice mints a self-addressed relay capability token ---
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

        # --- Alice opens a relay session targeting Bob ---
        req = RelaySessionRequest(
            target_agent=bob_reg["did"],
            capability_token=cap_bytes,
            session_params=RelaySessionParams(
                max_messages=3,
                max_bytes=1_000,
                max_rate=None,
                duration_sec=30,
                purpose=None,
            ),
            ephemeral_pk=None,
            nonce=b"\x00" * 32,
        )
        alice_ws.send_bytes(req.to_cbor())
        print("[trace] Alice -> RelaySessionRequest")

        # --- Bob receives the notify and accepts ---
        notify_raw = bob_ws.receive_bytes()
        notify = decode_relay_frame(notify_raw)
        assert isinstance(notify, RelaySessionNotify), f"expected Notify, got {type(notify)}"
        assert notify.initiator_did == alice_reg["did"]
        print(f"[trace] Bob  <- RelaySessionNotify (session={notify.session_id.hex()[:16]}…)")

        bob_ws.send_bytes(RelaySessionAccept(session_id=notify.session_id, accepted=True).to_cbor())
        print("[trace] Bob  -> RelaySessionAccept")

        # --- Alice receives her grant ---
        alice_grant = decode_relay_frame(alice_ws.receive_bytes())
        assert isinstance(alice_grant, RelaySessionGrant)
        print(f"[trace] Alice <- RelaySessionGrant (scm={alice_grant.scm.hex()[:16]}…)")

        # --- Bob receives his grant ---
        bob_grant = decode_relay_frame(bob_ws.receive_bytes())
        assert isinstance(bob_grant, RelaySessionGrant)
        print(f"[trace] Bob  <- RelaySessionGrant (scm={bob_grant.scm.hex()[:16]}…)")

        # --- Alice sends 3 data messages ---
        received_payloads: list[bytes] = []
        for i in range(1, 4):
            payload = f"hello-{i}".encode()
            alice_ws.send_bytes(
                RelayData(
                    session_id=alice_grant.session_id,
                    scm=alice_grant.scm,
                    seq=i,
                    payload=payload,
                    receipt_ack=None,
                ).to_cbor()
            )
            print(f"[trace] Alice -> RelayData seq={i} payload={payload!r}")

            fwd = decode_relay_frame(bob_ws.receive_bytes())
            assert isinstance(fwd, RelayData), f"expected RelayData, got {type(fwd)}"
            received_payloads.append(fwd.payload)
            print(f"[trace] Bob  <- RelayData seq={fwd.seq} payload={fwd.payload!r}")

        # --- Alice closes the session ---
        alice_ws.send_bytes(
            RelaySessionClose(
                session_id=alice_grant.session_id,
                reason_code=0x00,
                reason_text="done",
            ).to_cbor()
        )
        print("[trace] Alice -> RelaySessionClose(reason=done)")

        # Clean up
        try:
            alice_ws_cm.__exit__(None, None, None)
        except Exception:
            pass
        try:
            bob_ws_cm.__exit__(None, None, None)
        except Exception:
            pass

    # --- Verify ---
    expected = [f"hello-{i}".encode() for i in range(1, 4)]
    if received_payloads == expected:
        print("DEMO PASS: relay_direct — 3 messages delivered in order")
        return 0
    else:
        print(f"DEMO FAIL: expected {expected!r}, got {received_payloads!r}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
