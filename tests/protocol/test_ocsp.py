"""Tests for QASP OCSP (Online Certificate Status Protocol) module."""

from __future__ import annotations

import threading
import time

import cbor2
import pytest

from qasp.crypto import signatures
from qasp.framing import (
    OCSPRequestMessage,
    OCSPResponseMessage,
    MessageType,
    decode_frame,
    encode_frame,
)
from qasp.identity import create_did
from qasp.protocol.capability import CapabilityError
from qasp.protocol.ocsp import (
    DEFAULT_RESPONSE_VALIDITY_SECONDS,
    OCSP_NONCE_SIZE,
    OCSPError,
    OCSPNonceMismatchError,
    OCSPRequest,
    OCSPResponder,
    OCSPResponderUnreachableError,
    OCSPResponse,
    OCSPResponseExpiredError,
    OCSPSignatureError,
    OCSPStatus,
    StapledOCSPResponse,
    _encode_ocsp_response_data,
    check_token_status,
    create_ocsp_request,
    staple_response,
    verify_ocsp_response,
    verify_stapled_response,
)
from qasp.protocol.revocation import (
    CertificateRevocationList,
    RevocationReason,
    RevocationUrgency,
)


# =============================================================================
# TestOCSPStatus
# =============================================================================


class TestOCSPStatus:
    """Tests for OCSPStatus enum."""

    def test_good_value(self):
        assert OCSPStatus.GOOD == 0

    def test_revoked_value(self):
        assert OCSPStatus.REVOKED == 1

    def test_unknown_value(self):
        assert OCSPStatus.UNKNOWN == 2

    def test_constructible_from_int(self):
        assert OCSPStatus(0) is OCSPStatus.GOOD
        assert OCSPStatus(1) is OCSPStatus.REVOKED
        assert OCSPStatus(2) is OCSPStatus.UNKNOWN


# =============================================================================
# TestOCSPRequest
# =============================================================================


class TestOCSPRequest:
    """Tests for OCSPRequest dataclass."""

    def test_creation(self):
        req = OCSPRequest(token_id=b"\x01" * 16, nonce=b"\x02" * 32)
        assert req.token_id == b"\x01" * 16
        assert req.nonce == b"\x02" * 32

    def test_immutability(self):
        req = OCSPRequest(token_id=b"\x01" * 16, nonce=b"\x02" * 32)
        with pytest.raises(AttributeError):
            req.token_id = b"\xff"  # type: ignore[misc]


# =============================================================================
# TestOCSPResponse
# =============================================================================


class TestOCSPResponse:
    """Tests for OCSPResponse dataclass."""

    def test_creation_good(self):
        resp = OCSPResponse(
            status=OCSPStatus.GOOD,
            token_id=b"\x01" * 16,
            this_update=1000,
            next_update=2000,
            responder_id="did:qasp:test",
            nonce=b"\x02" * 32,
            signature=b"\x03" * 64,
        )
        assert resp.status == OCSPStatus.GOOD
        assert resp.revocation_reason is None
        assert resp.revocation_time is None

    def test_creation_revoked(self):
        resp = OCSPResponse(
            status=OCSPStatus.REVOKED,
            token_id=b"\x01" * 16,
            this_update=1000,
            next_update=2000,
            responder_id="did:qasp:test",
            nonce=b"\x02" * 32,
            signature=b"\x03" * 64,
            revocation_reason=1,
            revocation_time=900,
        )
        assert resp.status == OCSPStatus.REVOKED
        assert resp.revocation_reason == 1
        assert resp.revocation_time == 900

    def test_immutability(self):
        resp = OCSPResponse(
            status=OCSPStatus.GOOD,
            token_id=b"\x01" * 16,
            this_update=1000,
            next_update=2000,
            responder_id="did:qasp:test",
            nonce=b"\x02" * 32,
            signature=b"\x03" * 64,
        )
        with pytest.raises(AttributeError):
            resp.status = OCSPStatus.REVOKED  # type: ignore[misc]


# =============================================================================
# TestOCSPRequestCreation
# =============================================================================


class TestOCSPRequestCreation:
    """Tests for create_ocsp_request() function."""

    def test_nonce_size(self):
        req = create_ocsp_request(b"\x01" * 16)
        assert len(req.nonce) == OCSP_NONCE_SIZE

    def test_nonce_randomness(self):
        req1 = create_ocsp_request(b"\x01" * 16)
        req2 = create_ocsp_request(b"\x01" * 16)
        assert req1.nonce != req2.nonce

    def test_token_id_preserved(self):
        token_id = b"\xab\xcd" * 8
        req = create_ocsp_request(token_id)
        assert req.token_id == token_id


# =============================================================================
# TestOCSPResponderGoodStatus
# =============================================================================


class TestOCSPResponderGoodStatus:
    """Tests for OCSPResponder returning GOOD status."""

    def test_good_for_registered_token(
        self,
        ocsp_responder: OCSPResponder,
        registered_token_chain,
    ):
        root, _, _ = registered_token_chain
        req = create_ocsp_request(root.token_id)
        resp = ocsp_responder.handle_request(req)
        assert resp.status == OCSPStatus.GOOD

    def test_unknown_for_unregistered_token(
        self,
        ocsp_responder: OCSPResponder,
    ):
        req = create_ocsp_request(b"\xff" * 16)
        resp = ocsp_responder.handle_request(req)
        assert resp.status == OCSPStatus.UNKNOWN

    def test_signature_present(
        self,
        ocsp_responder: OCSPResponder,
        registered_token_chain,
    ):
        root, _, _ = registered_token_chain
        req = create_ocsp_request(root.token_id)
        resp = ocsp_responder.handle_request(req)
        assert len(resp.signature) > 0

    def test_nonce_echoed(
        self,
        ocsp_responder: OCSPResponder,
        registered_token_chain,
    ):
        root, _, _ = registered_token_chain
        req = create_ocsp_request(root.token_id)
        resp = ocsp_responder.handle_request(req)
        assert resp.nonce == req.nonce

    def test_timestamps_valid(
        self,
        ocsp_responder: OCSPResponder,
        registered_token_chain,
    ):
        root, _, _ = registered_token_chain
        now = int(time.time())
        req = create_ocsp_request(root.token_id)
        resp = ocsp_responder.handle_request(req)
        assert resp.this_update >= now - 1
        assert resp.next_update > resp.this_update


# =============================================================================
# TestOCSPResponderRevokedStatus
# =============================================================================


class TestOCSPResponderRevokedStatus:
    """Tests for OCSPResponder returning REVOKED status."""

    def test_revoked_status(
        self,
        ocsp_responder: OCSPResponder,
        registered_token_chain,
        crl: CertificateRevocationList,
        issuer_did,
        issuer_secret_key,
    ):
        root, _, _ = registered_token_chain
        crl.revoke(
            root.token_id,
            RevocationReason.KEY_COMPROMISE,
            RevocationUrgency.CRITICAL,
            str(issuer_did),
            issuer_secret_key,
        )
        ocsp_responder.invalidate(root.token_id)
        req = create_ocsp_request(root.token_id)
        resp = ocsp_responder.handle_request(req)
        assert resp.status == OCSPStatus.REVOKED

    def test_includes_reason(
        self,
        ocsp_responder: OCSPResponder,
        registered_token_chain,
        crl: CertificateRevocationList,
        issuer_did,
        issuer_secret_key,
    ):
        root, _, _ = registered_token_chain
        crl.revoke(
            root.token_id,
            RevocationReason.KEY_COMPROMISE,
            RevocationUrgency.CRITICAL,
            str(issuer_did),
            issuer_secret_key,
        )
        ocsp_responder.invalidate(root.token_id)
        req = create_ocsp_request(root.token_id)
        resp = ocsp_responder.handle_request(req)
        assert resp.revocation_reason == RevocationReason.KEY_COMPROMISE

    def test_includes_time(
        self,
        ocsp_responder: OCSPResponder,
        registered_token_chain,
        crl: CertificateRevocationList,
        issuer_did,
        issuer_secret_key,
    ):
        root, _, _ = registered_token_chain
        crl.revoke(
            root.token_id,
            RevocationReason.KEY_COMPROMISE,
            RevocationUrgency.CRITICAL,
            str(issuer_did),
            issuer_secret_key,
        )
        ocsp_responder.invalidate(root.token_id)
        req = create_ocsp_request(root.token_id)
        resp = ocsp_responder.handle_request(req)
        assert resp.revocation_time is not None
        assert resp.revocation_time > 0


# =============================================================================
# TestOCSPResponderCaching
# =============================================================================


class TestOCSPResponderCaching:
    """Tests for OCSPResponder caching behavior."""

    def test_cache_hit_same_status(
        self,
        ocsp_responder: OCSPResponder,
        registered_token_chain,
    ):
        root, _, _ = registered_token_chain
        req1 = create_ocsp_request(root.token_id)
        resp1 = ocsp_responder.handle_request(req1)
        req2 = create_ocsp_request(root.token_id)
        resp2 = ocsp_responder.handle_request(req2)
        # Same status, same timestamps (from cache)
        assert resp1.status == resp2.status
        assert resp1.this_update == resp2.this_update
        # Different nonces → different signatures
        assert resp1.nonce != resp2.nonce
        assert resp1.signature != resp2.signature

    def test_invalidation(
        self,
        ocsp_responder: OCSPResponder,
        registered_token_chain,
        crl: CertificateRevocationList,
        issuer_did,
        issuer_secret_key,
    ):
        root, _, _ = registered_token_chain
        req1 = create_ocsp_request(root.token_id)
        resp1 = ocsp_responder.handle_request(req1)
        assert resp1.status == OCSPStatus.GOOD

        crl.revoke(
            root.token_id,
            RevocationReason.KEY_COMPROMISE,
            RevocationUrgency.CRITICAL,
            str(issuer_did),
            issuer_secret_key,
        )
        ocsp_responder.invalidate(root.token_id)

        req2 = create_ocsp_request(root.token_id)
        resp2 = ocsp_responder.handle_request(req2)
        assert resp2.status == OCSPStatus.REVOKED

    def test_clear_cache(
        self,
        ocsp_responder: OCSPResponder,
        registered_token_chain,
    ):
        root, _, _ = registered_token_chain
        req = create_ocsp_request(root.token_id)
        ocsp_responder.handle_request(req)
        ocsp_responder.clear_cache()
        # No error; cache was cleared
        req2 = create_ocsp_request(root.token_id)
        resp2 = ocsp_responder.handle_request(req2)
        assert resp2.status == OCSPStatus.GOOD

    def test_cleanup_expired(self, responder_did, responder_secret_key, responder_public_key, crl):
        responder = OCSPResponder(
            responder_did=str(responder_did),
            responder_secret_key=responder_secret_key,
            responder_public_key=responder_public_key,
            crl=crl,
            response_validity_seconds=1,
        )
        # Populate cache
        req = create_ocsp_request(b"\xff" * 16)
        responder.handle_request(req)
        # Wait for expiry (2s to avoid int(time.time()) rounding edge cases)
        time.sleep(2)
        removed = responder.cleanup_expired_cache()
        assert removed >= 1


# =============================================================================
# TestOCSPResponseVerification
# =============================================================================


class TestOCSPResponseVerification:
    """Tests for verify_ocsp_response() function."""

    def test_valid_response(
        self,
        ocsp_responder: OCSPResponder,
        responder_public_key,
        registered_token_chain,
    ):
        root, _, _ = registered_token_chain
        req = create_ocsp_request(root.token_id)
        resp = ocsp_responder.handle_request(req)
        status = verify_ocsp_response(resp, req, responder_public_key)
        assert status == OCSPStatus.GOOD

    def test_invalid_signature(
        self,
        ocsp_responder: OCSPResponder,
        registered_token_chain,
    ):
        root, _, _ = registered_token_chain
        req = create_ocsp_request(root.token_id)
        resp = ocsp_responder.handle_request(req)
        wrong_pub, _ = signatures.generate_keypair()
        with pytest.raises(OCSPSignatureError):
            verify_ocsp_response(resp, req, wrong_pub)

    def test_nonce_mismatch(
        self,
        ocsp_responder: OCSPResponder,
        responder_public_key,
        registered_token_chain,
    ):
        root, _, _ = registered_token_chain
        req = create_ocsp_request(root.token_id)
        resp = ocsp_responder.handle_request(req)
        fake_req = OCSPRequest(token_id=root.token_id, nonce=b"\x00" * 32)
        with pytest.raises(OCSPNonceMismatchError):
            verify_ocsp_response(resp, fake_req, responder_public_key)

    def test_expired_response(
        self,
        ocsp_responder: OCSPResponder,
        responder_public_key,
        registered_token_chain,
    ):
        root, _, _ = registered_token_chain
        req = create_ocsp_request(root.token_id)
        resp = ocsp_responder.handle_request(req)
        far_future = resp.next_update + 1
        with pytest.raises(OCSPResponseExpiredError):
            verify_ocsp_response(resp, req, responder_public_key, now=far_future)

    def test_token_id_mismatch(
        self,
        ocsp_responder: OCSPResponder,
        responder_public_key,
        registered_token_chain,
    ):
        root, _, _ = registered_token_chain
        req = create_ocsp_request(root.token_id)
        resp = ocsp_responder.handle_request(req)
        wrong_req = OCSPRequest(token_id=b"\xee" * 16, nonce=req.nonce)
        with pytest.raises(OCSPError, match="Token ID mismatch"):
            verify_ocsp_response(resp, wrong_req, responder_public_key)


# =============================================================================
# TestOCSPStapling
# =============================================================================


class TestOCSPStapling:
    """Tests for OCSP stapling functions."""

    def test_staple_creation(
        self,
        ocsp_responder: OCSPResponder,
        registered_token_chain,
    ):
        root, _, _ = registered_token_chain
        req = create_ocsp_request(root.token_id)
        resp = ocsp_responder.handle_request(req)
        stapled = staple_response(resp)
        assert isinstance(stapled, StapledOCSPResponse)
        assert stapled.response is resp
        assert len(stapled.response_cbor) > 0

    def test_verify_good(
        self,
        ocsp_responder: OCSPResponder,
        responder_public_key,
        registered_token_chain,
    ):
        root, _, _ = registered_token_chain
        req = create_ocsp_request(root.token_id)
        resp = ocsp_responder.handle_request(req)
        stapled = staple_response(resp)
        status = verify_stapled_response(stapled, responder_public_key)
        assert status == OCSPStatus.GOOD

    def test_verify_revoked(
        self,
        ocsp_responder: OCSPResponder,
        responder_public_key,
        registered_token_chain,
        crl: CertificateRevocationList,
        issuer_did,
        issuer_secret_key,
    ):
        root, _, _ = registered_token_chain
        crl.revoke(
            root.token_id,
            RevocationReason.KEY_COMPROMISE,
            RevocationUrgency.CRITICAL,
            str(issuer_did),
            issuer_secret_key,
        )
        ocsp_responder.invalidate(root.token_id)
        req = create_ocsp_request(root.token_id)
        resp = ocsp_responder.handle_request(req)
        stapled = staple_response(resp)
        status = verify_stapled_response(stapled, responder_public_key)
        assert status == OCSPStatus.REVOKED

    def test_verify_expired(
        self,
        ocsp_responder: OCSPResponder,
        responder_public_key,
        registered_token_chain,
    ):
        root, _, _ = registered_token_chain
        req = create_ocsp_request(root.token_id)
        resp = ocsp_responder.handle_request(req)
        stapled = staple_response(resp)
        with pytest.raises(OCSPResponseExpiredError):
            verify_stapled_response(
                stapled, responder_public_key, now=resp.next_update + 1
            )

    def test_bad_signature(
        self,
        ocsp_responder: OCSPResponder,
        registered_token_chain,
    ):
        root, _, _ = registered_token_chain
        req = create_ocsp_request(root.token_id)
        resp = ocsp_responder.handle_request(req)
        stapled = staple_response(resp)
        wrong_pub, _ = signatures.generate_keypair()
        with pytest.raises(OCSPSignatureError):
            verify_stapled_response(stapled, wrong_pub)


# =============================================================================
# TestOCSPFallback
# =============================================================================


class TestOCSPFallback:
    """Tests for check_token_status() OCSP-first, CRL-fallback."""

    def test_ocsp_first(
        self,
        ocsp_responder: OCSPResponder,
        responder_public_key,
        registered_token_chain,
    ):
        root, _, _ = registered_token_chain
        status = check_token_status(
            root.token_id,
            responder=ocsp_responder,
            responder_public_key=responder_public_key,
        )
        assert status == OCSPStatus.GOOD

    def test_crl_fallback(
        self,
        crl: CertificateRevocationList,
        registered_token_chain,
    ):
        root, _, _ = registered_token_chain
        status = check_token_status(root.token_id, crl=crl)
        assert status == OCSPStatus.GOOD

    def test_crl_fallback_revoked(
        self,
        crl: CertificateRevocationList,
        registered_token_chain,
        issuer_did,
        issuer_secret_key,
    ):
        root, _, _ = registered_token_chain
        crl.revoke(
            root.token_id,
            RevocationReason.KEY_COMPROMISE,
            RevocationUrgency.CRITICAL,
            str(issuer_did),
            issuer_secret_key,
        )
        status = check_token_status(root.token_id, crl=crl)
        assert status == OCSPStatus.REVOKED

    def test_neither_raises(self):
        with pytest.raises(OCSPResponderUnreachableError):
            check_token_status(b"\x01" * 16)


# =============================================================================
# TestOCSPThreadSafety
# =============================================================================


class TestOCSPThreadSafety:
    """Tests for thread safety of OCSPResponder."""

    def test_concurrent_requests(
        self,
        ocsp_responder: OCSPResponder,
        registered_token_chain,
    ):
        root, child, grandchild = registered_token_chain
        token_ids = [root.token_id, child.token_id, grandchild.token_id]
        results: list[OCSPResponse] = []
        errors: list[Exception] = []

        def query(tid):
            try:
                req = create_ocsp_request(tid)
                resp = ocsp_responder.handle_request(req)
                results.append(resp)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=query, args=(tid,)) for tid in token_ids * 3]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(results) == 9

    def test_concurrent_invalidation(
        self,
        ocsp_responder: OCSPResponder,
        registered_token_chain,
    ):
        root, _, _ = registered_token_chain
        errors: list[Exception] = []

        def query():
            try:
                for _ in range(5):
                    req = create_ocsp_request(root.token_id)
                    ocsp_responder.handle_request(req)
            except Exception as e:
                errors.append(e)

        def invalidate():
            try:
                for _ in range(5):
                    ocsp_responder.invalidate(root.token_id)
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=query),
            threading.Thread(target=query),
            threading.Thread(target=invalidate),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0


# =============================================================================
# TestOCSPExceptions
# =============================================================================


class TestOCSPExceptions:
    """Tests for OCSP exception hierarchy."""

    def test_ocsp_error_is_capability_error(self):
        assert issubclass(OCSPError, CapabilityError)

    def test_signature_error_is_ocsp_error(self):
        assert issubclass(OCSPSignatureError, OCSPError)

    def test_expired_error_is_ocsp_error(self):
        assert issubclass(OCSPResponseExpiredError, OCSPError)

    def test_nonce_mismatch_is_ocsp_error(self):
        assert issubclass(OCSPNonceMismatchError, OCSPError)

    def test_unreachable_is_ocsp_error(self):
        assert issubclass(OCSPResponderUnreachableError, OCSPError)

    def test_alert_codes(self):
        assert OCSPError.alert_code == 64
        assert OCSPSignatureError.alert_code == 65
        assert OCSPResponseExpiredError.alert_code == 66
        assert OCSPNonceMismatchError.alert_code == 67
        assert OCSPResponderUnreachableError.alert_code == 68


# =============================================================================
# TestOCSPCBOREncoding
# =============================================================================


class TestOCSPCBOREncoding:
    """Tests for OCSP CBOR encoding helpers."""

    def test_deterministic_encoding(self):
        data1 = _encode_ocsp_response_data(
            0, b"\x01" * 16, 1000, 2000, "did:qasp:test", b"\x02" * 32, None, None
        )
        data2 = _encode_ocsp_response_data(
            0, b"\x01" * 16, 1000, 2000, "did:qasp:test", b"\x02" * 32, None, None
        )
        assert data1 == data2

    def test_hex_encoding_of_binary_fields(self):
        token_id = b"\xab\xcd" * 8
        nonce = b"\xef" * 32
        data = _encode_ocsp_response_data(
            0, token_id, 1000, 2000, "did:qasp:test", nonce, None, None
        )
        decoded = cbor2.loads(data)
        assert decoded["token_id"] == token_id.hex()
        assert decoded["nonce"] == nonce.hex()

    def test_alphabetical_keys(self):
        data = _encode_ocsp_response_data(
            0, b"\x01" * 16, 1000, 2000, "did:qasp:test", b"\x02" * 32, None, None
        )
        decoded = cbor2.loads(data)
        keys = list(decoded.keys())
        assert keys == sorted(keys)

    def test_none_fields_as_null(self):
        data = _encode_ocsp_response_data(
            0, b"\x01" * 16, 1000, 2000, "did:qasp:test", b"\x02" * 32, None, None
        )
        decoded = cbor2.loads(data)
        assert decoded["revocation_reason"] is None
        assert decoded["revocation_time"] is None

    def test_revocation_fields_present_when_set(self):
        data = _encode_ocsp_response_data(
            1, b"\x01" * 16, 1000, 2000, "did:qasp:test", b"\x02" * 32, 1, 900
        )
        decoded = cbor2.loads(data)
        assert decoded["revocation_reason"] == 1
        assert decoded["revocation_time"] == 900


# =============================================================================
# TestOCSPFramingRoundTrip
# =============================================================================


class TestOCSPFramingRoundTrip:
    """Tests for OCSP message framing round-trip."""

    def test_request_message_round_trip(self):
        msg = OCSPRequestMessage(token_id=b"\x01" * 16, nonce=b"\x02" * 32)
        hmac_key = b"\x00" * 48
        frame = encode_frame(msg, hmac_key)
        decoded, consumed = decode_frame(frame, hmac_key)
        assert isinstance(decoded, OCSPRequestMessage)
        assert decoded.message_type == MessageType.OCSP_REQUEST
        assert decoded.token_id == b"\x01" * 16
        assert decoded.nonce == b"\x02" * 32
        assert consumed == len(frame)

    def test_response_message_round_trip(self):
        msg = OCSPResponseMessage(
            status=1,
            token_id=b"\x01" * 16,
            this_update=1000,
            next_update=2000,
            responder_id="did:qasp:test",
            nonce=b"\x02" * 32,
            signature=b"\x03" * 64,
            revocation_reason=1,
            revocation_time=900,
        )
        hmac_key = b"\x00" * 48
        frame = encode_frame(msg, hmac_key)
        decoded, consumed = decode_frame(frame, hmac_key)
        assert isinstance(decoded, OCSPResponseMessage)
        assert decoded.message_type == MessageType.OCSP_RESPONSE
        assert decoded.status == 1
        assert decoded.token_id == b"\x01" * 16
        assert decoded.responder_id == "did:qasp:test"
        assert decoded.revocation_reason == 1
        assert decoded.revocation_time == 900
        assert consumed == len(frame)

    def test_response_message_none_fields_round_trip(self):
        msg = OCSPResponseMessage(
            status=0,
            token_id=b"\x01" * 16,
            this_update=1000,
            next_update=2000,
            responder_id="did:qasp:test",
            nonce=b"\x02" * 32,
            signature=b"\x03" * 64,
        )
        hmac_key = b"\x00" * 48
        frame = encode_frame(msg, hmac_key)
        decoded, _ = decode_frame(frame, hmac_key)
        assert isinstance(decoded, OCSPResponseMessage)
        assert decoded.revocation_reason is None
        assert decoded.revocation_time is None


# =============================================================================
# TestOCSPConstants
# =============================================================================


class TestOCSPConstants:
    """Tests for OCSP constants."""

    def test_nonce_size(self):
        assert OCSP_NONCE_SIZE == 32

    def test_default_validity(self):
        assert DEFAULT_RESPONSE_VALIDITY_SECONDS == 600
