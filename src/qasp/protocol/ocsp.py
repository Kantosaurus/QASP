"""Online Certificate Status Protocol (OCSP) for QASP tokens.

This module provides real-time, on-demand revocation status checks
with sub-second latency. It complements the CRL's periodic batch
checking with per-token queries, and supports OCSP stapling for
offline signature verification.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING

import cbor2

from qasp.crypto.exceptions import InvalidSignatureError
from qasp.crypto.signatures import sign, verify
from qasp.protocol.capability import CapabilityError

if TYPE_CHECKING:
    from qasp.protocol.revocation import CertificateRevocationList

__all__ = [
    "DEFAULT_RESPONSE_VALIDITY_SECONDS",
    "OCSP_NONCE_SIZE",
    "OCSPError",
    "OCSPNonceMismatchError",
    "OCSPRequest",
    "OCSPResponder",
    "OCSPResponderUnreachableError",
    "OCSPResponse",
    "OCSPResponseExpiredError",
    "OCSPSignatureError",
    "OCSPStatus",
    "StapledOCSPResponse",
    "check_token_status",
    "create_ocsp_request",
    "staple_response",
    "verify_ocsp_response",
    "verify_stapled_response",
]

# =============================================================================
# Constants
# =============================================================================

OCSP_NONCE_SIZE = 32
DEFAULT_RESPONSE_VALIDITY_SECONDS = 600


# =============================================================================
# Enums
# =============================================================================


class OCSPStatus(IntEnum):
    """OCSP token status codes."""

    GOOD = 0
    REVOKED = 1
    UNKNOWN = 2


# =============================================================================
# Exceptions
# =============================================================================


class OCSPError(CapabilityError):
    """Base exception for OCSP errors."""

    alert_code: int = 64


class OCSPSignatureError(OCSPError):
    """Raised when an OCSP response signature is invalid."""

    alert_code: int = 65


class OCSPResponseExpiredError(OCSPError):
    """Raised when an OCSP response has expired."""

    alert_code: int = 66


class OCSPNonceMismatchError(OCSPError):
    """Raised when an OCSP response nonce does not match the request."""

    alert_code: int = 67


class OCSPResponderUnreachableError(OCSPError):
    """Raised when no OCSP responder or CRL fallback is available."""

    alert_code: int = 68


# =============================================================================
# Data Structures
# =============================================================================


@dataclass(frozen=True)
class OCSPRequest:
    """An OCSP status request for a token.

    Attributes:
        token_id: Identifier of the token to check.
        nonce: Random nonce for replay protection.
    """

    token_id: bytes
    nonce: bytes


@dataclass(frozen=True)
class OCSPResponse:
    """A signed OCSP status response.

    Attributes:
        status: OCSP status code.
        token_id: Identifier of the queried token.
        this_update: Unix timestamp when status was determined.
        next_update: Unix timestamp when this response expires.
        responder_id: DID of the OCSP responder.
        nonce: Echoed nonce from the request.
        signature: ML-DSA-65 signature over response data.
        revocation_reason: Revocation reason code (if revoked).
        revocation_time: Unix timestamp of revocation (if revoked).
    """

    status: OCSPStatus
    token_id: bytes
    this_update: int
    next_update: int
    responder_id: str
    nonce: bytes
    signature: bytes
    revocation_reason: int | None = None
    revocation_time: int | None = None


@dataclass(frozen=True)
class StapledOCSPResponse:
    """An OCSP response with cached CBOR data for offline verification.

    Attributes:
        response: The OCSP response.
        response_cbor: CBOR-encoded signable data for signature verification.
    """

    response: OCSPResponse
    response_cbor: bytes


# =============================================================================
# CBOR Helpers
# =============================================================================


def _encode_ocsp_response_data(
    status: int,
    token_id: bytes,
    this_update: int,
    next_update: int,
    responder_id: str,
    nonce: bytes,
    revocation_reason: int | None,
    revocation_time: int | None,
) -> bytes:
    """CBOR-encode OCSP response data for signing.

    Dict keys are in alphabetical order. Binary fields are hex-encoded.
    None fields are included as CBOR null.
    """
    data = {
        "next_update": next_update,
        "nonce": nonce.hex(),
        "responder_id": responder_id,
        "revocation_reason": revocation_reason,
        "revocation_time": revocation_time,
        "status": status,
        "this_update": this_update,
        "token_id": token_id.hex(),
    }
    return cbor2.dumps(data)


def _sign_ocsp_response(
    secret_key: bytes,
    status: int,
    token_id: bytes,
    this_update: int,
    next_update: int,
    responder_id: str,
    nonce: bytes,
    revocation_reason: int | None,
    revocation_time: int | None,
) -> bytes:
    """Sign OCSP response data with ML-DSA-65."""
    message = _encode_ocsp_response_data(
        status,
        token_id,
        this_update,
        next_update,
        responder_id,
        nonce,
        revocation_reason,
        revocation_time,
    )
    return sign(secret_key, message)


def _verify_ocsp_response_signature(
    public_key: bytes,
    response: OCSPResponse,
) -> bool:
    """Verify an OCSP response's ML-DSA-65 signature.

    Raises:
        OCSPSignatureError: If the signature is invalid.
    """
    message = _encode_ocsp_response_data(
        response.status,
        response.token_id,
        response.this_update,
        response.next_update,
        response.responder_id,
        response.nonce,
        response.revocation_reason,
        response.revocation_time,
    )
    try:
        verify(public_key, message, response.signature)
    except InvalidSignatureError as e:
        raise OCSPSignatureError(
            f"OCSP response signature verification failed: {e}"
        ) from e
    return True


# =============================================================================
# Internal Cache Type
# =============================================================================


@dataclass
class _CachedStatus:
    """Internal cache entry for status determinations."""

    status: OCSPStatus
    revocation_reason: int | None
    revocation_time: int | None
    this_update: int
    next_update: int


# =============================================================================
# OCSPResponder
# =============================================================================


class OCSPResponder:
    """Thread-safe OCSP responder with status caching.

    Caches status determinations (not signed responses) so each
    request gets a fresh signature with its unique nonce while
    avoiding repeated CRL lookups.
    """

    def __init__(
        self,
        responder_did: str,
        responder_secret_key: bytes,
        responder_public_key: bytes,
        crl: CertificateRevocationList,
        response_validity_seconds: int = DEFAULT_RESPONSE_VALIDITY_SECONDS,
    ) -> None:
        self._responder_did = responder_did
        self._secret_key = responder_secret_key
        self._public_key = responder_public_key
        self._crl = crl
        self._validity = response_validity_seconds
        self._lock = threading.Lock()
        self._cache: dict[bytes, _CachedStatus] = {}

    def handle_request(self, request: OCSPRequest) -> OCSPResponse:
        """Handle an OCSP request and return a signed response.

        Checks the cache for a valid status determination. On miss or
        expiry, queries the CRL. Always generates a fresh signature
        with the request's nonce.
        """
        with self._lock:
            cached = self._cache.get(request.token_id)
            now = int(time.time())

            if cached is None or now >= cached.next_update:
                cached = self._determine_status(request.token_id)
                self._cache[request.token_id] = cached

        signature = _sign_ocsp_response(
            self._secret_key,
            cached.status,
            request.token_id,
            cached.this_update,
            cached.next_update,
            self._responder_did,
            request.nonce,
            cached.revocation_reason,
            cached.revocation_time,
        )

        return OCSPResponse(
            status=cached.status,
            token_id=request.token_id,
            this_update=cached.this_update,
            next_update=cached.next_update,
            responder_id=self._responder_did,
            nonce=request.nonce,
            signature=signature,
            revocation_reason=cached.revocation_reason,
            revocation_time=cached.revocation_time,
        )

    def _determine_status(self, token_id: bytes) -> _CachedStatus:
        """Determine the OCSP status for a token by querying the CRL."""
        now = int(time.time())
        this_update = now
        next_update = now + self._validity

        entry = self._crl.get_entry(token_id)
        if entry is not None:
            return _CachedStatus(
                status=OCSPStatus.REVOKED,
                revocation_reason=entry.reason,
                revocation_time=entry.revocation_time,
                this_update=this_update,
                next_update=next_update,
            )

        # Token is known if it has children registered in the CRL
        if token_id in self._crl._children:
            return _CachedStatus(
                status=OCSPStatus.GOOD,
                revocation_reason=None,
                revocation_time=None,
                this_update=this_update,
                next_update=next_update,
            )

        return _CachedStatus(
            status=OCSPStatus.UNKNOWN,
            revocation_reason=None,
            revocation_time=None,
            this_update=this_update,
            next_update=next_update,
        )

    def invalidate(self, token_id: bytes) -> None:
        """Remove a cached status entry for a token."""
        with self._lock:
            self._cache.pop(token_id, None)

    def clear_cache(self) -> None:
        """Clear all cached status entries."""
        with self._lock:
            self._cache.clear()

    def cleanup_expired_cache(self) -> int:
        """Remove expired cache entries.

        Returns:
            Number of entries removed.
        """
        with self._lock:
            now = int(time.time())
            expired = [
                tid for tid, entry in self._cache.items()
                if entry.next_update < now
            ]
            for tid in expired:
                del self._cache[tid]
            return len(expired)


# =============================================================================
# Client Functions
# =============================================================================


def create_ocsp_request(token_id: bytes) -> OCSPRequest:
    """Create an OCSP request with a random nonce."""
    return OCSPRequest(
        token_id=token_id,
        nonce=os.urandom(OCSP_NONCE_SIZE),
    )


def verify_ocsp_response(
    response: OCSPResponse,
    request: OCSPRequest,
    responder_public_key: bytes,
    now: int | None = None,
) -> OCSPStatus:
    """Verify an OCSP response against its request.

    Checks token_id match, nonce match, expiry, and signature.

    Returns:
        The verified OCSP status.

    Raises:
        OCSPError: If token_id does not match.
        OCSPNonceMismatchError: If nonce does not match.
        OCSPResponseExpiredError: If response has expired.
        OCSPSignatureError: If signature is invalid.
    """
    if response.token_id != request.token_id:
        raise OCSPError(
            f"Token ID mismatch: response has {response.token_id.hex()[:16]}..., "
            f"request has {request.token_id.hex()[:16]}..."
        )

    if response.nonce != request.nonce:
        raise OCSPNonceMismatchError("Response nonce does not match request nonce")

    if now is None:
        now = int(time.time())

    if now > response.next_update:
        raise OCSPResponseExpiredError(
            f"Response expired at {response.next_update}, current time is {now}"
        )

    _verify_ocsp_response_signature(responder_public_key, response)

    return OCSPStatus(response.status)


def check_token_status(
    token_id: bytes,
    responder: OCSPResponder | None = None,
    crl: CertificateRevocationList | None = None,
    responder_public_key: bytes | None = None,
) -> OCSPStatus:
    """Check token status via OCSP (preferred) with CRL fallback.

    Tries the OCSP responder first. If unavailable, falls back to CRL.

    Returns:
        The token's OCSP status.

    Raises:
        OCSPResponderUnreachableError: If neither responder nor CRL available.
    """
    if responder is not None:
        request = create_ocsp_request(token_id)
        response = responder.handle_request(request)
        if responder_public_key is not None:
            verify_ocsp_response(response, request, responder_public_key)
        return OCSPStatus(response.status)

    if crl is not None:
        if crl.is_revoked(token_id):
            return OCSPStatus.REVOKED
        return OCSPStatus.GOOD

    raise OCSPResponderUnreachableError(
        "No OCSP responder or CRL fallback available"
    )


# =============================================================================
# Stapling Functions
# =============================================================================


def staple_response(response: OCSPResponse) -> StapledOCSPResponse:
    """Create a stapled OCSP response for offline verification.

    Stores the CBOR-encoded signable data alongside the response
    so verifiers don't need to re-encode.
    """
    response_cbor = _encode_ocsp_response_data(
        response.status,
        response.token_id,
        response.this_update,
        response.next_update,
        response.responder_id,
        response.nonce,
        response.revocation_reason,
        response.revocation_time,
    )
    return StapledOCSPResponse(response=response, response_cbor=response_cbor)


def verify_stapled_response(
    stapled: StapledOCSPResponse,
    responder_public_key: bytes,
    now: int | None = None,
) -> OCSPStatus:
    """Verify a stapled OCSP response offline.

    Checks expiry and verifies the ML-DSA-65 signature against
    the cached CBOR data.

    Returns:
        The verified OCSP status.

    Raises:
        OCSPResponseExpiredError: If the stapled response has expired.
        OCSPSignatureError: If the signature is invalid.
    """
    if now is None:
        now = int(time.time())

    if now > stapled.response.next_update:
        raise OCSPResponseExpiredError(
            f"Stapled response expired at {stapled.response.next_update}, "
            f"current time is {now}"
        )

    try:
        verify(responder_public_key, stapled.response_cbor, stapled.response.signature)
    except InvalidSignatureError as e:
        raise OCSPSignatureError(
            f"Stapled OCSP response signature verification failed: {e}"
        ) from e

    return OCSPStatus(stapled.response.status)
