"""SPIFFE identity primitives for QASP.

This module implements SPIFFE ID parsing, SVID certificate handling,
and trust bundle management for platform attestation alongside QASP's
capability authorization.

SPIFFE (Secure Production Identity Framework for Everyone) SVIDs prove
*where an agent is running*, complementing QASP tokens which prove
*what an agent is allowed to do*.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512

from qasp.identity.exceptions import (
    ExpiredSVIDError,
    InvalidSPIFFEIDError,
    SVIDVerificationError,
    TrustBundleError,
)

__all__ = [
    "SPIFFEID",
    "SVIDCertificate",
    "TrustBundle",
    "TrustBundleRegistry",
    "get_trust_bundle_registry",
    "parse_spiffe_id",
    "parse_svid_from_x509",
    "verify_svid",
    "verify_svid_with_registry",
]

# SPIFFE ID constraints per the SPIFFE specification
_MAX_TRUST_DOMAIN_LENGTH = 255
# Trust domain: lowercase alphanumeric, hyphens, dots, underscores
_TRUST_DOMAIN_PATTERN = re.compile(r"^[a-z0-9._-]+$")
# Path segments: alphanumeric, hyphens, dots, underscores
_PATH_SEGMENT_PATTERN = re.compile(r"^[a-zA-Z0-9._-]+$")


@dataclass(frozen=True)
class SPIFFEID:
    """A SPIFFE identity.

    Attributes:
        trust_domain: The trust domain (e.g., "company-x.com").
        path: The workload path (e.g., "/ns/production/agent/alpha").
    """

    trust_domain: str
    path: str

    def __str__(self) -> str:
        return f"spiffe://{self.trust_domain}{self.path}"

    @classmethod
    def parse(cls, uri: str) -> SPIFFEID:
        return parse_spiffe_id(uri)


@dataclass(frozen=True)
class SVIDCertificate:
    """A parsed SPIFFE Verifiable Identity Document (X.509 SVID).

    Attributes:
        spiffe_id: The SPIFFE ID extracted from the leaf certificate's URI SAN.
        certificate_chain: DER-encoded X.509 certificate chain (leaf first).
        leaf_not_before: Validity start of the leaf certificate.
        leaf_not_after: Validity end of the leaf certificate.
        signature_algorithm: Human-readable signature algorithm name.
        raw_leaf: DER-encoded leaf certificate bytes.
    """

    spiffe_id: SPIFFEID
    certificate_chain: tuple[bytes, ...]
    leaf_not_before: datetime
    leaf_not_after: datetime
    signature_algorithm: str
    raw_leaf: bytes


@dataclass(frozen=True)
class TrustBundle:
    """A SPIFFE trust bundle for a trust domain.

    Attributes:
        trust_domain: The trust domain this bundle authenticates.
        root_certificates: DER-encoded root CA certificates.
        sequence_number: Monotonically increasing version for bundle updates.
    """

    trust_domain: str
    root_certificates: tuple[bytes, ...]
    sequence_number: int


class TrustBundleRegistry:
    """Thread-safe registry for SPIFFE trust bundles.

    Follows the same Lock pattern as DIDRegistry.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._bundles: dict[str, TrustBundle] = {}

    def register_bundle(self, bundle: TrustBundle) -> None:
        """Register or update a trust bundle.

        Updates are only accepted if the new bundle has a higher or equal
        sequence number than the existing one.

        Raises:
            TrustBundleError: If the new bundle has a lower sequence number.
        """
        with self._lock:
            existing = self._bundles.get(bundle.trust_domain)
            if existing is not None and bundle.sequence_number < existing.sequence_number:
                raise TrustBundleError(
                    f"Cannot downgrade trust bundle for {bundle.trust_domain}: "
                    f"existing sequence {existing.sequence_number}, "
                    f"new sequence {bundle.sequence_number}"
                )
            self._bundles[bundle.trust_domain] = bundle

    def lookup_bundle(self, trust_domain: str) -> TrustBundle:
        """Look up a trust bundle by trust domain.

        Raises:
            TrustBundleError: If the trust domain is not registered.
        """
        with self._lock:
            bundle = self._bundles.get(trust_domain)
        if bundle is None:
            raise TrustBundleError(f"No trust bundle for domain: {trust_domain}")
        return bundle

    def remove_bundle(self, trust_domain: str) -> bool:
        """Remove a trust bundle. Returns True if it was present."""
        with self._lock:
            if trust_domain in self._bundles:
                del self._bundles[trust_domain]
                return True
            return False

    def clear(self) -> None:
        """Remove all trust bundles."""
        with self._lock:
            self._bundles.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._bundles)

    def __contains__(self, trust_domain: str) -> bool:
        with self._lock:
            return trust_domain in self._bundles


# Module-level singleton
_trust_bundle_registry: TrustBundleRegistry | None = None
_trust_bundle_registry_lock = threading.Lock()


def get_trust_bundle_registry() -> TrustBundleRegistry:
    """Get the module-level TrustBundleRegistry singleton."""
    global _trust_bundle_registry
    if _trust_bundle_registry is None:
        with _trust_bundle_registry_lock:
            if _trust_bundle_registry is None:
                _trust_bundle_registry = TrustBundleRegistry()
    return _trust_bundle_registry


def parse_spiffe_id(uri: str) -> SPIFFEID:
    """Parse a SPIFFE ID URI.

    Validates format per the SPIFFE specification:
    - Must start with "spiffe://"
    - Trust domain <= 255 chars, lowercase alphanumeric/hyphens/dots/underscores
    - Path segments use alphanumeric/hyphens/dots/underscores

    Args:
        uri: The SPIFFE ID URI string (e.g., "spiffe://example.com/workload").

    Returns:
        A SPIFFEID instance.

    Raises:
        InvalidSPIFFEIDError: If the URI is malformed.
    """
    if not uri.startswith("spiffe://"):
        raise InvalidSPIFFEIDError(
            f"Invalid SPIFFE ID scheme: expected 'spiffe://', got '{uri}'"
        )

    remainder = uri[len("spiffe://"):]
    if not remainder:
        raise InvalidSPIFFEIDError("Empty trust domain in SPIFFE ID")

    # Split trust domain from path
    slash_idx = remainder.find("/")
    if slash_idx == -1:
        trust_domain = remainder
        path = ""
    else:
        trust_domain = remainder[:slash_idx]
        path = remainder[slash_idx:]

    if not trust_domain:
        raise InvalidSPIFFEIDError("Empty trust domain in SPIFFE ID")

    if len(trust_domain) > _MAX_TRUST_DOMAIN_LENGTH:
        raise InvalidSPIFFEIDError(
            f"Trust domain exceeds {_MAX_TRUST_DOMAIN_LENGTH} characters: "
            f"got {len(trust_domain)}"
        )

    if not _TRUST_DOMAIN_PATTERN.match(trust_domain):
        raise InvalidSPIFFEIDError(
            f"Invalid trust domain characters: '{trust_domain}'"
        )

    # Validate path segments
    if path:
        segments = path.split("/")[1:]  # skip leading empty from "/"
        for segment in segments:
            if not segment:
                raise InvalidSPIFFEIDError(
                    f"Empty path segment in SPIFFE ID: '{uri}'"
                )
            if not _PATH_SEGMENT_PATTERN.match(segment):
                raise InvalidSPIFFEIDError(
                    f"Invalid path segment characters: '{segment}'"
                )

    return SPIFFEID(trust_domain=trust_domain, path=path)


def _get_signature_algorithm_name(cert: x509.Certificate) -> str:
    """Extract a human-readable signature algorithm name from a certificate."""
    oid = cert.signature_algorithm_oid
    # Common OID mappings
    oid_map = {
        "1.2.840.10045.4.3.2": "ecdsa-sha256",
        "1.2.840.10045.4.3.3": "ecdsa-sha384",
        "1.2.840.10045.4.3.4": "ecdsa-sha512",
        "1.2.840.113549.1.1.11": "rsa-sha256",
        "1.2.840.113549.1.1.12": "rsa-sha384",
        "1.2.840.113549.1.1.13": "rsa-sha512",
    }
    return oid_map.get(oid.dotted_string, oid.dotted_string)


def parse_svid_from_x509(cert_chain_der: list[bytes]) -> SVIDCertificate:
    """Parse an X.509 SVID from a DER-encoded certificate chain.

    The leaf certificate (first in chain) must contain a SPIFFE ID
    in a URI Subject Alternative Name.

    Args:
        cert_chain_der: List of DER-encoded certificates (leaf first).

    Returns:
        An SVIDCertificate instance.

    Raises:
        SVIDVerificationError: If parsing fails or no SPIFFE URI SAN is found.
    """
    if not cert_chain_der:
        raise SVIDVerificationError("Empty certificate chain")

    try:
        leaf = x509.load_der_x509_certificate(cert_chain_der[0])
    except Exception as e:
        raise SVIDVerificationError(f"Failed to parse leaf certificate: {e}") from e

    # Extract SPIFFE ID from URI SAN
    spiffe_id = _extract_spiffe_id_from_cert(leaf)

    sig_alg = _get_signature_algorithm_name(leaf)

    not_before = leaf.not_valid_before_utc
    not_after = leaf.not_valid_after_utc

    return SVIDCertificate(
        spiffe_id=spiffe_id,
        certificate_chain=tuple(cert_chain_der),
        leaf_not_before=not_before,
        leaf_not_after=not_after,
        signature_algorithm=sig_alg,
        raw_leaf=cert_chain_der[0],
    )


def _extract_spiffe_id_from_cert(cert: x509.Certificate) -> SPIFFEID:
    """Extract SPIFFE ID from a certificate's URI SAN extension."""
    try:
        san_ext = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
    except x509.ExtensionNotFound as e:
        raise SVIDVerificationError(
            "Certificate has no SubjectAlternativeName extension"
        ) from e

    uri_sans = san_ext.value.get_values_for_type(x509.UniformResourceIdentifier)
    if not uri_sans:
        raise SVIDVerificationError(
            "Certificate has no URI Subject Alternative Names"
        )

    # Find the first spiffe:// URI
    for uri in uri_sans:
        if uri.startswith("spiffe://"):
            try:
                return parse_spiffe_id(uri)
            except InvalidSPIFFEIDError as e:
                raise SVIDVerificationError(
                    f"Certificate contains invalid SPIFFE ID: {e}"
                ) from e

    raise SVIDVerificationError(
        "Certificate has no SPIFFE URI in Subject Alternative Names"
    )


def verify_svid(
    svid: SVIDCertificate,
    bundle: TrustBundle,
    now: datetime | None = None,
) -> bool:
    """Verify an SVID against a trust bundle.

    Checks:
    1. Trust domain matches between SVID and bundle
    2. Leaf certificate is within validity period
    3. Certificate chain is signed by a root in the trust bundle

    Args:
        svid: The SVID to verify.
        bundle: The trust bundle containing trusted root CAs.
        now: Current time for validity check (defaults to UTC now).

    Returns:
        True if verification succeeds.

    Raises:
        SVIDVerificationError: If trust domain mismatch or chain verification fails.
        ExpiredSVIDError: If the SVID has expired or is not yet valid.
    """
    if now is None:
        now = datetime.now(UTC)

    # Check trust domain match
    if svid.spiffe_id.trust_domain != bundle.trust_domain:
        raise SVIDVerificationError(
            f"Trust domain mismatch: SVID has '{svid.spiffe_id.trust_domain}', "
            f"bundle has '{bundle.trust_domain}'"
        )

    # Check temporal validity
    if now < svid.leaf_not_before:
        raise ExpiredSVIDError(
            f"SVID not yet valid: not_before={svid.leaf_not_before}, now={now}"
        )
    if now > svid.leaf_not_after:
        raise ExpiredSVIDError(
            f"SVID expired: not_after={svid.leaf_not_after}, now={now}"
        )

    # Verify certificate chain against trust bundle roots
    _verify_chain_against_bundle(svid, bundle)

    return True


def _verify_chain_against_bundle(
    svid: SVIDCertificate, bundle: TrustBundle
) -> None:
    """Verify the SVID certificate chain against trust bundle root CAs.

    For a single-cert chain (self-signed or leaf-only), verifies the leaf
    is signed by a trusted root. For multi-cert chains, verifies each cert
    is signed by the next, and the last is signed by a trusted root.

    Raises:
        SVIDVerificationError: If chain verification fails.
    """
    # Parse all certs in the chain
    chain_certs: list[x509.Certificate] = []
    for i, der_bytes in enumerate(svid.certificate_chain):
        try:
            chain_certs.append(x509.load_der_x509_certificate(der_bytes))
        except Exception as e:
            raise SVIDVerificationError(
                f"Failed to parse certificate at index {i}: {e}"
            ) from e

    # Parse root certificates from bundle
    root_certs: list[x509.Certificate] = []
    for i, der_bytes in enumerate(bundle.root_certificates):
        try:
            root_certs.append(x509.load_der_x509_certificate(der_bytes))
        except Exception as e:
            raise SVIDVerificationError(
                f"Failed to parse root certificate at index {i}: {e}"
            ) from e

    if not root_certs:
        raise SVIDVerificationError("Trust bundle has no root certificates")

    # Verify chain linkage: each cert should be signed by the next
    for i in range(len(chain_certs) - 1):
        _verify_cert_signature(chain_certs[i], chain_certs[i + 1])

    # The last cert in the chain (or the only cert) must be signed by a root
    last_cert = chain_certs[-1]
    for root in root_certs:
        try:
            _verify_cert_signature(last_cert, root)
            return  # Success
        except SVIDVerificationError:
            continue

    raise SVIDVerificationError(
        "Certificate chain not signed by any trusted root CA"
    )


def _verify_cert_signature(
    cert: x509.Certificate, issuer: x509.Certificate
) -> None:
    """Verify that cert was signed by issuer's public key.

    Raises:
        SVIDVerificationError: If signature verification fails.
    """
    issuer_public_key = issuer.public_key()
    try:
        if isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
            issuer_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(_get_hash_for_cert(cert)),
            )
        elif isinstance(issuer_public_key, rsa.RSAPublicKey):
            issuer_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                _get_hash_for_cert(cert),
            )
        else:
            raise SVIDVerificationError(
                f"Unsupported issuer key type: {type(issuer_public_key)}"
            )
    except InvalidSignature as e:
        raise SVIDVerificationError(
            "Certificate signature verification failed"
        ) from e


def _get_hash_for_cert(cert: x509.Certificate) -> SHA256 | SHA384 | SHA512:
    """Get the hash algorithm used by a certificate's signature."""
    alg_name = _get_signature_algorithm_name(cert)
    if "sha384" in alg_name:
        return SHA384()
    if "sha512" in alg_name:
        return SHA512()
    return SHA256()


def verify_svid_with_registry(
    svid: SVIDCertificate,
    registry: TrustBundleRegistry | None = None,
    now: datetime | None = None,
) -> bool:
    """Verify an SVID using a trust bundle registry.

    Convenience wrapper that looks up the trust bundle for the SVID's
    trust domain from the registry.

    Args:
        svid: The SVID to verify.
        registry: The registry to use (defaults to module singleton).
        now: Current time for validity check.

    Returns:
        True if verification succeeds.

    Raises:
        TrustBundleError: If no bundle exists for the trust domain.
        SVIDVerificationError: If verification fails.
        ExpiredSVIDError: If the SVID has expired.
    """
    if registry is None:
        registry = get_trust_bundle_registry()
    bundle = registry.lookup_bundle(svid.spiffe_id.trust_domain)
    return verify_svid(svid, bundle, now=now)
