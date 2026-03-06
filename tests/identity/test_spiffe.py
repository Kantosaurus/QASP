"""Tests for SPIFFE identity primitives."""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from qasp.identity.exceptions import (
    ExpiredSVIDError,
    InvalidSPIFFEIDError,
    SVIDVerificationError,
    TrustBundleError,
)
from qasp.identity.spiffe import (
    SPIFFEID,
    SVIDCertificate,
    TrustBundle,
    TrustBundleRegistry,
    get_trust_bundle_registry,
    parse_spiffe_id,
    parse_svid_from_x509,
    verify_svid,
    verify_svid_with_registry,
)


# =============================================================================
# Test Certificate Helpers
# =============================================================================


def _generate_ca_keypair():
    """Generate an EC P-256 CA keypair and self-signed certificate."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test SPIFFE CA"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _generate_svid_cert(
    ca_key,
    ca_cert,
    spiffe_uri: str,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
):
    """Generate an SVID leaf certificate signed by the CA."""
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    if not_before is None:
        not_before = datetime.now(UTC) - timedelta(hours=1)
    if not_after is None:
        not_after = datetime.now(UTC) + timedelta(hours=23)

    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "SVID Workload"),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier(spiffe_uri),
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return leaf_key, cert


def _cert_to_der(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


# =============================================================================
# TestSPIFFEIDParsing
# =============================================================================


class TestSPIFFEIDParsing:
    def test_valid_simple(self):
        sid = parse_spiffe_id("spiffe://example.com/workload")
        assert sid.trust_domain == "example.com"
        assert sid.path == "/workload"

    def test_valid_nested_path(self):
        sid = parse_spiffe_id("spiffe://company-x.com/ns/production/agent/alpha")
        assert sid.trust_domain == "company-x.com"
        assert sid.path == "/ns/production/agent/alpha"

    def test_minimal_no_path(self):
        sid = parse_spiffe_id("spiffe://example.com")
        assert sid.trust_domain == "example.com"
        assert sid.path == ""

    def test_invalid_scheme(self):
        with pytest.raises(InvalidSPIFFEIDError, match="scheme"):
            parse_spiffe_id("https://example.com/workload")

    def test_empty_trust_domain(self):
        with pytest.raises(InvalidSPIFFEIDError, match="Empty trust domain"):
            parse_spiffe_id("spiffe:///workload")

    def test_trust_domain_too_long(self):
        long_domain = "a" * 256
        with pytest.raises(InvalidSPIFFEIDError, match="exceeds"):
            parse_spiffe_id(f"spiffe://{long_domain}/workload")

    def test_trust_domain_max_length_ok(self):
        domain = "a" * 255
        sid = parse_spiffe_id(f"spiffe://{domain}/workload")
        assert sid.trust_domain == domain

    def test_invalid_trust_domain_chars(self):
        with pytest.raises(InvalidSPIFFEIDError, match="Invalid trust domain"):
            parse_spiffe_id("spiffe://UPPER.com/workload")

    def test_invalid_path_chars(self):
        with pytest.raises(InvalidSPIFFEIDError, match="Invalid path segment"):
            parse_spiffe_id("spiffe://example.com/work load")

    def test_empty_path_segment(self):
        with pytest.raises(InvalidSPIFFEIDError, match="Empty path segment"):
            parse_spiffe_id("spiffe://example.com/a//b")

    def test_str_roundtrip(self):
        uri = "spiffe://example.com/ns/prod/agent"
        sid = parse_spiffe_id(uri)
        assert str(sid) == uri

    def test_str_roundtrip_no_path(self):
        sid = parse_spiffe_id("spiffe://example.com")
        assert str(sid) == "spiffe://example.com"

    def test_equality_and_hashing(self):
        a = parse_spiffe_id("spiffe://example.com/a")
        b = parse_spiffe_id("spiffe://example.com/a")
        c = parse_spiffe_id("spiffe://example.com/b")
        assert a == b
        assert a != c
        assert hash(a) == hash(b)
        assert {a, b, c} == {a, c}

    def test_classmethod_parse(self):
        sid = SPIFFEID.parse("spiffe://example.com/foo")
        assert sid.trust_domain == "example.com"
        assert sid.path == "/foo"


# =============================================================================
# TestTrustBundleRegistry
# =============================================================================


class TestTrustBundleRegistry:
    def test_register_and_lookup(self):
        registry = TrustBundleRegistry()
        bundle = TrustBundle(
            trust_domain="example.com",
            root_certificates=(b"cert1",),
            sequence_number=1,
        )
        registry.register_bundle(bundle)
        result = registry.lookup_bundle("example.com")
        assert result is bundle

    def test_lookup_missing_raises(self):
        registry = TrustBundleRegistry()
        with pytest.raises(TrustBundleError, match="No trust bundle"):
            registry.lookup_bundle("missing.com")

    def test_remove(self):
        registry = TrustBundleRegistry()
        bundle = TrustBundle("example.com", (b"cert",), 1)
        registry.register_bundle(bundle)
        assert registry.remove_bundle("example.com") is True
        assert registry.remove_bundle("example.com") is False

    def test_clear(self):
        registry = TrustBundleRegistry()
        registry.register_bundle(TrustBundle("a.com", (b"c",), 1))
        registry.register_bundle(TrustBundle("b.com", (b"c",), 1))
        assert len(registry) == 2
        registry.clear()
        assert len(registry) == 0

    def test_contains(self):
        registry = TrustBundleRegistry()
        registry.register_bundle(TrustBundle("a.com", (b"c",), 1))
        assert "a.com" in registry
        assert "b.com" not in registry

    def test_update_with_higher_sequence(self):
        registry = TrustBundleRegistry()
        registry.register_bundle(TrustBundle("a.com", (b"old",), 1))
        registry.register_bundle(TrustBundle("a.com", (b"new",), 2))
        result = registry.lookup_bundle("a.com")
        assert result.root_certificates == (b"new",)
        assert result.sequence_number == 2

    def test_update_with_equal_sequence(self):
        registry = TrustBundleRegistry()
        registry.register_bundle(TrustBundle("a.com", (b"old",), 1))
        registry.register_bundle(TrustBundle("a.com", (b"new",), 1))
        result = registry.lookup_bundle("a.com")
        assert result.root_certificates == (b"new",)

    def test_downgrade_rejected(self):
        registry = TrustBundleRegistry()
        registry.register_bundle(TrustBundle("a.com", (b"v2",), 2))
        with pytest.raises(TrustBundleError, match="downgrade"):
            registry.register_bundle(TrustBundle("a.com", (b"v1",), 1))

    def test_thread_safety(self):
        registry = TrustBundleRegistry()
        errors = []

        def register_bundles(start: int):
            try:
                for i in range(start, start + 50):
                    domain = f"domain-{i}.com"
                    registry.register_bundle(TrustBundle(domain, (b"c",), 1))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=register_bundles, args=(i * 50,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(registry) == 200

    def test_singleton(self):
        r1 = get_trust_bundle_registry()
        r2 = get_trust_bundle_registry()
        assert r1 is r2


# =============================================================================
# TestSVIDParsing
# =============================================================================


class TestSVIDParsing:
    def test_parse_ecdsa_cert_with_spiffe_san(self):
        ca_key, ca_cert = _generate_ca_keypair()
        _, leaf_cert = _generate_svid_cert(
            ca_key, ca_cert, "spiffe://example.com/workload/alpha"
        )
        chain = [_cert_to_der(leaf_cert), _cert_to_der(ca_cert)]
        svid = parse_svid_from_x509(chain)

        assert svid.spiffe_id.trust_domain == "example.com"
        assert svid.spiffe_id.path == "/workload/alpha"
        assert svid.signature_algorithm == "ecdsa-sha256"
        assert len(svid.certificate_chain) == 2
        assert svid.raw_leaf == chain[0]

    def test_empty_chain_raises(self):
        with pytest.raises(SVIDVerificationError, match="Empty certificate chain"):
            parse_svid_from_x509([])

    def test_no_san_raises(self):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "No SAN"),
            ]))
            .issuer_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "No SAN"),
            ]))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC) - timedelta(hours=1))
            .not_valid_after(datetime.now(UTC) + timedelta(hours=23))
            .sign(key, hashes.SHA256())
        )
        with pytest.raises(SVIDVerificationError, match="SubjectAlternativeName"):
            parse_svid_from_x509([_cert_to_der(cert)])

    def test_non_spiffe_uri_raises(self):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "Non-SPIFFE"),
            ]))
            .issuer_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "Non-SPIFFE"),
            ]))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC) - timedelta(hours=1))
            .not_valid_after(datetime.now(UTC) + timedelta(hours=23))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.UniformResourceIdentifier("https://example.com"),
                ]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        with pytest.raises(SVIDVerificationError, match="no SPIFFE URI"):
            parse_svid_from_x509([_cert_to_der(cert)])

    def test_extract_spiffe_id_from_leaf(self):
        ca_key, ca_cert = _generate_ca_keypair()
        _, leaf_cert = _generate_svid_cert(
            ca_key, ca_cert, "spiffe://prod.example.com/ns/default/sa/web"
        )
        svid = parse_svid_from_x509([_cert_to_der(leaf_cert)])
        assert str(svid.spiffe_id) == "spiffe://prod.example.com/ns/default/sa/web"


# =============================================================================
# TestSVIDVerification
# =============================================================================


class TestSVIDVerification:
    def test_valid_svid_against_bundle(self):
        ca_key, ca_cert = _generate_ca_keypair()
        _, leaf_cert = _generate_svid_cert(
            ca_key, ca_cert, "spiffe://example.com/workload"
        )
        chain = [_cert_to_der(leaf_cert), _cert_to_der(ca_cert)]
        svid = parse_svid_from_x509(chain)
        bundle = TrustBundle(
            trust_domain="example.com",
            root_certificates=(_cert_to_der(ca_cert),),
            sequence_number=1,
        )
        assert verify_svid(svid, bundle) is True

    def test_expired_svid_raises(self):
        ca_key, ca_cert = _generate_ca_keypair()
        _, leaf_cert = _generate_svid_cert(
            ca_key,
            ca_cert,
            "spiffe://example.com/workload",
            not_before=datetime.now(UTC) - timedelta(days=10),
            not_after=datetime.now(UTC) - timedelta(days=1),
        )
        chain = [_cert_to_der(leaf_cert), _cert_to_der(ca_cert)]
        svid = parse_svid_from_x509(chain)
        bundle = TrustBundle("example.com", (_cert_to_der(ca_cert),), 1)

        with pytest.raises(ExpiredSVIDError, match="expired"):
            verify_svid(svid, bundle)

    def test_not_yet_valid_svid_raises(self):
        ca_key, ca_cert = _generate_ca_keypair()
        _, leaf_cert = _generate_svid_cert(
            ca_key,
            ca_cert,
            "spiffe://example.com/workload",
            not_before=datetime.now(UTC) + timedelta(days=1),
            not_after=datetime.now(UTC) + timedelta(days=10),
        )
        chain = [_cert_to_der(leaf_cert), _cert_to_der(ca_cert)]
        svid = parse_svid_from_x509(chain)
        bundle = TrustBundle("example.com", (_cert_to_der(ca_cert),), 1)

        with pytest.raises(ExpiredSVIDError, match="not yet valid"):
            verify_svid(svid, bundle)

    def test_wrong_trust_domain_raises(self):
        ca_key, ca_cert = _generate_ca_keypair()
        _, leaf_cert = _generate_svid_cert(
            ca_key, ca_cert, "spiffe://example.com/workload"
        )
        chain = [_cert_to_der(leaf_cert), _cert_to_der(ca_cert)]
        svid = parse_svid_from_x509(chain)
        bundle = TrustBundle("other-domain.com", (_cert_to_der(ca_cert),), 1)

        with pytest.raises(SVIDVerificationError, match="Trust domain mismatch"):
            verify_svid(svid, bundle)

    def test_untrusted_ca_raises(self):
        ca_key, ca_cert = _generate_ca_keypair()
        other_ca_key, other_ca_cert = _generate_ca_keypair()
        _, leaf_cert = _generate_svid_cert(
            ca_key, ca_cert, "spiffe://example.com/workload"
        )
        chain = [_cert_to_der(leaf_cert), _cert_to_der(ca_cert)]
        svid = parse_svid_from_x509(chain)
        # Bundle uses a different CA
        bundle = TrustBundle("example.com", (_cert_to_der(other_ca_cert),), 1)

        with pytest.raises(SVIDVerificationError, match="not signed by any trusted root"):
            verify_svid(svid, bundle)

    def test_verify_with_registry(self):
        ca_key, ca_cert = _generate_ca_keypair()
        _, leaf_cert = _generate_svid_cert(
            ca_key, ca_cert, "spiffe://example.com/workload"
        )
        chain = [_cert_to_der(leaf_cert), _cert_to_der(ca_cert)]
        svid = parse_svid_from_x509(chain)

        registry = TrustBundleRegistry()
        registry.register_bundle(
            TrustBundle("example.com", (_cert_to_der(ca_cert),), 1)
        )

        assert verify_svid_with_registry(svid, registry=registry) is True

    def test_verify_with_registry_missing_bundle(self):
        ca_key, ca_cert = _generate_ca_keypair()
        _, leaf_cert = _generate_svid_cert(
            ca_key, ca_cert, "spiffe://missing.com/workload"
        )
        chain = [_cert_to_der(leaf_cert)]
        svid = parse_svid_from_x509(chain)

        registry = TrustBundleRegistry()
        with pytest.raises(TrustBundleError, match="No trust bundle"):
            verify_svid_with_registry(svid, registry=registry)

    def test_verify_with_explicit_now(self):
        ca_key, ca_cert = _generate_ca_keypair()
        not_before = datetime(2025, 1, 1, tzinfo=UTC)
        not_after = datetime(2025, 12, 31, tzinfo=UTC)
        _, leaf_cert = _generate_svid_cert(
            ca_key, ca_cert, "spiffe://example.com/workload",
            not_before=not_before, not_after=not_after,
        )
        chain = [_cert_to_der(leaf_cert), _cert_to_der(ca_cert)]
        svid = parse_svid_from_x509(chain)
        bundle = TrustBundle("example.com", (_cert_to_der(ca_cert),), 1)

        mid = datetime(2025, 6, 15, tzinfo=UTC)
        assert verify_svid(svid, bundle, now=mid) is True

        past = datetime(2024, 6, 15, tzinfo=UTC)
        with pytest.raises(ExpiredSVIDError):
            verify_svid(svid, bundle, now=past)
