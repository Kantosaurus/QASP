"""Tests for SPIFFE platform attestation protocol integration."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from qasp.crypto import signatures
from qasp.identity import DID, create_did
from qasp.identity.spiffe import (
    SPIFFEID,
    SVIDCertificate,
    TrustBundle,
    TrustBundleRegistry,
    parse_spiffe_id,
    parse_svid_from_x509,
)
from qasp.protocol.capability import (
    AuthorityChainEntry,
    MultiOwnerCapabilityToken,
    create_multi_owner_token,
    create_token,
)
from qasp.protocol.spiffe_attestation import (
    ATTESTATION_NONCE_SIZE,
    AttestationExpiredError,
    CompositeMultiOwnerToken,
    InvalidAttestationError,
    PlatformAttestationEntry,
    SPIFFEAttestationError,
    attestation_from_cbor,
    attestation_to_cbor,
    composite_token_from_cbor,
    composite_token_to_cbor,
    create_composite_token,
    create_platform_attestation,
    verify_composite_token,
)


# =============================================================================
# Test Certificate Helpers
# =============================================================================


def _generate_ca_keypair():
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


def _generate_svid_cert(ca_key, ca_cert, spiffe_uri, not_before=None, not_after=None):
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


def _make_svid_and_bundle(
    trust_domain: str = "example.com",
    path: str = "/workload",
    not_before: datetime | None = None,
    not_after: datetime | None = None,
):
    """Create a valid SVID and matching trust bundle."""
    ca_key, ca_cert = _generate_ca_keypair()
    uri = f"spiffe://{trust_domain}{path}"
    _, leaf_cert = _generate_svid_cert(
        ca_key, ca_cert, uri, not_before=not_before, not_after=not_after
    )
    chain = [_cert_to_der(leaf_cert), _cert_to_der(ca_cert)]
    svid = parse_svid_from_x509(chain)
    bundle = TrustBundle(trust_domain, (_cert_to_der(ca_cert),), 1)
    return svid, bundle


def _make_multi_owner_token():
    """Create a minimal valid MultiOwnerCapabilityToken for testing."""
    pub, sec = signatures.generate_keypair()
    did, _ = create_did(pub)
    sub_pub, _ = signatures.generate_keypair()
    sub_did, _ = create_did(sub_pub)

    token = create_token(
        issuer_did=did,
        issuer_secret_key=sec,
        subject_did=sub_did,
        resource_uri="qasp://test/resource",
        verbs={"read", "write"},
    )
    entry = AuthorityChainEntry(chain=(token,), root_public_key=pub)
    return create_multi_owner_token([entry])


# =============================================================================
# TestPlatformAttestationEntry
# =============================================================================


class TestPlatformAttestationEntry:
    def test_creation(self):
        svid, _ = _make_svid_and_bundle()
        now = datetime.now(UTC)
        nonce = os.urandom(ATTESTATION_NONCE_SIZE)
        entry = PlatformAttestationEntry(
            role="platform",
            spiffe_id=svid.spiffe_id,
            svid=svid,
            attested_at=now,
            attestation_nonce=nonce,
        )
        assert entry.role == "platform"
        assert entry.spiffe_id == svid.spiffe_id
        assert entry.attested_at == now
        assert len(entry.attestation_nonce) == ATTESTATION_NONCE_SIZE

    def test_frozen(self):
        svid, _ = _make_svid_and_bundle()
        entry = PlatformAttestationEntry(
            role="platform",
            spiffe_id=svid.spiffe_id,
            svid=svid,
            attested_at=datetime.now(UTC),
            attestation_nonce=os.urandom(ATTESTATION_NONCE_SIZE),
        )
        with pytest.raises(AttributeError):
            entry.role = "other"  # type: ignore[misc]

    def test_create_platform_attestation_helper(self):
        svid, _ = _make_svid_and_bundle()
        entry = create_platform_attestation(svid.spiffe_id, svid)
        assert entry.role == "platform"
        assert len(entry.attestation_nonce) == ATTESTATION_NONCE_SIZE


# =============================================================================
# TestCompositeMultiOwnerToken
# =============================================================================


class TestCompositeMultiOwnerToken:
    def test_zero_attestations_backward_compat(self):
        mot = _make_multi_owner_token()
        composite = create_composite_token(mot)
        assert composite.platform_attestations == ()
        assert composite.composition == "all"

    def test_one_attestation(self):
        mot = _make_multi_owner_token()
        svid, _ = _make_svid_and_bundle()
        attestation = create_platform_attestation(svid.spiffe_id, svid)
        composite = create_composite_token(mot, [attestation])
        assert len(composite.platform_attestations) == 1

    def test_delegates_verbs(self):
        mot = _make_multi_owner_token()
        composite = create_composite_token(mot)
        assert composite.effective_verbs() == mot.effective_verbs()

    def test_delegates_constraints(self):
        mot = _make_multi_owner_token()
        composite = create_composite_token(mot)
        assert composite.effective_constraints() == mot.effective_constraints()

    def test_composition_default(self):
        mot = _make_multi_owner_token()
        composite = create_composite_token(mot)
        assert composite.composition == "all"


# =============================================================================
# TestVerifyCompositeToken
# =============================================================================


class TestVerifyCompositeToken:
    def test_valid_chain_and_attestation(self):
        mot = _make_multi_owner_token()
        svid, bundle = _make_svid_and_bundle()
        attestation = create_platform_attestation(svid.spiffe_id, svid)
        composite = create_composite_token(mot, [attestation])

        registry = TrustBundleRegistry()
        registry.register_bundle(bundle)

        assert verify_composite_token(
            composite,
            trust_bundle_registry=registry,
            check_expiry=False,  # skip ML-DSA token expiry for this test
        ) is True

    def test_no_attestations_passes(self):
        mot = _make_multi_owner_token()
        composite = create_composite_token(mot)
        assert verify_composite_token(composite, check_expiry=False) is True

    def test_expired_attestation_fails(self):
        mot = _make_multi_owner_token()
        svid, bundle = _make_svid_and_bundle(
            not_before=datetime.now(UTC) - timedelta(days=10),
            not_after=datetime.now(UTC) - timedelta(days=1),
        )
        attestation = create_platform_attestation(svid.spiffe_id, svid)
        composite = create_composite_token(mot, [attestation])

        registry = TrustBundleRegistry()
        registry.register_bundle(bundle)

        with pytest.raises(AttestationExpiredError):
            verify_composite_token(
                composite,
                trust_bundle_registry=registry,
                check_expiry=False,
            )

    def test_invalid_svid_fails(self):
        mot = _make_multi_owner_token()
        svid, _ = _make_svid_and_bundle()
        attestation = create_platform_attestation(svid.spiffe_id, svid)
        composite = create_composite_token(mot, [attestation])

        # Registry with no bundle for this domain
        registry = TrustBundleRegistry()

        with pytest.raises(SPIFFEAttestationError):
            verify_composite_token(
                composite,
                trust_bundle_registry=registry,
                check_expiry=False,
            )

    def test_invalid_role_fails(self):
        mot = _make_multi_owner_token()
        svid, bundle = _make_svid_and_bundle()
        # Create attestation with wrong role
        bad_attestation = PlatformAttestationEntry(
            role="admin",
            spiffe_id=svid.spiffe_id,
            svid=svid,
            attested_at=datetime.now(UTC),
            attestation_nonce=os.urandom(ATTESTATION_NONCE_SIZE),
        )
        composite = create_composite_token(mot, [bad_attestation])

        registry = TrustBundleRegistry()
        registry.register_bundle(bundle)

        with pytest.raises(InvalidAttestationError, match="role"):
            verify_composite_token(
                composite,
                trust_bundle_registry=registry,
                check_expiry=False,
            )

    def test_invalid_nonce_size_fails(self):
        mot = _make_multi_owner_token()
        svid, bundle = _make_svid_and_bundle()
        bad_attestation = PlatformAttestationEntry(
            role="platform",
            spiffe_id=svid.spiffe_id,
            svid=svid,
            attested_at=datetime.now(UTC),
            attestation_nonce=b"\x00" * 8,  # wrong size
        )
        composite = create_composite_token(mot, [bad_attestation])

        registry = TrustBundleRegistry()
        registry.register_bundle(bundle)

        with pytest.raises(InvalidAttestationError, match="nonce size"):
            verify_composite_token(
                composite,
                trust_bundle_registry=registry,
                check_expiry=False,
            )


# =============================================================================
# TestCBORSerialization
# =============================================================================


class TestCBORSerialization:
    def test_attestation_roundtrip(self):
        svid, _ = _make_svid_and_bundle()
        original = create_platform_attestation(svid.spiffe_id, svid)

        cbor_bytes = attestation_to_cbor(original)
        restored = attestation_from_cbor(cbor_bytes)

        assert restored.role == original.role
        assert str(restored.spiffe_id) == str(original.spiffe_id)
        assert restored.attestation_nonce == original.attestation_nonce
        assert restored.svid.certificate_chain == original.svid.certificate_chain
        assert abs(
            restored.attested_at.timestamp() - original.attested_at.timestamp()
        ) < 1.0

    def test_composite_token_roundtrip(self):
        mot = _make_multi_owner_token()
        svid, _ = _make_svid_and_bundle()
        attestation = create_platform_attestation(svid.spiffe_id, svid)
        composite = create_composite_token(mot, [attestation])

        # Serialize with a dummy token blob
        token_blob = b"serialized-multi-owner-token"
        cbor_bytes = composite_token_to_cbor(composite, token_blob)

        # Deserialize — pass the original MOT as the pre-deserialized token
        restored = composite_token_from_cbor(cbor_bytes, mot)

        assert restored.composition == composite.composition
        assert len(restored.platform_attestations) == 1
        assert (
            str(restored.platform_attestations[0].spiffe_id)
            == str(composite.platform_attestations[0].spiffe_id)
        )
        assert restored.token is mot

    def test_attestation_from_cbor_invalid(self):
        with pytest.raises(InvalidAttestationError):
            attestation_from_cbor(b"\xff\xff\xff")

    def test_attestation_from_cbor_not_map(self):
        import cbor2

        with pytest.raises(InvalidAttestationError, match="must be a map"):
            attestation_from_cbor(cbor2.dumps([1, 2, 3]))

    def test_composite_from_cbor_invalid(self):
        mot = _make_multi_owner_token()
        with pytest.raises(InvalidAttestationError):
            composite_token_from_cbor(b"\xff\xff", mot)
