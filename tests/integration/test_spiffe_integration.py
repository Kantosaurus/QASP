"""End-to-end integration tests for SPIFFE/SPIRE support."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from qasp.crypto import signatures
from qasp.identity import create_did
from qasp.identity.spiffe import (
    TrustBundle,
    TrustBundleRegistry,
    parse_svid_from_x509,
)
from qasp.protocol.capability import (
    AuthorityChainEntry,
    create_multi_owner_token,
    create_token,
)
from qasp.protocol.spiffe_attestation import (
    create_composite_token,
    create_platform_attestation,
    verify_composite_token,
)


# =============================================================================
# Helpers
# =============================================================================


def _generate_ca_keypair():
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Enterprise CA"),
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


def _generate_svid_cert(ca_key, ca_cert, spiffe_uri):
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Agent Workload"),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(hours=1))
        .not_valid_after(datetime.now(UTC) + timedelta(hours=23))
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
# TestSPIFFEEndToEnd
# =============================================================================


class TestSPIFFEEndToEnd:
    def test_full_enterprise_flow(self):
        """Full flow: trust bundle -> SVID -> multi-owner token + attestation -> verify."""
        # 1. Enterprise sets up trust bundle
        ca_key, ca_cert = _generate_ca_keypair()
        trust_domain = "enterprise.example.com"
        bundle = TrustBundle(
            trust_domain=trust_domain,
            root_certificates=(_cert_to_der(ca_cert),),
            sequence_number=1,
        )
        registry = TrustBundleRegistry()
        registry.register_bundle(bundle)

        # 2. Agent gets SVID from SPIRE
        spiffe_uri = f"spiffe://{trust_domain}/ns/production/agent/alpha"
        _, leaf_cert = _generate_svid_cert(ca_key, ca_cert, spiffe_uri)
        chain_der = [_cert_to_der(leaf_cert), _cert_to_der(ca_cert)]
        svid = parse_svid_from_x509(chain_der)

        assert str(svid.spiffe_id) == spiffe_uri

        # 3. Create multi-owner capability token (QASP authorization)
        owner1_pub, owner1_sec = signatures.generate_keypair()
        owner1_did, _ = create_did(owner1_pub)
        agent_pub, _ = signatures.generate_keypair()
        agent_did, _ = create_did(agent_pub)

        root_token = create_token(
            issuer_did=owner1_did,
            issuer_secret_key=owner1_sec,
            subject_did=agent_did,
            resource_uri="qasp://enterprise/data",
            verbs={"read", "analyze"},
        )
        entry = AuthorityChainEntry(chain=(root_token,), root_public_key=owner1_pub)
        mot = create_multi_owner_token([entry])

        # 4. Create platform attestation and composite token
        attestation = create_platform_attestation(svid.spiffe_id, svid)
        composite = create_composite_token(mot, [attestation])

        assert len(composite.platform_attestations) == 1
        assert composite.effective_verbs().verbs == frozenset({"read", "analyze"})

        # 5. Verify composite token (both capability chain + platform attestation)
        result = verify_composite_token(
            composite,
            trust_bundle_registry=registry,
            check_expiry=False,  # skip ML-DSA token expiry for test timing
        )
        assert result is True

    def test_backward_compat_zero_attestations(self):
        """Composite with zero attestations behaves like plain multi-owner token."""
        pub, sec = signatures.generate_keypair()
        did, _ = create_did(pub)
        sub_pub, _ = signatures.generate_keypair()
        sub_did, _ = create_did(sub_pub)

        token = create_token(
            issuer_did=did,
            issuer_secret_key=sec,
            subject_did=sub_did,
            resource_uri="qasp://test/resource",
            verbs={"read"},
        )
        entry = AuthorityChainEntry(chain=(token,), root_public_key=pub)
        mot = create_multi_owner_token([entry])

        composite = create_composite_token(mot)
        assert composite.platform_attestations == ()

        result = verify_composite_token(composite, check_expiry=False)
        assert result is True

    def test_multiple_attestations(self):
        """Verify a composite token with attestations from multiple trust domains."""
        # Domain 1
        ca1_key, ca1_cert = _generate_ca_keypair()
        _, leaf1 = _generate_svid_cert(
            ca1_key, ca1_cert, "spiffe://domain1.com/agent"
        )
        svid1 = parse_svid_from_x509([_cert_to_der(leaf1), _cert_to_der(ca1_cert)])
        bundle1 = TrustBundle("domain1.com", (_cert_to_der(ca1_cert),), 1)

        # Domain 2
        ca2_key, ca2_cert = _generate_ca_keypair()
        _, leaf2 = _generate_svid_cert(
            ca2_key, ca2_cert, "spiffe://domain2.com/agent"
        )
        svid2 = parse_svid_from_x509([_cert_to_der(leaf2), _cert_to_der(ca2_cert)])
        bundle2 = TrustBundle("domain2.com", (_cert_to_der(ca2_cert),), 1)

        registry = TrustBundleRegistry()
        registry.register_bundle(bundle1)
        registry.register_bundle(bundle2)

        # Create MOT
        pub, sec = signatures.generate_keypair()
        did, _ = create_did(pub)
        sub_pub, _ = signatures.generate_keypair()
        sub_did, _ = create_did(sub_pub)

        token = create_token(
            issuer_did=did,
            issuer_secret_key=sec,
            subject_did=sub_did,
            resource_uri="qasp://test/multi",
            verbs={"read"},
        )
        entry = AuthorityChainEntry(chain=(token,), root_public_key=pub)
        mot = create_multi_owner_token([entry])

        att1 = create_platform_attestation(svid1.spiffe_id, svid1)
        att2 = create_platform_attestation(svid2.spiffe_id, svid2)
        composite = create_composite_token(mot, [att1, att2])

        result = verify_composite_token(
            composite,
            trust_bundle_registry=registry,
            check_expiry=False,
        )
        assert result is True
