"""Tests for PKI certificate chain integration."""
from __future__ import annotations

import pytest

from qasp.crypto import signatures
from qasp.crypto.certificates import (
    Certificate,
    CertificateError,
    create_issued_certificate,
    create_self_signed,
    verify_certificate,
    verify_certificate_chain,
)


class TestIssuedCertificate:
    """Tests for create_issued_certificate."""

    def test_create_basic_issued_cert(self) -> None:
        """Test creating a basic issued certificate."""
        # Create CA
        ca_pk, ca_sk = signatures.generate_keypair()
        ca_cert = create_self_signed(
            "QASP Root CA",
            (ca_pk, ca_sk),
            is_ca=True,
            key_usage=frozenset({"keyCertSign", "digitalSignature"}),
        )

        # Create issued cert
        sub_pk, sub_sk = signatures.generate_keypair()
        sub_cert = create_issued_certificate(
            subject="Test Agent",
            subject_keypair=(sub_pk, sub_sk),
            issuer_cert=ca_cert,
            issuer_secret_key=ca_sk,
        )

        assert sub_cert.subject == "Test Agent"
        assert sub_cert.issuer == "QASP Root CA"
        assert sub_cert.public_key == sub_pk
        assert verify_certificate(sub_cert, ca_pk)

    def test_issuer_must_be_ca(self) -> None:
        """Test that issuer must have is_ca=True."""
        pk1, sk1 = signatures.generate_keypair()
        non_ca = create_self_signed("Not CA", (pk1, sk1), is_ca=False)

        pk2, sk2 = signatures.generate_keypair()
        with pytest.raises(CertificateError, match="[Cc][Aa]"):
            create_issued_certificate(
                "Child",
                (pk2, sk2),
                non_ca,
                sk1,
            )

    def test_capability_class_constraint(self) -> None:
        """Test capability class subsetting."""
        ca_pk, ca_sk = signatures.generate_keypair()
        ca_cert = create_self_signed(
            "CA",
            (ca_pk, ca_sk),
            is_ca=True,
            permitted_capability_classes=("read", "write"),
        )

        sub_pk, sub_sk = signatures.generate_keypair()
        # Valid subset
        sub_cert = create_issued_certificate(
            "Sub",
            (sub_pk, sub_sk),
            ca_cert,
            ca_sk,
            permitted_capability_classes=("read",),
        )
        assert sub_cert.permitted_capability_classes == ("read",)

        # Invalid superset
        pk3, sk3 = signatures.generate_keypair()
        with pytest.raises(CertificateError):
            create_issued_certificate(
                "Bad",
                (pk3, sk3),
                ca_cert,
                ca_sk,
                permitted_capability_classes=("read", "write", "admin"),
            )

    def test_delegation_depth_constraint(self) -> None:
        """Test delegation depth decrements."""
        ca_pk, ca_sk = signatures.generate_keypair()
        ca_cert = create_self_signed(
            "CA",
            (ca_pk, ca_sk),
            is_ca=True,
            max_delegation_depth=2,
        )

        sub_pk, sub_sk = signatures.generate_keypair()
        sub_cert = create_issued_certificate(
            "Sub",
            (sub_pk, sub_sk),
            ca_cert,
            ca_sk,
            is_ca=True,
        )
        # Should auto-decrement
        assert sub_cert.max_delegation_depth == 1

    def test_spending_limit_constraint(self) -> None:
        """Test spending limit narrowing."""
        ca_pk, ca_sk = signatures.generate_keypair()
        ca_cert = create_self_signed(
            "CA",
            (ca_pk, ca_sk),
            is_ca=True,
            spending_limit=1000,
        )

        sub_pk, sub_sk = signatures.generate_keypair()
        # Valid lower limit
        sub_cert = create_issued_certificate(
            "Sub",
            (sub_pk, sub_sk),
            ca_cert,
            ca_sk,
            spending_limit=500,
        )
        assert sub_cert.spending_limit == 500

        # Invalid higher limit
        pk3, sk3 = signatures.generate_keypair()
        with pytest.raises(CertificateError):
            create_issued_certificate(
                "Bad",
                (pk3, sk3),
                ca_cert,
                ca_sk,
                spending_limit=2000,
            )


class TestCertificateChainVerification:
    """Tests for verify_certificate_chain."""

    def test_two_level_chain(self) -> None:
        """Test simple root->leaf chain."""
        ca_pk, ca_sk = signatures.generate_keypair()
        ca_cert = create_self_signed(
            "Root CA",
            (ca_pk, ca_sk),
            is_ca=True,
            key_usage=frozenset({"keyCertSign", "digitalSignature"}),
        )

        leaf_pk, leaf_sk = signatures.generate_keypair()
        leaf_cert = create_issued_certificate(
            "Leaf",
            (leaf_pk, leaf_sk),
            ca_cert,
            ca_sk,
        )

        assert verify_certificate_chain([ca_cert, leaf_cert])

    def test_three_level_chain(self) -> None:
        """Test root->intermediate->leaf chain."""
        root_pk, root_sk = signatures.generate_keypair()
        root_cert = create_self_signed(
            "Root CA",
            (root_pk, root_sk),
            is_ca=True,
            key_usage=frozenset({"keyCertSign", "digitalSignature"}),
            max_delegation_depth=2,
        )

        int_pk, int_sk = signatures.generate_keypair()
        int_cert = create_issued_certificate(
            "Intermediate CA",
            (int_pk, int_sk),
            root_cert,
            root_sk,
            is_ca=True,
        )

        leaf_pk, leaf_sk = signatures.generate_keypair()
        leaf_cert = create_issued_certificate(
            "Leaf",
            (leaf_pk, leaf_sk),
            int_cert,
            int_sk,
        )

        assert verify_certificate_chain([root_cert, int_cert, leaf_cert])

    def test_broken_chain_fails(self) -> None:
        """Test that a broken chain is rejected."""
        ca_pk, ca_sk = signatures.generate_keypair()
        ca_cert = create_self_signed(
            "Root CA",
            (ca_pk, ca_sk),
            is_ca=True,
            key_usage=frozenset({"keyCertSign", "digitalSignature"}),
        )

        # Create cert from different CA
        other_pk, other_sk = signatures.generate_keypair()
        other_cert = create_self_signed(
            "Other CA",
            (other_pk, other_sk),
            is_ca=True,
            key_usage=frozenset({"keyCertSign", "digitalSignature"}),
        )

        leaf_pk, leaf_sk = signatures.generate_keypair()
        leaf_cert = create_issued_certificate(
            "Leaf",
            (leaf_pk, leaf_sk),
            other_cert,
            other_sk,
        )

        # Chain says root->leaf but leaf was signed by other
        with pytest.raises(CertificateError):
            verify_certificate_chain([ca_cert, leaf_cert])

    def test_expired_cert_fails(self) -> None:
        """Test that expired certificates are rejected with check_validity=True."""
        ca_pk, ca_sk = signatures.generate_keypair()
        ca_cert = create_self_signed(
            "Root CA",
            (ca_pk, ca_sk),
            validity_days=0,
            is_ca=True,
            key_usage=frozenset({"keyCertSign", "digitalSignature"}),
        )

        leaf_pk, leaf_sk = signatures.generate_keypair()
        leaf_cert = create_issued_certificate(
            "Leaf",
            (leaf_pk, leaf_sk),
            ca_cert,
            ca_sk,
            validity_days=0,
        )

        # With validity check on, should fail
        with pytest.raises(CertificateError):
            verify_certificate_chain([ca_cert, leaf_cert], check_validity=True)

    def test_trusted_roots(self) -> None:
        """Test verification against trusted roots."""
        ca_pk, ca_sk = signatures.generate_keypair()
        ca_cert = create_self_signed(
            "Root CA",
            (ca_pk, ca_sk),
            is_ca=True,
            key_usage=frozenset({"keyCertSign", "digitalSignature"}),
        )

        leaf_pk, leaf_sk = signatures.generate_keypair()
        leaf_cert = create_issued_certificate(
            "Leaf",
            (leaf_pk, leaf_sk),
            ca_cert,
            ca_sk,
        )

        assert verify_certificate_chain(
            [ca_cert, leaf_cert], trusted_roots=[ca_cert]
        )

    def test_untrusted_root_fails(self) -> None:
        """Test that untrusted roots are rejected."""
        ca_pk, ca_sk = signatures.generate_keypair()
        ca_cert = create_self_signed(
            "Root CA",
            (ca_pk, ca_sk),
            is_ca=True,
            key_usage=frozenset({"keyCertSign", "digitalSignature"}),
        )

        other_pk, other_sk = signatures.generate_keypair()
        other_root = create_self_signed(
            "Other Root", (other_pk, other_sk), is_ca=True
        )

        leaf_pk, leaf_sk = signatures.generate_keypair()
        leaf_cert = create_issued_certificate(
            "Leaf",
            (leaf_pk, leaf_sk),
            ca_cert,
            ca_sk,
        )

        # Chain signed by ca_cert but trusted_roots only has other_root
        with pytest.raises(CertificateError):
            verify_certificate_chain(
                [ca_cert, leaf_cert], trusted_roots=[other_root]
            )

    def test_non_ca_intermediate_fails(self) -> None:
        """Test that non-CA intermediates are rejected."""
        ca_pk, ca_sk = signatures.generate_keypair()
        ca_cert = create_self_signed(
            "Root CA",
            (ca_pk, ca_sk),
            is_ca=True,
            key_usage=frozenset({"keyCertSign", "digitalSignature"}),
        )

        # Non-CA intermediate
        int_pk, int_sk = signatures.generate_keypair()
        int_cert = create_issued_certificate(
            "Not CA",
            (int_pk, int_sk),
            ca_cert,
            ca_sk,
            is_ca=False,
        )

        leaf_pk, leaf_sk = signatures.generate_keypair()
        # Can't issue from non-CA
        with pytest.raises(CertificateError):
            create_issued_certificate(
                "Leaf",
                (leaf_pk, leaf_sk),
                int_cert,
                int_sk,
            )
