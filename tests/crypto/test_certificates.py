"""Tests for X.509-PQ certificates with ML-DSA-65."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from qasp.crypto.certificates import (
    ML_DSA_65_OID,
    Certificate,
    CertificateError,
    create_self_signed,
    parse_certificate,
    verify_certificate,
)
from qasp.crypto.exceptions import InvalidKeyError, InvalidSignatureError


class TestSelfSignedCertificate:
    """Tests for self-signed certificate creation."""

    def test_create_self_signed(self, mldsa_keypair: tuple[bytes, bytes]) -> None:
        """Can create a self-signed certificate."""
        cert = create_self_signed(
            subject="CN=Test",
            keypair=mldsa_keypair,
        )
        assert isinstance(cert, Certificate)
        assert cert.subject == "CN=Test"
        assert cert.issuer == "CN=Test"

    def test_certificate_has_public_key(self, mldsa_keypair: tuple[bytes, bytes]) -> None:
        """Certificate contains the public key."""
        public_key, _ = mldsa_keypair
        cert = create_self_signed(
            subject="CN=Test",
            keypair=mldsa_keypair,
        )
        assert cert.public_key == public_key

    def test_certificate_has_correct_oid(self, mldsa_keypair: tuple[bytes, bytes]) -> None:
        """Certificate has ML-DSA-65 signature algorithm OID."""
        cert = create_self_signed(
            subject="CN=Test",
            keypair=mldsa_keypair,
        )
        assert cert.signature_algorithm == ML_DSA_65_OID

    def test_certificate_has_signature(self, mldsa_keypair: tuple[bytes, bytes]) -> None:
        """Certificate has a signature."""
        cert = create_self_signed(
            subject="CN=Test",
            keypair=mldsa_keypair,
        )
        assert cert.signature is not None
        assert len(cert.signature) > 0

    def test_certificate_has_validity_period(
        self, mldsa_keypair: tuple[bytes, bytes]
    ) -> None:
        """Certificate has validity period."""
        cert = create_self_signed(
            subject="CN=Test",
            keypair=mldsa_keypair,
            validity_days=365,
        )
        assert cert.not_before is not None
        assert cert.not_after is not None
        assert cert.not_after > cert.not_before

    def test_certificate_custom_validity(
        self, mldsa_keypair: tuple[bytes, bytes]
    ) -> None:
        """Can set custom validity period."""
        cert = create_self_signed(
            subject="CN=Test",
            keypair=mldsa_keypair,
            validity_days=30,
        )
        expected_duration = timedelta(days=30)
        actual_duration = cert.not_after - cert.not_before
        # Allow small difference
        assert abs(actual_duration.total_seconds() - expected_duration.total_seconds()) < 60

    def test_certificate_has_serial_number(
        self, mldsa_keypair: tuple[bytes, bytes]
    ) -> None:
        """Certificate has a serial number."""
        cert = create_self_signed(
            subject="CN=Test",
            keypair=mldsa_keypair,
        )
        assert cert.serial_number is not None
        assert cert.serial_number > 0

    def test_certificate_has_raw_der(self, mldsa_keypair: tuple[bytes, bytes]) -> None:
        """Certificate has raw DER-encoded data."""
        cert = create_self_signed(
            subject="CN=Test",
            keypair=mldsa_keypair,
        )
        assert cert.raw is not None
        assert len(cert.raw) > 0
        # DER SEQUENCE starts with 0x30
        assert cert.raw[0] == 0x30

    def test_certificate_key_usage(self, mldsa_keypair: tuple[bytes, bytes]) -> None:
        """Can set key usage flags."""
        cert = create_self_signed(
            subject="CN=Test",
            keypair=mldsa_keypair,
            key_usage=frozenset({"digitalSignature", "keyEncipherment"}),
        )
        assert "digitalSignature" in cert.key_usage
        assert "keyEncipherment" in cert.key_usage

    def test_certificate_subject_alt_names(
        self, mldsa_keypair: tuple[bytes, bytes]
    ) -> None:
        """Can set subject alternative names."""
        cert = create_self_signed(
            subject="CN=Test",
            keypair=mldsa_keypair,
            subject_alt_names=("example.com", "test.example.com"),
        )
        assert "example.com" in cert.subject_alt_names
        assert "test.example.com" in cert.subject_alt_names

    def test_certificate_invalid_keypair(self) -> None:
        """Raises InvalidKeyError for invalid keypair."""
        with pytest.raises(InvalidKeyError):
            create_self_signed(
                subject="CN=Test",
                keypair=(b"short", b"also_short"),
            )


class TestCertificateVerification:
    """Tests for certificate verification."""

    def test_verify_valid_certificate(
        self, mldsa_keypair: tuple[bytes, bytes]
    ) -> None:
        """Valid self-signed certificate verifies successfully."""
        cert = create_self_signed(
            subject="CN=Test",
            keypair=mldsa_keypair,
        )
        assert verify_certificate(cert)

    def test_verify_with_explicit_key(
        self, mldsa_keypair: tuple[bytes, bytes]
    ) -> None:
        """Can verify with explicit issuer key."""
        public_key, _ = mldsa_keypair
        cert = create_self_signed(
            subject="CN=Test",
            keypair=mldsa_keypair,
        )
        assert verify_certificate(cert, issuer_public_key=public_key)

    def test_verify_with_wrong_key_fails(
        self,
        mldsa_keypair: tuple[bytes, bytes],
        mlkem_public_key: bytes,  # Wrong type of key
    ) -> None:
        """Verification fails with wrong public key."""
        cert = create_self_signed(
            subject="CN=Test",
            keypair=mldsa_keypair,
        )
        # Use a different ML-DSA key
        from qasp.crypto import signatures

        other_pk, _ = signatures.generate_keypair()
        with pytest.raises(InvalidSignatureError):
            verify_certificate(cert, issuer_public_key=other_pk)


class TestCertificateParsing:
    """Tests for certificate parsing."""

    def test_parse_der_certificate(self, mldsa_keypair: tuple[bytes, bytes]) -> None:
        """Can parse a DER-encoded certificate."""
        original = create_self_signed(
            subject="CN=Test",
            keypair=mldsa_keypair,
        )
        parsed = parse_certificate(original.raw)
        assert parsed.subject == original.subject
        assert parsed.issuer == original.issuer
        assert parsed.serial_number == original.serial_number

    def test_parse_pem_certificate(self, mldsa_keypair: tuple[bytes, bytes]) -> None:
        """Can parse a PEM-encoded certificate."""
        original = create_self_signed(
            subject="CN=Test",
            keypair=mldsa_keypair,
        )
        pem = original.to_pem()
        parsed = parse_certificate(pem.encode("ascii"))
        assert parsed.subject == original.subject

    def test_parsed_certificate_verifies(
        self, mldsa_keypair: tuple[bytes, bytes]
    ) -> None:
        """Parsed certificate can be verified."""
        original = create_self_signed(
            subject="CN=Test",
            keypair=mldsa_keypair,
        )
        parsed = parse_certificate(original.raw)
        assert verify_certificate(parsed)

    def test_parse_roundtrip_preserves_public_key(
        self, mldsa_keypair: tuple[bytes, bytes]
    ) -> None:
        """Parsing preserves the public key."""
        public_key, _ = mldsa_keypair
        original = create_self_signed(
            subject="CN=Test",
            keypair=mldsa_keypair,
        )
        parsed = parse_certificate(original.raw)
        assert parsed.public_key == public_key

    def test_parse_roundtrip_preserves_validity(
        self, mldsa_keypair: tuple[bytes, bytes]
    ) -> None:
        """Parsing preserves validity period."""
        original = create_self_signed(
            subject="CN=Test",
            keypair=mldsa_keypair,
            validity_days=365,
        )
        parsed = parse_certificate(original.raw)
        assert parsed.not_before == original.not_before
        assert parsed.not_after == original.not_after

    def test_parse_invalid_data_fails(self) -> None:
        """Parsing invalid data raises CertificateError."""
        with pytest.raises(CertificateError):
            parse_certificate(b"not a certificate")


class TestCertificateMethods:
    """Tests for Certificate helper methods."""

    def test_is_valid_current(self, mldsa_keypair: tuple[bytes, bytes]) -> None:
        """is_valid returns True for current certificate."""
        cert = create_self_signed(
            subject="CN=Test",
            keypair=mldsa_keypair,
            validity_days=365,
        )
        assert cert.is_valid()

    def test_is_valid_expired(self, mldsa_keypair: tuple[bytes, bytes]) -> None:
        """is_valid returns False for expired certificate."""
        cert = create_self_signed(
            subject="CN=Test",
            keypair=mldsa_keypair,
            validity_days=1,
        )
        future = datetime.now(UTC) + timedelta(days=2)
        assert not cert.is_valid(future)

    def test_is_valid_not_yet_valid(self, mldsa_keypair: tuple[bytes, bytes]) -> None:
        """is_valid returns False before not_before."""
        cert = create_self_signed(
            subject="CN=Test",
            keypair=mldsa_keypair,
        )
        past = cert.not_before - timedelta(days=1)
        assert not cert.is_valid(past)

    def test_is_self_signed_true(self, mldsa_keypair: tuple[bytes, bytes]) -> None:
        """is_self_signed returns True for self-signed certificate."""
        cert = create_self_signed(
            subject="CN=Test",
            keypair=mldsa_keypair,
        )
        assert cert.is_self_signed()

    def test_to_pem_format(self, mldsa_keypair: tuple[bytes, bytes]) -> None:
        """to_pem produces valid PEM format."""
        cert = create_self_signed(
            subject="CN=Test",
            keypair=mldsa_keypair,
        )
        pem = cert.to_pem()
        assert pem.startswith("-----BEGIN CERTIFICATE-----\n")
        assert pem.endswith("-----END CERTIFICATE-----\n")

    def test_to_der(self, mldsa_keypair: tuple[bytes, bytes]) -> None:
        """to_der returns raw DER data."""
        cert = create_self_signed(
            subject="CN=Test",
            keypair=mldsa_keypair,
        )
        assert cert.to_der() == cert.raw

    def test_get_did_with_san(self, mldsa_keypair: tuple[bytes, bytes]) -> None:
        """get_did extracts DID from subject alt names."""
        cert = create_self_signed(
            subject="CN=Test",
            keypair=mldsa_keypair,
            subject_alt_names=("example.com", "did:qasp:abc123"),
        )
        assert cert.get_did() == "did:qasp:abc123"

    def test_get_did_without_san(self, mldsa_keypair: tuple[bytes, bytes]) -> None:
        """get_did returns None when no DID in SANs."""
        cert = create_self_signed(
            subject="CN=Test",
            keypair=mldsa_keypair,
        )
        assert cert.get_did() is None
