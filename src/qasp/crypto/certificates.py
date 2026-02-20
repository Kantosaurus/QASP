"""X.509-PQ certificates with ML-DSA-65 signatures.

This module provides support for X.509 certificates using the post-quantum
ML-DSA-65 signature algorithm (FIPS 204).

ML-DSA-65 OID: 2.16.840.1.101.3.4.3.18

Certificate structure follows RFC 5280 with:
- SubjectPublicKeyInfo containing ML-DSA-65 public key
- Signature using ML-DSA-65
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from qasp.crypto.exceptions import InvalidKeyError, VerificationError
from qasp.crypto.signatures import (
    ML_DSA_65_PUBLIC_KEY_SIZE,
    sign,
    verify,
)

if TYPE_CHECKING:
    pass

__all__ = [
    "Certificate",
    "CertificateError",
    "create_self_signed",
    "parse_certificate",
    "verify_certificate",
]

# ML-DSA-65 OID: 2.16.840.1.101.3.4.3.18 (NIST CSOR)
ML_DSA_65_OID = "2.16.840.1.101.3.4.3.18"
ML_DSA_65_OID_BYTES = bytes([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12])

# DER encoding helpers
DER_SEQUENCE = 0x30
DER_SET = 0x31
DER_INTEGER = 0x02
DER_BIT_STRING = 0x03
DER_OCTET_STRING = 0x04
DER_NULL = 0x05
DER_OID = 0x06
DER_UTF8_STRING = 0x0C
DER_PRINTABLE_STRING = 0x13
DER_UTC_TIME = 0x17
DER_GENERALIZED_TIME = 0x18
DER_CONTEXT_0 = 0xA0
DER_CONTEXT_3 = 0xA3


class CertificateError(Exception):
    """Exception for certificate-related errors."""


def _encode_length(length: int) -> bytes:
    """Encode a DER length field."""
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    elif length < 0x10000:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    else:
        return bytes([0x83, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])


def _encode_sequence(contents: bytes) -> bytes:
    """Encode a DER SEQUENCE."""
    return bytes([DER_SEQUENCE]) + _encode_length(len(contents)) + contents


def _encode_set(contents: bytes) -> bytes:
    """Encode a DER SET."""
    return bytes([DER_SET]) + _encode_length(len(contents)) + contents


def _encode_integer(value: int) -> bytes:
    """Encode a DER INTEGER."""
    if value == 0:
        content = b"\x00"
    else:
        # Convert to bytes (big-endian)
        byte_length = (value.bit_length() + 8) // 8  # Extra byte for sign
        content = value.to_bytes(byte_length, "big", signed=False)
        # Remove leading zeros but keep one if needed for positive sign
        while len(content) > 1 and content[0] == 0 and content[1] < 0x80:
            content = content[1:]
        # Add leading zero if high bit set (to keep it positive)
        if content[0] >= 0x80:
            content = b"\x00" + content
    return bytes([DER_INTEGER]) + _encode_length(len(content)) + content


def _encode_bit_string(data: bytes, unused_bits: int = 0) -> bytes:
    """Encode a DER BIT STRING."""
    content = bytes([unused_bits]) + data
    return bytes([DER_BIT_STRING]) + _encode_length(len(content)) + content


def _encode_octet_string(data: bytes) -> bytes:
    """Encode a DER OCTET STRING."""
    return bytes([DER_OCTET_STRING]) + _encode_length(len(data)) + data


def _encode_oid(oid_bytes: bytes) -> bytes:
    """Encode a DER OID."""
    return bytes([DER_OID]) + _encode_length(len(oid_bytes)) + oid_bytes


def _encode_utf8_string(text: str) -> bytes:
    """Encode a DER UTF8String."""
    encoded = text.encode("utf-8")
    return bytes([DER_UTF8_STRING]) + _encode_length(len(encoded)) + encoded


def _encode_printable_string(text: str) -> bytes:
    """Encode a DER PrintableString."""
    encoded = text.encode("ascii")
    return bytes([DER_PRINTABLE_STRING]) + _encode_length(len(encoded)) + encoded


def _encode_utc_time(dt: datetime) -> bytes:
    """Encode a DER UTCTime."""
    # UTCTime: YYMMDDHHMMSSZ
    time_str = dt.strftime("%y%m%d%H%M%SZ").encode("ascii")
    return bytes([DER_UTC_TIME]) + _encode_length(len(time_str)) + time_str


def _encode_generalized_time(dt: datetime) -> bytes:
    """Encode a DER GeneralizedTime."""
    # GeneralizedTime: YYYYMMDDHHMMSSZ
    time_str = dt.strftime("%Y%m%d%H%M%SZ").encode("ascii")
    return bytes([DER_GENERALIZED_TIME]) + _encode_length(len(time_str)) + time_str


def _encode_time(dt: datetime) -> bytes:
    """Encode a datetime as UTCTime or GeneralizedTime."""
    if dt.year < 2050:
        return _encode_utc_time(dt)
    else:
        return _encode_generalized_time(dt)


def _encode_explicit(tag: int, contents: bytes) -> bytes:
    """Encode with explicit context tag."""
    return bytes([tag]) + _encode_length(len(contents)) + contents


def _encode_algorithm_identifier() -> bytes:
    """Encode ML-DSA-65 AlgorithmIdentifier."""
    # AlgorithmIdentifier ::= SEQUENCE { algorithm OID }
    # ML-DSA algorithms have no parameters (implicit NULL)
    return _encode_sequence(_encode_oid(ML_DSA_65_OID_BYTES))


def _encode_name(common_name: str) -> bytes:
    """Encode an X.501 Name (simplified - just CN)."""
    # Name ::= SEQUENCE OF RelativeDistinguishedName
    # RDN ::= SET OF AttributeTypeAndValue
    # ATV ::= SEQUENCE { type OID, value ANY }

    # CN OID: 2.5.4.3
    cn_oid = bytes([0x55, 0x04, 0x03])
    atv = _encode_sequence(_encode_oid(cn_oid) + _encode_utf8_string(common_name))
    rdn = _encode_set(atv)
    return _encode_sequence(rdn)


def _encode_subject_public_key_info(public_key: bytes) -> bytes:
    """Encode SubjectPublicKeyInfo for ML-DSA-65."""
    # SubjectPublicKeyInfo ::= SEQUENCE {
    #     algorithm AlgorithmIdentifier,
    #     subjectPublicKey BIT STRING
    # }
    algorithm = _encode_algorithm_identifier()
    public_key_bits = _encode_bit_string(public_key)
    return _encode_sequence(algorithm + public_key_bits)


def _encode_validity(not_before: datetime, not_after: datetime) -> bytes:
    """Encode certificate Validity."""
    # Validity ::= SEQUENCE { notBefore Time, notAfter Time }
    return _encode_sequence(_encode_time(not_before) + _encode_time(not_after))


def _encode_extensions(
    key_usage: frozenset[str],
    subject_alt_names: tuple[str, ...],
    is_ca: bool,
) -> bytes:
    """Encode X.509v3 extensions."""
    extensions_content = b""

    # Basic Constraints (critical for CA)
    # OID: 2.5.29.19
    bc_oid = bytes([0x55, 0x1D, 0x13])
    bc_value = _encode_sequence(b"\x01\x01" + (b"\xFF" if is_ca else b"\x00"))
    bc_ext = _encode_sequence(
        _encode_oid(bc_oid) + b"\x01\x01\xFF" + _encode_octet_string(bc_value)
    )
    extensions_content += bc_ext

    # Key Usage (if specified)
    if key_usage:
        # OID: 2.5.29.15
        ku_oid = bytes([0x55, 0x1D, 0x0F])

        # Build key usage bit string
        ku_bits = 0
        ku_mapping = {
            "digitalSignature": 0,
            "nonRepudiation": 1,
            "keyEncipherment": 2,
            "dataEncipherment": 3,
            "keyAgreement": 4,
            "keyCertSign": 5,
            "cRLSign": 6,
        }
        for usage in key_usage:
            if usage in ku_mapping:
                ku_bits |= 1 << (7 - ku_mapping[usage])

        # Encode as BIT STRING with proper padding
        if ku_bits == 0:
            ku_bytes = b"\x00"
            unused = 0
        else:
            ku_bytes = bytes([ku_bits])
            # Count trailing zeros
            unused = 0
            temp = ku_bits
            while temp and (temp & 1) == 0:
                unused += 1
                temp >>= 1

        ku_value = (
            bytes([DER_BIT_STRING]) + _encode_length(len(ku_bytes) + 1) + bytes([unused]) + ku_bytes
        )
        ku_ext = _encode_sequence(
            _encode_oid(ku_oid) + b"\x01\x01\xFF" + _encode_octet_string(ku_value)
        )
        extensions_content += ku_ext

    # Subject Alternative Names (if specified)
    if subject_alt_names:
        # OID: 2.5.29.17
        san_oid = bytes([0x55, 0x1D, 0x11])
        san_content = b""
        for name in subject_alt_names:
            # Encode as dNSName (context tag 2)
            name_bytes = name.encode("ascii")
            san_content += bytes([0x82]) + _encode_length(len(name_bytes)) + name_bytes
        san_value = _encode_sequence(san_content)
        san_ext = _encode_sequence(
            _encode_oid(san_oid) + _encode_octet_string(san_value)
        )
        extensions_content += san_ext

    return _encode_explicit(DER_CONTEXT_3, _encode_sequence(extensions_content))


def _build_tbs_certificate(
    serial_number: int,
    issuer: str,
    subject: str,
    public_key: bytes,
    not_before: datetime,
    not_after: datetime,
    key_usage: frozenset[str],
    extended_key_usage: frozenset[str],  # noqa: ARG001 - reserved for future use
    subject_alt_names: tuple[str, ...],
    is_ca: bool,
) -> bytes:
    """Build the TBSCertificate structure.

    TBSCertificate ::= SEQUENCE {
        version [0] Version DEFAULT v1,
        serialNumber CertificateSerialNumber,
        signature AlgorithmIdentifier,
        issuer Name,
        validity Validity,
        subject Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        extensions [3] Extensions OPTIONAL
    }
    """
    content = b""

    # Version: [0] INTEGER (2 for v3)
    version = _encode_explicit(DER_CONTEXT_0, _encode_integer(2))
    content += version

    # Serial number
    content += _encode_integer(serial_number)

    # Signature algorithm
    content += _encode_algorithm_identifier()

    # Issuer
    content += _encode_name(issuer)

    # Validity
    content += _encode_validity(not_before, not_after)

    # Subject
    content += _encode_name(subject)

    # Subject public key info
    content += _encode_subject_public_key_info(public_key)

    # Extensions (v3)
    content += _encode_extensions(key_usage, subject_alt_names, is_ca)

    return _encode_sequence(content)


@dataclass(frozen=True)
class Certificate:
    """An X.509-PQ certificate with ML-DSA-65 signature.

    Attributes:
        subject: The certificate subject (CN).
        issuer: The certificate issuer (CN).
        public_key: The subject's ML-DSA-65 public key.
        signature_algorithm: The signature algorithm OID.
        signature: The certificate signature.
        not_before: Validity start time.
        not_after: Validity end time.
        serial_number: The certificate serial number.
        raw: The complete DER-encoded certificate.
        key_usage: Set of key usage flags.
        extended_key_usage: Set of extended key usage OIDs.
        subject_alt_names: Subject alternative names.
    """

    subject: str
    issuer: str
    public_key: bytes
    signature_algorithm: str
    signature: bytes
    not_before: datetime
    not_after: datetime
    serial_number: int
    raw: bytes
    key_usage: frozenset[str] = field(default_factory=frozenset)
    extended_key_usage: frozenset[str] = field(default_factory=frozenset)
    subject_alt_names: tuple[str, ...] = field(default_factory=tuple)

    def is_valid(self, now: datetime | None = None) -> bool:
        """Check if the certificate is currently valid.

        Args:
            now: The current time (defaults to UTC now).

        Returns:
            True if the certificate is within its validity period.
        """
        if now is None:
            now = datetime.now(UTC)
        return self.not_before <= now <= self.not_after

    def is_self_signed(self) -> bool:
        """Check if this is a self-signed certificate.

        Returns:
            True if issuer equals subject.
        """
        return self.issuer == self.subject

    def get_did(self) -> str | None:
        """Extract a did:qasp identifier from subject alt names.

        Returns:
            The DID string if found, None otherwise.
        """
        for name in self.subject_alt_names:
            if name.startswith("did:qasp:"):
                return name
        return None

    def to_pem(self) -> str:
        """Convert to PEM format.

        Returns:
            PEM-encoded certificate string.
        """
        b64 = base64.b64encode(self.raw).decode("ascii")
        lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
        return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"

    def to_der(self) -> bytes:
        """Get DER-encoded certificate.

        Returns:
            DER-encoded certificate bytes.
        """
        return self.raw


def create_self_signed(
    subject: str,
    keypair: tuple[bytes, bytes],
    validity_days: int = 365,
    key_usage: frozenset[str] | None = None,
    extended_key_usage: frozenset[str] | None = None,
    subject_alt_names: tuple[str, ...] | None = None,
    is_ca: bool = False,
) -> Certificate:
    """Create a self-signed X.509-PQ certificate.

    Args:
        subject: The certificate subject (CN).
        keypair: Tuple of (public_key, secret_key) for ML-DSA-65.
        validity_days: Certificate validity period in days.
        key_usage: Key usage flags (e.g., {"digitalSignature"}).
        extended_key_usage: Extended key usage OIDs.
        subject_alt_names: Subject alternative names (e.g., DIDs).
        is_ca: Whether this is a CA certificate.

    Returns:
        A self-signed Certificate.

    Raises:
        InvalidKeyError: If the keypair is invalid.
        CertificateError: If certificate creation fails.
    """
    public_key, secret_key = keypair

    if len(public_key) != ML_DSA_65_PUBLIC_KEY_SIZE:
        raise InvalidKeyError(
            f"Invalid public key size: expected {ML_DSA_65_PUBLIC_KEY_SIZE}, "
            f"got {len(public_key)}"
        )

    # Generate serial number (random 128-bit positive integer)
    serial_number = int.from_bytes(os.urandom(16), "big") >> 1  # Ensure positive

    # Set validity period
    not_before = datetime.now(UTC).replace(microsecond=0)
    not_after = not_before + timedelta(days=validity_days)

    # Defaults
    if key_usage is None:
        key_usage = frozenset({"digitalSignature"})
    if extended_key_usage is None:
        extended_key_usage = frozenset()
    if subject_alt_names is None:
        subject_alt_names = ()

    # Build TBS certificate
    tbs_certificate = _build_tbs_certificate(
        serial_number=serial_number,
        issuer=subject,  # Self-signed
        subject=subject,
        public_key=public_key,
        not_before=not_before,
        not_after=not_after,
        key_usage=key_usage,
        extended_key_usage=extended_key_usage,
        subject_alt_names=subject_alt_names,
        is_ca=is_ca,
    )

    # Sign with ML-DSA-65
    signature = sign(secret_key, tbs_certificate)

    # Build complete certificate
    # Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    certificate_content = (
        tbs_certificate + _encode_algorithm_identifier() + _encode_bit_string(signature)
    )
    raw = _encode_sequence(certificate_content)

    return Certificate(
        subject=subject,
        issuer=subject,
        public_key=public_key,
        signature_algorithm=ML_DSA_65_OID,
        signature=signature,
        not_before=not_before,
        not_after=not_after,
        serial_number=serial_number,
        raw=raw,
        key_usage=key_usage,
        extended_key_usage=extended_key_usage,
        subject_alt_names=subject_alt_names,
    )


def verify_certificate(
    certificate: Certificate,
    issuer_public_key: bytes | None = None,
) -> bool:
    """Verify a certificate's signature.

    Args:
        certificate: The certificate to verify.
        issuer_public_key: The issuer's public key (None for self-signed).

    Returns:
        True if the signature is valid.

    Raises:
        InvalidKeyError: If the public key is invalid.
        InvalidSignatureError: If the signature is invalid.
    """
    # Use certificate's own key for self-signed
    if issuer_public_key is None:
        if not certificate.is_self_signed():
            raise VerificationError(
                "Must provide issuer public key for non-self-signed certificates"
            )
        issuer_public_key = certificate.public_key

    # Extract TBS certificate from raw DER
    raw = certificate.raw

    # Parse outer SEQUENCE
    if raw[0] != DER_SEQUENCE:
        raise VerificationError("Invalid certificate: not a SEQUENCE")

    # Get content start position (skip length field)
    if raw[1] < 0x80:
        content_start = 2
    elif raw[1] == 0x81:
        content_start = 3
    elif raw[1] == 0x82:
        content_start = 4
    else:
        raise VerificationError("Invalid certificate: unsupported length encoding")

    # Parse TBS certificate (first element)
    tbs_start = content_start
    if raw[tbs_start] != DER_SEQUENCE:
        raise VerificationError("Invalid certificate: TBS not a SEQUENCE")

    # Get TBS length
    if raw[tbs_start + 1] < 0x80:
        tbs_len = raw[tbs_start + 1]
        tbs_header_len = 2
    elif raw[tbs_start + 1] == 0x81:
        tbs_len = raw[tbs_start + 2]
        tbs_header_len = 3
    elif raw[tbs_start + 1] == 0x82:
        tbs_len = (raw[tbs_start + 2] << 8) | raw[tbs_start + 3]
        tbs_header_len = 4
    else:
        raise VerificationError("Invalid certificate: unsupported TBS length encoding")

    tbs_certificate = raw[tbs_start : tbs_start + tbs_header_len + tbs_len]

    # Verify signature
    return verify(issuer_public_key, tbs_certificate, certificate.signature)


def _parse_length(data: bytes, offset: int) -> tuple[int, int]:
    """Parse a DER length field.

    Returns:
        Tuple of (length, bytes_consumed).
    """
    if data[offset] < 0x80:
        return data[offset], 1
    elif data[offset] == 0x81:
        return data[offset + 1], 2
    elif data[offset] == 0x82:
        return (data[offset + 1] << 8) | data[offset + 2], 3
    elif data[offset] == 0x83:
        return (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3], 4
    else:
        raise CertificateError(f"Unsupported length encoding at offset {offset}")


def _parse_integer(data: bytes, offset: int) -> tuple[int, int]:
    """Parse a DER INTEGER.

    Returns:
        Tuple of (value, bytes_consumed).
    """
    if data[offset] != DER_INTEGER:
        raise CertificateError(f"Expected INTEGER at offset {offset}")
    length, len_size = _parse_length(data, offset + 1)
    start = offset + 1 + len_size
    value = int.from_bytes(data[start : start + length], "big")
    return value, 1 + len_size + length


def _parse_sequence(data: bytes, offset: int) -> tuple[bytes, int]:
    """Parse a DER SEQUENCE.

    Returns:
        Tuple of (contents, bytes_consumed).
    """
    if data[offset] != DER_SEQUENCE:
        raise CertificateError(f"Expected SEQUENCE at offset {offset}")
    length, len_size = _parse_length(data, offset + 1)
    start = offset + 1 + len_size
    return data[start : start + length], 1 + len_size + length


def _parse_bit_string(data: bytes, offset: int) -> tuple[bytes, int]:
    """Parse a DER BIT STRING.

    Returns:
        Tuple of (contents, bytes_consumed).
    """
    if data[offset] != DER_BIT_STRING:
        raise CertificateError(f"Expected BIT STRING at offset {offset}")
    length, len_size = _parse_length(data, offset + 1)
    start = offset + 1 + len_size
    # Skip unused bits indicator
    return data[start + 1 : start + length], 1 + len_size + length


def _parse_time(data: bytes, offset: int) -> tuple[datetime, int]:
    """Parse a DER UTCTime or GeneralizedTime.

    Returns:
        Tuple of (datetime, bytes_consumed).
    """
    tag = data[offset]
    length, len_size = _parse_length(data, offset + 1)
    start = offset + 1 + len_size
    time_str = data[start : start + length].decode("ascii")

    if tag == DER_UTC_TIME:
        # YYMMDDHHMMSSZ
        year = int(time_str[0:2])
        year += 2000 if year < 50 else 1900
        month = int(time_str[2:4])
        day = int(time_str[4:6])
        hour = int(time_str[6:8])
        minute = int(time_str[8:10])
        second = int(time_str[10:12])
    elif tag == DER_GENERALIZED_TIME:
        # YYYYMMDDHHMMSSZ
        year = int(time_str[0:4])
        month = int(time_str[4:6])
        day = int(time_str[6:8])
        hour = int(time_str[8:10])
        minute = int(time_str[10:12])
        second = int(time_str[12:14])
    else:
        raise CertificateError(f"Invalid time tag at offset {offset}")

    return datetime(year, month, day, hour, minute, second, tzinfo=UTC), 1 + len_size + length


def _parse_name(data: bytes, offset: int) -> tuple[str, int]:
    """Parse an X.501 Name, extracting the CN.

    Returns:
        Tuple of (common_name, bytes_consumed).
    """
    if data[offset] != DER_SEQUENCE:
        raise CertificateError(f"Expected SEQUENCE for Name at offset {offset}")

    length, len_size = _parse_length(data, offset + 1)
    content_start = offset + 1 + len_size
    content_end = content_start + length
    consumed = 1 + len_size + length

    # Look for CN (OID 2.5.4.3)
    cn_oid = bytes([0x55, 0x04, 0x03])
    pos = content_start

    while pos < content_end:
        # Parse RDN (SET)
        if data[pos] != DER_SET:
            raise CertificateError(f"Expected SET in Name at offset {pos}")
        rdn_len, rdn_len_size = _parse_length(data, pos + 1)
        rdn_start = pos + 1 + rdn_len_size
        rdn_end = rdn_start + rdn_len

        # Parse AttributeTypeAndValue (SEQUENCE)
        atv_pos = rdn_start
        while atv_pos < rdn_end:
            if data[atv_pos] != DER_SEQUENCE:
                raise CertificateError(f"Expected SEQUENCE for ATV at offset {atv_pos}")
            atv_len, atv_len_size = _parse_length(data, atv_pos + 1)
            atv_content_start = atv_pos + 1 + atv_len_size

            # Check OID
            if data[atv_content_start] == DER_OID:
                oid_len, oid_len_size = _parse_length(data, atv_content_start + 1)
                oid_start = atv_content_start + 1 + oid_len_size
                oid_bytes = data[oid_start : oid_start + oid_len]
                if oid_bytes == cn_oid:
                    # Found CN, parse value
                    value_pos = atv_content_start + 1 + oid_len_size + oid_len
                    value_tag = data[value_pos]
                    value_len, value_len_size = _parse_length(data, value_pos + 1)
                    value_start = value_pos + 1 + value_len_size
                    value_bytes = data[value_start : value_start + value_len]

                    if value_tag == DER_UTF8_STRING:
                        return value_bytes.decode("utf-8"), consumed
                    elif value_tag == DER_PRINTABLE_STRING:
                        return value_bytes.decode("ascii"), consumed

            atv_pos += 1 + atv_len_size + atv_len

        pos = rdn_end

    raise CertificateError("CN not found in Name")


def parse_certificate(data: bytes) -> Certificate:
    """Parse a DER-encoded X.509-PQ certificate.

    Args:
        data: The DER-encoded certificate data.

    Returns:
        A Certificate instance.

    Raises:
        CertificateError: If parsing fails.
    """
    # Handle PEM format
    if data.startswith(b"-----BEGIN CERTIFICATE-----"):
        lines = data.decode("ascii").strip().split("\n")
        b64_data = "".join(lines[1:-1])
        data = base64.b64decode(b64_data)

    try:
        # Parse outer SEQUENCE
        content, _ = _parse_sequence(data, 0)

        # Parse TBS certificate
        offset = 0
        tbs_content, tbs_consumed = _parse_sequence(content, offset)
        offset += tbs_consumed

        # Parse TBS fields
        tbs_offset = 0

        # Version [0] (optional, default v1)
        if tbs_content[tbs_offset] == DER_CONTEXT_0:
            # Explicit tag - skip version field
            version_len, version_len_size = _parse_length(tbs_content, tbs_offset + 1)
            tbs_offset += 1 + version_len_size + version_len

        # Serial number
        serial_number, serial_consumed = _parse_integer(tbs_content, tbs_offset)
        tbs_offset += serial_consumed

        # Signature algorithm (skip for now)
        _, sig_alg_consumed = _parse_sequence(tbs_content, tbs_offset)
        tbs_offset += sig_alg_consumed

        # Issuer
        issuer, issuer_consumed = _parse_name(tbs_content, tbs_offset)
        tbs_offset += issuer_consumed

        # Validity
        validity_content, validity_consumed = _parse_sequence(tbs_content, tbs_offset)
        tbs_offset += validity_consumed
        not_before, nb_consumed = _parse_time(validity_content, 0)
        not_after, _ = _parse_time(validity_content, nb_consumed)

        # Subject
        subject, subject_consumed = _parse_name(tbs_content, tbs_offset)
        tbs_offset += subject_consumed

        # SubjectPublicKeyInfo
        spki_content, spki_consumed = _parse_sequence(tbs_content, tbs_offset)
        tbs_offset += spki_consumed

        # Parse SPKI to get public key
        # Skip algorithm identifier
        _, alg_consumed = _parse_sequence(spki_content, 0)
        public_key, _ = _parse_bit_string(spki_content, alg_consumed)

        # Skip to signature algorithm after TBS
        # Parse signature algorithm
        _, outer_sig_alg_consumed = _parse_sequence(content, tbs_consumed)

        # Parse signature
        signature, _ = _parse_bit_string(content, tbs_consumed + outer_sig_alg_consumed)

        return Certificate(
            subject=subject,
            issuer=issuer,
            public_key=public_key,
            signature_algorithm=ML_DSA_65_OID,
            signature=signature,
            not_before=not_before,
            not_after=not_after,
            serial_number=serial_number,
            raw=data,
        )

    except Exception as e:
        raise CertificateError(f"Failed to parse certificate: {e}") from e
