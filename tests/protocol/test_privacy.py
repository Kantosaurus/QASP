"""Tests for non-repudiation with privacy (trace entries)."""

from __future__ import annotations

import hashlib
import os
import time

import cbor2
import pytest

from qasp.auditor.service import AuditorService
from qasp.crypto import kem
from qasp.crypto.signatures import generate_keypair
from qasp.identity.did import create_did
from qasp.protocol.privacy import (
    TraceDecryptionError,
    TraceEntry,
    TraceVerificationError,
    create_private_trace_entry,
    decrypt_auditor_envelope,
    verify_args_hash,
    verify_trace_entry,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def auditor_kem_keypair() -> tuple[bytes, bytes]:
    """ML-KEM-768 keypair for the auditor."""
    return kem.generate_keypair()


@pytest.fixture
def auditor_kem_pk(auditor_kem_keypair: tuple[bytes, bytes]) -> bytes:
    return auditor_kem_keypair[0]


@pytest.fixture
def auditor_kem_sk(auditor_kem_keypair: tuple[bytes, bytes]) -> bytes:
    return auditor_kem_keypair[1]


@pytest.fixture
def signer_keypair() -> tuple[bytes, bytes]:
    """ML-DSA-65 keypair for the signer."""
    return generate_keypair()


@pytest.fixture
def signer_pk(signer_keypair: tuple[bytes, bytes]) -> bytes:
    return signer_keypair[0]


@pytest.fixture
def signer_sk(signer_keypair: tuple[bytes, bytes]) -> bytes:
    return signer_keypair[1]


@pytest.fixture
def sample_arguments() -> bytes:
    return b'{"patient_id":"P12345","symptoms":"headache,fever"}'


@pytest.fixture
def sample_result() -> bytes:
    return b'{"diagnosis":"influenza","confidence":0.87}'


@pytest.fixture
def sample_token_id() -> bytes:
    return os.urandom(32)


@pytest.fixture
def trace_entry(
    auditor_kem_pk: bytes,
    signer_sk: bytes,
    sample_arguments: bytes,
    sample_result: bytes,
    sample_token_id: bytes,
) -> TraceEntry:
    """A fully constructed trace entry for reuse across tests."""
    return create_private_trace_entry(
        action="exec",
        resource="qasp://medical-api/diagnosis/lookup",
        arguments=sample_arguments,
        result=sample_result,
        auditor_kem_pk=auditor_kem_pk,
        signer_sk=signer_sk,
        token_id=sample_token_id,
    )


# =============================================================================
# TestCreatePrivateTraceEntry
# =============================================================================


class TestCreatePrivateTraceEntry:

    def test_args_hash_is_sha384(
        self, trace_entry: TraceEntry, sample_arguments: bytes,
    ) -> None:
        expected = hashlib.sha384(sample_arguments).digest()
        assert trace_entry.args_hash == expected
        assert len(trace_entry.args_hash) == 48

    def test_result_hash_is_sha384(
        self, trace_entry: TraceEntry, sample_result: bytes,
    ) -> None:
        expected = hashlib.sha384(sample_result).digest()
        assert trace_entry.result_hash == expected
        assert len(trace_entry.result_hash) == 48

    def test_encrypted_args_is_cbor_envelope(
        self, trace_entry: TraceEntry,
    ) -> None:
        envelope = cbor2.loads(trace_entry.args_encrypted)
        assert "kem_ct" in envelope
        assert "nonce" in envelope
        assert "encrypted" in envelope
        assert len(envelope["kem_ct"]) == 1088  # ML-KEM-768 ciphertext
        assert len(envelope["nonce"]) == 12  # AES-GCM nonce

    def test_signature_is_present(self, trace_entry: TraceEntry) -> None:
        assert len(trace_entry.signature) > 0

    def test_fields_match_inputs(
        self, trace_entry: TraceEntry, sample_token_id: bytes,
    ) -> None:
        assert trace_entry.token_id == sample_token_id
        assert trace_entry.action == "exec"
        assert trace_entry.resource == "qasp://medical-api/diagnosis/lookup"

    def test_default_timestamp(
        self,
        auditor_kem_pk: bytes,
        signer_sk: bytes,
        sample_arguments: bytes,
        sample_result: bytes,
        sample_token_id: bytes,
    ) -> None:
        before = int(time.time())
        entry = create_private_trace_entry(
            action="read",
            resource="qasp://test",
            arguments=sample_arguments,
            result=sample_result,
            auditor_kem_pk=auditor_kem_pk,
            signer_sk=signer_sk,
            token_id=sample_token_id,
        )
        after = int(time.time())
        assert before <= entry.timestamp <= after

    def test_explicit_timestamp(
        self,
        auditor_kem_pk: bytes,
        signer_sk: bytes,
        sample_arguments: bytes,
        sample_result: bytes,
        sample_token_id: bytes,
    ) -> None:
        ts = 1700000000
        entry = create_private_trace_entry(
            action="exec",
            resource="qasp://test",
            arguments=sample_arguments,
            result=sample_result,
            auditor_kem_pk=auditor_kem_pk,
            signer_sk=signer_sk,
            token_id=sample_token_id,
            timestamp=ts,
        )
        assert entry.timestamp == ts


# =============================================================================
# TestVerifyTraceEntry
# =============================================================================


class TestVerifyTraceEntry:

    def test_valid_entry_verifies(
        self, trace_entry: TraceEntry, signer_pk: bytes,
    ) -> None:
        assert verify_trace_entry(trace_entry, signer_pk) is True

    def test_tampered_action_fails(
        self, trace_entry: TraceEntry, signer_pk: bytes,
    ) -> None:
        # Reconstruct with a different action but same signature
        tampered = TraceEntry(
            token_id=trace_entry.token_id,
            action="tampered",
            resource=trace_entry.resource,
            timestamp=trace_entry.timestamp,
            args_hash=trace_entry.args_hash,
            args_encrypted=trace_entry.args_encrypted,
            result_hash=trace_entry.result_hash,
            signature=trace_entry.signature,
        )
        with pytest.raises(TraceVerificationError):
            verify_trace_entry(tampered, signer_pk)

    def test_wrong_key_fails(self, trace_entry: TraceEntry) -> None:
        wrong_pk, _ = generate_keypair()
        with pytest.raises(TraceVerificationError):
            verify_trace_entry(trace_entry, wrong_pk)


# =============================================================================
# TestDecryptAuditorEnvelope
# =============================================================================


class TestDecryptAuditorEnvelope:

    def test_roundtrip_decrypt(
        self,
        trace_entry: TraceEntry,
        auditor_kem_sk: bytes,
        sample_arguments: bytes,
        sample_token_id: bytes,
    ) -> None:
        recovered = decrypt_auditor_envelope(
            trace_entry.args_encrypted, auditor_kem_sk, sample_token_id,
        )
        assert recovered == sample_arguments

    def test_wrong_key_fails(
        self, trace_entry: TraceEntry, sample_token_id: bytes,
    ) -> None:
        _, wrong_sk = kem.generate_keypair()
        with pytest.raises(TraceDecryptionError):
            decrypt_auditor_envelope(
                trace_entry.args_encrypted, wrong_sk, sample_token_id,
            )

    def test_tampered_envelope_fails(
        self, auditor_kem_sk: bytes, sample_token_id: bytes,
    ) -> None:
        tampered = cbor2.dumps({
            "kem_ct": os.urandom(1088),
            "nonce": os.urandom(12),
            "encrypted": os.urandom(64),
        })
        with pytest.raises(TraceDecryptionError):
            decrypt_auditor_envelope(tampered, auditor_kem_sk, sample_token_id)

    def test_empty_args_roundtrip(
        self,
        auditor_kem_pk: bytes,
        auditor_kem_sk: bytes,
        signer_sk: bytes,
        sample_token_id: bytes,
    ) -> None:
        entry = create_private_trace_entry(
            action="exec",
            resource="qasp://test",
            arguments=b"",
            result=b"",
            auditor_kem_pk=auditor_kem_pk,
            signer_sk=signer_sk,
            token_id=sample_token_id,
        )
        recovered = decrypt_auditor_envelope(
            entry.args_encrypted, auditor_kem_sk, sample_token_id,
        )
        assert recovered == b""


# =============================================================================
# TestVerifyArgsHash
# =============================================================================


class TestVerifyArgsHash:

    def test_correct_args_match(
        self, trace_entry: TraceEntry, sample_arguments: bytes,
    ) -> None:
        assert verify_args_hash(trace_entry, sample_arguments) is True

    def test_wrong_args_mismatch(self, trace_entry: TraceEntry) -> None:
        assert verify_args_hash(trace_entry, b"wrong data") is False


# =============================================================================
# TestRoundTrip
# =============================================================================


class TestRoundTrip:

    def test_full_lifecycle(
        self,
        trace_entry: TraceEntry,
        signer_pk: bytes,
        auditor_kem_sk: bytes,
        sample_arguments: bytes,
        sample_token_id: bytes,
    ) -> None:
        # Verify signature
        assert verify_trace_entry(trace_entry, signer_pk) is True
        # Decrypt
        recovered = decrypt_auditor_envelope(
            trace_entry.args_encrypted, auditor_kem_sk, sample_token_id,
        )
        assert recovered == sample_arguments
        # Verify hash
        assert verify_args_hash(trace_entry, recovered) is True

    def test_cbor_serialization_roundtrip(
        self, trace_entry: TraceEntry,
    ) -> None:
        serialized = trace_entry.to_cbor()
        restored = TraceEntry.from_cbor(serialized)
        assert restored.token_id == trace_entry.token_id
        assert restored.action == trace_entry.action
        assert restored.resource == trace_entry.resource
        assert restored.timestamp == trace_entry.timestamp
        assert restored.args_hash == trace_entry.args_hash
        assert restored.args_encrypted == trace_entry.args_encrypted
        assert restored.result_hash == trace_entry.result_hash
        assert restored.signature == trace_entry.signature


# =============================================================================
# TestAuditorServiceDecrypt
# =============================================================================


class TestAuditorServiceDecrypt:

    def test_auditor_decrypts_trace(
        self,
        auditor_kem_keypair: tuple[bytes, bytes],
        trace_entry: TraceEntry,
        sample_arguments: bytes,
    ) -> None:
        sig_pk, sig_sk = generate_keypair()
        did, _ = create_did(sig_pk)
        service = AuditorService(
            auditor_did=str(did),
            secret_key=sig_sk,
            public_key=sig_pk,
            kem_secret_key=auditor_kem_keypair[1],
            kem_public_key=auditor_kem_keypair[0],
        )
        recovered = service.decrypt_trace_arguments(trace_entry)
        assert recovered == sample_arguments

    def test_auditor_without_kem_raises(
        self, trace_entry: TraceEntry,
    ) -> None:
        sig_pk, sig_sk = generate_keypair()
        did, _ = create_did(sig_pk)
        service = AuditorService(
            auditor_did=str(did),
            secret_key=sig_sk,
            public_key=sig_pk,
        )
        with pytest.raises(TraceDecryptionError, match="not configured"):
            service.decrypt_trace_arguments(trace_entry)
