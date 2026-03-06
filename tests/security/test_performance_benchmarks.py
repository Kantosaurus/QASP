"""Performance benchmarks for cryptographic operations.

These tests measure latency and throughput for key QASP operations.
All marked @pytest.mark.slow. Run with: pytest tests/security/test_performance_benchmarks.py -v -m slow -s
"""

from __future__ import annotations

import time

import pytest

from qasp.crypto import hybrid, signatures
from qasp.framing.messages import ClientAuth, ServerHello
from qasp.identity import DID, create_did
from qasp.protocol.accounting import Meter, ReceiptChain
from qasp.protocol.capability import (
    VerbSet,
    attenuate_token,
    create_token,
    verify_delegation_chain,
    verify_token,
)
from qasp.protocol.handshake import (
    Handshake,
    HandshakeFailure,
    HandshakeKeys,
)


def _run_full_handshake() -> tuple[HandshakeKeys, HandshakeKeys]:
    """Execute a complete handshake and return (client_keys, server_keys)."""
    client = Handshake(
        kem_keypair=hybrid.generate_keypair(),
        sig_keypair=signatures.generate_keypair(),
        is_initiator=True,
    )
    server = Handshake(
        kem_keypair=hybrid.generate_keypair(),
        sig_keypair=signatures.generate_keypair(),
        is_initiator=False,
    )

    client_hello = client.create_client_hello()
    server_hello = server.process_client_hello(client_hello)
    assert isinstance(server_hello, ServerHello)

    client_auth = client.process_server_hello(server_hello)
    assert isinstance(client_auth, ClientAuth)

    server_keys = server.process_client_auth(client_auth)
    assert isinstance(server_keys, HandshakeKeys)

    client_keys = client.complete_client_handshake()
    assert isinstance(client_keys, HandshakeKeys)

    return client_keys, server_keys


# =============================================================================
# Handshake Performance
# =============================================================================


@pytest.mark.slow
@pytest.mark.security
class TestHandshakePerformance:
    """Benchmark complete handshake operations."""

    def test_handshake_latency(self) -> None:
        """Measure individual handshake latency over 5 runs."""
        times = []
        for _ in range(5):
            start = time.perf_counter()
            _run_full_handshake()
            elapsed = time.perf_counter() - start
            times.append(elapsed)

        print(f"\nHandshake latency (n=5):")
        print(f"  min: {min(times):.3f}s")
        print(f"  max: {max(times):.3f}s")
        print(f"  avg: {sum(times) / len(times):.3f}s")

        for t in times:
            assert t < 10.0, f"Handshake took {t:.3f}s (>10s sanity limit)"

    def test_handshake_throughput(self) -> None:
        """Measure handshake throughput over 10 runs."""
        n = 10
        start = time.perf_counter()
        for _ in range(n):
            _run_full_handshake()
        elapsed = time.perf_counter() - start

        throughput = n / elapsed
        print(f"\nHandshake throughput (n={n}):")
        print(f"  total: {elapsed:.3f}s")
        print(f"  rate: {throughput:.2f} handshakes/sec")


# =============================================================================
# Token Performance
# =============================================================================


@pytest.mark.slow
@pytest.mark.security
class TestTokenPerformance:
    """Benchmark token creation and verification."""

    def test_token_creation_time(self) -> None:
        """Measure average token creation time over 20 runs."""
        pk, sk = signatures.generate_keypair()
        subject_pk, _ = signatures.generate_keypair()
        issuer_did, _ = create_did(pk)
        subject_did, _ = create_did(subject_pk)

        times = []
        for _ in range(20):
            start = time.perf_counter()
            create_token(
                issuer_did=issuer_did,
                issuer_secret_key=sk,
                subject_did=subject_did,
                resource_uri="qasp://bench/resource",
                verbs={"read", "write"},
            )
            elapsed = time.perf_counter() - start
            times.append(elapsed)

        avg = sum(times) / len(times)
        print(f"\nToken creation (n=20):")
        print(f"  min: {min(times) * 1000:.1f}ms")
        print(f"  max: {max(times) * 1000:.1f}ms")
        print(f"  avg: {avg * 1000:.1f}ms")

    def test_token_verification_time(self) -> None:
        """Measure average token verification time over 20 runs."""
        pk, sk = signatures.generate_keypair()
        subject_pk, _ = signatures.generate_keypair()
        issuer_did, _ = create_did(pk)
        subject_did, _ = create_did(subject_pk)

        token = create_token(
            issuer_did=issuer_did,
            issuer_secret_key=sk,
            subject_did=subject_did,
            resource_uri="qasp://bench/resource",
            verbs={"read", "write"},
        )

        times = []
        for _ in range(20):
            start = time.perf_counter()
            verify_token(token, pk, check_expiry=True)
            elapsed = time.perf_counter() - start
            times.append(elapsed)

        avg = sum(times) / len(times)
        print(f"\nToken verification (n=20):")
        print(f"  min: {min(times) * 1000:.1f}ms")
        print(f"  max: {max(times) * 1000:.1f}ms")
        print(f"  avg: {avg * 1000:.1f}ms")

    def test_delegation_chain_depth_vs_verification_time(self) -> None:
        """Measure verification time as delegation chain depth increases."""
        issuer_pk, issuer_sk = signatures.generate_keypair()
        issuer_did, issuer_doc = create_did(issuer_pk)

        from qasp.identity import DIDRegistry
        from qasp.protocol.capability import LocalDIDResolver

        registry = DIDRegistry()
        registry.register(issuer_doc)

        max_depth = 5
        # Pre-generate all keypairs for the chain
        keypairs = []
        dids = []
        for _ in range(max_depth + 1):
            kp = signatures.generate_keypair()
            keypairs.append(kp)
            did, doc = create_did(kp[0])
            dids.append(did)
            registry.register(doc)

        resolver = LocalDIDResolver(registry)

        print(f"\nDelegation chain verification time:")
        print(f"  {'Depth':<8} {'Time (ms)':<12}")
        print(f"  {'-----':<8} {'---------':<12}")

        for depth in range(1, max_depth + 1):
            # Build chain of given depth
            root = create_token(
                issuer_did=issuer_did,
                issuer_secret_key=issuer_sk,
                subject_did=dids[0],
                resource_uri="qasp://bench/resource",
                verbs={"read", "write"},
                max_delegation_depth=max_depth,
            )

            chain = [root]
            for d in range(depth):
                parent = chain[-1]
                child = attenuate_token(
                    parent_token=parent,
                    delegator_secret_key=keypairs[d][1],
                    new_subject_did=dids[d + 1],
                )
                chain.append(child)

            start = time.perf_counter()
            verify_delegation_chain(
                chain,
                issuer_pk,
                did_resolver=resolver,
                check_expiry=True,
            )
            elapsed = time.perf_counter() - start

            print(f"  {depth:<8} {elapsed * 1000:.1f}")

            if depth == max_depth:
                assert elapsed < 30.0, (
                    f"Depth-{depth} chain verification took {elapsed:.3f}s (>30s limit)"
                )


# =============================================================================
# Metering Performance
# =============================================================================


@pytest.mark.slow
@pytest.mark.security
class TestMeteringPerformance:
    """Benchmark metering operations."""

    def test_receipt_generation_time(self) -> None:
        """Measure per-receipt generation time over 20 receipts."""
        pk, sk = signatures.generate_keypair()
        meter = Meter(session_id=b"bench_session", meter_id=b"bench_meter", issuer="bench")
        prev_hash = b""

        times = []
        for i in range(20):
            meter.record(resource="res/compute", operation="invoke", units=1)
            start = time.perf_counter()
            receipt = meter.generate_receipt(sk, prev_hash=prev_hash)
            elapsed = time.perf_counter() - start
            times.append(elapsed)
            prev_hash = receipt.compute_hash()

        avg = sum(times) / len(times)
        print(f"\nReceipt generation (n=20):")
        print(f"  min: {min(times) * 1000:.1f}ms")
        print(f"  max: {max(times) * 1000:.1f}ms")
        print(f"  avg: {avg * 1000:.1f}ms")

    def test_receipt_chain_verification_time(self) -> None:
        """Build 20-receipt chain, time full verification."""
        pk, sk = signatures.generate_keypair()
        meter = Meter(session_id=b"bench_session", meter_id=b"bench_meter", issuer="bench")
        chain = ReceiptChain()
        prev_hash = b""

        for i in range(20):
            meter.record(resource="res/compute", operation="invoke", units=i + 1)
            receipt = meter.generate_receipt(sk, prev_hash=prev_hash)
            chain.append(receipt)
            prev_hash = receipt.compute_hash()

        start = time.perf_counter()
        chain.verify(pk)
        elapsed = time.perf_counter() - start

        print(f"\nReceipt chain verification (n=20 receipts):")
        print(f"  time: {elapsed * 1000:.1f}ms")
        print(f"  per-receipt: {elapsed / 20 * 1000:.1f}ms")
