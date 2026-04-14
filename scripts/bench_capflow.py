"""CapFlow M6 benchmarks: SCM fast-path throughput, session setup latency,
memory per session, and PQC amortization ratio.

Run: python scripts/bench_capflow.py [--scm-iters N] [--sessions N]
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import time
import tracemalloc
import types
from pathlib import Path


# ---------------------------------------------------------------------------
# Probe for real liboqs *before* importing any qasp module that chains to oqs.
# The installed oqs Python package (liboqs-python) raises SystemExit(1) and
# prints a noisy 5-second git-clone sequence if the native .dll/.so is absent.
# We run the probe in a child subprocess so all side-effects are isolated from
# the benchmark process and its stdout/stderr.
# ---------------------------------------------------------------------------
def _probe_liboqs() -> bool:
    """Return True only if a real, functional liboqs native library is present.

    Runs the check in a subprocess to contain oqs's noisy install attempt.
    """
    import subprocess

    code = (
        "import oqs; sig = oqs.Signature('ML-DSA-65'); "
        "pk = sig.generate_keypair(); "
        "raise SystemExit(0 if len(bytes(pk)) == 1952 else 2)"
    )
    try:
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            timeout=30,
        )
        return result.returncode == 0
    except (Exception, OSError):
        return False


_LIBOQS_AVAILABLE = _probe_liboqs()


# ---------------------------------------------------------------------------
# If liboqs is not available, inject a lightweight stub so that importing the
# relay package (which deep-chains through qasp.crypto.signatures → oqs) does
# not blow up with SystemExit.
# ---------------------------------------------------------------------------
if not _LIBOQS_AVAILABLE and "oqs" not in sys.modules:
    _stub = types.ModuleType("oqs")

    class _StubSig:
        def __init__(self, *a, **k) -> None:
            pass

        def generate_keypair(self) -> bytes:
            return b"\x00" * 32

        def export_secret_key(self) -> bytes:
            return b"\x00" * 32

        def sign(self, msg: bytes) -> bytes:
            return b""

        def verify(self, *a, **k) -> bool:
            return True

        def free(self) -> None:
            pass

    _stub.Signature = _StubSig  # type: ignore[attr-defined]
    _stub.oqs_version = lambda: "0"  # type: ignore[attr-defined]
    sys.modules["oqs"] = _stub


# ---------------------------------------------------------------------------
# Now it is safe to import relay modules.
# ---------------------------------------------------------------------------
from qasp.protocol.relay.scm import (  # noqa: E402
    DIRECTION_A_TO_B,
    EpochKeyRing,
    derive_scm,
    validate_scm,
)


# ---------------------------------------------------------------------------
# Benchmark functions
# ---------------------------------------------------------------------------

def bench_scm_validate(iterations: int) -> tuple[float, float]:
    """Return (microseconds_per_op, ops_per_sec)."""
    ring = EpochKeyRing()
    sid = os.urandom(16)
    cap = os.urandom(48)
    now = int(time.time())
    epoch = ring.current_epoch(now)
    scm = derive_scm(ring.current_key, sid, cap, DIRECTION_A_TO_B, epoch)
    t0 = time.perf_counter()
    for _ in range(iterations):
        assert validate_scm(scm, ring, sid, cap, DIRECTION_A_TO_B, now_ts=now)
    dt = time.perf_counter() - t0
    return (dt / iterations) * 1e6, iterations / dt


def bench_session_setup(sessions: int) -> tuple[float, float]:
    """Return (P50 ms, P99 ms) of relay-side SCM derivation (without PQC)."""
    ring = EpochKeyRing()
    latencies_ms: list[float] = []
    for _ in range(sessions):
        t0 = time.perf_counter()
        sid = os.urandom(16)
        cap = hashlib.sha384(os.urandom(32)).digest()
        now = int(time.time())
        epoch = ring.current_epoch(now)
        derive_scm(ring.current_key, sid, cap, DIRECTION_A_TO_B, epoch)
        derive_scm(ring.current_key, sid, cap, 0x01, epoch)
        latencies_ms.append((time.perf_counter() - t0) * 1000)
    latencies_ms.sort()
    p50 = latencies_ms[len(latencies_ms) // 2]
    p99 = latencies_ms[int(len(latencies_ms) * 0.99)]
    return p50, p99


def bench_memory_per_session(n: int) -> int:
    """Return average bytes per session (Python object footprint)."""
    from qasp.protocol.relay.session import RelaySession

    tracemalloc.start()
    snap_before = tracemalloc.take_snapshot()
    sessions = [
        RelaySession(
            session_id=os.urandom(16),
            initiator_did=f"did:qasp:alice-{i}",
            target_did=f"did:qasp:bob-{i}",
            cap_token_hash=os.urandom(48),
            scm_a=os.urandom(32),
            scm_b=os.urandom(32),
            expires_at=2_000_000_000,
            max_messages=100,
            max_bytes=10_000,
            max_rate=None,
            epoch_installed=1,
            attenuated_token_for_target=b"",
        )
        for i in range(n)
    ]
    snap_after = tracemalloc.take_snapshot()
    diff = snap_after.compare_to(snap_before, "lineno")
    total = sum(stat.size_diff for stat in diff if stat.size_diff > 0)
    tracemalloc.stop()
    # Keep the list alive so the allocations are not reclaimed early.
    _ = sessions
    return total // n if n else 0


def bench_pqc_amortization(iterations: int = 100) -> dict | None:
    """Measure ML-DSA-65 verify latency. Returns None if liboqs is missing."""
    if not _LIBOQS_AVAILABLE:
        return None
    from qasp.crypto.signatures import generate_keypair, sign, verify
    pk, sk = generate_keypair()
    msg = b"hello" * 100
    sig = sign(sk, msg)
    t0 = time.perf_counter()
    for _ in range(iterations):
        assert verify(pk, msg, sig)
    dt = time.perf_counter() - t0
    per_op_us = (dt / iterations) * 1e6
    return {"verify_us": per_op_us, "verify_ops_sec": iterations / dt}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="CapFlow M6 benchmark harness")
    ap.add_argument("--scm-iters", type=int, default=100_000,
                    help="iterations for SCM validate benchmark")
    ap.add_argument("--sessions", type=int, default=1_000,
                    help="number of session setups to simulate")
    ap.add_argument("--pqc-iters", type=int, default=100,
                    help="iterations for ML-DSA-65 verify benchmark")
    ap.add_argument("--out", default="docs/capflow-benchmarks.md",
                    help="path to write the markdown report")
    args = ap.parse_args()

    print("Running CapFlow benchmarks...")
    print(f"  SCM validate iterations: {args.scm_iters:,}")
    print(f"  Sessions simulated:      {args.sessions:,}")
    print(f"  PQC iterations:          {args.pqc_iters:,}")
    print()

    scm_us, scm_ops = bench_scm_validate(args.scm_iters)
    print(f"  SCM validate: {scm_us:.3f} us/op, {scm_ops:,.0f} ops/sec")

    p50_ms, p99_ms = bench_session_setup(args.sessions)
    print(f"  Session setup: P50={p50_ms:.3f}ms, P99={p99_ms:.3f}ms")

    mem = bench_memory_per_session(args.sessions)
    print(f"  Memory per session: {mem:,} bytes")

    pqc = bench_pqc_amortization(args.pqc_iters)
    if pqc is None:
        print("  PQC amortization: not measurable (liboqs unavailable)")
        amortization_line = (
            "- **PQC amortization ratio:** _not measurable_ "
            "(liboqs unavailable on this host)"
        )
    else:
        ratio = pqc["verify_us"] / scm_us
        print(
            f"  ML-DSA-65 verify: {pqc['verify_us']:.2f} us/op "
            f"({pqc['verify_ops_sec']:,.0f} ops/sec)"
        )
        print(f"  Amortization ratio (verify / SCM): {ratio:.1f}x")
        amortization_line = (
            f"- **PQC amortization ratio:** {ratio:.1f}x "
            f"(ML-DSA-65 verify {pqc['verify_us']:.1f} us / "
            f"SCM validate {scm_us:.3f} us)"
        )

    pqc_table_cell = "—" if pqc is None else f"{ratio:.1f}x"

    report = (
        "# CapFlow PoC benchmarks\n\n"
        f"Run with `python scripts/bench_capflow.py --scm-iters {args.scm_iters} "
        f"--sessions {args.sessions} --pqc-iters {args.pqc_iters}`.\n\n"
        "## Results\n\n"
        f"- **SCM validate:** {scm_us:.3f} us/op ({scm_ops:,.0f} ops/sec)\n"
        f"- **Session setup latency:** P50={p50_ms:.3f}ms, P99={p99_ms:.3f}ms\n"
        f"- **Memory per session:** {mem:,} bytes\n"
        f"{amortization_line}\n\n"
        "## PRD §M6 targets (PoC)\n\n"
        "| Metric | Target | Measured |\n"
        "|---|---|---|\n"
        f"| Fast-path throughput | > 10K msg/sec | {scm_ops:,.0f} ops/sec |\n"
        f"| Session setup latency | < 50 ms | P99={p99_ms:.3f} ms |\n"
        f"| Memory per session | < 2 KB | {mem:,} bytes |\n"
        f"| PQC amortization | > 500x | {pqc_table_cell} |\n"
    )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report, encoding="utf-8")
    print(f"\nReport written to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
