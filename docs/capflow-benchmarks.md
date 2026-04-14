# CapFlow PoC benchmarks

Run with `python scripts/bench_capflow.py --scm-iters 10000 --sessions 100 --pqc-iters 10`.

## Results

- **SCM validate:** 2.578 us/op (387,852 ops/sec)
- **Session setup latency:** P50=0.006ms, P99=0.032ms
- **Memory per session:** 867 bytes
- **PQC amortization ratio:** _not measurable_ (liboqs unavailable on this host)

## PRD §M6 targets (PoC)

| Metric | Target | Measured |
|---|---|---|
| Fast-path throughput | > 10K msg/sec | 387,852 ops/sec |
| Session setup latency | < 50 ms | P99=0.032 ms |
| Memory per session | < 2 KB | 867 bytes |
| PQC amortization | > 500x | — |
