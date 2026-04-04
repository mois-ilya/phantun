# Backlog

Future work ideas — not planned yet, just captured for later.

## High Concurrency Benchmark
- Measure how phantun degrades under many simultaneous connections (16, 64, 256) on fixed core count
- Metrics: throughput per connection, tail latency, memory usage, fairness
- Interesting for stealth level 3: contention on cwnd atomics, flume buffer pressure (512-bounded)
- Related: `RwLock<HashMap>` in `Shared::tuples` may become bottleneck at high connection counts
- Prerequisite: stealth-performance benchmarks (20260404) should be done first as baseline

## Fix Stealth Level 3 Thread-Safety
- Race conditions in `Socket::recv` congestion control (`lib.rs:384-461`):
  - `dup_ack_count` check + cwnd halving not atomic — can fire twice under concurrent recv
  - `cwnd` slow start increment: load-compute-store TOCTOU
  - `seq.store(last_acked)` in send vs `seq.fetch_add` — concurrent sends can corrupt seq
- Not a data correctness issue (packets still delivered), but distorts congestion simulation
- Fix approach: CAS-loop or Mutex for level 3 state updates in recv path
- After fix, re-run stealth-performance benchmarks to measure improvement
