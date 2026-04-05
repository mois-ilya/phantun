# Backlog

Future work ideas — not planned yet, just captured for later.

## High Concurrency Benchmark
- Measure how phantun degrades under many simultaneous connections (16, 64, 256) on fixed core count
- Metrics: throughput per connection, tail latency, memory usage, fairness
- Interesting for stealth level 3: contention on CongestionState Mutex, flume buffer pressure (512-bounded)
- Related: `RwLock<HashMap>` in `Shared::tuples` may become bottleneck at high connection counts
- Prerequisite: stealth-performance benchmarks (20260404) should be done first as baseline

## Refactor build_tcp_packet() Parameters into Struct
- `build_tcp_packet()` has 11 positional parameters after mimic work — fragile and hard to extend
- Bundle into a struct (e.g. `TcpBuildConfig`) with `Default` impl
- Existing call sites use `..Default::default()`, new fields don't require updating all callers
- ~20 call sites in packet.rs and lib.rs (tests + production)
- Plan already recommended this ("new params should be bundled into a struct") but subagent skipped it

