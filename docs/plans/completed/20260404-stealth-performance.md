# Stealth Performance Benchmarks

## Overview
- Add comprehensive benchmarks comparing performance across stealth levels 0–3
- Two layers: micro-benchmarks (packet construction CPU overhead) and throughput (end-to-end data transfer through tunnel)
- Throughput benchmarks in single-core (1 TUN queue, 1 connection) and multi-core (N TUN queues, 4*N parallel connections) modes — matching the original README benchmark methodology
- Migrate from unstable `#[bench]` (nightly-only) to criterion (stable Rust)
- All benchmarks grouped by stealth level and core count for easy comparison

## Context (from discovery)
- **Existing benchmarks**: 3 `#[bench]` functions in `fake-tcp/src/packet.rs:1372-1437` — only StealthLevel::Off, requires nightly
- **Feature flag**: `benchmark = []` in `fake-tcp/Cargo.toml` + `#![cfg_attr(feature = "benchmark", feature(test))]` in `lib.rs`
- **TestEnv**: `fake-tcp/tests/common/mod.rs` — full network namespace isolation with TUN, veth, DNAT, ready for throughput testing
- **Stack/Socket API**: `Stack::new(tun, local_ip, local_ip6, stealth)`, `Socket::send(&[u8])`, `Socket::recv(&mut [u8])` — async, channel-backed
- **StealthLevel variants**: Off(0), Basic(1), Standard(2), Full(3)
- **Docker**: `Dockerfile.test` with iproute2, iptables, `--privileged` — ready for integration benchmarks
- **No criterion dependency** anywhere in the workspace currently
- **Nightly not installed** — only `stable-aarch64-apple-darwin`

## Development Approach
- **testing approach**: Regular (benchmarks are the deliverable, not tests)
- Complete each task fully before moving to the next
- Make small, focused changes
- **CRITICAL: all existing tests must pass after each task** — no regressions
- **CRITICAL: update this plan file when scope changes during implementation**
- Maintain backward compatibility (existing test infrastructure untouched)

## Testing Strategy
- **Tests**: `./scripts/run-tests.sh` (handles sudo and environment automatically)
- **Benchmarks**: `./scripts/run-benchmarks.sh` (handles sudo and environment automatically)
- **Clippy**: `cargo clippy --verbose`

## Progress Tracking
- Mark completed items with `[x]` immediately when done
- Add newly discovered tasks with ➕ prefix
- Document issues/blockers with ⚠️ prefix

## Implementation Steps

### Task 1: Remove legacy nightly benchmarks and `benchmark` feature

**Files:**
- Modify: `fake-tcp/src/packet.rs` — delete `mod benchmarks` (lines 1372–1437)
- Modify: `fake-tcp/src/lib.rs` — remove `#![cfg_attr(feature = "benchmark", feature(test))]`
- Modify: `fake-tcp/Cargo.toml` — remove `benchmark = []` from `[features]`

- [x] Delete `#[cfg(all(test, feature = "benchmark"))] mod benchmarks { ... }` block from `packet.rs`
- [x] Remove `#![cfg_attr(feature = "benchmark", feature(test))]` from `lib.rs`
- [x] Remove `benchmark = []` line from `fake-tcp/Cargo.toml` `[features]`
- [x] Run `cargo test -p fake-tcp` — must pass (no feature breakage)
- [x] Run `cargo clippy -p fake-tcp --verbose` — must be clean

### Task 2: Add criterion dependency and micro-benchmark scaffold

**Files:**
- Modify: `fake-tcp/Cargo.toml` — add criterion dev-dependency and `[[bench]]` section
- Create: `fake-tcp/benches/packet_construction.rs` — criterion benchmarks for `build_tcp_packet`

- [x] Add `criterion = { version = "0.5", features = ["html_reports"] }` to `[dev-dependencies]` in `fake-tcp/Cargo.toml`
- [x] Add `[[bench]] name = "packet_construction" harness = false` to `fake-tcp/Cargo.toml`
- [x] Create `fake-tcp/benches/packet_construction.rs` with criterion benchmark groups
- [x] Benchmark `build_tcp_packet` for all 4 stealth levels × 3 payload sizes (128, 512, 1460 bytes) = 12 benchmarks
- [x] Use realistic parameters per stealth level: Off → flags=ACK, ts_val=0, ts_ecr=0, window=0xFFFF; Basic+ → flags=ACK|PSH (as real code does for data), ts_val=1000, ts_ecr=500, window=0xFFFF; Standard+ → flags=ACK|PSH, ts_val=5000, ts_ecr=3000, window=29200. Note: Off ignores ts_val/ts_ecr — values are for API completeness only
- [x] Group benchmarks: `stealth_off/`, `stealth_basic/`, `stealth_standard/`, `stealth_full/` with payload size sub-benchmarks
- [x] Run `cargo bench -p fake-tcp --bench packet_construction` on macOS — must produce results
- [x] Run `cargo test -p fake-tcp` — must still pass

### Task 3: Add throughput benchmark through tunnel

**Files:**
- Create: `fake-tcp/src/testing.rs` — extracted TestEnv (feature-gated behind `integration-tests`)
- Modify: `fake-tcp/src/lib.rs` — add `pub mod testing` behind feature gate
- Modify: `fake-tcp/tests/common/mod.rs` — re-export from `fake_tcp::testing`
- Create: `fake-tcp/benches/throughput.rs` — criterion benchmarks for end-to-end data transfer
- Modify: `fake-tcp/Cargo.toml` — add `[[bench]]` section for throughput, feature-gate with `integration-tests`

- [x] Add `[[bench]] name = "throughput" harness = false required-features = ["integration-tests"]` to `fake-tcp/Cargo.toml`
- [x] Extract `TestEnv` and ALL helpers (`unique_suffix`, `run_ip`, `netns_exec`, `create_tun_in_netns`) from `tests/common/mod.rs` into `src/testing.rs` (behind `integration-tests` feature). Add `tun_queues: usize` parameter to `create_tun_in_netns` and call `.queues(tun_queues)` on `TunBuilder`
- [x] Update `tests/common/mod.rs` to re-export from `fake_tcp::testing` instead of duplicating
- [x] Parameterize setup: `setup_test_env_with_config(stealth: StealthLevel, tun_queues: usize)` — controls both stealth level and TUN queue count. Original `setup_test_env()` calls it with `(StealthLevel::Off, 1)`
- [x] TUN creation: pass `tun_queues` to `TunBuilder::new().queues(tun_queues)` for client and server TUNs. `raw_client_tun` always stays single-queue (not used by benchmarks)
- [x] Add integration test: `setup_test_env_with_config(StealthLevel::Basic, 1)` connects and sends data successfully
- [x] Add integration test: `setup_test_env_with_config(StealthLevel::Off, 4)` — verify multi-queue TUN connect + data transfer works before relying on it in benchmarks
- [x] Create `fake-tcp/benches/throughput.rs` with two benchmark group levels: core count (1, 4) × stealth level (0–3)
- [x] **Single-core mode**: `tokio::runtime::Builder::new_multi_thread().worker_threads(1)`, TUN with `.queues(1)`, 1 Socket pair sending 10MB
- [x] **Multi-core mode**: `tokio::runtime::Builder::new_multi_thread().worker_threads(N)`, TUN with `.queues(N)`, 4*N parallel Socket pairs each sending 10MB/(4*N) concurrently via `JoinSet`. Setup verifies all TUN queues are covered via `Socket::tun_queue_id()` and retries if random assignment misses any queue. Note: `connect`/`accept` are `&mut self` — establish all connections **sequentially**, then measure only the parallel send/recv loop
- [x] Setup `TestEnv` + establish N Socket pairs outside `b.iter()`. Only the send/recv loop over connected Sockets goes inside `b.iter()`. TestEnv creation is expensive (~500ms: netns + iptables), must be amortized across iterations
- [x] Tune criterion `measurement_time` and `sample_size` for stable results
- [x] Group benchmarks: `throughput/{cores}core/stealth_{level}` — e.g. `throughput/1core/stealth_off`, `throughput/4core/stealth_full`
- [x] Run `./scripts/run-benchmarks.sh` — exit code 0, output includes `=== BENCHMARKS COMPLETE ===`
- [x] Run `./scripts/run-tests.sh` — exit code 0, output includes `=== ALL TESTS PASSED ===`

### Task 4: Add benchmark runner script

**Files:**
- Create: `scripts/run-benchmarks.sh` — auto-detects environment like `run-tests.sh`

- [x] Create `scripts/run-benchmarks.sh` with environment detection (same pattern as `run-tests.sh`)
- [x] Inside Docker: run `cargo bench -p fake-tcp --bench packet_construction` + `cargo bench -p fake-tcp --bench throughput --features integration-tests`
- [x] Outside Docker + Docker available: build `Dockerfile.test`, run with CMD override: `docker run --privileged --rm phantun-test cargo bench -p fake-tcp --features integration-tests`
- [x] Outside Docker + no Docker: run only `cargo bench -p fake-tcp --bench packet_construction` (throughput needs Linux/Docker)
- [x] Make script executable (`chmod +x`)
- [x] Test script locally on macOS

### Task 5: Verify acceptance criteria

- [x] `cargo bench -p fake-tcp --bench packet_construction` runs on macOS/stable and produces comparison across 4 stealth levels
- [x] Benchmarks and tests verified in Task 3
- [x] `cargo clippy -p fake-tcp --verbose` is clean
- [x] `scripts/run-benchmarks.sh` works from macOS (runs micro-benchmarks, skips throughput)
- [x] Criterion HTML reports generated in `target/criterion/`

### Task 6: [Final] Update documentation

- [x] Update CLAUDE.md with benchmark commands
- [x] Move this plan to `docs/plans/completed/` (create directory if needed)

## Technical Details

### Benchmark matrix

| Benchmark | Stealth Levels | Params | Environment |
|---|---|---|---|
| `build_tcp_packet` | Off, Basic, Standard, Full | 3 payload sizes (128, 512, 1460) | macOS/Linux (stable) |
| Throughput 1-core | Off, Basic, Standard, Full | 1 TUN queue, 1 connection, 10MB | Linux/Docker only |
| Throughput 4-core | Off, Basic, Standard, Full | 4 TUN queues, 16 connections (4×4), 10MB total | Linux/Docker only |

Total: 12 micro + 8 throughput = 20 benchmarks

### Criterion group structure
```
packet_construction/
  stealth_off/128
  stealth_off/512
  stealth_off/1460
  stealth_basic/128
  ...
throughput/
  1core/stealth_off
  1core/stealth_basic
  1core/stealth_standard
  1core/stealth_full
  4core/stealth_off
  4core/stealth_basic
  4core/stealth_standard
  4core/stealth_full
```

### TestEnv code sharing
`tests/common/mod.rs` cannot be imported from `benches/`. Solution: extract `TestEnv` into `src/testing.rs` behind `#[cfg(feature = "integration-tests")]`, then both `tests/` and `benches/` import via `fake_tcp::testing::TestEnv`.

### TestEnv parameterization
Currently `setup_test_env()` hardcodes `StealthLevel::Off` and creates single-queue TUNs. Add `setup_test_env_with_config(stealth: StealthLevel, tun_queues: usize)`. Original `setup_test_env()` calls new fn with `(StealthLevel::Off, 1)` — zero breakage.

### Multi-core scaling model
Phantun's multi-core scaling comes from three layers working together:
1. **Multi-queue TUN** — `TunBuilder::new().queues(N)` creates N kernel-level packet queues
2. **Stack reader tasks** — `Stack::new(tun_vec)` spawns one reader per TUN fd
3. **Parallel connections** — 4*N Socket pairs sending concurrently saturate all queues

All three must scale together. 4 worker threads with 1 TUN queue won't scale — bottleneck is the single fd. The benchmark controls all three via `(worker_threads, tun_queues, num_connections)` = `(N, N, 4*N)`. Queue coverage is verified via `Socket::tun_queue_id()` after connection setup; if any queue is missed, the benchmark retries with a fresh `TestEnv`.

### Async runtime in criterion
Criterion's iteration loop is synchronous. Strategy:
- **Single-core**: `tokio::runtime::Builder::new_multi_thread().worker_threads(1).build()`
- **Multi-core**: `tokio::runtime::Builder::new_multi_thread().worker_threads(4).build()`
- Call `rt.block_on(setup_test_env_with_config(level, N))` once before iterations (expensive: netns + iptables)
- Inside `b.iter()`: `rt.block_on(send_recv_loop())` — the hot path
- Multi-core send_recv_loop: spawn 4*N tasks via `JoinSet`, each task sends 10MB/(4*N) through its own Socket pair, await all
- Use `criterion::BenchmarkGroup::measurement_time()` and `sample_size()` for stable results

### Micro-benchmark parameters per stealth level
- **Off**: ts_val=0, ts_ecr=0, window=0xFFFF (original behavior)
- **Basic**: ts_val=1000, ts_ecr=500, window=0xFFFF (timestamps active)
- **Standard**: ts_val=5000, ts_ecr=3000, window=29200 (dynamic window)
- **Full**: ts_val=5000, ts_ecr=3000, window=29200 (same params, congestion path in stack not packet builder)

### Data volume for throughput
- Send 10MB (10_485_760 bytes) in chunks of 1460 bytes (MSS)
- Measure wall-clock time for complete transfer
- Criterion handles statistical analysis (iterations, confidence intervals)
- Tune `measurement_time` (10-30s) and `sample_size` (10-50) for stability

## Post-Completion

**CI integration** (separate plan):
- GitHub Actions job for criterion benchmarks
- Baseline storage and regression detection
- PR comments with performance delta

**Absolute throughput numbers** (future):
- iperf3-based benchmark through actual client/server binaries
- Compare with udp2raw (update the README benchmark image)
