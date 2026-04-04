# Stealth Performance Benchmarks

## Overview
- Add comprehensive benchmarks comparing performance across stealth levels 0–3
- Two layers: micro-benchmarks (packet construction CPU overhead) and throughput (end-to-end data transfer through tunnel)
- Migrate from unstable `#[bench]` (nightly-only) to criterion (stable Rust)
- All benchmarks grouped by stealth level for easy comparison

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
- **unit tests**: not required for benchmark code itself (benchmarks are measurement, not logic)
- **regression check**: `cargo test -p fake-tcp` must pass after each task (no feature breakage)
- **benchmark validation**: each benchmark must actually run and produce results

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

- [ ] Delete `#[cfg(all(test, feature = "benchmark"))] mod benchmarks { ... }` block from `packet.rs`
- [ ] Remove `#![cfg_attr(feature = "benchmark", feature(test))]` from `lib.rs`
- [ ] Remove `benchmark = []` line from `fake-tcp/Cargo.toml` `[features]`
- [ ] Run `cargo test -p fake-tcp` — must pass (no feature breakage)
- [ ] Run `cargo clippy -p fake-tcp --verbose` — must be clean

### Task 2: Add criterion dependency and micro-benchmark scaffold

**Files:**
- Modify: `fake-tcp/Cargo.toml` — add criterion dev-dependency and `[[bench]]` section
- Create: `fake-tcp/benches/packet_construction.rs` — criterion benchmarks for `build_tcp_packet`

- [ ] Add `criterion = { version = "0.5", features = ["html_reports"] }` to `[dev-dependencies]` in `fake-tcp/Cargo.toml`
- [ ] Add `[[bench]] name = "packet_construction" harness = false` to `fake-tcp/Cargo.toml`
- [ ] Create `fake-tcp/benches/packet_construction.rs` with criterion benchmark groups
- [ ] Benchmark `build_tcp_packet` for all 4 stealth levels × 3 payload sizes (128, 512, 1460 bytes) = 12 benchmarks
- [ ] Use realistic parameters per stealth level: Off → ts_val=0, ts_ecr=0, window=0xFFFF; Basic+ → ts_val=1000, ts_ecr=500, window=0xFFFF; Standard+ → ts_val=5000, ts_ecr=3000, window=29200 (Linux default)
- [ ] Group benchmarks: `stealth_off/`, `stealth_basic/`, `stealth_standard/`, `stealth_full/` with payload size sub-benchmarks
- [ ] Run `cargo bench -p fake-tcp --bench packet_construction` on macOS — must produce results
- [ ] Run `cargo test -p fake-tcp` — must still pass

### Task 3: Add throughput benchmark through tunnel

**Files:**
- Create: `fake-tcp/src/testing.rs` — extracted TestEnv (feature-gated behind `integration-tests`)
- Modify: `fake-tcp/src/lib.rs` — add `pub mod testing` behind feature gate
- Modify: `fake-tcp/tests/common/mod.rs` — re-export from `fake_tcp::testing`
- Create: `fake-tcp/benches/throughput.rs` — criterion benchmarks for end-to-end data transfer
- Modify: `fake-tcp/Cargo.toml` — add `[[bench]]` section for throughput, feature-gate with `integration-tests`

- [ ] Add `[[bench]] name = "throughput" harness = false required-features = ["integration-tests"]` to `fake-tcp/Cargo.toml`
- [ ] Extract `TestEnv` from `tests/common/mod.rs` into feature-gated module `src/testing.rs` (behind `integration-tests` feature) so both tests and benches can import it
- [ ] Update `tests/common/mod.rs` to re-export from `fake_tcp::testing` instead of duplicating
- [ ] Parameterize `setup_test_env()` to accept `StealthLevel` via new `setup_test_env_with_stealth(level)` — original calls new fn with `StealthLevel::Off`
- [ ] Add integration test: `setup_test_env_with_stealth(StealthLevel::Basic)` connects and sends data successfully
- [ ] Create `fake-tcp/benches/throughput.rs` — create `tokio::Runtime` at benchmark group level, use `rt.block_on()` for setup and within `b.iter()`
- [ ] Setup `TestEnv` once per stealth-level group (expensive: netns + iptables), iterate only the send/recv loop
- [ ] Implement throughput: connect client→server, send 10MB in 1460-byte chunks, measure total time
- [ ] Benchmark all 4 stealth levels; tune criterion `measurement_time` and `sample_size` for stable results
- [ ] Group benchmarks: `throughput/stealth_off`, `throughput/stealth_basic`, `throughput/stealth_standard`, `throughput/stealth_full`
- [ ] Run in Docker: `cargo bench -p fake-tcp --bench throughput --features integration-tests` — must produce results
- [ ] Run `cargo test -p fake-tcp --features integration-tests` in Docker — must still pass (including new stealth setup test)

### Task 4: Add benchmark runner script

**Files:**
- Create: `scripts/run-benchmarks.sh` — auto-detects environment like `run-tests.sh`

- [ ] Create `scripts/run-benchmarks.sh` with Docker auto-detection (same pattern as `run-tests.sh`)
- [ ] Outside Docker: build `Dockerfile.test`, run with CMD override: `docker run --privileged --rm phantun-test cargo bench -p fake-tcp --features integration-tests`
- [ ] Inside Docker: run `cargo bench -p fake-tcp --bench packet_construction` + `cargo bench -p fake-tcp --bench throughput --features integration-tests`
- [ ] On macOS without Docker: run only `cargo bench -p fake-tcp --bench packet_construction` (throughput needs Linux)
- [ ] Make script executable (`chmod +x`)
- [ ] Test script locally on macOS (should run micro-benchmarks only)

### Task 5: Verify acceptance criteria

- [ ] `cargo bench -p fake-tcp --bench packet_construction` runs on macOS/stable and produces comparison across 4 stealth levels
- [ ] `cargo bench -p fake-tcp --bench throughput --features integration-tests` runs in Docker and produces throughput comparison
- [ ] `cargo test -p fake-tcp` passes (macOS)
- [ ] `cargo test -p fake-tcp --features integration-tests` passes (Docker)
- [ ] `cargo clippy -p fake-tcp --verbose` is clean
- [ ] `scripts/run-benchmarks.sh` works from macOS (runs micro-benchmarks, skips throughput)
- [ ] Criterion HTML reports generated in `target/criterion/`

### Task 6: [Final] Update documentation

- [ ] Update CLAUDE.md with benchmark commands
- [ ] Run `cargo test -p fake-tcp` — must pass
- [ ] Move this plan to `docs/plans/completed/`

## Technical Details

### Benchmark matrix

| Benchmark | Stealth Levels | Payload Sizes | Environment |
|---|---|---|---|
| `build_tcp_packet` | Off, Basic, Standard, Full | 128, 512, 1460 bytes | macOS/Linux (stable) |
| Throughput | Off, Basic, Standard, Full | 1MB total transfer | Linux/Docker only |

### Criterion group structure
```
packet_construction/
  stealth_off/128
  stealth_off/512
  stealth_off/1460
  stealth_basic/128
  ...
throughput/
  stealth_off
  stealth_basic
  stealth_standard
  stealth_full
```

### TestEnv code sharing
`tests/common/mod.rs` cannot be imported from `benches/`. Solution: extract `TestEnv` into `src/testing.rs` behind `#[cfg(feature = "integration-tests")]`, then both `tests/` and `benches/` import via `fake_tcp::testing::TestEnv`.

### TestEnv parameterization
Currently `setup_test_env()` hardcodes `StealthLevel::Off`. Add `setup_test_env_with_stealth(level: StealthLevel)`. Original function calls new one with `StealthLevel::Off` — zero breakage for existing tests.

### Async runtime in criterion
Criterion's iteration loop is synchronous. Strategy:
- Create `tokio::Runtime::new()` at benchmark group level
- Call `rt.block_on(setup_test_env_with_stealth(level))` once before iterations (expensive: netns + iptables)
- Inside `b.iter()`: only `rt.block_on(send_recv_loop())` — the hot path
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
