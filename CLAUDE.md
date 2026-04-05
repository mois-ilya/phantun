# Phantun

UDP-to-TCP obfuscator. Rust workspace with two crates: `fake-tcp` (userspace TCP stack library) and `phantun` (client/server binaries).

## Build & Run

```bash
cargo build                     # debug build
cargo build --release           # release build
cargo clippy --verbose          # lint (CI runs this)
```

## Stealth Mode

`--stealth <0-3>` on client/server controls TCP fingerprint realism:
- `0` — default, original behavior (byte-identical to pre-stealth code)
- `1` — random ISN, Linux-like SYN options (MSS+SACK+TS+wscale), timestamps on all packets, PSH on data
- `2` — dynamic window, frequent ACK, correct ts_ecr echo
- `3` — dup ACK tracking, send window constraint, congestion simulation (may throttle throughput)

## Testing

```bash
./scripts/run-tests.sh              # tests (unit + integration)
./scripts/run-benchmarks.sh         # benchmarks (micro + throughput)
cargo clippy -p fake-tcp --verbose  # lint
```

## Git Hooks

```bash
# One-time setup after clone:
git config core.hooksPath .githooks
```

- **pre-commit**: always runs tests. `RUN_TESTS=1` (Ralphex Docker) adds clippy + runs directly; otherwise runs via Docker
- **pre-push**: always full test suite
- If pre-commit blocks due to test failures, you can `git commit --no-verify` to skip the hook and fix the failing test in a separate commit. This avoids getting stuck in a fix loop. All tests must pass before finishing your work.

## Architecture

- **`fake-tcp/`** — Core library. Userspace TCP stack over TUN interface.
  - `lib.rs` — `Stack` (connection manager), `Socket` (per-connection async I/O), `StealthLevel` enum
  - `packet.rs` — TCP/IP packet construction/parsing (IPv4 + IPv6), `TcpBuildOptions` for stealth params
  - `testing.rs` — Integration test helpers (`TestEnv`, netns/TUN setup), feature-gated behind `integration-tests`
  - `benches/` — Criterion benchmarks: `packet_construction` (per-level microbench), `throughput` (TUN tunnel data transfer, requires `integration-tests` feature)
- **`scripts/`** — Runner scripts: `run-tests.sh` (test suite), `run-benchmarks.sh` (benchmarks). Auto-detect Docker vs native environment.
- **`phantun/`** — Client and server binaries
  - `src/bin/client.rs` — Listens UDP, tunnels through fake-TCP to server
  - `src/bin/server.rs` — Accepts fake-TCP, forwards to backend UDP
  - `src/utils.rs` — Socket helpers (SO_REUSEPORT, IPv6 netlink, pktinfo)

## Code Conventions

- Hot path (send/recv): `AtomicU32` with `Ordering::Relaxed` for levels 0-2; Level 3 uses `Mutex<CongestionState>` for grouped congestion state updates (cwnd, ssthresh, dup_ack_count, etc.)
- `build_tcp_packet()` is pure — stealth state passed via `TcpBuildOptions`, not read from Socket
- Each stealth level includes all lower levels (`StealthLevel` implements `PartialOrd`)
- Async runtime: Tokio with `features = ["full"]`
- Channels: `flume` (MPMC) for packet routing between tasks
- Graceful shutdown: `tokio_util::CancellationToken`
- Logging: `log` crate, controlled via `RUST_LOG` env var
- Test naming: `test_<concept>_<expectation>`
- Edition 2024, resolver v3

## Gotchas

- `--stealth 0` must remain byte-identical to pre-stealth output (backward compatibility invariant)
- Level 3 congestion simulation intentionally throttles throughput for realism
- Integration tests require DNAT iptables rules to route TCP to TUN peer address
- `parse_ip_packet` returns `None` on malformed/short buffers; callers log a warning and continue
- Binaries require `CAP_NET_ADMIN` or root for TUN device creation
- Cross-compilation uses `cross` tool; MIPS targets require nightly toolchain
- Integration test helpers live in `fake-tcp/src/testing.rs` (not `tests/common/mod.rs`, which is a thin re-export)
- `cargo test --workspace` does not compile on macOS (tokio-tun is Linux-only); use `scripts/run-tests.sh`
- Integration tests and throughput benchmarks require Linux (`--privileged` Docker for network namespaces + iptables)
