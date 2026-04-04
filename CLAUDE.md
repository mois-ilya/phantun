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
./scripts/run-tests.sh       # auto-detects: Docker inside → cargo test, outside → docker build+run
cargo clippy -p fake-tcp --verbose  # quick lint (macOS)
```

`cargo test --workspace` does NOT compile on macOS (tokio-tun is linux-only). `scripts/run-tests.sh` handles this automatically.

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
- **`phantun/`** — Client and server binaries
  - `src/bin/client.rs` — Listens UDP, tunnels through fake-TCP to server
  - `src/bin/server.rs` — Accepts fake-TCP, forwards to backend UDP
  - `src/utils.rs` — Socket helpers (SO_REUSEPORT, IPv6 netlink, pktinfo)

## Code Conventions

- Hot path (send/recv): `AtomicU32` with `Ordering::Relaxed`, no locks, no allocations
- `build_tcp_packet()` is pure — stealth state passed via `TcpBuildOptions`, not read from Socket
- Each stealth level includes all lower levels (`StealthLevel` implements `PartialOrd`)
- Async runtime: Tokio with `features = ["full"]`
- Channels: `flume` (MPMC) for packet routing between tasks
- Graceful shutdown: `tokio_util::CancellationToken`
- Logging: `log` crate, controlled via `RUST_LOG` env var
- Test naming: `test_<concept>_<expectation>`
- Edition 2024, resolver v3

## Gotchas

- `cargo test --workspace` does NOT compile on macOS — tokio-tun is linux-only. Use Docker
- `--stealth 0` must remain byte-identical to pre-stealth output (backward compatibility invariant)
- Level 3 congestion simulation intentionally throttles throughput for realism
- Integration tests require DNAT iptables rules to route TCP to TUN peer address
- `parse_ip_packet` in `packet.rs` panics on malformed/short buffers — known issue, see `#[should_panic]` tests
- Binaries require `CAP_NET_ADMIN` or root for TUN device creation
- Docker integration tests need `--privileged` flag (network namespaces + iptables)
- Cross-compilation uses `cross` tool; MIPS targets require nightly toolchain
