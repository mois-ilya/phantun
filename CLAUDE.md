# Phantun

UDP-to-TCP obfuscator. Rust workspace with two crates: `fake-tcp` (userspace TCP stack library) and `phantun` (client/server binaries).

## Build & Run

```bash
cargo build                     # debug build
cargo build --release           # release build
cargo clippy --verbose          # lint (CI runs this)
```

## Testing

```bash
# Unit tests (run anywhere)
cargo test --workspace

# Integration tests (require Linux network namespaces — Docker only)
docker build -f Dockerfile.test -t phantun-test .
docker run --privileged phantun-test
```

Integration tests use the `integration-tests` feature flag on `fake-tcp` and require `--privileged` for network namespace creation.

## Architecture

- **`fake-tcp/`** — Core library. Userspace TCP stack over TUN interface.
  - `lib.rs` — `Stack` (connection manager) and `Socket` (per-connection async I/O)
  - `packet.rs` — TCP/IP packet construction/parsing (IPv4 + IPv6)
- **`phantun/`** — Client and server binaries
  - `src/bin/client.rs` — Listens UDP, tunnels through fake-TCP to server
  - `src/bin/server.rs` — Accepts fake-TCP, forwards to backend UDP
  - `src/utils.rs` — Socket helpers (SO_REUSEPORT, IPv6 netlink, pktinfo)

## Code Conventions

- Async runtime: Tokio with `features = ["full"]`
- Channels: `flume` (MPMC) for packet routing between tasks
- Graceful shutdown: `tokio_util::CancellationToken`
- Logging: `log` crate, controlled via `RUST_LOG` env var
- Test naming: `test_<concept>_<expectation>`
- Edition 2024, resolver v3

## Gotchas

- `fake-tcp` integration tests only work on Linux (need network namespaces + TUN)
- `parse_ip_packet` in `packet.rs` panics on malformed/short buffers — known issue, see TODO comments and `#[should_panic]` tests
- Binaries require `CAP_NET_ADMIN` or root for TUN device creation
- Docker integration tests need `--privileged` flag
- Cross-compilation uses `cross` tool; MIPS targets require nightly toolchain
