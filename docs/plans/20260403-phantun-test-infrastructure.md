# Phantun Test Infrastructure

## Overview

Cover the current Phantun fake TCP implementation with tests **before** making any fork changes. Tests capture existing behavior as a snapshot, ensuring future changes (realistic TCP fingerprint for ТСПУ evasion) behind feature flags remain backward-compatible.

Currently: zero tests in the entire project. CI runs only `clippy` + `build`.

Two test layers:
1. **Packet structure unit tests** — pure functions, runs on macOS with `cargo test`
2. **Handshake + data flow integration tests** — requires Linux TUN + network namespaces, runs in Docker

Wire fingerprint tests (raw packet capture) deferred to the fork implementation plan — unit tests already verify packet structure byte-by-byte, making raw capture redundant at this stage.

### Acceptance Criteria

1. `cargo test -p fake-tcp` passes on macOS (unit tests)
2. `docker run --privileged phantun-test` passes (integration tests)
3. All current behavioral invariants documented as test assertions
4. Zero production `.rs` code changes (only `Cargo.toml` feature flag + test files + Docker infrastructure)

## Context

**Key files:**
- `fake-tcp/src/packet.rs` — `build_tcp_packet()` and `parse_ip_packet()`, pure functions
- `fake-tcp/src/lib.rs` — `Socket`, `Stack`, handshake FSM + minimal seq/ack tracking
- `fake-tcp/Cargo.toml` — crate config, already has `[features]` with `benchmark = []`
- `docker/Dockerfile` — existing deployment Dockerfile (not for tests)
- `.github/workflows/rust.yml` — CI, currently clippy + build only

**Current behavior to snapshot:**
- SYN packets: TCP options = NOP + wscale(14), doff=6, window=0xFFFF
- Data packets: no TCP options, doff=5, window=0xFFFF, flags=ACK only
- seq starts at 0; post-handshake seq = 1 (incremented by SYN)
- Server requires SYN(seq==0), sends RST otherwise
- ACK updates only in recv(), idle ACK after 128MB threshold
- No timestamps anywhere
- `parse_ip_packet()` panics (unwrap) on malformed/short buffers; returns None only for non-TCP protocol or unknown IP version

**Client/Server asymmetry in Stack::new():**
- Client: `Stack::new(tun, tun_peer, ...)` — uses TUN's **peer** address as local_ip (source of outgoing packets)
- Server: `Stack::new(tun, tun_local, ...)` — uses TUN's **own** address as local_ip
- Test helpers MUST replicate this pattern, otherwise handshake fails

**Constraints:**
- macOS development, Docker installed (daemon not running currently)
- `tokio-tun` is Linux-only — Socket/Stack tests require Linux
- No production `.rs` code changes; only Cargo.toml feature flag
- Tests document current behavior, not desired future behavior

## Development Approach

- **Testing approach**: we ARE writing the tests — this is the deliverable
- Complete each task fully before moving to the next
- Layer 1 runs on macOS with `cargo test`
- Layer 2 runs in Docker with `cargo test --features integration-tests`
- **CRITICAL: all tests must pass before starting next task**
- **CRITICAL: update this plan file when scope changes during implementation**

## Progress Tracking

- Mark completed items with `[x]` immediately when done
- Add newly discovered tasks with ➕ prefix
- Document issues/blockers with ⚠️ prefix
- Update plan if implementation deviates from original scope

## Implementation Steps

### Task 1: Add `integration-tests` feature flag to fake-tcp

**Files:**
- Modify: `fake-tcp/Cargo.toml`

- [ ] Add `integration-tests = []` to the existing `[features]` section (alongside `benchmark`)
- [ ] Verify `cargo test -p fake-tcp` still works (no tests yet, but compilation OK)
- [ ] Verify `cargo test -p fake-tcp --features integration-tests` compiles

### Task 2: Unit tests for `build_tcp_packet()` — SYN packets

**Files:**
- Modify: `fake-tcp/src/packet.rs` (add `#[cfg(test)] mod tests` at bottom)

- [ ] Add test module boilerplate with `use super::*` and necessary imports
- [ ] Test IPv4 SYN: total length = 20 (IP) + 24 (TCP with options) = 44 bytes
- [ ] Test IPv4 SYN: IP header fields (version=4, protocol=TCP, TTL=64, DF flag)
- [ ] Test IPv4 SYN: TCP flags = SYN, doff=6, window=0xFFFF
- [ ] Test IPv4 SYN: TCP options = NOP + wscale(14), exactly 4 bytes
- [ ] Test IPv4 SYN: seq and ack match input parameters
- [ ] Test IPv4 SYN: checksum is valid (recompute and compare)
- [ ] Test IPv6 SYN: same TCP-level checks, IPv6 header (version=6, hop_limit=64)
- [ ] Run `cargo test -p fake-tcp` — all pass

### Task 3: Unit tests for `build_tcp_packet()` — data and control packets

**Files:**
- Modify: `fake-tcp/src/packet.rs`

- [ ] Test IPv4 ACK data packet: total length = 20 (IP) + 20 (TCP) + payload_len
- [ ] Test IPv4 ACK data packet: doff=5, no TCP options, window=0xFFFF
- [ ] Test IPv4 ACK data packet: payload bytes match input
- [ ] Test IPv4 ACK data packet: flags = ACK only (no PSH)
- [ ] Test RST packet: flags = RST|ACK, no payload, correct seq/ack
- [ ] Test SYN|ACK packet: flags correct, options same as SYN (NOP + wscale)
- [ ] Test packet with no payload (ACK-only, no data): length = IP + TCP headers only
- [ ] Test IPv6 data packet: same TCP-level checks
- [ ] Run `cargo test -p fake-tcp` — all pass

### Task 4: Unit tests for `parse_ip_packet()` and round-trip

**Files:**
- Modify: `fake-tcp/src/packet.rs`

- [ ] Test round-trip IPv4 SYN: build → parse → verify all TCP fields match
- [ ] Test round-trip IPv4 data: build → parse → verify payload, seq, ack, flags
- [ ] Test round-trip IPv6 SYN: build → parse → verify all fields
- [ ] Test round-trip IPv6 data: build → parse → verify payload
- [ ] Test parse with non-TCP IPv4 protocol returns None (set protocol to UDP in crafted IP header)
- [ ] Test parse with unknown IP version (not 4, not 6) returns None
- [ ] Test parse panics on empty buffer — `#[should_panic]`
- [ ] Test parse panics on valid IPv4 header but too short for TCP — `#[should_panic]`
- [ ] Run `cargo test -p fake-tcp` — all pass

### Task 5: Create Dockerfile.test and .dockerignore

**Files:**
- Create: `Dockerfile.test`
- Create: `.dockerignore`

- [ ] Create `.dockerignore` excluding `target/`, `.git/`, `*.md`, `docs/`
- [ ] Base image: `rust:latest`
- [ ] Install `iproute2` (for TUN/namespace management)
- [ ] Separate RUN layer: `cargo build -p fake-tcp --features integration-tests --tests` (caches dependencies)
- [ ] Copy workspace source after dependency cache layer
- [ ] Set working directory
- [ ] Default CMD: `cargo test -p fake-tcp --features integration-tests`
- [ ] Document required Docker flags in comment: `--privileged` (needed for network namespaces)
- [ ] Verify Dockerfile builds: `docker build -f Dockerfile.test -t phantun-test .`

### Task 6: Integration test helpers (network namespace + TUN setup)

**Files:**
- Create: `fake-tcp/tests/common/mod.rs`

- [ ] Helper to create network namespace (`ip netns add`)
- [ ] Helper to create veth pair connecting two namespaces
- [ ] Helper to create and configure TUN inside a namespace (using `setns()` in a dedicated thread, then returning fd)
- [ ] Helper to set up ip routes + `ip_forward=1` inside each namespace
- [ ] Helper to create client+server Stack pair: client Stack with `local_ip=tun_peer`, server Stack with `local_ip=tun_local`
- [ ] Cleanup helper (delete namespaces on drop)
- [ ] Gate entire file with `#![cfg(feature = "integration-tests")]`
- [ ] Verify compiles in Docker: `docker run --privileged phantun-test cargo test -p fake-tcp --features integration-tests --no-run`

### Task 7: Integration tests — handshake

**Files:**
- Create: `fake-tcp/tests/handshake.rs`

- [ ] Gate with `#![cfg(feature = "integration-tests")]`
- [ ] Test: client connect + server accept → both reach Established
- [ ] Test: server rejects SYN with seq != 0 (current behavior snapshot)
- [ ] Test: RST sent on socket drop
- [ ] Run in Docker: `docker run --privileged phantun-test` — all pass

### Task 8: Integration tests — data exchange and seq/ack

**Files:**
- Create: `fake-tcp/tests/data_exchange.rs`

- [ ] Gate with `#![cfg(feature = "integration-tests")]`
- [ ] Test: send data client→server, verify received correctly
- [ ] Test: send data server→client, verify received correctly
- [ ] Test: seq increments by payload.len() after each send (post-handshake seq starts at 1)
- [ ] Test: ack updates to remote_seq + payload.len() after recv
- [ ] Test: multiple sequential sends accumulate seq correctly
- [ ] Run in Docker — all pass

### Task 9: Add CI integration

**Files:**
- Modify: `.github/workflows/rust.yml`

- [ ] Add step for unit tests: `cargo test --workspace`
- [ ] Add job for integration tests: build Dockerfile.test, run with `--privileged`
- [ ] Verify CI config is valid YAML
- [ ] Push and verify CI passes (or document limitations if `--privileged` not available on GitHub Actions)

### Task 10: Verify acceptance criteria

- [ ] `cargo test -p fake-tcp` passes on macOS (Layer 1 — unit tests)
- [ ] `docker run --privileged phantun-test` passes (Layer 2 — integration)
- [ ] All current behavior is documented as test assertions
- [ ] No production `.rs` code was changed (only Cargo.toml feature flag)
- [ ] Run full test suite one final time

### Task 11: [Final] Update documentation

- [ ] Add test running instructions to README.md
- [ ] Move this plan to `docs/plans/completed/`

## Technical Details

### Packet structure (current, to be asserted in tests)

**IPv4 SYN packet (44 bytes):**
```
[20 bytes IPv4 header][24 bytes TCP header with options]
  IPv4: version=4, ihl=5, protocol=6(TCP), ttl=64, flags=DF
  TCP:  doff=6, flags=SYN, window=0xFFFF
        options: NOP(1) + wscale(3,14) = 4 bytes padding to 32-bit
```

**IPv4 data packet (40 + payload bytes):**
```
[20 bytes IPv4 header][20 bytes TCP header][payload]
  IPv4: version=4, ihl=5, protocol=6(TCP), ttl=64, flags=DF
  TCP:  doff=5, flags=ACK, window=0xFFFF, no options
```

### Seq/ack lifecycle

```
Client: seq=0 → send SYN → seq still 0
Server: recv SYN(seq=0) → ack=0+1=1 → send SYN+ACK(seq=0, ack=1) → seq still 0
Client: recv SYN+ACK → seq=0+1=1 → ack=server_seq+1=1 → send ACK(seq=1, ack=1)
Server: recv ACK(ack=0+1=1) → seq=0+1=1 → Established

Post-handshake: both sides seq=1
Send 100 bytes: seq becomes 1+100=101
```

### Network namespace topology for integration tests

```
┌─ ns-client ─────────────────┐      ┌─ ns-server ─────────────────┐
│                              │      │                              │
│  tun-c                       │      │  tun-s                       │
│    address: 10.0.0.1         │      │    address: 10.0.1.1         │
│    destination: 10.0.0.2     │      │    destination: 10.0.1.2     │
│                              │      │                              │
│  Client Stack                │      │  Server Stack                │
│    local_ip: 10.0.0.2        │      │    local_ip: 10.0.1.1        │
│    (= tun_peer)              │      │    (= tun_local)             │
│                              │      │                              │
│  veth-c: 10.1.0.1/30 ───────┼──────┼── veth-s: 10.1.0.2/30       │
│                              │      │                              │
│  route 10.0.1.0/24           │      │  route 10.0.0.0/24           │
│    via 10.1.0.2              │      │    via 10.1.0.1              │
│  ip_forward=1                │      │  ip_forward=1                │
└──────────────────────────────┘      └──────────────────────────────┘

Packet flow (client → server):
1. Client Stack writes to tun-c: src=10.0.0.2, dst=10.0.1.1
2. Kernel in ns-client routes 10.0.1.0/24 → veth-c → veth-s
3. Kernel in ns-server routes dst=10.0.1.1 → tun-s (local address)
4. Server Stack reads from tun-s
```

**Why namespaces (not two TUNs in one namespace):**
In a single namespace, both TUN IPs are local. Kernel delivers packets to its own TCP stack instead of routing to the other TUN. Namespaces provide real isolation — each namespace has its own routing table, same as production (separate machines).

**How one process owns TUNs in two namespaces:**
Use `setns()` in a dedicated thread before calling `TunBuilder::new()`. The fd stays bound to the namespace where it was created. tokio tasks operating on those fds work fine — fd operations are namespace-independent once opened.

### Docker test environment

```bash
# Build
docker build -f Dockerfile.test -t phantun-test .

# Run all tests (unit + integration)
docker run --privileged phantun-test

# Run only unit tests (no Docker needed)
cargo test -p fake-tcp
```

`--privileged` is required (not just `--cap-add=NET_ADMIN`) because network namespace creation needs full capabilities.

### Feature flag usage

```toml
# fake-tcp/Cargo.toml
[features]
benchmark = []
integration-tests = []
```

Integration tests gated with:
```rust
#![cfg(feature = "integration-tests")]
```

Normal `cargo test` skips integration tests. Explicit `--features integration-tests` + Linux + `--privileged` Docker required.

## Post-Completion

**Manual verification:**
- Start Docker daemon on macOS, run full integration suite
- Verify Docker image size is reasonable
- Verify tests are deterministic (run 3x, no flakes)

**Future work (after this plan):**
- Fork implementation: timestamps, MSS, SACK, random ISN, dynamic window — behind `--stealth` / feature flag
- Wire fingerprint tests (raw packet capture) — useful when testing new fingerprint, redundant for current behavior
- Trait abstraction for TUN to enable state machine testing on macOS
