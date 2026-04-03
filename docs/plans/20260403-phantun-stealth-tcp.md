# Phantun Stealth TCP

## Overview

Add realistic TCP fingerprinting to Phantun to bypass ТСПУ (and other stateful DPI). Three graduated stealth levels controlled by `--stealth N` CLI flag:

- **Level 0**: current behavior (backward compatible, no changes)
- **Level 1**: eliminate hard signatures (random ISN, realistic SYN, timestamps on all packets)
- **Level 2**: udp2raw-parity stateful mimicry (dynamic window, frequent ACK, ts_ecr echo)
- **Level 3**: beyond udp2raw (dup ACK tracking, send window constraint, congestion simulation)

Each level includes all previous levels. Default: `--stealth 0` (current behavior).

**Performance goal**: maintain Phantun's multi-threaded throughput advantage. Key constraints:
- Level 1: +12 bytes/packet (timestamps), negligible CPU — should preserve ~95%+ throughput
- Level 2: extra state tracking (AtomicU32 ops), more frequent ACK packets — small impact
- Level 3: congestion simulation may intentionally throttle sending rate for realism

**Dependency**: test infrastructure plan (`20260403-phantun-test-infrastructure.md`) should be completed first for Layer 1 unit tests. Integration tests can be developed in parallel.

## Context

**Files to modify:**
- `fake-tcp/src/packet.rs` — `build_tcp_packet()` needs new parameters (timestamps, window, options)
- `fake-tcp/src/lib.rs` — `Socket` struct needs new state fields; `send()`/`recv()` need stealth logic
- `phantun/src/bin/client.rs` — add `--stealth` CLI arg, pass to Stack
- `phantun/src/bin/server.rs` — add `--stealth` CLI arg, pass to Stack

**Current signatures to fix (from analysis):**
1. `seq = 0` always, server requires `SYN(seq==0)` — strongest fingerprint
2. SYN: only NOP + wscale(14), no MSS/SACK/timestamps
3. Data packets: no TCP options at all (doff=5)
4. Window: static 0xFFFF, never changes
5. ACK: updates only on recv(), standalone ACK after 128MB — hugely unrealistic
6. No timestamps anywhere

**Performance-critical path:**
- `Socket::send()` → `Socket::build_tcp_packet()` → `packet::build_tcp_packet()` → TUN write
- `Stack::reader_task()` → parse → channel → `Socket::recv()`
- These are hot paths. Any per-packet work must be O(1) and lock-free.

## Development Approach

- **Testing approach**: TDD — write tests for expected behavior first, then implement
- Complete each stealth level fully before starting the next
- Maintain backward compatibility: `--stealth 0` must behave identically to current code
- All existing tests (from test infrastructure plan) must keep passing
- **CRITICAL: all tests must pass before starting next task**
- **CRITICAL: update this plan file when scope changes during implementation**
- Hot path changes must use `Ordering::Relaxed` atomics, no locks, no allocations

## Testing Strategy

- **Unit tests**: each stealth level gets tests in `fake-tcp/src/packet.rs` mod tests
  - Level 0: existing snapshot tests (from test infrastructure plan)
  - Level 1: SYN has MSS+SACK+TS+wscale, data has timestamps, ISN != 0
  - Level 2: window varies, ACK updates frequently, ts_ecr echoes peer
  - Level 3: dup ACK detection, send window constraint, congestion behavior
- **Integration tests**: Docker tests verify end-to-end for each level

## Progress Tracking

- Mark completed items with `[x]` immediately when done
- Add newly discovered tasks with ➕ prefix
- Document issues/blockers with ⚠️ prefix
- Update plan if implementation deviates from original scope

## Implementation Steps

### Task 1: Add StealthLevel enum and --stealth CLI flag

- [x] Create `StealthLevel` enum in `fake-tcp/src/lib.rs`: `Off(0)`, `Basic(1)`, `Standard(2)`, `Full(3)`
- [x] Implement `From<u8>` for StealthLevel with clamping
- [x] Add `stealth: StealthLevel` field to `Stack` and `Socket`
- [x] Thread `stealth` through `Stack::new()` → `Socket::new()` → `Socket::build_tcp_packet()`
- [x] Add `--stealth <LEVEL>` arg to `client.rs` and `server.rs` CLI (default: 0)
- [x] Write tests: StealthLevel parsing, default behavior, clamping
- [x] Run `cargo test` — all pass, `--stealth 0` behaves identically to current code

### Task 2: Random ISN (Level 1)

- [x] Write tests: with stealth >= 1, SYN seq != 0; with stealth 0, SYN seq == 0
- [x] Write test: server with stealth >= 1 accepts SYN with any seq (not just 0)
- [x] In `Socket::new()`: when stealth >= 1, initialize `seq` from `rand::random::<u32>()`
- [x] In `reader_task`: when stealth >= 1, accept SYN with any seq value (remove `== 0` check)
- [x] Run `cargo test` — all pass

### Task 3: Realistic SYN fingerprint (Level 1)

- [x] Write tests: with stealth >= 1, SYN packet has MSS=1460, SACK_PERM, Timestamps, wscale=7, doff=10 (40 bytes header)
- [x] Write tests: SYN+ACK has same options
- [x] Write test: stealth 0 still produces old SYN format (NOP + wscale=14, doff=6)
- [x] Extend `build_tcp_packet()` signature: add `stealth: StealthLevel` parameter
- [x] When stealth >= 1 and SYN flag set, build options: MSS(1460) + SACK_PERM + Timestamps(tsval, 0) + NOP + wscale(7)
- [x] Options layout (20 bytes): MSS(4) + SACK_PERM(2) + Timestamps(10) + NOP(1) + wscale(3) = 20 (doff=10, 40-byte header)
- [x] Verify options byte layout matches Linux kernel TCP SYN fingerprint
- [x] Run `cargo test` — all pass

### Task 4: Timestamps state in Socket (Level 1)

- [x] Write tests: timestamps increment monotonically on successive packets
- [x] Write test: ts_ecr = 0 on first SYN, then echoes peer's tsval after receiving
- [x] Add to Socket: `ts_val: AtomicU32` (local timestamp counter), `ts_ecr: AtomicU32` (last received peer tsval)
- [x] Initialize `ts_val` from `Instant::now()` converted to ms-granularity counter
- [x] In `build_tcp_packet()`: when stealth >= 1, always include NOP+NOP+Timestamps(tsval, tsecr) — 12 bytes, doff=8 for non-SYN
- [x] In recv path (`reader_task` or `Socket::recv()`): parse incoming TCP timestamps, update `ts_ecr`
- [x] Increment `ts_val` based on elapsed time (not per-packet, to avoid timing attacks)
- [x] Run `cargo test` — all pass

### Task 5: PSH flag on data packets (Level 1)

- [x] Write test: with stealth >= 1, data packets have PSH|ACK flags (not just ACK)
- [x] Write test: stealth 0 still uses plain ACK
- [x] In `Socket::send()`: when stealth >= 1, use `tcp::TcpFlags::PSH | tcp::TcpFlags::ACK`
- [x] Run `cargo test` — all pass

### Task 6: Frequent ACK updates (Level 2)

- [x] Write test: with stealth >= 2, ACK updates on every received packet (not 128MB threshold)
- [x] Write test: standalone ACK sent when receiving data without sending
- [x] Write test: stealth 0 and 1 keep 128MB threshold
- [x] Add `ack_update_mode` logic to `Socket::recv()`: when stealth >= 2, send ACK after each received packet if no data is being sent concurrently
- [x] Reduce/remove 128MB threshold for stealth >= 2
- [x] Piggyback ACK on next data send to minimize extra packets
- [x] Run `cargo test` — all pass

### Task 7: Dynamic window (Level 2)

- [x] Write test: with stealth >= 2, window varies between packets (not static 0xFFFF)
- [x] Write test: window is in realistic range (e.g., 32K-64K base, randomized)
- [x] Write test: stealth 0 and 1 keep static 0xFFFF
- [x] Add `window_base: u16` to Socket; use thread-local RNG via `rand::random()` for jitter (lock-free)
- [x] In `build_tcp_packet()`: added `window: u16` parameter; Socket computes window = base + random_offset when stealth >= 2
- [x] Apply wscale to advertised window value (base 256-512 with wscale=7 = ~32K-64K effective)
- [x] Run `cargo test` — all 83 tests pass, clippy clean

### Task 8: ts_ecr echo correctness (Level 2)

- [x] Write test: outgoing ts_ecr matches last received peer tsval exactly
- [x] Write test: after receiving multiple packets, ts_ecr reflects the latest
- [x] Verify `ts_ecr` update path in recv is atomic and consistent
- [x] Verify integration: handshake ts_ecr flow (SYN: ecr=0, SYN+ACK: ecr=peer_tsval, ACK: ecr=peer_tsval)
- [x] Run `cargo test` — all pass

### Task 9: Duplicate ACK tracking (Level 3)

- [x] Write test: when same ACK received 3 times, trigger fast retransmit behavior
- [x] Write test: seq resets to acked position on triple dup ACK
- [x] Add to Socket: `dup_ack_count: AtomicU32`, `last_acked_seq: AtomicU32`
- [x] In recv path: count consecutive identical ACK values
- [x] When dup_ack_count >= 3: reset send-side seq to last_acked_seq (simulate fast retransmit)
- [x] Run `cargo test` — all pass

### Task 10: Send window constraint (Level 3)

- [x] Write test: send-side seq does not advance beyond peer's advertised window
- [x] Write test: when window is exhausted, seq wraps back to acked position
- [x] Add to Socket: `peer_window: AtomicU32` (parsed from incoming packets)
- [x] In `Socket::send()`: check if `seq + payload_len` exceeds `last_acked_seq + peer_window`
- [x] If exceeds: wrap seq back to `last_acked_seq` (like udp2raw seq_mode 3)
- [x] Run `cargo test` — all pass

### Task 11: Congestion simulation (Level 3)

- [x] Write test: initial sends have gradually increasing burst size (slow start behavior)
- [x] Write test: after stable period, sending rate stabilizes (congestion avoidance)
- [x] Add to Socket: `cwnd: AtomicU32` (congestion window), `ssthresh: AtomicU32`
- [x] Implement minimal slow start: cwnd starts small, doubles each RTT estimate until ssthresh
- [x] Implement minimal congestion avoidance: cwnd grows linearly after ssthresh
- [x] On triple dup ACK: halve cwnd (multiplicative decrease)
- [x] This is the most performance-impacting change — document overhead in benchmarks
- [x] Run `cargo test` — all 111 tests pass

### Task 12: Verify acceptance criteria

- [ ] `--stealth 0`: all existing tests pass, byte-identical output to current code
- [ ] `--stealth 1`: SYN has MSS+SACK+TS+wscale, data has timestamps, ISN random, PSH on data
- [ ] `--stealth 2`: window varies, ACK updates frequently, ts_ecr correct
- [ ] `--stealth 3`: dup ACK handled, send window constrained, congestion simulated
- [ ] Run full test suite (unit + integration in Docker)
- [ ] Run linter: `cargo clippy` — all clean
- [ ] Benchmark: compare throughput at each stealth level vs level 0

### Task 13: [Final] Update documentation

- [ ] Update README.md with `--stealth` flag documentation
- [ ] Document stealth levels and their trade-offs
- [ ] Update project knowledge docs if new patterns discovered

## Technical Details

### StealthLevel enum

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum StealthLevel {
    Off = 0,      // current behavior, byte-compatible
    Basic = 1,    // fix hard signatures (ISN, SYN fingerprint, timestamps)
    Standard = 2, // stateful mimicry (dynamic window, frequent ACK, ts_ecr)
    Full = 3,     // advanced (dup ACK, send window, congestion)
}
```

### Packet structure by stealth level

**Level 0 (current):**
```
SYN:  doff=6  (24 bytes) — NOP + wscale(14)
Data: doff=5  (20 bytes) — no options
```

**Level 1:**
```
SYN:  doff=11 (44 bytes) — MSS(1460) + SACK_PERM + TS(val,0) + NOP + NOP + wscale(7) + NOP
Data: doff=8  (32 bytes) — NOP + NOP + TS(val,ecr)
Overhead vs level 0: +12 bytes per data packet (~0.8% on 1460-byte payload)
```

**Level 2:**
```
Same packet format as Level 1
Behavioral difference: window varies, ACK more frequent, ts_ecr echoes correctly
Extra packets: occasional standalone ACKs when receiving without sending
```

**Level 3:**
```
Same packet format as Level 1-2
Behavioral difference: seq/ack patterns mimic real TCP congestion control
Potential throughput impact: congestion window limits burst size
```

### Socket state additions by level

```rust
// Level 1 additions:
ts_val: AtomicU32,        // local timestamp counter (ms granularity)
ts_ecr: AtomicU32,        // last received peer tsval

// Level 2 additions:
window_base: u16,         // base window value for randomization

// Level 3 additions:
dup_ack_count: AtomicU32, // consecutive identical ACK counter
last_acked_seq: AtomicU32,// seq confirmed by peer's ACK
peer_window: AtomicU32,   // peer's advertised receive window
cwnd: AtomicU32,          // congestion window
ssthresh: AtomicU32,      // slow start threshold
```

All fields are `AtomicU32` with `Ordering::Relaxed` — no locks on hot path.

### Performance analysis

| Operation | Level 0 | Level 1 | Level 2 | Level 3 |
|-----------|---------|---------|---------|---------|
| Per-packet CPU | baseline | +timestamp read | +RNG for window | +cwnd check |
| Per-packet bytes | 20B TCP | 32B TCP (+12) | 32B TCP | 32B TCP |
| Extra packets | none | none | occasional ACK | occasional ACK |
| Throughput impact | 0% | ~1% (bytes) | ~2-3% (ACKs) | variable (cwnd) |
| Lock-free | yes | yes | yes | yes |

### build_tcp_packet() signature change

```rust
// Current:
pub fn build_tcp_packet(
    local_addr: SocketAddr, remote_addr: SocketAddr,
    seq: u32, ack: u32, flags: u8, payload: Option<&[u8]>,
) -> Bytes

// New:
pub fn build_tcp_packet(
    local_addr: SocketAddr, remote_addr: SocketAddr,
    seq: u32, ack: u32, flags: u8, payload: Option<&[u8]>,
    opts: &TcpBuildOptions,  // stealth-dependent options
) -> Bytes

pub struct TcpBuildOptions {
    pub stealth: StealthLevel,
    pub ts_val: u32,    // 0 if stealth < 1
    pub ts_ecr: u32,    // 0 if stealth < 1
    pub window: u16,    // 0xFFFF if stealth < 2
}
```

This keeps `build_tcp_packet` as a pure function — all state is passed in, not read from Socket internals.

## Post-Completion

**Manual verification:**
- Deploy to ru-relay + nuremberg with `--stealth 1`, verify data packets pass through ТСПУ
- If level 1 doesn't pass, try level 2
- Measure throughput at each level vs udp2raw baseline (75 Mbps)
- Target: 150+ Mbps at level 1-2 on 2 vCPU

**Real-world testing:**
- pcap capture on both sides, manual inspection of TCP fingerprint
- Compare fingerprint against real Linux 5.x TCP SYN using `p0f` or similar
- Long-duration stability test (24h+)
