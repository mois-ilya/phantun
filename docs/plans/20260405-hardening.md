# Hardening: Fix Runtime Panics, Parsing Bugs, and Race Conditions

## Overview
- Eliminate all runtime panics from production code paths (parse failures, TUN I/O errors)
- Fix IPv4 IHL hardcoding that causes silent packet corruption when IP options are present
- Fix Level 3 congestion control race conditions using Mutex for grouped state updates
- Result: phantun survives malformed packets, TUN errors, and concurrent access without crashing

## Context (from discovery)
- Files involved: `fake-tcp/src/packet.rs`, `fake-tcp/src/lib.rs`
- Race conditions documented in `docs/plans/backlog.md` under "Fix Stealth Level 3 Thread-Safety"
- All 117 existing tests pass on current branch `phantun-test-infrastructure`
- Integration tests run in Docker with `--privileged` (TUN + iptables)
- All tests run inside Docker via `./scripts/run-tests.sh`

## Development Approach
- **Testing approach**: implement fix + write test in same task, verify test passes
- Complete each task fully before moving to the next
- Make small, focused changes
- **CRITICAL: every task MUST include new/updated tests**
- **CRITICAL: all tests must pass before starting next task**
- **CRITICAL: update this plan file when scope changes during implementation**
- Run tests after each change
- Maintain backward compatibility (stealth 0 must remain byte-identical)

## Testing Strategy
- **Tests**: `./scripts/run-tests.sh`
- **Clippy**: `cargo clippy --verbose`

## Progress Tracking
- Mark completed items with `[x]` immediately when done
- Add newly discovered tasks with ➕ prefix
- Document issues/blockers with ⚠️ prefix

## Implementation Steps

### Task 1: Fix SYN window fingerprint (64240 instead of 256-543)

**Files:**
- Modify: `fake-tcp/src/lib.rs`
- Unit tests in: `fake-tcp/src/lib.rs` `#[cfg(test)]` module (SYN window logic)
- Integration tests in: `fake-tcp/tests/` (SYN+ACK on wire)

- [ ] Add `const SYN_WINDOW: u16 = 64240` in `lib.rs` near `current_window()` (Linux `TCP_INIT_CWND * MSS` = 44 * 1460, pre-wscale)
- [ ] In the window computation block before `build_tcp_packet()` call (`lib.rs` ~line 284), when `is_syn && stealth >= Basic`, use `SYN_WINDOW` instead of `self.current_window()`. The bug: Basic sends 0xFFFF, Standard/Full sends 256-512 — neither matches real Linux SYN window of 64240.
- [ ] Write unit test helper `compute_syn_window(stealth, is_syn) -> u16` in `#[cfg(test)]` (following existing pattern of `compute_window_base`, `compute_current_window`). Test it returns 64240 for stealth >= Basic when is_syn=true, and window_base for data packets.
- [ ] Write integration test `test_syn_ack_window_matches_linux_default` — send crafted SYN via `raw_client_tun` to server with stealth >= Basic, capture SYN+ACK response, verify TCP window field = 64240
- [ ] Write integration test `test_data_packet_window_still_uses_window_base` — establish connection, send data, verify data packets use dynamic window_base (not 64240)
- [ ] Verify existing tests still pass: `./scripts/run-tests.sh`
- [ ] Run clippy: `cargo clippy --verbose`

### Task 2: Fix IPv4 IHL hardcoding in `parse_ip_packet`

**Files:**
- Modify: `fake-tcp/src/packet.rs`
- Unit tests in: `fake-tcp/src/packet.rs` `#[cfg(test)]` module (pure function, no TUN needed)

- [ ] Write unit test `test_parse_ip_packet_with_ip_options` — build IPv4 packet with IHL=6 (24-byte header with 4 bytes of options), verify TCP is parsed correctly from the right offset. Should fail on current code.
- [ ] Write unit test `test_parse_ip_packet_with_max_ihl` — IHL=15 (60-byte header), verify correct parsing or graceful None
- [ ] Fix `parse_ip_packet`: guard `if v4.get_header_length() < 5 { return None; }`, then compute TCP offset as `(v4.get_header_length() as usize) * 4` instead of hardcoded `IPV4_HEADER_LEN`
- [ ] Write test `test_parse_ip_packet_with_ihl_below_minimum` — IHL=3 (malformed), verify returns None
- [ ] Verify existing tests still pass: `./scripts/run-tests.sh`
- [ ] Run clippy: `cargo clippy --verbose`

### Task 3: Replace `parse_ip_packet().unwrap()` with graceful error handling

**Files:**
- Modify: `fake-tcp/src/lib.rs`

- [ ] Write unit test `test_recv_malformed_packet_skips_and_retries` in `lib.rs` `#[cfg(test)]` — create a flume channel, push malformed bytes followed by valid packet bytes, test that the new parsing loop skips the bad packet and returns the valid payload. Note: in production, `reader_task` pre-validates packets before forwarding to Socket — this test is defense-in-depth for the recv() loop itself.
- [ ] Refactor `recv()` (line ~369): replace `.and_then()` closure with explicit loop. Target structure:
  ```rust
  loop {
      let raw_buf = self.incoming.recv_async().await.ok()?;  // None = channel closed
      let Some((_, tcp_packet)) = parse_ip_packet(&raw_buf) else {
          warn!("malformed packet, skipping");
          continue;
      };
      if tcp_packet.get_flags() & RST != 0 { return None; }
      // ... congestion + payload logic ...
      return Some(payload.len());
  }
  ```
  Key: `continue` skips bad packets, `?` on channel close returns None, RST returns None.
- [ ] Replace `parse_ip_packet(&buf).unwrap()` in `accept()` (line ~507) with if-let, log warning and continue retry loop. Also handle `buf.unwrap()` (line ~530) — channel disconnect during handshake should return error, not panic.
- [ ] Replace `parse_ip_packet(&buf).unwrap()` in `connect()` (line ~563) with if-let, log warning and continue retry loop. Also handle `buf.unwrap()` (line ~586) — same channel disconnect handling.
- [ ] Verify `reader_task` (line ~772) already uses `match` — confirm no unwrap there
- [ ] Run full test suite: `./scripts/run-tests.sh`

### Task 4: Replace `tun.try_send().unwrap()` and `tun.send().unwrap()` with error handling

**Files:**
- Modify: `fake-tcp/src/lib.rs`

- [ ] Audit all `tun.send().unwrap()`, `tun.try_send().unwrap()`, and `tun.recv() -> size.unwrap()` in production code (accept, connect, reader_task, Drop)
- [ ] Replace `size.unwrap()` on TUN recv in reader_task (line ~818) with match — on error, log warning and `continue` (skip bad read)
- [ ] Replace `self.tun.send(&buf).await.unwrap()` in `accept()` (line ~499) with `.await.ok()` + log on error, `continue` retry loop (transient TUN error should not abandon connection)
- [ ] Replace `self.tun.send(&buf).await.unwrap()` in `connect()` (line ~555) with `.await.ok()` + log on error, continue retry
- [ ] Replace `self.tun.send(&buf).await.unwrap()` in `connect()` (line ~592) with same pattern
- [ ] Replace `shared.tun[0].try_send(&buf).unwrap()` in reader_task RST paths (lines ~847, ~883) with `.ok()` + log
- [ ] Note: Drop impl's `tuples.write().unwrap()` and `tuples_purge.send().unwrap()` reviewed — intentional panics (poisoned lock / closed channel = unrecoverable state)
- [ ] Note: no mock TUN test — `tokio_tun::Tun` is a concrete type with no trait abstraction. Error handling verified by code review + existing integration tests not panicking.
- [ ] Run `./scripts/run-tests.sh` — must pass before next task

### Task 5: Extract `CongestionState` struct behind Mutex for Level 3

**Files:**
- Modify: `fake-tcp/src/lib.rs`
- Unit tests in: `fake-tcp/src/lib.rs` `#[cfg(test)]` module (access to private types)

- [ ] Define `CongestionState` struct with fields: `dup_ack_count: u32`, `last_acked_seq: u32`, `peer_window: u32`, `cwnd: u32`, `ssthresh: u32`, `snd_nxt: u32`, `last_peer_window: u16`
- [ ] Add `congestion: Option<std::sync::Mutex<CongestionState>>` field to Socket — `None` for stealth < Full, `Some(Mutex::new(...))` for Full. Use `std::sync::Mutex` (NOT tokio::sync::Mutex) — lock is never held across `.await` points, all congestion reads/writes are synchronous.
- [ ] Write unit test `test_congestion_state_fields_initialized_correctly` in `#[cfg(test)]` — construct `CongestionState` directly, verify initial values (cwnd=10*MSS, ssthresh=u32::MAX, etc.)
- [ ] Write unit test `test_congestion_state_none_for_lower_stealth` in `#[cfg(test)]` — verify `congestion` is `None` for stealth levels Off, Basic, and Standard (test via Socket construction inside the test module where private access is available)
- [ ] Run `./scripts/run-tests.sh` — must pass before Task 6

### Task 6: Migrate `recv()` congestion control to use Mutex

**Files:**
- Modify: `fake-tcp/src/lib.rs`

- [ ] Write integration test `test_concurrent_recv_dup_ack_fires_once` — create Socket pair with stealth=Full via TestEnv. Establish connection, then craft 3+ duplicate ACK packets via `raw_client_tun` with spoofed src=10.0.0.2 (routes: raw_client_tun → ns_c kernel with ip_forward → veth → ns_s → DNAT → tun-s → server reader_task). Spawn multiple recv() tasks on the server Socket, inject the dup ACKs, verify cwnd is halved exactly once. Use stress iteration (100+ rounds) since race conditions are probabilistic.
- [ ] Rewrite recv() congestion block (lines ~383-461): acquire `congestion.lock()`, perform all dup-ACK detection, cwnd updates, peer window updates, AND `seq.store(prev_acked)` for fast retransmit rewind inside the lock, then release
- [ ] Remove atomics used only in recv() congestion: `dup_ack_count`, `last_acked_seq`, `peer_window`, `last_peer_window` from Socket (now inside CongestionState)
- [ ] Keep `ack.store()` and `last_ack.store()` as atomics (they're used by send() for ACK piggybacking, not congestion)
- [ ] Note: `seq` rewind in recv() (fast retransmit) MUST happen inside the lock to prevent TOCTOU with send()'s window constraint check + fetch_add
- [ ] Verify levels 0-2 are untouched (no lock acquired when `stealth < Full`)
- [ ] Run full test suite: `./scripts/run-tests.sh`

### Task 7: Migrate `send()` window constraint to use Mutex

**Files:**
- Modify: `fake-tcp/src/lib.rs`

- [ ] Write integration test `test_concurrent_send_seq_consistency` — create Socket pair with stealth=Full via TestEnv. Establish connection, spawn 10+ concurrent tasks calling send() with small payloads on the client Socket. Capture packets on server side, verify seq advances monotonically (no gaps, no duplicates). Use stress iteration (100+ rounds) since race conditions are probabilistic.
- [ ] Rewrite send() window constraint block (lines ~320-338): acquire `congestion.lock()` to read `last_acked_seq`, `peer_window`, `cwnd` atomically, compute bytes_in_flight, decide whether to rewind `seq`, AND do `seq.fetch_add` + `snd_nxt` update — all inside the lock to prevent interleaving with concurrent sends and recv() fast retransmit
- [ ] Remove atomics used only in send() congestion: `cwnd`, `ssthresh`, `snd_nxt` from Socket (now inside CongestionState)
- [ ] Note: `seq.fetch_add` and `snd_nxt.fetch_update` MUST be inside the lock — otherwise a concurrent send() could interleave between the window check and the fetch_add, causing both sends to compute stale bytes_in_flight
- [ ] Run full test suite: `./scripts/run-tests.sh`

### Task 8: Verify atomic field cleanup

**Files:**
- Modify: `fake-tcp/src/lib.rs`

- [ ] Verify all congestion atomics were removed in Tasks 6-7: `dup_ack_count`, `last_acked_seq`, `peer_window`, `cwnd`, `ssthresh`, `snd_nxt`, `last_peer_window` should no longer exist on Socket struct
- [ ] Verify `seq: AtomicU32`, `ack: AtomicU32`, `last_ack: AtomicU32`, `ts_ecr: AtomicU32` remain as atomics (used across send/recv without congestion coupling)
- [ ] Verify `build_tcp_packet()` is pure — receives window via parameter, does NOT read congestion fields directly
- [ ] Run clippy: `cargo clippy --verbose`
- [ ] Run full test suite: `./scripts/run-tests.sh`

### Task 9: Verify acceptance criteria

- [ ] Verify SYN window = 64240 for stealth >= Basic (test from Task 1)
- [ ] Verify IPv4 packets with IHL > 5 are parsed correctly (test from Task 2)
- [ ] Verify malformed packets skip gracefully (test from Task 3)
- [ ] Verify TUN errors don't panic (test from Task 4)
- [ ] Verify Level 3 concurrent recv doesn't double-halve cwnd (test from Task 6)
- [ ] Verify Level 3 concurrent send maintains seq consistency (test from Task 7)
- [ ] Verify stealth level 0 remains byte-identical to pre-stealth (existing tests)
- [ ] Run full test suite: `./scripts/run-tests.sh`
- [ ] Run clippy clean: `cargo clippy --verbose`

### Task 10: [Final] Update documentation

- [ ] Update `docs/plans/backlog.md` — remove "Fix Stealth Level 3 Thread-Safety" (done)
- [ ] Update CLAUDE.md if new patterns discovered (e.g., Mutex usage for Level 3)
- [ ] Move this plan to `docs/plans/completed/`

## Technical Details

### SYN window fix
- Linux kernel SYN window = `TCP_DEFAULT_INIT_RCVWND` = 64240 bytes (44 * MSS 1460), pre-wscale
- Current code: Basic sends `0xFFFF` (wrong), Standard/Full sends `window_base` 256-512 (wrong)
- With wscale=7: `256 * 128 = 32K` (reasonable for data), but SYN literally says "I can receive 271 bytes" — DPI fingerprint
- Basic's `0xFFFF` (65535) is also wrong — real Linux never sends 65535 as SYN window
- Fix: SYN/SYN+ACK → hardcoded 64240, data packets → `window_base + jitter` (unchanged)
- Applies to stealth >= Basic (levels 1-3). Level 0 keeps `0xFFFF`.

### IPv4 IHL fix
- pnet's `Ipv4Packet::get_header_length()` returns the raw IHL field value in 4-byte words (e.g., 5 for standard 20-byte header)
- To get byte offset: `(v4.get_header_length() as usize) * 4`
- Replace `buf.get(IPV4_HEADER_LEN..)` with `buf.get((v4.get_header_length() as usize) * 4..)`
- IPv6 has fixed 40-byte header, no change needed

### CongestionState struct
```rust
struct CongestionState {
    dup_ack_count: u32,
    last_acked_seq: u32,
    peer_window: u32,
    cwnd: u32,
    ssthresh: u32,
    snd_nxt: u32,
    last_peer_window: u16,
}
```

- Wrapped in `Option<std::sync::Mutex<CongestionState>>` — `None` for stealth < Full, `Some(Mutex::new(...))` for Full
- Use `std::sync::Mutex` (NOT `tokio::sync::Mutex`) — lock never held across `.await` points
- Lock held only during synchronous congestion state reads/writes in recv() and send()
- `seq`, `ack`, `last_ack`, `ts_ecr`, `last_window_sent` remain as atomics. `seq` writes are guarded by the Mutex in Level 3 but the field itself stays AtomicU32 (levels 0-2 use it lock-free). `window_base` is a plain `u16` set at construction time (immutable after init).

### Fields that stay atomic
| Field | Why |
|-------|-----|
| `seq: AtomicU32` | Stays atomic but ALL writes (fetch_add, rewind store) happen inside the congestion Mutex when stealth >= Full. For levels 0-2, no lock needed — fetch_add is sufficient. |
| `ack: AtomicU32` | Written in recv(), read in build_tcp_packet() — independent |
| `last_ack: AtomicU32` | ACK dedup in build_tcp_packet() — independent |
| `ts_ecr: AtomicU32` | Last-writer-wins timestamp echo — no consistency needed |
| `last_window_sent: AtomicU16` | Window dedup in build_tcp_packet() — independent |

## Post-Completion

**Manual verification:**
- Run high-concurrency benchmark (from backlog) to measure contention impact of Mutex
- Test with real traffic at stealth level 3 to verify congestion behavior is correct
- Fuzz `parse_ip_packet` with random byte sequences to verify no panics remain
