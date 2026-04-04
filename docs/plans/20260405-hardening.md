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
- Unit tests in `packet.rs` run on macOS; integration tests require Linux

## Development Approach
- **Testing approach**: TDD — write failing test first, then fix
- Complete each task fully before moving to the next
- Make small, focused changes
- **CRITICAL: every task MUST include new/updated tests**
- **CRITICAL: all tests must pass before starting next task**
- **CRITICAL: update this plan file when scope changes during implementation**
- Run tests after each change
- Maintain backward compatibility (stealth 0 must remain byte-identical)

## Testing Strategy
- **Unit tests**: `cargo test -p fake-tcp` on macOS for packet parsing
- **Full suite**: `./scripts/run-tests.sh` (Docker-based, includes integration tests)
- **Clippy**: `cargo clippy --verbose` must pass

## Progress Tracking
- Mark completed items with `[x]` immediately when done
- Add newly discovered tasks with ➕ prefix
- Document issues/blockers with ⚠️ prefix

## Implementation Steps

### Task 1: Fix IPv4 IHL hardcoding in `parse_ip_packet`

**Files:**
- Modify: `fake-tcp/src/packet.rs`

- [ ] Write test `test_parse_ip_packet_with_ip_options` — build IPv4 packet with IHL=6 (24-byte header with 4 bytes of options), verify TCP is parsed correctly from the right offset. Should fail on current code.
- [ ] Write test `test_parse_ip_packet_with_max_ihl` — IHL=15 (60-byte header), verify correct parsing or graceful None
- [ ] Fix `parse_ip_packet`: compute TCP offset as `(v4.get_header_length() as usize) * 4` (pnet's `get_header_length()` returns the IHL field in 4-byte words, e.g. 5 for standard 20-byte header), use instead of hardcoded `IPV4_HEADER_LEN`
- [ ] Verify existing tests still pass: `cargo test -p fake-tcp`
- [ ] Run clippy: `cargo clippy -p fake-tcp --verbose`

### Task 2: Replace `parse_ip_packet().unwrap()` with graceful error handling

**Files:**
- Modify: `fake-tcp/src/lib.rs`

- [ ] Write test `test_recv_malformed_packet_skips_and_retries` — feed a malformed packet followed by a valid packet into Socket's incoming channel, verify `recv()` skips the bad one and returns the valid payload (no panic). Should panic on current code.
- [ ] Replace `parse_ip_packet(&raw_buf).unwrap()` in `recv()` (line ~369): restructure from closure into a loop — on parse failure, log warning and `continue` (retry next packet from channel), NOT return `None` (which would kill the connection). Only return `None` on channel close or RST.
- [ ] Replace `parse_ip_packet(&buf).unwrap()` in `accept()` (line ~507) with match/if-let, log warning and continue retry loop
- [ ] Replace `parse_ip_packet(&buf).unwrap()` in `connect()` (line ~563) with match/if-let, log warning and continue retry loop
- [ ] Verify `reader_task` (line ~772) already uses `match` — confirm no unwrap there
- [ ] Run full test suite: `./scripts/run-tests.sh`

### Task 3: Replace `tun.try_send().unwrap()` and `tun.send().unwrap()` with error handling

**Files:**
- Modify: `fake-tcp/src/lib.rs`

- [ ] Audit all `tun.send().unwrap()` and `tun.try_send().unwrap()` in production code (accept, connect, reader_task, Drop)
- [ ] Replace `self.tun.send(&buf).await.unwrap()` in `accept()` (line ~499) with `.await.ok()` + log on error, `continue` retry loop (transient TUN error should not abandon connection)
- [ ] Replace `self.tun.send(&buf).await.unwrap()` in `connect()` (line ~555) with `.await.ok()` + log on error, continue retry
- [ ] Replace `self.tun.send(&buf).await.unwrap()` in `connect()` (line ~592) with same pattern
- [ ] Replace `shared.tun[0].try_send(&buf).unwrap()` in reader_task RST paths (lines ~847, ~883) with `.ok()` + log
- [ ] Note: Drop impl's `tuples.write().unwrap()` and `tuples_purge.send().unwrap()` reviewed — intentional panics (poisoned lock / closed channel = unrecoverable state)
- [ ] Write test that verifies accept/connect don't panic when TUN send fails (mock/closed TUN channel)
- [ ] Run tests — must pass before Task 4

### Task 4: Extract `CongestionState` struct behind Mutex for Level 3

**Files:**
- Modify: `fake-tcp/src/lib.rs`

- [ ] Define `CongestionState` struct with fields: `dup_ack_count: u32`, `last_acked_seq: u32`, `peer_window: u32`, `cwnd: u32`, `ssthresh: u32`, `snd_nxt: u32`, `last_peer_window: u16`
- [ ] Add `congestion: Mutex<CongestionState>` field to Socket, initialized only when `stealth >= Full`
- [ ] Write test `test_congestion_state_fields_initialized_correctly` — verify initial values match current AtomicU32 defaults (cwnd=10*MSS, ssthresh=u32::MAX, etc.)
- [ ] Write test `test_congestion_state_none_for_lower_stealth` — verify `congestion` is `None` for stealth levels Off, Basic, and Standard
- [ ] Run `cargo test -p fake-tcp` — must pass before Task 5

### Task 5: Migrate `recv()` congestion control to use Mutex

**Files:**
- Modify: `fake-tcp/src/lib.rs`

- [ ] Write test `test_concurrent_recv_dup_ack_fires_once` — spawn multiple tasks calling recv() on shared Socket with stealth=Full, inject 3+ duplicate ACKs simultaneously, verify cwnd is halved exactly once (not twice). Should fail on current code due to race.
- [ ] Rewrite recv() congestion block (lines ~383-461): acquire `congestion.lock()`, perform all dup-ACK detection, cwnd updates, peer window updates, AND `seq.store(prev_acked)` for fast retransmit rewind inside the lock, then release
- [ ] Keep `ack.store()` and `last_ack.store()` as atomics (they're used by send() for ACK piggybacking, not congestion)
- [ ] Note: `seq` rewind in recv() (fast retransmit) MUST happen inside the lock to prevent TOCTOU with send()'s window constraint check + fetch_add
- [ ] Verify levels 0-2 are untouched (no lock acquired when `stealth < Full`)
- [ ] Run full test suite: `./scripts/run-tests.sh`

### Task 6: Migrate `send()` window constraint to use Mutex

**Files:**
- Modify: `fake-tcp/src/lib.rs`

- [ ] Write test `test_concurrent_send_seq_consistency` — spawn multiple tasks calling send() on shared Socket with stealth=Full, verify seq advances monotonically (no gaps, no duplicates). Should fail on current code.
- [ ] Rewrite send() window constraint block (lines ~320-338): acquire `congestion.lock()` to read `last_acked_seq`, `peer_window`, `cwnd` atomically, compute bytes_in_flight, decide whether to rewind `seq`, AND do `seq.fetch_add` + `snd_nxt` update — all inside the lock to prevent interleaving with concurrent sends and recv() fast retransmit
- [ ] Note: `seq.fetch_add` and `snd_nxt.fetch_update` MUST be inside the lock — otherwise a concurrent send() could interleave between the window check and the fetch_add, causing both sends to compute stale bytes_in_flight
- [ ] Run full test suite: `./scripts/run-tests.sh`

### Task 7: Clean up removed AtomicU32 fields

**Files:**
- Modify: `fake-tcp/src/lib.rs`

- [ ] Remove `dup_ack_count: AtomicU32`, `last_acked_seq: AtomicU32`, `peer_window: AtomicU32`, `cwnd: AtomicU32`, `ssthresh: AtomicU32`, `snd_nxt: AtomicU32`, `last_peer_window: AtomicU16` from Socket struct (now inside CongestionState)
- [ ] Audit reads of moved fields — `peer_window`, `cwnd`, `last_acked_seq`, `snd_nxt` are only read in send() and recv() congestion blocks (already under lock). `build_tcp_packet()` is pure and receives window via parameter, does NOT read `peer_window` directly. No external callers need updating.
- [ ] Verify `seq: AtomicU32` and `ack: AtomicU32` and `last_ack: AtomicU32` and `ts_ecr: AtomicU32` remain as atomics (used across send/recv without congestion coupling)
- [ ] Run clippy: `cargo clippy --verbose`
- [ ] Run full test suite: `./scripts/run-tests.sh`

### Task 8: Verify acceptance criteria

- [ ] Verify IPv4 packets with IHL > 5 are parsed correctly (test from Task 1)
- [ ] Verify malformed packets don't panic (test from Task 2)
- [ ] Verify TUN errors don't panic (test from Task 3)
- [ ] Verify Level 3 concurrent recv doesn't double-halve cwnd (test from Task 5)
- [ ] Verify Level 3 concurrent send maintains seq consistency (test from Task 6)
- [ ] Verify stealth level 0 remains byte-identical to pre-stealth (existing tests)
- [ ] Run full test suite: `./scripts/run-tests.sh`
- [ ] Run clippy clean: `cargo clippy --verbose`

### Task 9: [Final] Update documentation

- [ ] Update `docs/plans/backlog.md` — remove "Fix Stealth Level 3 Thread-Safety" (done)
- [ ] Update CLAUDE.md if new patterns discovered (e.g., Mutex usage for Level 3)
- [ ] Move this plan to `docs/plans/completed/`

## Technical Details

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

- Wrapped in `Option<Mutex<CongestionState>>` — `None` for stealth < Full, `Some(Mutex::new(...))` for Full
- Lock held only during congestion state reads/writes in recv() and send()
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
