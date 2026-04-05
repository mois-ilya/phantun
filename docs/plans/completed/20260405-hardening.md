# Hardening: Fix Runtime Panics, Parsing Bugs, and Race Conditions

## Overview
- Eliminate all runtime panics from production code paths (parse failures, TUN I/O errors)
- Fix IPv4 IHL hardcoding that causes silent packet corruption when IP options are present
- Fix SYN window fingerprint (64240 instead of wrong values)
- Fix Level 3 congestion control race conditions using Mutex for grouped state updates
- Result: phantun survives malformed packets, TUN errors, and concurrent access without crashing

## Context (from discovery)
- Files involved: `fake-tcp/src/packet.rs`, `fake-tcp/src/lib.rs`
- Race conditions documented in `docs/plans/backlog.md` under "Fix Stealth Level 3 Thread-Safety"
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
- Add newly discovered tasks with + prefix
- Document issues/blockers with ! prefix

## Implementation Steps

### Task 1: Fix SYN window fingerprint (64240 instead of 256-543)

**Files:**
- Modify: `fake-tcp/src/lib.rs`
- Unit tests in: `fake-tcp/src/lib.rs` `#[cfg(test)]` module (SYN window logic)
- Integration tests in: `fake-tcp/tests/` (SYN+ACK on wire)

- [x] Add `const SYN_WINDOW: u16 = 64240` in `lib.rs` near `current_window()` (Linux `TCP_INIT_CWND * MSS` = 44 * 1460, pre-wscale)
- [x] In `build_tcp_packet()` method near the `self.current_window()` call, when `is_syn && stealth >= Basic`, use `SYN_WINDOW` instead of `self.current_window()`. The bug: Basic sends 0xFFFF, Standard/Full sends 256-512 — neither matches real Linux SYN window of 64240.
- [x] Write unit test helper `compute_syn_window(stealth, is_syn) -> u16` in `#[cfg(test)]` (following existing pattern of `compute_window_base`, `compute_current_window`). Test it returns 64240 for stealth >= Basic when is_syn=true, and window_base for data packets.
- [x] Write integration test `test_syn_ack_window_matches_linux_default` — send crafted SYN via `raw_client_tun` to server with stealth >= Basic, capture SYN+ACK response, verify TCP window field = 64240
- [x] Write integration test `test_data_packet_window_still_uses_window_base` — establish connection, send data, verify data packets use dynamic window_base (not 64240)
- [x] Verify existing tests still pass: `./scripts/run-tests.sh`
- [x] Run clippy: `cargo clippy --verbose`

### Task 2: Fix IPv4 IHL hardcoding in `parse_ip_packet`

**Files:**
- Modify: `fake-tcp/src/packet.rs`
- Unit tests in: `fake-tcp/src/packet.rs` `#[cfg(test)]` module (pure function, no TUN needed)

- [x] Write unit test `test_parse_ip_packet_with_ip_options` — IHL=6, verify TCP parsed from correct offset
- [x] Write unit test `test_parse_ip_packet_with_max_ihl` — IHL=15, verify correct parsing or graceful None
- [x] Fix `parse_ip_packet`: compute TCP offset as `(v4.get_header_length() as usize) * 4` instead of hardcoded `IPV4_HEADER_LEN`
- [x] Add guard `if v4.get_header_length() < 5 { return None; }` for malformed IHL values
- [x] Write test `test_parse_ip_packet_with_ihl_below_minimum` — IHL=3 (malformed), verify returns None
- [x] Verify existing tests still pass: `./scripts/run-tests.sh`
- [x] Run clippy: `cargo clippy --verbose`

### Task 3: Replace `parse_ip_packet().unwrap()` with graceful error handling [DONE]

**Files:**
- Modify: `fake-tcp/src/lib.rs`

- [x] Refactor `recv()`: replace `.and_then()` closure with explicit loop with `continue` on parse failure
- [x] Replace `parse_ip_packet().unwrap()` in `accept()` with if-let + warning + continue
- [x] Replace `parse_ip_packet().unwrap()` in `connect()` with if-let + warning + continue
- [x] Handle `buf.unwrap()` channel disconnect in accept/connect
- [x] Verify `reader_task` already uses `match`
- [x] Run full test suite: `./scripts/run-tests.sh`

### Task 4: Replace `tun.send/recv().unwrap()` with error handling [DONE]

**Files:**
- Modify: `fake-tcp/src/lib.rs`

- [x] Replace `size.unwrap()` on TUN recv in reader_task with match + warning + continue
- [x] Replace `tun.send().unwrap()` in accept() with error handling + continue
- [x] Replace `tun.send().unwrap()` in connect() (both SYN send and handshake ACK)
- [x] Replace `try_send().unwrap()` in reader_task RST paths
- [x] Fix Drop impl: assert! -> warning, tuples_purge.send().unwrap() -> let _ = ...
- [x] Fix connect() seq corruption on TUN ACK send failure (found in code review)
- [x] Run `./scripts/run-tests.sh`

### Task 5: Extract `CongestionState` struct behind Mutex for Level 3 [DONE]

**Files:**
- Modify: `fake-tcp/src/lib.rs`

- [x] Define `CongestionState` struct with fields: dup_ack_count, last_acked_seq, peer_window, cwnd, ssthresh, snd_nxt, last_peer_window
- [x] Add `congestion: Option<std::sync::Mutex<CongestionState>>` field to Socket
- [x] Write test `test_congestion_state_some_for_full_stealth`
- [x] Run `./scripts/run-tests.sh`

### Task 6: Migrate `recv()` congestion control to use Mutex [DONE]

**Files:**
- Modify: `fake-tcp/src/lib.rs`

- [x] Write integration test `test_concurrent_recv_dup_ack_fires_once`
- [x] Rewrite recv() congestion block under `congestion.lock()`
- [x] Remove congestion atomics from Socket (now inside CongestionState)
- [x] Run full test suite: `./scripts/run-tests.sh`

### Task 7: Migrate `send()` window constraint to use Mutex [DONE]

**Files:**
- Modify: `fake-tcp/src/lib.rs`

- [x] Write integration test `test_concurrent_send_seq_consistency`
- [x] Rewrite send() window constraint under `congestion.lock()`
- [x] Remove remaining congestion atomics (cwnd, ssthresh, snd_nxt)
- [x] Run full test suite: `./scripts/run-tests.sh`

### Task 8: Verify and finalize

- [x] Verify all congestion atomics removed from Socket struct
- [x] Verify seq, ack, last_ack, ts_ecr, last_window_sent remain as atomics
- [x] Run clippy: `cargo clippy --verbose`
- [x] Run `./scripts/run-tests.sh` — exit code 0, all 129 unit + 10 integration tests pass
- [x] Move this plan to `docs/plans/completed/` (create directory if needed)

## Technical Details

### SYN window fix
- Linux kernel SYN window = 64240 bytes (44 * MSS 1460), pre-wscale
- Current code: Basic sends `0xFFFF` (wrong), Standard/Full sends `window_base` 256-512 (wrong)
- Fix: SYN/SYN+ACK -> hardcoded 64240, data packets -> `window_base + jitter` (unchanged)
- Applies to stealth >= Basic (levels 1-3). Level 0 keeps `0xFFFF`.

### IPv4 IHL fix
- pnet's `Ipv4Packet::get_header_length()` returns the raw IHL field value in 4-byte words
- To get byte offset: `(v4.get_header_length() as usize) * 4`
- Guard: return None if IHL < 5 (malformed)

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

- Wrapped in `Option<std::sync::Mutex<CongestionState>>` — `None` for stealth < Full
- Use `std::sync::Mutex` (NOT `tokio::sync::Mutex`) — lock never held across `.await` points
- Lock held only during synchronous congestion state reads/writes in recv() and send()

## Post-Completion

**Manual verification:**
- Run high-concurrency benchmark to measure contention impact of Mutex
- Test with real traffic at stealth level 3 to verify congestion behavior
- Fuzz `parse_ip_packet` with random byte sequences to verify no panics remain
