# Mimic udp2raw TCP Fingerprint Mode

## Overview
- Add `--mimic udp2raw` flag that fully replicates udp2raw's TCP fingerprint behavior
- Goal: TSPU bypass debugging — identify which specific fingerprint triggers DPI blocking
- Each fingerprint aspect has an individual `--mimic-no-*` toggle to disable it independently
- Method: enable full mimic, verify bypass works, then disable features one by one to isolate the trigger
- Orthogonal to `--stealth 0-3` — mimic overrides specific packet construction params without touching StealthLevel
- When mimic is active, stealth behavior is forced to at least Standard level (timestamps, ISN, ACK frequency)

## Context (from discovery)
- files/components involved:
  - `fake-tcp/src/packet.rs` — TCP/IP packet construction, IP ID, SYN options, window field
  - `fake-tcp/src/lib.rs` — Socket (window calc, PSH logic, timestamp, ISN), Stack, StealthLevel enum, Shared struct
  - `phantun/src/bin/client.rs` — CLI argument parsing
  - `phantun/src/bin/server.rs` — CLI argument parsing
- related patterns found:
  - StealthLevel flows: CLI → Stack::new() → Shared → Socket::new() → build_tcp_packet()
  - Packet params controlled by Socket fields: `window_base`, `stealth`, `ts_offset`, `congestion`
  - `build_tcp_packet()` in packet.rs already has 10 params — new params should be bundled into a struct
  - IP ID currently always 0 (BytesMut::zeroed) with DF flag — correct per RFC 6864 but distinguishable
  - IP ID is IPv4-only — IPv6 has no identification field; mimic IP ID changes are no-ops for IPv6
  - phantun sends one UDP datagram = one TCP segment per `send()` call — no batching
- dependencies identified:
  - `pnet` crate for packet construction (IPv4 `set_identification` method available)
  - `clap` for CLI parsing (`Command::try_get_matches_from()` for testing)
  - Existing stealth level 2 (Standard) provides base behavior mimic builds on

## Development Approach
- **testing approach**: Regular (code first, then tests)
- complete each task fully before moving to the next
- make small, focused changes
- **CRITICAL: every task MUST include new/updated tests** for code changes in that task
- **CRITICAL: all tests must pass before starting next task** — no exceptions
- **CRITICAL: update this plan file when scope changes during implementation**
- run tests after each change
- maintain backward compatibility — stealth 0-3 must be unaffected

## Testing Strategy
- **unit tests**: required for every task
  - Packet construction tests: verify IP ID, wscale, window, PSH for mimic mode
  - MimicProfile toggle tests: each `--mimic-no-*` flag correctly disables its feature
  - CLI parsing tests: use `Command::try_get_matches_from()` for idiomatic clap testing
- **integration tests**: existing TUN-based tests should still pass (regression)
- **manual TSPU testing**: post-completion, user tests against real DPI (not automated)

## Progress Tracking
- mark completed items with `[x]` immediately when done
- add newly discovered tasks with ➕ prefix
- document issues/blockers with ⚠️ prefix
- update plan if implementation deviates from original scope

## What Goes Where
- **Implementation Steps** (`[ ]` checkboxes): code changes, tests, documentation
- **Post-Completion** (no checkboxes): manual TSPU testing, feature toggle experiments

## Implementation Steps

### Task 1: Define MimicProfile, MimicParams, and wire through Stack/Socket

**Files:**
- Modify: `fake-tcp/src/lib.rs`
- Modify: `fake-tcp/src/packet.rs`

- [x] Define `MimicProfile` struct in lib.rs with fields: `ip_id_incrementing: bool`, `wscale: u8`, `window_raw: u16`, `psh_always: bool`
- [x] Add `MimicProfile::udp2raw()` constructor returning: `ip_id_incrementing=true`, `wscale=5`, `window_raw=41000`, `psh_always=false`
- [x] Define `MimicParams` struct in packet.rs for per-packet overrides: `ip_id: u16`, `wscale: Option<u8>` — passed as `Option<MimicParams>` to `build_tcp_packet()` (single new param instead of multiple)
- [x] Add `Option<MimicProfile>` to `Shared` struct and wire through `Stack::new()` signature
- [x] Pass mimic from Shared to `Socket::new()` in both outbound (connect) and inbound (accept) paths
- [x] Store `mimic: Option<MimicProfile>` (immutable config) in Socket struct; add `ip_id_counter: Option<AtomicU16>` as per-socket mutable state initialized from profile
- [x] When mimic is active: force effective stealth to at least `StealthLevel::Standard` for timestamps, ISN, ACK frequency
- [x] Write unit tests for `MimicProfile::udp2raw()` default values
- [x] Write unit tests verifying Socket fields are correctly initialized from MimicProfile
- [x] Run tests — must pass before next task

### Task 2: Incrementing IP ID in packet construction

**Files:**
- Modify: `fake-tcp/src/packet.rs`
- Modify: `fake-tcp/src/lib.rs`

- [x] In `build_tcp_packet()`: when `MimicParams.ip_id > 0`, call `set_identification(ip_id)` on IPv4 packet and clear DF flag (udp2raw does not set DF); for IPv6 packets, ip_id is ignored (IPv6 has no ID field)
- [x] In Socket's `build_tcp_packet()` wrapper: if `ip_id_counter` is Some, `fetch_add(1, Relaxed)` and pass value in MimicParams; otherwise pass `ip_id: 0`
- [x] Initialize `ip_id_counter` with random starting value (like udp2raw) in Socket::new() when mimic has `ip_id_incrementing=true`
- [x] Write unit tests: IPv4 packet with ip_id=0 has ID=0 + DF flag set (existing behavior preserved)
- [x] Write unit tests: IPv4 packet with ip_id=N has ID=N, DF flag cleared
- [x] Write unit tests: IPv6 packet with mimic ip_id — no panic, ID field absent, no behavioral change
- [x] Write unit tests: AtomicU16 counter increments correctly across multiple sends, wraps at u16::MAX
- [x] Run tests — must pass before next task

### Task 3: Configurable window scale and raw window

**Files:**
- Modify: `fake-tcp/src/packet.rs`
- Modify: `fake-tcp/src/lib.rs`

- [x] In `build_tcp_packet()`: when `MimicParams.wscale` is Some, use it in SYN options instead of hardcoded 7
- [x] In Socket::new(): when mimic is Some, set `window_base` to `mimic.window_raw` (exact value, no jitter — match udp2raw's static window behavior)
- [x] Override SYN window: when mimic is Some, use `mimic.window_raw` as SYN window instead of 64240
- [x] In `current_window()`: when mimic is Some, return `mimic.window_raw` directly (static, matching udp2raw)
- [x] Write unit tests: SYN packet with wscale=5 has correct option bytes at correct offset (offset 18, value 5)
- [x] Write unit tests: window field in mimic mode equals window_raw exactly (41000), no jitter
- [x] Write unit tests: without mimic, window and wscale behavior unchanged per stealth level
- [x] Run tests — must pass before next task

### Task 4: PSH flag behavior for mimic mode

**Files:**
- Modify: `fake-tcp/src/lib.rs`

- [x] In Socket's send path where flags are set: when mimic is active and `psh_always=false`, set ACK only (no PSH) — since phantun sends one UDP datagram per TCP segment, every segment is effectively "the last", so disabling PSH entirely matches udp2raw's behavior where PSH is not set on most data packets
- [x] When `psh_always=true` (mimic-no-psh toggle) or no mimic: use existing behavior (PSH on all data for stealth >= Basic, no PSH for Off)
- [x] Write unit tests: mimic with psh_always=false → data packets have ACK flag only, no PSH
- [x] Write unit tests: mimic with psh_always=true → data packets have PSH|ACK (same as stealth Basic+)
- [x] Write unit tests: without mimic, PSH behavior unchanged per stealth level
- [x] Run tests — must pass before next task

### Task 5: CLI flags for --mimic and --mimic-no-* toggles

**Files:**
- Modify: `phantun/src/bin/client.rs`
- Modify: `phantun/src/bin/server.rs`

- [x] Add `--mimic <PROFILE>` argument (currently only "udp2raw" accepted) to both client.rs and server.rs
- [x] Add toggle flags: `--mimic-no-ipid`, `--mimic-no-wscale`, `--mimic-no-psh`, `--mimic-no-window` — each requires `--mimic` to be set (use clap's `requires`)
- [x] Extract a `build_mimic_profile(matches: &ArgMatches) -> Option<MimicProfile>` helper function for testability
- [x] Parse flags: start with `MimicProfile::udp2raw()`, then apply each `--mimic-no-*` to disable corresponding feature
- [x] Pass `Option<MimicProfile>` to `Stack::new()` alongside stealth level
- [x] Write unit tests using `Command::try_get_matches_from()`: mimic alone, mimic with each toggle, mimic with all toggles
- [x] Write unit tests: `build_mimic_profile()` returns correct profile for each flag combination
- [x] Run tests — must pass before next task

### Task 6: Verify acceptance criteria

- [x] Verify: `--stealth 0` still produces byte-identical packets to pre-mimic code (backward compat)
- [x] Verify: `--stealth 2` without `--mimic` behaves identically to before
- [x] Verify: `--mimic udp2raw` produces packets with: incrementing IP ID (non-zero), wscale=5, raw window=41000, no PSH on data
- [x] Verify: each `--mimic-no-*` flag correctly disables only its target feature
- [x] Verify: `--mimic udp2raw --mimic-no-ipid --mimic-no-wscale --mimic-no-psh --mimic-no-window` produces packets equivalent to `--stealth 2` behavior
- [x] Run full test suite: `./scripts/run-tests.sh`
- [x] Run clippy: `cargo clippy -p fake-tcp --verbose`

### Task 7: [Final] Update documentation

- [ ] Update CLAUDE.md with mimic mode description and flag reference
- [ ] Update README.md usage section with `--mimic udp2raw` examples and debugging workflow
- [ ] Move this plan to `docs/plans/completed/`

## Technical Details

### MimicProfile struct (immutable config, stored in Shared and Socket)
```rust
/// Immutable fingerprint profile — controls which TCP behaviors to mimic.
pub struct MimicProfile {
    /// Use incrementing IP ID counter instead of 0+DF (IPv4 only, no-op for IPv6)
    pub ip_id_incrementing: bool,
    /// TCP window scale value for SYN options (udp2raw=5, phantun default=7)
    pub wscale: u8,
    /// Raw TCP window value (before scaling). udp2raw uses 41000 (static, no jitter)
    pub window_raw: u16,
    /// Whether PSH flag is set on every data packet (true=phantun default, false=udp2raw style)
    pub psh_always: bool,
}
```

### MimicParams struct (per-packet, passed to build_tcp_packet)
```rust
/// Per-packet mimic overrides, computed by Socket from MimicProfile + mutable state.
pub struct MimicParams {
    /// IPv4 identification field value (0 = use default behavior with DF)
    pub ip_id: u16,
    /// Window scale override for SYN packets (None = use stealth default)
    pub wscale: Option<u8>,
}
```

### Per-socket mutable state (derived from MimicProfile in Socket::new)
```rust
// In Socket struct:
mimic: Option<MimicProfile>,          // immutable config
ip_id_counter: Option<AtomicU16>,     // Some when mimic.ip_id_incrementing=true, random start
```

### udp2raw defaults
| Feature | udp2raw | phantun stealth 2 | mimic udp2raw |
|---------|---------|-------------------|---------------|
| IP ID | incrementing counter | 0 (DF=1) | incrementing counter (no DF) |
| Window Scale | 5 | 7 | 5 |
| Raw Window | 41000 (static) | 256-512 (with jitter) | 41000 (static) |
| Effective Window | ~1.3MB | ~32-64KB | ~1.3MB |
| PSH on data | no (most packets) | yes (all data) | no |
| Timestamps | yes | yes | yes (from stealth >= Standard) |
| ISN | random | random | random (from stealth >= Standard) |

### Toggle flags mapping
| CLI flag | MimicProfile field | Effect when set |
|----------|-------------------|-----------------|
| `--mimic-no-ipid` | `ip_id_incrementing = false` | IP ID=0 with DF (phantun default) |
| `--mimic-no-wscale` | `wscale = 7` | Use phantun's default wscale=7 |
| `--mimic-no-psh` | `psh_always = true` | PSH on all data (stealth Basic+ behavior) |
| `--mimic-no-window` | `window_raw` = random 256..512 | Use phantun's Standard window computation |

### Debugging workflow
1. `--mimic udp2raw` → verify TSPU bypass works (should match udp2raw behavior)
2. `--mimic udp2raw --mimic-no-ipid` → if still bypasses, IP ID is not the trigger
3. `--mimic udp2raw --mimic-no-wscale` → if still bypasses, wscale is not the trigger
4. `--mimic udp2raw --mimic-no-psh` → if still bypasses, PSH is not the trigger
5. `--mimic udp2raw --mimic-no-window` → if still bypasses, window size is not the trigger
6. Combine: disable multiple to narrow down further

## Post-Completion
*Items requiring manual intervention — no checkboxes, informational only*

**Manual TSPU testing:**
- Deploy phantun with `--mimic udp2raw` and verify it bypasses DPI (baseline)
- Run toggle experiments one by one to isolate which fingerprint triggers blocking
- Document findings for future stealth level improvements

**Future work (based on findings):**
- Integrate successful fingerprint changes into stealth level 2 or 3 as default behavior
- Consider adding more mimic profiles (e.g., `--mimic linux-curl`, `--mimic chrome`) if DPI profiling proves useful
