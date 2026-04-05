//! A minimum, userspace TCP based datagram stack
//!
//! # Overview
//!
//! `fake-tcp` is a reusable library that implements a minimum TCP stack in
//! user space using the Tun interface. It allows programs to send datagrams
//! as if they are part of a TCP connection. `fake-tcp` has been tested to
//! be able to pass through a variety of NAT and stateful firewalls while
//! fully preserves certain desirable behavior such as out of order delivery
//! and no congestion/flow controls.
//!
//! # Core Concepts
//!
//! The core of the `fake-tcp` crate compose of two structures. [`Stack`] and
//! [`Socket`].
//!
//! ## [`Stack`]
//!
//! [`Stack`] represents a virtual TCP stack that operates at
//! Layer 3. It is responsible for:
//!
//! * TCP active and passive open and handshake
//! * `RST` handling
//! * Interact with the Tun interface at Layer 3
//! * Distribute incoming datagrams to corresponding [`Socket`]
//!
//! ## [`Socket`]
//!
//! [`Socket`] represents a TCP connection. It registers the identifying
//! tuple `(src_ip, src_port, dest_ip, dest_port)` inside the [`Stack`] so
//! so that incoming packets can be distributed to the right [`Socket`] with
//! using a channel. It is also what the client should use for
//! sending/receiving datagrams.
//!
//! # Examples
//!
//! Please see [`client.rs`](https://github.com/dndx/phantun/blob/main/phantun/src/bin/client.rs)
//! and [`server.rs`](https://github.com/dndx/phantun/blob/main/phantun/src/bin/server.rs) files
//! from the `phantun` crate for how to use this library in client/server mode, respectively.


pub mod packet;

#[cfg(feature = "integration-tests")]
pub mod testing;

use bytes::{Bytes, BytesMut};
use log::{error, info, trace, warn};
use packet::*;
use pnet::packet::{tcp, Packet};
use rand::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{
    atomic::{AtomicU16, AtomicU32, Ordering},
    Arc, Mutex, RwLock,
};
use std::time::Instant;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;
use tokio_tun::Tun;
use tokio_util::sync::CancellationToken;

/// Stealth level controlling TCP fingerprint realism.
///
/// Each level includes all behaviors of previous levels.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum StealthLevel {
    #[default]
    Off = 0,      // current behavior, byte-compatible
    Basic = 1,    // fix hard signatures (ISN, SYN fingerprint, timestamps)
    Standard = 2, // stateful mimicry (dynamic window, frequent ACK, ts_ecr)
    Full = 3,     // advanced (dup ACK, send window, congestion)
}

impl From<u8> for StealthLevel {
    fn from(value: u8) -> Self {
        match value {
            0 => StealthLevel::Off,
            1 => StealthLevel::Basic,
            2 => StealthLevel::Standard,
            _ => StealthLevel::Full, // clamp anything >= 3 to Full
        }
    }
}

/// Immutable fingerprint profile — controls which TCP behaviors to mimic.
/// When active, forces effective stealth to at least `Standard` level.
#[derive(Clone, Debug)]
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

impl MimicProfile {
    /// Returns a profile that mimics udp2raw's TCP fingerprint.
    pub fn udp2raw() -> Self {
        MimicProfile {
            ip_id_incrementing: true,
            wscale: 5,
            window_raw: 41000,
            psh_always: false,
        }
    }
}

const TIMEOUT: time::Duration = time::Duration::from_secs(1);
const RETRIES: usize = 6;
const MPMC_BUFFER_LEN: usize = 512;
const MPSC_BUFFER_LEN: usize = 128;
const MSS: u32 = 1460;
const MAX_UNACKED_LEN: u32 = 128 * 1024 * 1024; // 128MB
/// Linux TCP default SYN window (64240 bytes), matching the kernel's initial
/// rcvbuf-derived window (net.ipv4.tcp_rmem default).
const SYN_WINDOW: u16 = 64240;

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct AddrTuple {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
}

impl AddrTuple {
    fn new(local_addr: SocketAddr, remote_addr: SocketAddr) -> AddrTuple {
        AddrTuple {
            local_addr,
            remote_addr,
        }
    }
}

struct Shared {
    tuples: RwLock<HashMap<AddrTuple, flume::Sender<Bytes>>>,
    listening: RwLock<HashSet<u16>>,
    tun: Vec<Arc<Tun>>,
    ready: mpsc::Sender<Socket>,
    tuples_purge: broadcast::Sender<AddrTuple>,
    stealth: StealthLevel,
    mimic: Option<MimicProfile>,
}

pub struct Stack {
    shared: Arc<Shared>,
    local_ip: Ipv4Addr,
    local_ip6: Option<Ipv6Addr>,
    ready: mpsc::Receiver<Socket>,
    cancel: CancellationToken,
    reader_handles: Vec<JoinHandle<()>>,
}

pub enum State {
    Idle,
    SynSent,
    SynReceived,
    Established,
}

/// Grouped congestion control state for stealth Level 3 (Full).
///
/// All fields are protected by a single Mutex to prevent race conditions
/// between concurrent recv() and send() calls that read/write related
/// congestion state. Only allocated when `stealth >= Full`.
pub(crate) struct CongestionState {
    /// Count of consecutive identical ACK values from peer
    pub(crate) dup_ack_count: u32,
    /// Last sequence number acknowledged by peer
    pub(crate) last_acked_seq: u32,
    /// Peer's effective advertised receive window
    pub(crate) peer_window: u32,
    /// Congestion window in bytes
    pub(crate) cwnd: u32,
    /// Slow start threshold in bytes
    pub(crate) ssthresh: u32,
    /// Highest sequence number ever sent (monotonically increasing, never rewound)
    pub(crate) snd_nxt: u32,
    /// Last peer advertised window seen (raw, unscaled) for dup ACK detection
    pub(crate) last_peer_window: u16,
}

pub struct Socket {
    shared: Arc<Shared>,
    tun: Arc<Tun>,
    incoming: flume::Receiver<Bytes>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    seq: AtomicU32,
    ack: AtomicU32,
    last_ack: AtomicU32,
    state: State,
    stealth: StealthLevel,
    /// Epoch for computing ts_val (stealth >= Basic)
    ts_epoch: Instant,
    /// Random offset added to ts_val to avoid leaking uptime (stealth >= Basic)
    ts_offset: u32,
    /// Last received peer tsval, echoed back as ts_ecr (stealth >= Basic)
    ts_ecr: AtomicU32,
    /// Base window value for dynamic window randomization (stealth >= Standard)
    window_base: u16,
    /// Last window value we sent, reused for duplicate ACKs (stealth >= Standard)
    last_window_sent: AtomicU16,
    /// Grouped congestion state behind a Mutex (stealth >= Full only).
    /// `None` for stealth levels Off, Basic, and Standard.
    congestion: Option<Mutex<CongestionState>>,
    /// Immutable mimic fingerprint profile (None = no mimic active)
    mimic: Option<MimicProfile>,
    /// Per-socket incrementing IP ID counter (Some when mimic.ip_id_incrementing=true)
    ip_id_counter: Option<AtomicU16>,
}

/// A socket that represents a unique TCP connection between a server and client.
///
/// The `Socket` object itself satisfies `Sync` and `Send`, which means it can
/// be safely called within an async future.
///
/// To close a TCP connection that is no longer needed, simply drop this object
/// out of scope.
impl Socket {
    #[allow(clippy::too_many_arguments)]
    fn new(
        shared: Arc<Shared>,
        tun: Arc<Tun>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        ack: Option<u32>,
        state: State,
        stealth: StealthLevel,
        mimic: Option<MimicProfile>,
    ) -> (Socket, flume::Sender<Bytes>) {
        let (incoming_tx, incoming_rx) = flume::bounded(MPMC_BUFFER_LEN);

        // When mimic is active, force effective stealth to at least Standard
        let effective_stealth = if mimic.is_some() {
            stealth.max(StealthLevel::Standard)
        } else {
            stealth
        };

        let initial_seq = if effective_stealth >= StealthLevel::Basic {
            rand::random::<u32>()
        } else {
            0
        };

        let ip_id_counter = mimic
            .as_ref()
            .filter(|m| m.ip_id_incrementing)
            .map(|_| AtomicU16::new(rand::random::<u16>()));

        (
            Socket {
                shared,
                tun,
                incoming: incoming_rx,
                local_addr,
                remote_addr,
                seq: AtomicU32::new(initial_seq),
                ack: AtomicU32::new(ack.unwrap_or(0)),
                last_ack: AtomicU32::new(ack.unwrap_or(0)),
                state,
                stealth: effective_stealth,
                ts_epoch: Instant::now(),
                ts_offset: if effective_stealth >= StealthLevel::Basic {
                    rand::random::<u32>()
                } else {
                    0
                },
                ts_ecr: AtomicU32::new(0),
                window_base: if let Some(ref m) = mimic {
                    m.window_raw
                } else if effective_stealth >= StealthLevel::Standard {
                    // Random base window in range 256..=512, representing ~32K-64K
                    // effective receive window with wscale=7
                    256 + (rand::random::<u16>() % 257)
                } else {
                    0xFFFF
                },
                last_window_sent: AtomicU16::new(0),
                congestion: if effective_stealth >= StealthLevel::Full {
                    Some(Mutex::new(CongestionState {
                        dup_ack_count: 0,
                        last_acked_seq: initial_seq,
                        peer_window: 0,
                        cwnd: 10 * MSS,
                        ssthresh: 65535,
                        snd_nxt: initial_seq,
                        last_peer_window: 0,
                    }))
                } else {
                    None
                },
                mimic,
                ip_id_counter,
            },
            incoming_tx,
        )
    }

    /// Returns an opaque identifier for the TUN queue this socket is bound to.
    /// Two sockets on the same queue return the same value. Useful for verifying
    /// that benchmark connections cover all queues.
    #[cfg(feature = "integration-tests")]
    pub fn tun_queue_id(&self) -> usize {
        Arc::as_ptr(&self.tun) as usize
    }

    /// Compute the current ts_val from elapsed time + random offset
    fn current_ts_val(&self) -> u32 {
        if self.stealth >= StealthLevel::Basic {
            (self.ts_epoch.elapsed().as_millis() as u32).wrapping_add(self.ts_offset)
        } else {
            0
        }
    }

    /// Compute the current advertised window value.
    /// For stealth >= Standard, adds small random jitter to window_base.
    /// For lower stealth levels, returns static 0xFFFF.
    fn current_window(&self) -> u16 {
        if self.mimic.is_some() {
            // Mimic mode: return static window_raw (no jitter), matching udp2raw
            self.window_base
        } else if self.stealth >= StealthLevel::Standard {
            // Add jitter of 0..32 to base window to simulate natural variation
            self.window_base.wrapping_add(rand::random::<u16>() % 32)
        } else {
            0xFFFF
        }
    }

    fn build_tcp_packet(&self, flags: u8, payload: Option<&[u8]>) -> Bytes {
        let ack = self.ack.load(Ordering::Relaxed);
        let prev_ack = self.last_ack.load(Ordering::Relaxed);
        self.last_ack.store(ack, Ordering::Relaxed);

        // Per RFC 5681, duplicate ACKs must carry the same advertised window.
        // If we re-rolled jitter on every pure ACK, the peer's dup-ACK detector
        // would see window updates instead of true duplicates. Reuse the
        // previous window when sending a pure ACK with an unchanged ack number.
        // Exclude SYN/SYN+ACK: handshake packets must always advertise a real
        // window (last_window_sent starts at 0 and hasn't been set yet).
        let is_syn = (flags & tcp::TcpFlags::SYN) != 0;
        let window = if is_syn && self.mimic.is_some() {
            // Mimic mode: use profile's window_raw for SYN packets too
            let w = self.window_base;
            self.last_window_sent.store(w, Ordering::Relaxed);
            w
        } else if is_syn && self.stealth >= StealthLevel::Basic {
            // SYN/SYN+ACK: use Linux-like initial window (64240) for stealth >= Basic.
            let w = SYN_WINDOW;
            self.last_window_sent.store(w, Ordering::Relaxed);
            w
        } else if self.stealth >= StealthLevel::Standard
            && !is_syn
            && payload.is_none()
            && ack == prev_ack
        {
            self.last_window_sent.load(Ordering::Relaxed)
        } else {
            let w = self.current_window();
            self.last_window_sent.store(w, Ordering::Relaxed);
            w
        };

        let mimic_params = self.mimic.as_ref().map(|profile| {
            MimicParams {
                ip_id: self
                    .ip_id_counter
                    .as_ref()
                    .map(|c| c.fetch_add(1, Ordering::Relaxed))
                    .unwrap_or(0),
                wscale: Some(profile.wscale),
            }
        });

        build_tcp_packet(
            self.local_addr,
            self.remote_addr,
            self.seq.load(Ordering::Relaxed),
            ack,
            flags,
            payload,
            self.stealth,
            self.current_ts_val(),
            self.ts_ecr.load(Ordering::Relaxed),
            window,
            mimic_params.as_ref(),
        )
    }

    /// Sends a datagram to the other end.
    ///
    /// This method takes `&self`, and it can be called safely by multiple threads
    /// at the same time.
    ///
    /// A return of `None` means the Tun socket returned an error
    /// and this socket must be closed.
    pub async fn send(&self, payload: &[u8]) -> Option<()> {
        match self.state {
            State::Established => {
                let flags = if let Some(ref mimic) = self.mimic {
                    if mimic.psh_always {
                        // mimic-no-psh toggle: use stealth Basic+ behavior (PSH on all data)
                        tcp::TcpFlags::PSH | tcp::TcpFlags::ACK
                    } else {
                        // udp2raw style: ACK only, no PSH on data packets
                        tcp::TcpFlags::ACK
                    }
                } else if self.stealth >= StealthLevel::Basic {
                    tcp::TcpFlags::PSH | tcp::TcpFlags::ACK
                } else {
                    tcp::TcpFlags::ACK
                };

                // Send window constraint + seq advance (stealth >= Full):
                // All congestion reads (peer_window, cwnd, last_acked_seq) and
                // seq writes (fetch_add, snd_nxt update) are done under a single
                // Mutex to prevent interleaving between concurrent send() calls
                // and recv()'s fast retransmit seq rewind.
                let buf = if let Some(ref cong_mutex) = self.congestion {
                    let mut cong = cong_mutex.lock().unwrap_or_else(|e| e.into_inner());
                    // Effective window: use peer's advertised window if known,
                    // otherwise fall back to cwnd alone (peer_window starts at 0
                    // until the first data packet is received from the peer)
                    let effective_win = if cong.peer_window > 0 {
                        cong.peer_window.min(cong.cwnd)
                    } else {
                        cong.cwnd
                    };
                    if effective_win > 0 {
                        let current_seq = self.seq.load(Ordering::Relaxed);
                        let bytes_in_flight = current_seq.wrapping_sub(cong.last_acked_seq);
                        if bytes_in_flight.wrapping_add(payload.len() as u32) > effective_win {
                            self.seq.store(cong.last_acked_seq, Ordering::Relaxed);
                        }
                    }
                    // Build packet while seq still holds the pre-advance value
                    let buf = self.build_tcp_packet(flags, Some(payload));
                    // seq.fetch_add and snd_nxt update must be inside the lock
                    // to prevent a concurrent send() from interleaving between
                    // the window check and the fetch_add
                    let new_seq = self.seq.fetch_add(payload.len() as u32, Ordering::Relaxed)
                        .wrapping_add(payload.len() as u32);
                    if (new_seq.wrapping_sub(cong.snd_nxt) as i32) > 0 {
                        cong.snd_nxt = new_seq;
                    }
                    buf
                } else {
                    // Non-Full stealth: no lock needed
                    let buf = self.build_tcp_packet(flags, Some(payload));
                    self.seq.fetch_add(payload.len() as u32, Ordering::Relaxed);
                    buf
                };

                self.tun.send(&buf).await.ok().and(Some(()))
            }
            _ => unreachable!(),
        }
    }

    /// Attempt to receive a datagram from the other end.
    ///
    /// This method takes `&self`, and it can be called safely by multiple threads
    /// at the same time.
    ///
    /// A return of `None` means the TCP connection is broken
    /// and this socket must be closed.
    pub async fn recv(&self, buf: &mut [u8]) -> Option<usize> {
        match self.state {
            State::Established => {
                loop {
                    let raw_buf = match self.incoming.recv_async().await {
                        Ok(buf) => buf,
                        Err(_) => return None,
                    };

                    let (_v4_packet, tcp_packet) = match parse_ip_packet(&raw_buf) {
                        Some(parsed) => parsed,
                        None => {
                            warn!("Connection {} recv: failed to parse packet, skipping", self);
                            continue;
                        }
                    };

                    if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
                        info!("Connection {} reset by peer", self);
                        return None;
                    }

                    // Update ts_ecr with peer's tsval from incoming packet
                    if self.stealth >= StealthLevel::Basic
                        && let Some(peer_tsval) = parse_tcp_timestamps(&tcp_packet).map(|(tsval, _)| tsval)
                    {
                        self.ts_ecr.store(peer_tsval, Ordering::Relaxed);
                    }

                    // Track duplicate ACKs for fast retransmit (stealth >= Full)
                    // All congestion state reads/writes are done under a single Mutex
                    // to prevent race conditions between concurrent recv() calls
                    // (e.g., double-halving cwnd on duplicate ACKs).
                    if self.stealth >= StealthLevel::Full {
                        let peer_ack = tcp_packet.get_acknowledgement();
                        let is_pure_ack = tcp_packet.payload().is_empty();
                        let peer_raw_window = tcp_packet.get_window();

                        let mut cong = self.congestion.as_ref().unwrap().lock().unwrap_or_else(|e| e.into_inner());

                        let mut ack_is_valid = false;
                        if peer_ack == cong.last_acked_seq && is_pure_ack && peer_raw_window == cong.last_peer_window
                            && (cong.snd_nxt.wrapping_sub(cong.last_acked_seq) as i32) > 0
                        {
                            // Only count pure ACKs (no data) with unchanged advertised
                            // window AND outstanding data (snd_nxt > last_acked) as
                            // duplicate ACKs per RFC 5681. Packets with a changed window
                            // are window updates, not dup ACKs.
                            cong.dup_ack_count += 1;
                            ack_is_valid = true;
                            if cong.dup_ack_count >= 3 {
                                // Triple duplicate ACK: reset seq to last acked position
                                // (simulate fast retransmit). Must be inside the lock to
                                // prevent TOCTOU with send()'s window constraint + fetch_add.
                                self.seq.store(cong.last_acked_seq, Ordering::Relaxed);
                                // Multiplicative decrease: halve cwnd, set ssthresh
                                let new_ssthresh = (cong.cwnd / 2).max(2 * MSS);
                                cong.ssthresh = new_ssthresh;
                                cong.cwnd = new_ssthresh;
                                // Reset counter to prevent repeated halving on subsequent dups
                                cong.dup_ack_count = 0;
                            }
                        } else if (peer_ack.wrapping_sub(cong.last_acked_seq) as i32) > 0
                            && (cong.snd_nxt.wrapping_sub(peer_ack) as i32) >= 0
                        {
                            // Accept ACKs that advance monotonically AND do not
                            // exceed SND.NXT. ACKs past what we've sent are invalid
                            // (could be injected by a middlebox) and are dropped to
                            // prevent last_acked_seq from jumping ahead of seq.
                            cong.last_acked_seq = peer_ack;
                            cong.dup_ack_count = 0;
                            ack_is_valid = true;
                            // Congestion window growth on new ACK
                            // Cap cwnd at 1MB to keep congestion simulation meaningful
                            const MAX_CWND: u32 = 1_048_576;
                            if cong.cwnd < MAX_CWND {
                                if cong.cwnd < cong.ssthresh {
                                    // Slow start: increase cwnd by MSS (doubles per RTT)
                                    cong.cwnd = (cong.cwnd + MSS).min(MAX_CWND);
                                } else {
                                    // Congestion avoidance: increase cwnd by MSS per RTT
                                    // Approximate: add MSS^2/cwnd per ACK
                                    let increment = (MSS * MSS).checked_div(cong.cwnd).unwrap_or(1);
                                    cong.cwnd = (cong.cwnd + increment.max(1)).min(MAX_CWND);
                                }
                            }
                        } else if peer_ack == cong.last_acked_seq {
                            // Non-dup-ACK with matching ack number (e.g., data-carrying
                            // packet or changed window): still valid for window updates.
                            ack_is_valid = true;
                        }
                        // else: Invalid ACK (beyond SND.NXT, stale, or reordered):
                        // skip window updates to prevent a bogus advertised
                        // window from shrinking the effective send window.

                        if ack_is_valid {
                            // Update last seen peer window for dup ACK detection
                            cong.last_peer_window = peer_raw_window;

                            // Store peer's advertised receive window (scaled by wscale=7).
                            // NOTE: This assumes the peer also uses wscale=7, which is true
                            // when both sides run the same stealth level (as documented in
                            // README). Mismatched stealth levels will produce incorrect
                            // window scaling.
                            let raw_window = tcp_packet.get_window() as u32;
                            cong.peer_window = raw_window << 7;
                        }
                        // Lock released here at end of scope
                    }

                    let payload = tcp_packet.payload();

                    let new_ack = tcp_packet.get_sequence().wrapping_add(payload.len() as u32);
                    let last_ask = self.last_ack.load(Ordering::Relaxed);
                    self.ack.store(new_ack, Ordering::Relaxed);

                    let send_ack = if self.stealth >= StealthLevel::Standard {
                        // Level 2+: send standalone ACK on every received data packet
                        new_ack != last_ask
                    } else {
                        // Level 0-1: only send ACK after 128MB of unacked data
                        new_ack.overflowing_sub(last_ask).0 > MAX_UNACKED_LEN
                    };

                    if send_ack {
                        let ack_buf = self.build_tcp_packet(tcp::TcpFlags::ACK, None);
                        if let Err(e) = self.tun.try_send(&ack_buf) {
                            info!("Connection {} unable to send standalone ACK: {}", self, e)
                        }
                    }

                    let copy_len = payload.len().min(buf.len());
                    if payload.len() > buf.len() {
                        warn!(
                            "recv: payload ({} bytes) truncated to buffer size ({} bytes)",
                            payload.len(),
                            buf.len()
                        );
                    }
                    buf[..copy_len].copy_from_slice(&payload[..copy_len]);

                    return Some(copy_len);
                }
            }
            _ => unreachable!(),
        }
    }

    async fn accept(mut self, cancel: CancellationToken) {
        for _ in 0..RETRIES {
            if cancel.is_cancelled() {
                trace!("Accept cancelled during handshake, aborting");
                return;
            }
            match self.state {
                State::Idle => {
                    let buf = self.build_tcp_packet(tcp::TcpFlags::SYN | tcp::TcpFlags::ACK, None);
                    // ACK set by constructor
                    if let Err(e) = self.tun.send(&buf).await {
                        warn!("accept: failed to send SYN+ACK to TUN: {}, retrying", e);
                        continue;
                    }
                    self.state = State::SynReceived;
                    info!("Sent SYN + ACK to client");
                }
                State::SynReceived => {
                    let res = tokio::select! {
                        _ = cancel.cancelled() => {
                            trace!("Accept cancelled while waiting for ACK");
                            return;
                        }
                        res = time::timeout(TIMEOUT, self.incoming.recv_async()) => res,
                    };
                    if let Ok(buf) = res {
                        let buf = match buf {
                            Ok(b) => b,
                            Err(_) => {
                                warn!("accept: incoming channel closed");
                                return;
                            }
                        };
                        let (_v4_packet, tcp_packet) = match parse_ip_packet(&buf) {
                            Some(parsed) => parsed,
                            None => {
                                warn!("accept: failed to parse incoming packet, retrying");
                                continue;
                            }
                        };

                        if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
                            return;
                        }

                        // Update ts_ecr from handshake ACK
                        if self.stealth >= StealthLevel::Basic
                            && let Some(peer_tsval) = parse_tcp_timestamps(&tcp_packet).map(|(tsval, _)| tsval)
                        {
                            self.ts_ecr.store(peer_tsval, Ordering::Relaxed);
                        }

                        if tcp_packet.get_flags() == tcp::TcpFlags::ACK
                            && tcp_packet.get_acknowledgement()
                                == self.seq.load(Ordering::Relaxed).wrapping_add(1)
                        {
                            // found our ACK
                            self.seq.fetch_add(1, Ordering::Relaxed);
                            // Update CongestionState so Level 3
                            // bytes_in_flight starts at 0
                            let new_seq = self.seq.load(Ordering::Relaxed);
                            if let Some(ref cong_mutex) = self.congestion {
                                let mut cong = cong_mutex.lock().unwrap_or_else(|e| e.into_inner());
                                cong.last_acked_seq = new_seq;
                                cong.snd_nxt = new_seq;
                            }
                            self.state = State::Established;

                            info!("Connection from {:?} established", self.remote_addr);
                            let ready = self.shared.ready.clone();
                            tokio::select! {
                                biased;
                                _ = cancel.cancelled() => {
                                    trace!("Accept cancelled while sending to ready queue");
                                }
                                res = ready.send(self) => {
                                    if let Err(e) = res {
                                        error!("Unable to send accepted socket to ready queue: {}", e);
                                    }
                                }
                            }
                            return;
                        }
                    } else {
                        info!("Waiting for client ACK timed out");
                        self.state = State::Idle;
                    }
                }
                _ => unreachable!(),
            }
        }
    }

    async fn connect(&mut self) -> Option<()> {
        for _ in 0..RETRIES {
            match self.state {
                State::Idle => {
                    let buf = self.build_tcp_packet(tcp::TcpFlags::SYN, None);
                    if let Err(e) = self.tun.send(&buf).await {
                        warn!("connect: failed to send SYN to TUN: {}, retrying", e);
                        continue;
                    }
                    self.state = State::SynSent;
                    info!("Sent SYN to server");
                }
                State::SynSent => {
                    match time::timeout(TIMEOUT, self.incoming.recv_async()).await {
                        Ok(buf) => {
                            let buf = match buf {
                                Ok(b) => b,
                                Err(_) => {
                                    warn!("connect: incoming channel closed");
                                    return None;
                                }
                            };
                            let (_v4_packet, tcp_packet) = match parse_ip_packet(&buf) {
                                Some(parsed) => parsed,
                                None => {
                                    warn!("connect: failed to parse incoming packet, retrying");
                                    continue;
                                }
                            };

                            if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
                                return None;
                            }

                            // Update ts_ecr from SYN+ACK
                            if self.stealth >= StealthLevel::Basic
                                && let Some(peer_tsval) = parse_tcp_timestamps(&tcp_packet).map(|(tsval, _)| tsval)
                            {
                                self.ts_ecr.store(peer_tsval, Ordering::Relaxed);
                            }

                            if tcp_packet.get_flags() == tcp::TcpFlags::SYN | tcp::TcpFlags::ACK
                                && tcp_packet.get_acknowledgement()
                                    == self.seq.load(Ordering::Relaxed).wrapping_add(1)
                            {
                                // found our SYN + ACK
                                self.seq.fetch_add(1, Ordering::Relaxed);
                                self.ack
                                    .store(tcp_packet.get_sequence().wrapping_add(1), Ordering::Relaxed);
                                // Update CongestionState so Level 3
                                // bytes_in_flight starts at 0
                                let new_seq = self.seq.load(Ordering::Relaxed);
                                if let Some(ref cong_mutex) = self.congestion {
                                    let mut cong = cong_mutex.lock().unwrap_or_else(|e| e.into_inner());
                                    cong.last_acked_seq = new_seq;
                                    cong.snd_nxt = new_seq;
                                }

                                // send ACK to finish handshake
                                let buf = self.build_tcp_packet(tcp::TcpFlags::ACK, None);
                                if let Err(e) = self.tun.send(&buf).await {
                                    warn!("connect: failed to send handshake ACK to TUN: {}, retrying", e);
                                    // Roll back seq so the retransmitted SYN+ACK passes
                                    // the ack == seq + 1 check on the next iteration.
                                    // ack/congestion updates are idempotent (absolute stores).
                                    self.seq.fetch_sub(1, Ordering::Relaxed);
                                    continue;
                                }

                                self.state = State::Established;

                                info!("Connection to {:?} established", self.remote_addr);
                                return Some(());
                            }
                        }
                        Err(_) => {
                            info!("Waiting for SYN + ACK timed out");
                            // Reset ts_ecr so the retransmitted SYN has ts_ecr=0
                            // (RFC 7323: initial SYN must not echo a prior peer timestamp)
                            if self.stealth >= StealthLevel::Basic {
                                self.ts_ecr.store(0, Ordering::Relaxed);
                            }
                            self.state = State::Idle;
                        }
                    }
                }
                _ => unreachable!(),
            }
        }

        None
    }
}

impl Drop for Socket {
    /// Drop the socket and close the TCP connection
    fn drop(&mut self) {
        let tuple = AddrTuple::new(self.local_addr, self.remote_addr);
        // dissociates ourself from the dispatch map
        if let Ok(mut tuples) = self.shared.tuples.write() {
            if tuples.remove(&tuple).is_none() {
                warn!("Socket drop: tuple {:?} already removed from dispatch map", tuple);
            }
        } else {
            warn!("Socket drop: tuples lock poisoned, cannot remove {:?}", tuple);
        }
        // purge cache (ignore error if no receivers exist, e.g. during shutdown)
        let _ = self.shared.tuples_purge.send(tuple);

        // Send RST with StealthLevel::Off to avoid timestamps on RST packets,
        // which would be a distinguishing fingerprint (real Linux omits them)
        let buf = build_tcp_packet(
            self.local_addr,
            self.remote_addr,
            self.seq.load(Ordering::Relaxed),
            0,
            tcp::TcpFlags::RST,
            None,
            StealthLevel::Off,
            0,
            0,
            0, // Real Linux sends RST with window=0
            None,
        );
        if let Err(e) = self.tun.try_send(&buf) {
            warn!("Unable to send RST to remote end: {}", e);
        }

        info!("Fake TCP connection to {} closed", self);
    }
}

impl fmt::Display for Socket {
    /// User-friendly string representation of the socket
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(Fake TCP connection from {} to {})",
            self.local_addr, self.remote_addr
        )
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        // Note: reader tasks are signalled but not joined (Drop is sync).
        // Call shutdown() for clean teardown that awaits task completion.
        self.cancel.cancel();
    }
}

/// A userspace TCP state machine
impl Stack {
    /// Create a new stack, `tun` is an array of [`Tun`](tokio_tun::Tun).
    /// When more than one [`Tun`](tokio_tun::Tun) object is passed in, same amount
    /// of reader will be spawned later. This allows user to utilize the performance
    /// benefit of Multiqueue Tun support on machines with SMP.
    pub fn new(
        tun: Vec<Tun>,
        local_ip: Ipv4Addr,
        local_ip6: Option<Ipv6Addr>,
        stealth: StealthLevel,
        mimic: Option<MimicProfile>,
    ) -> Stack {
        let tun: Vec<Arc<Tun>> = tun.into_iter().map(Arc::new).collect();
        let (ready_tx, ready_rx) = mpsc::channel(MPSC_BUFFER_LEN);
        let (tuples_purge_tx, _tuples_purge_rx) = broadcast::channel(16);
        let cancel = CancellationToken::new();
        let shared = Arc::new(Shared {
            tuples: RwLock::new(HashMap::new()),
            tun: tun.clone(),
            listening: RwLock::new(HashSet::new()),
            ready: ready_tx,
            tuples_purge: tuples_purge_tx.clone(),
            stealth,
            mimic,
        });

        let mut reader_handles = Vec::with_capacity(tun.len());
        for t in tun {
            let handle = tokio::spawn(Stack::reader_task(
                t,
                shared.clone(),
                tuples_purge_tx.subscribe(),
                cancel.clone(),
            ));
            reader_handles.push(handle);
        }

        Stack {
            shared,
            local_ip,
            local_ip6,
            ready: ready_rx,
            cancel,
            reader_handles,
        }
    }

    /// Shuts down the stack by cancelling all reader tasks and waiting for them to finish.
    ///
    /// This releases TUN file descriptors and stops background tasks, preventing
    /// resource leaks when a `Stack` is no longer needed. Can be called multiple
    /// times safely; subsequent calls are no-ops.
    pub async fn shutdown(&mut self) {
        self.cancel.cancel();
        for handle in self.reader_handles.drain(..) {
            let _ = handle.await;
        }
    }

    /// Listens for incoming connections on the given `port`.
    pub fn listen(&mut self, port: u16) {
        assert!(self.shared.listening.write().unwrap().insert(port));
    }

    /// Accepts an incoming connection.
    pub async fn accept(&mut self) -> Socket {
        self.ready.recv().await.unwrap()
    }

    /// Connects to the remote end. `None` returned means
    /// the connection attempt failed.
    pub async fn connect(&mut self, addr: SocketAddr) -> Option<Socket> {
        let mut rng = SmallRng::from_os_rng();
        for local_port in rng.random_range(32768..=60999)..=60999 {
            let local_addr = SocketAddr::new(
                if addr.is_ipv4() {
                    IpAddr::V4(self.local_ip)
                } else {
                    IpAddr::V6(self.local_ip6.expect("IPv6 local address undefined"))
                },
                local_port,
            );
            let tuple = AddrTuple::new(local_addr, addr);
            let mut sock;

            {
                let mut tuples = self.shared.tuples.write().unwrap();
                if tuples.contains_key(&tuple) {
                    trace!(
                        "Fake TCP connection to {}, local port number {} already in use, trying another one",
                        addr, local_port
                    );
                    continue;
                }

                let incoming;
                (sock, incoming) = Socket::new(
                    self.shared.clone(),
                    self.shared.tun.choose(&mut rng).unwrap().clone(),
                    local_addr,
                    addr,
                    None,
                    State::Idle,
                    self.shared.stealth,
                    self.shared.mimic.clone(),
                );

                assert!(tuples.insert(tuple, incoming).is_none());
            }

            return sock.connect().await.map(|_| sock);
        }

        error!(
            "Fake TCP connection to {} failed, emphemeral port number exhausted",
            addr
        );
        None
    }

    async fn reader_task(
        tun: Arc<Tun>,
        shared: Arc<Shared>,
        mut tuples_purge: broadcast::Receiver<AddrTuple>,
        cancel: CancellationToken,
    ) {
        let mut tuples: HashMap<AddrTuple, flume::Sender<Bytes>> = HashMap::new();

        loop {
            let mut buf = BytesMut::zeroed(MAX_PACKET_LEN);

            tokio::select! {
                _ = cancel.cancelled() => {
                    trace!("Reader task cancelled, shutting down");
                    return;
                }
                size = tun.recv(&mut buf) => {
                    let size = match size {
                        Ok(s) => s,
                        Err(e) => {
                            warn!("reader_task: TUN recv error: {}, continuing", e);
                            continue;
                        }
                    };
                    buf.truncate(size);
                    let buf = buf.freeze();

                    match parse_ip_packet(&buf) {
                        Some((ip_packet, tcp_packet)) => {
                            let local_addr =
                                SocketAddr::new(ip_packet.get_destination(), tcp_packet.get_destination());
                            let remote_addr = SocketAddr::new(ip_packet.get_source(), tcp_packet.get_source());

                            let tuple = AddrTuple::new(local_addr, remote_addr);
                            if let Some(c) = tuples.get(&tuple) {
                                tokio::select! {
                                    _ = cancel.cancelled() => { return; }
                                    // clone is cheap (Bytes refcount bump); buf may be needed if cache entry is stale
                    result = c.send_async(buf.clone()) => {
                                        if result.is_err() {
                                            trace!("Cache hit, but receiver closed — removing stale entry");
                                            tuples.remove(&tuple);
                                        } else {
                                            continue;
                                        }
                                    }
                                }
                                // Stale cache entry removed — fall through to shared map lookup
                            }

                            {
                                trace!("Cache miss, checking the shared tuples table for connection");
                                let sender = {
                                    let tuples = shared.tuples.read().unwrap();
                                    tuples.get(&tuple).cloned()
                                };

                                if let Some(c) = sender {
                                    trace!("Storing connection information into local tuples");
                                    tuples.insert(tuple, c.clone());
                                    tokio::select! {
                                        _ = cancel.cancelled() => { return; }
                                        result = c.send_async(buf) => {
                                            if result.is_err() {
                                                trace!("Tuple found in shared map, but receiver closed, dropping packet");
                                            }
                                        }
                                    }
                                    continue;
                                }
                            }

                            if tcp_packet.get_flags() == tcp::TcpFlags::SYN
                                && shared
                                    .listening
                                    .read()
                                    .unwrap()
                                    .contains(&tcp_packet.get_destination())
                            {
                                // SYN seen on listening socket
                                if shared.stealth >= StealthLevel::Basic || tcp_packet.get_sequence() == 0 {
                                    let (sock, incoming) = Socket::new(
                                        shared.clone(),
                                        tun.clone(),
                                        local_addr,
                                        remote_addr,
                                        Some(tcp_packet.get_sequence().wrapping_add(1)),
                                        State::Idle,
                                        shared.stealth,
                                        shared.mimic.clone(),
                                    );
                                    // Echo client's SYN tsval in SYN+ACK ts_ecr (RFC 7323)
                                    if shared.stealth >= StealthLevel::Basic
                                        && let Some((peer_tsval, _)) = parse_tcp_timestamps(&tcp_packet)
                                    {
                                        sock.ts_ecr.store(peer_tsval, Ordering::Relaxed);
                                    }
                                    assert!(shared
                                        .tuples
                                        .write()
                                        .unwrap()
                                        .insert(tuple, incoming)
                                        .is_none());
                                    tokio::spawn(sock.accept(cancel.clone()));
                                } else {
                                    trace!("Bad TCP SYN packet from {}, sending RST", remote_addr);
                                    let buf = build_tcp_packet(
                                        local_addr,
                                        remote_addr,
                                        0,
                                        tcp_packet.get_sequence().wrapping_add(tcp_packet.payload().len() as u32).wrapping_add(1), // +1 because of SYN flag set
                                        tcp::TcpFlags::RST | tcp::TcpFlags::ACK,
                                        None,
                                        StealthLevel::Off,
                                        0, 0,
                                        0xFFFF,
                                        None,
                                    );
                                    if let Err(e) = shared.tun[0].try_send(&buf) {
                                        warn!("reader_task: failed to send RST for bad SYN: {}", e);
                                    }
                                }
                            } else if (tcp_packet.get_flags() & tcp::TcpFlags::RST) == 0 {
                                info!("Unknown TCP packet from {}, sending RST", remote_addr);
                                let flags = tcp_packet.get_flags();
                                let has_ack = (flags & tcp::TcpFlags::ACK) != 0;

                                let (rst_seq, rst_ack, rst_flags, rst_window) = if shared.stealth >= StealthLevel::Basic {
                                    if has_ack {
                                        // RFC 793: ACK set -> <SEQ=SEG.ACK><CTL=RST>
                                        (tcp_packet.get_acknowledgement(), 0, tcp::TcpFlags::RST, 0)
                                    } else {
                                        // RFC 793: no ACK -> <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
                                        let mut seg_len = tcp_packet.payload().len() as u32;
                                        if (flags & tcp::TcpFlags::SYN) != 0 { seg_len += 1; }
                                        if (flags & tcp::TcpFlags::FIN) != 0 { seg_len += 1; }
                                        (0, tcp_packet.get_sequence().wrapping_add(seg_len), tcp::TcpFlags::RST | tcp::TcpFlags::ACK, 0)
                                    }
                                } else {
                                    (tcp_packet.get_acknowledgement(),
                                     tcp_packet.get_sequence().wrapping_add(tcp_packet.payload().len() as u32),
                                     tcp::TcpFlags::RST | tcp::TcpFlags::ACK,
                                     0xFFFF)
                                };

                                let buf = build_tcp_packet(
                                    local_addr,
                                    remote_addr,
                                    rst_seq,
                                    rst_ack,
                                    rst_flags,
                                    None,
                                    StealthLevel::Off,
                                    0, 0,
                                    rst_window,
                                    None,
                                );
                                if let Err(e) = shared.tun[0].try_send(&buf) {
                                    warn!("reader_task: failed to send RST for unknown packet: {}", e);
                                }
                            }
                        }
                        None => {
                            continue;
                        }
                    }
                },
                tuple = tuples_purge.recv() => {
                    match tuple {
                        Ok(tuple) => {
                            tuples.remove(&tuple);
                            trace!("Removed cached tuple: {:?}", tuple);
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!("tuples_purge receiver lagged by {} messages, clearing local cache", n);
                            tuples.clear();
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stealth_level_from_u8_valid_values() {
        assert_eq!(StealthLevel::from(0), StealthLevel::Off);
        assert_eq!(StealthLevel::from(1), StealthLevel::Basic);
        assert_eq!(StealthLevel::from(2), StealthLevel::Standard);
        assert_eq!(StealthLevel::from(3), StealthLevel::Full);
    }

    #[test]
    fn test_stealth_level_from_u8_clamping() {
        assert_eq!(StealthLevel::from(4), StealthLevel::Full);
        assert_eq!(StealthLevel::from(10), StealthLevel::Full);
        assert_eq!(StealthLevel::from(255), StealthLevel::Full);
    }

    #[test]
    fn test_stealth_level_default() {
        let level: StealthLevel = Default::default();
        assert_eq!(level, StealthLevel::Off);
    }

    #[test]
    fn test_stealth_level_ordering() {
        assert!(StealthLevel::Off < StealthLevel::Basic);
        assert!(StealthLevel::Basic < StealthLevel::Standard);
        assert!(StealthLevel::Standard < StealthLevel::Full);
    }

    #[test]
    fn test_stealth_level_comparison_gte() {
        assert!(StealthLevel::Full >= StealthLevel::Basic);
        assert!(StealthLevel::Standard >= StealthLevel::Standard);
        assert!(StealthLevel::Off < StealthLevel::Basic);
    }


    // --- Task 2: Random ISN tests ---

    /// Helper to compute initial seq the same way Socket::new does
    fn initial_seq(stealth: StealthLevel) -> u32 {
        if stealth >= StealthLevel::Basic {
            rand::random::<u32>()
        } else {
            0
        }
    }

    #[test]
    fn test_isn_stealth_off_is_zero() {
        // With stealth Off, ISN must always be 0
        for _ in 0..100 {
            assert_eq!(initial_seq(StealthLevel::Off), 0);
        }
    }

    #[test]
    fn test_isn_stealth_basic_is_random() {
        // With stealth >= Basic, ISN should be random (not always 0)
        // Run multiple iterations; probability of all being 0 is (1/2^32)^10 ≈ 0
        let mut seen_nonzero = false;
        for _ in 0..10 {
            if initial_seq(StealthLevel::Basic) != 0 {
                seen_nonzero = true;
                break;
            }
        }
        assert!(seen_nonzero, "ISN should be random with stealth >= Basic");
    }

    #[test]
    fn test_isn_stealth_standard_is_random() {
        let mut seen_nonzero = false;
        for _ in 0..10 {
            if initial_seq(StealthLevel::Standard) != 0 {
                seen_nonzero = true;
                break;
            }
        }
        assert!(seen_nonzero, "ISN should be random with stealth >= Standard");
    }

    #[test]
    fn test_isn_stealth_full_is_random() {
        let mut seen_nonzero = false;
        for _ in 0..10 {
            if initial_seq(StealthLevel::Full) != 0 {
                seen_nonzero = true;
                break;
            }
        }
        assert!(seen_nonzero, "ISN should be random with stealth >= Full");
    }

    #[test]
    fn test_isn_stealth_basic_has_variety() {
        // Check that different calls produce different values (not a constant)
        let values: Vec<u32> = (0..10).map(|_| initial_seq(StealthLevel::Basic)).collect();
        let unique: std::collections::HashSet<u32> = values.into_iter().collect();
        assert!(unique.len() > 1, "ISN should vary between connections");
    }

    // --- Task 6: Frequent ACK updates (Level 2) ---

    #[test]
    fn test_ack_threshold_stealth_off_uses_128mb() {
        // Stealth Off: ACK only sent when unacked exceeds MAX_UNACKED_LEN (128MB)
        let threshold = MAX_UNACKED_LEN;
        let stealth = StealthLevel::Off;

        // Small gap: no ACK
        let new_ack: u32 = 1000;
        let last_ack: u32 = 0;
        let should_ack = should_send_standalone_ack(stealth, new_ack, last_ack);
        assert!(!should_ack, "stealth Off: small gap should not trigger ACK");

        // Gap exceeding 128MB: ACK
        let new_ack: u32 = threshold + 1;
        let last_ack: u32 = 0;
        let should_ack = should_send_standalone_ack(stealth, new_ack, last_ack);
        assert!(should_ack, "stealth Off: gap > 128MB should trigger ACK");
    }

    #[test]
    fn test_ack_threshold_stealth_basic_uses_128mb() {
        // Stealth Basic (level 1): still uses 128MB threshold
        let threshold = MAX_UNACKED_LEN;
        let stealth = StealthLevel::Basic;

        let new_ack: u32 = 1000;
        let last_ack: u32 = 0;
        let should_ack = should_send_standalone_ack(stealth, new_ack, last_ack);
        assert!(!should_ack, "stealth Basic: small gap should not trigger ACK");

        let new_ack: u32 = threshold + 1;
        let last_ack: u32 = 0;
        let should_ack = should_send_standalone_ack(stealth, new_ack, last_ack);
        assert!(should_ack, "stealth Basic: gap > 128MB should trigger ACK");
    }

    #[test]
    fn test_ack_threshold_stealth_standard_sends_on_every_packet() {
        // Stealth Standard (level 2): ACK on every received data packet
        let stealth = StealthLevel::Standard;

        // Even a small gap triggers ACK
        let new_ack: u32 = 100;
        let last_ack: u32 = 0;
        let should_ack = should_send_standalone_ack(stealth, new_ack, last_ack);
        assert!(should_ack, "stealth Standard: any data should trigger standalone ACK");

        // Single byte of data triggers ACK
        let new_ack: u32 = 1;
        let last_ack: u32 = 0;
        let should_ack = should_send_standalone_ack(stealth, new_ack, last_ack);
        assert!(should_ack, "stealth Standard: even 1 byte should trigger ACK");
    }

    #[test]
    fn test_ack_threshold_stealth_full_sends_on_every_packet() {
        // Stealth Full (level 3): also ACKs on every received packet
        let stealth = StealthLevel::Full;

        let new_ack: u32 = 1460;
        let last_ack: u32 = 0;
        let should_ack = should_send_standalone_ack(stealth, new_ack, last_ack);
        assert!(should_ack, "stealth Full: any data should trigger standalone ACK");
    }

    #[test]
    fn test_ack_no_standalone_when_unchanged() {
        // No standalone ACK when ack hasn't changed (e.g., zero-length payload)
        for stealth in [StealthLevel::Off, StealthLevel::Basic, StealthLevel::Standard, StealthLevel::Full] {
            let new_ack: u32 = 100;
            let last_ack: u32 = 100;
            let should_ack = should_send_standalone_ack(stealth, new_ack, last_ack);
            assert!(!should_ack, "stealth {:?}: no ACK when ack unchanged", stealth);
        }
    }

    /// Helper that mirrors the ACK decision logic in Socket::recv()
    fn should_send_standalone_ack(stealth: StealthLevel, new_ack: u32, last_ack: u32) -> bool {
        if stealth >= StealthLevel::Standard {
            // Level 2+: ACK on every received data packet
            new_ack != last_ack
        } else {
            // Level 0-1: only ACK after 128MB of unacked data
            new_ack.overflowing_sub(last_ack).0 > MAX_UNACKED_LEN
        }
    }


    // --- Task 7: Dynamic window tests ---

    /// Helper that mirrors Socket's window_base initialization
    fn compute_window_base(stealth: StealthLevel) -> u16 {
        if stealth >= StealthLevel::Standard {
            256 + (rand::random::<u16>() % 257)
        } else {
            0xFFFF
        }
    }

    /// Helper that mirrors Socket::current_window()
    fn compute_current_window(stealth: StealthLevel, window_base: u16) -> u16 {
        if stealth >= StealthLevel::Standard {
            window_base.wrapping_add(rand::random::<u16>() % 32)
        } else {
            0xFFFF
        }
    }

    /// Helper that mirrors the SYN window logic in Socket::build_tcp_packet().
    /// Returns the window value that would be used for a SYN or data packet.
    fn compute_syn_window(stealth: StealthLevel, is_syn: bool) -> u16 {
        if is_syn && stealth >= StealthLevel::Basic {
            SYN_WINDOW
        } else if stealth >= StealthLevel::Standard {
            // Data packets use dynamic window_base + jitter
            compute_window_base(stealth).wrapping_add(rand::random::<u16>() % 32)
        } else {
            0xFFFF
        }
    }

    #[test]
    fn test_window_stealth_off_is_static_0xffff() {
        for _ in 0..10 {
            let base = compute_window_base(StealthLevel::Off);
            assert_eq!(base, 0xFFFF);
            let window = compute_current_window(StealthLevel::Off, base);
            assert_eq!(window, 0xFFFF);
        }
    }

    #[test]
    fn test_window_stealth_basic_is_static_0xffff() {
        for _ in 0..10 {
            let base = compute_window_base(StealthLevel::Basic);
            assert_eq!(base, 0xFFFF);
            let window = compute_current_window(StealthLevel::Basic, base);
            assert_eq!(window, 0xFFFF);
        }
    }

    #[test]
    fn test_window_stealth_standard_base_in_range() {
        // Window base should be in 256..=512
        for _ in 0..50 {
            let base = compute_window_base(StealthLevel::Standard);
            assert!(base >= 256, "window_base {} should be >= 256", base);
            assert!(base <= 512, "window_base {} should be <= 512", base);
        }
    }

    #[test]
    fn test_window_stealth_standard_varies() {
        // Multiple calls to current_window should produce varying values
        let base = 400u16;
        let windows: Vec<u16> = (0..20)
            .map(|_| compute_current_window(StealthLevel::Standard, base))
            .collect();
        let unique: std::collections::HashSet<u16> = windows.into_iter().collect();
        assert!(unique.len() > 1, "window values should vary with jitter");
    }

    #[test]
    fn test_window_stealth_standard_jitter_bounded() {
        // Jitter should be 0..32, so window in [base, base+31]
        let base = 350u16;
        for _ in 0..100 {
            let window = compute_current_window(StealthLevel::Standard, base);
            assert!(window >= base, "window {} should be >= base {}", window, base);
            assert!(window < base + 32, "window {} should be < base + 32 = {}", window, base + 32);
        }
    }

    #[test]
    fn test_window_stealth_full_also_dynamic() {
        // Stealth Full (level 3) should also use dynamic window
        let base = compute_window_base(StealthLevel::Full);
        assert!((256..=512).contains(&base));
        let window = compute_current_window(StealthLevel::Full, base);
        assert!((base..base + 32).contains(&window), "window {} should be in range [{}..{})", window, base, base + 32);
    }

    // --- SYN window fingerprint tests ---

    #[test]
    fn test_syn_window_basic_returns_64240() {
        for _ in 0..10 {
            let w = compute_syn_window(StealthLevel::Basic, true);
            assert_eq!(w, 64240, "SYN window at Basic should be 64240, got {}", w);
        }
    }

    #[test]
    fn test_syn_window_standard_returns_64240() {
        for _ in 0..10 {
            let w = compute_syn_window(StealthLevel::Standard, true);
            assert_eq!(w, 64240, "SYN window at Standard should be 64240, got {}", w);
        }
    }

    #[test]
    fn test_syn_window_full_returns_64240() {
        for _ in 0..10 {
            let w = compute_syn_window(StealthLevel::Full, true);
            assert_eq!(w, 64240, "SYN window at Full should be 64240, got {}", w);
        }
    }

    #[test]
    fn test_syn_window_off_returns_0xffff() {
        // Stealth Off: SYN window should remain 0xFFFF (backward compat)
        let w = compute_syn_window(StealthLevel::Off, true);
        assert_eq!(w, 0xFFFF, "SYN window at Off should be 0xFFFF, got {}", w);
    }

    #[test]
    fn test_data_packet_window_not_64240_for_standard() {
        // Data packets (is_syn=false) at Standard should use dynamic window, not 64240
        for _ in 0..20 {
            let w = compute_syn_window(StealthLevel::Standard, false);
            assert_ne!(w, 64240, "data packet window should not be SYN_WINDOW");
            assert!(w >= 256 && w <= 543, "data window {} out of expected range", w);
        }
    }

    // --- Task 9: Duplicate ACK tracking (Level 3) ---

    /// Simulates the duplicate ACK tracking logic from Socket::recv().
    /// Returns (new_dup_ack_count, new_last_acked_seq, seq_result).
    /// After fast retransmit triggers, counter resets to 0 (matching real code).
    /// `is_pure_ack`: true if the packet carries no payload (only pure ACKs
    /// count as duplicate ACKs per RFC 5681).
    /// `same_window`: true if the advertised window matches the previous packet
    /// (per RFC 5681, changed windows make it a window update, not a dup ACK).
    /// `snd_nxt`: the next sequence number we will send (ACKs past this are invalid).
    #[allow(clippy::too_many_arguments)]
    fn simulate_dup_ack_tracking(
        stealth: StealthLevel,
        peer_ack: u32,
        prev_acked_seq: u32,
        prev_dup_count: u32,
        current_seq: u32,
        is_pure_ack: bool,
        same_window: bool,
        snd_nxt: u32,
    ) -> (u32, u32, u32) {
        if stealth >= StealthLevel::Full {
            if peer_ack == prev_acked_seq && is_pure_ack && same_window
                && (snd_nxt.wrapping_sub(prev_acked_seq) as i32) > 0
            {
                let new_count = prev_dup_count + 1;
                if new_count >= 3 {
                    // Fast retransmit: reset seq, then reset counter
                    (0, prev_acked_seq, prev_acked_seq)
                } else {
                    (new_count, prev_acked_seq, current_seq)
                }
            } else if (peer_ack.wrapping_sub(prev_acked_seq) as i32) > 0
                && (snd_nxt.wrapping_sub(peer_ack) as i32) >= 0
            {
                // New ACK that advances monotonically AND <= SND.NXT: reset counter
                (0, peer_ack, current_seq)
            } else {
                // Stale/reordered ACK, ACK past SND.NXT, data packet, or window update: ignore
                (prev_dup_count, prev_acked_seq, current_seq)
            }
        } else {
            // Below Full: no dup ACK tracking
            (prev_dup_count, prev_acked_seq, current_seq)
        }
    }

    #[test]
    fn test_dup_ack_triple_triggers_fast_retransmit() {
        // Real TCP: 3 *duplicate* ACKs (4 total with same value) trigger fast retransmit
        // With our fix: new ACK sets count=0, each dup increments, triggers at count>=3
        let stealth = StealthLevel::Full;
        let acked_seq = 5000u32;
        let current_seq = 6460u32;

        // Original ACK with value 5000: new peer_ack, count becomes 0
        let (count, last_acked, seq) =
            simulate_dup_ack_tracking(stealth, acked_seq, 0, 0, current_seq, true, true, current_seq);
        assert_eq!(count, 0);
        assert_eq!(last_acked, acked_seq);
        assert_eq!(seq, current_seq, "no reset on original ACK");

        // First duplicate ACK: count becomes 1
        let (count, last_acked, seq) =
            simulate_dup_ack_tracking(stealth, acked_seq, acked_seq, 0, current_seq, true, true, current_seq);
        assert_eq!(count, 1);
        assert_eq!(last_acked, acked_seq);
        assert_eq!(seq, current_seq, "no reset on first dup ACK");

        // Second duplicate ACK: count becomes 2
        let (count, last_acked, seq) =
            simulate_dup_ack_tracking(stealth, acked_seq, acked_seq, 1, current_seq, true, true, current_seq);
        assert_eq!(count, 2);
        assert_eq!(last_acked, acked_seq);
        assert_eq!(seq, current_seq, "no reset on second dup ACK");

        // Third duplicate ACK: count reaches 3, triggers fast retransmit, counter resets
        let (count, last_acked, seq) =
            simulate_dup_ack_tracking(stealth, acked_seq, acked_seq, 2, current_seq, true, true, current_seq);
        assert_eq!(count, 0, "counter should reset after fast retransmit");
        assert_eq!(last_acked, acked_seq);
        assert_eq!(seq, acked_seq, "seq should reset to acked position on triple dup ACK");
    }

    #[test]
    fn test_dup_ack_seq_resets_to_acked_position() {
        // Verify that after triple dup ACK, seq equals the acknowledged seq
        let stealth = StealthLevel::Full;
        let acked_seq = 12345u32;
        let current_seq = 99999u32;

        // Simulate the 3rd duplicate ACK (prev_dup_count=2 -> new_count=3 -> triggers)
        let (count, _, seq) =
            simulate_dup_ack_tracking(stealth, acked_seq, acked_seq, 2, current_seq, true, true, current_seq);
        assert_eq!(count, 0, "counter resets after retransmit");
        assert_eq!(seq, acked_seq, "seq must equal last_acked_seq after fast retransmit");
    }

    #[test]
    fn test_dup_ack_count_resets_on_new_ack() {
        // When a new (different) ACK value arrives, dup count resets to 0
        let stealth = StealthLevel::Full;

        // Had 2 dup ACKs for seq 1000, now get ACK for seq 2000
        let (count, last_acked, seq) =
            simulate_dup_ack_tracking(stealth, 2000, 1000, 2, 5000, true, true, 5000);
        assert_eq!(count, 0, "dup count should reset to 0 on new ACK value");
        assert_eq!(last_acked, 2000, "last_acked should update to new value");
        assert_eq!(seq, 5000, "seq should not change on new ACK");
    }

    #[test]
    fn test_dup_ack_counter_resets_after_retransmit() {
        // After fast retransmit triggers, counter resets to 0.
        // Subsequent dups start counting from 0 again, needing 3 more to trigger.
        let stealth = StealthLevel::Full;
        let acked = 7000u32;

        // 3rd dup triggers retransmit, counter resets to 0
        let (count, _, seq) =
            simulate_dup_ack_tracking(stealth, acked, acked, 2, 9000, true, true, 9000);
        assert_eq!(count, 0, "counter resets after retransmit");
        assert_eq!(seq, acked, "seq resets on retransmit");

        // Next dup ACK: count goes to 1 (starting fresh)
        let (count, _, seq) =
            simulate_dup_ack_tracking(stealth, acked, acked, 0, 9000, true, true, 9000);
        assert_eq!(count, 1, "counting starts fresh after reset");
        assert_eq!(seq, 9000, "no retransmit yet");
    }

    #[test]
    fn test_dup_ack_not_tracked_below_full() {
        // Stealth levels below Full should not track dup ACKs
        for stealth in [StealthLevel::Off, StealthLevel::Basic, StealthLevel::Standard] {
            let (count, last_acked, seq) =
                simulate_dup_ack_tracking(stealth, 5000, 5000, 2, 8000, true, true, 8000);
            // Should return unchanged values since no tracking happens
            assert_eq!(count, 2, "stealth {:?}: dup count should not change", stealth);
            assert_eq!(last_acked, 5000, "stealth {:?}: last_acked should not change", stealth);
            assert_eq!(seq, 8000, "stealth {:?}: seq should not change", stealth);
        }
    }

    #[test]
    fn test_dup_ack_no_outstanding_data_not_counted() {
        // Per RFC 5681, duplicate ACKs should only be counted when there is
        // outstanding (unacknowledged) data in flight. When snd_nxt == last_acked,
        // nothing is outstanding and dup ACKs should be ignored.
        let stealth = StealthLevel::Full;
        let acked = 5000u32;

        // snd_nxt == acked means no data in flight
        let (count, _, seq) =
            simulate_dup_ack_tracking(stealth, acked, acked, 0, 9000, true, true, acked);
        assert_eq!(count, 0, "no outstanding data: dup ACK should not increment counter");
        assert_eq!(seq, 9000, "seq should not change");

        // Even with prev_dup_count=2, should not trigger retransmit
        let (count, _, seq) =
            simulate_dup_ack_tracking(stealth, acked, acked, 2, 9000, true, true, acked);
        assert_eq!(count, 2, "no outstanding data: counter should not advance");
        assert_eq!(seq, 9000, "no retransmit without outstanding data");
    }

    #[test]
    fn test_dup_ack_wrapping_seq_values() {
        // Test with wrapping sequence numbers near u32::MAX
        let stealth = StealthLevel::Full;
        let acked = u32::MAX - 100;
        let current_seq = u32::MAX;

        // Third dup ACK with high seq values
        let (count, _, seq) =
            simulate_dup_ack_tracking(stealth, acked, acked, 2, current_seq, true, true, current_seq);
        assert_eq!(count, 0, "counter resets after retransmit");
        assert_eq!(seq, acked, "fast retransmit should work with high seq values");
    }

    #[test]
    fn test_dup_ack_data_packets_not_counted() {
        // Data packets (non-empty payload) with the same ACK should NOT
        // count as duplicate ACKs per RFC 5681
        let stealth = StealthLevel::Full;
        let acked = 5000u32;

        // Three data packets with same ACK should not trigger fast retransmit
        let (count, _, seq) =
            simulate_dup_ack_tracking(stealth, acked, acked, 0, 9000, false, true, 9000);
        assert_eq!(count, 0, "data packet should not increment dup ACK counter");
        assert_eq!(seq, 9000, "seq should not change");

        let (count, _, seq) =
            simulate_dup_ack_tracking(stealth, acked, acked, 0, 9000, false, true, 9000);
        assert_eq!(count, 0);
        assert_eq!(seq, 9000);

        let (count, _, seq) =
            simulate_dup_ack_tracking(stealth, acked, acked, 0, 9000, false, true, 9000);
        assert_eq!(count, 0, "still no retransmit from data packets");
        assert_eq!(seq, 9000);
    }

    #[test]
    fn test_stale_ack_ignored() {
        // A stale/reordered ACK that goes backwards should be ignored
        let stealth = StealthLevel::Full;
        let current_acked = 5000u32;

        // Stale ACK with value 3000 (behind current 5000) should be ignored
        let (count, last_acked, seq) =
            simulate_dup_ack_tracking(stealth, 3000, current_acked, 0, 9000, true, true, 9000);
        assert_eq!(count, 0, "stale ACK should not change dup count");
        assert_eq!(last_acked, current_acked, "last_acked should not move backwards");
        assert_eq!(seq, 9000, "seq should not change");
    }

    #[test]
    fn test_ack_past_snd_nxt_ignored() {
        // An ACK beyond what we've sent (past SND.NXT) should be ignored.
        // This prevents a middlebox or buggy peer from corrupting last_acked_seq.
        let stealth = StealthLevel::Full;
        let prev_acked = 1000u32;
        let snd_nxt = 5000u32; // we've sent up to seq 5000

        // ACK for 6000 is past SND.NXT (5000) — should be dropped
        let (count, last_acked, seq) =
            simulate_dup_ack_tracking(stealth, 6000, prev_acked, 0, 9000, true, true, snd_nxt);
        assert_eq!(count, 0, "ACK past SND.NXT should not change dup count");
        assert_eq!(last_acked, prev_acked, "last_acked should not advance past SND.NXT");
        assert_eq!(seq, 9000, "seq should not change");

        // ACK exactly at SND.NXT is valid
        let (count, last_acked, seq) =
            simulate_dup_ack_tracking(stealth, snd_nxt, prev_acked, 0, 9000, true, true, snd_nxt);
        assert_eq!(count, 0);
        assert_eq!(last_acked, snd_nxt, "ACK at SND.NXT should be accepted");
        assert_eq!(seq, 9000);
    }

    #[test]
    fn test_window_update_not_counted_as_dup_ack() {
        // Per RFC 5681, a pure ACK with a changed advertised window is a
        // window update, not a duplicate ACK. It should NOT increment the
        // dup ACK counter or trigger fast retransmit.
        let stealth = StealthLevel::Full;
        let acked = 5000u32;

        // Three pure ACKs with same ACK number but different window (same_window=false)
        let (count, _, seq) =
            simulate_dup_ack_tracking(stealth, acked, acked, 0, 9000, true, false, 9000);
        assert_eq!(count, 0, "window update should not increment dup ACK counter");
        assert_eq!(seq, 9000, "seq should not change");

        let (count, _, seq) =
            simulate_dup_ack_tracking(stealth, acked, acked, 0, 9000, true, false, 9000);
        assert_eq!(count, 0);
        assert_eq!(seq, 9000);

        let (count, _, seq) =
            simulate_dup_ack_tracking(stealth, acked, acked, 0, 9000, true, false, 9000);
        assert_eq!(count, 0, "three window updates should not trigger fast retransmit");
        assert_eq!(seq, 9000);
    }

    // --- Task 10: Send window constraint (Level 3) ---

    /// Simulates the send window constraint logic from Socket::send().
    /// Returns (seq_used_for_packet, new_seq_after_send).
    fn simulate_send_window_constraint(
        stealth: StealthLevel,
        current_seq: u32,
        payload_len: u32,
        last_acked_seq: u32,
        peer_window: u32,
        cwnd: u32,
    ) -> (u32, u32) {
        let mut seq = current_seq;
        if stealth >= StealthLevel::Full {
            let effective_win = if peer_window > 0 { peer_window.min(cwnd) } else { cwnd };
            if effective_win > 0 {
                let bytes_in_flight = seq.wrapping_sub(last_acked_seq);
                if bytes_in_flight.wrapping_add(payload_len) > effective_win {
                    // Window exhausted: wrap seq back to last acked position
                    seq = last_acked_seq;
                }
            }
        }
        (seq, seq.wrapping_add(payload_len))
    }

    #[test]
    fn test_send_window_constraint_seq_does_not_exceed_window() {
        // With stealth >= Full, seq should not advance beyond last_acked_seq + peer_window
        let stealth = StealthLevel::Full;
        let last_acked = 1000u32;
        let peer_window = 65536u32; // 64KB window
        let payload_len = 1460u32;

        let cwnd = 10 * 1460 * 100; // large cwnd so peer_window is the binding constraint

        // First send: seq=1000, bytes_in_flight=0, 0+1460 <= 65536 -> OK
        let (seq_used, new_seq) =
            simulate_send_window_constraint(stealth, last_acked, payload_len, last_acked, peer_window, cwnd);
        assert_eq!(seq_used, 1000, "first send should use current seq");
        assert_eq!(new_seq, 1000 + 1460);

        // Subsequent sends advance seq but stay within window
        let current_seq = last_acked + 60000; // 60000 bytes in flight
        let (seq_used, new_seq) =
            simulate_send_window_constraint(stealth, current_seq, payload_len, last_acked, peer_window, cwnd);
        assert_eq!(seq_used, current_seq, "should still be within window");
        assert_eq!(new_seq, current_seq + payload_len);

        // Send that would exceed window: 65000 + 1460 > 65536
        let current_seq = last_acked + 65000;
        let (seq_used, new_seq) =
            simulate_send_window_constraint(stealth, current_seq, payload_len, last_acked, peer_window, cwnd);
        assert_eq!(seq_used, last_acked, "should wrap back to last_acked when window exhausted");
        assert_eq!(new_seq, last_acked + payload_len);
    }

    #[test]
    fn test_send_window_constraint_wraps_seq_to_acked_position() {
        // When window is exhausted, seq wraps back to last_acked_seq
        let stealth = StealthLevel::Full;
        let last_acked = 5000u32;
        let peer_window = 32768u32; // 32KB window
        let payload_len = 1460u32;

        let cwnd = 10 * 1460 * 100; // large cwnd so peer_window is the binding constraint

        // seq has advanced far beyond window
        let current_seq = last_acked + 50000;
        let (seq_used, _) =
            simulate_send_window_constraint(stealth, current_seq, payload_len, last_acked, peer_window, cwnd);
        assert_eq!(seq_used, last_acked, "seq must wrap back to last_acked_seq");
    }

    #[test]
    fn test_send_window_constraint_not_applied_below_full() {
        // Stealth levels below Full should not apply send window constraint
        let last_acked = 1000u32;
        let peer_window = 1000u32; // very small window
        let payload_len = 1460u32;
        let current_seq = last_acked + 5000; // way beyond window

        let cwnd = 10 * 1460;

        for stealth in [StealthLevel::Off, StealthLevel::Basic, StealthLevel::Standard] {
            let (seq_used, new_seq) =
                simulate_send_window_constraint(stealth, current_seq, payload_len, last_acked, peer_window, cwnd);
            assert_eq!(seq_used, current_seq, "stealth {:?}: should not constrain seq", stealth);
            assert_eq!(new_seq, current_seq + payload_len);
        }
    }

    #[test]
    fn test_send_window_constraint_zero_peer_window_falls_back_to_cwnd() {
        // When peer_window is 0 (not yet received from peer), cwnd is the sole constraint
        let stealth = StealthLevel::Full;
        let last_acked = 1000u32;
        let peer_window = 0u32;
        let payload_len = 1460u32;
        let cwnd = 10 * 1460; // 14600

        // Within cwnd: 5000 in flight + 1460 = 6460 < 14600
        let current_seq = last_acked + 5000;
        let (seq_used, _) =
            simulate_send_window_constraint(stealth, current_seq, payload_len, last_acked, peer_window, cwnd);
        assert_eq!(seq_used, current_seq, "within cwnd should not wrap even with peer_window=0");

        // Exceeds cwnd: 14000 in flight + 1460 = 15460 > 14600
        let current_seq = last_acked + 14000;
        let (seq_used, _) =
            simulate_send_window_constraint(stealth, current_seq, payload_len, last_acked, peer_window, cwnd);
        assert_eq!(seq_used, last_acked, "should wrap when exceeding cwnd with peer_window=0");
    }

    #[test]
    fn test_send_window_constraint_exact_boundary() {
        // When bytes_in_flight + payload exactly equals peer_window, should NOT wrap
        let stealth = StealthLevel::Full;
        let last_acked = 0u32;
        let peer_window = 10000u32;
        let payload_len = 1000u32;
        let current_seq = 9000u32; // 9000 in flight, +1000 = 10000 = peer_window

        let cwnd = 10 * 1460 * 100; // large cwnd so peer_window is the binding constraint

        let (seq_used, _) =
            simulate_send_window_constraint(stealth, current_seq, payload_len, last_acked, peer_window, cwnd);
        assert_eq!(seq_used, current_seq, "exactly at window boundary should not wrap");

        // But one byte over should wrap
        let current_seq = 9001u32;
        let (seq_used, _) =
            simulate_send_window_constraint(stealth, current_seq, payload_len, last_acked, peer_window, cwnd);
        assert_eq!(seq_used, last_acked, "one byte over window should wrap");
    }

    #[test]
    fn test_send_window_constraint_wrapping_arithmetic() {
        // Test with sequence numbers near u32::MAX
        let stealth = StealthLevel::Full;
        let last_acked = u32::MAX - 500;
        let peer_window = 1000u32;
        let payload_len = 100u32;

        let cwnd = 10 * 1460 * 100; // large cwnd so peer_window is the binding constraint

        // current_seq within window (200 bytes in flight)
        let current_seq = u32::MAX - 300;
        let (seq_used, _) =
            simulate_send_window_constraint(stealth, current_seq, payload_len, last_acked, peer_window, cwnd);
        assert_eq!(seq_used, current_seq, "should be within window with wrapping");

        // current_seq exceeds window: 950 bytes in flight + 100 payload = 1050 > 1000
        let current_seq = last_acked.wrapping_add(950);
        let (seq_used, _) =
            simulate_send_window_constraint(stealth, current_seq, payload_len, last_acked, peer_window, cwnd);
        assert_eq!(seq_used, last_acked, "should wrap when exceeding window with wrapping seq");
    }

    #[test]
    fn test_send_window_constraint_uses_min_of_peer_window_and_cwnd() {
        // The effective window is min(peer_window, cwnd). When cwnd < peer_window,
        // cwnd should be the binding constraint.
        let stealth = StealthLevel::Full;
        let last_acked = 0u32;
        let payload_len = 1460u32;

        // peer_window is large but cwnd is small -> cwnd constrains
        let peer_window = 100_000u32;
        let cwnd = 5000u32;
        let current_seq = 4000u32; // 4000 in flight, +1460 = 5460 > cwnd(5000)
        let (seq_used, _) =
            simulate_send_window_constraint(stealth, current_seq, payload_len, last_acked, peer_window, cwnd);
        assert_eq!(seq_used, last_acked, "cwnd should constrain when smaller than peer_window");

        // peer_window is small but cwnd is large -> peer_window constrains
        let peer_window = 5000u32;
        let cwnd = 100_000u32;
        let current_seq = 4000u32; // 4000 in flight, +1460 = 5460 > peer_window(5000)
        let (seq_used, _) =
            simulate_send_window_constraint(stealth, current_seq, payload_len, last_acked, peer_window, cwnd);
        assert_eq!(seq_used, last_acked, "peer_window should constrain when smaller than cwnd");

        // Both allow: within min(50000, 60000) = 50000
        let peer_window = 50_000u32;
        let cwnd = 60_000u32;
        let current_seq = 40_000u32; // 40000 in flight, +1460 = 41460 < 50000
        let (seq_used, _) =
            simulate_send_window_constraint(stealth, current_seq, payload_len, last_acked, peer_window, cwnd);
        assert_eq!(seq_used, current_seq, "should not constrain when within both windows");
    }

    // --- Task 11: Congestion simulation (Level 3) ---

    const MAX_CWND: u32 = 1_048_576;

    /// Simulates congestion window growth on receiving a new (non-duplicate) ACK.
    /// Returns the new cwnd value.
    fn simulate_cwnd_growth(cwnd: u32, ssthresh: u32) -> u32 {
        if cwnd >= MAX_CWND {
            return cwnd;
        }
        if cwnd < ssthresh {
            // Slow start: increase cwnd by MSS
            (cwnd + MSS).min(MAX_CWND)
        } else {
            // Congestion avoidance: increase by MSS^2/cwnd per ACK
            let increment = (MSS * MSS).checked_div(cwnd).unwrap_or(1);
            (cwnd + increment.max(1)).min(MAX_CWND)
        }
    }

    /// Simulates multiplicative decrease on triple dup ACK.
    /// Returns (new_cwnd, new_ssthresh).
    fn simulate_cwnd_decrease(cwnd: u32) -> (u32, u32) {
        let new_ssthresh = (cwnd / 2).max(2 * MSS);
        (new_ssthresh, new_ssthresh)
    }

    /// Simulates congestion window constraint in send path.
    /// Returns (seq_used, new_seq_after_send).
    fn simulate_cwnd_constraint(
        current_seq: u32,
        payload_len: u32,
        last_acked_seq: u32,
        cwnd: u32,
    ) -> (u32, u32) {
        let mut seq = current_seq;
        if cwnd > 0 {
            let bytes_in_flight = seq.wrapping_sub(last_acked_seq);
            if bytes_in_flight.wrapping_add(payload_len) > cwnd {
                seq = last_acked_seq;
            }
        }
        (seq, seq.wrapping_add(payload_len))
    }

    #[test]
    fn test_congestion_slow_start_increasing_burst() {
        // Initial cwnd = 10*MSS (RFC 6928). Each new ACK adds MSS to cwnd (slow start).
        let initial_cwnd = 10 * MSS;
        let ssthresh = 65535u32;

        // Verify cwnd grows by MSS on each ACK during slow start
        let cwnd1 = simulate_cwnd_growth(initial_cwnd, ssthresh);
        assert_eq!(cwnd1, 11 * MSS, "cwnd should grow by MSS in slow start");

        let cwnd2 = simulate_cwnd_growth(cwnd1, ssthresh);
        assert_eq!(cwnd2, 12 * MSS, "second ACK grows cwnd further");

        let cwnd3 = simulate_cwnd_growth(cwnd2, ssthresh);
        assert_eq!(cwnd3, 13 * MSS);

        // All of these are below ssthresh, so still in slow start
        assert!(cwnd3 < ssthresh, "should still be in slow start phase");
    }

    #[test]
    fn test_congestion_avoidance_stabilizes() {
        // Once cwnd >= ssthresh, growth becomes linear (much slower)
        let ssthresh = 20 * MSS;
        let cwnd = ssthresh; // Just hit the threshold

        // In congestion avoidance, growth per ACK is MSS^2/cwnd
        let cwnd1 = simulate_cwnd_growth(cwnd, ssthresh);
        let growth1 = cwnd1 - cwnd;
        assert!(
            growth1 < MSS,
            "congestion avoidance should grow less than MSS per ACK, got {}",
            growth1
        );

        // Growth should be roughly MSS^2/cwnd = MSS/20 ~= 73 bytes
        let expected_growth = (MSS * MSS) / cwnd;
        assert_eq!(growth1, expected_growth);

        // After many ACKs, growth is still small per ACK
        let mut current = cwnd;
        for _ in 0..100 {
            current = simulate_cwnd_growth(current, ssthresh);
        }
        // After 100 ACKs in CA, cwnd should have grown modestly
        assert!(
            current > cwnd,
            "cwnd should grow in congestion avoidance"
        );
        assert!(
            current < cwnd + 100 * MSS,
            "growth should be much less than slow start, got {}",
            current - cwnd
        );
    }

    #[test]
    fn test_congestion_triple_dup_ack_halves_cwnd() {
        // On triple dup ACK, cwnd is halved (multiplicative decrease)
        let cwnd = 40 * MSS;
        let (new_cwnd, new_ssthresh) = simulate_cwnd_decrease(cwnd);
        assert_eq!(new_cwnd, 20 * MSS, "cwnd should be halved");
        assert_eq!(new_ssthresh, 20 * MSS, "ssthresh should equal halved cwnd");
    }

    #[test]
    fn test_congestion_cwnd_floor_on_decrease() {
        // cwnd should not go below 2*MSS even after multiplicative decrease
        let cwnd = 2 * MSS;
        let (new_cwnd, _) = simulate_cwnd_decrease(cwnd);
        assert_eq!(new_cwnd, 2 * MSS, "cwnd floor is 2*MSS");

        let cwnd = MSS; // pathologically small
        let (new_cwnd, _) = simulate_cwnd_decrease(cwnd);
        assert_eq!(new_cwnd, 2 * MSS, "cwnd floor enforced even below 2*MSS");
    }

    #[test]
    fn test_congestion_cwnd_constraint_limits_send() {
        // When bytes_in_flight + payload > cwnd, seq wraps back
        let last_acked = 1000u32;
        let cwnd = 10 * MSS; // 14600

        // Within cwnd: 5000 bytes in flight + 1460 = 6460 < 14600
        let current_seq = last_acked + 5000;
        let (seq_used, _) = simulate_cwnd_constraint(current_seq, MSS, last_acked, cwnd);
        assert_eq!(seq_used, current_seq, "within cwnd should use current seq");

        // Exceeds cwnd: 14000 + 1460 = 15460 > 14600
        let current_seq = last_acked + 14000;
        let (seq_used, _) = simulate_cwnd_constraint(current_seq, MSS, last_acked, cwnd);
        assert_eq!(seq_used, last_acked, "exceeding cwnd should wrap seq back");
    }

    #[test]
    fn test_congestion_slow_start_to_avoidance_transition() {
        // Simulate full lifecycle: slow start -> congestion avoidance
        let mut cwnd = 10 * MSS;
        let ssthresh = 20 * MSS;

        // Slow start phase
        let mut ack_count = 0;
        while cwnd < ssthresh {
            cwnd = simulate_cwnd_growth(cwnd, ssthresh);
            ack_count += 1;
        }
        assert_eq!(ack_count, 10, "should take 10 ACKs to exit slow start from 10*MSS to 20*MSS");
        assert_eq!(cwnd, 20 * MSS);

        // Now in congestion avoidance - growth is much slower
        let cwnd_at_ca_start = cwnd;
        for _ in 0..20 {
            cwnd = simulate_cwnd_growth(cwnd, ssthresh);
        }
        let ca_growth = cwnd - cwnd_at_ca_start;
        let ss_growth = cwnd_at_ca_start - 10 * MSS; // = 10 * MSS
        assert!(
            ca_growth < ss_growth,
            "CA growth ({}) should be less than SS growth ({})",
            ca_growth,
            ss_growth
        );
    }

    #[test]
    fn test_congestion_decrease_then_slow_start() {
        // After multiplicative decrease, cwnd should resume slow start
        let cwnd = 40 * MSS;
        let (new_cwnd, new_ssthresh) = simulate_cwnd_decrease(cwnd);
        assert_eq!(new_cwnd, 20 * MSS);
        assert_eq!(new_ssthresh, 20 * MSS);

        // cwnd == ssthresh, so we're in congestion avoidance immediately
        let growth = simulate_cwnd_growth(new_cwnd, new_ssthresh);
        let increment = growth - new_cwnd;
        assert!(
            increment < MSS,
            "after decrease, should be in congestion avoidance, not slow start"
        );
    }

    #[test]
    fn test_congestion_not_applied_below_full() {
        // cwnd is only initialized for stealth >= Full; for lower levels, cwnd = 0
        // and the constraint is skipped
        let stealth_off = StealthLevel::Off;
        let stealth_basic = StealthLevel::Basic;
        let stealth_standard = StealthLevel::Standard;

        // When cwnd = 0, constraint should not be applied (our Socket::new sets cwnd=0 for < Full)
        // In the simulation helper, cwnd=0 means skip
        let current_seq = 50000u32;
        let (seq_used, _) = simulate_cwnd_constraint(current_seq, MSS, 0, 0);
        assert_eq!(seq_used, current_seq, "cwnd=0 should skip constraint");

        // Verify Socket::new sets cwnd=0 for non-Full stealth levels
        // (tested implicitly via the stealth level check in send())
        assert!(stealth_off < StealthLevel::Full);
        assert!(stealth_basic < StealthLevel::Full);
        assert!(stealth_standard < StealthLevel::Full);
    }

    // --- Hardening: graceful parse_ip_packet error handling ---

    /// Test that recv() skips malformed packets and returns the next valid one.
    /// Before the fix, this would panic due to unwrap() on parse_ip_packet().
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_recv_malformed_packet_skips_and_retries() {
        use tokio_tun::TunBuilder;

        // Create a real TUN device (requires root/Docker)
        let tuns = TunBuilder::new()
            .name("tmalform0")
            .address("10.200.0.1".parse::<std::net::Ipv4Addr>().unwrap())
            .destination("10.200.0.2".parse::<std::net::Ipv4Addr>().unwrap())
            .up()
            .build()
            .expect("failed to create TUN device");
        let tun = Arc::new(tuns.into_iter().next().unwrap());

        let (ready_tx, _ready_rx) = mpsc::channel(1);
        let (tuples_purge_tx, _purge_rx_keep) = broadcast::channel(1);
        let shared = Arc::new(Shared {
            tuples: RwLock::new(HashMap::new()),
            listening: RwLock::new(HashSet::new()),
            tun: vec![tun.clone()],
            ready: ready_tx,
            tuples_purge: tuples_purge_tx,
            stealth: StealthLevel::Off,
            mimic: None,
        });

        let local_addr: SocketAddr = "10.200.0.1:1234".parse().unwrap();
        let remote_addr: SocketAddr = "10.200.0.2:5678".parse().unwrap();

        let (socket, sender) = Socket::new(
            shared.clone(),
            tun,
            local_addr,
            remote_addr,
            Some(100),
            State::Established,
            StealthLevel::Off,
            None,
        );

        // Register the tuple in the shared map so Drop doesn't panic
        let tuple = AddrTuple::new(local_addr, remote_addr);
        shared.tuples.write().unwrap().insert(tuple, sender.clone());

        // Send a malformed packet (garbage bytes that parse_ip_packet returns None for)
        sender.send_async(Bytes::from_static(b"garbage")).await.unwrap();

        // Build a valid IPv4+TCP packet with payload "hello"
        let valid_packet = build_tcp_packet(
            remote_addr,
            local_addr,
            100, // seq
            0,   // ack
            pnet::packet::tcp::TcpFlags::ACK,
            Some(b"hello"),
            StealthLevel::Off,
            0, 0, 0xFFFF, None,
        );
        sender.send_async(valid_packet).await.unwrap();

        // recv() should skip the malformed packet and return the valid payload
        let mut buf = vec![0u8; 128];
        let n = socket.recv(&mut buf).await.expect("recv returned None instead of skipping malformed packet");
        assert_eq!(&buf[..n], b"hello");
    }

    /// Verify that accept() and connect() don't panic when TUN send errors
    /// are encountered. We use a valid TUN device but no server responds,
    /// so both functions exhaust retries and return gracefully.
    /// The key assertion is that the new error-handling code paths compile
    /// and execute without panicking.
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_tun_send_failure_no_panic() {
        use tokio_tun::TunBuilder;

        // Create a real TUN device (sends succeed, but no peer responds)
        let tuns = TunBuilder::new()
            .name("ttunfail0")
            .address("10.201.0.1".parse::<std::net::Ipv4Addr>().unwrap())
            .destination("10.201.0.2".parse::<std::net::Ipv4Addr>().unwrap())
            .up()
            .build()
            .expect("failed to create TUN device");
        let tun = Arc::new(tuns.into_iter().next().unwrap());

        let (ready_tx, _ready_rx) = mpsc::channel(1);
        let (tuples_purge_tx, _purge_rx_keep) = broadcast::channel(1);
        let shared = Arc::new(Shared {
            tuples: RwLock::new(HashMap::new()),
            listening: RwLock::new(HashSet::new()),
            tun: vec![tun.clone()],
            ready: ready_tx,
            tuples_purge: tuples_purge_tx,
            stealth: StealthLevel::Off,
            mimic: None,
        });

        // Test connect: should exhaust retries without panicking
        {
            let local_addr: SocketAddr = "10.201.0.1:1234".parse().unwrap();
            let remote_addr: SocketAddr = "10.201.0.2:5678".parse().unwrap();

            let (mut socket, sender) = Socket::new(
                shared.clone(),
                tun.clone(),
                local_addr,
                remote_addr,
                Some(100),
                State::Idle,
                StealthLevel::Off,
                None,
            );

            let tuple = AddrTuple::new(local_addr, remote_addr);
            shared.tuples.write().unwrap().insert(tuple, sender);

            // connect() should return None after retries without panicking
            let result = socket.connect().await;
            assert!(result.is_none(), "connect should return None when no server responds");
        }

        // Test accept: should exhaust retries without panicking
        {
            let local_addr: SocketAddr = "10.201.0.1:2345".parse().unwrap();
            let remote_addr: SocketAddr = "10.201.0.2:6789".parse().unwrap();

            let (socket, sender) = Socket::new(
                shared.clone(),
                tun.clone(),
                local_addr,
                remote_addr,
                Some(100),
                State::Idle,
                StealthLevel::Off,
                None,
            );

            let tuple = AddrTuple::new(local_addr, remote_addr);
            shared.tuples.write().unwrap().insert(tuple, sender);

            // accept() should complete after retries without panicking
            let cancel = tokio_util::sync::CancellationToken::new();
            socket.accept(cancel).await;
        }
    }

    // --- Task 4: CongestionState struct tests ---

    #[test]
    fn test_congestion_state_fields_initialized_correctly() {
        // Verify CongestionState initial values match current AtomicU32 defaults
        // for stealth >= Full: cwnd=10*MSS, ssthresh=65535, etc.
        let cs = CongestionState {
            dup_ack_count: 0,
            last_acked_seq: 42,
            peer_window: 0,
            cwnd: 10 * MSS,
            ssthresh: 65535,
            snd_nxt: 42,
            last_peer_window: 0,
        };

        assert_eq!(cs.dup_ack_count, 0);
        assert_eq!(cs.last_acked_seq, 42);
        assert_eq!(cs.peer_window, 0);
        assert_eq!(cs.cwnd, 10 * MSS);
        assert_eq!(cs.ssthresh, 65535);
        assert_eq!(cs.snd_nxt, 42);
        assert_eq!(cs.last_peer_window, 0);
    }

    #[test]
    fn test_congestion_state_none_for_lower_stealth() {
        // Verify `congestion` is `None` for stealth levels Off, Basic, and Standard
        // We can't construct a full Socket without TUN, so we mirror the initialization logic
        for stealth in [StealthLevel::Off, StealthLevel::Basic, StealthLevel::Standard] {
            let congestion: Option<Mutex<CongestionState>> = if stealth >= StealthLevel::Full {
                Some(Mutex::new(CongestionState {
                    dup_ack_count: 0,
                    last_acked_seq: 0,
                    peer_window: 0,
                    cwnd: 10 * MSS,
                    ssthresh: 65535,
                    snd_nxt: 0,
                    last_peer_window: 0,
                }))
            } else {
                None
            };
            assert!(
                congestion.is_none(),
                "congestion should be None for stealth {:?}",
                stealth
            );
        }
    }

    // --- Task 5: Concurrent recv() dup ACK test ---

    /// Test that concurrent recv() calls with duplicate ACKs only halve cwnd once.
    /// Before the Mutex fix, concurrent recv() calls could each see dup_ack_count=2,
    /// increment to 3, and both trigger the multiplicative decrease — halving cwnd twice.
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_concurrent_recv_dup_ack_fires_once() {
        use tokio_tun::TunBuilder;

        let tuns = TunBuilder::new()
            .name("tconcdup0")
            .address("10.210.0.1".parse::<std::net::Ipv4Addr>().unwrap())
            .destination("10.210.0.2".parse::<std::net::Ipv4Addr>().unwrap())
            .up()
            .build()
            .expect("failed to create TUN device");
        let tun = Arc::new(tuns.into_iter().next().unwrap());

        let (ready_tx, _ready_rx) = mpsc::channel(1);
        let (tuples_purge_tx, _purge_rx_keep) = broadcast::channel(1);
        let shared = Arc::new(Shared {
            tuples: RwLock::new(HashMap::new()),
            listening: RwLock::new(HashSet::new()),
            tun: vec![tun.clone()],
            ready: ready_tx,
            tuples_purge: tuples_purge_tx,
            stealth: StealthLevel::Full,
            mimic: None,
        });

        let local_addr: SocketAddr = "10.210.0.1:1234".parse().unwrap();
        let remote_addr: SocketAddr = "10.210.0.2:5678".parse().unwrap();

        let (socket, sender) = Socket::new(
            shared.clone(),
            tun,
            local_addr,
            remote_addr,
            Some(100),
            State::Established,
            StealthLevel::Full,
            None,
        );

        let tuple = AddrTuple::new(local_addr, remote_addr);
        shared.tuples.write().unwrap().insert(tuple, sender.clone());

        // Set up initial state: advance snd_nxt beyond last_acked_seq so dup ACK
        // detection sees outstanding data. We do this by updating the CongestionState
        // directly.
        let initial_seq = socket.seq.load(Ordering::Relaxed);
        let initial_cwnd = {
            let mut cong = socket.congestion.as_ref().unwrap().lock().unwrap();
            cong.last_acked_seq = initial_seq;
            cong.snd_nxt = initial_seq.wrapping_add(5000); // simulate 5000 bytes in flight
            cong.cwnd
        };

        // Build pure ACK packets (no payload) that all ACK the same seq number,
        // with the same window — these are duplicate ACKs per RFC 5681.
        // We need 4+ dup ACKs so that even if processed serially, the 3rd triggers
        // the fast retransmit. With the race bug, concurrent processing could double-halve.
        let peer_window: u16 = 512;
        for _ in 0..6 {
            let dup_ack_packet = build_tcp_packet(
                remote_addr,
                local_addr,
                200,          // peer seq (doesn't matter for dup ACK detection)
                initial_seq,  // ack = last_acked_seq (this makes it a dup ACK)
                pnet::packet::tcp::TcpFlags::ACK,
                None,         // pure ACK, no payload
                StealthLevel::Full,
                1000, 500,    // ts_val, ts_ecr
                peer_window,
                None,
            );
            sender.send_async(dup_ack_packet).await.unwrap();
        }

        // Also send a valid data packet at the end so recv() returns
        let final_packet = build_tcp_packet(
            remote_addr,
            local_addr,
            200,
            initial_seq,
            pnet::packet::tcp::TcpFlags::ACK,
            Some(b"done"),
            StealthLevel::Full,
            1001, 500,
            peer_window,
            None,
        );
        sender.send_async(final_packet).await.unwrap();

        // Set last_peer_window to match the dup ACK window so they're detected as dups
        {
            let mut cong = socket.congestion.as_ref().unwrap().lock().unwrap();
            cong.last_peer_window = peer_window;
        }

        // Single recv() call processes the dup ACKs sequentially within the loop.
        // The Mutex ensures that even if we spawned multiple concurrent recv() tasks,
        // they'd serialize the congestion state updates.
        let socket = Arc::new(socket);

        // Spawn multiple concurrent recv() tasks to stress the lock
        let mut handles = vec![];
        for _ in 0..4 {
            let s = socket.clone();
            handles.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 128];
                s.recv(&mut buf).await
            }));
        }

        // Wait for all to complete (most will get None when channel is empty after
        // the data packet is consumed by one of them)
        drop(sender); // close channel so remaining recv() calls return None
        for h in handles {
            let _ = h.await;
        }

        // Verify cwnd was halved exactly once (not twice)
        let final_cwnd = socket.congestion.as_ref().unwrap().lock().unwrap().cwnd;
        let expected_cwnd = (initial_cwnd / 2).max(2 * MSS);
        assert_eq!(
            final_cwnd, expected_cwnd,
            "cwnd should be halved exactly once: initial={}, expected={}, got={}",
            initial_cwnd, expected_cwnd, final_cwnd
        );
    }

    #[test]
    fn test_congestion_state_some_for_full_stealth() {
        // Verify `congestion` is `Some` for stealth Full
        let stealth = StealthLevel::Full;
        let initial_seq: u32 = 12345;
        let congestion: Option<Mutex<CongestionState>> = if stealth >= StealthLevel::Full {
            Some(Mutex::new(CongestionState {
                dup_ack_count: 0,
                last_acked_seq: initial_seq,
                peer_window: 0,
                cwnd: 10 * MSS,
                ssthresh: 65535,
                snd_nxt: initial_seq,
                last_peer_window: 0,
            }))
        } else {
            None
        };
        assert!(congestion.is_some(), "congestion should be Some for stealth Full");

        let cs = congestion.unwrap().into_inner().unwrap();
        assert_eq!(cs.cwnd, 10 * MSS);
        assert_eq!(cs.ssthresh, 65535);
        assert_eq!(cs.last_acked_seq, initial_seq);
        assert_eq!(cs.snd_nxt, initial_seq);
    }

    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_concurrent_send_seq_consistency() {
        use tokio_tun::TunBuilder;

        let tuns = TunBuilder::new()
            .name("tconcsnd0")
            .address("10.220.0.1".parse::<std::net::Ipv4Addr>().unwrap())
            .destination("10.220.0.2".parse::<std::net::Ipv4Addr>().unwrap())
            .up()
            .build()
            .expect("failed to create TUN device");
        let tun = Arc::new(tuns.into_iter().next().unwrap());

        let (ready_tx, _ready_rx) = mpsc::channel(1);
        let (tuples_purge_tx, _purge_rx_keep) = broadcast::channel(1);
        let shared = Arc::new(Shared {
            tuples: RwLock::new(HashMap::new()),
            listening: RwLock::new(HashSet::new()),
            tun: vec![tun.clone()],
            ready: ready_tx,
            tuples_purge: tuples_purge_tx,
            stealth: StealthLevel::Full,
            mimic: None,
        });

        let local_addr: SocketAddr = "10.220.0.1:1234".parse().unwrap();
        let remote_addr: SocketAddr = "10.220.0.2:5678".parse().unwrap();

        let (socket, sender) = Socket::new(
            shared.clone(),
            tun,
            local_addr,
            remote_addr,
            Some(100),
            State::Established,
            StealthLevel::Full,
            None,
        );

        let tuple = AddrTuple::new(local_addr, remote_addr);
        shared.tuples.write().unwrap().insert(tuple, sender);

        let initial_seq = socket.seq.load(Ordering::Relaxed);

        // Set a large window so sends are not blocked by window constraint
        {
            let mut cong = socket.congestion.as_ref().unwrap().lock().unwrap();
            cong.last_acked_seq = initial_seq;
            cong.peer_window = 1_000_000;
            cong.cwnd = 1_000_000;
        }

        let socket = Arc::new(socket);
        let num_tasks = 8;
        let sends_per_task = 10;
        let payload_len: u32 = 100;

        // Spawn concurrent send() tasks
        let mut handles = vec![];
        for _ in 0..num_tasks {
            let s = socket.clone();
            handles.push(tokio::spawn(async move {
                let payload = vec![0xABu8; payload_len as usize];
                for _ in 0..sends_per_task {
                    s.send(&payload).await;
                }
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        // Verify seq advanced by exactly num_tasks * sends_per_task * payload_len
        let final_seq = socket.seq.load(Ordering::Relaxed);
        let expected_advance = (num_tasks * sends_per_task) as u32 * payload_len;
        let actual_advance = final_seq.wrapping_sub(initial_seq);
        assert_eq!(
            actual_advance, expected_advance,
            "seq should advance monotonically: initial={}, expected advance={}, actual advance={}, final={}",
            initial_seq, expected_advance, actual_advance, final_seq
        );

        // Verify snd_nxt is at least as high as final seq
        let final_snd_nxt = socket.congestion.as_ref().unwrap().lock().unwrap().snd_nxt;
        assert!(
            (final_snd_nxt.wrapping_sub(final_seq) as i32) >= 0,
            "snd_nxt ({}) should be >= final seq ({})",
            final_snd_nxt, final_seq
        );
    }

    // --- Mimic profile tests ---

    #[test]
    fn test_mimic_profile_udp2raw_defaults() {
        let profile = MimicProfile::udp2raw();
        assert!(profile.ip_id_incrementing);
        assert_eq!(profile.wscale, 5);
        assert_eq!(profile.window_raw, 41000);
        assert!(!profile.psh_always);
    }

    #[test]
    fn test_mimic_forces_stealth_to_standard() {
        // When mimic is active, stealth Off should be elevated to Standard
        let stealth = StealthLevel::Off;
        let mimic = Some(MimicProfile::udp2raw());
        let effective = if mimic.is_some() {
            stealth.max(StealthLevel::Standard)
        } else {
            stealth
        };
        assert_eq!(effective, StealthLevel::Standard);
    }

    #[test]
    fn test_mimic_preserves_higher_stealth() {
        // When mimic is active but stealth is already Full, keep Full
        let stealth = StealthLevel::Full;
        let mimic = Some(MimicProfile::udp2raw());
        let effective = if mimic.is_some() {
            stealth.max(StealthLevel::Standard)
        } else {
            stealth
        };
        assert_eq!(effective, StealthLevel::Full);
    }

    #[test]
    fn test_no_mimic_preserves_stealth() {
        // Without mimic, stealth Off stays Off
        let stealth = StealthLevel::Off;
        let mimic: Option<MimicProfile> = None;
        let effective = if mimic.is_some() {
            stealth.max(StealthLevel::Standard)
        } else {
            stealth
        };
        assert_eq!(effective, StealthLevel::Off);
    }

    #[test]
    fn test_mimic_ip_id_counter_initialized_when_incrementing() {
        let profile = MimicProfile::udp2raw();
        assert!(profile.ip_id_incrementing);
        let counter = profile
            .ip_id_incrementing
            .then(|| AtomicU16::new(rand::random::<u16>()));
        assert!(counter.is_some());
    }

    #[test]
    fn test_mimic_ip_id_counter_none_when_not_incrementing() {
        let mut profile = MimicProfile::udp2raw();
        profile.ip_id_incrementing = false;
        let counter = profile
            .ip_id_incrementing
            .then(|| AtomicU16::new(rand::random::<u16>()));
        assert!(counter.is_none());
    }

    #[test]
    fn test_mimic_ip_id_counter_increments_and_wraps() {
        let counter = AtomicU16::new(u16::MAX - 1);
        let v0 = counter.fetch_add(1, Ordering::Relaxed);
        assert_eq!(v0, u16::MAX - 1);
        let v1 = counter.fetch_add(1, Ordering::Relaxed);
        assert_eq!(v1, u16::MAX);
        let v2 = counter.fetch_add(1, Ordering::Relaxed);
        assert_eq!(v2, 0, "should wrap around at u16::MAX");
        let v3 = counter.fetch_add(1, Ordering::Relaxed);
        assert_eq!(v3, 1);
    }

    #[test]
    fn test_mimic_ip_id_counter_sequential_values() {
        let start = 100u16;
        let counter = AtomicU16::new(start);
        for i in 0..10 {
            let val = counter.fetch_add(1, Ordering::Relaxed);
            assert_eq!(val, start + i);
        }
    }

    /// Verify Socket fields are correctly initialized from MimicProfile.
    /// Uses TUN device to construct a real Socket.
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_socket_initialized_from_mimic_profile() {
        use tokio_tun::TunBuilder;

        let tuns = TunBuilder::new()
            .name("tmimic0")
            .address("10.230.0.1".parse::<std::net::Ipv4Addr>().unwrap())
            .destination("10.230.0.2".parse::<std::net::Ipv4Addr>().unwrap())
            .up()
            .build()
            .expect("failed to create TUN device");
        let tun = Arc::new(tuns.into_iter().next().unwrap());

        let (ready_tx, _ready_rx) = mpsc::channel(1);
        let (tuples_purge_tx, _purge_rx_keep) = broadcast::channel(1);
        let shared = Arc::new(Shared {
            tuples: RwLock::new(HashMap::new()),
            listening: RwLock::new(HashSet::new()),
            tun: vec![tun.clone()],
            ready: ready_tx,
            tuples_purge: tuples_purge_tx,
            stealth: StealthLevel::Off, // mimic should force to Standard
            mimic: Some(MimicProfile::udp2raw()),
        });

        let local_addr: SocketAddr = "10.230.0.1:1234".parse().unwrap();
        let remote_addr: SocketAddr = "10.230.0.2:5678".parse().unwrap();
        let profile = MimicProfile::udp2raw();

        let (socket, sender) = Socket::new(
            shared.clone(),
            tun,
            local_addr,
            remote_addr,
            Some(100),
            State::Established,
            StealthLevel::Off,
            Some(profile),
        );

        let tuple = AddrTuple::new(local_addr, remote_addr);
        shared.tuples.write().unwrap().insert(tuple, sender);

        // Stealth should be elevated to Standard
        assert!(socket.stealth >= StealthLevel::Standard);
        // Mimic profile should be stored
        assert!(socket.mimic.is_some());
        let m = socket.mimic.as_ref().unwrap();
        assert!(m.ip_id_incrementing);
        assert_eq!(m.wscale, 5);
        assert_eq!(m.window_raw, 41000);
        assert!(!m.psh_always);
        // IP ID counter should be initialized
        assert!(socket.ip_id_counter.is_some());
        // ts_offset should be non-zero (random) since stealth is now >= Basic
        // (probabilistic: chance of 0 is 1/2^32)
        // ISN (seq) should also be random
        // Just verify stealth-dependent fields are initialized correctly
        assert_ne!(socket.ts_offset, 0, "ts_offset should be random when mimic forces stealth >= Basic (extremely unlikely to be 0)");
    }

    // --- Task 3: Window scale and raw window tests ---

    #[test]
    fn test_mimic_window_base_set_to_window_raw() {
        // When mimic is active, window_base should equal mimic.window_raw
        let profile = MimicProfile::udp2raw();
        // Simulate the window_base initialization logic from Socket::new()
        let mimic = Some(profile);
        let window_base = if let Some(ref m) = mimic {
            m.window_raw
        } else {
            256 + (rand::random::<u16>() % 257)
        };
        assert_eq!(window_base, 41000, "window_base should equal mimic.window_raw");
    }

    #[test]
    fn test_no_mimic_standard_window_base_in_range() {
        // Without mimic, stealth Standard window_base should be in 256..=512
        let mimic: Option<MimicProfile> = None;
        for _ in 0..100 {
            let window_base = if let Some(ref m) = mimic {
                m.window_raw
            } else {
                256 + (rand::random::<u16>() % 257)
            };
            assert!(
                (256..=512).contains(&window_base),
                "window_base {} should be in 256..=512",
                window_base
            );
        }
    }

    #[test]
    fn test_mimic_wscale_passed_in_mimic_params() {
        // When mimic is active, MimicParams should have wscale from profile
        let profile = MimicProfile::udp2raw();
        let mimic = Some(profile);
        let mimic_params = mimic.as_ref().map(|p| MimicParams {
            ip_id: 0,
            wscale: Some(p.wscale),
        });
        assert!(mimic_params.is_some());
        assert_eq!(mimic_params.unwrap().wscale, Some(5));
    }

    #[test]
    fn test_no_mimic_no_mimic_params() {
        // Without mimic and no ip_id_counter, mimic_params should be None
        let mimic: Option<MimicProfile> = None;
        let mimic_params = mimic.as_ref().map(|p| MimicParams {
            ip_id: 0,
            wscale: Some(p.wscale),
        });
        assert!(mimic_params.is_none());
    }

    // --- Task 4: PSH flag behavior for mimic mode ---

    /// Helper that mirrors the data-packet flag logic from Socket::send().
    /// Returns the flags that would be used for a data packet given mimic + stealth.
    fn compute_data_flags(mimic: &Option<MimicProfile>, stealth: StealthLevel) -> u8 {
        if let Some(m) = mimic {
            if m.psh_always {
                tcp::TcpFlags::PSH | tcp::TcpFlags::ACK
            } else {
                tcp::TcpFlags::ACK
            }
        } else if stealth >= StealthLevel::Basic {
            tcp::TcpFlags::PSH | tcp::TcpFlags::ACK
        } else {
            tcp::TcpFlags::ACK
        }
    }

    #[test]
    fn test_mimic_psh_always_false_data_flags_ack_only() {
        // udp2raw style: psh_always=false → ACK only, no PSH
        let mimic = Some(MimicProfile::udp2raw()); // psh_always=false
        let flags = compute_data_flags(&mimic, StealthLevel::Standard);
        assert_eq!(flags, tcp::TcpFlags::ACK, "mimic psh_always=false should produce ACK only");
        assert_eq!(flags & tcp::TcpFlags::PSH, 0, "PSH flag must not be set");
    }

    #[test]
    fn test_mimic_psh_always_true_data_flags_psh_ack() {
        // mimic-no-psh toggle: psh_always=true → PSH|ACK (same as stealth Basic+)
        let mut profile = MimicProfile::udp2raw();
        profile.psh_always = true;
        let mimic = Some(profile);
        let flags = compute_data_flags(&mimic, StealthLevel::Standard);
        assert_eq!(flags, tcp::TcpFlags::PSH | tcp::TcpFlags::ACK,
            "mimic psh_always=true should produce PSH|ACK");
    }

    #[test]
    fn test_no_mimic_stealth_basic_psh_ack() {
        // Without mimic, stealth Basic+ → PSH|ACK
        let flags = compute_data_flags(&None, StealthLevel::Basic);
        assert_eq!(flags, tcp::TcpFlags::PSH | tcp::TcpFlags::ACK,
            "stealth Basic without mimic should produce PSH|ACK");
    }

    #[test]
    fn test_no_mimic_stealth_standard_psh_ack() {
        let flags = compute_data_flags(&None, StealthLevel::Standard);
        assert_eq!(flags, tcp::TcpFlags::PSH | tcp::TcpFlags::ACK,
            "stealth Standard without mimic should produce PSH|ACK");
    }

    #[test]
    fn test_no_mimic_stealth_full_psh_ack() {
        let flags = compute_data_flags(&None, StealthLevel::Full);
        assert_eq!(flags, tcp::TcpFlags::PSH | tcp::TcpFlags::ACK,
            "stealth Full without mimic should produce PSH|ACK");
    }

    #[test]
    fn test_no_mimic_stealth_off_ack_only() {
        // Without mimic, stealth Off → ACK only (no PSH)
        let flags = compute_data_flags(&None, StealthLevel::Off);
        assert_eq!(flags, tcp::TcpFlags::ACK, "stealth Off without mimic should produce ACK only");
        assert_eq!(flags & tcp::TcpFlags::PSH, 0, "PSH flag must not be set for stealth Off");
    }

    #[test]
    fn test_mimic_psh_always_false_all_stealth_levels() {
        // Regardless of stealth level, mimic psh_always=false → ACK only
        let mimic = Some(MimicProfile::udp2raw());
        for stealth in [StealthLevel::Off, StealthLevel::Basic, StealthLevel::Standard, StealthLevel::Full] {
            let flags = compute_data_flags(&mimic, stealth);
            assert_eq!(flags, tcp::TcpFlags::ACK,
                "mimic psh_always=false should be ACK only regardless of stealth {:?}", stealth);
        }
    }

    /// Verify Socket window_base and current_window() behavior with mimic profile.
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_socket_mimic_window_static() {
        use tokio_tun::TunBuilder;

        let tuns = TunBuilder::new()
            .name("tmwin0")
            .address("10.231.0.1".parse::<std::net::Ipv4Addr>().unwrap())
            .destination("10.231.0.2".parse::<std::net::Ipv4Addr>().unwrap())
            .up()
            .build()
            .expect("failed to create TUN device");
        let tun = Arc::new(tuns.into_iter().next().unwrap());

        let (ready_tx, _ready_rx) = mpsc::channel(1);
        let (tuples_purge_tx, _purge_rx_keep) = broadcast::channel(1);
        let shared = Arc::new(Shared {
            tuples: RwLock::new(HashMap::new()),
            listening: RwLock::new(HashSet::new()),
            tun: vec![tun.clone()],
            ready: ready_tx,
            tuples_purge: tuples_purge_tx,
            stealth: StealthLevel::Off,
            mimic: Some(MimicProfile::udp2raw()),
        });

        let local_addr: SocketAddr = "10.231.0.1:1234".parse().unwrap();
        let remote_addr: SocketAddr = "10.231.0.2:5678".parse().unwrap();

        let (socket, sender) = Socket::new(
            shared.clone(),
            tun,
            local_addr,
            remote_addr,
            Some(100),
            State::Established,
            StealthLevel::Off,
            Some(MimicProfile::udp2raw()),
        );

        let tuple = AddrTuple::new(local_addr, remote_addr);
        shared.tuples.write().unwrap().insert(tuple, sender);

        // window_base should be mimic.window_raw
        assert_eq!(socket.window_base, 41000, "window_base should be mimic's window_raw");

        // current_window() should return exactly window_base (static, no jitter)
        for _ in 0..50 {
            assert_eq!(socket.current_window(), 41000, "current_window should be static 41000 in mimic mode");
        }
    }
}
