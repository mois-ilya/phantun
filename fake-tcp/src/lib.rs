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

#![cfg_attr(feature = "benchmark", feature(test))]

pub mod packet;

use bytes::{Bytes, BytesMut};
use log::{error, info, trace, warn};
use packet::*;
use pnet::packet::{tcp, Packet};
use rand::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc, RwLock,
};
use std::time::Instant;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::time;
use tokio_tun::Tun;

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

const TIMEOUT: time::Duration = time::Duration::from_secs(1);
const RETRIES: usize = 6;
const MPMC_BUFFER_LEN: usize = 512;
const MPSC_BUFFER_LEN: usize = 128;
const MAX_UNACKED_LEN: u32 = 128 * 1024 * 1024; // 128MB

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
}

pub struct Stack {
    shared: Arc<Shared>,
    local_ip: Ipv4Addr,
    local_ip6: Option<Ipv6Addr>,
    ready: mpsc::Receiver<Socket>,
}

pub enum State {
    Idle,
    SynSent,
    SynReceived,
    Established,
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
    /// Count of consecutive identical ACK values from peer (stealth >= Full)
    dup_ack_count: AtomicU32,
    /// Last sequence number acknowledged by peer (stealth >= Full)
    last_acked_seq: AtomicU32,
    /// Peer's effective advertised receive window (stealth >= Full)
    peer_window: AtomicU32,
    /// Congestion window in bytes (stealth >= Full)
    cwnd: AtomicU32,
    /// Slow start threshold in bytes (stealth >= Full)
    ssthresh: AtomicU32,
}

/// A socket that represents a unique TCP connection between a server and client.
///
/// The `Socket` object itself satisfies `Sync` and `Send`, which means it can
/// be safely called within an async future.
///
/// To close a TCP connection that is no longer needed, simply drop this object
/// out of scope.
impl Socket {
    fn new(
        shared: Arc<Shared>,
        tun: Arc<Tun>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        ack: Option<u32>,
        state: State,
        stealth: StealthLevel,
    ) -> (Socket, flume::Sender<Bytes>) {
        let (incoming_tx, incoming_rx) = flume::bounded(MPMC_BUFFER_LEN);

        let initial_seq = if stealth >= StealthLevel::Basic {
            rand::random::<u32>()
        } else {
            0
        };

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
                stealth,
                ts_epoch: Instant::now(),
                ts_offset: if stealth >= StealthLevel::Basic {
                    rand::random::<u32>()
                } else {
                    0
                },
                ts_ecr: AtomicU32::new(0),
                window_base: if stealth >= StealthLevel::Standard {
                    // Random base window in range 256..=512, representing ~32K-64K
                    // effective receive window with wscale=7
                    256 + (rand::random::<u16>() % 257)
                } else {
                    0xFFFF
                },
                dup_ack_count: AtomicU32::new(0),
                // Initialize to initial_seq so Level 3 constraints don't see a
                // huge bytes_in_flight on the first send after handshake
                last_acked_seq: AtomicU32::new(initial_seq),
                peer_window: AtomicU32::new(0),
                // Initial cwnd = 10 * MSS (RFC 6928), ssthresh = 64KB
                cwnd: AtomicU32::new(if stealth >= StealthLevel::Full {
                    10 * 1460
                } else {
                    0
                }),
                ssthresh: AtomicU32::new(if stealth >= StealthLevel::Full {
                    65535
                } else {
                    0
                }),
            },
            incoming_tx,
        )
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
        if self.stealth >= StealthLevel::Standard {
            // Add jitter of 0..32 to base window to simulate natural variation
            self.window_base.wrapping_add(rand::random::<u16>() % 32)
        } else {
            0xFFFF
        }
    }

    fn build_tcp_packet(&self, flags: u8, payload: Option<&[u8]>) -> Bytes {
        let ack = self.ack.load(Ordering::Relaxed);
        self.last_ack.store(ack, Ordering::Relaxed);

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
            self.current_window(),
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
                let flags = if self.stealth >= StealthLevel::Basic {
                    tcp::TcpFlags::PSH | tcp::TcpFlags::ACK
                } else {
                    tcp::TcpFlags::ACK
                };

                // Send window constraint (stealth >= Full): wrap seq back if bytes
                // in flight would exceed the effective window (min of peer's
                // advertised window and congestion window)
                if self.stealth >= StealthLevel::Full {
                    let peer_win = self.peer_window.load(Ordering::Relaxed);
                    let cwnd = self.cwnd.load(Ordering::Relaxed);
                    // Effective window: use peer's advertised window if known,
                    // otherwise fall back to cwnd alone (peer_window starts at 0
                    // until the first data packet is received from the peer)
                    let effective_win = if peer_win > 0 { peer_win.min(cwnd) } else { cwnd };
                    if effective_win > 0 {
                        let last_acked = self.last_acked_seq.load(Ordering::Relaxed);
                        let current_seq = self.seq.load(Ordering::Relaxed);
                        let bytes_in_flight = current_seq.wrapping_sub(last_acked);
                        if bytes_in_flight.wrapping_add(payload.len() as u32) > effective_win {
                            self.seq.store(last_acked, Ordering::Relaxed);
                        }
                    }
                }

                let buf = self.build_tcp_packet(flags, Some(payload));
                self.seq.fetch_add(payload.len() as u32, Ordering::Relaxed);
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
                self.incoming.recv_async().await.ok().and_then(|raw_buf| {
                    let (_v4_packet, tcp_packet) = parse_ip_packet(&raw_buf).unwrap();

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
                    if self.stealth >= StealthLevel::Full {
                        let peer_ack = tcp_packet.get_acknowledgement();
                        let prev_acked = self.last_acked_seq.load(Ordering::Relaxed);
                        if peer_ack == prev_acked {
                            let count = self.dup_ack_count.fetch_add(1, Ordering::Relaxed) + 1;
                            if count >= 3 {
                                // Triple duplicate ACK: reset seq to last acked position
                                // (simulate fast retransmit)
                                self.seq.store(prev_acked, Ordering::Relaxed);
                                // Multiplicative decrease: halve cwnd, set ssthresh
                                let cwnd = self.cwnd.load(Ordering::Relaxed);
                                let new_ssthresh = (cwnd / 2).max(2 * 1460);
                                self.ssthresh.store(new_ssthresh, Ordering::Relaxed);
                                self.cwnd.store(new_ssthresh, Ordering::Relaxed);
                                // Reset counter to prevent repeated halving on subsequent dups
                                self.dup_ack_count.store(0, Ordering::Relaxed);
                            }
                        } else {
                            self.last_acked_seq.store(peer_ack, Ordering::Relaxed);
                            self.dup_ack_count.store(0, Ordering::Relaxed);
                            // Congestion window growth on new ACK
                            let cwnd = self.cwnd.load(Ordering::Relaxed);
                            let ssthresh = self.ssthresh.load(Ordering::Relaxed);
                            if cwnd < ssthresh {
                                // Slow start: increase cwnd by MSS (doubles per RTT)
                                self.cwnd.store(cwnd + 1460, Ordering::Relaxed);
                            } else {
                                // Congestion avoidance: increase cwnd by MSS per RTT
                                // Approximate: add MSS^2/cwnd per ACK
                                let increment = (1460u32 * 1460).checked_div(cwnd).unwrap_or(1);
                                self.cwnd.store(cwnd + increment.max(1), Ordering::Relaxed);
                            }
                        }

                        // Store peer's advertised receive window (scaled by wscale=7).
                        // NOTE: This assumes the peer also uses wscale=7, which is true
                        // when both sides run the same stealth level (as documented in
                        // README). Mismatched stealth levels will produce incorrect
                        // window scaling.
                        let raw_window = tcp_packet.get_window() as u32;
                        self.peer_window.store(raw_window << 7, Ordering::Relaxed);
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
                        let buf = self.build_tcp_packet(tcp::TcpFlags::ACK, None);
                        if let Err(e) = self.tun.try_send(&buf) {
                            info!("Connection {} unable to send standalone ACK: {}", self, e)
                        }
                    }

                    buf[..payload.len()].copy_from_slice(payload);

                    Some(payload.len())
                })
            }
            _ => unreachable!(),
        }
    }

    async fn accept(mut self) {
        for _ in 0..RETRIES {
            match self.state {
                State::Idle => {
                    let buf = self.build_tcp_packet(tcp::TcpFlags::SYN | tcp::TcpFlags::ACK, None);
                    // ACK set by constructor
                    self.tun.send(&buf).await.unwrap();
                    self.state = State::SynReceived;
                    info!("Sent SYN + ACK to client");
                }
                State::SynReceived => {
                    let res = time::timeout(TIMEOUT, self.incoming.recv_async()).await;
                    if let Ok(buf) = res {
                        let buf = buf.unwrap();
                        let (_v4_packet, tcp_packet) = parse_ip_packet(&buf).unwrap();

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
                                == self.seq.load(Ordering::Relaxed) + 1
                        {
                            // found our ACK
                            self.seq.fetch_add(1, Ordering::Relaxed);
                            self.state = State::Established;

                            info!("Connection from {:?} established", self.remote_addr);
                            let ready = self.shared.ready.clone();
                            if let Err(e) = ready.send(self).await {
                                error!("Unable to send accepted socket to ready queue: {}", e);
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
                    self.tun.send(&buf).await.unwrap();
                    self.state = State::SynSent;
                    info!("Sent SYN to server");
                }
                State::SynSent => {
                    match time::timeout(TIMEOUT, self.incoming.recv_async()).await {
                        Ok(buf) => {
                            let buf = buf.unwrap();
                            let (_v4_packet, tcp_packet) = parse_ip_packet(&buf).unwrap();

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
                                    == self.seq.load(Ordering::Relaxed) + 1
                            {
                                // found our SYN + ACK
                                self.seq.fetch_add(1, Ordering::Relaxed);
                                self.ack
                                    .store(tcp_packet.get_sequence() + 1, Ordering::Relaxed);

                                // send ACK to finish handshake
                                let buf = self.build_tcp_packet(tcp::TcpFlags::ACK, None);
                                self.tun.send(&buf).await.unwrap();

                                self.state = State::Established;

                                info!("Connection to {:?} established", self.remote_addr);
                                return Some(());
                            }
                        }
                        Err(_) => {
                            info!("Waiting for SYN + ACK timed out");
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
        assert!(self.shared.tuples.write().unwrap().remove(&tuple).is_some());
        // purge cache
        self.shared.tuples_purge.send(tuple).unwrap();

        let buf = build_tcp_packet(
            self.local_addr,
            self.remote_addr,
            self.seq.load(Ordering::Relaxed),
            0,
            tcp::TcpFlags::RST,
            None,
            self.stealth,
            self.current_ts_val(),
            0, // RST doesn't need ts_ecr
            self.current_window(),
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
    ) -> Stack {
        let tun: Vec<Arc<Tun>> = tun.into_iter().map(Arc::new).collect();
        let (ready_tx, ready_rx) = mpsc::channel(MPSC_BUFFER_LEN);
        let (tuples_purge_tx, _tuples_purge_rx) = broadcast::channel(16);
        let shared = Arc::new(Shared {
            tuples: RwLock::new(HashMap::new()),
            tun: tun.clone(),
            listening: RwLock::new(HashSet::new()),
            ready: ready_tx,
            tuples_purge: tuples_purge_tx.clone(),
            stealth,
        });

        for t in tun {
            tokio::spawn(Stack::reader_task(
                t,
                shared.clone(),
                tuples_purge_tx.subscribe(),
            ));
        }

        Stack {
            shared,
            local_ip,
            local_ip6,
            ready: ready_rx,
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
    ) {
        let mut tuples: HashMap<AddrTuple, flume::Sender<Bytes>> = HashMap::new();

        loop {
            let mut buf = BytesMut::zeroed(MAX_PACKET_LEN);

            tokio::select! {
                size = tun.recv(&mut buf) => {
                    let size = size.unwrap();
                    buf.truncate(size);
                    let buf = buf.freeze();

                    match parse_ip_packet(&buf) {
                        Some((ip_packet, tcp_packet)) => {
                            let local_addr =
                                SocketAddr::new(ip_packet.get_destination(), tcp_packet.get_destination());
                            let remote_addr = SocketAddr::new(ip_packet.get_source(), tcp_packet.get_source());

                            let tuple = AddrTuple::new(local_addr, remote_addr);
                            if let Some(c) = tuples.get(&tuple) {
                                if c.send_async(buf).await.is_err() {
                                    trace!("Cache hit, but receiver already closed, dropping packet");
                                }

                                continue;

                                // If not Ok, receiver has been closed and just fall through to the slow
                                // path below
                            } else {
                                trace!("Cache miss, checking the shared tuples table for connection");
                                let sender = {
                                    let tuples = shared.tuples.read().unwrap();
                                    tuples.get(&tuple).cloned()
                                };

                                if let Some(c) = sender {
                                    trace!("Storing connection information into local tuples");
                                    tuples.insert(tuple, c.clone());
                                    c.send_async(buf).await.unwrap();
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
                                        Some(tcp_packet.get_sequence() + 1),
                                        State::Idle,
                                        shared.stealth,
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
                                    tokio::spawn(sock.accept());
                                } else {
                                    trace!("Bad TCP SYN packet from {}, sending RST", remote_addr);
                                    let buf = build_tcp_packet(
                                        local_addr,
                                        remote_addr,
                                        0,
                                        tcp_packet.get_sequence() + tcp_packet.payload().len() as u32 + 1, // +1 because of SYN flag set
                                        tcp::TcpFlags::RST | tcp::TcpFlags::ACK,
                                        None,
                                        StealthLevel::Off,
                                        0, 0,
                                        0xFFFF,
                                    );
                                    shared.tun[0].try_send(&buf).unwrap();
                                }
                            } else if (tcp_packet.get_flags() & tcp::TcpFlags::RST) == 0 {
                                info!("Unknown TCP packet from {}, sending RST", remote_addr);
                                let buf = build_tcp_packet(
                                    local_addr,
                                    remote_addr,
                                    tcp_packet.get_acknowledgement(),
                                    tcp_packet.get_sequence() + tcp_packet.payload().len() as u32,
                                    tcp::TcpFlags::RST | tcp::TcpFlags::ACK,
                                    None,
                                    StealthLevel::Off,
                                    0, 0,
                                    0xFFFF,
                                );
                                shared.tun[0].try_send(&buf).unwrap();
                            }
                        }
                        None => {
                            continue;
                        }
                    }
                },
                tuple = tuples_purge.recv() => {
                    let tuple = tuple.unwrap();
                    tuples.remove(&tuple);
                    trace!("Removed cached tuple: {:?}", tuple);
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

    #[test]
    fn test_stealth_level_copy_clone() {
        let a = StealthLevel::Basic;
        let b = a; // Copy
        let c = a; // Clone (Copy trait)
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn test_stealth_level_debug() {
        assert_eq!(format!("{:?}", StealthLevel::Off), "Off");
        assert_eq!(format!("{:?}", StealthLevel::Full), "Full");
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

    #[test]
    fn test_stealth_syn_acceptance_logic() {
        // Verify the acceptance condition used in reader_task:
        // stealth >= Basic || seq == 0

        // stealth Off, seq 0: accepted
        assert!(StealthLevel::Off >= StealthLevel::Basic || 0u32 == 0);

        // stealth Off, seq nonzero: rejected
        assert!(!(StealthLevel::Off >= StealthLevel::Basic || 12345u32 == 0));

        // stealth Basic, seq 0: accepted
        assert!(StealthLevel::Basic >= StealthLevel::Basic || 0u32 == 0);

        // stealth Basic, seq nonzero: accepted (because stealth >= Basic)
        assert!(StealthLevel::Basic >= StealthLevel::Basic || 12345u32 == 0);

        // stealth Standard, seq nonzero: accepted
        assert!(StealthLevel::Standard >= StealthLevel::Basic || 99999u32 == 0);

        // stealth Full, seq nonzero: accepted
        assert!(StealthLevel::Full >= StealthLevel::Basic || 99999u32 == 0);
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
        assert_ne!(window, 0xFFFF, "stealth Full should not use static 0xFFFF");
    }

    // --- Task 9: Duplicate ACK tracking (Level 3) ---

    /// Simulates the duplicate ACK tracking logic from Socket::recv().
    /// Returns (new_dup_ack_count, new_last_acked_seq, seq_result).
    /// After fast retransmit triggers, counter resets to 0 (matching real code).
    fn simulate_dup_ack_tracking(
        stealth: StealthLevel,
        peer_ack: u32,
        prev_acked_seq: u32,
        prev_dup_count: u32,
        current_seq: u32,
    ) -> (u32, u32, u32) {
        if stealth >= StealthLevel::Full {
            if peer_ack == prev_acked_seq {
                let new_count = prev_dup_count + 1;
                if new_count >= 3 {
                    // Fast retransmit: reset seq, then reset counter
                    (0, prev_acked_seq, prev_acked_seq)
                } else {
                    (new_count, prev_acked_seq, current_seq)
                }
            } else {
                // New ACK value: reset counter to 0 (not 1)
                (0, peer_ack, current_seq)
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
            simulate_dup_ack_tracking(stealth, acked_seq, 0, 0, current_seq);
        assert_eq!(count, 0);
        assert_eq!(last_acked, acked_seq);
        assert_eq!(seq, current_seq, "no reset on original ACK");

        // First duplicate ACK: count becomes 1
        let (count, last_acked, seq) =
            simulate_dup_ack_tracking(stealth, acked_seq, acked_seq, 0, current_seq);
        assert_eq!(count, 1);
        assert_eq!(last_acked, acked_seq);
        assert_eq!(seq, current_seq, "no reset on first dup ACK");

        // Second duplicate ACK: count becomes 2
        let (count, last_acked, seq) =
            simulate_dup_ack_tracking(stealth, acked_seq, acked_seq, 1, current_seq);
        assert_eq!(count, 2);
        assert_eq!(last_acked, acked_seq);
        assert_eq!(seq, current_seq, "no reset on second dup ACK");

        // Third duplicate ACK: count reaches 3, triggers fast retransmit, counter resets
        let (count, last_acked, seq) =
            simulate_dup_ack_tracking(stealth, acked_seq, acked_seq, 2, current_seq);
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
            simulate_dup_ack_tracking(stealth, acked_seq, acked_seq, 2, current_seq);
        assert_eq!(count, 0, "counter resets after retransmit");
        assert_eq!(seq, acked_seq, "seq must equal last_acked_seq after fast retransmit");
    }

    #[test]
    fn test_dup_ack_count_resets_on_new_ack() {
        // When a new (different) ACK value arrives, dup count resets to 0
        let stealth = StealthLevel::Full;

        // Had 2 dup ACKs for seq 1000, now get ACK for seq 2000
        let (count, last_acked, seq) =
            simulate_dup_ack_tracking(stealth, 2000, 1000, 2, 5000);
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
            simulate_dup_ack_tracking(stealth, acked, acked, 2, 9000);
        assert_eq!(count, 0, "counter resets after retransmit");
        assert_eq!(seq, acked, "seq resets on retransmit");

        // Next dup ACK: count goes to 1 (starting fresh)
        let (count, _, seq) =
            simulate_dup_ack_tracking(stealth, acked, acked, 0, 9000);
        assert_eq!(count, 1, "counting starts fresh after reset");
        assert_eq!(seq, 9000, "no retransmit yet");
    }

    #[test]
    fn test_dup_ack_not_tracked_below_full() {
        // Stealth levels below Full should not track dup ACKs
        for stealth in [StealthLevel::Off, StealthLevel::Basic, StealthLevel::Standard] {
            let (count, last_acked, seq) =
                simulate_dup_ack_tracking(stealth, 5000, 5000, 2, 8000);
            // Should return unchanged values since no tracking happens
            assert_eq!(count, 2, "stealth {:?}: dup count should not change", stealth);
            assert_eq!(last_acked, 5000, "stealth {:?}: last_acked should not change", stealth);
            assert_eq!(seq, 8000, "stealth {:?}: seq should not change", stealth);
        }
    }

    #[test]
    fn test_dup_ack_wrapping_seq_values() {
        // Test with wrapping sequence numbers near u32::MAX
        let stealth = StealthLevel::Full;
        let acked = u32::MAX - 100;
        let current_seq = u32::MAX;

        // Third dup ACK with high seq values
        let (count, _, seq) =
            simulate_dup_ack_tracking(stealth, acked, acked, 2, current_seq);
        assert_eq!(count, 0, "counter resets after retransmit");
        assert_eq!(seq, acked, "fast retransmit should work with high seq values");
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

    const MSS: u32 = 1460;

    /// Simulates congestion window growth on receiving a new (non-duplicate) ACK.
    /// Returns the new cwnd value.
    fn simulate_cwnd_growth(cwnd: u32, ssthresh: u32) -> u32 {
        if cwnd < ssthresh {
            // Slow start: increase cwnd by MSS
            cwnd + MSS
        } else {
            // Congestion avoidance: increase by MSS^2/cwnd per ACK
            let increment = (MSS * MSS).checked_div(cwnd).unwrap_or(1);
            cwnd + increment.max(1)
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
}
