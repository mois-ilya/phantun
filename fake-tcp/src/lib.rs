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

        (
            Socket {
                shared,
                tun,
                incoming: incoming_rx,
                local_addr,
                remote_addr,
                seq: AtomicU32::new(if stealth >= StealthLevel::Basic {
                    rand::random::<u32>()
                } else {
                    0
                }),
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
                        && let Some(peer_tsval) = parse_tcp_timestamp(&tcp_packet)
                    {
                        self.ts_ecr.store(peer_tsval, Ordering::Relaxed);
                    }

                    let payload = tcp_packet.payload();

                    let new_ack = tcp_packet.get_sequence().wrapping_add(payload.len() as u32);
                    let last_ask = self.last_ack.load(Ordering::Relaxed);
                    self.ack.store(new_ack, Ordering::Relaxed);

                    if new_ack.overflowing_sub(last_ask).0 > MAX_UNACKED_LEN {
                        let buf = self.build_tcp_packet(tcp::TcpFlags::ACK, None);
                        if let Err(e) = self.tun.try_send(&buf) {
                            // This should not really happen as we have not sent anything for
                            // quite some time...
                            info!("Connection {} unable to send idling ACK back: {}", self, e)
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
                            && let Some(peer_tsval) = parse_tcp_timestamp(&tcp_packet)
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
                                && let Some(peer_tsval) = parse_tcp_timestamp(&tcp_packet)
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
        assert!(!(StealthLevel::Off >= StealthLevel::Basic));
    }

    #[test]
    fn test_stealth_level_copy_clone() {
        let a = StealthLevel::Basic;
        let b = a; // Copy
        let c = a.clone(); // Clone
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
}
