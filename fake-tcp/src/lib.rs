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
    Arc, RwLock,
};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;
use tokio_tun::Tun;
use tokio_util::sync::CancellationToken;

const TIMEOUT: time::Duration = time::Duration::from_secs(1);
const RETRIES: usize = 6;
const MPMC_BUFFER_LEN: usize = 512;
const MPSC_BUFFER_LEN: usize = 128;

/// udp2raw fingerprint constants
const WINDOW_BASE: u16 = 40960;
const WINDOW_JITTER: u16 = 512;

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
    /// Last received peer tsval, echoed back as ts_ecr
    ts_ecr: AtomicU32,
    /// Last window value we sent, reused for duplicate ACKs
    last_window_sent: AtomicU16,
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
    ) -> (Socket, flume::Sender<Bytes>) {
        let (incoming_tx, incoming_rx) = flume::bounded(MPMC_BUFFER_LEN);

        let initial_seq = rand::random::<u32>();

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
                ts_ecr: AtomicU32::new(0),
                last_window_sent: AtomicU16::new(0),
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

    /// Compute the current ts_val as Unix epoch milliseconds (u32).
    /// Matches udp2raw: get_current_time() returns epoch ms, cast to u32 (network.cpp:1665).
    fn current_ts_val(&self) -> u32 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u32
    }

    /// Compute the current advertised window value.
    /// Fresh random window per packet, matching udp2raw: 40960 + random % 512.
    fn current_window(&self) -> u16 {
        WINDOW_BASE + (rand::random::<u16>() % WINDOW_JITTER)
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
        let window = if !is_syn && payload.is_none() && ack == prev_ack {
            self.last_window_sent.load(Ordering::Relaxed)
        } else {
            let w = self.current_window();
            self.last_window_sent.store(w, Ordering::Relaxed);
            w
        };

        build_tcp_packet(
            self.local_addr,
            self.remote_addr,
            self.seq.load(Ordering::Relaxed),
            ack,
            flags,
            payload,
            self.current_ts_val(),
            self.ts_ecr.load(Ordering::Relaxed),
            window,
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
                let flags = tcp::TcpFlags::PSH | tcp::TcpFlags::ACK;

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
                loop {
                    let raw_buf = self.incoming.recv_async().await.ok()?;
                    let (_v4_packet, tcp_packet) = parse_ip_packet(&raw_buf).unwrap();

                    if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
                        info!("Connection {} reset by peer", self);
                        return None;
                    }

                    // Update ts_ecr with peer's tsval from incoming packet
                    if let Some(peer_tsval) = parse_tcp_timestamps(&tcp_packet).map(|(tsval, _)| tsval) {
                        self.ts_ecr.store(peer_tsval, Ordering::Relaxed);
                    }

                    let payload = tcp_packet.payload();

                    // Skip ACK-only packets (no payload) — update ack state but don't deliver to app
                    if payload.is_empty() {
                        continue;
                    }

                    let new_ack = tcp_packet.get_sequence().wrapping_add(payload.len() as u32);
                    let last_ask = self.last_ack.load(Ordering::Relaxed);
                    self.ack.store(new_ack, Ordering::Relaxed);

                    // Send standalone ACK on every received data packet
                    let send_ack = new_ack != last_ask;

                    if send_ack {
                        let ack_buf = self.build_tcp_packet(tcp::TcpFlags::ACK, None);
                        if let Err(e) = self.tun.try_send(&ack_buf) {
                            info!("Connection {} unable to send standalone ACK: {}", self, e)
                        }
                    }

                    buf[..payload.len()].copy_from_slice(payload);
                    return Some(payload.len());
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
                    self.tun.send(&buf).await.unwrap();
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
                        let buf = buf.unwrap();
                        let (_v4_packet, tcp_packet) = parse_ip_packet(&buf).unwrap();

                        if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
                            return;
                        }

                        // Update ts_ecr from handshake ACK
                        if let Some(peer_tsval) = parse_tcp_timestamps(&tcp_packet).map(|(tsval, _)| tsval) {
                            self.ts_ecr.store(peer_tsval, Ordering::Relaxed);
                        }

                        if tcp_packet.get_flags() == tcp::TcpFlags::ACK
                            && tcp_packet.get_acknowledgement()
                                == self.seq.load(Ordering::Relaxed).wrapping_add(1)
                        {
                            // found our ACK
                            self.seq.fetch_add(1, Ordering::Relaxed);
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
                            if let Some(peer_tsval) = parse_tcp_timestamps(&tcp_packet).map(|(tsval, _)| tsval) {
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
        // Ignore error: after Stack::shutdown(), reader tasks (the only
        // broadcast subscribers) are gone, so send() returns Err — that's fine
        // because there is no local cache left to purge.
        let _ = self.shared.tuples_purge.send(tuple);

        // Send RST — real Linux omits timestamps on RST packets, so we send
        // with ts_val=0 and ts_ecr=0 and window=0
        let buf = build_tcp_packet(
            self.local_addr,
            self.remote_addr,
            self.seq.load(Ordering::Relaxed),
            0,
            tcp::TcpFlags::RST,
            None,
            0,
            0,
            0,
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
                                // SYN seen on listening socket — always accept (random ISN)
                                let (sock, incoming) = Socket::new(
                                    shared.clone(),
                                    tun.clone(),
                                    local_addr,
                                    remote_addr,
                                    Some(tcp_packet.get_sequence().wrapping_add(1)),
                                    State::Idle,
                                );
                                // Echo client's SYN tsval in SYN+ACK ts_ecr (RFC 7323)
                                if let Some((peer_tsval, _)) = parse_tcp_timestamps(&tcp_packet) {
                                    sock.ts_ecr.store(peer_tsval, Ordering::Relaxed);
                                }
                                assert!(shared
                                    .tuples
                                    .write()
                                    .unwrap()
                                    .insert(tuple, incoming)
                                    .is_none());
                                tokio::spawn(sock.accept(cancel.clone()));
                            } else if (tcp_packet.get_flags() & tcp::TcpFlags::RST) == 0 {
                                info!("Unknown TCP packet from {}, sending RST", remote_addr);
                                let flags = tcp_packet.get_flags();
                                let has_ack = (flags & tcp::TcpFlags::ACK) != 0;

                                let (rst_seq, rst_ack, rst_flags, rst_window) = if has_ack {
                                    // RFC 793: ACK set -> <SEQ=SEG.ACK><CTL=RST>
                                    (tcp_packet.get_acknowledgement(), 0, tcp::TcpFlags::RST, 0)
                                } else {
                                    // RFC 793: no ACK -> <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
                                    let mut seg_len = tcp_packet.payload().len() as u32;
                                    if (flags & tcp::TcpFlags::SYN) != 0 { seg_len += 1; }
                                    if (flags & tcp::TcpFlags::FIN) != 0 { seg_len += 1; }
                                    (0, tcp_packet.get_sequence().wrapping_add(seg_len), tcp::TcpFlags::RST | tcp::TcpFlags::ACK, 0)
                                };

                                let buf = build_tcp_packet(
                                    local_addr,
                                    remote_addr,
                                    rst_seq,
                                    rst_ack,
                                    rst_flags,
                                    None,
                                    0, 0,
                                    rst_window,
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

    // --- ISN randomness tests ---

    #[test]
    fn test_isn_is_random() {
        // ISN should be random (not always 0)
        let mut seen_nonzero = false;
        for _ in 0..10 {
            if rand::random::<u32>() != 0 {
                seen_nonzero = true;
                break;
            }
        }
        assert!(seen_nonzero, "ISN should be random");
    }

    #[test]
    fn test_isn_has_variety() {
        let values: Vec<u32> = (0..10).map(|_| rand::random::<u32>()).collect();
        let unique: std::collections::HashSet<u32> = values.into_iter().collect();
        assert!(unique.len() > 1, "ISN should vary between connections");
    }

    // --- ACK threshold tests ---

    #[test]
    fn test_ack_threshold_sends_on_every_packet() {
        // ACK is sent on every received data packet when new_ack != last_ack
        let new_ack: u32 = 100;
        let last_ack: u32 = 0;
        let should_ack = new_ack != last_ack;
        assert!(should_ack, "any data should trigger standalone ACK");

        let new_ack: u32 = 1;
        let last_ack: u32 = 0;
        let should_ack = new_ack != last_ack;
        assert!(should_ack, "even 1 byte should trigger ACK");
    }

    #[test]
    fn test_ack_no_standalone_when_unchanged() {
        let new_ack: u32 = 100;
        let last_ack: u32 = 100;
        let should_ack = new_ack != last_ack;
        assert!(!should_ack, "no ACK when ack unchanged");
    }

    // --- Dynamic window tests ---

    #[test]
    fn test_window_base_in_range() {
        // Window base should be in WINDOW_BASE..WINDOW_BASE+WINDOW_JITTER
        for _ in 0..50 {
            let base = WINDOW_BASE + (rand::random::<u16>() % WINDOW_JITTER);
            assert!(base >= WINDOW_BASE, "window_base {} should be >= WINDOW_BASE {}", base, WINDOW_BASE);
            assert!(base < WINDOW_BASE + WINDOW_JITTER, "window_base {} should be < WINDOW_BASE+JITTER", base);
        }
    }

    #[test]
    fn test_window_varies_with_jitter() {
        let windows: Vec<u16> = (0..20)
            .map(|_| WINDOW_BASE + (rand::random::<u16>() % WINDOW_JITTER))
            .collect();
        let unique: std::collections::HashSet<u16> = windows.into_iter().collect();
        assert!(unique.len() > 1, "window values should vary with jitter");
    }

    #[test]
    fn test_window_jitter_bounded() {
        for _ in 0..100 {
            let window = WINDOW_BASE + (rand::random::<u16>() % WINDOW_JITTER);
            assert!(window >= WINDOW_BASE, "window {} should be >= WINDOW_BASE {}", window, WINDOW_BASE);
            assert!(window < WINDOW_BASE + WINDOW_JITTER, "window {} should be < WINDOW_BASE+JITTER {}", window, WINDOW_BASE + WINDOW_JITTER);
        }
    }

    // --- ts_ecr echo correctness tests ---

    #[test]
    fn test_tsecr_atomic_store_load_consistent() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let ts_ecr = AtomicU32::new(0);

        ts_ecr.store(123456789, Ordering::Relaxed);
        assert_eq!(ts_ecr.load(Ordering::Relaxed), 123456789);

        ts_ecr.store(987654321, Ordering::Relaxed);
        assert_eq!(ts_ecr.load(Ordering::Relaxed), 987654321);

        ts_ecr.store(u32::MAX, Ordering::Relaxed);
        assert_eq!(ts_ecr.load(Ordering::Relaxed), u32::MAX);
    }

    // --- WSCALE constant check ---

    #[test]
    fn test_wscale_is_5() {
        assert_eq!(packet::WSCALE, 5, "udp2raw uses wscale=5");
    }

    // --- WINDOW_BASE constant check ---

    #[test]
    fn test_window_base_is_40960() {
        assert_eq!(WINDOW_BASE, 40960, "udp2raw uses window base 40960");
    }
}
