// Integration test helpers: network namespace + TUN setup.
// Feature-gated behind `integration-tests` — this module is only compiled when
// the feature is enabled.

use crate::{Socket, Stack};
use std::net::Ipv4Addr;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tokio_tun::TunBuilder;

// ── unique-name helpers ──────────────────────────────────────────────────────

/// 8-hex-char suffix guaranteed unique across processes and within a process.
/// Combines the PID (lower 16 bits) with a per-process atomic counter so that
/// parallel test binaries (`cargo test` runs each integration test file as a
/// separate process) never collide on namespace/interface names.
pub(crate) fn unique_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    format!("{:04x}{:04x}", pid as u16, n as u16)
}

// ── shell helpers ────────────────────────────────────────────────────────────

/// Run `ip <args>` in the current (default) network namespace; panic on failure.
pub(crate) fn run_ip(args: &[&str]) {
    let status = Command::new("ip")
        .args(args)
        .status()
        .expect("failed to spawn `ip`");
    assert!(
        status.success(),
        "ip {:?} failed with exit status {}",
        args,
        status
    );
}

/// Run `ip netns exec <ns> <program> <args>` ; panic on failure.
pub(crate) fn netns_exec(ns: &str, program: &str, args: &[&str]) {
    let status = Command::new("ip")
        .args(["netns", "exec", ns, program])
        .args(args)
        .status()
        .unwrap_or_else(|e| panic!("failed to spawn `ip netns exec {ns} {program}`: {e}"));
    assert!(
        status.success(),
        "ip netns exec {ns} {program} {:?} failed with exit status {status}",
        args
    );
}

// ── TUN creation inside a network namespace ──────────────────────────────────

/// Create a TUN device inside `ns_name` using `setns()` on a dedicated OS thread.
///
/// `setns()` changes the network namespace of the *calling thread*.  We isolate
/// this to a `std::thread::spawn`-ed thread so the tokio worker threads are not
/// affected.  The resulting `Vec<tokio_tun::Tun>` is `Send`, so it crosses the
/// thread boundary safely.
///
/// `tun_queues` controls how many kernel-level packet queues the TUN device has.
pub(crate) fn create_tun_in_netns(
    ns_name: &str,
    tun_name: &str,
    addr: Ipv4Addr,
    dest: Ipv4Addr,
    tun_queues: usize,
) -> Vec<tokio_tun::Tun> {
    let ns_name = ns_name.to_owned();
    let tun_name = tun_name.to_owned();

    // Capture the current tokio runtime handle so we can enter it from the
    // spawned thread (AsyncFd::new inside TunBuilder::build needs this).
    let handle = tokio::runtime::Handle::current();

    let handle_thread = std::thread::spawn(move || {
        // 1. Open the namespace fd created by `ip netns add`.
        let ns_path = format!("/var/run/netns/{ns_name}");
        let ns_file = std::fs::File::open(&ns_path)
            .unwrap_or_else(|e| panic!("open netns file {ns_path}: {e}"));

        // 2. Enter the network namespace on this thread.
        nix::sched::setns(&ns_file, nix::sched::CloneFlags::CLONE_NEWNET)
            .unwrap_or_else(|e| panic!("setns into {ns_name}: {e}"));

        // 3. Build TUN inside the namespace.  We must enter the tokio runtime
        //    context so that AsyncFd can register with the reactor.
        let _guard = handle.enter();
        TunBuilder::new()
            .name(&tun_name)
            .address(addr)
            .destination(dest)
            .queues(tun_queues)
            .up()
            .build()
            .unwrap_or_else(|e| panic!("TunBuilder::build in {ns_name}: {e}"))
    });

    match handle_thread.join() {
        Ok(tuns) => tuns,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

// ── public test environment ──────────────────────────────────────────────────

/// Holds a client `Stack` and a server `Stack` backed by TUN devices inside
/// isolated network namespaces.  Drops cleanly: namespaces are deleted on Drop.
///
/// Topology (all addresses are IPv4):
///
/// ```text
/// ns-client                          ns-server
///   tun-c  10.0.0.1 <-> 10.0.0.2      tun-s  10.0.1.1 <-> 10.0.1.2
///   tun-r  10.0.2.1 <-> 10.0.2.2      (raw TUN for crafted packets)
///   veth-c 10.1.0.1/30 ─────────────── veth-s 10.1.0.2/30
///   route  10.0.1.0/24 via 10.1.0.2    route  10.0.0.0/24 via 10.1.0.1
///                                       route  10.0.2.0/24 via 10.1.0.1
///
/// Client Stack local_ip = 10.0.0.2  (tun peer = tun_dest)
/// Server Stack local_ip = 10.0.1.1  (tun local = tun_addr)
/// raw_client_tun: TUN at 10.0.2.1<->10.0.2.2 for crafting raw IP packets
/// ```
pub struct TestEnv {
    pub client_stack: Stack,
    pub server_stack: Stack,
    /// Raw TUN device in ns-client for sending/receiving hand-crafted IP packets.
    /// Use src IP 10.0.2.2 in crafted packets; responses arrive here.
    #[allow(dead_code)]
    pub raw_client_tun: tokio_tun::Tun,
    ns_client: String,
    ns_server: String,
}

impl TestEnv {
    /// Shut down the stacks (cancels reader tasks, releases TUN FDs) and clean up namespaces.
    ///
    /// Prefer this over simply dropping to avoid leaking background tasks and kernel resources.
    pub async fn shutdown(&mut self) {
        tokio::join!(
            self.client_stack.shutdown(),
            self.server_stack.shutdown(),
        );
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        // Best-effort cleanup; ignore errors (namespace might already be gone).
        // For proper cleanup that also stops reader tasks, use `shutdown()` instead.
        let _ = Command::new("ip")
            .args(["netns", "del", &self.ns_client])
            .status();
        let _ = Command::new("ip")
            .args(["netns", "del", &self.ns_server])
            .status();
    }
}

/// Set up two isolated namespaces with a veth cross-link and TUN devices,
/// then return a `TestEnv` with ready-to-use `Stack` objects.
///
/// - `tun_queues`: number of TUN queues for client and server TUNs
///   (raw_client_tun always uses 1 queue)
///
/// Must be called from within a tokio runtime context.
pub async fn setup_test_env_with_config(tun_queues: usize) -> TestEnv {
    let sfx = unique_suffix();

    // Interface/namespace names (<=15 chars to respect IFNAMSIZ).
    let ns_c = format!("nc{sfx}"); // 10 chars
    let ns_s = format!("ns{sfx}"); // 10 chars
    let vc = format!("vc{sfx}"); // 10 chars
    let vs = format!("vs{sfx}"); // 10 chars
    let tun_c_name = format!("tc{sfx}"); // 10 chars
    let tun_s_name = format!("ts{sfx}"); // 10 chars

    let tun_r_name = format!("tr{sfx}"); // 10 chars — raw TUN in ns_c

    // TUN point-to-point addresses.
    // Client tun: local=10.0.0.1, peer=10.0.0.2  ->  Stack local_ip = 10.0.0.2
    // Server tun: local=10.0.1.1, peer=10.0.1.2  ->  Stack local_ip = 10.0.1.1
    // Raw tun:    local=10.0.2.1, peer=10.0.2.2  ->  for crafted-packet tests
    let tun_c_addr: Ipv4Addr = "10.0.0.1".parse().unwrap();
    let tun_c_dest: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let tun_s_addr: Ipv4Addr = "10.0.1.1".parse().unwrap();
    let tun_s_dest: Ipv4Addr = "10.0.1.2".parse().unwrap();
    let tun_r_addr: Ipv4Addr = "10.0.2.1".parse().unwrap();
    let tun_r_dest: Ipv4Addr = "10.0.2.2".parse().unwrap();

    // ── 1. Create network namespaces ─────────────────────────────────────────
    run_ip(&["netns", "add", &ns_c]);
    run_ip(&["netns", "add", &ns_s]);

    // ── 2. Create veth pair in default ns, then move each end ────────────────
    run_ip(&["link", "add", &vc, "type", "veth", "peer", "name", &vs]);
    run_ip(&["link", "set", &vc, "netns", &ns_c]);
    run_ip(&["link", "set", &vs, "netns", &ns_s]);

    // ── 3. Configure veth interfaces inside each namespace ───────────────────
    netns_exec(&ns_c, "ip", &["addr", "add", "10.1.0.1/30", "dev", &vc]);
    netns_exec(&ns_c, "ip", &["link", "set", &vc, "up"]);
    netns_exec(&ns_c, "ip", &["link", "set", "lo", "up"]);

    netns_exec(&ns_s, "ip", &["addr", "add", "10.1.0.2/30", "dev", &vs]);
    netns_exec(&ns_s, "ip", &["link", "set", &vs, "up"]);
    netns_exec(&ns_s, "ip", &["link", "set", "lo", "up"]);

    // ── 4. Create TUN devices inside each namespace ──────────────────────────
    let client_tuns = create_tun_in_netns(&ns_c, &tun_c_name, tun_c_addr, tun_c_dest, tun_queues);
    let server_tuns = create_tun_in_netns(&ns_s, &tun_s_name, tun_s_addr, tun_s_dest, tun_queues);
    // Raw TUN in ns_c for crafting arbitrary packets — always single-queue.
    let raw_tuns = create_tun_in_netns(&ns_c, &tun_r_name, tun_r_addr, tun_r_dest, 1);

    // ── 5. Add cross-namespace routes ────────────────────────────────────────
    netns_exec(
        &ns_c,
        "ip",
        &["route", "add", "10.0.1.0/24", "via", "10.1.0.2"],
    );
    netns_exec(
        &ns_s,
        "ip",
        &["route", "add", "10.0.0.0/24", "via", "10.1.0.1"],
    );
    // Server also needs a route back to the raw TUN subnet (10.0.2.0/24).
    netns_exec(
        &ns_s,
        "ip",
        &["route", "add", "10.0.2.0/24", "via", "10.1.0.1"],
    );

    // ── 6. Enable IPv4 forwarding in each namespace ──────────────────────────
    netns_exec(&ns_c, "sysctl", &["-w", "net.ipv4.ip_forward=1"]);
    netns_exec(&ns_s, "sysctl", &["-w", "net.ipv4.ip_forward=1"]);

    // ── 6b. DNAT in server namespace ────────────────────────────────────────
    netns_exec(
        &ns_s,
        "iptables",
        &[
            "-t", "nat", "-A", "PREROUTING",
            "-p", "tcp", "-d", "10.0.1.1",
            "-j", "DNAT", "--to-destination", "10.0.1.2",
        ],
    );

    // ── 6c. Disable strict TCP conntrack checking ─────────────────────────
    // Fake-TCP packets don't follow real TCP state machine rules, so the
    // kernel's conntrack module drops them after ~50 packets.  Setting
    // nf_conntrack_tcp_be_liberal=1 per-namespace (not globally) prevents
    // this without permanently weakening host conntrack validation.
    netns_exec(
        &ns_s,
        "sysctl",
        &["-w", "net.netfilter.nf_conntrack_tcp_be_liberal=1"],
    );
    netns_exec(
        &ns_c,
        "sysctl",
        &["-w", "net.netfilter.nf_conntrack_tcp_be_liberal=1"],
    );
    // Also increase the TUN transmit queue to handle burst traffic
    netns_exec(
        &ns_c,
        "ip",
        &["link", "set", &tun_c_name, "txqueuelen", "10000"],
    );
    netns_exec(
        &ns_s,
        "ip",
        &["link", "set", &tun_s_name, "txqueuelen", "10000"],
    );
    // Increase the veth transmit queues too
    netns_exec(
        &ns_c,
        "ip",
        &["link", "set", &vc, "txqueuelen", "10000"],
    );
    netns_exec(
        &ns_s,
        "ip",
        &["link", "set", &vs, "txqueuelen", "10000"],
    );

    // ── 7. Build Stack objects ───────────────────────────────────────────────
    let client_stack = Stack::new(client_tuns, tun_c_dest, None);
    let server_stack = Stack::new(server_tuns, tun_s_addr, None);
    let raw_client_tun = raw_tuns.into_iter().next().unwrap();

    TestEnv {
        client_stack,
        server_stack,
        raw_client_tun,
        ns_client: ns_c,
        ns_server: ns_s,
    }
}

/// Convenience wrapper: set up test env with default config (1 TUN queue).
pub async fn setup_test_env() -> TestEnv {
    setup_test_env_with_config(1).await
}

// ── bulk transfer helper ────────────────────────────────────────────────────

/// Send `total_bytes` from `client` to `server` using concurrent spawned tasks.
///
/// Data is sent in chunks of `chunk_size` bytes (fill byte `0xAB`).  The transfer
/// must complete within `transfer_timeout` or the function panics.
///
/// This is the canonical send/recv loop shared by integration tests and benchmarks.
/// Client ACK draining must be handled externally by the caller if required.
pub async fn send_recv_loop(
    client: Arc<Socket>,
    server: Arc<Socket>,
    total_bytes: usize,
    chunk_size: usize,
    transfer_timeout: Duration,
) {
    let sender = {
        let client = Arc::clone(&client);
        tokio::spawn(async move {
            let chunk = vec![0xABu8; chunk_size];
            let mut sent = 0;
            while sent < total_bytes {
                let to_send = std::cmp::min(chunk_size, total_bytes - sent);
                client.send(&chunk[..to_send]).await.expect("send failed");
                sent += to_send;
            }
        })
    };

    let receiver = {
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            let mut received = 0;
            let mut buf = vec![0u8; chunk_size + 100];
            while received < total_bytes {
                let n = server.recv(&mut buf).await.expect("recv returned None");
                assert!(n > 0, "recv returned 0 bytes");
                received += n;
            }
        })
    };

    timeout(transfer_timeout, async {
        sender.await.expect("sender panicked");
        receiver.await.expect("receiver panicked");
    })
    .await
    .expect("send_recv_loop timed out — possible deadlock or resource exhaustion");
}
