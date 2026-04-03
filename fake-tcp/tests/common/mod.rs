// Integration test helpers: network namespace + TUN setup.
// Gated behind the integration-tests feature — this entire module is a no-op
// when compiled without it.
#![cfg(feature = "integration-tests")]

use fake_tcp::Stack;
use std::net::Ipv4Addr;
use std::process::Command;
use tokio_tun::TunBuilder;

// ── unique-name helpers ──────────────────────────────────────────────────────

/// 8-hex-char suffix derived from sub-second nanoseconds, good enough for
/// serialised test runs and highly unlikely to collide in parallel runs.
fn unique_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    format!("{:08x}", nanos)
}

// ── shell helpers ────────────────────────────────────────────────────────────

/// Run `ip <args>` in the current (default) network namespace; panic on failure.
fn run_ip(args: &[&str]) {
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
fn netns_exec(ns: &str, program: &str, args: &[&str]) {
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
fn create_tun_in_netns(
    ns_name: &str,
    tun_name: &str,
    addr: Ipv4Addr,
    dest: Ipv4Addr,
) -> Vec<tokio_tun::Tun> {
    let ns_name = ns_name.to_owned();
    let tun_name = tun_name.to_owned();

    // Capture the current tokio runtime handle so we can enter it from the
    // spawned thread (AsyncFd::new inside TunBuilder::build needs this).
    let handle = tokio::runtime::Handle::current();

    let (tx, rx) = std::sync::mpsc::channel::<Vec<tokio_tun::Tun>>();

    std::thread::spawn(move || {
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
        let tuns = TunBuilder::new()
            .name(&tun_name)
            .packet_info(false)
            .address(addr)
            .destination(dest)
            .up()
            .build()
            .unwrap_or_else(|e| panic!("TunBuilder::build in {ns_name}: {e}"));

        tx.send(tuns).unwrap();
    });

    rx.recv().expect("TUN-creation thread panicked before sending")
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
///   veth-c 10.1.0.1/30 ─────────────── veth-s 10.1.0.2/30
///   route  10.0.1.0/24 via 10.1.0.2    route  10.0.0.0/24 via 10.1.0.1
///
/// Client Stack local_ip = 10.0.0.2  (tun peer = tun_dest)
/// Server Stack local_ip = 10.0.1.1  (tun local = tun_addr)
/// ```
pub struct TestEnv {
    pub client_stack: Stack,
    pub server_stack: Stack,
    ns_client: String,
    ns_server: String,
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        // Best-effort cleanup; ignore errors (namespace might already be gone).
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
/// Must be called from within a `#[tokio::test]` context (needs a runtime).
pub async fn setup_test_env() -> TestEnv {
    let sfx = unique_suffix();

    // Interface/namespace names (≤15 chars to respect IFNAMSIZ).
    let ns_c = format!("nc{sfx}"); // 10 chars
    let ns_s = format!("ns{sfx}"); // 10 chars
    let vc = format!("vc{sfx}"); // 10 chars
    let vs = format!("vs{sfx}"); // 10 chars
    let tun_c_name = format!("tc{sfx}"); // 10 chars
    let tun_s_name = format!("ts{sfx}"); // 10 chars

    // TUN point-to-point addresses.
    // Client tun: local=10.0.0.1, peer=10.0.0.2  →  Stack local_ip = 10.0.0.2
    // Server tun: local=10.0.1.1, peer=10.0.1.2  →  Stack local_ip = 10.0.1.1
    let tun_c_addr: Ipv4Addr = "10.0.0.1".parse().unwrap();
    let tun_c_dest: Ipv4Addr = "10.0.0.2".parse().unwrap();
    let tun_s_addr: Ipv4Addr = "10.0.1.1".parse().unwrap();
    let tun_s_dest: Ipv4Addr = "10.0.1.2".parse().unwrap();

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
    // (uses setns on a dedicated thread; must happen *before* we add routes
    //  so the tun interface exists when route add runs)
    let client_tuns = create_tun_in_netns(&ns_c, &tun_c_name, tun_c_addr, tun_c_dest);
    let server_tuns = create_tun_in_netns(&ns_s, &tun_s_name, tun_s_addr, tun_s_dest);

    // ── 5. Add cross-namespace routes ────────────────────────────────────────
    //  Client needs to reach the server's TUN subnet via the veth link.
    //  Server needs to reach the client's TUN subnet via the veth link.
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

    // ── 6. Enable IPv4 forwarding in each namespace ──────────────────────────
    netns_exec(&ns_c, "sysctl", &["-w", "net.ipv4.ip_forward=1"]);
    netns_exec(&ns_s, "sysctl", &["-w", "net.ipv4.ip_forward=1"]);

    // ── 7. Build Stack objects ───────────────────────────────────────────────
    // Client Stack: local_ip = tun peer address (10.0.0.2)
    // Server Stack: local_ip = tun own address  (10.0.1.1)
    let client_stack = Stack::new(client_tuns, tun_c_dest, None);
    let server_stack = Stack::new(server_tuns, tun_s_addr, None);

    TestEnv {
        client_stack,
        server_stack,
        ns_client: ns_c,
        ns_server: ns_s,
    }
}
