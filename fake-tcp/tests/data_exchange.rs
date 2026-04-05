#![cfg(feature = "integration-tests")]

mod common;

use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::timeout;

const SERVER_PORT: u16 = 14322;
const TEST_TIMEOUT: Duration = Duration::from_secs(10);

// ── helpers ──────────────────────────────────────────────────────────────────

/// Perform the handshake and return (client_socket, server_socket, env).
///
/// The `TestEnv` must be kept alive for the duration of the test to prevent
/// premature namespace cleanup (its `Drop` impl deletes the namespaces).
async fn connected_pair() -> (fake_tcp::Socket, fake_tcp::Socket, common::TestEnv) {
    let mut env = common::setup_test_env().await;
    let server_addr: SocketAddr = format!("10.0.1.1:{SERVER_PORT}").parse().unwrap();
    env.server_stack.listen(SERVER_PORT);

    let (client_result, server_sock) = tokio::join!(
        timeout(TEST_TIMEOUT, env.client_stack.connect(server_addr)),
        timeout(TEST_TIMEOUT, env.server_stack.accept()),
    );

    let client_sock = client_result
        .expect("connect timed out")
        .expect("client connect returned None");
    let server_sock = server_sock.expect("accept timed out");

    (client_sock, server_sock, env)
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// Test: send data client → server, verify received correctly.
///
/// Verifies that a single payload sent by the client arrives at the server
/// intact, and that both sides are in Established state after the handshake.
#[tokio::test]
async fn test_send_client_to_server() {
    let (client_sock, server_sock, mut env) = connected_pair().await;

    let payload = b"hello from client";
    client_sock.send(payload).await.expect("client send failed");

    let mut buf = vec![0u8; 128];
    let n = timeout(TEST_TIMEOUT, server_sock.recv(&mut buf))
        .await
        .expect("server recv timed out")
        .expect("server recv returned None (unexpected RST)");

    assert_eq!(&buf[..n], payload as &[u8]);

    drop(client_sock);
    drop(server_sock);
    env.shutdown().await;
}

/// Test: send data server → client, verify received correctly.
///
/// Mirrors `test_send_client_to_server` in the reverse direction.
#[tokio::test]
async fn test_send_server_to_client() {
    let (client_sock, server_sock, mut env) = connected_pair().await;

    let payload = b"hello from server";
    server_sock.send(payload).await.expect("server send failed");

    let mut buf = vec![0u8; 128];
    let n = timeout(TEST_TIMEOUT, client_sock.recv(&mut buf))
        .await
        .expect("client recv timed out")
        .expect("client recv returned None (unexpected RST)");

    assert_eq!(&buf[..n], payload as &[u8]);

    drop(client_sock);
    drop(server_sock);
    env.shutdown().await;
}

/// Test: seq increments by payload.len() after each send.
///
/// Post-handshake, both sides have seq=1.  After sending a payload of length L,
/// the sender's seq becomes 1+L.  This test verifies that two consecutive sends
/// both deliver their payloads correctly.
///
/// Limitation: fake-tcp's receive path does not validate incoming seq values
/// (it routes by address tuple only), so this test would still pass even if
/// seq stopped incrementing.  Direct seq-on-the-wire verification would require
/// raw packet capture, which is deferred to wire-fingerprint tests.
#[tokio::test]
async fn test_seq_increments_by_payload_len() {
    let (client_sock, server_sock, mut env) = connected_pair().await;

    // Send two payloads of known sizes.
    // Post-handshake: client seq = 1.
    // After first send (16 bytes): client seq = 1 + 16 = 17.
    // After second send (15 bytes): client seq = 17 + 15 = 32.
    let first = b"seq-increment-1!"; // 16 bytes
    let second = b"seq-increment-2"; // 15 bytes

    client_sock.send(first).await.expect("first send failed");
    client_sock.send(second).await.expect("second send failed");

    let mut buf1 = vec![0u8; 128];
    let n1 = timeout(TEST_TIMEOUT, server_sock.recv(&mut buf1))
        .await
        .expect("first recv timed out")
        .expect("first recv returned None");
    assert_eq!(&buf1[..n1], first as &[u8], "first payload mismatch");

    let mut buf2 = vec![0u8; 128];
    let n2 = timeout(TEST_TIMEOUT, server_sock.recv(&mut buf2))
        .await
        .expect("second recv timed out")
        .expect("second recv returned None");
    assert_eq!(&buf2[..n2], second as &[u8], "second payload mismatch");

    drop(client_sock);
    drop(server_sock);
    env.shutdown().await;
}

/// Test: ack updates to remote_seq + payload.len() after recv.
///
/// When the server recvs a payload from the client, it sets its internal ack to
/// client_seq + payload.len().  The server then uses that ack value in its next
/// outgoing packet.  We verify this end-to-end by confirming the server can
/// recv then send a reply that the client receives correctly.
///
/// Limitation: fake-tcp's receive path does not enforce incoming ack values
/// (it only checks for RST), so a stale or incorrect ack would still be
/// accepted by the client.  This test confirms the recv-then-send flow works,
/// but would not catch a broken ack update.  Direct ack verification would
/// require raw packet capture.
#[tokio::test]
async fn test_ack_updates_after_recv() {
    let (client_sock, server_sock, mut env) = connected_pair().await;

    // Client sends; server recvs → server ack = 1 + payload.len().
    let payload = b"ack-update-test";
    client_sock.send(payload).await.expect("client send failed");

    let mut buf = vec![0u8; 128];
    let n = timeout(TEST_TIMEOUT, server_sock.recv(&mut buf))
        .await
        .expect("server recv timed out")
        .expect("server recv returned None");
    assert_eq!(&buf[..n], payload as &[u8], "server received wrong data");

    // Server sends back after having recv'd.  This confirms the server side
    // is operational after recv, but does not verify the ack value on the wire
    // (see doc comment above).
    let reply = b"ack-reply";
    server_sock.send(reply).await.expect("server send failed");

    let mut buf2 = vec![0u8; 128];
    let n2 = timeout(TEST_TIMEOUT, client_sock.recv(&mut buf2))
        .await
        .expect("client recv timed out")
        .expect("client recv returned None");
    assert_eq!(&buf2[..n2], reply as &[u8], "client received wrong reply");

    drop(client_sock);
    drop(server_sock);
    env.shutdown().await;
}

/// Test: multiple sequential sends accumulate seq correctly.
///
/// Sends five payloads of different sizes from client to server and verifies
/// that all are received in order with correct content.
///
/// Limitation: same as `test_seq_increments_by_payload_len` — payload delivery
/// does not depend on correct seq values in fake-tcp's current implementation,
/// so this test verifies data flow rather than seq arithmetic on the wire.
#[tokio::test]
async fn test_multiple_sequential_sends_accumulate_seq() {
    let (client_sock, server_sock, mut env) = connected_pair().await;

    let payloads: &[&[u8]] = &[
        b"first-payload",
        b"second",
        b"third-payload-longer",
        b"4",
        b"fifth-and-final-payload",
    ];

    // Send all payloads sequentially.
    for p in payloads {
        client_sock.send(p).await.expect("send failed");
    }

    // Receive and verify each one.
    for expected in payloads {
        let mut buf = vec![0u8; 256];
        let n = timeout(TEST_TIMEOUT, server_sock.recv(&mut buf))
            .await
            .expect("recv timed out")
            .expect("recv returned None");
        assert_eq!(&buf[..n], *expected, "payload mismatch");
    }

    drop(client_sock);
    drop(server_sock);
    env.shutdown().await;
}
