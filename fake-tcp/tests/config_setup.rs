#![cfg(feature = "integration-tests")]

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

const SERVER_PORT: u16 = 14323;
const TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// MSS accounting for 12 bytes of TCP timestamp options.
const BULK_CHUNK_SIZE: usize = 1448;
/// Total bytes for bulk transfer tests (1 MB).
const BULK_TOTAL_BYTES: usize = 1_048_576;
/// Timeout for bulk connect/accept.
const BULK_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Timeout for the 1 MB transfer.
const BULK_TRANSFER_TIMEOUT: Duration = Duration::from_secs(60);

/// Test: basic connect and data transfer with default config.
#[tokio::test]
async fn test_connect_and_send() {
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

    let payload = b"udp2raw fingerprint data";
    client_sock.send(payload).await.expect("client send failed");

    let mut buf = vec![0u8; 128];
    let n = timeout(TEST_TIMEOUT, server_sock.recv(&mut buf))
        .await
        .expect("server recv timed out")
        .expect("server recv returned None");
    assert_eq!(&buf[..n], payload as &[u8]);

    drop(client_sock);
    drop(server_sock);
    env.shutdown().await;
}

/// Test: bulk data transfer (1MB) through tunnel verifies throughput.
///
/// Requires `nf_conntrack_tcp_be_liberal=1` (set in `setup_test_env_with_config`)
/// to prevent Linux conntrack from dropping fake-TCP packets that don't follow
/// proper TCP sequence number rules.
#[tokio::test]
async fn test_bulk_transfer_1mb() {
    let mut env = common::setup_test_env().await;
    let server_addr: SocketAddr = format!("10.0.1.1:{SERVER_PORT}").parse().unwrap();
    env.server_stack.listen(SERVER_PORT);

    let (client_result, server_sock) = tokio::join!(
        timeout(TEST_TIMEOUT, env.client_stack.connect(server_addr)),
        timeout(TEST_TIMEOUT, env.server_stack.accept()),
    );

    let client_sock = Arc::new(
        client_result
            .expect("connect timed out")
            .expect("client connect returned None"),
    );
    let server_sock = Arc::new(server_sock.expect("accept timed out"));

    common::send_recv_loop(
        client_sock.clone(),
        server_sock.clone(),
        BULK_TOTAL_BYTES,
        BULK_CHUNK_SIZE,
        BULK_TRANSFER_TIMEOUT,
    )
    .await;

    drop(client_sock);
    drop(server_sock);
    env.shutdown().await;
}

/// Test: setup_test_env_with_config with 4 TUN queues connects and transfers data.
#[tokio::test]
async fn test_multi_queue_tun_connect_and_send() {
    let mut env = common::setup_test_env_with_config(4).await;
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

    let payload = b"multi-queue data transfer";
    client_sock.send(payload).await.expect("client send failed");

    let mut buf = vec![0u8; 128];
    let n = timeout(TEST_TIMEOUT, server_sock.recv(&mut buf))
        .await
        .expect("server recv timed out")
        .expect("server recv returned None");
    assert_eq!(&buf[..n], payload as &[u8]);

    drop(client_sock);
    drop(server_sock);
    env.shutdown().await;
}

/// Test: bulk transfer with 4 TUN queues.
#[tokio::test]
async fn test_bulk_transfer_multi_queue() {
    let mut env = common::setup_test_env_with_config(4).await;
    let server_addr: SocketAddr = format!("10.0.1.1:{SERVER_PORT}").parse().unwrap();
    env.server_stack.listen(SERVER_PORT);

    let (client_result, server_sock) = tokio::join!(
        timeout(BULK_CONNECT_TIMEOUT, env.client_stack.connect(server_addr)),
        timeout(BULK_CONNECT_TIMEOUT, env.server_stack.accept()),
    );

    let client_sock = Arc::new(
        client_result
            .expect("connect timed out")
            .expect("client connect returned None"),
    );
    let server_sock = Arc::new(server_sock.expect("accept timed out"));

    common::send_recv_loop(
        client_sock.clone(),
        server_sock.clone(),
        BULK_TOTAL_BYTES,
        BULK_CHUNK_SIZE,
        BULK_TRANSFER_TIMEOUT,
    )
    .await;

    drop(client_sock);
    drop(server_sock);
    env.shutdown().await;
}

/// Test: shutdown can be called multiple times without panicking.
#[tokio::test]
async fn test_shutdown_idempotent() {
    let mut env = common::setup_test_env().await;
    env.shutdown().await;
    env.shutdown().await; // second call should be a no-op
}
