#![cfg(feature = "integration-tests")]

mod common;

use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::timeout;

const SERVER_PORT: u16 = 14321;
const TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Test: client connect + server accept → both sockets reach Established state.
///
/// Verified by sending a payload through the connection after the handshake.
#[tokio::test]
async fn test_connect_accept_established() {
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

    // Confirm both sides are Established by exchanging data.
    let payload = b"established";
    client_sock.send(payload).await.expect("send failed");

    let mut buf = vec![0u8; 64];
    let n = timeout(TEST_TIMEOUT, server_sock.recv(&mut buf))
        .await
        .expect("recv timed out")
        .expect("recv returned None (unexpected RST)");

    assert_eq!(&buf[..n], payload as &[u8]);

    drop(client_sock);
    drop(server_sock);
    env.shutdown().await;
}

/// Test: dropping a Socket sends RST to the peer.
///
/// After the handshake, dropping the client socket must cause the server's
/// next recv() to return None (RST received).
#[tokio::test]
async fn test_rst_on_socket_drop() {
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

    // Drop the client socket — Socket::drop() sends RST via try_send.
    drop(client_sock);

    // The server's recv should return None once the RST arrives.
    let mut buf = vec![0u8; 64];
    let result = timeout(TEST_TIMEOUT, server_sock.recv(&mut buf))
        .await
        .expect("server recv timed out waiting for RST notification");

    assert!(
        result.is_none(),
        "expected recv to return None after client RST, got Some"
    );

    drop(server_sock);
    env.shutdown().await;
}
