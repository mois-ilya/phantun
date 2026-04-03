#![cfg(feature = "integration-tests")]

mod common;

use bytes::BytesMut;
use fake_tcp::packet::{build_tcp_packet, parse_ip_packet};
use pnet::packet::tcp;
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
}

/// Test: server rejects SYN with seq != 0 (current behavior snapshot).
///
/// The server must respond with RST|ACK when the SYN sequence number is
/// non-zero.  This is verified by injecting a hand-crafted SYN packet via
/// the raw client TUN and reading back the response.
#[tokio::test]
async fn test_server_rejects_nonzero_seq_syn() {
    let mut env = common::setup_test_env().await;
    env.server_stack.listen(SERVER_PORT);

    // Craft a SYN with seq=1 (non-zero).
    // src: 10.0.2.2 — the peer address of the raw TUN; responses come back here.
    // dst: 10.0.1.1 — the server's Stack local_ip.
    let crafted_src: SocketAddr = "10.0.2.2:54321".parse().unwrap();
    let crafted_dst: SocketAddr = format!("10.0.1.1:{SERVER_PORT}").parse().unwrap();
    let syn_seq: u32 = 1; // non-zero → server must reject

    let syn_pkt = build_tcp_packet(crafted_src, crafted_dst, syn_seq, 0, tcp::TcpFlags::SYN, None);
    env.raw_client_tun
        .send(&syn_pkt)
        .await
        .expect("raw TUN send failed");

    // Read back the RST|ACK.  Filter out any non-TCP noise (shouldn't be any
    // in an isolated namespace, but guard anyway).
    let mut buf = BytesMut::zeroed(1500);
    let n = timeout(TEST_TIMEOUT, env.raw_client_tun.recv(&mut buf))
        .await
        .expect("raw TUN recv timed out — server did not reply")
        .expect("raw TUN recv error");
    buf.truncate(n);
    let frozen = buf.freeze();

    let (_ip, tcp_pkt) =
        parse_ip_packet(&frozen).expect("server reply is not a valid IP/TCP packet");

    assert_eq!(
        tcp_pkt.get_flags(),
        tcp::TcpFlags::RST | tcp::TcpFlags::ACK,
        "server must respond with RST|ACK to SYN with non-zero seq"
    );
    // ack = syn_seq + 1 (SYN consumes one sequence number)
    assert_eq!(
        tcp_pkt.get_acknowledgement(),
        syn_seq + 1,
        "RST ack field must equal SYN seq + 1"
    );
    // The RST is addressed back to our crafted source port.
    assert_eq!(
        tcp_pkt.get_destination(),
        54321,
        "RST destination port must match the crafted SYN source port"
    );
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
}
