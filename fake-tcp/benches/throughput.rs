use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use fake_tcp::testing::{setup_test_env_with_config, TestEnv};
use fake_tcp::Socket;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time::timeout;

const SERVER_PORT_BASE: u16 = 15000;
const TOTAL_BYTES: usize = 10_485_760; // 10 MB
// MSS accounting for 12 bytes of TCP timestamp options.
const CHUNK_SIZE: usize = 1448;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

const MAX_SETUP_RETRIES: usize = 10;

/// Establish N connections sequentially (connect/accept are &mut self).
async fn establish_connections(
    env: &mut TestEnv,
    n: usize,
    port_base: u16,
) -> Vec<(Arc<Socket>, Arc<Socket>)> {
    let mut pairs = Vec::with_capacity(n);
    for i in 0..n {
        let port = port_base + i as u16;
        env.server_stack.listen(port);
        let server_addr: SocketAddr = format!("10.0.1.1:{port}").parse().unwrap();

        let (client_result, server_sock) = tokio::join!(
            timeout(CONNECT_TIMEOUT, env.client_stack.connect(server_addr)),
            timeout(CONNECT_TIMEOUT, env.server_stack.accept()),
        );

        let client_sock = client_result
            .expect("connect timed out")
            .expect("client connect returned None");
        let server_sock = server_sock.expect("accept timed out");

        pairs.push((Arc::new(client_sock), Arc::new(server_sock)));
    }
    pairs
}

/// Spawn persistent drain tasks that continuously consume packets from
/// client sockets' incoming channels. This prevents the bounded channel
/// (capacity 512) from filling up and blocking the Stack reader task between
/// criterion iterations.
///
/// Returns join handles that run until the client sockets are dropped.
fn spawn_drain_tasks(
    rt: &tokio::runtime::Runtime,
    pairs: &[(Arc<Socket>, Arc<Socket>)],
) -> Vec<JoinHandle<()>> {
    pairs
        .iter()
        .map(|(client, _)| {
            let client = Arc::clone(client);
            rt.spawn(async move {
                let mut buf = vec![0u8; CHUNK_SIZE + 100];
                // Loop until recv returns None (channel closed on Socket drop)
                while client.recv(&mut buf).await.is_some() {}
            })
        })
        .collect()
}

/// Send `total_bytes` from client to server using concurrent send+recv.
async fn send_recv_loop(client: Arc<Socket>, server: Arc<Socket>, total_bytes: usize) {
    const TRANSFER_TIMEOUT: Duration = Duration::from_secs(120);

    let sender = {
        let client = Arc::clone(&client);
        tokio::spawn(async move {
            let chunk = vec![0xABu8; CHUNK_SIZE];
            let mut sent = 0;
            while sent < total_bytes {
                let to_send = std::cmp::min(CHUNK_SIZE, total_bytes - sent);
                client.send(&chunk[..to_send]).await.expect("send failed");
                sent += to_send;
            }
        })
    };

    let receiver = {
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            let mut received = 0;
            let mut buf = vec![0u8; CHUNK_SIZE + 100];
            while received < total_bytes {
                let n = server.recv(&mut buf).await.expect("recv returned None");
                assert!(n > 0, "recv returned 0 bytes — connection may be closed");
                received += n;
            }
        })
    };

    timeout(TRANSFER_TIMEOUT, async {
        sender.await.expect("sender panicked");
        receiver.await.expect("receiver panicked");
    })
    .await
    .expect("send_recv_loop timed out — possible deadlock or resource exhaustion");
}

fn bench_throughput(c: &mut Criterion) {
    let core_counts: &[(usize, usize, &str)] = &[(2, 1, "1core"), (4, 4, "4core")];

    for &(worker_threads, tun_queues, core_label) in core_counts {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(worker_threads)
            .enable_all()
            .build()
            .expect("failed to build tokio runtime");

        let mut group = c.benchmark_group(format!("throughput/{core_label}"));
        group.measurement_time(Duration::from_secs(60));
        group.sample_size(10);

        let num_connections = if tun_queues > 1 { tun_queues * 4 } else { 1 };
        let bytes_per_connection = TOTAL_BYTES / num_connections;

        let (mut env, pairs) = rt.block_on(async {
            for attempt in 0..MAX_SETUP_RETRIES {
                let mut env = setup_test_env_with_config(tun_queues).await;
                let pairs = establish_connections(
                    &mut env,
                    num_connections,
                    SERVER_PORT_BASE,
                )
                .await;

                if tun_queues <= 1 {
                    return (env, pairs);
                }

                let client_queues: HashSet<usize> =
                    pairs.iter().map(|(c, _)| c.tun_queue_id()).collect();
                let server_queues: HashSet<usize> =
                    pairs.iter().map(|(_, s)| s.tun_queue_id()).collect();
                if client_queues.len() >= tun_queues && server_queues.len() >= tun_queues {
                    return (env, pairs);
                }

                eprintln!(
                    "Queue coverage client={}/{} server={}/{} on attempt {}, retrying setup...",
                    client_queues.len(),
                    tun_queues,
                    server_queues.len(),
                    tun_queues,
                    attempt + 1,
                );
                drop(pairs);
                env.shutdown().await;
            }
            panic!(
                "Failed to achieve full TUN queue coverage after {} attempts",
                MAX_SETUP_RETRIES,
            );
        });

        let drain_handles = spawn_drain_tasks(&rt, &pairs);

        group.bench_with_input(
            BenchmarkId::from_parameter(core_label),
            &core_label,
            |b, _| {
                b.iter(|| {
                    rt.block_on(async {
                        let mut set = tokio::task::JoinSet::new();
                        for (client, server) in &pairs {
                            let client = Arc::clone(client);
                            let server = Arc::clone(server);
                            let bytes = bytes_per_connection;
                            set.spawn(async move {
                                send_recv_loop(client, server, bytes).await;
                            });
                        }
                        while let Some(result) = set.join_next().await {
                            result.expect("send_recv task panicked");
                        }
                    });
                });
            },
        );

        drop(pairs);
        for handle in drain_handles {
            rt.block_on(handle).ok();
        }
        rt.block_on(env.shutdown());

        group.finish();
    }
}

criterion_group!(benches, bench_throughput);
criterion_main!(benches);
