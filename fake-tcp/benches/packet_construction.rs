use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use fake_tcp::packet::build_tcp_packet;
use pnet::packet::tcp::TcpFlags;
use std::net::SocketAddr;

const PAYLOAD_SIZES: &[usize] = &[128, 512, 1460];

fn bench_packet_construction(c: &mut Criterion) {
    let local: SocketAddr = "10.0.0.1:12345".parse().unwrap();
    let remote: SocketAddr = "10.0.0.2:80".parse().unwrap();

    let mut group = c.benchmark_group("packet_construction");
    for &size in PAYLOAD_SIZES {
        let payload = vec![0xABu8; size];
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                criterion::black_box(build_tcp_packet(
                    criterion::black_box(local),
                    criterion::black_box(remote),
                    1000,
                    2000,
                    TcpFlags::PSH | TcpFlags::ACK,
                    Some(&payload),
                    5000,
                    3000,
                    29200,
                ))
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_packet_construction);
criterion_main!(benches);
