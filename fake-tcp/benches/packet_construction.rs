use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use fake_tcp::StealthLevel;
use fake_tcp::packet::build_tcp_packet;
use pnet::packet::tcp::TcpFlags;
use std::net::SocketAddr;

const PAYLOAD_SIZES: &[usize] = &[128, 512, 1460];

fn bench_stealth_level(c: &mut Criterion, group_name: &str, stealth: StealthLevel, flags: u8, ts_val: u32, ts_ecr: u32, window: u16) {
    let local: SocketAddr = "10.0.0.1:12345".parse().unwrap();
    let remote: SocketAddr = "10.0.0.2:80".parse().unwrap();

    let mut group = c.benchmark_group(group_name);
    for &size in PAYLOAD_SIZES {
        let payload = vec![0xABu8; size];
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                criterion::black_box(build_tcp_packet(
                    criterion::black_box(local),
                    criterion::black_box(remote),
                    1000,
                    2000,
                    flags,
                    Some(&payload),
                    stealth,
                    ts_val,
                    ts_ecr,
                    window,
                    None,
                ))
            });
        });
    }
    group.finish();
}

fn bench_stealth_off(c: &mut Criterion) {
    bench_stealth_level(c, "stealth_off", StealthLevel::Off, TcpFlags::ACK, 0, 0, 0xFFFF);
}

fn bench_stealth_basic(c: &mut Criterion) {
    bench_stealth_level(c, "stealth_basic", StealthLevel::Basic, TcpFlags::ACK | TcpFlags::PSH, 1000, 500, 0xFFFF);
}

fn bench_stealth_standard(c: &mut Criterion) {
    bench_stealth_level(c, "stealth_standard", StealthLevel::Standard, TcpFlags::ACK | TcpFlags::PSH, 5000, 3000, 29200);
}

fn bench_stealth_full(c: &mut Criterion) {
    bench_stealth_level(c, "stealth_full", StealthLevel::Full, TcpFlags::ACK | TcpFlags::PSH, 5000, 3000, 29200);
}

criterion_group!(benches, bench_stealth_off, bench_stealth_basic, bench_stealth_standard, bench_stealth_full);
criterion_main!(benches);
