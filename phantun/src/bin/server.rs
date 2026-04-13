use clap::{crate_version, Arg, ArgAction, Command};
use fake_tcp::packet::MAX_PACKET_LEN;
use fake_tcp::Stack;
use log::{debug, error, info, trace};
use phantun::utils::{assign_ipv6_address, new_udp_reuseport};
use phantun::wire::{Incoming, HEARTBEAT_INTERVAL, HEARTBEAT_SIZE, classify_incoming, encode_payload};
use phantun::xor;
use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio::time;
use tokio_tun::TunBuilder;
use tokio_util::sync::CancellationToken;

use phantun::UDP_TTL;

#[tokio::main]
async fn main() -> io::Result<()> {
    pretty_env_logger::init();

    let matches = Command::new("Phantun Server")
        .version(crate_version!())
        .author("Datong Sun (github.com/dndx)")
        .arg(
            Arg::new("local")
                .short('l')
                .long("local")
                .required(true)
                .value_name("PORT")
                .help("Sets the port where Phantun Server listens for incoming Phantun Client TCP connections")
        )
        .arg(
            Arg::new("remote")
                .short('r')
                .long("remote")
                .required(true)
                .value_name("IP or HOST NAME:PORT")
                .help("Sets the address or host name and port where Phantun Server forwards UDP packets to, IPv6 address need to be specified as: \"[IPv6]:PORT\"")
        )
        .arg(
            Arg::new("tun")
                .long("tun")
                .required(false)
                .value_name("tunX")
                .help("Sets the Tun interface name, if absent, pick the next available name")
                .default_value("")
        )
        .arg(
            Arg::new("tun_local")
                .long("tun-local")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface local address (O/S's end)")
                .default_value("192.168.201.1")
        )
        .arg(
            Arg::new("tun_peer")
                .long("tun-peer")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface destination (peer) address (Phantun Server's end). \
                       You will need to setup DNAT rules to this address in order for Phantun Server \
                       to accept TCP traffic from Phantun Client")
                .default_value("192.168.201.2")
        )
        .arg(
            Arg::new("ipv4_only")
                .long("ipv4-only")
                .short('4')
                .required(false)
                .help("Do not assign IPv6 addresses to Tun interface")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["tun_local6", "tun_peer6"]),
        )
        .arg(
            Arg::new("tun_local6")
                .long("tun-local6")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv6 local address (O/S's end)")
                .default_value("fcc9::1")
        )
        .arg(
            Arg::new("tun_peer6")
                .long("tun-peer6")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv6 destination (peer) address (Phantun Client's end). \
                       You will need to setup SNAT/MASQUERADE rules on your Internet facing interface \
                       in order for Phantun Client to connect to Phantun Server")
                .default_value("fcc9::2")
        )
        .arg(
            Arg::new("handshake_packet")
                .long("handshake-packet")
                .required(false)
                .value_name("PATH")
                .help("Specify a file, which, after TCP handshake, its content will be sent as the \
                      first data packet to the client.\n\
                      Note: ensure this file's size does not exceed the MTU of the outgoing interface. \
                      The content is always sent out in a single packet and will not be further segmented")
        )
        .arg(
            Arg::new("key")
                .long("key")
                .required(false)
                .value_name("KEY")
                .help("XOR obfuscation key (must match client). If omitted, payload is sent as-is.")
        )
        .get_matches();

    let local_port: u16 = matches
        .get_one::<String>("local")
        .unwrap()
        .parse()
        .expect("bad local port");

    let remote_addr = tokio::net::lookup_host(matches.get_one::<String>("remote").unwrap())
        .await
        .expect("bad remote address or host")
        .next()
        .expect("unable to resolve remote host name");

    info!("Remote address is: {}", remote_addr);

    let tun_local: Ipv4Addr = matches
        .get_one::<String>("tun_local")
        .unwrap()
        .parse()
        .expect("bad local address for Tun interface");
    let tun_peer: Ipv4Addr = matches
        .get_one::<String>("tun_peer")
        .unwrap()
        .parse()
        .expect("bad peer address for Tun interface");

    let (tun_local6, tun_peer6) = if matches.get_flag("ipv4_only") {
        (None, None)
    } else {
        (
            matches
                .get_one::<String>("tun_local6")
                .map(|v| v.parse().expect("bad local address for Tun interface")),
            matches
                .get_one::<String>("tun_peer6")
                .map(|v| v.parse().expect("bad peer address for Tun interface")),
        )
    };

    let tun_name = matches.get_one::<String>("tun").unwrap();
    let handshake_packet: Option<Vec<u8>> = matches
        .get_one::<String>("handshake_packet")
        .map(fs::read)
        .transpose()?;

    let key: Option<Arc<Vec<u8>>> = match matches.get_one::<String>("key") {
        Some(k) if k.is_empty() => {
            eprintln!("--key must not be empty");
            std::process::exit(2);
        }
        Some(k) => Some(Arc::new(k.as_bytes().to_vec())),
        None => None,
    };

    let num_cpus = num_cpus::get();
    info!("{} cores available", num_cpus);

    let tun = TunBuilder::new()
        .name(tun_name) // if name is empty, then it is set by kernel.
        .up() // or set it up manually using `sudo ip link set <tun-name> up`.
        .address(tun_local)
        .destination(tun_peer)
        .queues(num_cpus)
        .build()
        .unwrap();

    if let (Some(tun_local6), Some(tun_peer6)) = (tun_local6, tun_peer6) {
        assign_ipv6_address(tun[0].name(), tun_local6, tun_peer6);
    }

    info!("Created TUN device {}", tun[0].name());

    //thread::sleep(time::Duration::from_secs(5));
    let mut stack = Stack::new(tun, tun_local, tun_local6);
    stack.listen(local_port);
    info!("Listening on {}", local_port);

    let main_loop = tokio::spawn(async move {
        let mut buf_udp = [0u8; MAX_PACKET_LEN];
        // buf_tcp must fit an encoded packet: payload (up to MAX_PACKET_LEN) + xor::OVERHEAD
        let mut buf_tcp = [0u8; MAX_PACKET_LEN + xor::OVERHEAD];

        loop {
            let sock = Arc::new(stack.accept().await);
            info!("New connection: {}", sock);
            if let Some(ref p) = handshake_packet {
                // When --key is set the peer classifies every inbound TCP payload
                // through the XOR envelope, so a plaintext handshake packet would
                // be dropped as DecodeFailed. Pass the handshake through the same
                // encoder: the disguise value is lost (peer already expects XOR)
                // but the feature remains functional.
                let encoded = encode_payload(&key, p);
                if sock.send(encoded.as_ref()).await.is_none() {
                    error!("Failed to send handshake packet to remote, closing connection.");
                    continue;
                }

                debug!("Sent handshake packet to: {}", sock);
            }

            let packet_received = Arc::new(Notify::new());
            let quit = CancellationToken::new();
            let udp_sock = UdpSocket::bind(if remote_addr.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            })
            .await?;
            let local_addr = udp_sock.local_addr()?;
            drop(udp_sock);

            for i in 0..num_cpus {
                let sock = sock.clone();
                let quit = quit.clone();
                let packet_received = packet_received.clone();
                let udp_sock = new_udp_reuseport(local_addr);
                let key = key.clone();

                tokio::spawn(async move {
                    udp_sock.connect(remote_addr).await.unwrap();

                    loop {
                        tokio::select! {
                            Ok(size) = udp_sock.recv(&mut buf_udp) => {
                                let payload = encode_payload(&key, &buf_udp[..size]);
                                if sock.send(payload.as_ref()).await.is_none() {
                                    quit.cancel();
                                    return;
                                }

                                packet_received.notify_one();
                            },
                            res = sock.recv(&mut buf_tcp) => {
                                match res {
                                    Some(size) => {
                                        if size > 0 {
                                            match classify_incoming(&key, &buf_tcp[..size]) {
                                                Incoming::Data(decoded) => {
                                                    if let Err(e) = udp_sock.send(decoded.as_ref()).await {
                                                        error!("Unable to send UDP packet to {}: {}, closing connection", e, remote_addr);
                                                        quit.cancel();
                                                        return;
                                                    }
                                                    // Only real data resets the UDP_TTL idle timer;
                                                    // heartbeats must not mask a vanished UDP peer.
                                                    packet_received.notify_one();
                                                }
                                                Incoming::Heartbeat => {}
                                                Incoming::DecodeFailed => {
                                                    trace!("xor decode failed for {} bytes (key mismatch?)", size);
                                                }
                                            }
                                        }
                                    },
                                    None => {
                                        quit.cancel();
                                        return;
                                    },
                                }
                            },
                            _ = quit.cancelled() => {
                                debug!("worker {} terminated", i);
                                return;
                            },
                        };
                    }
                });
            }

            // heartbeat task — only when XOR key is set (without key, receiver
            // cannot distinguish heartbeat filler from real UDP payload)
            if let Some(k) = key.as_ref() {
                let sock_hb = sock.clone();
                let quit_hb = quit.clone();
                let key_hb: Arc<Vec<u8>> = k.clone();
                tokio::spawn(async move {
                    let mut interval = time::interval(HEARTBEAT_INTERVAL);
                    // skip the immediate first tick — no point beating right after connect
                    interval.tick().await;
                    loop {
                        tokio::select! {
                            _ = interval.tick() => {
                                let hb = xor::encode_heartbeat(&key_hb, HEARTBEAT_SIZE);
                                if sock_hb.send(&hb).await.is_none() {
                                    quit_hb.cancel();
                                    return;
                                }
                            },
                            _ = quit_hb.cancelled() => {
                                return;
                            },
                        }
                    }
                });
            }

            tokio::spawn(async move {
                loop {
                    let read_timeout = time::sleep(UDP_TTL);
                    let packet_received_fut = packet_received.notified();

                    tokio::select! {
                        _ = read_timeout => {
                            info!("No traffic seen in the last {:?}, closing connection", UDP_TTL);

                            quit.cancel();
                            return;
                        },
                        _ = quit.cancelled() => {
                            return;
                        },
                        _ = packet_received_fut => {},
                    }
                }
            });
        }
    });

    tokio::join!(main_loop).0.unwrap()
}
