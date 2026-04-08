use bytes::{Bytes, BytesMut};
use internet_checksum::Checksum;
use pnet::packet::{MutablePacket, Packet};
use pnet::packet::{ip, ipv4, ipv6, tcp};
use std::convert::TryInto;
use std::net::{IpAddr, SocketAddr};
use std::sync::{OnceLock, atomic::{AtomicU16, Ordering}};

/// Global IP ID counter, initialized to a random value on first use.
/// Matches udp2raw behavior: single global counter, random seed, monotonically
/// incrementing per packet (network.cpp:36, 374, 1184).
static IP_ID_COUNTER: OnceLock<AtomicU16> = OnceLock::new();

fn next_ip_id() -> u16 {
    IP_ID_COUNTER
        .get_or_init(|| AtomicU16::new(rand::random::<u16>()))
        .fetch_add(1, Ordering::Relaxed)
}

const IPV4_HEADER_LEN: usize = 20;
/// Window scale shift count matching udp2raw (network.cpp wscale=5).
pub const WSCALE: u8 = 5;
const IPV6_HEADER_LEN: usize = 40;
const TCP_HEADER_LEN: usize = 20;
pub const MAX_PACKET_LEN: usize = 1500;

pub enum IPPacket<'p> {
    V4(ipv4::Ipv4Packet<'p>),
    V6(ipv6::Ipv6Packet<'p>),
}

impl IPPacket<'_> {
    pub fn get_source(&self) -> IpAddr {
        match self {
            IPPacket::V4(p) => IpAddr::V4(p.get_source()),
            IPPacket::V6(p) => IpAddr::V6(p.get_source()),
        }
    }

    pub fn get_destination(&self) -> IpAddr {
        match self {
            IPPacket::V4(p) => IpAddr::V4(p.get_destination()),
            IPPacket::V6(p) => IpAddr::V6(p.get_destination()),
        }
    }
}

/// Build a TCP/IP packet with the udp2raw fingerprint hardcoded:
/// - SYN options: MSS(1460) + SACK_PERM + Timestamps + NOP + WScale(5) = 20 bytes
/// - Non-SYN options: NOP + NOP + Timestamps = 12 bytes
/// - DF flag always set, TTL=64
#[allow(clippy::too_many_arguments)]
pub fn build_tcp_packet(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: Option<&[u8]>,
    ts_val: u32,
    ts_ecr: u32,
    window: u16,
) -> Bytes {
    let ip_header_len = match local_addr {
        SocketAddr::V4(_) => IPV4_HEADER_LEN,
        SocketAddr::V6(_) => IPV6_HEADER_LEN,
    };
    let is_syn = (flags & tcp::TcpFlags::SYN) != 0;
    let tcp_options_len = if is_syn {
        20 // MSS(4) + SACK_PERM(2)+TS_hdr(2) + TS_val(4) + TS_ecr(4) + NOP(1)+wscale(3)
    } else {
        12 // NOP(1) + NOP(1) + TS(10)
    };
    let tcp_header_len = TCP_HEADER_LEN + tcp_options_len;
    let tcp_total_len = tcp_header_len + payload.map_or(0, |payload| payload.len());
    let total_len = ip_header_len + tcp_total_len;
    let mut buf = BytesMut::zeroed(total_len);

    let mut ip_buf = buf.split_to(ip_header_len);
    let mut tcp_buf = buf.split_to(tcp_total_len);
    assert_eq!(0, buf.len());

    match (local_addr, remote_addr) {
        (SocketAddr::V4(local), SocketAddr::V4(remote)) => {
            let mut v4 = ipv4::MutableIpv4Packet::new(&mut ip_buf).unwrap();
            v4.set_version(4);
            v4.set_header_length(IPV4_HEADER_LEN as u8 / 4);
            v4.set_next_level_protocol(ip::IpNextHeaderProtocols::Tcp);
            v4.set_ttl(64);
            v4.set_source(*local.ip());
            v4.set_destination(*remote.ip());
            v4.set_total_length(total_len.try_into().unwrap());
            v4.set_flags(ipv4::Ipv4Flags::DontFragment);
            v4.set_identification(next_ip_id());
            let mut cksm = Checksum::new();
            cksm.add_bytes(v4.packet());
            v4.set_checksum(u16::from_be_bytes(cksm.checksum()));
        }
        (SocketAddr::V6(local), SocketAddr::V6(remote)) => {
            let mut v6 = ipv6::MutableIpv6Packet::new(&mut ip_buf).unwrap();
            v6.set_version(6);
            v6.set_payload_length(tcp_total_len.try_into().unwrap());
            v6.set_next_header(ip::IpNextHeaderProtocols::Tcp);
            v6.set_hop_limit(64);
            v6.set_source(*local.ip());
            v6.set_destination(*remote.ip());
        }
        _ => unreachable!(),
    };

    let mut tcp = tcp::MutableTcpPacket::new(&mut tcp_buf).unwrap();
    tcp.set_window(window);
    tcp.set_source(local_addr.port());
    tcp.set_destination(remote_addr.port());
    tcp.set_sequence(seq);
    tcp.set_acknowledgement(ack);
    tcp.set_flags(flags);
    tcp.set_data_offset((tcp_header_len / 4) as u8);

    if is_syn {
        // Linux 5.x SYN fingerprint (compact layout from tcp_options_write):
        // MSS(4) + SACK_PERM(2)+TS_hdr(2) + TS_val(4) + TS_ecr(4) + NOP+WS(4) = 20 bytes
        // The kernel packs SACK_PERM as padding before the Timestamps option.
        let pkt = tcp.packet_mut();
        let opts = &mut pkt[TCP_HEADER_LEN..tcp_header_len];
        // MSS: kind=2, len=4, value=1460 (0x05B4)
        opts[0] = 2;
        opts[1] = 4;
        opts[2] = 0x05;
        opts[3] = 0xB4;
        // SACK permitted (kind=4, len=2) + Timestamps header (kind=8, len=10)
        opts[4] = 4;
        opts[5] = 2;
        opts[6] = 8;
        opts[7] = 10;
        // Timestamps: tsval, tsecr
        opts[8..12].copy_from_slice(&ts_val.to_be_bytes());
        opts[12..16].copy_from_slice(&ts_ecr.to_be_bytes());
        // NOP + Window scale: kind=3, len=3, shift=5
        opts[16] = 1;
        opts[17] = 3;
        opts[18] = 3;
        opts[19] = WSCALE;
    } else {
        // Non-SYN packets: NOP + NOP + Timestamps (12 bytes, doff=8)
        let pkt = tcp.packet_mut();
        let opts = &mut pkt[TCP_HEADER_LEN..tcp_header_len];
        opts[0] = 1; // NOP
        opts[1] = 1; // NOP
        opts[2] = 8; // Timestamps kind
        opts[3] = 10; // Timestamps len
        opts[4..8].copy_from_slice(&ts_val.to_be_bytes());
        opts[8..12].copy_from_slice(&ts_ecr.to_be_bytes());
    }

    if let Some(payload) = payload {
        tcp.set_payload(payload);
    }

    let mut cksm = Checksum::new();
    let ip::IpNextHeaderProtocol(tcp_protocol) = ip::IpNextHeaderProtocols::Tcp;

    match (local_addr, remote_addr) {
        (SocketAddr::V4(local), SocketAddr::V4(remote)) => {
            cksm.add_bytes(&local.ip().octets());
            cksm.add_bytes(&remote.ip().octets());

            let mut pseudo = [0u8, tcp_protocol, 0, 0];
            pseudo[2..].copy_from_slice(&(tcp_total_len as u16).to_be_bytes());
            cksm.add_bytes(&pseudo);
        }
        (SocketAddr::V6(local), SocketAddr::V6(remote)) => {
            cksm.add_bytes(&local.ip().octets());
            cksm.add_bytes(&remote.ip().octets());

            let mut pseudo = [0u8, 0, 0, 0, 0, 0, 0, tcp_protocol];
            pseudo[0..4].copy_from_slice(&(tcp_total_len as u32).to_be_bytes());
            cksm.add_bytes(&pseudo);
        }
        _ => unreachable!(),
    };

    cksm.add_bytes(tcp.packet());
    tcp.set_checksum(u16::from_be_bytes(cksm.checksum()));

    ip_buf.unsplit(tcp_buf);
    ip_buf.freeze()
}

/// Parse both TSval and TSecr from TCP timestamp option.
/// Returns `Some((tsval, tsecr))` if a valid timestamp option is found.
pub fn parse_tcp_timestamps(tcp_packet: &tcp::TcpPacket<'_>) -> Option<(u32, u32)> {
    let opts = tcp_packet.get_options_raw();
    let mut i = 0;
    while i < opts.len() {
        match opts[i] {
            0 => break,
            1 => i += 1,
            8 if i + 9 < opts.len() && opts[i + 1] == 10 => {
                let tsval = u32::from_be_bytes([opts[i + 2], opts[i + 3], opts[i + 4], opts[i + 5]]);
                let tsecr = u32::from_be_bytes([opts[i + 6], opts[i + 7], opts[i + 8], opts[i + 9]]);
                return Some((tsval, tsecr));
            }
            _ => {
                if i + 1 >= opts.len() {
                    break;
                }
                let len = opts[i + 1] as usize;
                if len < 2 {
                    break;
                }
                i += len;
                continue;
            }
        }
    }
    None
}

pub fn parse_ip_packet(buf: &Bytes) -> Option<(IPPacket<'_>, tcp::TcpPacket<'_>)> {
    let version = (*buf.first()?) >> 4;
    if version == 4 {
        let v4 = ipv4::Ipv4Packet::new(buf)?;
        if v4.get_next_level_protocol() != ip::IpNextHeaderProtocols::Tcp {
            return None;
        }

        let tcp = tcp::TcpPacket::new(buf.get(IPV4_HEADER_LEN..)?)?;
        Some((IPPacket::V4(v4), tcp))
    } else if version == 6 {
        let v6 = ipv6::Ipv6Packet::new(buf)?;
        if v6.get_next_header() != ip::IpNextHeaderProtocols::Tcp {
            return None;
        }

        let tcp = tcp::TcpPacket::new(buf.get(IPV6_HEADER_LEN..)?)?;
        Some((IPPacket::V6(v6), tcp))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use internet_checksum::Checksum;
    use pnet::packet::{ip, ipv4, ipv6, tcp};

    fn ipv4_syn_packet() -> Bytes {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        build_tcp_packet(local, remote, 0, 0, tcp::TcpFlags::SYN, None, 0, 0, 0xFFFF)
    }

    fn ipv6_syn_packet() -> Bytes {
        let local: SocketAddr = "[fd00::1]:1234".parse().unwrap();
        let remote: SocketAddr = "[fd00::2]:5678".parse().unwrap();
        build_tcp_packet(local, remote, 0, 0, tcp::TcpFlags::SYN, None, 0, 0, 0xFFFF)
    }

    #[test]
    fn test_ipv4_syn_total_length() {
        let pkt = ipv4_syn_packet();
        // 20 (IPv4 header) + 40 (TCP: 20 base + 20 options) = 60
        assert_eq!(pkt.len(), 60);
    }

    #[test]
    fn test_ipv4_syn_ip_header_fields() {
        let pkt = ipv4_syn_packet();
        let v4 = ipv4::Ipv4Packet::new(&pkt).unwrap();
        assert_eq!(v4.get_version(), 4);
        assert_eq!(v4.get_next_level_protocol(), ip::IpNextHeaderProtocols::Tcp);
        assert_eq!(v4.get_ttl(), 64);
        assert_eq!(v4.get_flags(), ipv4::Ipv4Flags::DontFragment);
        assert_eq!(v4.get_total_length() as usize, 60);
    }

    #[test]
    fn test_ipv4_syn_tcp_flags_doff_window() {
        let pkt = ipv4_syn_packet();
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.get_flags(), tcp::TcpFlags::SYN);
        assert_eq!(tcp_pkt.get_data_offset(), 10, "doff=10 means 40-byte TCP header");
        assert_eq!(tcp_pkt.get_window(), 0xFFFF);
    }

    #[test]
    fn test_ipv4_syn_tcp_options_layout() {
        let pkt = ipv4_syn_packet();
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let opts = tcp_pkt.get_options_raw();
        assert_eq!(opts.len(), 20, "SYN options: MSS(4)+SACK(2)+TS_hdr(2)+TS(8)+NOP+WS(4) = 20 bytes");
        // MSS
        assert_eq!(opts[0], 2, "MSS kind");
        assert_eq!(opts[1], 4, "MSS len");
        assert_eq!(u16::from_be_bytes([opts[2], opts[3]]), 1460, "MSS value=1460");
        // SACK_PERM
        assert_eq!(opts[4], 4, "SACK_PERM kind");
        assert_eq!(opts[5], 2, "SACK_PERM len");
        // Timestamps header
        assert_eq!(opts[6], 8, "TS kind");
        assert_eq!(opts[7], 10, "TS len");
        // NOP + wscale=5
        assert_eq!(opts[16], 1, "NOP before wscale");
        assert_eq!(opts[17], 3, "wscale kind");
        assert_eq!(opts[18], 3, "wscale len");
        assert_eq!(opts[19], 5, "wscale shift=5");
    }

    #[test]
    fn test_ipv4_syn_seq_ack_match_input() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let seq = 0x12345678u32;
        let ack = 0x87654321u32;
        let pkt = build_tcp_packet(local, remote, seq, ack, tcp::TcpFlags::SYN, None, 0, 0, 0xFFFF);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.get_sequence(), seq);
        assert_eq!(tcp_pkt.get_acknowledgement(), ack);
    }

    #[test]
    fn test_ipv4_syn_checksum_valid() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let pkt = build_tcp_packet(local, remote, 0, 0, tcp::TcpFlags::SYN, None, 0, 0, 0xFFFF);

        // Verify IPv4 header checksum
        let v4 = ipv4::Ipv4Packet::new(&pkt).unwrap();
        let stored_ip_cksm = v4.get_checksum();
        let mut ip_hdr = pkt[..20].to_vec();
        ip_hdr[10] = 0;
        ip_hdr[11] = 0;
        let mut cksm = Checksum::new();
        cksm.add_bytes(&ip_hdr);
        assert_eq!(stored_ip_cksm, u16::from_be_bytes(cksm.checksum()));

        // Verify TCP checksum via IPv4 pseudo-header
        let stored_tcp_cksm = tcp::TcpPacket::new(&pkt[20..]).unwrap().get_checksum();
        let tcp_len = pkt.len() - 20;
        let mut tcp_bytes = pkt[20..].to_vec();
        tcp_bytes[16] = 0;
        tcp_bytes[17] = 0;
        let ip::IpNextHeaderProtocol(proto) = ip::IpNextHeaderProtocols::Tcp;
        let mut cksm = Checksum::new();
        cksm.add_bytes(&[10, 0, 0, 1]); // src IP
        cksm.add_bytes(&[10, 0, 0, 2]); // dst IP
        cksm.add_bytes(&[0, proto, (tcp_len >> 8) as u8, (tcp_len & 0xFF) as u8]);
        cksm.add_bytes(&tcp_bytes);
        assert_eq!(stored_tcp_cksm, u16::from_be_bytes(cksm.checksum()));
    }

    #[test]
    fn test_ipv6_syn_total_length() {
        let pkt = ipv6_syn_packet();
        // 40 (IPv6 header) + 40 (TCP header with options) = 80
        assert_eq!(pkt.len(), 80);
    }

    #[test]
    fn test_ipv6_syn_ip_header_fields() {
        let pkt = ipv6_syn_packet();
        let v6 = ipv6::Ipv6Packet::new(&pkt).unwrap();
        assert_eq!(v6.get_version(), 6);
        assert_eq!(v6.get_next_header(), ip::IpNextHeaderProtocols::Tcp);
        assert_eq!(v6.get_hop_limit(), 64);
        assert_eq!(v6.get_payload_length() as usize, 40, "payload_length = TCP header with options");
    }

    #[test]
    fn test_ipv6_syn_tcp_flags_doff_window_options() {
        let local: SocketAddr = "[fd00::1]:9000".parse().unwrap();
        let remote: SocketAddr = "[fd00::2]:9001".parse().unwrap();
        let seq = 0xABCDu32;
        let ack = 0x1234u32;
        let pkt = build_tcp_packet(local, remote, seq, ack, tcp::TcpFlags::SYN, None, 0, 0, 0xFFFF);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[40..]).unwrap();
        assert_eq!(tcp_pkt.get_flags(), tcp::TcpFlags::SYN);
        assert_eq!(tcp_pkt.get_data_offset(), 10);
        assert_eq!(tcp_pkt.get_window(), 0xFFFF);
        assert_eq!(tcp_pkt.get_sequence(), seq);
        assert_eq!(tcp_pkt.get_acknowledgement(), ack);
        let opts = tcp_pkt.get_options_raw();
        assert_eq!(opts.len(), 20);
        assert_eq!(opts[0], 2);   // MSS kind
        assert_eq!(u16::from_be_bytes([opts[2], opts[3]]), 1460);
        assert_eq!(opts[19], 5);  // wscale shift=5
    }

    #[test]
    fn test_ipv4_ack_data_total_length() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let payload = b"hello world";
        let pkt = build_tcp_packet(local, remote, 1, 1, tcp::TcpFlags::ACK, Some(payload), 0, 0, 0xFFFF);
        // 20 (IPv4) + 32 (TCP: 20 base + 12 timestamp options) + 11 (payload) = 63
        assert_eq!(pkt.len(), 20 + 32 + payload.len());
    }

    #[test]
    fn test_ipv4_ack_data_doff_timestamps_window() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let payload = b"data";
        let pkt = build_tcp_packet(local, remote, 1, 1, tcp::TcpFlags::ACK, Some(payload), 0, 0, 0xFFFF);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.get_data_offset(), 8, "doff=8 means 32-byte TCP header (with TS options)");
        assert_eq!(tcp_pkt.get_options_raw().len(), 12, "NOP+NOP+TS = 12 bytes");
        assert_eq!(tcp_pkt.get_window(), 0xFFFF);
    }

    #[test]
    fn test_ipv4_ack_data_payload_bytes_match() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let payload = b"test payload bytes";
        let pkt = build_tcp_packet(local, remote, 42, 99, tcp::TcpFlags::ACK, Some(payload), 0, 0, 0xFFFF);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.payload(), payload);
    }

    #[test]
    fn test_rst_ack_flags_no_payload_seq_ack() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let seq = 0xDEADBEEFu32;
        let ack = 0xCAFEBABEu32;
        let pkt = build_tcp_packet(
            local,
            remote,
            seq,
            ack,
            tcp::TcpFlags::RST | tcp::TcpFlags::ACK,
            None,
            0, 0,
            0xFFFF,
        );
        // 20 (IPv4) + 32 (TCP with TS options) = 52, no payload
        assert_eq!(pkt.len(), 52);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.get_flags(), tcp::TcpFlags::RST | tcp::TcpFlags::ACK);
        assert_eq!(tcp_pkt.payload().len(), 0);
        assert_eq!(tcp_pkt.get_sequence(), seq);
        assert_eq!(tcp_pkt.get_acknowledgement(), ack);
    }

    #[test]
    fn test_syn_ack_flags_and_options() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let pkt = build_tcp_packet(
            local,
            remote,
            0,
            1,
            tcp::TcpFlags::SYN | tcp::TcpFlags::ACK,
            None,
            0, 0,
            0xFFFF,
        );
        // SYN|ACK: has SYN flag -> 20-byte options -> 60 bytes
        assert_eq!(pkt.len(), 60);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.get_flags(), tcp::TcpFlags::SYN | tcp::TcpFlags::ACK);
        assert_eq!(tcp_pkt.get_data_offset(), 10);
        let opts = tcp_pkt.get_options_raw();
        assert_eq!(opts.len(), 20);
        assert_eq!(opts[0], 2);   // MSS
        assert_eq!(opts[19], 5);  // wscale=5
    }

    #[test]
    fn test_ack_only_no_data_length() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let pkt = build_tcp_packet(local, remote, 1, 1, tcp::TcpFlags::ACK, None, 0, 0, 0xFFFF);
        // 20 (IPv4) + 32 (TCP with TS options) = 52
        assert_eq!(pkt.len(), 52);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.get_data_offset(), 8);
        assert_eq!(tcp_pkt.payload().len(), 0);
    }

    #[test]
    fn test_ipv6_ack_data_tcp_checks() {
        let local: SocketAddr = "[fd00::1]:1234".parse().unwrap();
        let remote: SocketAddr = "[fd00::2]:5678".parse().unwrap();
        let payload = b"ipv6 payload";
        let seq = 100u32;
        let ack = 200u32;
        let pkt = build_tcp_packet(local, remote, seq, ack, tcp::TcpFlags::ACK, Some(payload), 0, 0, 0xFFFF);
        // 40 (IPv6) + 32 (TCP with TS) + payload
        assert_eq!(pkt.len(), 40 + 32 + payload.len());
        let v6 = ipv6::Ipv6Packet::new(&pkt).unwrap();
        assert_eq!(v6.get_version(), 6);
        assert_eq!(v6.get_payload_length() as usize, 32 + payload.len());
        let tcp_pkt = tcp::TcpPacket::new(&pkt[40..]).unwrap();
        assert_eq!(tcp_pkt.get_flags(), tcp::TcpFlags::ACK);
        assert_eq!(tcp_pkt.get_data_offset(), 8);
        assert_eq!(tcp_pkt.get_window(), 0xFFFF);
        assert_eq!(tcp_pkt.get_sequence(), seq);
        assert_eq!(tcp_pkt.get_acknowledgement(), ack);
        assert_eq!(tcp_pkt.payload(), payload);
    }

    #[test]
    fn test_roundtrip_ipv4_syn() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let seq = 0x12345678u32;
        let ack = 0u32;
        let pkt = build_tcp_packet(local, remote, seq, ack, tcp::TcpFlags::SYN, None, 0, 0, 0xFFFF);
        let (ip_pkt, tcp_pkt) = parse_ip_packet(&pkt).unwrap();
        assert_eq!(ip_pkt.get_source(), IpAddr::V4("10.0.0.1".parse().unwrap()));
        assert_eq!(ip_pkt.get_destination(), IpAddr::V4("10.0.0.2".parse().unwrap()));
        assert_eq!(tcp_pkt.get_flags(), tcp::TcpFlags::SYN);
        assert_eq!(tcp_pkt.get_sequence(), seq);
        assert_eq!(tcp_pkt.get_acknowledgement(), ack);
        assert_eq!(tcp_pkt.get_data_offset(), 10);
        assert_eq!(tcp_pkt.get_window(), 0xFFFF);
        let opts = tcp_pkt.get_options_raw();
        assert_eq!(opts[0], 2);   // MSS
        assert_eq!(opts[19], 5);  // wscale=5
    }

    #[test]
    fn test_roundtrip_ipv4_data() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let seq = 100u32;
        let ack = 200u32;
        let payload = b"roundtrip data";
        let pkt = build_tcp_packet(local, remote, seq, ack, tcp::TcpFlags::ACK, Some(payload), 0, 0, 0xFFFF);
        let (ip_pkt, tcp_pkt) = parse_ip_packet(&pkt).unwrap();
        assert_eq!(ip_pkt.get_source(), IpAddr::V4("10.0.0.1".parse().unwrap()));
        assert_eq!(ip_pkt.get_destination(), IpAddr::V4("10.0.0.2".parse().unwrap()));
        assert_eq!(tcp_pkt.get_flags(), tcp::TcpFlags::ACK);
        assert_eq!(tcp_pkt.get_sequence(), seq);
        assert_eq!(tcp_pkt.get_acknowledgement(), ack);
        assert_eq!(tcp_pkt.payload(), payload as &[u8]);
    }

    #[test]
    fn test_roundtrip_ipv6_syn() {
        let local: SocketAddr = "[fd00::1]:9000".parse().unwrap();
        let remote: SocketAddr = "[fd00::2]:9001".parse().unwrap();
        let seq = 0xABCDu32;
        let ack = 0u32;
        let pkt = build_tcp_packet(local, remote, seq, ack, tcp::TcpFlags::SYN, None, 0, 0, 0xFFFF);
        let (ip_pkt, tcp_pkt) = parse_ip_packet(&pkt).unwrap();
        assert_eq!(ip_pkt.get_source(), IpAddr::V6("fd00::1".parse().unwrap()));
        assert_eq!(ip_pkt.get_destination(), IpAddr::V6("fd00::2".parse().unwrap()));
        assert_eq!(tcp_pkt.get_flags(), tcp::TcpFlags::SYN);
        assert_eq!(tcp_pkt.get_sequence(), seq);
        assert_eq!(tcp_pkt.get_acknowledgement(), ack);
        assert_eq!(tcp_pkt.get_data_offset(), 10);
        assert_eq!(tcp_pkt.get_window(), 0xFFFF);
    }

    #[test]
    fn test_roundtrip_ipv6_data() {
        let local: SocketAddr = "[fd00::1]:9000".parse().unwrap();
        let remote: SocketAddr = "[fd00::2]:9001".parse().unwrap();
        let seq = 50u32;
        let ack = 60u32;
        let payload = b"ipv6 roundtrip";
        let pkt = build_tcp_packet(local, remote, seq, ack, tcp::TcpFlags::ACK, Some(payload), 0, 0, 0xFFFF);
        let (ip_pkt, tcp_pkt) = parse_ip_packet(&pkt).unwrap();
        assert_eq!(ip_pkt.get_source(), IpAddr::V6("fd00::1".parse().unwrap()));
        assert_eq!(ip_pkt.get_destination(), IpAddr::V6("fd00::2".parse().unwrap()));
        assert_eq!(tcp_pkt.get_flags(), tcp::TcpFlags::ACK);
        assert_eq!(tcp_pkt.get_sequence(), seq);
        assert_eq!(tcp_pkt.get_acknowledgement(), ack);
        assert_eq!(tcp_pkt.payload(), payload as &[u8]);
    }

    #[test]
    fn test_parse_non_tcp_ipv4_returns_none() {
        // IPv4 header with protocol=UDP(17) — parse_ip_packet must return None
        let mut buf = vec![0u8; 28];
        buf[0] = 0x45; // version=4, IHL=5
        buf[8] = 64;   // TTL
        buf[9] = 17;   // protocol = UDP, not TCP
        let bytes = Bytes::copy_from_slice(&buf);
        assert!(parse_ip_packet(&bytes).is_none());
    }

    #[test]
    fn test_parse_unknown_ip_version_returns_none() {
        // First nibble = 5 (not 4 or 6) — parse_ip_packet must return None
        let mut buf = vec![0u8; 40];
        buf[0] = 0x50; // version=5
        let bytes = Bytes::copy_from_slice(&buf);
        assert!(parse_ip_packet(&bytes).is_none());
    }

    #[test]
    fn test_parse_returns_none_on_empty_buffer() {
        let bytes = Bytes::new();
        assert!(parse_ip_packet(&bytes).is_none());
    }

    #[test]
    fn test_parse_returns_none_on_ipv4_too_short_for_tcp() {
        // 20-byte buffer with version=4 and protocol=TCP but no TCP header
        let mut buf = vec![0u8; 20];
        buf[0] = 0x45; // version=4, IHL=5
        buf[8] = 64;   // TTL
        buf[9] = 6;    // TCP
        let bytes = Bytes::copy_from_slice(&buf);
        assert!(parse_ip_packet(&bytes).is_none());
    }

    #[test]
    fn test_syn_options_mss_1460() {
        let pkt = ipv4_syn_packet();
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let opts = tcp_pkt.get_options_raw();
        assert_eq!(opts.len(), 20);
        assert_eq!(opts[0], 2, "MSS kind");
        assert_eq!(opts[1], 4, "MSS len");
        assert_eq!(u16::from_be_bytes([opts[2], opts[3]]), 1460, "MSS value");
    }

    #[test]
    fn test_syn_options_sack_perm() {
        let pkt = ipv4_syn_packet();
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let opts = tcp_pkt.get_options_raw();
        assert_eq!(opts[4], 4, "SACK_PERM kind");
        assert_eq!(opts[5], 2, "SACK_PERM len");
    }

    #[test]
    fn test_syn_options_timestamps() {
        let pkt = ipv4_syn_packet();
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let opts = tcp_pkt.get_options_raw();
        assert_eq!(opts[6], 8, "Timestamps kind");
        assert_eq!(opts[7], 10, "Timestamps len");
        let ts_ecr = u32::from_be_bytes([opts[12], opts[13], opts[14], opts[15]]);
        assert_eq!(ts_ecr, 0, "ts_ecr=0 on initial SYN");
    }

    #[test]
    fn test_syn_options_wscale_5() {
        let pkt = ipv4_syn_packet();
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let opts = tcp_pkt.get_options_raw();
        assert_eq!(opts[16], 1, "NOP before wscale");
        assert_eq!(opts[17], 3, "wscale kind");
        assert_eq!(opts[18], 3, "wscale len");
        assert_eq!(opts[19], 5, "wscale shift=5");
    }

    #[test]
    fn test_syn_options_full_linux_layout() {
        let pkt = ipv4_syn_packet();
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let opts = tcp_pkt.get_options_raw();
        assert_eq!(opts.len(), 20);
        let expected_prefix = [
            2, 4, 0x05, 0xB4, // MSS = 1460
            4, 2,              // SACK permitted
            8, 10,             // Timestamps kind + len
        ];
        assert_eq!(&opts[0..8], &expected_prefix);
        let expected_suffix = [
            1,          // NOP
            3, 3, 5,    // wscale = 5
        ];
        assert_eq!(&opts[16..20], &expected_suffix);
    }

    #[test]
    fn test_data_packet_has_timestamps_doff8() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let payload = b"hello";
        let pkt = build_tcp_packet(local, remote, 100, 200, tcp::TcpFlags::ACK, Some(payload), 5000, 3000, 0xFFFF);
        // 20 (IPv4) + 32 (TCP: 20 base + 12 options) + 5 (payload) = 57
        assert_eq!(pkt.len(), 20 + 32 + payload.len());
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.get_data_offset(), 8, "doff=8 means 32-byte TCP header with timestamps");
    }

    #[test]
    fn test_data_packet_timestamps_options_layout() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let ts_val = 12345u32;
        let ts_ecr = 67890u32;
        let pkt = build_tcp_packet(local, remote, 1, 1, tcp::TcpFlags::ACK, Some(b"data"), ts_val, ts_ecr, 0xFFFF);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let opts = tcp_pkt.get_options_raw();
        assert_eq!(opts.len(), 12);
        assert_eq!(opts[0], 1, "NOP");
        assert_eq!(opts[1], 1, "NOP");
        assert_eq!(opts[2], 8, "Timestamps kind");
        assert_eq!(opts[3], 10, "Timestamps len");
        let parsed_tsval = u32::from_be_bytes([opts[4], opts[5], opts[6], opts[7]]);
        let parsed_tsecr = u32::from_be_bytes([opts[8], opts[9], opts[10], opts[11]]);
        assert_eq!(parsed_tsval, ts_val, "tsval matches input");
        assert_eq!(parsed_tsecr, ts_ecr, "tsecr matches input");
    }

    #[test]
    fn test_syn_has_tsval_filled_in() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let ts_val = 42000u32;
        let pkt = build_tcp_packet(local, remote, 0, 0, tcp::TcpFlags::SYN, None, ts_val, 0, 0xFFFF);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let opts = tcp_pkt.get_options_raw();
        let parsed_tsval = u32::from_be_bytes([opts[8], opts[9], opts[10], opts[11]]);
        let parsed_tsecr = u32::from_be_bytes([opts[12], opts[13], opts[14], opts[15]]);
        assert_eq!(parsed_tsval, ts_val, "SYN tsval should be filled in");
        assert_eq!(parsed_tsecr, 0, "SYN tsecr should be 0 for initial SYN");
    }

    #[test]
    fn test_syn_ack_has_tsecr() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let ts_val = 50000u32;
        let ts_ecr = 42000u32;
        let pkt = build_tcp_packet(local, remote, 0, 1, tcp::TcpFlags::SYN | tcp::TcpFlags::ACK, None, ts_val, ts_ecr, 0xFFFF);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let opts = tcp_pkt.get_options_raw();
        let parsed_tsval = u32::from_be_bytes([opts[8], opts[9], opts[10], opts[11]]);
        let parsed_tsecr = u32::from_be_bytes([opts[12], opts[13], opts[14], opts[15]]);
        assert_eq!(parsed_tsval, ts_val);
        assert_eq!(parsed_tsecr, ts_ecr, "SYN+ACK should echo peer's tsval");
    }

    #[test]
    fn test_data_checksum_valid() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let payload = b"checksum test";
        let pkt = build_tcp_packet(local, remote, 100, 200, tcp::TcpFlags::ACK, Some(payload), 9999, 8888, 0xFFFF);
        let tcp_len = pkt.len() - 20;
        let mut tcp_bytes = pkt[20..].to_vec();
        let stored_cksm = tcp::TcpPacket::new(&tcp_bytes).unwrap().get_checksum();
        tcp_bytes[16] = 0;
        tcp_bytes[17] = 0;
        let ip::IpNextHeaderProtocol(proto) = ip::IpNextHeaderProtocols::Tcp;
        let mut cksm = Checksum::new();
        cksm.add_bytes(&[10, 0, 0, 1]);
        cksm.add_bytes(&[10, 0, 0, 2]);
        cksm.add_bytes(&[0, proto, (tcp_len >> 8) as u8, (tcp_len & 0xFF) as u8]);
        cksm.add_bytes(&tcp_bytes);
        assert_eq!(stored_cksm, u16::from_be_bytes(cksm.checksum()));
    }

    #[test]
    fn test_psh_ack_flags_data_packet() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let payload = b"hello";
        let pkt = build_tcp_packet(
            local, remote, 1, 1,
            tcp::TcpFlags::PSH | tcp::TcpFlags::ACK,
            Some(payload), 1000, 500,
            0xFFFF,
        );
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(
            tcp_pkt.get_flags(),
            tcp::TcpFlags::PSH | tcp::TcpFlags::ACK,
        );
        assert_eq!(tcp_pkt.payload(), payload);
    }

    #[test]
    fn test_window_value_passed_through() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let window = 350u16;
        let pkt = build_tcp_packet(
            local, remote, 1, 1, tcp::TcpFlags::ACK, Some(b"data"),
            1000, 500, window,
        );
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.get_window(), window);
    }

    // --- parse_tcp_timestamps tests ---

    #[test]
    fn test_parse_tcp_timestamp_from_data_packet() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let ts_val = 55555u32;
        let pkt = build_tcp_packet(local, remote, 1, 1, tcp::TcpFlags::ACK, Some(b"x"), ts_val, 0, 0xFFFF);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let parsed = parse_tcp_timestamps(&tcp_pkt).map(|(tsval, _)| tsval);
        assert_eq!(parsed, Some(ts_val));
    }

    #[test]
    fn test_parse_tcp_timestamp_from_syn() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let ts_val = 77777u32;
        let pkt = build_tcp_packet(local, remote, 0, 0, tcp::TcpFlags::SYN, None, ts_val, 0, 0xFFFF);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let parsed = parse_tcp_timestamps(&tcp_pkt).map(|(tsval, _)| tsval);
        assert_eq!(parsed, Some(ts_val));
    }

    #[test]
    fn test_parse_tcp_timestamps_returns_both_values() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let pkt = build_tcp_packet(
            local, remote, 1, 1, tcp::TcpFlags::ACK, Some(b"x"),
            11111, 22222, 0xFFFF,
        );
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let (tsval, tsecr) = parse_tcp_timestamps(&tcp_pkt).expect("should parse both");
        assert_eq!(tsval, 11111);
        assert_eq!(tsecr, 22222);
    }

    #[test]
    fn test_timestamps_monotonically_increasing() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let pkt1 = build_tcp_packet(local, remote, 1, 1, tcp::TcpFlags::ACK, Some(b"a"), 1000, 0, 0xFFFF);
        let pkt2 = build_tcp_packet(local, remote, 2, 1, tcp::TcpFlags::ACK, Some(b"b"), 1050, 0, 0xFFFF);
        let opts1 = tcp::TcpPacket::new(&pkt1[20..]).unwrap().get_options_raw().to_vec();
        let opts2 = tcp::TcpPacket::new(&pkt2[20..]).unwrap().get_options_raw().to_vec();
        let ts1 = u32::from_be_bytes([opts1[4], opts1[5], opts1[6], opts1[7]]);
        let ts2 = u32::from_be_bytes([opts2[4], opts2[5], opts2[6], opts2[7]]);
        assert!(ts2 > ts1, "timestamps should be monotonically increasing: {} > {}", ts2, ts1);
    }

    #[test]
    fn test_tsecr_matches_peer_tsval_exactly() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let peer_tsval = 99999u32;

        let peer_pkt = build_tcp_packet(
            remote, local, 1, 1, tcp::TcpFlags::ACK, Some(b"hello"),
            peer_tsval, 50000, 0xFFFF,
        );
        let tcp_pkt = tcp::TcpPacket::new(&peer_pkt[20..]).unwrap();
        let extracted_tsval = parse_tcp_timestamps(&tcp_pkt).map(|(tsval, _)| tsval).expect("should parse peer tsval");
        assert_eq!(extracted_tsval, peer_tsval);

        let our_pkt = build_tcp_packet(
            local, remote, 1, 2, tcp::TcpFlags::ACK, Some(b"world"),
            60000, extracted_tsval, 0xFFFF,
        );
        let our_tcp = tcp::TcpPacket::new(&our_pkt[20..]).unwrap();
        let (_, our_tsecr) = parse_tcp_timestamps(&our_tcp).expect("should have timestamps");
        assert_eq!(our_tsecr, peer_tsval, "outgoing ts_ecr must match last received peer tsval exactly");
    }
}
