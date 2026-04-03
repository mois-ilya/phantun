use bytes::{Bytes, BytesMut};
use internet_checksum::Checksum;
use pnet::packet::{MutablePacket, Packet};
use pnet::packet::{ip, ipv4, ipv6, tcp};
use std::convert::TryInto;
use std::net::{IpAddr, SocketAddr};

use crate::StealthLevel;

const IPV4_HEADER_LEN: usize = 20;
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

#[allow(clippy::too_many_arguments)]
pub fn build_tcp_packet(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: Option<&[u8]>,
    stealth: StealthLevel,
    ts_val: u32,
    ts_ecr: u32,
) -> Bytes {
    let ip_header_len = match local_addr {
        SocketAddr::V4(_) => IPV4_HEADER_LEN,
        SocketAddr::V6(_) => IPV6_HEADER_LEN,
    };
    let is_syn = (flags & tcp::TcpFlags::SYN) != 0;
    let tcp_options_len = if is_syn {
        if stealth >= StealthLevel::Basic {
            20 // MSS(4) + SACK_PERM(2) + TS(10) + NOP(1) + wscale(3)
        } else {
            4 // NOP(1) + wscale(3)
        }
    } else if stealth >= StealthLevel::Basic {
        12 // NOP(1) + NOP(1) + TS(10)
    } else {
        0
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
    tcp.set_window(0xffff);
    tcp.set_source(local_addr.port());
    tcp.set_destination(remote_addr.port());
    tcp.set_sequence(seq);
    tcp.set_acknowledgement(ack);
    tcp.set_flags(flags);
    tcp.set_data_offset((tcp_header_len / 4) as u8);
    if is_syn {
        if stealth >= StealthLevel::Basic {
            // Linux 5.x SYN fingerprint: MSS + SACK_PERM + Timestamps + NOP + wscale
            let pkt = tcp.packet_mut();
            let opts = &mut pkt[TCP_HEADER_LEN..tcp_header_len];
            // MSS: kind=2, len=4, value=1460 (0x05B4)
            opts[0] = 2;
            opts[1] = 4;
            opts[2] = 0x05;
            opts[3] = 0xB4;
            // SACK permitted: kind=4, len=2
            opts[4] = 4;
            opts[5] = 2;
            // Timestamps: kind=8, len=10, tsval, tsecr
            opts[6] = 8;
            opts[7] = 10;
            opts[8..12].copy_from_slice(&ts_val.to_be_bytes());
            opts[12..16].copy_from_slice(&ts_ecr.to_be_bytes());
            // NOP: kind=1
            opts[16] = 1;
            // Window scale: kind=3, len=3, shift=7
            opts[17] = 3;
            opts[18] = 3;
            opts[19] = 7;
        } else {
            let wscale = tcp::TcpOption::wscale(14);
            tcp.set_options(&[tcp::TcpOption::nop(), wscale]);
        }
    } else if stealth >= StealthLevel::Basic {
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

/// Extract the TSval from TCP timestamp option (kind=8, len=10).
/// Returns None if no timestamp option is found.
pub fn parse_tcp_timestamp(tcp_packet: &tcp::TcpPacket<'_>) -> Option<u32> {
    let opts = tcp_packet.get_options_raw();
    let mut i = 0;
    while i < opts.len() {
        match opts[i] {
            0 => break,        // End of options
            1 => i += 1,       // NOP - single byte
            8 if i + 9 < opts.len() && opts[i + 1] == 10 => {
                // Timestamps: kind=8, len=10, tsval(4), tsecr(4)
                let tsval = u32::from_be_bytes([opts[i + 2], opts[i + 3], opts[i + 4], opts[i + 5]]);
                return Some(tsval);
            }
            _ => {
                // Variable-length option: kind, len, data...
                if i + 1 >= opts.len() {
                    break;
                }
                let len = opts[i + 1] as usize;
                if len < 2 {
                    break; // malformed
                }
                i += len;
                continue;
            }
        }
    }
    None
}

// TODO(security): panics on empty/short buffers instead of returning None.
// buf[0] index panics on empty input; .unwrap() panics when buffer has valid
// IP header but is too short for TCP. Malformed packet can crash the process.
// See #[should_panic] tests in this file. Fix before stealth TCP work.
pub fn parse_ip_packet(buf: &Bytes) -> Option<(IPPacket<'_>, tcp::TcpPacket<'_>)> {
    if buf[0] >> 4 == 4 {
        let v4 = ipv4::Ipv4Packet::new(buf).unwrap();
        if v4.get_next_level_protocol() != ip::IpNextHeaderProtocols::Tcp {
            return None;
        }

        let tcp = tcp::TcpPacket::new(&buf[IPV4_HEADER_LEN..]).unwrap();
        Some((IPPacket::V4(v4), tcp))
    } else if buf[0] >> 4 == 6 {
        let v6 = ipv6::Ipv6Packet::new(buf).unwrap();
        if v6.get_next_header() != ip::IpNextHeaderProtocols::Tcp {
            return None;
        }

        let tcp = tcp::TcpPacket::new(&buf[IPV6_HEADER_LEN..]).unwrap();
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
        build_tcp_packet(local, remote, 0, 0, tcp::TcpFlags::SYN, None, StealthLevel::Off, 0, 0)
    }

    fn ipv6_syn_packet() -> Bytes {
        let local: SocketAddr = "[fd00::1]:1234".parse().unwrap();
        let remote: SocketAddr = "[fd00::2]:5678".parse().unwrap();
        build_tcp_packet(local, remote, 0, 0, tcp::TcpFlags::SYN, None, StealthLevel::Off, 0, 0)
    }

    #[test]
    fn test_ipv4_syn_total_length() {
        let pkt = ipv4_syn_packet();
        // 20 (IPv4 header) + 24 (TCP header with options: 20 base + 4 options) = 44
        assert_eq!(pkt.len(), 44);
    }

    #[test]
    fn test_ipv4_syn_ip_header_fields() {
        let pkt = ipv4_syn_packet();
        let v4 = ipv4::Ipv4Packet::new(&pkt).unwrap();
        assert_eq!(v4.get_version(), 4);
        assert_eq!(v4.get_next_level_protocol(), ip::IpNextHeaderProtocols::Tcp);
        assert_eq!(v4.get_ttl(), 64);
        assert_eq!(v4.get_flags(), ipv4::Ipv4Flags::DontFragment);
        assert_eq!(v4.get_total_length() as usize, 44);
    }

    #[test]
    fn test_ipv4_syn_tcp_flags_doff_window() {
        let pkt = ipv4_syn_packet();
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.get_flags(), tcp::TcpFlags::SYN);
        assert_eq!(tcp_pkt.get_data_offset(), 6, "doff=6 means 24-byte TCP header");
        assert_eq!(tcp_pkt.get_window(), 0xFFFF);
    }

    #[test]
    fn test_ipv4_syn_tcp_options_nop_wscale() {
        let pkt = ipv4_syn_packet();
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let opts = tcp_pkt.get_options_raw();
        assert_eq!(opts.len(), 4, "SYN options: NOP(1) + wscale(3) = 4 bytes");
        assert_eq!(opts[0], 1, "NOP kind=1");
        assert_eq!(opts[1], 3, "wscale kind=3");
        assert_eq!(opts[2], 3, "wscale length=3");
        assert_eq!(opts[3], 14, "wscale shift=14");
    }

    #[test]
    fn test_ipv4_syn_seq_ack_match_input() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let seq = 0x12345678u32;
        let ack = 0x87654321u32;
        let pkt = build_tcp_packet(local, remote, seq, ack, tcp::TcpFlags::SYN, None, StealthLevel::Off, 0, 0);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.get_sequence(), seq);
        assert_eq!(tcp_pkt.get_acknowledgement(), ack);
    }

    #[test]
    fn test_ipv4_syn_checksum_valid() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let pkt = build_tcp_packet(local, remote, 0, 0, tcp::TcpFlags::SYN, None, StealthLevel::Off, 0, 0);

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
        // 40 (IPv6 header) + 24 (TCP header with options) = 64
        assert_eq!(pkt.len(), 64);
    }

    #[test]
    fn test_ipv6_syn_ip_header_fields() {
        let pkt = ipv6_syn_packet();
        let v6 = ipv6::Ipv6Packet::new(&pkt).unwrap();
        assert_eq!(v6.get_version(), 6);
        assert_eq!(v6.get_next_header(), ip::IpNextHeaderProtocols::Tcp);
        assert_eq!(v6.get_hop_limit(), 64);
        assert_eq!(v6.get_payload_length() as usize, 24, "payload_length = TCP header with options");
    }

    #[test]
    fn test_ipv6_syn_tcp_flags_doff_window_options() {
        let local: SocketAddr = "[fd00::1]:9000".parse().unwrap();
        let remote: SocketAddr = "[fd00::2]:9001".parse().unwrap();
        let seq = 0xABCDu32;
        let ack = 0x1234u32;
        let pkt = build_tcp_packet(local, remote, seq, ack, tcp::TcpFlags::SYN, None, StealthLevel::Off, 0, 0);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[40..]).unwrap();
        assert_eq!(tcp_pkt.get_flags(), tcp::TcpFlags::SYN);
        assert_eq!(tcp_pkt.get_data_offset(), 6);
        assert_eq!(tcp_pkt.get_window(), 0xFFFF);
        assert_eq!(tcp_pkt.get_sequence(), seq);
        assert_eq!(tcp_pkt.get_acknowledgement(), ack);
        let opts = tcp_pkt.get_options_raw();
        assert_eq!(opts.len(), 4);
        assert_eq!(opts[0], 1);  // NOP
        assert_eq!(opts[1], 3);  // wscale kind
        assert_eq!(opts[2], 3);  // wscale length
        assert_eq!(opts[3], 14); // wscale shift
    }

    // --- Task 3: data and control packets ---

    #[test]
    fn test_ipv4_ack_data_total_length() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let payload = b"hello world";
        let pkt = build_tcp_packet(local, remote, 1, 1, tcp::TcpFlags::ACK, Some(payload), StealthLevel::Off, 0, 0);
        // 20 (IPv4) + 20 (TCP, no options) + 11 (payload) = 51
        assert_eq!(pkt.len(), 20 + 20 + payload.len());
    }

    #[test]
    fn test_ipv4_ack_data_doff_no_options_window() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let payload = b"data";
        let pkt = build_tcp_packet(local, remote, 1, 1, tcp::TcpFlags::ACK, Some(payload), StealthLevel::Off, 0, 0);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.get_data_offset(), 5, "doff=5 means 20-byte TCP header (no options)");
        assert_eq!(tcp_pkt.get_options_raw().len(), 0, "no TCP options for data packets");
        assert_eq!(tcp_pkt.get_window(), 0xFFFF);
    }

    #[test]
    fn test_ipv4_ack_data_payload_bytes_match() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let payload = b"test payload bytes";
        let pkt = build_tcp_packet(local, remote, 42, 99, tcp::TcpFlags::ACK, Some(payload), StealthLevel::Off, 0, 0);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.payload(), payload);
    }

    #[test]
    fn test_ipv4_ack_data_flags_ack_only() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let payload = b"data";
        let pkt = build_tcp_packet(local, remote, 1, 1, tcp::TcpFlags::ACK, Some(payload), StealthLevel::Off, 0, 0);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.get_flags(), tcp::TcpFlags::ACK, "only ACK flag set, no PSH");
        assert_eq!(tcp_pkt.get_flags() & tcp::TcpFlags::PSH, 0, "PSH flag not set");
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
            StealthLevel::Off,
            0, 0,
        );
        // 20 (IPv4) + 20 (TCP) = 40, no payload
        assert_eq!(pkt.len(), 40);
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
            StealthLevel::Off,
            0, 0,
        );
        // SYN|ACK: wscale is set because SYN flag is present → 44 bytes
        assert_eq!(pkt.len(), 44);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.get_flags(), tcp::TcpFlags::SYN | tcp::TcpFlags::ACK);
        assert_eq!(tcp_pkt.get_data_offset(), 6);
        let opts = tcp_pkt.get_options_raw();
        assert_eq!(opts.len(), 4);
        assert_eq!(opts[0], 1);  // NOP
        assert_eq!(opts[1], 3);  // wscale kind
        assert_eq!(opts[2], 3);  // wscale length
        assert_eq!(opts[3], 14); // wscale shift=14
    }

    #[test]
    fn test_ack_only_no_data_length() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let pkt = build_tcp_packet(local, remote, 1, 1, tcp::TcpFlags::ACK, None, StealthLevel::Off, 0, 0);
        // 20 (IPv4) + 20 (TCP, no options, no payload) = 40
        assert_eq!(pkt.len(), 40);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.get_data_offset(), 5);
        assert_eq!(tcp_pkt.payload().len(), 0);
    }

    #[test]
    fn test_ipv6_ack_data_tcp_checks() {
        let local: SocketAddr = "[fd00::1]:1234".parse().unwrap();
        let remote: SocketAddr = "[fd00::2]:5678".parse().unwrap();
        let payload = b"ipv6 payload";
        let seq = 100u32;
        let ack = 200u32;
        let pkt = build_tcp_packet(local, remote, seq, ack, tcp::TcpFlags::ACK, Some(payload), StealthLevel::Off, 0, 0);
        // 40 (IPv6) + 20 (TCP) + payload
        assert_eq!(pkt.len(), 40 + 20 + payload.len());
        let v6 = ipv6::Ipv6Packet::new(&pkt).unwrap();
        assert_eq!(v6.get_version(), 6);
        assert_eq!(v6.get_payload_length() as usize, 20 + payload.len());
        let tcp_pkt = tcp::TcpPacket::new(&pkt[40..]).unwrap();
        assert_eq!(tcp_pkt.get_flags(), tcp::TcpFlags::ACK);
        assert_eq!(tcp_pkt.get_data_offset(), 5);
        assert_eq!(tcp_pkt.get_window(), 0xFFFF);
        assert_eq!(tcp_pkt.get_sequence(), seq);
        assert_eq!(tcp_pkt.get_acknowledgement(), ack);
        assert_eq!(tcp_pkt.payload(), payload);
    }

    // --- Task 4: parse_ip_packet() and round-trip ---

    #[test]
    fn test_roundtrip_ipv4_syn() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let seq = 0x12345678u32;
        let ack = 0u32;
        let pkt = build_tcp_packet(local, remote, seq, ack, tcp::TcpFlags::SYN, None, StealthLevel::Off, 0, 0);
        let (ip_pkt, tcp_pkt) = parse_ip_packet(&pkt).unwrap();
        assert_eq!(ip_pkt.get_source(), IpAddr::V4("10.0.0.1".parse().unwrap()));
        assert_eq!(ip_pkt.get_destination(), IpAddr::V4("10.0.0.2".parse().unwrap()));
        assert_eq!(tcp_pkt.get_flags(), tcp::TcpFlags::SYN);
        assert_eq!(tcp_pkt.get_sequence(), seq);
        assert_eq!(tcp_pkt.get_acknowledgement(), ack);
        assert_eq!(tcp_pkt.get_data_offset(), 6);
        assert_eq!(tcp_pkt.get_window(), 0xFFFF);
        let opts = tcp_pkt.get_options_raw();
        assert_eq!(opts[0], 1);  // NOP
        assert_eq!(opts[1], 3);  // wscale kind
        assert_eq!(opts[2], 3);  // wscale length
        assert_eq!(opts[3], 14); // wscale shift
    }

    #[test]
    fn test_roundtrip_ipv4_data() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let seq = 100u32;
        let ack = 200u32;
        let payload = b"roundtrip data";
        let pkt = build_tcp_packet(local, remote, seq, ack, tcp::TcpFlags::ACK, Some(payload), StealthLevel::Off, 0, 0);
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
        let pkt = build_tcp_packet(local, remote, seq, ack, tcp::TcpFlags::SYN, None, StealthLevel::Off, 0, 0);
        let (ip_pkt, tcp_pkt) = parse_ip_packet(&pkt).unwrap();
        assert_eq!(ip_pkt.get_source(), IpAddr::V6("fd00::1".parse().unwrap()));
        assert_eq!(ip_pkt.get_destination(), IpAddr::V6("fd00::2".parse().unwrap()));
        assert_eq!(tcp_pkt.get_flags(), tcp::TcpFlags::SYN);
        assert_eq!(tcp_pkt.get_sequence(), seq);
        assert_eq!(tcp_pkt.get_acknowledgement(), ack);
        assert_eq!(tcp_pkt.get_data_offset(), 6);
        assert_eq!(tcp_pkt.get_window(), 0xFFFF);
    }

    #[test]
    fn test_roundtrip_ipv6_data() {
        let local: SocketAddr = "[fd00::1]:9000".parse().unwrap();
        let remote: SocketAddr = "[fd00::2]:9001".parse().unwrap();
        let seq = 50u32;
        let ack = 60u32;
        let payload = b"ipv6 roundtrip";
        let pkt = build_tcp_packet(local, remote, seq, ack, tcp::TcpFlags::ACK, Some(payload), StealthLevel::Off, 0, 0);
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
    #[should_panic]
    fn test_parse_panics_on_empty_buffer() {
        let bytes = Bytes::new();
        parse_ip_packet(&bytes);
    }

    #[test]
    #[should_panic]
    fn test_parse_panics_on_ipv4_too_short_for_tcp() {
        // 20-byte buffer with version=4 and protocol=TCP but no TCP header
        // TcpPacket::new on empty slice unwraps None → panics
        let mut buf = vec![0u8; 20];
        buf[0] = 0x45; // version=4, IHL=5
        buf[8] = 64;   // TTL
        buf[9] = 6;    // TCP
        let bytes = Bytes::copy_from_slice(&buf);
        parse_ip_packet(&bytes);
    }

    // --- Task 3 (stealth plan): Realistic SYN fingerprint tests ---

    fn ipv4_stealth_syn_packet() -> Bytes {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        build_tcp_packet(local, remote, 0x12345678, 0, tcp::TcpFlags::SYN, None, StealthLevel::Basic, 1000, 0)
    }

    #[test]
    fn test_stealth_syn_total_length_ipv4() {
        let pkt = ipv4_stealth_syn_packet();
        // 20 (IPv4) + 40 (TCP: 20 base + 20 options) = 60
        assert_eq!(pkt.len(), 60);
    }

    #[test]
    fn test_stealth_syn_doff_10() {
        let pkt = ipv4_stealth_syn_packet();
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.get_data_offset(), 10, "doff=10 means 40-byte TCP header");
    }

    #[test]
    fn test_stealth_syn_options_mss_1460() {
        let pkt = ipv4_stealth_syn_packet();
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let opts = tcp_pkt.get_options_raw();
        assert_eq!(opts.len(), 20);
        // MSS: kind=2, len=4, value=1460 (0x05B4)
        assert_eq!(opts[0], 2, "MSS kind");
        assert_eq!(opts[1], 4, "MSS len");
        assert_eq!(u16::from_be_bytes([opts[2], opts[3]]), 1460, "MSS value");
    }

    #[test]
    fn test_stealth_syn_options_sack_perm() {
        let pkt = ipv4_stealth_syn_packet();
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let opts = tcp_pkt.get_options_raw();
        // SACK permitted: kind=4, len=2
        assert_eq!(opts[4], 4, "SACK_PERM kind");
        assert_eq!(opts[5], 2, "SACK_PERM len");
    }

    #[test]
    fn test_stealth_syn_options_timestamps() {
        let pkt = ipv4_stealth_syn_packet();
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let opts = tcp_pkt.get_options_raw();
        // Timestamps: kind=8, len=10
        assert_eq!(opts[6], 8, "Timestamps kind");
        assert_eq!(opts[7], 10, "Timestamps len");
        // tsecr should be 0 for SYN
        let ts_ecr = u32::from_be_bytes([opts[12], opts[13], opts[14], opts[15]]);
        assert_eq!(ts_ecr, 0, "ts_ecr=0 on initial SYN");
    }

    #[test]
    fn test_stealth_syn_options_wscale_7() {
        let pkt = ipv4_stealth_syn_packet();
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let opts = tcp_pkt.get_options_raw();
        // NOP at offset 16
        assert_eq!(opts[16], 1, "NOP before wscale");
        // wscale: kind=3, len=3, shift=7
        assert_eq!(opts[17], 3, "wscale kind");
        assert_eq!(opts[18], 3, "wscale len");
        assert_eq!(opts[19], 7, "wscale shift=7");
    }

    #[test]
    fn test_stealth_syn_options_full_linux_layout() {
        // Verify the complete byte layout matches Linux 5.x SYN fingerprint
        let pkt = ipv4_stealth_syn_packet();
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let opts = tcp_pkt.get_options_raw();
        assert_eq!(opts.len(), 20);
        // MSS(4) + SACK_PERM(2) + TS(10) + NOP(1) + wscale(3) = 20
        let expected_prefix = [
            2, 4, 0x05, 0xB4, // MSS = 1460
            4, 2,             // SACK permitted
            8, 10,            // Timestamps kind + len
        ];
        assert_eq!(&opts[0..8], &expected_prefix);
        let expected_suffix = [
            1,          // NOP
            3, 3, 7,    // wscale = 7
        ];
        assert_eq!(&opts[16..20], &expected_suffix);
    }

    #[test]
    fn test_stealth_syn_ack_has_same_options() {
        // SYN+ACK with stealth should have the same Linux-like options
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let pkt = build_tcp_packet(
            local, remote, 100, 1,
            tcp::TcpFlags::SYN | tcp::TcpFlags::ACK, None,
            StealthLevel::Basic,
            1000, 500,
        );
        assert_eq!(pkt.len(), 60, "SYN+ACK stealth: 20 IPv4 + 40 TCP");
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.get_data_offset(), 10);
        let opts = tcp_pkt.get_options_raw();
        assert_eq!(opts.len(), 20);
        // MSS
        assert_eq!(opts[0], 2);
        assert_eq!(u16::from_be_bytes([opts[2], opts[3]]), 1460);
        // SACK_PERM
        assert_eq!(opts[4], 4);
        // Timestamps
        assert_eq!(opts[6], 8);
        // wscale
        assert_eq!(opts[17], 3);
        assert_eq!(opts[19], 7);
    }

    #[test]
    fn test_stealth_off_syn_still_old_format() {
        // Stealth Off must produce the original format: NOP + wscale(14), doff=6
        let pkt = ipv4_syn_packet(); // uses StealthLevel::Off
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.get_data_offset(), 6);
        let opts = tcp_pkt.get_options_raw();
        assert_eq!(opts.len(), 4);
        assert_eq!(opts[0], 1);  // NOP
        assert_eq!(opts[1], 3);  // wscale kind
        assert_eq!(opts[3], 14); // wscale shift=14
    }

    #[test]
    fn test_stealth_syn_ipv6_total_length() {
        let local: SocketAddr = "[fd00::1]:1234".parse().unwrap();
        let remote: SocketAddr = "[fd00::2]:5678".parse().unwrap();
        let pkt = build_tcp_packet(local, remote, 0, 0, tcp::TcpFlags::SYN, None, StealthLevel::Basic, 1000, 0);
        // 40 (IPv6) + 40 (TCP: 20 base + 20 options) = 80
        assert_eq!(pkt.len(), 80);
        let v6 = ipv6::Ipv6Packet::new(&pkt).unwrap();
        assert_eq!(v6.get_payload_length() as usize, 40);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[40..]).unwrap();
        assert_eq!(tcp_pkt.get_data_offset(), 10);
    }

    #[test]
    fn test_stealth_syn_checksum_valid() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let pkt = build_tcp_packet(local, remote, 0x1234, 0, tcp::TcpFlags::SYN, None, StealthLevel::Basic, 1000, 0);

        // Verify IPv4 header checksum
        let v4 = ipv4::Ipv4Packet::new(&pkt).unwrap();
        let stored_ip_cksm = v4.get_checksum();
        let mut ip_hdr = pkt[..20].to_vec();
        ip_hdr[10] = 0;
        ip_hdr[11] = 0;
        let mut cksm = Checksum::new();
        cksm.add_bytes(&ip_hdr);
        assert_eq!(stored_ip_cksm, u16::from_be_bytes(cksm.checksum()));

        // Verify TCP checksum
        let tcp_len = pkt.len() - 20;
        let mut tcp_bytes = pkt[20..].to_vec();
        tcp_bytes[16] = 0;
        tcp_bytes[17] = 0;
        let ip::IpNextHeaderProtocol(proto) = ip::IpNextHeaderProtocols::Tcp;
        let mut cksm = Checksum::new();
        cksm.add_bytes(&[10, 0, 0, 1]);
        cksm.add_bytes(&[10, 0, 0, 2]);
        cksm.add_bytes(&[0, proto, (tcp_len >> 8) as u8, (tcp_len & 0xFF) as u8]);
        cksm.add_bytes(&tcp_bytes);
        assert_eq!(
            tcp::TcpPacket::new(&pkt[20..]).unwrap().get_checksum(),
            u16::from_be_bytes(cksm.checksum())
        );
    }

    #[test]
    fn test_stealth_standard_and_full_also_get_linux_syn() {
        // Higher stealth levels should also produce Linux-like SYN
        for stealth in [StealthLevel::Standard, StealthLevel::Full] {
            let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
            let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
            let pkt = build_tcp_packet(local, remote, 0, 0, tcp::TcpFlags::SYN, None, stealth, 1000, 0);
            assert_eq!(pkt.len(), 60, "stealth {:?} SYN should be 60 bytes", stealth);
            let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
            assert_eq!(tcp_pkt.get_data_offset(), 10);
            let opts = tcp_pkt.get_options_raw();
            assert_eq!(opts[0], 2); // MSS
            assert_eq!(opts[19], 7); // wscale=7
        }
    }

    // --- Task 4: Timestamps state tests ---

    #[test]
    fn test_stealth_data_packet_has_timestamps_doff8() {
        // Non-SYN packets with stealth >= Basic should have NOP+NOP+TS options (12 bytes, doff=8)
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let payload = b"hello";
        let pkt = build_tcp_packet(local, remote, 100, 200, tcp::TcpFlags::ACK, Some(payload), StealthLevel::Basic, 5000, 3000);
        // 20 (IPv4) + 32 (TCP: 20 base + 12 options) + 5 (payload) = 57
        assert_eq!(pkt.len(), 20 + 32 + payload.len());
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.get_data_offset(), 8, "doff=8 means 32-byte TCP header with timestamps");
    }

    #[test]
    fn test_stealth_data_packet_timestamps_options_layout() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let ts_val = 12345u32;
        let ts_ecr = 67890u32;
        let pkt = build_tcp_packet(local, remote, 1, 1, tcp::TcpFlags::ACK, Some(b"data"), StealthLevel::Basic, ts_val, ts_ecr);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let opts = tcp_pkt.get_options_raw();
        assert_eq!(opts.len(), 12);
        // NOP + NOP + Timestamps(kind=8, len=10, tsval, tsecr)
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
    fn test_stealth_syn_has_tsval_filled_in() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let ts_val = 42000u32;
        let pkt = build_tcp_packet(local, remote, 0, 0, tcp::TcpFlags::SYN, None, StealthLevel::Basic, ts_val, 0);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let opts = tcp_pkt.get_options_raw();
        // SYN timestamps at opts[8..12] (tsval) and opts[12..16] (tsecr)
        let parsed_tsval = u32::from_be_bytes([opts[8], opts[9], opts[10], opts[11]]);
        let parsed_tsecr = u32::from_be_bytes([opts[12], opts[13], opts[14], opts[15]]);
        assert_eq!(parsed_tsval, ts_val, "SYN tsval should be filled in");
        assert_eq!(parsed_tsecr, 0, "SYN tsecr should be 0 for initial SYN");
    }

    #[test]
    fn test_stealth_syn_ack_has_tsecr() {
        // SYN+ACK should echo the peer's tsval
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let ts_val = 50000u32;
        let ts_ecr = 42000u32; // peer's tsval from SYN
        let pkt = build_tcp_packet(local, remote, 0, 1, tcp::TcpFlags::SYN | tcp::TcpFlags::ACK, None, StealthLevel::Basic, ts_val, ts_ecr);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let opts = tcp_pkt.get_options_raw();
        let parsed_tsval = u32::from_be_bytes([opts[8], opts[9], opts[10], opts[11]]);
        let parsed_tsecr = u32::from_be_bytes([opts[12], opts[13], opts[14], opts[15]]);
        assert_eq!(parsed_tsval, ts_val);
        assert_eq!(parsed_tsecr, ts_ecr, "SYN+ACK should echo peer's tsval");
    }

    #[test]
    fn test_stealth_off_data_still_no_options() {
        // Stealth Off data packets must still have no TCP options
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let pkt = build_tcp_packet(local, remote, 1, 1, tcp::TcpFlags::ACK, Some(b"data"), StealthLevel::Off, 0, 0);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.get_data_offset(), 5, "stealth Off: doff=5, no options");
        assert_eq!(tcp_pkt.get_options_raw().len(), 0);
    }

    #[test]
    fn test_stealth_ack_only_has_timestamps() {
        // ACK-only (no payload) with stealth should also have timestamps
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let pkt = build_tcp_packet(local, remote, 1, 1, tcp::TcpFlags::ACK, None, StealthLevel::Basic, 1000, 500);
        // 20 (IPv4) + 32 (TCP: 20 base + 12 options) = 52
        assert_eq!(pkt.len(), 52);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.get_data_offset(), 8);
        let opts = tcp_pkt.get_options_raw();
        assert_eq!(opts[0], 1); // NOP
        assert_eq!(opts[1], 1); // NOP
        assert_eq!(opts[2], 8); // TS kind
    }

    #[test]
    fn test_stealth_data_packet_checksum_valid() {
        // Verify TCP checksum is correct with timestamp options
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let payload = b"checksum test";
        let pkt = build_tcp_packet(local, remote, 100, 200, tcp::TcpFlags::ACK, Some(payload), StealthLevel::Basic, 9999, 8888);
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
    fn test_stealth_ipv6_data_has_timestamps() {
        let local: SocketAddr = "[fd00::1]:1234".parse().unwrap();
        let remote: SocketAddr = "[fd00::2]:5678".parse().unwrap();
        let payload = b"ipv6 ts";
        let pkt = build_tcp_packet(local, remote, 1, 1, tcp::TcpFlags::ACK, Some(payload), StealthLevel::Basic, 2000, 1000);
        // 40 (IPv6) + 32 (TCP with TS) + payload
        assert_eq!(pkt.len(), 40 + 32 + payload.len());
        let tcp_pkt = tcp::TcpPacket::new(&pkt[40..]).unwrap();
        assert_eq!(tcp_pkt.get_data_offset(), 8);
        let opts = tcp_pkt.get_options_raw();
        assert_eq!(opts.len(), 12);
        let parsed_tsval = u32::from_be_bytes([opts[4], opts[5], opts[6], opts[7]]);
        assert_eq!(parsed_tsval, 2000);
    }

    #[test]
    fn test_timestamps_monotonically_increasing() {
        // Two packets built with increasing ts_val should have increasing timestamps
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let pkt1 = build_tcp_packet(local, remote, 1, 1, tcp::TcpFlags::ACK, Some(b"a"), StealthLevel::Basic, 1000, 0);
        let pkt2 = build_tcp_packet(local, remote, 2, 1, tcp::TcpFlags::ACK, Some(b"b"), StealthLevel::Basic, 1050, 0);
        let opts1 = tcp::TcpPacket::new(&pkt1[20..]).unwrap().get_options_raw().to_vec();
        let opts2 = tcp::TcpPacket::new(&pkt2[20..]).unwrap().get_options_raw().to_vec();
        let ts1 = u32::from_be_bytes([opts1[4], opts1[5], opts1[6], opts1[7]]);
        let ts2 = u32::from_be_bytes([opts2[4], opts2[5], opts2[6], opts2[7]]);
        assert!(ts2 > ts1, "timestamps should be monotonically increasing: {} > {}", ts2, ts1);
    }

    // --- parse_tcp_timestamp tests ---

    #[test]
    fn test_parse_tcp_timestamp_from_data_packet() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let ts_val = 55555u32;
        let pkt = build_tcp_packet(local, remote, 1, 1, tcp::TcpFlags::ACK, Some(b"x"), StealthLevel::Basic, ts_val, 0);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let parsed = parse_tcp_timestamp(&tcp_pkt);
        assert_eq!(parsed, Some(ts_val));
    }

    #[test]
    fn test_parse_tcp_timestamp_from_syn() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let ts_val = 77777u32;
        let pkt = build_tcp_packet(local, remote, 0, 0, tcp::TcpFlags::SYN, None, StealthLevel::Basic, ts_val, 0);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let parsed = parse_tcp_timestamp(&tcp_pkt);
        assert_eq!(parsed, Some(ts_val));
    }

    #[test]
    fn test_parse_tcp_timestamp_stealth_off_returns_none() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        // Stealth Off data packet has no options
        let pkt = build_tcp_packet(local, remote, 1, 1, tcp::TcpFlags::ACK, Some(b"x"), StealthLevel::Off, 0, 0);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let parsed = parse_tcp_timestamp(&tcp_pkt);
        assert_eq!(parsed, None);
    }

    #[test]
    fn test_parse_tcp_timestamp_stealth_off_syn_returns_none() {
        // Stealth Off SYN has NOP + wscale but no timestamps
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let pkt = build_tcp_packet(local, remote, 0, 0, tcp::TcpFlags::SYN, None, StealthLevel::Off, 0, 0);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let parsed = parse_tcp_timestamp(&tcp_pkt);
        assert_eq!(parsed, None);
    }
}

#[cfg(all(test, feature = "benchmark"))]
mod benchmarks {
    extern crate test;
    use super::*;
    use test::{black_box, Bencher};

    #[bench]
    fn bench_build_tcp_packet_1460(b: &mut Bencher) {
        let local_addr = "127.0.0.1:1234".parse().unwrap();
        let remote_addr = "127.0.0.2:1234".parse().unwrap();
        let payload = black_box([123u8; 1460]);
        b.iter(|| {
            build_tcp_packet(
                local_addr,
                remote_addr,
                123,
                456,
                tcp::TcpFlags::ACK,
                Some(&payload),
                StealthLevel::Off,
                0, 0,
            )
        });
    }

    #[bench]
    fn bench_build_tcp_packet_512(b: &mut Bencher) {
        let local_addr = "127.0.0.1:1234".parse().unwrap();
        let remote_addr = "127.0.0.2:1234".parse().unwrap();
        let payload = black_box([123u8; 512]);
        b.iter(|| {
            build_tcp_packet(
                local_addr,
                remote_addr,
                123,
                456,
                tcp::TcpFlags::ACK,
                Some(&payload),
                StealthLevel::Off,
                0, 0,
            )
        });
    }

    #[bench]
    fn bench_build_tcp_packet_128(b: &mut Bencher) {
        let local_addr = "127.0.0.1:1234".parse().unwrap();
        let remote_addr = "127.0.0.2:1234".parse().unwrap();
        let payload = black_box([123u8; 128]);
        b.iter(|| {
            build_tcp_packet(
                local_addr,
                remote_addr,
                123,
                456,
                tcp::TcpFlags::ACK,
                Some(&payload),
                StealthLevel::Off,
                0, 0,
            )
        });
    }
}
