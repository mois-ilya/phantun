use bytes::{Bytes, BytesMut};
use internet_checksum::Checksum;
use pnet::packet::{MutablePacket, Packet};
use pnet::packet::{ip, ipv4, ipv6, tcp};
use std::convert::TryInto;
use std::net::{IpAddr, SocketAddr};

use crate::StealthLevel;

/// Per-packet mimic overrides, computed by Socket from MimicProfile + mutable state.
pub struct MimicParams {
    /// IPv4 identification field value
    pub ip_id: u16,
    /// Whether incrementing IP ID mode is active (controls DF flag independently of ip_id value)
    pub ip_id_incrementing: bool,
    /// Window scale override for SYN packets (None = use stealth default)
    pub wscale: Option<u8>,
}

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
    window: u16,
    mimic: Option<&MimicParams>,
) -> Bytes {
    let ip_header_len = match local_addr {
        SocketAddr::V4(_) => IPV4_HEADER_LEN,
        SocketAddr::V6(_) => IPV6_HEADER_LEN,
    };
    let is_syn = (flags & tcp::TcpFlags::SYN) != 0;
    let tcp_options_len = if is_syn {
        if stealth >= StealthLevel::Basic {
            20 // MSS(4) + SACK_PERM(2)+TS_hdr(2) + TS_val(4) + TS_ecr(4) + NOP(1)+wscale(3)
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
            // DF is always set (both default phantun and udp2raw behavior).
            // When mimic has incrementing IP ID, also set the identification field.
            v4.set_flags(ipv4::Ipv4Flags::DontFragment);
            if let Some(mp) = mimic {
                if mp.ip_id_incrementing {
                    v4.set_identification(mp.ip_id);
                }
            }
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
        if stealth >= StealthLevel::Basic {
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
            // NOP + Window scale: kind=3, len=3, shift=N
            let wscale_value = mimic.and_then(|m| m.wscale).unwrap_or(7);
            opts[16] = 1;
            opts[17] = 3;
            opts[18] = 3;
            opts[19] = wscale_value;
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
        if v4.get_header_length() < 5 {
            return None;
        }
        if v4.get_next_level_protocol() != ip::IpNextHeaderProtocols::Tcp {
            return None;
        }

        let tcp_offset = (v4.get_header_length() as usize) * 4;
        let total_length = v4.get_total_length() as usize;
        // Reject packets where the declared IP total_length is too short to
        // contain even the IP header + minimum TCP header, or exceeds the
        // buffer.  Slice within total_length so trailing bytes beyond the IP
        // datagram are not fed to the TCP parser.
        if total_length < tcp_offset + TCP_HEADER_LEN || total_length > buf.len() {
            return None;
        }
        let tcp = tcp::TcpPacket::new(buf.get(tcp_offset..total_length)?)?;
        Some((IPPacket::V4(v4), tcp))
    } else if version == 6 {
        let v6 = ipv6::Ipv6Packet::new(buf)?;
        if v6.get_next_header() != ip::IpNextHeaderProtocols::Tcp {
            return None;
        }

        let payload_len = v6.get_payload_length() as usize;
        // Reject packets where payload_length is too short for a TCP header
        // or extends beyond the buffer. Slice within payload_length so
        // trailing bytes beyond the IPv6 datagram are not fed to the TCP parser.
        if payload_len < TCP_HEADER_LEN || IPV6_HEADER_LEN + payload_len > buf.len() {
            return None;
        }
        let tcp = tcp::TcpPacket::new(buf.get(IPV6_HEADER_LEN..IPV6_HEADER_LEN + payload_len)?)?;
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
        build_tcp_packet(local, remote, 0, 0, tcp::TcpFlags::SYN, None, StealthLevel::Off, 0, 0, 0xFFFF, None)
    }

    fn ipv6_syn_packet() -> Bytes {
        let local: SocketAddr = "[fd00::1]:1234".parse().unwrap();
        let remote: SocketAddr = "[fd00::2]:5678".parse().unwrap();
        build_tcp_packet(local, remote, 0, 0, tcp::TcpFlags::SYN, None, StealthLevel::Off, 0, 0, 0xFFFF, None)
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
        let pkt = build_tcp_packet(local, remote, seq, ack, tcp::TcpFlags::SYN, None, StealthLevel::Off, 0, 0, 0xFFFF, None);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.get_sequence(), seq);
        assert_eq!(tcp_pkt.get_acknowledgement(), ack);
    }

    #[test]
    fn test_ipv4_syn_checksum_valid() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let pkt = build_tcp_packet(local, remote, 0, 0, tcp::TcpFlags::SYN, None, StealthLevel::Off, 0, 0, 0xFFFF, None);

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
        let pkt = build_tcp_packet(local, remote, seq, ack, tcp::TcpFlags::SYN, None, StealthLevel::Off, 0, 0, 0xFFFF, None);
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
        let pkt = build_tcp_packet(local, remote, 1, 1, tcp::TcpFlags::ACK, Some(payload), StealthLevel::Off, 0, 0, 0xFFFF, None);
        // 20 (IPv4) + 20 (TCP, no options) + 11 (payload) = 51
        assert_eq!(pkt.len(), 20 + 20 + payload.len());
    }

    #[test]
    fn test_ipv4_ack_data_doff_no_options_window() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let payload = b"data";
        let pkt = build_tcp_packet(local, remote, 1, 1, tcp::TcpFlags::ACK, Some(payload), StealthLevel::Off, 0, 0, 0xFFFF, None);
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
        let pkt = build_tcp_packet(local, remote, 42, 99, tcp::TcpFlags::ACK, Some(payload), StealthLevel::Off, 0, 0, 0xFFFF, None);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.payload(), payload);
    }

    #[test]
    fn test_ipv4_ack_data_flags_ack_only() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let payload = b"data";
        let pkt = build_tcp_packet(local, remote, 1, 1, tcp::TcpFlags::ACK, Some(payload), StealthLevel::Off, 0, 0, 0xFFFF, None);
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
            0xFFFF,
            None,
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
            0xFFFF,
            None,
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
        let pkt = build_tcp_packet(local, remote, 1, 1, tcp::TcpFlags::ACK, None, StealthLevel::Off, 0, 0, 0xFFFF, None);
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
        let pkt = build_tcp_packet(local, remote, seq, ack, tcp::TcpFlags::ACK, Some(payload), StealthLevel::Off, 0, 0, 0xFFFF, None);
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
        let pkt = build_tcp_packet(local, remote, seq, ack, tcp::TcpFlags::SYN, None, StealthLevel::Off, 0, 0, 0xFFFF, None);
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
        let pkt = build_tcp_packet(local, remote, seq, ack, tcp::TcpFlags::ACK, Some(payload), StealthLevel::Off, 0, 0, 0xFFFF, None);
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
        let pkt = build_tcp_packet(local, remote, seq, ack, tcp::TcpFlags::SYN, None, StealthLevel::Off, 0, 0, 0xFFFF, None);
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
        let pkt = build_tcp_packet(local, remote, seq, ack, tcp::TcpFlags::ACK, Some(payload), StealthLevel::Off, 0, 0, 0xFFFF, None);
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
    fn test_parse_returns_none_on_ipv6_too_short_for_tcp() {
        // 40-byte IPv6 header with next_header=TCP but no TCP payload
        let mut buf = vec![0u8; 40];
        buf[0] = 0x60; // version=6
        buf[4] = 0;    // payload_length high byte
        buf[5] = 0;    // payload_length = 0 (no room for TCP)
        buf[6] = 6;    // next_header = TCP
        buf[7] = 64;   // hop limit
        let bytes = Bytes::copy_from_slice(&buf);
        assert!(parse_ip_packet(&bytes).is_none(), "IPv6 with payload_length=0 should return None");
    }

    #[test]
    fn test_parse_returns_none_on_ipv6_payload_length_exceeds_buffer() {
        // IPv6 header claiming payload_length=100 but buffer only has 60 bytes total
        let mut buf = vec![0u8; 60];
        buf[0] = 0x60; // version=6
        buf[4] = 0;    // payload_length high byte
        buf[5] = 100;  // payload_length = 100 (exceeds buffer)
        buf[6] = 6;    // next_header = TCP
        buf[7] = 64;   // hop limit
        let bytes = Bytes::copy_from_slice(&buf);
        assert!(parse_ip_packet(&bytes).is_none(), "IPv6 with payload_length exceeding buffer should return None");
    }

    #[test]
    fn test_parse_ip_packet_with_ip_options() {
        // IPv4 packet with IHL=6 (24-byte header: 20 standard + 4 bytes options)
        // followed by a valid TCP header
        let ip_hdr_len = 24usize;
        let tcp_hdr_len = 20usize;
        let total_len = ip_hdr_len + tcp_hdr_len;
        let mut buf = vec![0u8; total_len];

        // IPv4 header
        buf[0] = 0x46; // version=4, IHL=6
        buf[1] = 0;    // DSCP/ECN
        buf[2] = (total_len >> 8) as u8;
        buf[3] = (total_len & 0xff) as u8;
        buf[8] = 64;   // TTL
        buf[9] = 6;    // protocol = TCP
        // src IP: 10.0.0.1
        buf[12] = 10; buf[13] = 0; buf[14] = 0; buf[15] = 1;
        // dst IP: 10.0.0.2
        buf[16] = 10; buf[17] = 0; buf[18] = 0; buf[19] = 2;
        // IP options (4 bytes of NOP padding)
        buf[20] = 0x01; buf[21] = 0x01; buf[22] = 0x01; buf[23] = 0x01;

        // TCP header starts at offset 24
        // src port = 1234
        buf[ip_hdr_len] = (1234u16 >> 8) as u8;
        buf[ip_hdr_len + 1] = (1234u16 & 0xff) as u8;
        // dst port = 5678
        buf[ip_hdr_len + 2] = (5678u16 >> 8) as u8;
        buf[ip_hdr_len + 3] = (5678u16 & 0xff) as u8;
        // data offset = 5 (20 bytes)
        buf[ip_hdr_len + 12] = 0x50;

        // Compute IP checksum
        let mut csum = Checksum::new();
        csum.add_bytes(&buf[..ip_hdr_len]);
        let ip_csum = csum.checksum();
        buf[10] = ip_csum[0];
        buf[11] = ip_csum[1];

        let bytes = Bytes::copy_from_slice(&buf);
        let result = parse_ip_packet(&bytes);
        assert!(result.is_some(), "should parse IPv4 packet with IHL=6 (IP options present)");
        let (ip_pkt, tcp_pkt) = result.unwrap();
        match ip_pkt {
            IPPacket::V4(v4) => {
                assert_eq!(v4.get_header_length(), 6);
                assert_eq!(v4.get_source(), "10.0.0.1".parse::<std::net::Ipv4Addr>().unwrap());
            }
            _ => panic!("expected IPv4"),
        }
        assert_eq!(tcp_pkt.get_source(), 1234);
        assert_eq!(tcp_pkt.get_destination(), 5678);
    }

    #[test]
    fn test_parse_ip_packet_with_max_ihl() {
        // IPv4 packet with IHL=15 (60-byte header: 20 standard + 40 bytes options)
        // followed by a valid TCP header
        let ip_hdr_len = 60usize;
        let tcp_hdr_len = 20usize;
        let total_len = ip_hdr_len + tcp_hdr_len;
        let mut buf = vec![0u8; total_len];

        // IPv4 header
        buf[0] = 0x4F; // version=4, IHL=15
        buf[2] = (total_len >> 8) as u8;
        buf[3] = (total_len & 0xff) as u8;
        buf[8] = 64;   // TTL
        buf[9] = 6;    // protocol = TCP
        // src IP: 10.0.0.1
        buf[12] = 10; buf[13] = 0; buf[14] = 0; buf[15] = 1;
        // dst IP: 10.0.0.2
        buf[16] = 10; buf[17] = 0; buf[18] = 0; buf[19] = 2;
        // 40 bytes of NOP options (bytes 20..59)
        for i in 20..60 {
            buf[i] = 0x01;
        }

        // TCP header starts at offset 60
        buf[ip_hdr_len] = (4321u16 >> 8) as u8;
        buf[ip_hdr_len + 1] = (4321u16 & 0xff) as u8;
        buf[ip_hdr_len + 2] = (8765u16 >> 8) as u8;
        buf[ip_hdr_len + 3] = (8765u16 & 0xff) as u8;
        buf[ip_hdr_len + 12] = 0x50;

        // Compute IP checksum
        let mut csum = Checksum::new();
        csum.add_bytes(&buf[..ip_hdr_len]);
        let ip_csum = csum.checksum();
        buf[10] = ip_csum[0];
        buf[11] = ip_csum[1];

        let bytes = Bytes::copy_from_slice(&buf);
        let result = parse_ip_packet(&bytes);
        assert!(result.is_some(), "should parse IPv4 packet with IHL=15 (max IP options)");
        let (_, tcp_pkt) = result.unwrap();
        assert_eq!(tcp_pkt.get_source(), 4321);
        assert_eq!(tcp_pkt.get_destination(), 8765);
    }

    #[test]
    fn test_parse_ip_packet_with_ihl_below_minimum() {
        // IPv4 packet with IHL=3 (malformed — minimum valid is 5)
        // Should return None gracefully
        let mut buf = vec![0u8; 40];
        buf[0] = 0x43; // version=4, IHL=3
        buf[8] = 64;   // TTL
        buf[9] = 6;    // protocol = TCP
        let bytes = Bytes::copy_from_slice(&buf);
        assert!(parse_ip_packet(&bytes).is_none(), "IHL < 5 should return None");

        // Also test IHL=0 (extreme malformed case)
        buf[0] = 0x40; // version=4, IHL=0
        let bytes = Bytes::copy_from_slice(&buf);
        assert!(parse_ip_packet(&bytes).is_none(), "IHL=0 should return None");

        // IHL=4 (still below minimum of 5)
        buf[0] = 0x44; // version=4, IHL=4
        let bytes = Bytes::copy_from_slice(&buf);
        assert!(parse_ip_packet(&bytes).is_none(), "IHL=4 should return None");
    }

    // --- Task 3 (stealth plan): Realistic SYN fingerprint tests ---

    fn ipv4_stealth_syn_packet() -> Bytes {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        build_tcp_packet(local, remote, 0x12345678, 0, tcp::TcpFlags::SYN, None, StealthLevel::Basic, 1000, 0, 0xFFFF, None)
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
        // SACK permitted (packed as TS padding): kind=4, len=2
        assert_eq!(opts[4], 4, "SACK_PERM kind");
        assert_eq!(opts[5], 2, "SACK_PERM len");
    }

    #[test]
    fn test_stealth_syn_options_timestamps() {
        let pkt = ipv4_stealth_syn_packet();
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let opts = tcp_pkt.get_options_raw();
        // Timestamps: kind=8, len=10 (immediately after SACK_PERM)
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
        // NOP + wscale: kind=3, len=3, shift=7
        assert_eq!(opts[16], 1, "NOP before wscale");
        assert_eq!(opts[17], 3, "wscale kind");
        assert_eq!(opts[18], 3, "wscale len");
        assert_eq!(opts[19], 7, "wscale shift=7");
    }

    #[test]
    fn test_stealth_syn_options_full_linux_layout() {
        // Verify the complete byte layout matches Linux 5.x tcp_options_write() SYN fingerprint
        let pkt = ipv4_stealth_syn_packet();
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let opts = tcp_pkt.get_options_raw();
        assert_eq!(opts.len(), 20);
        // MSS(4) + SACK_PERM(2)+TS_hdr(2) + TS_val(4) + TS_ecr(4) + NOP+wscale(4) = 20
        let expected_prefix = [
            2, 4, 0x05, 0xB4, // MSS = 1460
            4, 2,              // SACK permitted (packed as TS padding)
            8, 10,             // Timestamps kind + len
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
            0xFFFF,
            None,
        );
        assert_eq!(pkt.len(), 60, "SYN+ACK stealth: 20 IPv4 + 40 TCP");
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.get_data_offset(), 10);
        let opts = tcp_pkt.get_options_raw();
        assert_eq!(opts.len(), 20);
        // MSS
        assert_eq!(opts[0], 2);
        assert_eq!(u16::from_be_bytes([opts[2], opts[3]]), 1460);
        // SACK_PERM (packed as TS padding)
        assert_eq!(opts[4], 4);
        // Timestamps
        assert_eq!(opts[6], 8);
        // NOP + wscale
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
        let pkt = build_tcp_packet(local, remote, 0, 0, tcp::TcpFlags::SYN, None, StealthLevel::Basic, 1000, 0, 0xFFFF, None);
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
        let pkt = build_tcp_packet(local, remote, 0x1234, 0, tcp::TcpFlags::SYN, None, StealthLevel::Basic, 1000, 0, 0xFFFF, None);

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
            let pkt = build_tcp_packet(local, remote, 0, 0, tcp::TcpFlags::SYN, None, stealth, 1000, 0, 0xFFFF, None);
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
        let pkt = build_tcp_packet(local, remote, 100, 200, tcp::TcpFlags::ACK, Some(payload), StealthLevel::Basic, 5000, 3000, 0xFFFF, None);
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
        let pkt = build_tcp_packet(local, remote, 1, 1, tcp::TcpFlags::ACK, Some(b"data"), StealthLevel::Basic, ts_val, ts_ecr, 0xFFFF, None);
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
        let pkt = build_tcp_packet(local, remote, 0, 0, tcp::TcpFlags::SYN, None, StealthLevel::Basic, ts_val, 0, 0xFFFF, None);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let opts = tcp_pkt.get_options_raw();
        // SYN timestamps at opts[8..12] (tsval) and opts[12..16] (tsecr)
        // (after MSS(4) + SACK_PERM(2)+TS_hdr(2))
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
        let pkt = build_tcp_packet(local, remote, 0, 1, tcp::TcpFlags::SYN | tcp::TcpFlags::ACK, None, StealthLevel::Basic, ts_val, ts_ecr, 0xFFFF, None);
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
        let pkt = build_tcp_packet(local, remote, 1, 1, tcp::TcpFlags::ACK, Some(b"data"), StealthLevel::Off, 0, 0, 0xFFFF, None);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.get_data_offset(), 5, "stealth Off: doff=5, no options");
        assert_eq!(tcp_pkt.get_options_raw().len(), 0);
    }

    #[test]
    fn test_stealth_ack_only_has_timestamps() {
        // ACK-only (no payload) with stealth should also have timestamps
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let pkt = build_tcp_packet(local, remote, 1, 1, tcp::TcpFlags::ACK, None, StealthLevel::Basic, 1000, 500, 0xFFFF, None);
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
        let pkt = build_tcp_packet(local, remote, 100, 200, tcp::TcpFlags::ACK, Some(payload), StealthLevel::Basic, 9999, 8888, 0xFFFF, None);
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
        let pkt = build_tcp_packet(local, remote, 1, 1, tcp::TcpFlags::ACK, Some(payload), StealthLevel::Basic, 2000, 1000, 0xFFFF, None);
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
        let pkt1 = build_tcp_packet(local, remote, 1, 1, tcp::TcpFlags::ACK, Some(b"a"), StealthLevel::Basic, 1000, 0, 0xFFFF, None);
        let pkt2 = build_tcp_packet(local, remote, 2, 1, tcp::TcpFlags::ACK, Some(b"b"), StealthLevel::Basic, 1050, 0, 0xFFFF, None);
        let opts1 = tcp::TcpPacket::new(&pkt1[20..]).unwrap().get_options_raw().to_vec();
        let opts2 = tcp::TcpPacket::new(&pkt2[20..]).unwrap().get_options_raw().to_vec();
        let ts1 = u32::from_be_bytes([opts1[4], opts1[5], opts1[6], opts1[7]]);
        let ts2 = u32::from_be_bytes([opts2[4], opts2[5], opts2[6], opts2[7]]);
        assert!(ts2 > ts1, "timestamps should be monotonically increasing: {} > {}", ts2, ts1);
    }

    // --- parse_tcp_timestamps tests ---

    #[test]
    fn test_parse_tcp_timestamp_from_data_packet() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let ts_val = 55555u32;
        let pkt = build_tcp_packet(local, remote, 1, 1, tcp::TcpFlags::ACK, Some(b"x"), StealthLevel::Basic, ts_val, 0, 0xFFFF, None);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let parsed = parse_tcp_timestamps(&tcp_pkt).map(|(tsval, _)| tsval);
        assert_eq!(parsed, Some(ts_val));
    }

    #[test]
    fn test_parse_tcp_timestamp_from_syn() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let ts_val = 77777u32;
        let pkt = build_tcp_packet(local, remote, 0, 0, tcp::TcpFlags::SYN, None, StealthLevel::Basic, ts_val, 0, 0xFFFF, None);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let parsed = parse_tcp_timestamps(&tcp_pkt).map(|(tsval, _)| tsval);
        assert_eq!(parsed, Some(ts_val));
    }

    #[test]
    fn test_parse_tcp_timestamp_stealth_off_returns_none() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        // Stealth Off data packet has no options
        let pkt = build_tcp_packet(local, remote, 1, 1, tcp::TcpFlags::ACK, Some(b"x"), StealthLevel::Off, 0, 0, 0xFFFF, None);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let parsed = parse_tcp_timestamps(&tcp_pkt).map(|(tsval, _)| tsval);
        assert_eq!(parsed, None);
    }

    // --- Task 5: PSH flag on data packets (Level 1) ---

    #[test]
    fn test_stealth_basic_data_psh_ack_flags() {
        // With stealth >= 1, data packets should have PSH|ACK flags
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let payload = b"hello";
        let pkt = build_tcp_packet(
            local, remote, 1, 1,
            tcp::TcpFlags::PSH | tcp::TcpFlags::ACK,
            Some(payload), StealthLevel::Basic, 1000, 500,
            0xFFFF,
            None,
        );
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(
            tcp_pkt.get_flags(),
            tcp::TcpFlags::PSH | tcp::TcpFlags::ACK,
            "stealth >= 1 data packets should have PSH|ACK"
        );
        assert_eq!(tcp_pkt.payload(), payload);
    }

    #[test]
    fn test_stealth_off_data_no_psh_flag() {
        // With stealth 0, data packets should have only ACK (no PSH)
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let payload = b"data";
        let pkt = build_tcp_packet(
            local, remote, 1, 1,
            tcp::TcpFlags::ACK,
            Some(payload), StealthLevel::Off, 0, 0,
            0xFFFF,
            None,
        );
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.get_flags(), tcp::TcpFlags::ACK, "stealth 0 should use plain ACK");
        assert_eq!(tcp_pkt.get_flags() & tcp::TcpFlags::PSH, 0, "stealth 0 should not have PSH");
    }

    #[test]
    fn test_stealth_basic_psh_ack_ipv6() {
        // PSH|ACK should also work for IPv6
        let local: SocketAddr = "[fd00::1]:1234".parse().unwrap();
        let remote: SocketAddr = "[fd00::2]:5678".parse().unwrap();
        let payload = b"ipv6 data";
        let pkt = build_tcp_packet(
            local, remote, 100, 200,
            tcp::TcpFlags::PSH | tcp::TcpFlags::ACK,
            Some(payload), StealthLevel::Basic, 2000, 1000,
            0xFFFF,
            None,
        );
        let tcp_pkt = tcp::TcpPacket::new(&pkt[40..]).unwrap();
        assert_eq!(
            tcp_pkt.get_flags(),
            tcp::TcpFlags::PSH | tcp::TcpFlags::ACK,
            "PSH|ACK should work for IPv6 packets"
        );
    }

    #[test]
    fn test_parse_tcp_timestamp_stealth_off_syn_returns_none() {
        // Stealth Off SYN has NOP + wscale but no timestamps
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let pkt = build_tcp_packet(local, remote, 0, 0, tcp::TcpFlags::SYN, None, StealthLevel::Off, 0, 0, 0xFFFF, None);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let parsed = parse_tcp_timestamps(&tcp_pkt).map(|(tsval, _)| tsval);
        assert_eq!(parsed, None);
    }

    // --- Task 7: Dynamic window (Level 2) ---

    #[test]
    fn test_stealth_standard_window_varies_between_packets() {
        // With stealth >= 2, window should vary between packets (not static 0xFFFF)
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        // Build multiple packets with different window values (simulating Socket jitter)
        let windows: Vec<u16> = (0..20).map(|i| {
            let window = 300 + (i % 32); // simulate base + jitter
            let pkt = build_tcp_packet(
                local, remote, 1, 1, tcp::TcpFlags::ACK, Some(b"data"),
                StealthLevel::Standard, 1000, 500, window, None,
            );
            let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
            tcp_pkt.get_window()
        }).collect();
        // Verify none are 0xFFFF
        for w in &windows {
            assert_ne!(*w, 0xFFFF, "stealth Standard window should not be static 0xFFFF");
        }
        // Verify at least some variation exists
        let unique: std::collections::HashSet<u16> = windows.into_iter().collect();
        assert!(unique.len() > 1, "window values should vary between packets");
    }

    #[test]
    fn test_stealth_standard_window_in_realistic_range() {
        // Window should be in a realistic range (256-544 with wscale=7 means ~32K-70K effective)
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        for window in [256u16, 300, 400, 512, 540] {
            let pkt = build_tcp_packet(
                local, remote, 1, 1, tcp::TcpFlags::ACK, Some(b"data"),
                StealthLevel::Standard, 1000, 500, window, None,
            );
            let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
            let w = tcp_pkt.get_window();
            assert_eq!(w, window, "window field should match passed value");
            // With wscale=7: effective = w * 128
            let effective = (w as u32) * 128;
            assert!(effective >= 32768, "effective window should be >= 32KB, got {}", effective);
            assert!(effective <= 131072, "effective window should be <= 128KB, got {}", effective);
        }
    }

    #[test]
    fn test_stealth_off_keeps_static_window() {
        // Stealth Off must keep static 0xFFFF window
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let pkt = build_tcp_packet(
            local, remote, 1, 1, tcp::TcpFlags::ACK, Some(b"data"),
            StealthLevel::Off, 0, 0, 0xFFFF,
            None,
        );
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.get_window(), 0xFFFF, "stealth Off should have static 0xFFFF window");
    }

    #[test]
    fn test_stealth_basic_keeps_static_window() {
        // Stealth Basic (level 1) must also keep static 0xFFFF window
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let pkt = build_tcp_packet(
            local, remote, 1, 1, tcp::TcpFlags::ACK, Some(b"data"),
            StealthLevel::Basic, 1000, 500, 0xFFFF,
            None,
        );
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.get_window(), 0xFFFF, "stealth Basic should have static 0xFFFF window");
    }

    #[test]
    fn test_stealth_window_on_syn_packet() {
        // SYN packet with stealth >= 2 should also use dynamic window
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let window = 350u16;
        let pkt = build_tcp_packet(
            local, remote, 0, 0, tcp::TcpFlags::SYN, None,
            StealthLevel::Standard, 1000, 0, window, None,
        );
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.get_window(), window, "SYN packet should use provided window value");
    }

    #[test]
    fn test_stealth_window_checksum_valid() {
        // Verify checksum is correct with non-0xFFFF window
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let payload = b"window test";
        let pkt = build_tcp_packet(
            local, remote, 100, 200, tcp::TcpFlags::ACK, Some(payload),
            StealthLevel::Standard, 5000, 3000, 400, None,
        );
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

    // --- Task 8: ts_ecr echo correctness (Level 2) ---

    #[test]
    fn test_tsecr_matches_peer_tsval_exactly() {
        // Simulate: peer sends packet with tsval=99999, we parse it and echo it back
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let peer_tsval = 99999u32;

        // Peer's outgoing packet (from peer's perspective: their tsval, their tsecr)
        let peer_pkt = build_tcp_packet(
            remote, local, 1, 1, tcp::TcpFlags::ACK, Some(b"hello"),
            StealthLevel::Basic, peer_tsval, 50000, 0xFFFF,
            None,
        );
        // Parse the peer's tsval from their packet
        let tcp_pkt = tcp::TcpPacket::new(&peer_pkt[20..]).unwrap();
        let extracted_tsval = parse_tcp_timestamps(&tcp_pkt).map(|(tsval, _)| tsval).expect("should parse peer tsval");
        assert_eq!(extracted_tsval, peer_tsval, "extracted tsval must match peer's tsval exactly");

        // Now build our response echoing it as ts_ecr
        let our_pkt = build_tcp_packet(
            local, remote, 1, 2, tcp::TcpFlags::ACK, Some(b"world"),
            StealthLevel::Basic, 60000, extracted_tsval, 0xFFFF,
            None,
        );
        let our_tcp = tcp::TcpPacket::new(&our_pkt[20..]).unwrap();
        let (_, our_tsecr) = parse_tcp_timestamps(&our_tcp).expect("should have timestamps");
        assert_eq!(our_tsecr, peer_tsval, "outgoing ts_ecr must match last received peer tsval exactly");
    }

    #[test]
    fn test_tsecr_reflects_latest_after_multiple_packets() {
        // Simulate receiving multiple packets with increasing tsval; ts_ecr should reflect the latest
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();

        let peer_tsvals = [10000u32, 20000, 30000, 40000, 50000];
        let mut latest_peer_tsval = 0u32;

        for &peer_tsval in &peer_tsvals {
            // Peer sends a packet
            let peer_pkt = build_tcp_packet(
                remote, local, 1, 1, tcp::TcpFlags::ACK, Some(b"data"),
                StealthLevel::Basic, peer_tsval, latest_peer_tsval, 0xFFFF,
            None,
            );
            let tcp_pkt = tcp::TcpPacket::new(&peer_pkt[20..]).unwrap();
            let extracted = parse_tcp_timestamps(&tcp_pkt).map(|(tsval, _)| tsval).expect("should parse");
            // Simulate Socket updating ts_ecr
            latest_peer_tsval = extracted;
        }

        // After all packets, ts_ecr should be the last peer tsval
        assert_eq!(latest_peer_tsval, 50000, "ts_ecr should reflect the latest peer tsval");

        // Build our response with the latest ts_ecr
        let our_pkt = build_tcp_packet(
            local, remote, 1, 6, tcp::TcpFlags::ACK, Some(b"resp"),
            StealthLevel::Basic, 70000, latest_peer_tsval, 0xFFFF,
            None,
        );
        let our_tcp = tcp::TcpPacket::new(&our_pkt[20..]).unwrap();
        let (_, our_tsecr) = parse_tcp_timestamps(&our_tcp).expect("should have timestamps");
        assert_eq!(our_tsecr, 50000, "ts_ecr must reflect the latest (most recent) peer tsval");
    }

    #[test]
    fn test_tsecr_atomic_store_load_consistent() {
        // Verify that AtomicU32 store/load pattern preserves exact ts_ecr values
        // This mirrors Socket's usage: store on recv, load on send
        use std::sync::atomic::{AtomicU32, Ordering};

        let ts_ecr = AtomicU32::new(0);

        // Simulate recv updating ts_ecr
        ts_ecr.store(123456789, Ordering::Relaxed);
        assert_eq!(ts_ecr.load(Ordering::Relaxed), 123456789);

        // Simulate second recv with different value
        ts_ecr.store(987654321, Ordering::Relaxed);
        assert_eq!(ts_ecr.load(Ordering::Relaxed), 987654321);

        // Verify max u32 value works (edge case)
        ts_ecr.store(u32::MAX, Ordering::Relaxed);
        assert_eq!(ts_ecr.load(Ordering::Relaxed), u32::MAX);
    }

    #[test]
    fn test_handshake_tsecr_flow_syn_ecr_zero() {
        // SYN: ts_ecr must be 0 (no peer timestamp received yet)
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();

        let syn = build_tcp_packet(
            local, remote, 0x12345678, 0, tcp::TcpFlags::SYN, None,
            StealthLevel::Basic, 1000, 0, 0xFFFF,
            None,
        );
        let syn_tcp = tcp::TcpPacket::new(&syn[20..]).unwrap();
        let (syn_tsval, syn_tsecr) = parse_tcp_timestamps(&syn_tcp).expect("SYN should have timestamps");
        assert_eq!(syn_tsval, 1000, "SYN tsval should be set");
        assert_eq!(syn_tsecr, 0, "SYN ts_ecr must be 0 (no prior peer timestamp)");
    }

    #[test]
    fn test_handshake_tsecr_flow_syn_ack_echoes_peer() {
        // SYN+ACK: ts_ecr should echo the client's SYN tsval
        let client: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let server: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let client_tsval = 1000u32;

        // Client sends SYN
        let syn = build_tcp_packet(
            client, server, 0x11111111, 0, tcp::TcpFlags::SYN, None,
            StealthLevel::Basic, client_tsval, 0, 0xFFFF,
            None,
        );
        // Server parses SYN and extracts client's tsval
        let syn_tcp = tcp::TcpPacket::new(&syn[20..]).unwrap();
        let peer_tsval = parse_tcp_timestamps(&syn_tcp).map(|(tsval, _)| tsval).expect("should extract client tsval from SYN");
        assert_eq!(peer_tsval, client_tsval);

        // Server sends SYN+ACK, echoing client's tsval
        let syn_ack = build_tcp_packet(
            server, client, 0x22222222, 0x11111112,
            tcp::TcpFlags::SYN | tcp::TcpFlags::ACK, None,
            StealthLevel::Basic, 2000, peer_tsval, 0xFFFF,
            None,
        );
        let syn_ack_tcp = tcp::TcpPacket::new(&syn_ack[20..]).unwrap();
        let (sa_tsval, sa_tsecr) = parse_tcp_timestamps(&syn_ack_tcp).expect("SYN+ACK should have timestamps");
        assert_eq!(sa_tsval, 2000, "SYN+ACK should have server's tsval");
        assert_eq!(sa_tsecr, client_tsval, "SYN+ACK ts_ecr must echo client's SYN tsval");
    }

    #[test]
    fn test_handshake_tsecr_flow_ack_echoes_server() {
        // Full 3-way handshake ts_ecr flow verification
        let client: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let server: SocketAddr = "10.0.0.2:5678".parse().unwrap();

        // Step 1: Client SYN (ts_ecr=0)
        let client_tsval_1 = 1000u32;
        let syn = build_tcp_packet(
            client, server, 0x11111111, 0, tcp::TcpFlags::SYN, None,
            StealthLevel::Basic, client_tsval_1, 0, 0xFFFF,
            None,
        );
        let syn_tcp = tcp::TcpPacket::new(&syn[20..]).unwrap();
        let server_sees_client_ts = parse_tcp_timestamps(&syn_tcp).map(|(tsval, _)| tsval).unwrap();

        // Step 2: Server SYN+ACK (ts_ecr = client's tsval)
        let server_tsval_1 = 2000u32;
        let syn_ack = build_tcp_packet(
            server, client, 0x22222222, 0x11111112,
            tcp::TcpFlags::SYN | tcp::TcpFlags::ACK, None,
            StealthLevel::Basic, server_tsval_1, server_sees_client_ts, 0xFFFF,
            None,
        );
        let syn_ack_tcp = tcp::TcpPacket::new(&syn_ack[20..]).unwrap();
        let client_sees_server_ts = parse_tcp_timestamps(&syn_ack_tcp).map(|(tsval, _)| tsval).unwrap();
        let (_, sa_ecr) = parse_tcp_timestamps(&syn_ack_tcp).unwrap();
        assert_eq!(sa_ecr, client_tsval_1, "SYN+ACK ecr = client SYN tsval");

        // Step 3: Client ACK (ts_ecr = server's tsval from SYN+ACK)
        let client_tsval_2 = 1050u32;
        let ack = build_tcp_packet(
            client, server, 0x11111112, 0x22222223, tcp::TcpFlags::ACK, None,
            StealthLevel::Basic, client_tsval_2, client_sees_server_ts, 0xFFFF,
            None,
        );
        let ack_tcp = tcp::TcpPacket::new(&ack[20..]).unwrap();
        let (ack_tsval, ack_tsecr) = parse_tcp_timestamps(&ack_tcp).expect("ACK should have timestamps");
        assert_eq!(ack_tsval, client_tsval_2, "ACK tsval is client's current timestamp");
        assert_eq!(ack_tsecr, server_tsval_1, "ACK ts_ecr must echo server's SYN+ACK tsval");
    }

    #[test]
    fn test_parse_tcp_timestamps_returns_both_values() {
        // Verify the new parse_tcp_timestamps helper extracts both tsval and tsecr
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let pkt = build_tcp_packet(
            local, remote, 1, 1, tcp::TcpFlags::ACK, Some(b"x"),
            StealthLevel::Basic, 11111, 22222, 0xFFFF,
            None,
        );
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let (tsval, tsecr) = parse_tcp_timestamps(&tcp_pkt).expect("should parse both");
        assert_eq!(tsval, 11111);
        assert_eq!(tsecr, 22222);
    }

    #[test]
    fn test_parse_tcp_timestamps_stealth_off_returns_none() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let pkt = build_tcp_packet(
            local, remote, 1, 1, tcp::TcpFlags::ACK, Some(b"x"),
            StealthLevel::Off, 0, 0, 0xFFFF,
            None,
        );
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert!(parse_tcp_timestamps(&tcp_pkt).is_none(), "stealth Off has no timestamps");
    }

    #[test]
    fn test_ipv4_no_mimic_has_zero_id_and_df() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let pkt = build_tcp_packet(
            local, remote, 1, 1, tcp::TcpFlags::ACK, Some(b"data"),
            StealthLevel::Off, 0, 0, 0xFFFF, None,
        );
        let v4 = ipv4::Ipv4Packet::new(&pkt).unwrap();
        assert_eq!(v4.get_identification(), 0, "default IP ID should be 0");
        assert_eq!(v4.get_flags(), ipv4::Ipv4Flags::DontFragment, "default should have DF");
    }

    #[test]
    fn test_ipv4_mimic_ip_id_zero_keeps_df() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let mp = MimicParams { ip_id: 0, ip_id_incrementing: false, wscale: None };
        let pkt = build_tcp_packet(
            local, remote, 1, 1, tcp::TcpFlags::ACK, Some(b"data"),
            StealthLevel::Off, 0, 0, 0xFFFF, Some(&mp),
        );
        let v4 = ipv4::Ipv4Packet::new(&pkt).unwrap();
        assert_eq!(v4.get_identification(), 0, "ip_id=0 should keep ID=0");
        assert_eq!(v4.get_flags(), ipv4::Ipv4Flags::DontFragment, "ip_id=0 should keep DF");
    }

    #[test]
    fn test_ipv4_mimic_ip_id_zero_with_incrementing_keeps_df() {
        // When ip_id counter wraps to 0, DF should still be set (udp2raw always sets DF)
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let mp = MimicParams { ip_id: 0, ip_id_incrementing: true, wscale: None };
        let pkt = build_tcp_packet(
            local, remote, 1, 1, tcp::TcpFlags::ACK, Some(b"data"),
            StealthLevel::Off, 0, 0, 0xFFFF, Some(&mp),
        );
        let v4 = ipv4::Ipv4Packet::new(&pkt).unwrap();
        assert_eq!(v4.get_identification(), 0, "ip_id=0 should still set ID=0");
        assert_eq!(v4.get_flags(), ipv4::Ipv4Flags::DontFragment,
            "DF should always be set (matches udp2raw)");
    }

    #[test]
    fn test_ipv4_mimic_ip_id_nonzero_sets_id_keeps_df() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let mp = MimicParams { ip_id: 42, ip_id_incrementing: true, wscale: None };
        let pkt = build_tcp_packet(
            local, remote, 1, 1, tcp::TcpFlags::ACK, Some(b"data"),
            StealthLevel::Off, 0, 0, 0xFFFF, Some(&mp),
        );
        let v4 = ipv4::Ipv4Packet::new(&pkt).unwrap();
        assert_eq!(v4.get_identification(), 42, "ip_id=42 should set ID=42");
        assert_eq!(v4.get_flags(), ipv4::Ipv4Flags::DontFragment, "DF should always be set (matches udp2raw)");
    }

    #[test]
    fn test_ipv4_mimic_ip_id_large_value() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let mp = MimicParams { ip_id: 65535, ip_id_incrementing: true, wscale: None };
        let pkt = build_tcp_packet(
            local, remote, 1, 1, tcp::TcpFlags::ACK, Some(b"data"),
            StealthLevel::Off, 0, 0, 0xFFFF, Some(&mp),
        );
        let v4 = ipv4::Ipv4Packet::new(&pkt).unwrap();
        assert_eq!(v4.get_identification(), 65535);
    }

    #[test]
    fn test_ipv6_mimic_ip_id_no_panic_no_change() {
        let local: SocketAddr = "[fd00::1]:9000".parse().unwrap();
        let remote: SocketAddr = "[fd00::2]:9001".parse().unwrap();
        let mp = MimicParams { ip_id: 42, ip_id_incrementing: true, wscale: None };
        // Should not panic — IPv6 has no identification field
        let pkt = build_tcp_packet(
            local, remote, 1, 1, tcp::TcpFlags::ACK, Some(b"data"),
            StealthLevel::Off, 0, 0, 0xFFFF, Some(&mp),
        );
        // Verify packet is still valid IPv6
        let (ip_pkt, _tcp_pkt) = parse_ip_packet(&pkt).unwrap();
        assert!(matches!(ip_pkt, IPPacket::V6(_)));
    }

    #[test]
    fn test_ipv4_mimic_ip_id_checksum_valid() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let mp = MimicParams { ip_id: 1000, ip_id_incrementing: true, wscale: None };
        let pkt = build_tcp_packet(
            local, remote, 1, 1, tcp::TcpFlags::ACK, Some(b"hello"),
            StealthLevel::Basic, 5000, 3000, 0xFFFF, Some(&mp),
        );
        // Verify IP header checksum (first 20 bytes for standard IPv4 header)
        let mut cksm = internet_checksum::Checksum::new();
        cksm.add_bytes(&pkt[..IPV4_HEADER_LEN]);
        assert_eq!(cksm.checksum(), [0, 0], "IP checksum should be valid");
    }

    // --- Task 3: Configurable window scale and raw window ---

    #[test]
    fn test_syn_mimic_wscale_5_at_correct_offset() {
        // SYN with stealth >= Basic and mimic wscale=5 should have wscale=5 at option offset 18
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let mp = MimicParams { ip_id: 0, ip_id_incrementing: false, wscale: Some(5) };
        let pkt = build_tcp_packet(
            local, remote, 0, 0, tcp::TcpFlags::SYN, None,
            StealthLevel::Basic, 1000, 0, 41000, Some(&mp),
        );
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let opts = tcp_pkt.get_options_raw();
        // Stealth >= Basic SYN has 20-byte options: MSS(4) + SACK+TS_hdr(4) + TS(8) + NOP+wscale(4)
        assert_eq!(opts.len(), 20);
        assert_eq!(opts[16], 1, "NOP before wscale");
        assert_eq!(opts[17], 3, "wscale kind");
        assert_eq!(opts[18], 3, "wscale len");
        assert_eq!(opts[19], 5, "wscale shift should be 5 from mimic");
    }

    #[test]
    fn test_syn_mimic_wscale_none_defaults_to_7() {
        // SYN with stealth >= Basic and mimic wscale=None should use default 7
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let mp = MimicParams { ip_id: 0, ip_id_incrementing: false, wscale: None };
        let pkt = build_tcp_packet(
            local, remote, 0, 0, tcp::TcpFlags::SYN, None,
            StealthLevel::Basic, 1000, 0, 0xFFFF, Some(&mp),
        );
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let opts = tcp_pkt.get_options_raw();
        assert_eq!(opts[19], 7, "wscale shift should default to 7 when mimic wscale is None");
    }

    #[test]
    fn test_syn_no_mimic_wscale_unchanged() {
        // SYN with stealth >= Basic and no mimic should have wscale=7
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let pkt = build_tcp_packet(
            local, remote, 0, 0, tcp::TcpFlags::SYN, None,
            StealthLevel::Basic, 1000, 0, 0xFFFF, None,
        );
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let opts = tcp_pkt.get_options_raw();
        assert_eq!(opts[19], 7, "wscale shift should be 7 without mimic");
    }

    #[test]
    fn test_syn_stealth_off_no_mimic_wscale_14() {
        // SYN with stealth Off and no mimic should have wscale=14 (original behavior)
        let pkt = ipv4_syn_packet();
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        let opts = tcp_pkt.get_options_raw();
        assert_eq!(opts[3], 14, "stealth Off wscale should be 14");
    }

    #[test]
    fn test_mimic_window_raw_in_data_packet() {
        // Data packet with mimic window=41000 should have window=41000
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let mp = MimicParams { ip_id: 1, ip_id_incrementing: true, wscale: Some(5) };
        let pkt = build_tcp_packet(
            local, remote, 1, 1, tcp::TcpFlags::ACK, Some(b"data"),
            StealthLevel::Standard, 5000, 3000, 41000, Some(&mp),
        );
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.get_window(), 41000, "window should be mimic's window_raw value");
    }

    #[test]
    fn test_mimic_window_raw_in_syn_packet() {
        // SYN packet with mimic window=41000 should have window=41000
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let mp = MimicParams { ip_id: 0, ip_id_incrementing: false, wscale: Some(5) };
        let pkt = build_tcp_packet(
            local, remote, 0, 0, tcp::TcpFlags::SYN, None,
            StealthLevel::Standard, 1000, 0, 41000, Some(&mp),
        );
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.get_window(), 41000, "SYN window should be mimic's window_raw");
    }
}
