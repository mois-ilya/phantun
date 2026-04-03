use bytes::{Bytes, BytesMut};
use internet_checksum::Checksum;
use pnet::packet::Packet;
use pnet::packet::{ip, ipv4, ipv6, tcp};
use std::convert::TryInto;
use std::net::{IpAddr, SocketAddr};

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

pub fn build_tcp_packet(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: Option<&[u8]>,
) -> Bytes {
    let ip_header_len = match local_addr {
        SocketAddr::V4(_) => IPV4_HEADER_LEN,
        SocketAddr::V6(_) => IPV6_HEADER_LEN,
    };
    let wscale = (flags & tcp::TcpFlags::SYN) != 0;
    let tcp_header_len = TCP_HEADER_LEN + if wscale { 4 } else { 0 }; // nop + wscale
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
    tcp.set_data_offset(TCP_HEADER_LEN as u8 / 4 + if wscale { 1 } else { 0 });
    if wscale {
        let wscale = tcp::TcpOption::wscale(14);
        tcp.set_options(&[tcp::TcpOption::nop(), wscale]);
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
        build_tcp_packet(local, remote, 0, 0, tcp::TcpFlags::SYN, None)
    }

    fn ipv6_syn_packet() -> Bytes {
        let local: SocketAddr = "[fd00::1]:1234".parse().unwrap();
        let remote: SocketAddr = "[fd00::2]:5678".parse().unwrap();
        build_tcp_packet(local, remote, 0, 0, tcp::TcpFlags::SYN, None)
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
        let pkt = build_tcp_packet(local, remote, seq, ack, tcp::TcpFlags::SYN, None);
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.get_sequence(), seq);
        assert_eq!(tcp_pkt.get_acknowledgement(), ack);
    }

    #[test]
    fn test_ipv4_syn_checksum_valid() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let pkt = build_tcp_packet(local, remote, 0, 0, tcp::TcpFlags::SYN, None);

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
        let pkt = build_tcp_packet(local, remote, seq, ack, tcp::TcpFlags::SYN, None);
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
        let pkt = build_tcp_packet(local, remote, 1, 1, tcp::TcpFlags::ACK, Some(payload));
        // 20 (IPv4) + 20 (TCP, no options) + 11 (payload) = 51
        assert_eq!(pkt.len(), 20 + 20 + payload.len());
    }

    #[test]
    fn test_ipv4_ack_data_doff_no_options_window() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let payload = b"data";
        let pkt = build_tcp_packet(local, remote, 1, 1, tcp::TcpFlags::ACK, Some(payload));
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
        let pkt = build_tcp_packet(local, remote, 42, 99, tcp::TcpFlags::ACK, Some(payload));
        let tcp_pkt = tcp::TcpPacket::new(&pkt[20..]).unwrap();
        assert_eq!(tcp_pkt.payload(), payload);
    }

    #[test]
    fn test_ipv4_ack_data_flags_ack_only() {
        let local: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:5678".parse().unwrap();
        let payload = b"data";
        let pkt = build_tcp_packet(local, remote, 1, 1, tcp::TcpFlags::ACK, Some(payload));
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
        let pkt = build_tcp_packet(local, remote, 1, 1, tcp::TcpFlags::ACK, None);
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
        let pkt = build_tcp_packet(local, remote, seq, ack, tcp::TcpFlags::ACK, Some(payload));
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
        let pkt = build_tcp_packet(local, remote, seq, ack, tcp::TcpFlags::SYN, None);
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
        let pkt = build_tcp_packet(local, remote, seq, ack, tcp::TcpFlags::ACK, Some(payload));
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
        let pkt = build_tcp_packet(local, remote, seq, ack, tcp::TcpFlags::SYN, None);
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
        let pkt = build_tcp_packet(local, remote, seq, ack, tcp::TcpFlags::ACK, Some(payload));
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
            )
        });
    }
}
