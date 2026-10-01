//! Minimal IPv4/IPv6 + TCP/UDP header handling: just enough to NAT-rewrite TCP
//! and to parse/build UDP datagrams. Everything else is dropped by the caller.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

const IPV4_HDR_MIN: usize = 20;
const IPV6_HDR: usize = 40;

#[derive(Debug, Clone, Copy)]
pub struct Parsed {
    pub proto: u8,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    /// Offset of the transport header.
    pub l4: usize,
    /// Offset one past the last byte of the IP datagram (packets may carry padding).
    pub end: usize,
}

impl Parsed {
    pub fn is_v4(&self) -> bool {
        self.src.is_ipv4()
    }
}

/// Parses an IP packet carrying TCP or UDP. Returns `None` for anything else,
/// including IPv4 fragments and IPv6 packets with extension headers.
pub fn parse(pkt: &[u8]) -> Option<Parsed> {
    match pkt.first()? >> 4 {
        4 => parse_v4(pkt),
        6 => parse_v6(pkt),
        _ => None,
    }
}

fn parse_v4(pkt: &[u8]) -> Option<Parsed> {
    if pkt.len() < IPV4_HDR_MIN {
        return None;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    let total = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if ihl < IPV4_HDR_MIN || total < ihl || total > pkt.len() {
        return None;
    }
    let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
    // MF flag set or non-zero fragment offset.
    if frag & 0x3fff != 0 {
        return None;
    }
    let proto = pkt[9];
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    finish(pkt, proto, IpAddr::V4(src), IpAddr::V4(dst), ihl, total)
}

fn parse_v6(pkt: &[u8]) -> Option<Parsed> {
    if pkt.len() < IPV6_HDR {
        return None;
    }
    let payload = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    let total = IPV6_HDR + payload;
    if total > pkt.len() {
        return None;
    }
    let proto = pkt[6];
    let src: [u8; 16] = pkt[8..24].try_into().ok()?;
    let dst: [u8; 16] = pkt[24..40].try_into().ok()?;
    finish(
        pkt,
        proto,
        IpAddr::V6(Ipv6Addr::from(src)),
        IpAddr::V6(Ipv6Addr::from(dst)),
        IPV6_HDR,
        total,
    )
}

fn finish(pkt: &[u8], proto: u8, src: IpAddr, dst: IpAddr, l4: usize, end: usize) -> Option<Parsed> {
    let min = match proto {
        PROTO_TCP => 20,
        PROTO_UDP => 8,
        _ => return None,
    };
    if end < l4 + min {
        return None;
    }
    let sport = u16::from_be_bytes([pkt[l4], pkt[l4 + 1]]);
    let dport = u16::from_be_bytes([pkt[l4 + 2], pkt[l4 + 3]]);
    Some(Parsed {
        proto,
        src: SocketAddr::new(src, sport),
        dst: SocketAddr::new(dst, dport),
        l4,
        end,
    })
}

pub fn tcp_flags(pkt: &[u8], p: &Parsed) -> u8 {
    pkt[p.l4 + 13]
}

pub const TCP_FIN: u8 = 0x01;
pub const TCP_RST: u8 = 0x04;

pub fn udp_payload<'a>(pkt: &'a [u8], p: &Parsed) -> &'a [u8] {
    &pkt[p.l4 + 8..p.end]
}

/// Rewrites source and destination of a TCP segment in place, patching the IPv4
/// header checksum and the TCP checksum incrementally (RFC 1624).
/// `new_src`/`new_dst` must be of the same family as the packet.
pub fn rewrite_tcp(pkt: &mut [u8], p: &Parsed, new_src: SocketAddr, new_dst: SocketAddr) {
    let l4 = p.l4;
    let mut tcp_csum = u16::from_be_bytes([pkt[l4 + 16], pkt[l4 + 17]]);

    match (p.src.ip(), p.dst.ip(), new_src.ip(), new_dst.ip()) {
        (IpAddr::V4(os), IpAddr::V4(od), IpAddr::V4(ns), IpAddr::V4(nd)) => {
            let mut ip_csum = u16::from_be_bytes([pkt[10], pkt[11]]);
            for (old, new, off) in [(os.octets(), ns.octets(), 12), (od.octets(), nd.octets(), 16)] {
                ip_csum = csum_replace(ip_csum, &old, &new);
                tcp_csum = csum_replace(tcp_csum, &old, &new);
                pkt[off..off + 4].copy_from_slice(&new);
            }
            pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());
        }
        (IpAddr::V6(os), IpAddr::V6(od), IpAddr::V6(ns), IpAddr::V6(nd)) => {
            for (old, new, off) in [(os.octets(), ns.octets(), 8), (od.octets(), nd.octets(), 24)] {
                tcp_csum = csum_replace(tcp_csum, &old, &new);
                pkt[off..off + 16].copy_from_slice(&new);
            }
        }
        _ => unreachable!("rewrite_tcp: address family mismatch"),
    }

    for (old, new, off) in [
        (p.src.port(), new_src.port(), l4),
        (p.dst.port(), new_dst.port(), l4 + 2),
    ] {
        tcp_csum = csum_replace(tcp_csum, &old.to_be_bytes(), &new.to_be_bytes());
        pkt[off..off + 2].copy_from_slice(&new.to_be_bytes());
    }
    pkt[l4 + 16..l4 + 18].copy_from_slice(&tcp_csum.to_be_bytes());
}

/// Builds a complete IP+UDP packet. Both addresses must be of the same family.
pub fn build_udp(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    let udp_len = 8 + payload.len();
    if udp_len > u16::MAX as usize {
        return None;
    }
    let mut udp = Vec::with_capacity(udp_len);
    udp.extend_from_slice(&src.port().to_be_bytes());
    udp.extend_from_slice(&dst.port().to_be_bytes());
    udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);

    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let total = IPV4_HDR_MIN + udp_len;
            if total > u16::MAX as usize {
                return None;
            }
            let mut out = Vec::with_capacity(total);
            out.extend_from_slice(&[0x45, 0]);
            out.extend_from_slice(&(total as u16).to_be_bytes());
            out.extend_from_slice(&[0, 0, 0x40, 0]); // id 0, DF
            out.extend_from_slice(&[64, PROTO_UDP, 0, 0]);
            out.extend_from_slice(&s.octets());
            out.extend_from_slice(&d.octets());
            let ip_csum = !fold(sum16(&out));
            out[10..12].copy_from_slice(&ip_csum.to_be_bytes());

            let mut sum = sum16(&s.octets()) + sum16(&d.octets());
            sum += PROTO_UDP as u32 + udp_len as u32;
            sum += sum16(&udp);
            let c = match !fold(sum) {
                0 => 0xffff,
                c => c,
            };
            udp[6..8].copy_from_slice(&c.to_be_bytes());
            out.extend_from_slice(&udp);
            Some(out)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut out = Vec::with_capacity(IPV6_HDR + udp_len);
            out.extend_from_slice(&[0x60, 0, 0, 0]);
            out.extend_from_slice(&(udp_len as u16).to_be_bytes());
            out.extend_from_slice(&[PROTO_UDP, 64]);
            out.extend_from_slice(&s.octets());
            out.extend_from_slice(&d.octets());

            let mut sum = sum16(&s.octets()) + sum16(&d.octets());
            sum += (udp_len as u32 >> 16) + (udp_len as u32 & 0xffff) + PROTO_UDP as u32;
            sum += sum16(&udp);
            let c = match !fold(sum) {
                0 => 0xffff,
                c => c,
            };
            udp[6..8].copy_from_slice(&c.to_be_bytes());
            out.extend_from_slice(&udp);
            Some(out)
        }
        _ => None,
    }
}

fn sum16(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    let (words, rest) = data.as_chunks::<2>();
    for w in words {
        sum += u16::from_be_bytes(*w) as u32;
    }
    if let [last] = rest {
        sum += (*last as u32) << 8;
    }
    sum
}

fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// RFC 1624 eqn. 3: HC' = ~(~HC + ~m + m'). `old` and `new` are word-aligned and of equal length.
fn csum_replace(csum: u16, old: &[u8], new: &[u8]) -> u16 {
    let mut sum = (!csum) as u32;
    for w in old.as_chunks::<2>().0 {
        sum += (!u16::from_be_bytes(*w)) as u32;
    }
    for w in new.as_chunks::<2>().0 {
        sum += u16::from_be_bytes(*w) as u32;
    }
    !fold(sum)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_tcp_csum(pkt: &[u8], p: &Parsed) -> u16 {
        let seg = &pkt[p.l4..p.end];
        let mut sum = match (p.src.ip(), p.dst.ip()) {
            (IpAddr::V4(s), IpAddr::V4(d)) => sum16(&s.octets()) + sum16(&d.octets()),
            (IpAddr::V6(s), IpAddr::V6(d)) => sum16(&s.octets()) + sum16(&d.octets()),
            _ => unreachable!(),
        };
        sum += PROTO_TCP as u32 + seg.len() as u32;
        let mut copy = seg.to_vec();
        copy[16] = 0;
        copy[17] = 0;
        sum += sum16(&copy);
        !fold(sum)
    }

    fn tcp_v4(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
        // Reuse the UDP builder for the IP header, then patch it into a TCP segment.
        let mut seg = vec![0u8; 20];
        seg[0..2].copy_from_slice(&src.port().to_be_bytes());
        seg[2..4].copy_from_slice(&dst.port().to_be_bytes());
        seg[4..8].copy_from_slice(&12345u32.to_be_bytes());
        seg[12] = 5 << 4;
        seg[13] = 0x02;
        seg[14..16].copy_from_slice(&65535u16.to_be_bytes());
        seg.extend_from_slice(payload);
        let total = 20 + seg.len();
        let mut pkt = vec![0x45, 0];
        pkt.extend_from_slice(&(total as u16).to_be_bytes());
        pkt.extend_from_slice(&[0, 1, 0x40, 0, 64, PROTO_TCP, 0, 0]);
        let (IpAddr::V4(s), IpAddr::V4(d)) = (src.ip(), dst.ip()) else { unreachable!() };
        pkt.extend_from_slice(&s.octets());
        pkt.extend_from_slice(&d.octets());
        let c = !fold(sum16(&pkt));
        pkt[10..12].copy_from_slice(&c.to_be_bytes());
        pkt.extend_from_slice(&seg);
        let p = parse(&pkt).unwrap();
        let c = full_tcp_csum(&pkt, &p);
        pkt[p.l4 + 16..p.l4 + 18].copy_from_slice(&c.to_be_bytes());
        pkt
    }

    #[test]
    fn rewrite_v4_keeps_checksums_valid() {
        let mut pkt = tcp_v4(
            "172.19.0.1:50123".parse().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
            b"hello world!",
        );
        let p = parse(&pkt).unwrap();
        rewrite_tcp(
            &mut pkt,
            &p,
            "172.19.0.2:1025".parse().unwrap(),
            "172.19.0.1:40000".parse().unwrap(),
        );
        let p2 = parse(&pkt).unwrap();
        assert_eq!(p2.src, "172.19.0.2:1025".parse().unwrap());
        assert_eq!(p2.dst, "172.19.0.1:40000".parse().unwrap());
        assert_eq!(fold(sum16(&pkt[..20])), 0xffff, "ip header checksum");
        let stored = u16::from_be_bytes([pkt[p2.l4 + 16], pkt[p2.l4 + 17]]);
        assert_eq!(stored, full_tcp_csum(&pkt, &p2));
    }

    #[test]
    fn udp_v4_roundtrip() {
        let src: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let dst: SocketAddr = "172.19.0.1:5555".parse().unwrap();
        let pkt = build_udp(src, dst, b"abc").unwrap();
        let p = parse(&pkt).unwrap();
        assert_eq!((p.proto, p.src, p.dst), (PROTO_UDP, src, dst));
        assert_eq!(udp_payload(&pkt, &p), b"abc");
        assert_eq!(fold(sum16(&pkt[..20])), 0xffff);
        let mut sum = sum16(&[1, 1, 1, 1]) + sum16(&[172, 19, 0, 1]) + PROTO_UDP as u32 + 11;
        sum += sum16(&pkt[20..]);
        assert_eq!(fold(sum), 0xffff, "udp checksum");
    }

    #[test]
    fn udp_v6_roundtrip() {
        let src: SocketAddr = "[2606:4700::1111]:53".parse().unwrap();
        let dst: SocketAddr = "[fdfe:dcba:9876::1]:5555".parse().unwrap();
        let pkt = build_udp(src, dst, b"hello").unwrap();
        let p = parse(&pkt).unwrap();
        assert_eq!((p.src, p.dst), (src, dst));
        assert_eq!(udp_payload(&pkt, &p), b"hello");
    }

    #[test]
    fn drops_fragments() {
        let mut pkt = tcp_v4("10.0.0.1:1".parse().unwrap(), "10.0.0.2:2".parse().unwrap(), b"");
        pkt[6] |= 0x20; // MF
        assert!(parse(&pkt).is_none());
    }
}
