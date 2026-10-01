//! SOCKS5 client (RFC 1928 / RFC 1929): CONNECT and UDP ASSOCIATE.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct Socks5 {
    pub server: SocketAddr,
    pub auth: Option<(String, String)>,
}

impl Socks5 {
    pub async fn connect(&self, target: SocketAddr) -> io::Result<TcpStream> {
        tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            let mut s = self.handshake().await?;
            request(&mut s, 0x01, target).await?;
            Ok(s)
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "socks5 connect timed out"))?
    }

    /// Opens a UDP association. The returned TCP stream must be kept open for
    /// the lifetime of the association.
    pub async fn udp_associate(&self) -> io::Result<UdpAssociation> {
        tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            let mut ctrl = self.handshake().await?;
            let unspecified = match self.server {
                SocketAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
                SocketAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
            };
            let mut relay = request(&mut ctrl, 0x03, unspecified).await?;
            if relay.ip().is_unspecified() {
                relay.set_ip(self.server.ip());
            }
            let bind = SocketAddr::new(ctrl.local_addr()?.ip(), 0);
            let socket = UdpSocket::bind(bind).await?;
            socket.connect(relay).await?;
            Ok(UdpAssociation { ctrl, socket })
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "socks5 udp associate timed out"))?
    }

    async fn handshake(&self) -> io::Result<TcpStream> {
        let mut s = TcpStream::connect(self.server).await?;
        s.set_nodelay(true)?;
        match &self.auth {
            None => s.write_all(&[5, 1, 0]).await?,
            Some(_) => s.write_all(&[5, 2, 0, 2]).await?,
        }
        let mut reply = [0u8; 2];
        s.read_exact(&mut reply).await?;
        if reply[0] != 5 {
            return Err(proto_err("bad socks version"));
        }
        match (reply[1], &self.auth) {
            (0, _) => {}
            (2, Some((user, pass))) => {
                if user.len() > 255 || pass.len() > 255 {
                    return Err(proto_err("socks credentials too long"));
                }
                let mut msg = vec![1, user.len() as u8];
                msg.extend_from_slice(user.as_bytes());
                msg.push(pass.len() as u8);
                msg.extend_from_slice(pass.as_bytes());
                s.write_all(&msg).await?;
                let mut r = [0u8; 2];
                s.read_exact(&mut r).await?;
                if r[1] != 0 {
                    return Err(proto_err("socks authentication failed"));
                }
            }
            _ => return Err(proto_err("no acceptable socks auth method")),
        }
        Ok(s)
    }
}

async fn request(s: &mut TcpStream, cmd: u8, target: SocketAddr) -> io::Result<SocketAddr> {
    let mut msg = vec![5, cmd, 0];
    encode_addr(&mut msg, target);
    s.write_all(&msg).await?;

    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("socks request failed, reply code {}", head[1]),
        ));
    }
    let ip = match head[3] {
        1 => {
            let mut b = [0u8; 4];
            s.read_exact(&mut b).await?;
            IpAddr::V4(b.into())
        }
        4 => {
            let mut b = [0u8; 16];
            s.read_exact(&mut b).await?;
            IpAddr::V6(b.into())
        }
        3 => {
            let len = s.read_u8().await? as usize;
            let mut skip = vec![0u8; len];
            s.read_exact(&mut skip).await?;
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        }
        _ => return Err(proto_err("bad address type in socks reply")),
    };
    let port = s.read_u16().await?;
    Ok(SocketAddr::new(ip, port))
}

fn encode_addr(buf: &mut Vec<u8>, addr: SocketAddr) {
    match addr.ip() {
        IpAddr::V4(ip) => {
            buf.push(1);
            buf.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            buf.push(4);
            buf.extend_from_slice(&ip.octets());
        }
    }
    buf.extend_from_slice(&addr.port().to_be_bytes());
}

fn proto_err(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

pub struct UdpAssociation {
    /// Closing this ends the association on the server side.
    pub ctrl: TcpStream,
    pub socket: UdpSocket,
}

/// Wraps a datagram in a SOCKS5 UDP request header.
pub fn encode_udp(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(22 + payload.len());
    buf.extend_from_slice(&[0, 0, 0]);
    encode_addr(&mut buf, target);
    buf.extend_from_slice(payload);
    buf
}

/// Parses a SOCKS5 UDP reply. Fragmented and domain-addressed datagrams are rejected.
pub fn decode_udp(buf: &[u8]) -> Option<(SocketAddr, &[u8])> {
    if buf.len() < 4 || buf[2] != 0 {
        return None;
    }
    let (ip, rest) = match buf[3] {
        1 if buf.len() >= 10 => {
            let b: [u8; 4] = buf[4..8].try_into().ok()?;
            (IpAddr::V4(b.into()), &buf[8..])
        }
        4 if buf.len() >= 22 => {
            let b: [u8; 16] = buf[4..20].try_into().ok()?;
            (IpAddr::V6(b.into()), &buf[20..])
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([rest[0], rest[1]]);
    Some((SocketAddr::new(ip.to_canonical(), port), &rest[2..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_header_roundtrip() {
        for target in ["1.2.3.4:53", "[2001:db8::1]:443"] {
            let target: SocketAddr = target.parse().unwrap();
            let enc = encode_udp(target, b"payload");
            let (addr, data) = decode_udp(&enc).unwrap();
            assert_eq!((addr, data), (target, &b"payload"[..]));
        }
    }
}
