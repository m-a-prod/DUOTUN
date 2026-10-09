//! "System" TCP stack: TCP itself is handled by the OS kernel. We only NAT
//! packets between the app and a local listener, then relay accepted
//! connections through SOCKS5.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use crate::nat::Nat;
use crate::packet::{self, Parsed};
use crate::Routes;
use crate::socks5::Socks5;

/// Local listener for one address family.
#[derive(Debug, Clone, Copy)]
pub struct Endpoint {
    /// Address of the TUN interface; the listener is bound here.
    pub local: IpAddr,
    /// Fake peer address used as the source of NATed packets.
    pub peer: IpAddr,
    pub port: u16,
}

pub struct TcpStack {
    pub nat: Arc<Nat>,
    pub v4: Endpoint,
    pub v6: Option<Endpoint>,
}

impl TcpStack {
    fn endpoint(&self, p: &Parsed) -> Option<Endpoint> {
        if p.is_v4() { Some(self.v4) } else { self.v6 }
    }

    /// Rewrites a TCP packet read from the TUN. Returns `true` if the packet
    /// should be written back to the TUN.
    pub fn handle(&self, pkt: &mut [u8], p: &Parsed) -> bool {
        let Some(ep) = self.endpoint(p) else {
            return false;
        };

        if p.src.ip() == ep.local && p.src.port() == ep.port {
            // Listener -> app direction.
            if p.dst.ip() != ep.peer {
                return false;
            }
            let Some(flow) = self.nat.inbound(p.dst.port()) else {
                trace!(port = p.dst.port(), "tcp reply for unknown nat port");
                return false;
            };
            packet::rewrite_tcp(pkt, p, flow.dst, flow.src);
            return true;
        }

        // App -> world direction.
        let flags = packet::tcp_flags(pkt, p);
        let Some(port) = self.nat.outbound(p.src, p.dst) else {
            warn!("nat port pool exhausted, dropping {} -> {}", p.src, p.dst);
            return false;
        };
        if flags & (packet::TCP_RST | packet::TCP_FIN) != 0 {
            trace!(port, flags, "tcp close flag");
        }
        packet::rewrite_tcp(
            pkt,
            p,
            SocketAddr::new(ep.peer, port),
            SocketAddr::new(ep.local, ep.port),
        );
        true
    }
}

pub async fn serve(
    mut listener: TcpListener,
    nat: Arc<Nat>,
    peer: IpAddr,
    routes: Arc<Routes>,
    dns: Option<SocketAddr>,
    cancel: CancellationToken,
) -> std::io::Result<()> {
    // The NAT rewrites flows to this exact address and port.
    let addr = listener.local_addr()?;
    let mut failures: std::collections::VecDeque<std::time::Instant> = Default::default();
    loop {
        let (stream, from) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) if accept_error_is_transient(&e) => {
                debug!("tcp accept: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
            Err(e) => {
                // macOS answers EINVAL once the listener's address went away for
                // a moment, e.g. the previous tunnel's teardown on the same utun
                // address. Listen again on the same port; give up only if it
                // keeps failing.
                let now = std::time::Instant::now();
                failures.retain(|t| now.duration_since(*t) < std::time::Duration::from_secs(60));
                failures.push_back(now);
                if failures.len() > 5 {
                    return Err(e);
                }
                warn!(%addr, "tcp listener failed ({e}), listening again");
                drop(listener);
                listener = relisten(addr).await.map_err(|re| std::io::Error::new(re.kind(), format!("{e}; listening again: {re}")))?;
                continue;
            }
        };
        if from.ip() != peer {
            debug!(%from, "unexpected connection to tun listener, dropping");
            continue;
        }
        let port = from.port();
        let Some(flow) = nat.accept(port) else {
            debug!(port, "accepted connection without nat entry");
            continue;
        };
        let (target, is_dns) = match dns {
            Some(upstream) if flow.dst.port() == 53 => (upstream, true),
            _ => (flow.dst, false),
        };
        let nat = nat.clone();
        let routes = routes.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            // DNS always goes through the proxy, whichever app asks.
            let socks = if is_dns { &routes.proxy } else { routes.pick(flow.src, true).await };
            tokio::select! {
                r = relay(stream, target, socks) => {
                    if let Err(e) = r {
                        debug!(src = %flow.src, dst = %target, "tcp relay ended: {e}");
                    }
                }
                _ = cancel.cancelled() => {}
            }
            nat.release(port);
        });
    }
}

/// Errors of one accept, not of the listener: retry right away.
fn accept_error_is_transient(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    if matches!(e.kind(), ConnectionAborted | ConnectionReset | Interrupted | WouldBlock) {
        return true;
    }
    // Out of file descriptors: connections close and free some.
    #[cfg(unix)]
    if matches!(e.raw_os_error(), Some(libc::EMFILE | libc::ENFILE)) {
        return true;
    }
    false
}

/// A new listener on `addr` (the old one's accepted sockets may still hold
/// the port, hence SO_REUSEADDR). The address can take a moment to return.
async fn relisten(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let mut last = None;
    for _ in 0..30 {
        let socket = if addr.is_ipv4() { tokio::net::TcpSocket::new_v4()? } else { tokio::net::TcpSocket::new_v6()? };
        socket.set_reuseaddr(true)?;
        match socket.bind(addr).and_then(|()| socket.listen(1024)) {
            Ok(l) => return Ok(l),
            Err(e) => last = Some(e),
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    Err(last.unwrap())
}

async fn relay(mut local: TcpStream, target: SocketAddr, socks: &Socks5) -> std::io::Result<()> {
    // macOS returns EINVAL here if the app already reset the connection; not worth failing over.
    let _ = local.set_nodelay(true);
    let mut remote = socks.connect(target).await?;
    trace!(%target, "tcp relay open");
    let (up, down) = tokio::io::copy_bidirectional(&mut local, &mut remote).await?;
    trace!(%target, up, down, "tcp relay closed");
    Ok(())
}

#[cfg(test)]
mod listener_tests {
    use super::*;

    #[tokio::test]
    async fn listens_again_on_the_same_port_while_connections_hold_it() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (accepted, _) = listener.accept().await.unwrap();
        drop(listener);
        let again = relisten(addr).await.unwrap();
        assert_eq!(again.local_addr().unwrap(), addr);
        let second = TcpStream::connect(addr).await.unwrap();
        let (_, from) = again.accept().await.unwrap();
        assert_eq!(from, second.local_addr().unwrap());
        drop((client, accepted));
    }

    #[test]
    fn per_accept_errors_are_retried() {
        use std::io::{Error, ErrorKind};
        assert!(accept_error_is_transient(&Error::from(ErrorKind::ConnectionAborted)));
        assert!(!accept_error_is_transient(&Error::from(ErrorKind::InvalidInput)));
        #[cfg(unix)]
        {
            assert!(accept_error_is_transient(&Error::from_raw_os_error(libc::EMFILE)));
            assert!(!accept_error_is_transient(&Error::from_raw_os_error(libc::EINVAL)));
        }
    }
}
