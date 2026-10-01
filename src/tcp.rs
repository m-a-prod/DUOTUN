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
    listener: TcpListener,
    nat: Arc<Nat>,
    peer: IpAddr,
    socks: Arc<Socks5>,
    dns: Option<SocketAddr>,
    cancel: CancellationToken,
) -> std::io::Result<()> {
    loop {
        let (stream, from) = listener.accept().await?;
        if from.ip() != peer {
            debug!(%from, "unexpected connection to tun listener, dropping");
            continue;
        }
        let port = from.port();
        let Some(flow) = nat.accept(port) else {
            debug!(port, "accepted connection without nat entry");
            continue;
        };
        let target = match dns {
            Some(upstream) if flow.dst.port() == 53 => upstream,
            _ => flow.dst,
        };
        let nat = nat.clone();
        let socks = socks.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            tokio::select! {
                r = relay(stream, target, &socks) => {
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

async fn relay(mut local: TcpStream, target: SocketAddr, socks: &Socks5) -> std::io::Result<()> {
    // macOS returns EINVAL here if the app already reset the connection; not worth failing over.
    let _ = local.set_nodelay(true);
    let mut remote = socks.connect(target).await?;
    trace!(%target, "tcp relay open");
    let (up, down) = tokio::io::copy_bidirectional(&mut local, &mut remote).await?;
    trace!(%target, up, down, "tcp relay closed");
    Ok(())
}
