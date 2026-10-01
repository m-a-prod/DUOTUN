//! NAT table for the system TCP stack.
//!
//! An app packet `src -> dst` entering the TUN is rewritten to
//! `fake_peer:nat_port -> tun_ip:listen_port`, so the kernel's own TCP stack
//! delivers the connection to our listener. The listener sees `fake_peer:nat_port`
//! as the peer and looks the original destination up here.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const PORT_FIRST: u16 = 1024;
/// Entries that never got accepted (e.g. SYN to a dead host) or whose relay finished.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy)]
pub struct Flow {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

struct Entry {
    flow: Flow,
    last_seen: Instant,
    /// A relay task currently owns this port; never expire it.
    active: bool,
}

#[derive(Default)]
struct Inner {
    by_port: HashMap<u16, Entry>,
    by_flow: HashMap<(SocketAddr, SocketAddr), u16>,
    cursor: u16,
}

#[derive(Default)]
pub struct Nat {
    inner: Mutex<Inner>,
}

impl Nat {
    /// Returns the NAT port for an outgoing app flow, allocating one if needed.
    pub fn outbound(&self, src: SocketAddr, dst: SocketAddr) -> Option<u16> {
        let mut g = self.inner.lock().unwrap();
        let now = Instant::now();
        if let Some(&port) = g.by_flow.get(&(src, dst)) {
            if let Some(e) = g.by_port.get_mut(&port) {
                e.last_seen = now;
            }
            return Some(port);
        }
        let port = g.alloc()?;
        g.by_port.insert(
            port,
            Entry {
                flow: Flow { src, dst },
                last_seen: now,
                active: false,
            },
        );
        g.by_flow.insert((src, dst), port);
        Some(port)
    }

    /// Looks up the flow for a packet coming back from our listener.
    pub fn inbound(&self, port: u16) -> Option<Flow> {
        let mut g = self.inner.lock().unwrap();
        let e = g.by_port.get_mut(&port)?;
        e.last_seen = Instant::now();
        Some(e.flow)
    }

    /// Called when the listener accepts a connection from `fake_peer:port`.
    pub fn accept(&self, port: u16) -> Option<Flow> {
        let mut g = self.inner.lock().unwrap();
        let e = g.by_port.get_mut(&port)?;
        e.active = true;
        e.last_seen = Instant::now();
        Some(e.flow)
    }

    /// Called when the relay for `port` has finished.
    pub fn release(&self, port: u16) {
        let mut g = self.inner.lock().unwrap();
        if let Some(e) = g.by_port.get_mut(&port) {
            e.active = false;
            e.last_seen = Instant::now();
        }
    }

    pub fn sweep(&self) -> usize {
        let mut g = self.inner.lock().unwrap();
        let now = Instant::now();
        let dead: Vec<u16> = g
            .by_port
            .iter()
            .filter(|(_, e)| !e.active && now.duration_since(e.last_seen) > IDLE_TIMEOUT)
            .map(|(&p, _)| p)
            .collect();
        for p in &dead {
            if let Some(e) = g.by_port.remove(p) {
                g.by_flow.remove(&(e.flow.src, e.flow.dst));
            }
        }
        dead.len()
    }

    pub(crate) fn len(&self) -> usize {
        self.inner.lock().unwrap().by_port.len()
    }
}

impl Inner {
    fn alloc(&mut self) -> Option<u16> {
        let span = (u16::MAX - PORT_FIRST) as u32 + 1;
        for _ in 0..span {
            self.cursor = if self.cursor < PORT_FIRST || self.cursor == u16::MAX {
                PORT_FIRST
            } else {
                self.cursor + 1
            };
            if !self.by_port.contains_key(&self.cursor) {
                return Some(self.cursor);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_flow_same_port() {
        let nat = Nat::default();
        let a: SocketAddr = "172.19.0.1:5000".parse().unwrap();
        let b: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let c: SocketAddr = "8.8.8.8:443".parse().unwrap();
        let p1 = nat.outbound(a, b).unwrap();
        assert_eq!(nat.outbound(a, b), Some(p1));
        let p2 = nat.outbound(a, c).unwrap();
        assert_ne!(p1, p2);
        assert_eq!(nat.accept(p1).unwrap().dst, b);
        assert_eq!(nat.inbound(p2).unwrap().dst, c);
    }
}
