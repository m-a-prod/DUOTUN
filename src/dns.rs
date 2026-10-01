//! DNS hijack. Every UDP query to port 53, whatever its destination, is sent to
//! the upstream through ONE shared SOCKS5 UDP association. Query IDs are
//! rewritten so answers can be matched back to the app socket that asked, and
//! the answer's source is the address the app originally queried.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use crate::packet;
use crate::socks5::{self, Socks5};
use crate::udp::PacketSink;

const QUEUE: usize = 1024;
const MAX_PENDING: usize = 4096;
const QUERY_TIMEOUT: Duration = Duration::from_secs(8);
const RECONNECT_DELAY: Duration = Duration::from_secs(1);

struct Query {
    app: SocketAddr,
    dst: SocketAddr,
    data: Vec<u8>,
}

struct Pending {
    app: SocketAddr,
    dst: SocketAddr,
    orig_id: [u8; 2],
    at: Instant,
}

#[derive(Clone)]
pub struct Dns {
    tx: mpsc::Sender<Query>,
}

impl Dns {
    pub fn spawn<S: PacketSink>(
        sink: Arc<S>,
        socks: Arc<Socks5>,
        upstream: SocketAddr,
        cancel: CancellationToken,
    ) -> Self {
        let (tx, rx) = mpsc::channel(QUEUE);
        tokio::spawn(async move {
            tokio::select! {
                _ = worker(rx, sink, socks, upstream) => {}
                _ = cancel.cancelled() => {}
            }
        });
        Self { tx }
    }

    pub fn query(&self, app: SocketAddr, dst: SocketAddr, payload: &[u8]) {
        // Shorter than a DNS header: not a query.
        if payload.len() < 12 {
            return;
        }
        let q = Query {
            app,
            dst,
            data: payload.to_vec(),
        };
        if self.tx.try_send(q).is_err() {
            trace!(%app, "dns queue full, dropping query");
        }
    }
}

async fn worker<S: PacketSink>(
    mut rx: mpsc::Receiver<Query>,
    sink: Arc<S>,
    socks: Arc<Socks5>,
    upstream: SocketAddr,
) {
    let mut pending: HashMap<u16, Pending> = HashMap::new();
    let mut next_id: u16 = 0;
    let mut buf = vec![0u8; 65536];
    let mut ctrl_buf = [0u8; 1];

    loop {
        // Connect lazily: wait for demand first so a dead proxy is not hammered.
        let Some(first) = rx.recv().await else { return };
        let assoc = match socks.udp_associate().await {
            Ok(a) => a,
            Err(e) => {
                warn!("dns: udp associate failed: {e}");
                tokio::time::sleep(RECONNECT_DELAY).await;
                continue;
            }
        };
        let socks5::UdpAssociation { mut ctrl, socket } = assoc;
        debug!(%upstream, "dns association open");

        let mut backlog = Some(first);
        let mut sweep = tokio::time::interval(Duration::from_secs(1));
        loop {
            let q = match backlog.take() {
                Some(q) => Some(q),
                None => tokio::select! {
                    q = rx.recv() => match q {
                        Some(q) => Some(q),
                        None => return,
                    },
                    n = socket.recv(&mut buf) => {
                        match n {
                            Ok(n) => deliver(&buf[..n], &mut pending, &*sink).await,
                            Err(e) => {
                                debug!("dns: association recv failed: {e}");
                                break;
                            }
                        }
                        None
                    }
                    r = ctrl.read(&mut ctrl_buf) => {
                        debug!("dns: association closed by proxy ({r:?})");
                        break;
                    }
                    _ = sweep.tick() => {
                        let now = Instant::now();
                        pending.retain(|_, p| now.duration_since(p.at) < QUERY_TIMEOUT);
                        None
                    }
                },
            };
            let Some(mut q) = q else { continue };

            if pending.len() >= MAX_PENDING {
                trace!("dns: too many queries in flight, dropping");
                continue;
            }
            while pending.contains_key(&next_id) {
                next_id = next_id.wrapping_add(1);
            }
            let id = next_id;
            next_id = next_id.wrapping_add(1);

            let orig_id = [q.data[0], q.data[1]];
            q.data[..2].copy_from_slice(&id.to_be_bytes());
            pending.insert(
                id,
                Pending {
                    app: q.app,
                    dst: q.dst,
                    orig_id,
                    at: Instant::now(),
                },
            );
            if let Err(e) = socket.send(&socks5::encode_udp(upstream, &q.data)).await {
                debug!("dns: association send failed: {e}");
                break;
            }
        }
        // Queries in flight on the dead association are lost; apps retry.
        pending.clear();
    }
}

async fn deliver<S: PacketSink>(dgram: &[u8], pending: &mut HashMap<u16, Pending>, sink: &S) {
    let Some((_, data)) = socks5::decode_udp(dgram) else { return };
    if data.len() < 12 {
        return;
    }
    let id = u16::from_be_bytes([data[0], data[1]]);
    let Some(p) = pending.remove(&id) else { return };
    let mut answer = data.to_vec();
    answer[..2].copy_from_slice(&p.orig_id);
    trace!(app = %p.app, ms = p.at.elapsed().as_millis(), "dns answer");
    if let Some(pkt) = packet::build_udp(p.dst, p.app, &answer) {
        sink.send(pkt).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Mutex;

    #[derive(Default)]
    struct Collect(Mutex<Vec<Vec<u8>>>);

    impl PacketSink for Collect {
        async fn send(&self, pkt: Vec<u8>) {
            self.0.lock().await.push(pkt);
        }
    }

    fn query(id: u16, name: &str) -> Vec<u8> {
        let mut q = id.to_be_bytes().to_vec();
        q.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.extend_from_slice(&[0, 0, 1, 0, 1]);
        q
    }

    /// Needs a SOCKS5 proxy with UDP on 127.0.0.1:17080 (`dev_run.py`).
    #[tokio::test]
    #[ignore]
    async fn live_resolve_through_proxy() {
        let sink = Arc::new(Collect::default());
        let socks = Arc::new(Socks5 { server: "127.0.0.1:17080".parse().unwrap(), auth: None });
        let dns = Dns::spawn(sink.clone(), socks, "1.1.1.1:53".parse().unwrap(), CancellationToken::new());

        let dst: SocketAddr = "172.19.0.2:53".parse().unwrap();
        let n = 50u16;
        for i in 0..n {
            // Same app port and same query ID on purpose: IDs must be remapped.
            let app: SocketAddr = format!("172.19.0.1:{}", 40000 + i).parse().unwrap();
            dns.query(app, dst, &query(0x1234, "example.com"));
        }
        tokio::time::sleep(Duration::from_secs(5)).await;

        let got = sink.0.lock().await;
        assert_eq!(got.len(), n as usize, "every query answered");
        for pkt in got.iter() {
            let p = packet::parse(pkt).unwrap();
            assert_eq!(p.src, dst, "answer comes from the address the app queried");
            let ans = packet::udp_payload(pkt, &p);
            assert_eq!(&ans[..2], &[0x12, 0x34], "original id restored");
            assert_eq!(ans[3] & 0x0f, 0, "rcode NOERROR");
        }
    }
}
