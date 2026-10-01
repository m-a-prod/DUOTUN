//! UDP over SOCKS5 UDP ASSOCIATE: one association per app socket (full-cone,
//! replies from any remote are delivered back). DNS is handled by `dns`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace};

use crate::packet;
use crate::Routes;
use crate::socks5;

const QUEUE: usize = 256;
const IDLE: Duration = Duration::from_secs(60);
/// Each session costs two sockets; keep well below the fd limit.
const MAX_SESSIONS: usize = 1024;

pub trait PacketSink: Send + Sync + 'static {
    fn send(&self, pkt: Vec<u8>) -> impl std::future::Future<Output = ()> + Send;
}

pub struct UdpStack<S: PacketSink> {
    sink: Arc<S>,
    routes: Arc<Routes>,
    cancel: CancellationToken,
    sessions: Mutex<HashMap<SocketAddr, Session>>,
    next_id: AtomicU64,
}

struct Session {
    id: u64,
    tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
}

impl<S: PacketSink> UdpStack<S> {
    pub fn new(sink: Arc<S>, routes: Arc<Routes>, cancel: CancellationToken) -> Arc<Self> {
        Arc::new(Self {
            sink,
            routes,
            cancel,
            sessions: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(0),
        })
    }

    pub fn handle(self: &Arc<Self>, src: SocketAddr, dst: SocketAddr, payload: &[u8]) {
        let mut sessions = self.sessions.lock().unwrap();
        let tx = match sessions.get(&src) {
            Some(s) if !s.tx.is_closed() => s.tx.clone(),
            _ => {
                if sessions.len() >= MAX_SESSIONS {
                    trace!(%src, "udp session limit reached, dropping");
                    return;
                }
                let (tx, rx) = mpsc::channel(QUEUE);
                let id = self.next_id.fetch_add(1, Ordering::Relaxed);
                sessions.insert(src, Session { id, tx: tx.clone() });
                let this = self.clone();
                tokio::spawn(async move {
                    tokio::select! {
                        r = this.run_session(src, rx) => {
                            if let Err(e) = r {
                                debug!(%src, "udp session ended: {e}");
                            }
                        }
                        _ = this.cancel.cancelled() => {}
                    }
                    let mut sessions = this.sessions.lock().unwrap();
                    if sessions.get(&src).is_some_and(|s| s.id == id) {
                        sessions.remove(&src);
                    }
                });
                tx
            }
        };
        drop(sessions);

        if tx.try_send((dst, payload.to_vec())).is_err() {
            trace!(%src, %dst, "udp queue full, dropping datagram");
        }
    }

    async fn run_session(
        &self,
        app: SocketAddr,
        mut rx: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    ) -> std::io::Result<()> {
        let socks = self.routes.pick(app, false).await;
        let socks5::UdpAssociation { mut ctrl, socket } = socks.udp_associate().await?;
        trace!(%app, "udp association open");

        let mut buf = vec![0u8; 65536];
        let mut ctrl_buf = [0u8; 1];
        loop {
            tokio::select! {
                msg = rx.recv() => {
                    let Some((target, data)) = msg else { return Ok(()) };
                    socket.send(&socks5::encode_udp(target, &data)).await?;
                }
                n = socket.recv(&mut buf) => {
                    let n = n?;
                    let Some((from, data)) = socks5::decode_udp(&buf[..n]) else { continue };
                    if from.is_ipv4() != app.is_ipv4() {
                        trace!(%from, %app, "udp reply family mismatch");
                        continue;
                    }
                    if let Some(pkt) = packet::build_udp(from, app, data) {
                        self.sink.send(pkt).await;
                    }
                }
                // The proxy closing the control connection ends the association.
                r = ctrl.read(&mut ctrl_buf) => {
                    r?;
                    return Ok(());
                }
                _ = tokio::time::sleep(IDLE) => return Ok(()),
            }
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }
}
