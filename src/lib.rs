//! duotun: routes all traffic of the machine through a SOCKS5 proxy (xray) via a TUN device.

pub mod dns;
pub mod nat;
pub mod packet;
pub mod process;
pub mod socks5;
pub mod sys;
pub mod tcp;
pub mod udp;

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use tun_rs::{AsyncDevice, DeviceBuilder};

use crate::dns::Dns;
use crate::nat::Nat;
use crate::process::{AppRouter, AppRules};
use crate::socks5::Socks5;
use crate::tcp::{Endpoint, TcpStack};
use crate::udp::{PacketSink, UdpStack};

#[derive(Debug, Clone)]
pub struct Config {
    pub socks: Socks5,
    /// Interface name; on macOS it must look like `utunN`. `None` lets the OS pick.
    pub tun_name: Option<String>,
    pub mtu: u16,
    /// TUN address; the listener binds here. Deliberately not 172.19.0.0/24
    /// (Throne/sing-box default) nor 198.18.0.0/16 (Clash fake-ip), so leftovers
    /// of those clients are never mistaken for ours.
    pub v4: Ipv4Addr,
    /// Point-to-point peer: source of NATed packets and the DNS address given to the system.
    pub v4_peer: Ipv4Addr,
    pub v6: Option<(Ipv6Addr, Ipv6Addr)>,
    /// Upstream all DNS queries (UDP and TCP port 53) are redirected to, through the proxy.
    pub dns: Option<SocketAddr>,
    /// Configure routes and system DNS.
    pub auto_route: bool,
    /// Addresses routed around the TUN (the proxy servers xray connects to).
    pub bypass: Vec<IpAddr>,
    /// Firewall port 53 outside the TUN (requires `auto_route`).
    pub strict_dns: bool,
    /// Per-app routing: flows of matching apps go through `direct_socks`.
    pub apps: Option<AppRules>,
    /// SOCKS whose traffic leaves directly (an xray inbound routed to freedom).
    pub direct_socks: Option<Socks5>,
    /// Route private/LAN/CGNAT/ULA ranges into the TUN by splitting their OS routes
    /// into halves so xray's routing rules can proxy or block them.
    pub route_private: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            socks: Socks5 {
                server: "127.0.0.1:10808".parse().unwrap(),
                auth: None,
            },
            tun_name: None,
            mtu: 9000,
            v4: Ipv4Addr::new(198, 19, 233, 1),
            v4_peer: Ipv4Addr::new(198, 19, 233, 2),
            v6: Some((
                "fd00:d0e7:7e0::1".parse().unwrap(),
                "fd00:d0e7:7e0::2".parse().unwrap(),
            )),
            dns: Some("1.1.1.1:53".parse().unwrap()),
            auto_route: true,
            bypass: vec![],
            strict_dns: true,
            apps: None,
            direct_socks: None,
            route_private: false,
        }
    }
}

struct TunSink(Arc<AsyncDevice>);

impl PacketSink for TunSink {
    async fn send(&self, pkt: Vec<u8>) {
        if let Err(e) = self.0.send(&pkt).await {
            debug!("tun write failed: {e}");
        }
    }
}

/// New upstream SOCKS, bypass routes and per-app rules for [`TunHandle::switch`].
#[derive(Debug, Clone)]
pub struct SwitchUpdate {
    pub socks: Socks5,
    pub bypass: Vec<IpAddr>,
    pub apps: Option<AppRules>,
    pub direct_socks: Option<Socks5>,
}

/// Control handle to a running TUN session (hot-swapping upstream without
/// recreating the TUN device, routes, DNS or firewall).
#[derive(Clone)]
pub struct TunHandle {
    tx: mpsc::Sender<(SwitchUpdate, oneshot::Sender<Result<()>>)>,
}

impl TunHandle {
    pub async fn switch(&self, update: SwitchUpdate) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send((update, reply_tx))
            .await
            .map_err(|_| anyhow::anyhow!("tunnel has stopped"))?;
        reply_rx
            .await
            .map_err(|_| anyhow::anyhow!("tunnel stopped during switch"))?
    }
}

/// Runs until `shutdown` resolves or a fatal error occurs. System settings are
/// always restored before returning.
pub async fn run(cfg: Config, shutdown: impl Future<Output = ()>) -> Result<()> {
    run_notify(cfg, shutdown, |_| {}).await
}

/// Like [`run`], but calls `ready` with the interface name once the TUN is up
/// and routes/DNS are in place.
pub async fn run_notify(
    cfg: Config,
    shutdown: impl Future<Output = ()>,
    ready: impl FnOnce(String),
) -> Result<()> {
    run_with_handle(cfg, shutdown, |name, _handle| ready(name)).await
}

/// Like [`run_notify`], and also passes a [`TunHandle`] for hot-swapping the
/// upstream proxy, bypass routes and per-app rules in place.
pub async fn run_with_handle(
    cfg: Config,
    shutdown: impl Future<Output = ()>,
    ready: impl FnOnce(String, TunHandle),
) -> Result<()> {
    raise_fd_limit();
    let started = std::time::Instant::now();
    if cfg.auto_route {
        sys::recover();
    }

    #[cfg(windows)]
    let mut cfg = cfg;
    let builder = DeviceBuilder::new();
    // On Windows `.mtu()` also sets the IPv6 MTU, and that fails with "Element
    // not found" (os error 1168) when IPv6 is turned off on the machine: the
    // whole adapter failed. IPv6 is set up below, after the adapter exists.
    #[cfg(windows)]
    let builder = builder.mtu_v4(cfg.mtu);
    #[cfg(not(windows))]
    let builder = builder.mtu(cfg.mtu);
    // Windows: the addresses are added below, once duplicate address
    // detection is off (tun-rs would add them before that).
    #[cfg(not(windows))]
    let mut builder = builder.ipv4(cfg.v4, 30, Some(cfg.v4_peer));
    #[cfg(not(windows))]
    if let Some((v6, _)) = cfg.v6 {
        builder = builder.ipv6(v6, 126);
    }
    #[cfg(windows)]
    let mut builder = builder;
    if let Some(name) = &cfg.tun_name {
        builder = builder.name(name);
    }
    let dev = Arc::new(
        builder
            .build_async()
            .context("creating TUN device (root required)")?,
    );
    #[cfg(windows)]
    {
        // Windows runs duplicate address detection on new addresses (IPv4
        // too) and refuses binds until it ends: ~3 s per connect. Off first,
        // then the addresses go in ready to use.
        let index = dev.if_index()?;
        sys::prepare_interface(index);
        sys::add_address(index, cfg.v4.into(), 30).context("adding the TUN address")?;
        // IPv6 off on this machine: tunnel IPv4 only (there is no IPv6 to leak).
        if let Some((v6, _)) = cfg.v6
            && let Err(e) = dev
                .set_mtu_v6(cfg.mtu)
                .map_err(anyhow::Error::from)
                .and_then(|()| sys::add_address(index, v6.into(), 126))
        {
            warn!("no IPv6 on the TUN ({e:#}); IPv4 only");
            cfg.v6 = None;
        }
    }
    let tun_name = dev.name()?;
    info!(
        "tun {tun_name} up, mtu {}, in {:.2} s",
        cfg.mtu,
        started.elapsed().as_secs_f32()
    );

    let l4 = bind_retry(SocketAddr::new(cfg.v4.into(), 0)).await?;
    let l6 = match cfg.v6 {
        Some((v6, _)) => Some(bind_retry(SocketAddr::new(v6.into(), 0)).await?),
        None => None,
    };

    let mut bypass = cfg.bypass.clone();
    let socks_ip = cfg.socks.server.ip();
    if !socks_ip.is_loopback() && !bypass.contains(&socks_ip) {
        bypass.push(socks_ip);
    }
    if cfg.auto_route && bypass.is_empty() {
        warn!("no --bypass given: xray's connection to its server will loop into the TUN");
    }

    let sys_cfg = Arc::new(Mutex::new(sys::SysConfig {
        tun_name: tun_name.clone(),
        dns: cfg.v4_peer,
        ipv6: cfg.v6.map(|(a, _)| a),
        bypass,
        strict_dns: cfg.strict_dns,
        route_private: cfg.route_private,
    }));
    let applying = std::time::Instant::now();
    let undo = if cfg.auto_route {
        let initial = sys_cfg.lock().unwrap().clone();
        Some(Arc::new(Mutex::new(sys::apply(&initial)?)))
    } else {
        None
    };
    info!(
        "routes and DNS in {:.2} s",
        applying.elapsed().as_secs_f32()
    );

    let (switch_tx, switch_rx) = mpsc::channel(8);
    ready(tun_name.clone(), TunHandle { tx: switch_tx });
    let cancel = CancellationToken::new();
    let result = tokio::select! {
        r = serve(&cfg, dev.clone(), l4, l6, sys_cfg.clone(), undo.clone(), switch_rx, cancel.clone()) => r,
        _ = follow_network(sys_cfg.clone(), undo.clone()) => Ok(()),
        _ = shutdown => {
            info!("shutting down");
            Ok(())
        }
    };

    // Close every relay and association first: reverting spawns processes,
    // which needs free file descriptors.
    cancel.cancel();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Revert while the TUN still exists: routes can be deleted cleanly and DNS
    // never points at a dead address.
    if let Some(log) = undo {
        log.lock().unwrap().revert();
    }
    drop(dev);
    result
}

/// Keeps routes in line with the uplink while the tunnel is up. Never returns.
async fn follow_network(
    sys_cfg: Arc<Mutex<sys::SysConfig>>,
    undo: Option<Arc<Mutex<sys::UndoLog>>>,
) {
    // Only Linux follows the uplink so far; elsewhere this just waits.
    let Some(undo) = undo.filter(|_| cfg!(target_os = "linux")) else {
        return std::future::pending().await;
    };
    let mut tick = tokio::time::interval(Duration::from_secs(3));
    tick.tick().await;
    loop {
        tick.tick().await;
        let (sys_cfg, undo) = (sys_cfg.clone(), undo.clone());
        let r = tokio::task::spawn_blocking(move || {
            let cfg = sys_cfg.lock().unwrap();
            let mut log = undo.lock().unwrap();
            sys::refresh(&cfg, &mut log)
        })
        .await;
        if let Ok(Err(e)) = r {
            warn!("network refresh failed: {e:#}");
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve(
    cfg: &Config,
    dev: Arc<AsyncDevice>,
    l4: TcpListener,
    l6: Option<TcpListener>,
    sys_cfg: Arc<Mutex<sys::SysConfig>>,
    undo: Option<Arc<Mutex<sys::UndoLog>>>,
    mut switch_rx: mpsc::Receiver<(SwitchUpdate, oneshot::Sender<Result<()>>)>,
    cancel: CancellationToken,
) -> Result<()> {
    let socks = Arc::new(cfg.socks.clone());
    let routes = Arc::new(Routes::new(
        socks.clone(),
        build_apps(cfg.apps.as_ref(), cfg.direct_socks.as_ref()),
    ));
    let (dns_tx, dns_rx) = watch::channel(socks.clone());
    let nat = Arc::new(Nat::default());
    let tcp = TcpStack {
        nat: nat.clone(),
        v4: Endpoint {
            local: cfg.v4.into(),
            peer: cfg.v4_peer.into(),
            port: l4.local_addr()?.port(),
        },
        v6: match (&l6, cfg.v6) {
            (Some(l), Some((local, peer))) => Some(Endpoint {
                local: local.into(),
                peer: peer.into(),
                port: l.local_addr()?.port(),
            }),
            _ => None,
        },
    };
    let sink = Arc::new(TunSink(dev.clone()));
    let udp = UdpStack::new(sink.clone(), routes.clone(), cancel.clone());
    let dns = cfg
        .dns
        .map(|upstream| Dns::spawn(sink.clone(), dns_rx, upstream, cancel.clone()));

    let mut tasks = tokio::task::JoinSet::new();
    {
        let routes = routes.clone();
        let cancel = cancel.clone();
        let auto_route = cfg.auto_route;
        tasks.spawn(async move {
            loop {
                let item = tokio::select! {
                    item = switch_rx.recv() => item,
                    _ = cancel.cancelled() => return Ok(()),
                };
                let Some((update, reply)) = item else {
                    cancel.cancelled().await;
                    return Ok(());
                };
                let mut bypass = update.bypass;
                let socks_ip = update.socks.server.ip();
                if !socks_ip.is_loopback() && !bypass.contains(&socks_ip) {
                    bypass.push(socks_ip);
                }
                let route_res = if auto_route
                    && let Some(undo) = undo.clone()
                {
                    let sys_cfg = sys_cfg.clone();
                    match tokio::task::spawn_blocking(move || {
                        let mut cfg = sys_cfg.lock().unwrap();
                        let mut log = undo.lock().unwrap();
                        sys::update_bypass(&mut cfg, bypass, &mut log)
                    })
                    .await
                    {
                        Ok(r) => r,
                        Err(e) => Err(anyhow::anyhow!("bypass update panicked: {e}")),
                    }
                } else {
                    Ok(())
                };
                if let Err(e) = route_res {
                    let _ = reply.send(Err(e));
                    continue;
                }
                let new_socks = Arc::new(update.socks);
                let new_apps = build_apps(update.apps.as_ref(), update.direct_socks.as_ref());
                routes.update(new_socks.clone(), new_apps);
                let _ = dns_tx.send(new_socks.clone());
                info!(socks = %new_socks.server, "switched TUN upstream in place");
                let _ = reply.send(Ok(()));
            }
        });
    }
    tasks.spawn(tcp::serve(
        l4,
        nat.clone(),
        cfg.v4_peer.into(),
        routes.clone(),
        cfg.dns,
        cancel.clone(),
    ));
    if let (Some(l), Some((_, peer))) = (l6, cfg.v6) {
        tasks.spawn(tcp::serve(
            l,
            nat.clone(),
            peer.into(),
            routes.clone(),
            cfg.dns,
            cancel.clone(),
        ));
    }
    {
        let nat = nat.clone();
        let udp = udp.clone();
        tasks.spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(30));
            loop {
                tick.tick().await;
                let swept = nat.sweep();
                debug!(nat = nat.len(), swept, udp = udp.len(), "housekeeping");
            }
        });
    }

    let mut buf = vec![0u8; 65536];
    loop {
        tokio::select! {
            n = dev.recv(&mut buf) => {
                let n = n.context("reading from TUN")?;
                let pkt = &mut buf[..n];
                let Some(p) = packet::parse(pkt) else { continue };
                match p.proto {
                    packet::PROTO_TCP => {
                        if tcp.handle(pkt, &p) {
                            let end = p.end;
                            if let Err(e) = dev.send(&pkt[..end]).await {
                                debug!("tun write failed: {e}");
                            }
                        }
                    }
                    packet::PROTO_UDP => {
                        let payload = packet::udp_payload(pkt, &p);
                        match &dns {
                            Some(dns) if p.dst.port() == 53 => dns.query(p.src, p.dst, payload),
                            _ => udp.handle(p.src, p.dst, payload),
                        }
                    }
                    _ => {}
                }
            }
            Some(r) = tasks.join_next() => {
                match r {
                    Ok(Ok(())) => bail!("background task exited"),
                    Ok(Err(e)) => return Err(e).context("tcp listener failed"),
                    Err(e) => bail!("background task panicked: {e}"),
                }
            }
        }
    }
}

fn build_apps(
    apps: Option<&AppRules>,
    direct: Option<&Socks5>,
) -> Option<(Arc<AppRouter>, Arc<Socks5>)> {
    match (apps, direct) {
        (Some(rules), Some(direct)) => {
            info!(mode = ?rules.mode, apps = ?rules.apps, "per-app routing");
            Some((AppRouter::new(rules.clone()), Arc::new(direct.clone())))
        }
        _ => None,
    }
}

struct RoutesState {
    proxy: Arc<Socks5>,
    apps: Option<(Arc<AppRouter>, Arc<Socks5>)>,
}

/// Which SOCKS a flow goes through. Swapped atomically on [`TunHandle::switch`].
pub struct Routes {
    state: RwLock<Arc<RoutesState>>,
}

impl Routes {
    fn new(proxy: Arc<Socks5>, apps: Option<(Arc<AppRouter>, Arc<Socks5>)>) -> Self {
        Self {
            state: RwLock::new(Arc::new(RoutesState { proxy, apps })),
        }
    }

    fn update(&self, proxy: Arc<Socks5>, apps: Option<(Arc<AppRouter>, Arc<Socks5>)>) {
        *self.state.write().unwrap() = Arc::new(RoutesState { proxy, apps });
    }

    /// Current default proxy SOCKS (used for DNS and non-bypass flows).
    pub fn proxy(&self) -> Arc<Socks5> {
        self.state.read().unwrap().proxy.clone()
    }

    /// The SOCKS for a new flow from the app socket `src`.
    pub async fn pick(&self, src: SocketAddr, tcp: bool) -> Arc<Socks5> {
        let state = self.state.read().unwrap().clone();
        if let Some((router, direct)) = &state.apps
            && router.is_direct(src, tcp).await
        {
            return direct.clone();
        }
        state.proxy.clone()
    }
}

/// IPv6 addresses may be tentative (DAD) for a moment after the TUN comes up.
async fn bind_retry(addr: SocketAddr) -> Result<TcpListener> {
    let mut last = None;
    // Windows runs duplicate address detection on the new adapter (IPv4 too)
    // and refuses to bind until it finishes.
    let attempts = if cfg!(windows) { 200 } else { 30 };
    for _ in 0..attempts {
        match TcpListener::bind(addr).await {
            Ok(l) => return Ok(l),
            Err(e) => last = Some(e),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(last.unwrap()).with_context(|| format!("binding listener on {addr}"))
}

/// macOS gives processes started from a shell (and sudo) a soft limit of 256.
#[cfg(unix)]
fn raise_fd_limit() {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: plain syscalls on a stack-allocated struct.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) != 0 {
            return;
        }
        // macOS rejects values above OPEN_MAX even when the hard limit is "unlimited".
        let want = if cfg!(target_os = "macos") {
            lim.rlim_max.min(10240)
        } else {
            lim.rlim_max.min(65536)
        };
        if lim.rlim_cur < want {
            let old = lim.rlim_cur;
            lim.rlim_cur = want;
            if libc::setrlimit(libc::RLIMIT_NOFILE, &lim) == 0 {
                debug!("fd limit {old} -> {want}");
            } else {
                warn!("could not raise fd limit above {old}");
            }
        }
    }
}

#[cfg(not(unix))]
fn raise_fd_limit() {}
