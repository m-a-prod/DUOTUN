use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use duotun::socks5::Socks5;

#[derive(Parser)]
#[command(version, about = "Route all traffic through a SOCKS5 proxy via TUN")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Bring the TUN up and route traffic through the proxy.
    Run(Box<RunArgs>),
    /// Revert routes/DNS left behind by a crashed run.
    Cleanup,
}

#[derive(Parser)]
struct RunArgs {
    /// SOCKS5 server (xray inbound).
    #[arg(long, default_value = "127.0.0.1:10808")]
    socks: SocketAddr,
    #[arg(long, requires = "socks_pass")]
    socks_user: Option<String>,
    #[arg(long, requires = "socks_user")]
    socks_pass: Option<String>,
    /// TUN interface name (macOS: utunN).
    #[arg(long)]
    name: Option<String>,
    #[arg(long, default_value_t = 9000)]
    mtu: u16,
    /// Proxy server host/IP to route around the TUN. Repeatable.
    #[arg(long = "bypass")]
    bypass: Vec<String>,
    /// DNS upstream reached through the proxy; all port-53 traffic goes there.
    #[arg(long, default_value = "1.1.1.1:53")]
    dns: SocketAddr,
    /// Do not hijack DNS.
    #[arg(long)]
    no_dns_hijack: bool,
    #[arg(long)]
    no_ipv6: bool,
    /// Do not firewall port 53 outside the TUN.
    #[arg(long)]
    no_strict_dns: bool,
    /// Only create the TUN; leave routes and DNS alone.
    #[arg(long)]
    no_auto_route: bool,
    /// App (executable name, macOS app name or path) for per-app routing. Repeatable.
    #[arg(long = "app", requires = "direct_socks")]
    apps: Vec<String>,
    /// `bypass`: the --app apps go direct; `only`: only they use the proxy.
    #[arg(long, value_enum, default_value = "bypass")]
    app_mode: AppModeArg,
    /// SOCKS5 that sends traffic direct (same credentials as --socks).
    #[arg(long)]
    direct_socks: Option<SocketAddr>,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum AppModeArg {
    Bypass,
    Only,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "duotun=info".into()),
        )
        .init();

    let cli = Cli::parse();
    let rt = tokio::runtime::Runtime::new()?;
    match cli.cmd {
        Cmd::Cleanup => {
            duotun::sys::recover();
            Ok(())
        }
        Cmd::Run(a) => rt.block_on(run(*a)),
    }
}

async fn run(a: RunArgs) -> Result<()> {
    let mut cfg = duotun::Config {
        socks: Socks5 {
            server: a.socks,
            auth: a.socks_user.zip(a.socks_pass),
        },
        tun_name: a.name,
        mtu: a.mtu,
        dns: (!a.no_dns_hijack).then_some(a.dns),
        auto_route: !a.no_auto_route,
        bypass: resolve_all(&a.bypass)?,
        strict_dns: !a.no_strict_dns,
        ..Default::default()
    };
    if let Some(direct) = a.direct_socks {
        cfg.direct_socks = Some(Socks5 { server: direct, auth: cfg.socks.auth.clone() });
        let mode = match a.app_mode {
            AppModeArg::Bypass => duotun::process::AppMode::Bypass,
            AppModeArg::Only => duotun::process::AppMode::Only,
        };
        cfg.apps = Some(duotun::process::AppRules { mode, apps: a.apps });
    }
    if a.no_ipv6 {
        cfg.v6 = None;
    }
    duotun::run(cfg, shutdown_signal()).await
}

/// Resolve before the TUN exists: afterwards system DNS points into the tunnel.
fn resolve_all(hosts: &[String]) -> Result<Vec<IpAddr>> {
    let mut out = vec![];
    for h in hosts {
        if let Ok(ip) = h.parse::<IpAddr>() {
            out.push(ip);
            continue;
        }
        let addrs = (h.as_str(), 0)
            .to_socket_addrs()
            .with_context(|| format!("resolving {h}"))?;
        out.extend(addrs.map(|a| a.ip()));
    }
    out.sort();
    out.dedup();
    Ok(out)
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}
