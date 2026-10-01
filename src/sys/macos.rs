use std::net::IpAddr;

use anyhow::{Context, Result, bail};
use tracing::{info, warn};

use super::{SysConfig, UndoLog, run, run_full};

const PF_ANCHOR: &str = "com.apple/250.Duotun";
const PF_RULES: &str = "/var/run/duotun.pf.conf";

struct DefaultRoute {
    gateway: Option<String>,
    iface: String,
}

pub fn apply(cfg: &SysConfig, log: &mut UndoLog) -> Result<()> {
    let v4 = default_route(false).context("no IPv4 default route")?;
    let v6 = default_route(true).ok();
    info!(
        "uplink: {} via {}",
        v4.iface,
        v4.gateway.as_deref().unwrap_or("link")
    );

    // 1. Proxy servers keep using the physical uplink; must precede the split routes.
    for ip in &cfg.bypass {
        let route = match ip {
            IpAddr::V4(_) => &v4,
            IpAddr::V6(_) => match &v6 {
                Some(r) => r,
                None => {
                    warn!("no IPv6 default route, cannot bypass {ip}");
                    continue;
                }
            },
        };
        add_host_route(*ip, route, log)?;
    }

    // 2. Everything else into the TUN. Two /1 halves beat 0.0.0.0/0 without touching the default route.
    let tun = cfg.tun_name.as_str();
    for net in ["0.0.0.0/1", "128.0.0.0/1"] {
        log.push_cmd(&["/sbin/route", "-n", "delete", "-net", net, "-interface", tun])?;
        run(&["/sbin/route", "-n", "add", "-net", net, "-interface", tun])?;
    }
    if cfg.ipv6.is_some() {
        for net in ["::/1", "8000::/1"] {
            log.push_cmd(&["/sbin/route", "-n", "delete", "-inet6", "-net", net, "-interface", tun])?;
            run(&["/sbin/route", "-n", "add", "-inet6", "-net", net, "-interface", tun])?;
        }
    }

    // 3. Point every network service's resolver into the TUN, so LAN DNS servers
    //    (which stay reachable through their more specific on-link route) are not used.
    set_dns(&cfg.dns.to_string(), log)?;
    flush_dns_cache();

    if cfg.strict_dns {
        block_dns_outside_tun(tun, log)?;
    }
    Ok(())
}

/// Loads rules into a sub-anchor of the stock `anchor "com.apple/*"`, so
/// /etc/pf.conf is never edited, and enables pf with a reference token so we
/// only turn it off again if nobody else needs it.
fn block_dns_outside_tun(tun: &str, log: &mut UndoLog) -> Result<()> {
    let main = run(&["/sbin/pfctl", "-s", "rules"]).unwrap_or_default();
    if !main.contains("anchor \"com.apple/*\"") {
        warn!("pf main ruleset has no com.apple anchor; strict DNS is NOT active");
        return Ok(());
    }

    let rules = format!(
        "pass out quick on lo0 proto {{ tcp udp }} to any port 53\n\
         pass out quick on {tun} proto {{ tcp udp }} to any port 53\n\
         block return out quick proto {{ tcp udp }} to any port 53\n"
    );
    std::fs::write(PF_RULES, rules)?;
    log.push_cmd(&["/sbin/pfctl", "-a", PF_ANCHOR, "-F", "all"])?;
    run(&["/sbin/pfctl", "-a", PF_ANCHOR, "-f", PF_RULES])?;

    let (out, err) = run_full(&["/sbin/pfctl", "-E"])?;
    let token = format!("{out}\n{err}")
        .lines()
        .find_map(|l| l.trim().strip_prefix("Token :").map(|t| t.trim().to_string()))
        .context("pfctl -E returned no token")?;
    log.push_cmd(&["/sbin/pfctl", "-X", &token])?;
    info!("strict dns: port 53 blocked outside {tun} (pf anchor {PF_ANCHOR})");
    Ok(())
}

fn default_route(v6: bool) -> Result<DefaultRoute> {
    let out = if v6 {
        run(&["/sbin/route", "-n", "get", "-inet6", "default"])?
    } else {
        run(&["/sbin/route", "-n", "get", "default"])?
    };
    let field = |name: &str| {
        out.lines()
            .find_map(|l| l.trim().strip_prefix(name))
            .map(|v| v.trim().to_string())
    };
    let iface = field("interface:").context("default route has no interface")?;
    if iface.starts_with("utun") {
        bail!("default route already points at {iface}; another VPN is active");
    }
    Ok(DefaultRoute {
        gateway: field("gateway:"),
        iface,
    })
}

fn add_host_route(ip: IpAddr, via: &DefaultRoute, log: &mut UndoLog) -> Result<()> {
    let ip_s = ip.to_string();
    let family = if ip.is_ipv6() { "-inet6" } else { "-inet" };
    let target: Vec<&str> = match &via.gateway {
        Some(gw) => vec![gw.as_str()],
        None => vec!["-interface", via.iface.as_str()],
    };

    log.push_cmd(&["/sbin/route", "-n", "delete", family, "-host", &ip_s])?;
    let mut add = vec!["/sbin/route", "-n", "add", family, "-host", &ip_s];
    add.extend(&target);
    if run(&add).is_err() {
        // Route already exists (e.g. left over by someone else): take it over.
        let mut change = vec!["/sbin/route", "-n", "change", family, "-host", &ip_s];
        change.extend(&target);
        run(&change)?;
    }
    info!("bypass {ip} -> {}", via.iface);
    Ok(())
}

fn set_dns(server: &str, log: &mut UndoLog) -> Result<()> {
    let services = run(&["/usr/sbin/networksetup", "-listallnetworkservices"])?;
    // First line is a legend; disabled services are prefixed with '*'.
    for svc in services.lines().skip(1).filter(|s| !s.starts_with('*') && !s.is_empty()) {
        let current = run(&["/usr/sbin/networksetup", "-getdnsservers", svc])?;
        let mut restore: Vec<String> = current
            .lines()
            .map(str::trim)
            .filter(|l| l.parse::<IpAddr>().is_ok())
            // A leftover from a crashed run (ours or another TUN client) is not worth restoring.
            .filter(|l| *l != server)
            .map(String::from)
            .collect();
        if restore.is_empty() {
            restore.push("Empty".into());
        }
        let mut undo = vec!["/usr/sbin/networksetup", "-setdnsservers", svc];
        undo.extend(restore.iter().map(String::as_str));
        log.push_cmd(&undo)?;
        run(&["/usr/sbin/networksetup", "-setdnsservers", svc, server])?;
        info!("dns for \"{svc}\" -> {server}");
    }
    log.push_cmd(&["/usr/bin/killall", "-HUP", "mDNSResponder"])?;
    Ok(())
}

fn flush_dns_cache() {
    let _ = run(&["/usr/bin/dscacheutil", "-flushcache"]);
    let _ = run(&["/usr/bin/killall", "-HUP", "mDNSResponder"]);
}
