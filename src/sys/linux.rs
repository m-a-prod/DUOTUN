use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result};
use tracing::{info, warn};

use super::{SysConfig, Undo, UndoLog, run};

struct DefaultRoute {
    gateway: Option<String>,
    dev: String,
}

pub fn apply(cfg: &SysConfig, log: &mut UndoLog) -> Result<()> {
    let v4 = default_route(false).context("no IPv4 default route")?;
    let v6 = default_route(true).ok();
    info!("uplink: {} via {}", v4.dev, v4.gateway.as_deref().unwrap_or("link"));

    for ip in &cfg.bypass {
        let (route, family, prefix) = match ip {
            IpAddr::V4(_) => (&v4, "-4", 32),
            IpAddr::V6(_) => match &v6 {
                Some(r) => (r, "-6", 128),
                None => {
                    warn!("no IPv6 default route, cannot bypass {ip}");
                    continue;
                }
            },
        };
        let dst = format!("{ip}/{prefix}");
        log.push_cmd(&["ip", family, "route", "del", &dst])?;
        let mut add = vec!["ip", family, "route", "replace", &dst];
        if let Some(gw) = &route.gateway {
            add.extend(["via", gw.as_str()]);
        }
        add.extend(["dev", route.dev.as_str()]);
        run(&add)?;
        info!("bypass {ip} -> {}", route.dev);
    }

    let tun = cfg.tun_name.as_str();
    for net in ["0.0.0.0/1", "128.0.0.0/1"] {
        log.push_cmd(&["ip", "-4", "route", "del", net, "dev", tun])?;
        run(&["ip", "-4", "route", "replace", net, "dev", tun])?;
    }
    if cfg.ipv6.is_some() {
        for net in ["::/1", "8000::/1"] {
            log.push_cmd(&["ip", "-6", "route", "del", net, "dev", tun])?;
            run(&["ip", "-6", "route", "replace", net, "dev", tun])?;
        }
    }

    set_dns(cfg, log)?;
    if cfg.strict_dns {
        block_dns_outside_tun(tun, log)?;
    }
    Ok(())
}

fn block_dns_outside_tun(tun: &str, log: &mut UndoLog) -> Result<()> {
    // nftables is not installed everywhere (e.g. minimal Arch): the tunnel still
    // works, only the hard leak guard is missing.
    if run(&["nft", "--version"]).is_err() {
        warn!("nft not found: strict DNS is NOT active (install nftables)");
        return Ok(());
    }
    let rules = format!(
        "table inet duotun {{\n\
           chain output {{\n\
             type filter hook output priority 0; policy accept;\n\
             oifname {{ \"lo\", \"{tun}\" }} accept\n\
             meta l4proto {{ tcp, udp }} th dport 53 reject\n\
           }}\n\
         }}\n"
    );
    let path = "/run/duotun.nft";
    std::fs::write(path, rules)?;
    log.push_cmd(&["nft", "delete", "table", "inet", "duotun"])?;
    run(&["nft", "-f", path])?;
    info!("strict dns: port 53 blocked outside {tun} (nft table inet duotun)");
    Ok(())
}

fn default_route(v6: bool) -> Result<DefaultRoute> {
    let out = run(&["ip", "-j", if v6 { "-6" } else { "-4" }, "route", "show", "default"])?;
    let routes: Vec<serde_json::Value> = serde_json::from_str(&out)?;
    let r = routes.first().context("empty default route table")?;
    Ok(DefaultRoute {
        gateway: r["gateway"].as_str().map(String::from),
        dev: r["dev"].as_str().context("default route has no dev")?.to_string(),
    })
}

fn set_dns(cfg: &SysConfig, log: &mut UndoLog) -> Result<()> {
    let tun = cfg.tun_name.as_str();
    let dns = cfg.dns.to_string();
    if run(&["resolvectl", "status"]).is_ok() {
        // systemd-resolved: make the TUN link the resolver for every domain.
        // TODO(strict): other links with DefaultRoute=yes may still be queried in
        // parallel; block port 53 outside the TUN with nftables for a hard guarantee.
        log.push_cmd(&["resolvectl", "revert", tun])?;
        run(&["resolvectl", "dns", tun, &dns])?;
        run(&["resolvectl", "domain", tun, "~."])?;
        run(&["resolvectl", "default-route", tun, "true"])?;
        let _ = run(&["resolvectl", "flush-caches"]);
        info!("dns via systemd-resolved on {tun} -> {dns}");
        return Ok(());
    }

    let path = Path::new("/etc/resolv.conf");
    let original = std::fs::read_to_string(path).unwrap_or_default();
    log.push(Undo::WriteFile {
        path: path.to_path_buf(),
        content: original,
    })?;
    std::fs::write(path, format!("# written by duotun\nnameserver {dns}\n"))?;
    info!("dns via /etc/resolv.conf -> {dns}");
    Ok(())
}
