//! Windows: routes via `route`/`netsh`, DNS on the Wintun adapter, and a
//! Windows Firewall rule that blocks DNS to anything but the TUN's resolver
//! (Windows otherwise queries every adapter's DNS server in parallel).

use std::net::IpAddr;

use anyhow::{Context, Result, bail};
use tracing::{info, warn};

use super::{SysConfig, UndoLog, run};

const FW_RULE: &str = "DUORAY DNS guard";
const FW_INBOUND: &str = "DUORAY TUN";

/// Turns off duplicate address detection on the new adapter so its addresses
/// become usable at once (WireGuard does the same). Best effort.
pub fn skip_dad(tun: &str) {
    for family in ["ipv4", "ipv6"] {
        let _ = run(&["netsh", "interface", family, "set", "interface", tun, "dadtransmits=0", "store=active"]);
    }
}

struct DefaultRoute {
    gateway: String,
    if_index: u32,
    alias: String,
}

fn ps(script: &str) -> Result<String> {
    let script = format!("[Console]::OutputEncoding=[Text.Encoding]::UTF8; {script}");
    Ok(run(&["powershell", "-NoProfile", "-NonInteractive", "-Command", &script])?)
}

pub fn apply(cfg: &SysConfig, log: &mut UndoLog) -> Result<()> {
    let tun = cfg.tun_name.as_str();
    let tun_index = adapter_index(tun)?;
    let v4 = default_route(false, tun).context("no IPv4 default route")?;
    let v6 = default_route(true, tun).ok();
    info!("uplink: {} via {}", v4.alias, v4.gateway);

    // 1. Proxy servers keep using the physical uplink.
    for ip in &cfg.bypass {
        let ip_s = ip.to_string();
        match ip {
            IpAddr::V4(_) => {
                log.push_cmd(&["route", "DELETE", &ip_s])?;
                run(&[
                    "route", "ADD", &ip_s, "MASK", "255.255.255.255", &v4.gateway, "IF", &v4.if_index.to_string(), "METRIC", "1",
                ])?;
            }
            IpAddr::V6(_) => {
                let Some(r) = &v6 else {
                    warn!("no IPv6 default route, cannot bypass {ip}");
                    continue;
                };
                let dst = format!("{ip_s}/128");
                let idx = r.if_index.to_string();
                log.push_cmd(&["netsh", "interface", "ipv6", "delete", "route", &dst, &idx])?;
                run(&["netsh", "interface", "ipv6", "add", "route", &dst, &idx, &r.gateway, "store=active"])?;
            }
        }
        info!("bypass {ip}");
    }

    // The kernel hands NATed TCP to our listener on the TUN address; Windows
    // Firewall drops such inbound connections on an unknown network otherwise.
    allow_inbound_on_tun(log)?;

    // 2. Everything else into the TUN (two halves leave the default route alone).
    let peer = cfg.dns.to_string();
    let tun_idx = tun_index.to_string();
    for net in ["0.0.0.0", "128.0.0.0"] {
        log.push_cmd(&["route", "DELETE", net, "MASK", "128.0.0.0", &peer])?;
        run(&["route", "ADD", net, "MASK", "128.0.0.0", &peer, "IF", &tun_idx, "METRIC", "1"])?;
    }
    if cfg.ipv6.is_some() {
        for net in ["::/1", "8000::/1"] {
            log.push_cmd(&["netsh", "interface", "ipv6", "delete", "route", net, &tun_idx])?;
            run(&["netsh", "interface", "ipv6", "add", "route", net, &tun_idx, "store=active"])?;
        }
    }

    // 3. The TUN's resolver, preferred over every other adapter.
    run(&[
        "netsh", "interface", "ipv4", "set", "dnsservers", &format!("name={tun_idx}"), "source=static",
        &format!("address={peer}"), "register=none", "validate=no",
    ])?;
    let _ = run(&["netsh", "interface", "ipv4", "set", "interface", &tun_idx, "metric=1"]);
    let _ = run(&["netsh", "interface", "ipv6", "set", "interface", &tun_idx, "metric=1"]);
    let _ = run(&["ipconfig", "/flushdns"]);

    if cfg.strict_dns {
        block_dns_outside_tun(&peer, log)?;
    }
    Ok(())
}

fn allow_inbound_on_tun(log: &mut UndoLog) -> Result<()> {
    let exe = std::env::current_exe()?.display().to_string();
    let name = format!("name={FW_INBOUND}");
    let _ = run(&["netsh", "advfirewall", "firewall", "delete", "rule", &name]);
    log.push_cmd(&["netsh", "advfirewall", "firewall", "delete", "rule", &name])?;
    if let Err(e) = run(&[
        "netsh", "advfirewall", "firewall", "add", "rule", &name, "dir=in", "action=allow", "protocol=TCP",
        &format!("program={exe}"), "enable=yes",
    ]) {
        warn!("could not add the inbound firewall rule: {e}");
    }
    Ok(())
}

/// Blocks port 53 to every address except the TUN's resolver. Best effort:
/// without the firewall service the tunnel still works, only unguarded.
fn block_dns_outside_tun(dns: &str, log: &mut UndoLog) -> Result<()> {
    let Ok(ip) = dns.parse::<std::net::Ipv4Addr>() else {
        bail!("TUN DNS must be IPv4");
    };
    let below = std::net::Ipv4Addr::from(u32::from(ip) - 1);
    let above = std::net::Ipv4Addr::from(u32::from(ip) + 1);
    let ranges = format!("0.0.0.0-{below},{above}-255.255.255.255,::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    let name = format!("name={FW_RULE}");
    let _ = run(&["netsh", "advfirewall", "firewall", "delete", "rule", &name]);
    log.push_cmd(&["netsh", "advfirewall", "firewall", "delete", "rule", &name])?;
    for proto in ["UDP", "TCP"] {
        let r = run(&[
            "netsh", "advfirewall", "firewall", "add", "rule", &name, "dir=out", "action=block",
            &format!("protocol={proto}"), "remoteport=53", &format!("remoteip={ranges}"),
        ]);
        if let Err(e) = r {
            warn!("firewall rule failed, strict DNS is NOT active: {e}");
            return Ok(());
        }
    }
    info!("strict dns: port 53 blocked except {dns} (Windows Firewall)");
    Ok(())
}

fn adapter_index(name: &str) -> Result<u32> {
    // The adapter may take a moment to appear after Wintun creates it.
    for _ in 0..20 {
        if let Ok(out) = ps(&format!("(Get-NetAdapter -Name '{name}' -ErrorAction Stop).ifIndex"))
            && let Ok(i) = out.trim().parse()
        {
            return Ok(i);
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    bail!("adapter {name} not found")
}

fn default_route(v6: bool, tun: &str) -> Result<DefaultRoute> {
    let (family, prefix) = if v6 { ("IPv6", "::/0") } else { ("IPv4", "0.0.0.0/0") };
    let out = ps(&format!(
        "Get-NetRoute -AddressFamily {family} -DestinationPrefix '{prefix}' -ErrorAction Stop | \
         Where-Object {{ $_.InterfaceAlias -ne '{tun}' }} | Sort-Object RouteMetric | \
         Select-Object -First 1 NextHop,ifIndex,InterfaceAlias | ConvertTo-Json -Compress"
    ))?;
    let v: serde_json::Value = serde_json::from_str(out.trim()).context("parsing Get-NetRoute")?;
    Ok(DefaultRoute {
        gateway: v["NextHop"].as_str().context("no next hop")?.to_string(),
        if_index: v["ifIndex"].as_u64().context("no ifIndex")? as u32,
        alias: v["InterfaceAlias"].as_str().unwrap_or_default().to_string(),
    })
}
