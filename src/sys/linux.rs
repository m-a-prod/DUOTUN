//! Linux: `ip` for routes, nftables (or iptables) for the DNS leak guard and
//! the host firewall exemption, systemd-resolved or /etc/resolv.conf for DNS.
//!
//! Things that differ from macOS and must be handled here:
//! - Strict reverse-path filtering (`rp_filter=1`, the default on many distros)
//!   drops replies to sockets bound to the uplink (xray's `sockopt.interface`):
//!   the route back to a remote address points into the TUN. The uplink is
//!   switched to loose mode while the tunnel is up.
//! - Host firewalls (ufw, firewalld, a plain nftables.conf) usually drop new
//!   inbound connections. The TCP stack hands every flow to a listener on the
//!   TUN address as a new inbound connection, so the TUN is exempted.
//! - DNS can be configured in many ways (systemd-resolved stub, NetworkManager,
//!   dnsmasq, a static file). Instead of depending on that, every query to port
//!   53 that would leave outside the TUN is DNATed into it, and whatever still
//!   tries (sockets bound to the uplink) is rejected.

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use super::{RunError, SysConfig, Undo, UndoLog, run};

#[derive(Debug, Clone, PartialEq, Eq)]
struct DefaultRoute {
    gateway: Option<String>,
    dev: String,
}

/// The uplink the bypass routes currently point at (for [`refresh`]).
static UPLINK: Mutex<Option<(DefaultRoute, Option<DefaultRoute>)>> = Mutex::new(None);

pub fn apply(cfg: &SysConfig, log: &mut UndoLog) -> Result<()> {
    let tun = cfg.tun_name.as_str();
    let v4 = default_route(false, tun).context("no IPv4 default route")?;
    let v6 = default_route(true, tun).ok();
    info!("uplink: {} via {}", v4.dev, v4.gateway.as_deref().unwrap_or("link"));

    loose_rp_filter(&v4.dev, log)?;
    route_bypass(cfg, &v4, v6.as_ref(), log)?;

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

    allow_tun_input(tun, log)?;
    let redirected = if cfg.strict_dns { guard_dns(cfg, log)? } else { false };
    set_dns(cfg, log, redirected)?;

    *UPLINK.lock().unwrap() = Some((v4, v6));
    Ok(())
}

/// Follows uplink changes (DHCP renewal with a new gateway, cable ↔ Wi-Fi):
/// bypass routes are re-pointed and the new uplink gets loose rp_filter.
pub fn refresh(cfg: &SysConfig, log: &mut UndoLog) -> Result<()> {
    let tun = cfg.tun_name.as_str();
    // Network down: keep everything as is until a new uplink shows up.
    let Ok(v4) = default_route(false, tun) else { return Ok(()) };
    let v6 = default_route(true, tun).ok();
    let mut current = UPLINK.lock().unwrap();
    if current.as_ref().is_some_and(|(a, b)| *a == v4 && *b == v6) {
        return Ok(());
    }
    info!("uplink changed: {} via {}", v4.dev, v4.gateway.as_deref().unwrap_or("link"));
    loose_rp_filter(&v4.dev, log)?;
    route_bypass(cfg, &v4, v6.as_ref(), log)?;
    *current = Some((v4, v6));
    Ok(())
}

/// Host routes for the proxy servers via the physical uplink.
fn route_bypass(cfg: &SysConfig, v4: &DefaultRoute, v6: Option<&DefaultRoute>, log: &mut UndoLog) -> Result<()> {
    for ip in &cfg.bypass {
        let (route, family, prefix) = match ip {
            IpAddr::V4(_) => (v4, "-4", 32),
            IpAddr::V6(_) => match v6 {
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
    Ok(())
}

/// The effective mode is max(all, dev): strict (1) drops replies to sockets
/// bound to the uplink, because the route back points into the TUN.
fn loose_rp_filter(dev: &str, log: &mut UndoLog) -> Result<()> {
    let read = |name: &str| {
        std::fs::read_to_string(format!("/proc/sys/net/ipv4/conf/{name}/rp_filter"))
            .ok()
            .and_then(|v| v.trim().parse::<u8>().ok())
    };
    let (Some(all), Some(own)) = (read("all"), read(dev)) else { return Ok(()) };
    if all.max(own) != 1 {
        return Ok(());
    }
    let path = format!("/proc/sys/net/ipv4/conf/{dev}/rp_filter");
    log.push(Undo::WriteFile { path: path.clone().into(), content: format!("{own}\n") })?;
    std::fs::write(&path, "2\n").with_context(|| format!("writing {path}"))?;
    info!("rp_filter on {dev}: strict -> loose");
    Ok(())
}

fn has(bin: &str) -> bool {
    !matches!(run(&[bin, "--version"]), Err(RunError::Spawn(_)))
}

/// iptables talks to nf_tables (its tables are visible to `nft`), not legacy xtables.
fn iptables_is_nft() -> bool {
    run(&["iptables", "--version"]).is_ok_and(|v| v.contains("nf_tables"))
}

/// Lets new inbound connections in through the TUN (the TCP stack terminates
/// every flow at a listener on the TUN address). Best effort: a firewall we
/// cannot open shows up as TCP not working, never as a leak.
fn allow_tun_input(tun: &str, log: &mut UndoLog) -> Result<()> {
    // iptables front-ends (ufw, docker, iptables.rules): insert at the top of INPUT.
    let iptables = has("iptables");
    for bin in ["iptables", "ip6tables"] {
        let Ok(rules) = run(&[bin, "-w", "-S", "INPUT"]) else { continue };
        let filtering = rules.lines().any(|l| l.starts_with("-P INPUT") && !l.ends_with("ACCEPT"))
            || rules.lines().any(|l| l.starts_with("-A INPUT"));
        if !filtering {
            continue;
        }
        log.push_cmd(&[bin, "-w", "-D", "INPUT", "-i", tun, "-j", "ACCEPT"])?;
        match run(&[bin, "-w", "-I", "INPUT", "1", "-i", tun, "-j", "ACCEPT"]) {
            Ok(_) => info!("{bin}: INPUT accepts {tun}"),
            Err(e) => warn!("{bin}: cannot open INPUT for {tun}: {e}"),
        }
    }

    // firewalld: put the TUN into the trusted zone (runtime only).
    if run(&["firewall-cmd", "--state"]).is_ok() {
        log.push_cmd(&["firewall-cmd", "--zone=trusted", "--remove-interface", tun])?;
        match run(&["firewall-cmd", "--zone=trusted", "--add-interface", tun]) {
            Ok(_) => info!("firewalld: {tun} in zone trusted"),
            Err(e) => warn!("firewalld: cannot trust {tun}: {e}"),
        }
    }

    // Native nftables rulesets (e.g. /etc/nftables.conf with policy drop).
    if !has("nft") {
        return Ok(());
    }
    let Ok(out) = run(&["nft", "-j", "list", "chains"]) else { return Ok(()) };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&out) else { return Ok(()) };
    let skip_iptables_tables = iptables && iptables_is_nft();
    for item in json["nftables"].as_array().into_iter().flatten() {
        let c = &item["chain"];
        if c["hook"] != "input" || c["type"] != "filter" {
            continue;
        }
        let (Some(family), Some(table), Some(chain)) = (c["family"].as_str(), c["table"].as_str(), c["name"].as_str())
        else {
            continue;
        };
        let iptables_owned = skip_iptables_tables && matches!(family, "ip" | "ip6") && table == "filter";
        if table == "duotun" || table == "firewalld" || iptables_owned {
            continue;
        }
        let rule = format!("iifname \"{tun}\" accept");
        match run(&["nft", "--echo", "--handle", "insert", "rule", family, table, chain, &rule]) {
            Ok(echo) => {
                let handle = echo.split("# handle ").nth(1).and_then(|h| h.split_whitespace().next());
                if let Some(h) = handle {
                    log.push_cmd(&["nft", "delete", "rule", family, table, chain, "handle", h])?;
                }
                info!("nft: {family} {table} {chain} accepts {tun}");
            }
            Err(e) => warn!("nft: cannot open {family} {table} {chain} for {tun}: {e}"),
        }
    }
    Ok(())
}

/// Redirects every DNS query that would leave outside the TUN into it, and
/// rejects what cannot be redirected. Returns whether queries are redirected
/// (then resolver settings do not matter for leaks).
fn guard_dns(cfg: &SysConfig, log: &mut UndoLog) -> Result<bool> {
    let tun = cfg.tun_name.as_str();
    if has("nft") {
        let _ = run(&["nft", "delete", "table", "inet", "duotun"]);
        log.push_cmd(&["nft", "delete", "table", "inet", "duotun"])?;
        let path = "/run/duotun.nft";
        std::fs::write(path, nft_rules(tun, cfg.dns, cfg.ipv6.is_some(), true))?;
        let loaded = run(&["nft", "-f", path]);
        if loaded.is_ok() {
            let _ = std::fs::remove_file(path);
            info!("strict dns: port 53 redirected into {tun}, blocked elsewhere (nft table inet duotun)");
            return Ok(true);
        }
        // Old kernel or nft without NAT in inet tables: block only.
        std::fs::write(path, nft_rules(tun, cfg.dns, cfg.ipv6.is_some(), false))?;
        let loaded = run(&["nft", "-f", path]);
        let _ = std::fs::remove_file(path);
        match loaded {
            Ok(_) => {
                info!("strict dns: port 53 blocked outside {tun} (nft, no redirect)");
                return Ok(false);
            }
            Err(e) => warn!("nft rules failed, trying iptables: {e}"),
        }
    }
    if has("iptables") {
        return iptables_guard(tun, cfg.dns, cfg.ipv6.is_some(), log);
    }
    warn!("neither nft nor iptables found: strict DNS is NOT active (install nftables)");
    Ok(false)
}

/// The output hook keeps the output device it was entered with, even after
/// DNAT rerouted the packet into the TUN: redirected queries are let through by
/// address there, and the final check on the real device is in postrouting.
fn nft_rules(tun: &str, dns: Ipv4Addr, ipv6: bool, redirect: bool) -> String {
    let nat = if redirect {
        format!(
            "  chain nat_output {{\n\
             \x20   type nat hook output priority -100; policy accept;\n\
             \x20   oifname \"{tun}\" return\n\
             \x20   fib daddr type local return\n\
             \x20   meta nfproto ipv4 meta l4proto {{ tcp, udp }} th dport 53 dnat ip to {dns}\n\
             \x20 }}\n\
             \x20 chain nat_prerouting {{\n\
             \x20   type nat hook prerouting priority -100; policy accept;\n\
             \x20   iifname {{ \"lo\", \"{tun}\" }} return\n\
             \x20   fib daddr type local return\n\
             \x20   meta nfproto ipv4 meta l4proto {{ tcp, udp }} th dport 53 dnat ip to {dns}\n\
             \x20 }}\n"
        )
    } else {
        String::new()
    };
    // Without IPv6 in the tunnel nothing may leave over IPv6 (LAN excepted).
    let v6_block = if ipv6 {
        String::new()
    } else {
        "    meta nfproto ipv6 ip6 daddr != { fe80::/10, fc00::/7, ff00::/8 } meta l4proto { tcp, udp } reject\n".into()
    };
    format!(
        "table inet duotun {{\n\
         {nat}\
         \x20 chain output {{\n\
         \x20   type filter hook output priority 0; policy accept;\n\
         \x20   oifname {{ \"lo\", \"{tun}\" }} accept\n\
         \x20   ip daddr {dns} accept\n\
         \x20   meta l4proto tcp th dport {{ 53, 853 }} reject with tcp reset\n\
         \x20   meta l4proto udp th dport {{ 53, 853 }} reject\n\
         {v6_block}\
         \x20 }}\n\
         \x20 chain postrouting {{\n\
         \x20   type filter hook postrouting priority 0; policy accept;\n\
         \x20   oifname {{ \"lo\", \"{tun}\" }} accept\n\
         \x20   meta l4proto {{ tcp, udp }} th dport {{ 53, 853 }} drop\n\
         \x20 }}\n\
         \x20 chain forward {{\n\
         \x20   type filter hook forward priority 0; policy accept;\n\
         \x20   oifname \"{tun}\" accept\n\
         \x20   meta l4proto tcp th dport {{ 53, 853 }} reject with tcp reset\n\
         \x20   meta l4proto udp th dport {{ 53, 853 }} reject\n\
         \x20 }}\n\
         }}\n"
    )
}

/// The same guard with iptables (no `nft` binary): chains DUOTUN* hooked at the
/// top of the built-in ones.
fn iptables_guard(tun: &str, dns: Ipv4Addr, ipv6: bool, log: &mut UndoLog) -> Result<bool> {
    let dns = dns.to_string();
    let mut redirected = true;
    // (binary, table, built-in chain, our chain, rules)
    let mut plan: Vec<(&str, &str, &str, &str, Vec<Vec<&str>>)> = vec![];
    let reject = |bin: &'static str| -> Vec<Vec<&str>> {
        let mut r = vec![vec!["-o", "lo", "-j", "RETURN"], vec!["-o", tun, "-j", "RETURN"]];
        // `-o` still names the original device after DNAT moved a query into the TUN.
        if bin == "iptables" {
            r.push(vec!["-d", dns.as_str(), "-j", "RETURN"]);
        }
        for port in ["53", "853"] {
            r.push(vec!["-p", "tcp", "--dport", port, "-j", "REJECT", "--reject-with", "tcp-reset"]);
            r.push(vec!["-p", "udp", "--dport", port, "-j", "REJECT"]);
        }
        if bin == "ip6tables" && !ipv6 {
            for net in ["fe80::/10", "fc00::/7", "ff00::/8"] {
                r.insert(2, vec!["-d", net, "-j", "RETURN"]);
            }
            r.push(vec!["-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"]);
            r.push(vec!["-p", "udp", "-j", "REJECT"]);
        }
        r
    };
    let dnat = |inbound: bool| -> Vec<Vec<&str>> {
        let mut r = vec![];
        if inbound {
            r.push(vec!["-i", "lo", "-j", "RETURN"]);
            r.push(vec!["-i", tun, "-j", "RETURN"]);
        } else {
            r.push(vec!["-o", tun, "-j", "RETURN"]);
        }
        r.push(vec!["-m", "addrtype", "--dst-type", "LOCAL", "-j", "RETURN"]);
        r.push(vec!["-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", dns.as_str()]);
        r.push(vec!["-p", "tcp", "--dport", "53", "-j", "DNAT", "--to-destination", dns.as_str()]);
        r
    };
    // Last check on the real output device (the OUTPUT chain sees the
    // pre-DNAT one): a redirected query that still heads for the uplink, from
    // a socket bound to it, is dropped.
    let post = || -> Vec<Vec<&str>> {
        let mut r = vec![vec!["-o", "lo", "-j", "RETURN"], vec!["-o", tun, "-j", "RETURN"]];
        for port in ["53", "853"] {
            r.push(vec!["-p", "tcp", "--dport", port, "-j", "DROP"]);
            r.push(vec!["-p", "udp", "--dport", port, "-j", "DROP"]);
        }
        r
    };
    plan.push(("iptables", "nat", "OUTPUT", "DUOTUN_DNS_OUT", dnat(false)));
    plan.push(("iptables", "nat", "PREROUTING", "DUOTUN_DNS_IN", dnat(true)));
    plan.push(("iptables", "filter", "OUTPUT", "DUOTUN_OUT", reject("iptables")));
    if has("ip6tables") {
        plan.push(("ip6tables", "filter", "OUTPUT", "DUOTUN_OUT", reject("ip6tables")));
        plan.push(("ip6tables", "mangle", "POSTROUTING", "DUOTUN_POST", post()));
    }
    plan.push(("iptables", "mangle", "POSTROUTING", "DUOTUN_POST", post()));
    for (bin, table, builtin, chain, rules) in plan {
        let base = [bin, "-w", "-t", table];
        let cmd = |extra: &[&str]| -> Vec<String> { base.iter().chain(extra).map(|s| s.to_string()).collect() };
        // Leftovers of a crashed run would make -N fail.
        let _ = run_strs(&cmd(&["-D", builtin, "-j", chain]));
        let _ = run_strs(&cmd(&["-F", chain]));
        let _ = run_strs(&cmd(&["-X", chain]));

        log.push(Undo::Cmd(cmd(&["-X", chain])))?;
        log.push(Undo::Cmd(cmd(&["-F", chain])))?;
        let result = (|| -> Result<(), RunError> {
            run_strs(&cmd(&["-N", chain]))?;
            for r in &rules {
                let mut full = vec!["-A", chain];
                full.extend(r);
                run_strs(&cmd(&full))?;
            }
            Ok(())
        })();
        if let Err(e) = result {
            warn!("{bin} -t {table}: {e}");
            if table == "nat" {
                redirected = false;
            }
            continue;
        }
        log.push(Undo::Cmd(cmd(&["-D", builtin, "-j", chain])))?;
        if let Err(e) = run_strs(&cmd(&["-I", builtin, "1", "-j", chain])) {
            warn!("{bin} -t {table}: {e}");
            if table == "nat" {
                redirected = false;
            }
        }
    }
    info!("strict dns: port 53 {} (iptables)", if redirected { "redirected into the TUN" } else { "blocked outside the TUN" });
    Ok(redirected)
}

fn run_strs(argv: &[String]) -> Result<String, RunError> {
    let args: Vec<&str> = argv.iter().map(String::as_str).collect();
    run(&args)
}

fn default_route(v6: bool, tun: &str) -> Result<DefaultRoute> {
    let out = run(&["ip", "-j", if v6 { "-6" } else { "-4" }, "route", "show", "default"])?;
    let routes: Vec<serde_json::Value> = serde_json::from_str(&out)?;
    let mut found: Vec<(u64, DefaultRoute)> = routes
        .iter()
        .filter_map(|r| {
            // Multipath routes list their gateways under `nexthops`.
            let hop = if r["dev"].is_string() { r } else { r["nexthops"].get(0)? };
            let dev = hop["dev"].as_str()?.to_string();
            (dev != tun).then(|| {
                (
                    r["metric"].as_u64().unwrap_or(0),
                    DefaultRoute { gateway: hop["gateway"].as_str().map(String::from), dev },
                )
            })
        })
        .collect();
    found.sort_by_key(|(metric, _)| *metric);
    found.into_iter().next().map(|(_, r)| r).context("empty default route table")
}

/// systemd-resolved answers through its stub, i.e. /etc/resolv.conf points
/// only at 127.0.0.53/54. Its D-Bus API is not namespaced: in another network
/// namespace (containers, tests) it would configure the host, so the stub
/// check also guards against that.
fn resolved_in_use() -> bool {
    let conf = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let servers: Vec<&str> = conf
        .lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .map(str::trim)
        .collect();
    !servers.is_empty()
        && servers.iter().all(|s| matches!(*s, "127.0.0.53" | "127.0.0.54"))
        && run(&["resolvectl", "status"]).is_ok()
}

fn set_dns(cfg: &SysConfig, log: &mut UndoLog, redirected: bool) -> Result<()> {
    let tun = cfg.tun_name.as_str();
    let dns = cfg.dns.to_string();
    if resolved_in_use() {
        // NetworkManager may push its own (empty) DNS for a device it sees come up.
        if run(&["nmcli", "-t", "general", "status"]).is_ok() {
            let _ = run(&["nmcli", "device", "set", tun, "managed", "no"]);
        }
        log.push_cmd(&["resolvectl", "flush-caches"])?;
        log.push_cmd(&["resolvectl", "revert", tun])?;
        let configured = run(&["resolvectl", "dns", tun, &dns])
            // `~.`: this link answers every domain, other links are not asked.
            .and_then(|_| run(&["resolvectl", "domain", tun, "~."]));
        if let Err(e) = run(&["resolvectl", "default-route", tun, "true"]) {
            debug!("resolvectl default-route: {e}");
        }
        let _ = run(&["resolvectl", "flush-caches"]);
        match configured {
            Ok(_) => info!("dns via systemd-resolved on {tun} -> {dns}"),
            // Its upstream queries are redirected into the TUN anyway.
            Err(e) if redirected => warn!("systemd-resolved not configured ({e}); relying on the redirect"),
            Err(e) => return Err(e.into()),
        }
        return Ok(());
    }
    if redirected {
        // Whatever resolv.conf says, its queries end up in the TUN.
        info!("dns: resolver left as is, all port-53 traffic goes into {tun}");
        return Ok(());
    }

    // No redirect available: point the resolver at the TUN ourselves.
    let path = Path::new("/etc/resolv.conf");
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => {
            let target = std::fs::read_link(path)?;
            log.push(Undo::Symlink { path: path.to_path_buf(), target })?;
            std::fs::remove_file(path)?;
        }
        _ => {
            let original = std::fs::read_to_string(path).unwrap_or_default();
            log.push(Undo::WriteFile { path: path.to_path_buf(), content: original })?;
        }
    }
    std::fs::write(path, format!("# written by duotun\nnameserver {dns}\n"))?;
    info!("dns via /etc/resolv.conf -> {dns}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nft_ruleset_redirects_and_blocks() {
        let r = nft_rules("duoray0", Ipv4Addr::new(198, 19, 233, 2), true, true);
        assert!(r.contains("dnat ip to 198.19.233.2"));
        assert!(r.contains("oifname { \"lo\", \"duoray0\" } accept"));
        assert!(!r.contains("meta nfproto ipv6 ip6 daddr"));
        let r = nft_rules("duoray0", Ipv4Addr::new(198, 19, 233, 2), false, false);
        assert!(!r.contains("dnat"));
        assert!(r.contains("meta nfproto ipv6 ip6 daddr"));
    }
}
