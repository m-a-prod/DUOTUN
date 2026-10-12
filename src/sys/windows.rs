//! Windows: routes via `route`/`netsh`, DNS on the Wintun adapter, and a
//! Windows Firewall rule that blocks DNS to anything but the TUN's resolver
//! (Windows otherwise queries every adapter's DNS server in parallel).

use std::net::IpAddr;

use anyhow::{Context, Result, bail};
use tracing::{info, warn};

use super::{SysConfig, UndoLog, run};

const FW_RULE: &str = "DUORAY DNS guard";
const FW_INBOUND: &str = "DUORAY TUN";
const FW_IPV6: &str = "DUORAY IPv6 guard";

/// Before any address goes on the new adapter: no duplicate address
/// detection (its addresses are usable at once; WireGuard does the same) and
/// metric 1, so its routes and DNS server win. Per family; IPv6 may be off.
pub fn prepare_interface(index: u32) {
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetIpInterfaceEntry, MIB_IPINTERFACE_ROW, SetIpInterfaceEntry};
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
    for family in [AF_INET, AF_INET6] {
        let mut row = MIB_IPINTERFACE_ROW { Family: family, InterfaceIndex: index, ..Default::default() };
        // SAFETY: Family and InterfaceIndex identify the row to fill.
        if unsafe { GetIpInterfaceEntry(&mut row) } != 0 {
            continue;
        }
        row.DadTransmits = 0;
        row.UseAutomaticMetric = false;
        row.Metric = 1;
        // Read back as non-zero, rejected when written (see tun-rs).
        row.SitePrefixLength = 0;
        // SAFETY: a row just read for this interface.
        let err = unsafe { SetIpInterfaceEntry(&mut row) };
        if err != 0 {
            warn!("TUN interface settings (family {family}): error {err}");
        }
    }
}

/// Adds `addr/prefix` to the adapter, preferred at once (no tentative wait).
pub fn add_address(index: u32, addr: IpAddr, prefix: u8) -> Result<()> {
    use windows_sys::Win32::Foundation::ERROR_OBJECT_ALREADY_EXISTS;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        CreateUnicastIpAddressEntry, InitializeUnicastIpAddressEntry, MIB_UNICASTIPADDRESS_ROW,
    };
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, IpDadStatePreferred, SOCKADDR_IN, SOCKADDR_IN6,
        SOCKADDR_INET,
    };
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    // SAFETY: fills defaults into a local row.
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceIndex = index;
    row.OnLinkPrefixLength = prefix;
    row.DadState = IpDadStatePreferred;
    row.Address = match addr {
        IpAddr::V4(a) => SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_addr: IN_ADDR { S_un: IN_ADDR_0 { S_addr: u32::from_ne_bytes(a.octets()) } },
                ..Default::default()
            },
        },
        IpAddr::V6(a) => SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_addr: IN6_ADDR { u: IN6_ADDR_0 { Byte: a.octets() } },
                ..Default::default()
            },
        },
    };
    // SAFETY: a fully initialised local row.
    let err = unsafe { CreateUnicastIpAddressEntry(&row) };
    if err != 0 && err != ERROR_OBJECT_ALREADY_EXISTS {
        bail!("CreateUnicastIpAddressEntry {addr}/{prefix}: error {err}");
    }
    Ok(())
}

struct DefaultRoute {
    gateway: String,
    if_index: u32,
    alias: String,
}

pub fn apply(cfg: &SysConfig, log: &mut UndoLog) -> Result<()> {
    let tun = cfg.tun_name.as_str();
    let tun_index = adapter_index(tun)?;
    let v4 = default_route(false, tun_index).context("no IPv4 default route")?;
    let v6 = default_route(true, tun_index).ok();
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
    } else if v6.is_some() {
        block_ipv6_outside_tun(cfg, log)?;
    }

    // 3. The TUN's resolver, preferred over every other adapter.
    run(&[
        "netsh", "interface", "ipv4", "set", "dnsservers", &format!("name={tun_idx}"), "source=static",
        &format!("address={peer}"), "register=none", "validate=no",
    ])?;
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

/// The TUN has no IPv6 (it could not be set up on it) but the uplink has:
/// IPv6 would bypass the tunnel. Blocks it to the internet (2000::/3, the
/// LAN keeps working) so apps fall back to IPv4, which goes through the TUN.
/// Not when a proxy server is IPv6-only reachable: block rules win over the
/// bypass route, and the tunnel itself would break.
fn block_ipv6_outside_tun(cfg: &SysConfig, log: &mut UndoLog) -> Result<()> {
    if cfg.bypass.iter().any(IpAddr::is_ipv6) {
        warn!("no IPv6 on the TUN and an IPv6 proxy server: IPv6 is NOT guarded");
        return Ok(());
    }
    let name = format!("name={FW_IPV6}");
    let _ = run(&["netsh", "advfirewall", "firewall", "delete", "rule", &name]);
    log.push_cmd(&["netsh", "advfirewall", "firewall", "delete", "rule", &name])?;
    match run(&["netsh", "advfirewall", "firewall", "add", "rule", &name, "dir=out", "action=block", "remoteip=2000::/3"]) {
        Ok(_) => info!("no IPv6 on the TUN: internet IPv6 blocked (Windows Firewall)"),
        Err(e) => warn!("firewall rule failed, IPv6 may bypass the tunnel: {e}"),
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

// The adapter and route lookups call the IP Helper API directly: each
// PowerShell start used to cost about two seconds of the connect time.

fn adapter_index(name: &str) -> Result<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex};
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    let alias: Vec<u16> = name.encode_utf16().chain([0]).collect();
    // The adapter may take a moment to appear after Wintun creates it.
    for _ in 0..40 {
        let mut luid = NET_LUID_LH::default();
        let mut index = 0;
        // SAFETY: `alias` is NUL-terminated; both outputs are valid locals.
        if unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut luid) } == 0
            && unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) } == 0
        {
            return Ok(index);
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    bail!("adapter {name} not found")
}

/// The default route Windows would use, ignoring the TUN: lowest route plus
/// interface metric, as the stack itself picks it.
fn default_route(v6: bool, tun_index: u32) -> Result<DefaultRoute> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIfEntry2, GetIpForwardTable2, GetIpInterfaceEntry, MIB_IF_ROW2, MIB_IPFORWARD_TABLE2,
        MIB_IPINTERFACE_ROW,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
    let family = if v6 { AF_INET6 } else { AF_INET };
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: on success the table is ours until FreeMibTable.
    let err = unsafe { GetIpForwardTable2(family, &mut table) };
    if err != 0 {
        bail!("GetIpForwardTable2: error {err}");
    }
    // SAFETY: the table holds NumEntries rows.
    let rows = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize) };
    let mut best: Option<(u32, DefaultRoute)> = None;
    for row in rows {
        if row.DestinationPrefix.PrefixLength != 0 || row.InterfaceIndex == tun_index {
            continue;
        }
        let mut iface = MIB_IPINTERFACE_ROW { Family: family, InterfaceLuid: row.InterfaceLuid, ..Default::default() };
        // SAFETY: Family and InterfaceLuid identify the row to fill.
        if unsafe { GetIpInterfaceEntry(&mut iface) } != 0 || !iface.Connected {
            continue;
        }
        let metric = row.Metric.saturating_add(iface.Metric);
        if best.as_ref().is_some_and(|(m, _)| *m <= metric) {
            continue;
        }
        // SAFETY: the union member matches the table's address family.
        let gateway = unsafe {
            if v6 {
                IpAddr::from(row.NextHop.Ipv6.sin6_addr.u.Byte).to_string()
            } else {
                IpAddr::from(row.NextHop.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()).to_string()
            }
        };
        let mut entry = MIB_IF_ROW2 { InterfaceLuid: row.InterfaceLuid, ..Default::default() };
        // SAFETY: InterfaceLuid identifies the row to fill.
        let alias = if unsafe { GetIfEntry2(&mut entry) } == 0 { wide(&entry.Alias) } else { String::new() };
        best = Some((metric, DefaultRoute { gateway, if_index: row.InterfaceIndex, alias }));
    }
    // SAFETY: allocated by GetIpForwardTable2 above.
    unsafe { FreeMibTable(table.cast()) };
    best.map(|(_, r)| r).context("no default route")
}

fn wide(s: &[u16]) -> String {
    String::from_utf16_lossy(&s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())])
}
