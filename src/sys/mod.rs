//! OS integration: routes, DNS pinning and crash recovery.
//!
//! Every change is recorded in an on-disk undo log *before* it is applied, so a
//! crash at any point can be reverted by the next start (or `duotun cleanup`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
use linux as imp;
#[cfg(target_os = "macos")]
use macos as imp;
#[cfg(windows)]
use windows as imp;
#[cfg(windows)]
pub use windows::{add_address, prepare_interface};

#[derive(Debug, Clone)]
pub struct SysConfig {
    pub tun_name: String,
    /// DNS server address the system resolver is pointed at; lives inside the TUN.
    pub dns: Ipv4Addr,
    pub ipv6: Option<Ipv6Addr>,
    /// Destinations that must keep using the physical uplink (the proxy servers).
    pub bypass: Vec<IpAddr>,
    /// Firewall off port 53 everywhere except the TUN and loopback, so even apps
    /// that query a DNS server directly (e.g. the LAN router) cannot leak.
    pub strict_dns: bool,
    /// Split non-TUN private/LAN/CGNAT/ULA routes into halves over the TUN.
    pub route_private: bool,
}

pub fn state_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    return PathBuf::from("/var/run/duotun.state.json");
    #[cfg(target_os = "linux")]
    return PathBuf::from("/run/duotun.state.json");
    #[cfg(windows)]
    return std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("duotun")
        .join("state.json");
}

/// Applies routes and DNS. The returned log reverts everything on `revert()`.
pub fn apply(cfg: &SysConfig) -> Result<UndoLog> {
    let mut log = UndoLog::create(state_path())?;
    if let Err(e) = imp::apply(cfg, &mut log) {
        log.revert();
        return Err(e);
    }
    Ok(log)
}

/// Re-applies what depends on the uplink after the network changed.
/// Cheap when nothing changed; meant to be called every few seconds.
pub fn refresh(cfg: &SysConfig, log: &mut UndoLog) -> Result<()> {
    #[cfg(target_os = "linux")]
    return imp::refresh(cfg, log);
    #[allow(unreachable_code)]
    {
        let _ = (cfg, log);
        Ok(())
    }
}

/// Updates the bypass host routes in place without touching the TUN, default
/// split routes, DNS or firewall. Adds new IPs first, then removes old ones.
pub fn update_bypass(
    cfg: &mut SysConfig,
    new_bypass: Vec<IpAddr>,
    log: &mut UndoLog,
) -> Result<()> {
    let to_add: Vec<IpAddr> = new_bypass
        .iter()
        .copied()
        .filter(|ip| !cfg.bypass.contains(ip))
        .collect();
    let to_remove: Vec<IpAddr> = cfg
        .bypass
        .iter()
        .copied()
        .filter(|ip| !new_bypass.contains(ip))
        .collect();
    if !to_add.is_empty() {
        imp::add_bypass(&cfg.tun_name, &to_add, log)?;
    }
    cfg.bypass = new_bypass;
    if !to_remove.is_empty() {
        imp::remove_bypass(&cfg.tun_name, &to_remove);
    }
    Ok(())
}

/// Reverts changes left behind by a previous run that did not exit cleanly.
pub fn recover() {
    let path = state_path();
    match UndoLog::load(&path) {
        Ok(Some(mut log)) => {
            warn!("found state from an unclean shutdown, reverting");
            log.revert();
        }
        Ok(None) => {}
        Err(e) => warn!("unreadable state file {}: {e:#}", path.display()),
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Undo {
    Cmd(Vec<String>),
    WriteFile {
        path: PathBuf,
        content: String,
    },
    /// Put a symlink back (e.g. /etc/resolv.conf managed by another tool).
    Symlink {
        path: PathBuf,
        target: PathBuf,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UndoLog {
    #[serde(skip)]
    path: PathBuf,
    steps: Vec<Undo>,
}

impl UndoLog {
    fn create(path: PathBuf) -> Result<Self> {
        let log = Self {
            path,
            steps: vec![],
        };
        log.persist()?;
        Ok(log)
    }

    fn load(path: &Path) -> Result<Option<Self>> {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let mut log: Self = serde_json::from_slice(&data)?;
        log.path = path.to_path_buf();
        Ok(Some(log))
    }

    /// Records how to undo a change. Call before making the change.
    pub fn push(&mut self, step: Undo) -> Result<()> {
        self.steps.push(step);
        self.persist()
    }

    pub fn push_cmd(&mut self, argv: &[&str]) -> Result<()> {
        let cmd: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        if self
            .steps
            .iter()
            .any(|s| matches!(s, Undo::Cmd(existing) if existing == &cmd))
        {
            return Ok(());
        }
        self.push(Undo::Cmd(cmd))
    }

    fn persist(&self) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("writing {}", self.path.display()))
    }

    /// Undoes all steps, newest first. Steps that could not even be attempted
    /// (e.g. the process could not be spawned) stay in the log for `cleanup`.
    pub fn revert(&mut self) {
        let mut retry = vec![];
        while let Some(step) = self.steps.pop() {
            match &step {
                Undo::Cmd(argv) => {
                    let args: Vec<&str> = argv.iter().map(String::as_str).collect();
                    match run(&args) {
                        Ok(_) => {}
                        // The command ran and failed: typically "not in table", nothing to undo.
                        Err(RunError::Failed(e)) => {
                            debug!("undo step failed (usually harmless): {e}")
                        }
                        Err(RunError::Spawn(e)) => {
                            warn!("undo step could not run: {e}");
                            retry.push(step);
                        }
                    }
                }
                // A per-interface sysctl of an interface that is gone: nothing to restore.
                Undo::WriteFile { path, .. } if path.starts_with("/proc") && !path.exists() => {}
                Undo::WriteFile { path, content } => {
                    if let Err(e) = std::fs::write(path, content) {
                        warn!("failed to restore {}: {e}", path.display());
                        retry.push(step);
                    }
                }
                #[cfg(unix)]
                Undo::Symlink { path, target } => {
                    let _ = std::fs::remove_file(path);
                    if let Err(e) = std::os::unix::fs::symlink(target, path) {
                        warn!(
                            "failed to restore {} -> {}: {e}",
                            path.display(),
                            target.display()
                        );
                        retry.push(step);
                    }
                }
                #[cfg(not(unix))]
                Undo::Symlink { .. } => {}
            }
        }
        if retry.is_empty() {
            let _ = std::fs::remove_file(&self.path);
            info!("system settings restored");
        } else {
            retry.reverse();
            self.steps = retry;
            let _ = self.persist();
            warn!(
                "{} undo steps failed; run `duotun cleanup` to retry",
                self.steps.len()
            );
        }
    }
}

#[derive(Debug)]
pub enum RunError {
    Spawn(String),
    Failed(String),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spawn(e) | Self::Failed(e) => f.write_str(e),
        }
    }
}

impl std::error::Error for RunError {}

pub fn run(argv: &[&str]) -> Result<String, RunError> {
    run_full(argv).map(|(stdout, _)| stdout)
}

/// Like `run`, but also returns stderr (some tools, e.g. `pfctl -E`, report there).
pub fn run_full(argv: &[&str]) -> Result<(String, String), RunError> {
    debug!("exec: {}", argv.join(" "));
    let out = Command::new(argv[0])
        .args(&argv[1..])
        .output()
        .map_err(|e| RunError::Spawn(format!("spawning {}: {e}", argv[0])))?;
    if !out.status.success() {
        return Err(RunError::Failed(format!(
            "`{}` failed: {}",
            argv.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok((
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cidr {
    pub net: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Option<Self> {
        let (addr, prefix) = s.trim().split_once('/')?;
        let ip: IpAddr = addr.split('%').next()?.parse().ok()?;
        let prefix: u8 = prefix.parse().ok()?;
        Self::new(ip, prefix)
    }

    pub fn new(ip: IpAddr, prefix: u8) -> Option<Self> {
        let max = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max {
            return None;
        }
        Some(Self {
            net: mask_ip(ip, prefix),
            prefix,
        })
    }

    pub fn format(self) -> String {
        format!("{}/{}", self.net, self.prefix)
    }

    pub fn is_ipv4(self) -> bool {
        self.net.is_ipv4()
    }

    fn overlaps(self, other: Self) -> bool {
        match (self.net, other.net) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let p = self.prefix.min(other.prefix);
                mask_v4(a, p) == mask_v4(b, p)
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let p = self.prefix.min(other.prefix);
                mask_v6(a, p) == mask_v6(b, p)
            }
            _ => false,
        }
    }

    fn split(self) -> Option<[Self; 2]> {
        match self.net {
            IpAddr::V4(a) if self.prefix < 32 => {
                let p = self.prefix + 1;
                let net = mask_v4(a, self.prefix);
                let bit = 1u32 << (31 - self.prefix);
                let second = Ipv4Addr::from(u32::from(net) | bit);
                Some([
                    Self {
                        net: IpAddr::V4(net),
                        prefix: p,
                    },
                    Self {
                        net: IpAddr::V4(second),
                        prefix: p,
                    },
                ])
            }
            IpAddr::V6(a) if self.prefix < 128 => {
                let p = self.prefix + 1;
                let net = mask_v6(a, self.prefix);
                let bit = 1u128 << (127 - self.prefix);
                let second = Ipv6Addr::from(u128::from(net) | bit);
                Some([
                    Self {
                        net: IpAddr::V6(net),
                        prefix: p,
                    },
                    Self {
                        net: IpAddr::V6(second),
                        prefix: p,
                    },
                ])
            }
            _ => None,
        }
    }
}

fn mask_ip(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(a) => IpAddr::V4(mask_v4(a, prefix)),
        IpAddr::V6(a) => IpAddr::V6(mask_v6(a, prefix)),
    }
}

fn mask_v4(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    };
    Ipv4Addr::from(u32::from(ip) & mask)
}

fn mask_v6(ip: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    let mask = if prefix == 0 {
        0
    } else {
        !0u128 << (128 - prefix)
    };
    Ipv6Addr::from(u128::from(ip) & mask)
}

#[cfg(any(windows, test))]
pub fn ipv4_netmask(prefix: u8) -> Ipv4Addr {
    let mask = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    };
    Ipv4Addr::from(mask)
}

fn is_private_candidate(c: Cidr) -> bool {
    const V4_PRIVATE: [(Ipv4Addr, u8); 4] = [
        (Ipv4Addr::new(10, 0, 0, 0), 8),
        (Ipv4Addr::new(172, 16, 0, 0), 12),
        (Ipv4Addr::new(192, 168, 0, 0), 16),
        (Ipv4Addr::new(100, 64, 0, 0), 10),
    ];
    const V4_EXCLUDED: [(Ipv4Addr, u8); 5] = [
        (Ipv4Addr::new(0, 0, 0, 0), 8),
        (Ipv4Addr::new(127, 0, 0, 0), 8),
        (Ipv4Addr::new(169, 254, 0, 0), 16),
        (Ipv4Addr::new(224, 0, 0, 0), 4),
        (Ipv4Addr::new(240, 0, 0, 0), 4),
    ];
    const V6_PRIVATE: [(Ipv6Addr, u8); 1] = [(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7)];
    const V6_EXCLUDED: [(Ipv6Addr, u8); 3] = [
        (Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 128),
        (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
        (Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),
    ];
    match c.net {
        IpAddr::V4(_) => {
            if !(2..=30).contains(&c.prefix) {
                return false;
            }
            let priv_match = V4_PRIVATE.iter().any(|&(ip, p)| {
                c.overlaps(Cidr {
                    net: IpAddr::V4(ip),
                    prefix: p,
                })
            });
            let excl_match = V4_EXCLUDED.iter().any(|&(ip, p)| {
                c.overlaps(Cidr {
                    net: IpAddr::V4(ip),
                    prefix: p,
                })
            });
            priv_match && !excl_match
        }
        IpAddr::V6(_) => {
            if !(2..=126).contains(&c.prefix) {
                return false;
            }
            let priv_match = V6_PRIVATE.iter().any(|&(ip, p)| {
                c.overlaps(Cidr {
                    net: IpAddr::V6(ip),
                    prefix: p,
                })
            });
            let excl_match = V6_EXCLUDED.iter().any(|&(ip, p)| {
                c.overlaps(Cidr {
                    net: IpAddr::V6(ip),
                    prefix: p,
                })
            });
            priv_match && !excl_match
        }
    }
}

/// Computes the split half-routes for all private/LAN/CGNAT/ULA non-TUN routes
/// so longest-prefix match sends them into the TUN instead of direct LAN.
pub fn private_split_routes(routes: &[Cidr]) -> Vec<Cidr> {
    let matching: std::collections::HashSet<Cidr> = routes
        .iter()
        .copied()
        .filter(|&c| is_private_candidate(c))
        .collect();
    let mut out = Vec::new();
    for &c in &matching {
        if let Some([a, b]) = c.split() {
            if !matching.contains(&a) {
                out.push(a);
            }
            if !matching.contains(&b) {
                out.push(b);
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(any(target_os = "linux", test))]
pub fn parse_ip_json_routes(json_str: &str, tun: &str) -> Vec<Cidr> {
    let Ok(routes) = serde_json::from_str::<Vec<serde_json::Value>>(json_str) else {
        return vec![];
    };
    const IGNORE_TYPES: &[&str] = &[
        "local",
        "broadcast",
        "multicast",
        "unreachable",
        "blackhole",
        "prohibit",
        "throw",
        "anycast",
    ];
    routes
        .iter()
        .filter_map(|r| {
            if let Some(ty) = r["type"].as_str()
                && IGNORE_TYPES.contains(&ty)
            {
                return None;
            }
            if r["dev"].as_str() == Some(tun) {
                return None;
            }
            if r["dev"].is_null()
                && let Some(hops) = r["nexthops"].as_array()
                && hops.iter().all(|h| h["dev"].as_str() == Some(tun))
            {
                return None;
            }
            let dst = r["dst"].as_str()?;
            if dst == "default" {
                return None;
            }
            Cidr::parse(dst)
        })
        .collect()
}

#[cfg(any(target_os = "macos", test))]
pub fn parse_netstat_routes(output: &str, v6: bool, tun: &str) -> Vec<Cidr> {
    let mut out = Vec::new();
    for line in output.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }
        let (dst, flags, netif) = (cols[0], cols[2], cols[3]);
        if dst == "Destination" || dst == "default" {
            continue;
        }
        if netif == tun || netif.starts_with("lo") {
            continue;
        }
        if flags.contains('H') {
            continue;
        }
        let parsed = if v6 {
            Cidr::parse(dst)
        } else {
            parse_bsd_v4_cidr(dst)
        };
        if let Some(cidr) = parsed {
            out.push(cidr);
        }
    }
    out
}

#[cfg(any(target_os = "macos", test))]
fn parse_bsd_v4_cidr(s: &str) -> Option<Cidr> {
    let (ip_part, explicit_prefix) = match s.split_once('/') {
        Some((a, p)) => (a, Some(p.parse::<u8>().ok()?)),
        None => (s, None),
    };
    let parts: Vec<&str> = ip_part.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        octets[i] = part.parse().ok()?;
    }
    let prefix = match explicit_prefix {
        Some(p) => p,
        None => match parts.len() {
            1 => 8,
            2 => 16,
            3 => 24,
            4 => 32,
            _ => return None,
        },
    };
    Cidr::new(IpAddr::V4(Ipv4Addr::from(octets)), prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> Cidr {
        Cidr::parse(s).unwrap()
    }

    #[test]
    fn private_routes_split_and_exclude_reserved() {
        let input = [
            c("192.168.1.5/24"),
            c("10.0.0.0/8"),
            c("172.16.0.0/12"),
            c("100.64.0.0/10"),
            c("fd12:3456:789a::/48"),
            // Excluded: loopback, link-local, multicast, reserved, supernet overlapping excluded, /31, /32, /1, /127
            c("127.0.0.0/8"),
            c("169.254.0.0/16"),
            c("224.0.0.0/4"),
            c("240.0.0.0/4"),
            c("0.0.0.0/2"),
            c("128.0.0.0/2"),
            c("fe80::/10"),
            c("ff00::/8"),
            c("192.168.99.0/31"),
            c("192.168.99.1/32"),
            c("fd00::/127"),
            // Public IPv4/v6
            c("8.8.8.0/24"),
            c("2001:db8::/32"),
        ];
        let got: Vec<String> = private_split_routes(&input)
            .into_iter()
            .map(Cidr::format)
            .collect();
        assert_eq!(
            got,
            vec![
                "10.0.0.0/9",
                "10.128.0.0/9",
                "100.64.0.0/11",
                "100.96.0.0/11",
                "172.16.0.0/13",
                "172.24.0.0/13",
                "192.168.1.0/25",
                "192.168.1.128/25",
                "fd12:3456:789a::/49",
                "fd12:3456:789a:8000::/49",
            ]
        );
    }

    #[test]
    fn nested_private_route_skips_overridden_half() {
        let input = [c("192.168.0.0/23"), c("192.168.0.0/24")];
        let got: Vec<String> = private_split_routes(&input)
            .into_iter()
            .map(Cidr::format)
            .collect();
        // 192.168.0.0/24 is already in `matching` (so its own /25 halves beat it).
        assert_eq!(
            got,
            vec!["192.168.0.0/25", "192.168.0.128/25", "192.168.1.0/24",]
        );
    }

    #[test]
    fn parses_ip_json_routes_and_skips_tun_and_special_types() {
        let json = r#"[
            {"dst": "default", "gateway": "192.168.1.1", "dev": "eth0"},
            {"dst": "192.168.1.0/24", "dev": "eth0", "protocol": "kernel"},
            {"dst": "192.168.1.0/25", "dev": "duoray0"},
            {"type": "local", "dst": "192.168.1.10", "dev": "eth0"},
            {"type": "broadcast", "dst": "192.168.1.255", "dev": "eth0"},
            {"dst": "10.8.0.0/24", "dev": "tun1"}
        ]"#;
        let got = parse_ip_json_routes(json, "duoray0");
        assert_eq!(got, vec![c("192.168.1.0/24"), c("10.8.0.0/24")]);
    }

    #[test]
    fn parses_macos_netstat_shorthands() {
        let v4 = "Routing tables
Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
10/8               192.168.1.1        UGSc                  en0
127                127.0.0.1          UCS                   lo0
169.254            link#4             UCS                   en0
172.16.0/20        link#5             UC                    bridge0
192.168.1          link#4             UCS                   en0
192.168.1.1/32     aa:bb:cc:dd:ee:ff  UHLS                  en0
192.168.1.0/25     link#9             UCS                   utun4
";
        let got = parse_netstat_routes(v4, false, "utun4");
        assert_eq!(
            got,
            vec![
                c("10.0.0.0/8"),
                c("169.254.0.0/16"),
                c("172.16.0.0/20"),
                c("192.168.1.0/24"),
            ]
        );

        let v6 = "Internet6:
Destination                             Gateway                         Flags         Netif Expire
default                                 fe80::1%en0                     UGc             en0
::1                                     ::1                             UHL             lo0
fd00:1234::/64                          link#4                          UC              en0
fd00:1234::/65                          link#9                          UC              utun4
fe80::%en0/64                           link#4                          UC              en0
";
        let got6 = parse_netstat_routes(v6, true, "utun4");
        assert_eq!(got6, vec![c("fd00:1234::/64"), c("fe80::/64")]);
    }

    #[test]
    fn netmask_formats_v4_prefixes() {
        assert_eq!(ipv4_netmask(0), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(ipv4_netmask(9), Ipv4Addr::new(255, 128, 0, 0));
        assert_eq!(ipv4_netmask(25), Ipv4Addr::new(255, 255, 255, 128));
        assert_eq!(ipv4_netmask(32), Ipv4Addr::new(255, 255, 255, 255));
    }
}
