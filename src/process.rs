//! Per-app routing: finds the process that owns the app side of a flow and
//! decides whether it goes through the proxy or the direct SOCKS.
//!
//! The lookup goes by the app socket's local port: a table of port → pid is
//! built from the OS socket list and rebuilt on a miss. Concurrent lookups
//! may share a scan only if it started after their lookup began.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tracing::{debug, info};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppMode {
    /// The listed apps bypass the proxy.
    Bypass,
    /// Only the listed apps use the proxy.
    Only,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRules {
    pub mode: AppMode,
    /// Executable names (`steam.exe`, `curl`), macOS app names (`Telegram`)
    /// or full paths. Case-insensitive.
    pub apps: Vec<String>,
}

impl AppRules {
    /// Does this executable match one of the entries?
    pub fn matches(&self, exe: &Path) -> bool {
        let path = exe.to_string_lossy().to_lowercase();
        let file = exe.file_name().map(|f| f.to_string_lossy().to_lowercase()).unwrap_or_default();
        let stem = file.strip_suffix(".exe").unwrap_or(&file);
        self.apps.iter().any(|entry| {
            let entry = entry.trim().to_lowercase();
            if entry.is_empty() {
                return false;
            }
            if entry.contains('/') || entry.contains('\\') {
                return path == entry || path.starts_with(&format!("{}/", entry.trim_end_matches('/')));
            }
            let name = entry.strip_suffix(".exe").unwrap_or(&entry);
            // A macOS bundle: everything inside Telegram.app belongs to "Telegram".
            stem == name || path.contains(&format!("/{}.app/", entry.trim_end_matches(".app")))
        })
    }

    /// `true` if a flow of this executable (or of an unknown one) goes direct.
    /// Unknown processes always use the proxy: never leak by mistake.
    pub fn is_direct(&self, exe: Option<&Path>) -> bool {
        match (self.mode, exe) {
            (_, None) => false,
            (AppMode::Bypass, Some(e)) => self.matches(e),
            (AppMode::Only, Some(e)) => !self.matches(e),
        }
    }
}

#[derive(Default)]
struct Table {
    ports: HashMap<u16, u32>,
    /// Scan start, not completion: sockets created during a scan can be missed.
    scanned: Option<Instant>,
}

impl Table {
    fn owner(&mut self, port: u16, asked: Instant, scan: impl FnOnce() -> HashMap<u16, u32>) -> Option<u32> {
        let found = self.ports.get(&port).copied();
        let fresh = self.scanned.is_some_and(|s| s.elapsed() < Duration::from_secs(1));
        if (found.is_some() && fresh) || self.scanned.is_some_and(|s| s > asked) {
            return found;
        }
        self.scanned = Some(Instant::now());
        self.ports = scan();
        self.ports.get(&port).copied()
    }
}

#[derive(Default)]
pub struct Finder {
    /// Only for logging decisions.
    rules: Option<AppRules>,
    tcp: Mutex<Table>,
    udp: Mutex<Table>,
    paths: Mutex<HashMap<u32, (Option<PathBuf>, Instant)>>,
}

impl Finder {
    /// Executable of the process owning the local socket `local`. Blocking.
    ///
    /// On a miss the table is rescanned, unless another lookup already
    /// rescanned it after this one started (the socket existed by then, so
    /// a second scan would not find it either). Lookups queue on the lock,
    /// so a burst of new connections shares one scan.
    pub fn lookup(&self, tcp: bool, local: SocketAddr) -> Option<PathBuf> {
        let asked = Instant::now();
        let pid = {
            let mut t = if tcp { self.tcp.lock().unwrap() } else { self.udp.lock().unwrap() };
            t.owner(local.port(), asked, || imp::scan(tcp))
        }?;
        let mut paths = self.paths.lock().unwrap();
        if let Some((p, at)) = paths.get(&pid)
            && at.elapsed() < Duration::from_secs(60)
        {
            return p.clone();
        }
        if paths.len() > 4096 {
            paths.clear();
        }
        let p = imp::exe_path(pid);
        debug!(pid, exe = ?p, port = local.port(), tcp, "flow owner");
        // Once per process: what per-app routing decided for it.
        if let Some(exe) = &p {
            let direct = self.rules.as_ref().is_some_and(|r| r.is_direct(Some(exe)));
            info!(pid, exe = %exe.display(), "app {}", if direct { "→ direct" } else { "→ proxy" });
        }
        // A transient proc_pidpath failure must not proxy this PID for a minute.
        if p.is_some() {
            paths.insert(pid, (p.clone(), Instant::now()));
        }
        p
    }
}

/// Port → pid of every socket of one protocol (diagnostics).
pub fn scan_table(tcp: bool) -> HashMap<u16, u32> {
    imp::scan(tcp)
}

/// Executable of a process (diagnostics).
pub fn exe_path(pid: u32) -> Option<PathBuf> {
    imp::exe_path(pid)
}

/// Decides per flow; shared by the TCP and UDP stacks.
pub struct AppRouter {
    pub rules: AppRules,
    finder: Finder,
}

impl AppRouter {
    pub fn new(rules: AppRules) -> Arc<Self> {
        let finder = Finder { rules: Some(rules.clone()), ..Default::default() };
        Arc::new(Self { rules, finder })
    }

    /// `true` if the flow from the app socket `src` should go direct.
    pub async fn is_direct(self: &Arc<Self>, src: SocketAddr, tcp: bool) -> bool {
        let this = self.clone();
        let exe = tokio::task::spawn_blocking(move || this.finder.lookup(tcp, src)).await.ok().flatten();
        let direct = self.rules.is_direct(exe.as_deref());
        debug!(%src, tcp, exe = ?exe, direct, "per-app flow decision");
        direct
    }
}

#[cfg(target_os = "macos")]
mod imp {
    //! libproc: every process's socket descriptors (needs root for other users).
    use std::collections::HashMap;
    use std::ffi::c_void;
    use std::path::PathBuf;

    unsafe extern "C" {
        fn proc_listallpids(buffer: *mut c_void, buffersize: i32) -> i32;
        fn proc_pidinfo(pid: i32, flavor: i32, arg: u64, buffer: *mut c_void, buffersize: i32) -> i32;
        fn proc_pidfdinfo(pid: i32, fd: i32, flavor: i32, buffer: *mut c_void, buffersize: i32) -> i32;
        fn proc_pidpath(pid: i32, buffer: *mut c_void, buffersize: u32) -> i32;
    }

    const PROC_PIDLISTFDS: i32 = 1;
    const PROC_PIDFDSOCKETINFO: i32 = 3;
    const PROX_FDTYPE_SOCKET: u32 = 2;
    // struct socket_fdinfo (sys/proc_info.h): size and field offsets.
    const SOCKET_FDINFO_SIZE: usize = 792;
    const OFF_PROTOCOL: usize = 180;
    const OFF_FAMILY: usize = 184;
    const OFF_KIND: usize = 256;
    const OFF_LPORT: usize = 268;
    const SOCKINFO_IN: i32 = 1;
    const SOCKINFO_TCP: i32 = 2;

    fn i32_at(b: &[u8], off: usize) -> i32 {
        i32::from_ne_bytes(b[off..off + 4].try_into().unwrap())
    }

    pub fn scan(tcp: bool) -> HashMap<u16, u32> {
        let mut out = HashMap::new();
        let want_proto = if tcp { libc::IPPROTO_TCP } else { libc::IPPROTO_UDP };
        // SAFETY: plain libproc calls on buffers we own, sized as passed.
        unsafe {
            let n = proc_listallpids(std::ptr::null_mut(), 0);
            if n <= 0 {
                return out;
            }
            let mut pids = vec![0i32; n as usize + 64];
            let n = proc_listallpids(pids.as_mut_ptr().cast(), (pids.len() * 4) as i32);
            pids.truncate(n.max(0) as usize);
            let mut fds: Vec<[u32; 2]> = vec![];
            let mut info = vec![0u8; SOCKET_FDINFO_SIZE];
            for pid in pids {
                let size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0);
                if size <= 0 {
                    continue;
                }
                fds.resize(size as usize / 8 + 16, [0, 0]);
                let size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds.as_mut_ptr().cast(), (fds.len() * 8) as i32);
                for &[fd, kind] in &fds[..size.max(0) as usize / 8] {
                    if kind != PROX_FDTYPE_SOCKET {
                        continue;
                    }
                    let r = proc_pidfdinfo(
                        pid,
                        fd as i32,
                        PROC_PIDFDSOCKETINFO,
                        info.as_mut_ptr().cast(),
                        SOCKET_FDINFO_SIZE as i32,
                    );
                    if r < SOCKET_FDINFO_SIZE as i32 {
                        continue;
                    }
                    let family = i32_at(&info, OFF_FAMILY);
                    let kind = i32_at(&info, OFF_KIND);
                    if !(family == libc::AF_INET || family == libc::AF_INET6)
                        || !(kind == SOCKINFO_IN || kind == SOCKINFO_TCP)
                        || i32_at(&info, OFF_PROTOCOL) != want_proto
                    {
                        continue;
                    }
                    // insi_lport holds the port in network byte order.
                    let port = u16::from_be(i32_at(&info, OFF_LPORT) as u16);
                    if port != 0 {
                        out.insert(port, pid as u32);
                    }
                }
            }
        }
        out
    }

    pub fn exe_path(pid: u32) -> Option<PathBuf> {
        let mut buf = vec![0u8; 4096];
        // SAFETY: buffer of the size passed.
        let n = unsafe { proc_pidpath(pid as i32, buf.as_mut_ptr().cast(), buf.len() as u32) };
        if n <= 0 {
            return None;
        }
        buf.truncate(n as usize);
        Some(PathBuf::from(String::from_utf8_lossy(&buf).into_owned()))
    }
}

#[cfg(target_os = "linux")]
mod imp {
    //! /proc/net/{tcp,udp}{,6} for port → socket inode, then /proc/*/fd for the owner.
    use std::collections::HashMap;
    use std::path::PathBuf;

    pub fn scan(tcp: bool) -> HashMap<u16, u32> {
        let proto = if tcp { "tcp" } else { "udp" };
        let mut inodes: HashMap<u64, u16> = HashMap::new();
        for file in [format!("/proc/net/{proto}"), format!("/proc/net/{proto}6")] {
            let Ok(text) = std::fs::read_to_string(&file) else { continue };
            for line in text.lines().skip(1) {
                let cols: Vec<&str> = line.split_whitespace().collect();
                let (Some(local), Some(inode)) = (cols.get(1), cols.get(9)) else { continue };
                let port = local.rsplit(':').next().and_then(|p| u16::from_str_radix(p, 16).ok());
                if let (Some(port), Ok(inode)) = (port, inode.parse::<u64>())
                    && inode != 0
                {
                    inodes.insert(inode, port);
                }
            }
        }
        let mut out = HashMap::new();
        let Ok(procs) = std::fs::read_dir("/proc") else { return out };
        for p in procs.flatten() {
            let Ok(pid) = p.file_name().to_string_lossy().parse::<u32>() else { continue };
            let Ok(fds) = std::fs::read_dir(p.path().join("fd")) else { continue };
            for fd in fds.flatten() {
                let Ok(link) = std::fs::read_link(fd.path()) else { continue };
                let link = link.to_string_lossy();
                if let Some(inode) = link.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']'))
                    && let Some(port) = inode.parse::<u64>().ok().and_then(|i| inodes.get(&i))
                {
                    out.insert(*port, pid);
                }
            }
        }
        out
    }

    pub fn exe_path(pid: u32) -> Option<PathBuf> {
        std::fs::read_link(format!("/proc/{pid}/exe")).ok()
    }
}

#[cfg(windows)]
mod imp {
    //! IP Helper tables with owning pids.
    use std::collections::HashMap;
    use std::path::PathBuf;

    use windows_sys::Win32::Foundation::{CloseHandle, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
    };

    /// Rows: (local port in network order in the low 16 bits, pid) at the
    /// given offsets of each fixed-size row after a u32 count.
    fn table(tcp: bool, family: u16) -> Vec<u8> {
        let mut size = 0u32;
        let mut buf: Vec<u8> = vec![];
        for _ in 0..4 {
            // SAFETY: the buffer has `size` bytes; the API reports the size needed.
            let r = unsafe {
                if tcp {
                    GetExtendedTcpTable(buf.as_mut_ptr().cast(), &mut size, 0, family as u32, TCP_TABLE_OWNER_PID_ALL, 0)
                } else {
                    GetExtendedUdpTable(buf.as_mut_ptr().cast(), &mut size, 0, family as u32, UDP_TABLE_OWNER_PID, 0)
                }
            };
            if r == NO_ERROR {
                return buf;
            }
            buf = vec![0u8; size as usize + 4096];
            size = buf.len() as u32;
        }
        vec![]
    }

    pub fn scan(tcp: bool) -> HashMap<u16, u32> {
        let mut out = HashMap::new();
        // (family, row size, local port offset, pid offset)
        let layouts: [(u16, usize, usize, usize); 2] = if tcp {
            // MIB_TCPROW_OWNER_PID: state, laddr, lport, raddr, rport, pid
            // MIB_TCP6ROW_OWNER_PID: laddr[16], lscope, lport, raddr[16], rscope, rport, state, pid
            [(AF_INET, 24, 8, 20), (AF_INET6, 56, 20, 52)]
        } else {
            // MIB_UDPROW_OWNER_PID: laddr, lport, pid
            // MIB_UDP6ROW_OWNER_PID: laddr[16], lscope, lport, pid
            [(AF_INET, 12, 4, 8), (AF_INET6, 28, 20, 24)]
        };
        for (family, row, port_off, pid_off) in layouts {
            let buf = table(tcp, family);
            if buf.len() < 4 {
                continue;
            }
            let n = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
            for i in 0..n {
                let base = 4 + i * row;
                if base + row > buf.len() {
                    break;
                }
                let raw = u32::from_ne_bytes(buf[base + port_off..base + port_off + 4].try_into().unwrap());
                let port = u16::from_be(raw as u16);
                let pid = u32::from_ne_bytes(buf[base + pid_off..base + pid_off + 4].try_into().unwrap());
                if port != 0 {
                    out.insert(port, pid);
                }
            }
        }
        out
    }

    pub fn exe_path(pid: u32) -> Option<PathBuf> {
        // SAFETY: handle checked and closed; buffer of the size passed.
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                return None;
            }
            let mut buf = vec![0u16; 32768];
            let mut len = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
            CloseHandle(h);
            (ok != 0).then(|| PathBuf::from(String::from_utf16_lossy(&buf[..len as usize])))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn miss_during_scan_is_rescanned() {
        let mut table = Table::default();
        let mut asked_during_scan = None;
        assert_eq!(
            table.owner(1000, Instant::now(), || {
                asked_during_scan = Some(Instant::now());
                HashMap::from([(1000, 10)])
            }),
            Some(10)
        );
        assert_eq!(
            table.owner(2000, asked_during_scan.unwrap(), || HashMap::from([(2000, 20)])),
            Some(20)
        );
    }

    #[test]
    fn miss_shares_scan_started_after_lookup() {
        let mut table = Table::default();
        let asked = Instant::now() - Duration::from_millis(1);
        table.owner(1000, Instant::now(), || HashMap::from([(1000, 10)]));
        assert_eq!(table.owner(2000, asked, || panic!("scan already covered this lookup")), None);
    }

    #[test]
    fn matching() {
        let r = AppRules { mode: AppMode::Bypass, apps: vec!["Steam.exe".into(), "Telegram".into(), "/usr/bin/curl".into()] };
        assert!(r.matches(Path::new(r"C:\Program Files (x86)\Steam\steam.exe")) || cfg!(not(windows)));
        assert!(r.matches(Path::new("/opt/steam/steam")));
        assert!(r.matches(Path::new("/Applications/Telegram.app/Contents/MacOS/Telegram")));
        assert!(r.matches(Path::new("/Applications/Telegram.app/Contents/Frameworks/Helper")));
        assert!(r.matches(Path::new("/usr/bin/curl")));
        assert!(!r.matches(Path::new("/usr/local/bin/curl")));
        assert!(!r.matches(Path::new("/usr/bin/wget")));

        assert!(r.is_direct(Some(Path::new("/opt/steam/steam"))));
        assert!(!r.is_direct(None), "unknown owner stays on the proxy");
        let only = AppRules { mode: AppMode::Only, ..r };
        assert!(!only.is_direct(Some(Path::new("/opt/steam/steam"))));
        assert!(only.is_direct(Some(Path::new("/usr/bin/wget"))));
        assert!(!only.is_direct(None));
    }

    /// Our own sockets must be found with our own executable.
    #[test]
    fn finds_own_sockets() {
        let finder = Finder::default();
        let me = std::env::current_exe().unwrap().canonicalize().unwrap();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let exe = finder.lookup(true, client.local_addr().unwrap()).expect("tcp owner");
        assert_eq!(exe.canonicalize().unwrap(), me);

        let udp = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let exe = finder.lookup(false, udp.local_addr().unwrap()).expect("udp owner");
        assert_eq!(exe.canonicalize().unwrap(), me);
    }
}
