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
pub use windows::skip_dad;

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
    WriteFile { path: PathBuf, content: String },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UndoLog {
    #[serde(skip)]
    path: PathBuf,
    steps: Vec<Undo>,
}

impl UndoLog {
    fn create(path: PathBuf) -> Result<Self> {
        let log = Self { path, steps: vec![] };
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
        self.push(Undo::Cmd(argv.iter().map(|s| s.to_string()).collect()))
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
                        Err(RunError::Failed(e)) => debug!("undo step failed (usually harmless): {e}"),
                        Err(RunError::Spawn(e)) => {
                            warn!("undo step could not run: {e}");
                            retry.push(step);
                        }
                    }
                }
                Undo::WriteFile { path, content } => {
                    if let Err(e) = std::fs::write(path, content) {
                        warn!("failed to restore {}: {e}", path.display());
                        retry.push(step);
                    }
                }
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
