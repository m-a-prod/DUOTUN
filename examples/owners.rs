//! `cargo run --example owners -- <app name>...`: lists TCP/UDP sockets whose
//! owner matches the given apps (per-app routing diagnostics).
use std::path::Path;

use duotun::process::{AppMode, AppRules};

fn main() {
    let apps: Vec<String> = std::env::args().skip(1).collect();
    let rules = AppRules { mode: AppMode::Bypass, apps };
    for tcp in [true, false] {
        let table = duotun::process::scan_table(tcp);
        let mut hits = 0;
        for (port, pid) in &table {
            let exe = duotun::process::exe_path(*pid);
            if let Some(e) = &exe
                && rules.matches(Path::new(e))
            {
                hits += 1;
                if hits <= 5 {
                    println!("{} port {port} pid {pid} {}", if tcp { "tcp" } else { "udp" }, e.display());
                }
            }
        }
        println!("{}: {} sockets, {hits} match", if tcp { "tcp" } else { "udp" }, table.len());
    }
}
