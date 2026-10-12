<p align="center">
  <img src="docs/images/banner.png" alt="DUOTUN" width="100%">
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-c97fa3?style=flat-square&labelColor=141118"></a>
  <img alt="Rust" src="https://img.shields.io/badge/Rust-2024-f4c2d7?style=flat-square&labelColor=141118">
  <img alt="Platforms" src="https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Linux-fdebf3?style=flat-square&labelColor=141118">
</p>

**DUOTUN** routes all traffic of a machine through a SOCKS5 proxy (such as
[Xray-core](https://github.com/XTLS/Xray-core)) via a TUN device, with DNS leaks
blocked at the system level. It is the tunnel behind
[DUORAY](https://github.com/m-a-prod/DUORAY) and can be used as a Rust library or
as a standalone command-line tool.

## Features

- **Kernel TCP stack.** No userspace TCP implementation: connections are NATed to a
  local listener and terminated by the operating system (the same approach as
  sing-box `stack: system`).
- **TCP, UDP and DNS.** TCP via SOCKS5 CONNECT, UDP via SOCKS5 UDP ASSOCIATE
  (full-cone), every port-53 query (UDP and TCP) to a chosen upstream through the
  proxy.
- **No DNS leaks.** The system resolver is pinned to the TUN, and port 53 outside
  the tunnel is blocked by the platform firewall.
- **IPv4 and IPv6.** IPv6 is tunnelled too; when it cannot be set up on the TUN,
  internet IPv6 is blocked so it never bypasses the tunnel.
- **Per-application routing.** Selected applications go direct, or only they use the
  proxy.
- **Crash safety.** Every system change is recorded in an undo log before it is
  applied; the next start or `duotun cleanup` reverts anything left behind.
- **Fast bring-up.** The TUN is ready in well under a second on all platforms.

## How it works

```
app ──► TUN ──► duotun ──NAT──► kernel TCP ──► listener ──► SOCKS5 CONNECT ──► proxy
                  │
                  ├── UDP ──► SOCKS5 UDP ASSOCIATE ──► proxy
                  └── DNS (any :53, UDP + TCP) ──► upstream, through the proxy
```

- **TCP:** a packet `app:p → dst:q` read from the TUN is rewritten to
  `peer:nat → tun:listen` and written back. The kernel completes the handshake with
  the listener; on accept, `nat` maps back to `dst:q`, which is opened with SOCKS5
  CONNECT. Replies are rewritten in reverse; checksums are patched incrementally
  (RFC 1624).
- **UDP:** one SOCKS5 UDP association per application socket.
- **DNS:** the system resolver points at the TUN peer address, so LAN DNS servers
  are not used; queries are answered by the upstream through the proxy.
- **Routes:** `0.0.0.0/1` and `128.0.0.0/1` (and `::/1`, `8000::/1`) via the TUN,
  host routes for the proxy servers via the physical gateway. The default route is
  left untouched.

## Platform support

| | Windows | macOS | Linux |
|---|---|---|---|
| TUN driver | Wintun (x64, x86) | `utun` | `tun` |
| Routes | `route`, `netsh` | `route` | `ip route`, loose `rp_filter` on the uplink |
| DNS pinning | resolver on the TUN adapter | `networksetup`, all services | `resolvectl` + DNAT of every port-53 query into the TUN |
| DNS leak blocking | Windows Firewall | pf anchor | nftables, otherwise iptables |
| Host firewall | — | — | TUN allowed in INPUT (iptables/ufw, firewalld, nftables) |
| Per-app routing | IP Helper tables | libproc | `/proc` |
| Uplink changes | reconnect by the client | reconnect by the client | followed automatically |

## Library usage

```toml
[dependencies]
duotun = { git = "https://github.com/m-a-prod/DUOTUN" }
```

```rust
use duotun::{Config, socks5::Socks5};

let cfg = Config {
    socks: Socks5 { server: "127.0.0.1:10808".parse()?, auth: None },
    bypass: vec!["203.0.113.10".parse()?], // the proxy server itself
    ..Default::default()
};
// Runs until the shutdown future resolves; system settings are always restored.
duotun::run(cfg, async { let _ = tokio::signal::ctrl_c().await; }).await?;
```

`run_notify` additionally reports the interface name once the TUN, routes and DNS
are in place. `duotun::sys::recover()` reverts a previous run that ended abnormally.
Creating a TUN and changing routes requires administrator rights; DUORAY runs DUOTUN
inside a privileged helper service for that reason.

## Command-line tool

```sh
cargo build --release
sudo ./target/release/duotun run --socks 127.0.0.1:10808 --bypass proxy.example.com
```

| Option | Default | Description |
|---|---|---|
| `--socks` | `127.0.0.1:10808` | SOCKS5 server to forward traffic to |
| `--socks-user`, `--socks-pass` | — | SOCKS5 credentials |
| `--bypass` | — | proxy server host or IP routed around the TUN; repeatable |
| `--dns` | `1.1.1.1:53` | DNS upstream reached through the proxy |
| `--name`, `--mtu` | OS default, `9000` | TUN interface name and MTU |
| `--app`, `--app-mode`, `--direct-socks` | `bypass` | per-application routing |
| `--no-ipv6`, `--no-dns-hijack`, `--no-strict-dns`, `--no-auto-route` | — | turn individual features off |

`duotun cleanup` reverts routes, DNS and firewall rules left by an interrupted run.
Stopping the process with Ctrl-C restores everything as well.

## License

[MIT](LICENSE) © DUALIZM
