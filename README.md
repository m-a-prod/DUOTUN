# duotun

Routes all traffic of the machine through a SOCKS5 proxy (xray) via a TUN device.
Rust, no userspace TCP stack: TCP is terminated by the OS kernel ("system" stack,
same idea as sing-box `stack: system`).

```
app ──► TUN ──► duotun ──NAT──► kernel TCP ──► listener ──► SOCKS5 CONNECT ──► xray
                  │
                  ├── UDP ──► SOCKS5 UDP ASSOCIATE ──► xray
                  └── DNS (any :53, UDP+TCP) ──► upstream (1.1.1.1) through xray
```

## How it works

- **TCP**: a packet `app:p -> dst:q` read from the TUN is rewritten to
  `198.19.233.2:nat -> 198.19.233.1:listen` and written back. The kernel completes the
  handshake with our listener; on accept we look up `nat` to get `dst:q` and
  open a SOCKS5 CONNECT to it. Replies are rewritten back. Checksums are
  patched incrementally (RFC 1624).
- **UDP**: one SOCKS5 UDP association per app socket (full-cone).
- **DNS**: every query to port 53, whatever the destination, goes to `--dns`
  through the proxy. The system resolver is pointed at `198.19.233.2` (inside the
  TUN), so LAN DNS servers are not used.
- **Routes**: `0.0.0.0/1` + `128.0.0.0/1` (and `::/1` + `8000::/1`) via the TUN,
  host routes for `--bypass` addresses (the proxy servers) via the physical
  gateway. The default route is not touched.
- **Crash safety**: every system change is written to an undo log
  (`/var/run/duotun.state.json`) *before* it is applied. The next start or
  `duotun cleanup` reverts it.

## Status

| | macOS | Windows | Linux |
|---|---|---|---|
| TUN + TCP/UDP/DNS | tested | tested (Wintun, x64 + x86) | tested |
| Auto route | `route` | `route` / `netsh` | `ip route`, loose `rp_filter` on the uplink |
| DNS pinning | `networksetup`, all services | resolver on the TUN adapter | `resolvectl` (if it serves resolv.conf) + DNAT of every port-53 query into the TUN |
| Strict DNS leak block | pf anchor | Windows Firewall rule | nftables, else iptables |
| Host firewall | — | — | TUN allowed in INPUT (iptables/ufw, firewalld, nftables) |
| Per-app routing (`--app`) | libproc | IP Helper tables | `/proc` (exe and `argv[0]`) |
| Network change handling | TODO | TODO | bypass routes follow the uplink |

Used as a library by [DUORAY](../Duoray) (`duotun::run_notify`), or standalone:

## Try it (macOS)

Turn off any other VPN first (Happ, Throne TUN): duotun refuses to start if the
default route already points at a `utun`.

```sh
cargo build --release

# 1. xray: SOCKS in, direct out bound to the physical interface (en0).
xray run -c examples/xray-direct.json

# 2. duotun (root: creates utun, changes routes and DNS). Ctrl-C restores everything.
sudo RUST_LOG=duotun=debug ./target/release/duotun run --socks 127.0.0.1:10808

# 3. check
curl -4 https://ifconfig.me ; curl -6 https://ifconfig.me
dig example.com            # server shown must be 198.19.233.2
scutil --dns | head -20
```

With a real server, pass its address so xray's own connection bypasses the TUN:

```sh
sudo ./target/release/duotun run --socks 127.0.0.1:10808 --bypass your.server.com
```

If something goes wrong: `sudo ./target/release/duotun cleanup`.
