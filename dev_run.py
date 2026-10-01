#!/usr/bin/env python3
"""Dev harness: vless:// link -> xray (SOCKS5 :10808) -> prints the sudo command for duotun.

    python3 dev_run.py 'vless://...'           # run xray, print duotun command, Ctrl-C stops xray
    python3 dev_run.py 'vless://...' --check   # verify the proxy works, then exit

The server hostname is resolved here, before the TUN exists: under the TUN the
system resolver points into the tunnel, and xray resolving its own server
through itself would deadlock. The IP goes into the xray config (TLS SNI keeps
the hostname) and is passed to duotun as --bypass.
"""

import argparse
import json
import os
import shlex
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

ROOT = Path(__file__).resolve().parent
RUN_DIR = ROOT / "run"
DUOTUN = ROOT / "target" / "release" / "duotun"
# Not 10808: Happ/v2rayN-style clients already listen there.
SOCKS_PORT = 17080


def parse_vless(link: str) -> dict:
    u = urlsplit(link.strip())
    if u.scheme != "vless":
        sys.exit(f"not a vless link: {u.scheme}://")
    q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
    return {
        "uuid": unquote(u.username or ""),
        "host": u.hostname,
        "port": u.port or 443,
        "name": unquote(u.fragment),
        "q": q,
    }


def resolve_v4(host: str) -> str:
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    if not infos:
        sys.exit(f"cannot resolve {host}")
    return infos[0][4][0]


def physical_iface() -> str:
    """First default route that is not a tunnel/bridge (another VPN may own the top route)."""
    out = subprocess.run(["netstat", "-rn", "-f", "inet"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        cols = line.split()
        if len(cols) >= 4 and cols[0] == "default":
            iface = cols[3]
            if not iface.startswith(("utun", "bridge", "ipsec", "ppp", "gif", "stf")):
                return iface
    sys.exit("no physical default route found")


def stream_settings(v: dict, iface: str) -> dict:
    q = v["q"]
    net = q.get("type", "tcp")
    sec = q.get("security", "none")
    ss = {"network": net, "security": sec, "sockopt": {"interface": iface}}

    sni = q.get("sni") or q.get("host") or v["host"]
    if sec == "tls":
        tls = {"serverName": sni, "fingerprint": q.get("fp", "chrome")}
        if q.get("alpn"):
            tls["alpn"] = q["alpn"].split(",")
        if q.get("allowInsecure") in ("1", "true"):
            tls["allowInsecure"] = True
        ss["tlsSettings"] = tls
    elif sec == "reality":
        ss["realitySettings"] = {
            "serverName": sni,
            "fingerprint": q.get("fp", "chrome"),
            "publicKey": q.get("pbk", ""),
            "shortId": q.get("sid", ""),
            "spiderX": q.get("spx", ""),
        }

    host = q.get("host", "")
    path = q.get("path", "/")
    if net in ("xhttp", "splithttp"):
        x = {"host": host, "path": path, "mode": q.get("mode", "auto")}
        if q.get("extra"):
            x["extra"] = json.loads(q["extra"])
        ss["network"] = "xhttp"
        ss["xhttpSettings"] = x
    elif net == "ws":
        ss["wsSettings"] = {"host": host, "path": path}
    elif net == "httpupgrade":
        ss["httpupgradeSettings"] = {"host": host, "path": path}
    elif net == "grpc":
        ss["grpcSettings"] = {
            "serviceName": q.get("serviceName", ""),
            "multiMode": q.get("mode") == "multi",
        }
    elif net in ("tcp", "raw") and q.get("headerType") == "http":
        ss["tcpSettings"] = {
            "header": {"type": "http", "request": {"path": [path], "headers": {"Host": [host]}}}
        }
    return ss


def xray_config(v: dict, server_ip: str, iface: str) -> dict:
    user = {"id": v["uuid"], "encryption": v["q"].get("encryption", "none")}
    if v["q"].get("flow"):
        user["flow"] = v["q"]["flow"]
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": SOCKS_PORT,
                "protocol": "socks",
                "settings": {"udp": True, "ip": "127.0.0.1"},
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                    "routeOnly": True,
                },
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {"vnext": [{"address": server_ip, "port": v["port"], "users": [user]}]},
                "streamSettings": stream_settings(v, iface),
            },
            {
                "tag": "direct",
                "protocol": "freedom",
                "streamSettings": {"sockopt": {"interface": iface}},
            },
        ],
        "routing": {
            "rules": [{"ip": ["geoip:private"], "outboundTag": "direct"}],
        },
    }


def wait_port(port: int, proc: subprocess.Popen, timeout: float = 10) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            sys.exit(f"xray exited with code {proc.returncode}")
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    sys.exit(f"xray did not open :{port} in {timeout}s")


def exit_ip() -> str | None:
    r = subprocess.run(
        ["curl", "-s", "-m", "15", "--socks5-hostname", f"127.0.0.1:{SOCKS_PORT}", "https://ifconfig.me"],
        capture_output=True,
        text=True,
    )
    return r.stdout.strip() if r.returncode == 0 else None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("link")
    ap.add_argument("--check", action="store_true", help="verify the proxy works, then exit")
    args = ap.parse_args()

    v = parse_vless(args.link)
    server_ip = resolve_v4(v["host"])
    iface = physical_iface()
    print(f"server  : {v['name'] or v['host']}")
    print(f"address : {v['host']} -> {server_ip}:{v['port']}")
    print(f"uplink  : {iface}")

    RUN_DIR.mkdir(exist_ok=True)
    cfg_path = RUN_DIR / "xray.json"
    cfg_path.write_text(json.dumps(xray_config(v, server_ip, iface), indent=2))
    os.chmod(cfg_path, 0o600)

    test = subprocess.run(["xray", "run", "-test", "-c", str(cfg_path)], capture_output=True, text=True)
    if test.returncode != 0:
        sys.exit(f"xray rejected config:\n{test.stdout}{test.stderr}")

    if not DUOTUN.exists():
        print("building duotun...")
        subprocess.run(["cargo", "build", "--release"], cwd=ROOT, check=True)

    with socket.socket() as s:
        if s.connect_ex(("127.0.0.1", SOCKS_PORT)) == 0:
            sys.exit(f"127.0.0.1:{SOCKS_PORT} is already taken by another process")

    xray = subprocess.Popen(["xray", "run", "-c", str(cfg_path)])
    try:
        wait_port(SOCKS_PORT, xray)
        ip = exit_ip()
        if ip is None:
            sys.exit("proxy check failed: no response through xray (see xray log above)")
        print(f"proxy OK, exit IP: {ip}")
        if args.check:
            return

        cmd = [
            "sudo", "RUST_LOG=duotun=debug", str(DUOTUN), "run",
            "--socks", f"127.0.0.1:{SOCKS_PORT}",
            "--bypass", server_ip,
        ]
        print()
        print("Disable other VPNs (Happ, Throne TUN), then in another terminal run:")
        print()
        print("  " + shlex.join(cmd))
        print()
        print(f"Expect `curl https://ifconfig.me` = {ip}. Ctrl-C duotun first, then this script.")
        print("If anything gets stuck: sudo " + shlex.quote(str(DUOTUN)) + " cleanup")
        xray.wait()
    except KeyboardInterrupt:
        pass
    finally:
        if xray.poll() is None:
            xray.send_signal(signal.SIGTERM)
            try:
                xray.wait(5)
            except subprocess.TimeoutExpired:
                xray.kill()


if __name__ == "__main__":
    main()
