#!/usr/bin/env python3
"""
netscan.py - simple LAN scanner (host discovery + port scan + banner grab).

Uses only the Python standard library. No admin/root rights needed
(uses TCP connect scans, not raw packets).

ONLY scan networks you own or have explicit permission to test.

Examples:
    python netscan.py                         # auto-detect your /24 LAN, scan common ports
    python netscan.py -t 192.168.1.0/24       # scan a specific subnet
    python netscan.py -t 192.168.1.10 -p 1-1024
    python netscan.py -t 192.168.1.0/24 -p 22,80,443,3389 -o results.json
"""

import argparse
import ipaddress
import json
import platform
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8000: "HTTP-alt",
    8080: "HTTP-proxy", 8443: "HTTPS-alt",
}


def get_local_network() -> str:
    """Find this PC's LAN IP (no packets are actually sent) and assume a /24."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except OSError:
        ip = "127.0.0.1"
    finally:
        s.close()
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


def parse_ports(spec: str) -> list[int]:
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


def is_alive(ip: str, timeout: float) -> bool:
    """Ping the host; fall back to probing a few common TCP ports."""
    flag = "-n" if platform.system() == "Windows" else "-c"
    wait = ["-w", str(int(timeout * 1000))] if platform.system() == "Windows" \
        else ["-W", str(max(1, int(timeout)))]
    try:
        r = subprocess.run(["ping", flag, "1", *wait, ip],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if r.returncode == 0:
            return True
    except FileNotFoundError:
        pass
    for port in (445, 135, 80, 443, 22):  # firewalls often block ping
        with socket.socket() as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                return True
    return False


def scan_port(ip: str, port: int, timeout: float):
    """Return (port, banner) if open, else None."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = ""
            try:
                if port in (80, 8000, 8080):
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(128).decode(errors="ignore").strip().splitlines()[0]
            except (OSError, IndexError):
                pass
            return port, banner[:80]
    except OSError:
        return None


def get_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


def get_mac(ip: str) -> str:
    """Read MAC from the OS ARP cache (populated after we contacted the host)."""
    try:
        out = subprocess.run(["arp", "-a", ip], capture_output=True, text=True).stdout
        m = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", out)
        return m.group(0).lower().replace("-", ":") if m else ""
    except FileNotFoundError:
        return ""


def scan_host(ip: str, ports: list[int], timeout: float, workers: int) -> dict:
    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for res in ex.map(lambda p: scan_port(ip, p, timeout), ports):
            if res:
                port, banner = res
                open_ports.append({
                    "port": port,
                    "service": COMMON_PORTS.get(port, "unknown"),
                    "banner": banner,
                })
    return {"ip": ip, "hostname": get_hostname(ip), "mac": get_mac(ip),
            "open_ports": open_ports}


def main():
    ap = argparse.ArgumentParser(description="Simple LAN scanner")
    ap.add_argument("-t", "--target", help="IP or CIDR (default: your local /24)")
    ap.add_argument("-p", "--ports", default=",".join(map(str, COMMON_PORTS)),
                    help="e.g. 22,80,443 or 1-1024 (default: common ports)")
    ap.add_argument("--timeout", type=float, default=1.0)
    ap.add_argument("--threads", type=int, default=100)
    ap.add_argument("-o", "--output", help="save results as JSON")
    args = ap.parse_args()

    target = args.target or get_local_network()
    net = ipaddress.ip_network(target, strict=False)
    hosts = [str(h) for h in (net.hosts() if net.num_addresses > 1 else [net.network_address])]
    ports = parse_ports(args.ports)

    print(f"[*] Target: {target} ({len(hosts)} addresses), {len(ports)} ports")
    start = time.time()

    # 1) Host discovery
    alive = []
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(is_alive, h, args.timeout): h for h in hosts}
        for f in as_completed(futures):
            if f.result():
                alive.append(futures[f])
    alive.sort(key=ipaddress.ip_address)
    print(f"[+] {len(alive)} host(s) up\n")

    # 2) Port scan each live host
    results = []
    for ip in alive:
        r = scan_host(ip, ports, args.timeout, args.threads)
        results.append(r)
        name = f" ({r['hostname']})" if r["hostname"] else ""
        mac = f"  MAC {r['mac']}" if r["mac"] else ""
        print(f"{ip}{name}{mac}")
        if r["open_ports"]:
            for p in r["open_ports"]:
                b = f"  | {p['banner']}" if p["banner"] else ""
                print(f"    {p['port']:>5}/tcp  {p['service']:<12}{b}")
        else:
            print("    no open ports found")
        print()

    print(f"[*] Done in {time.time() - start:.1f}s")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[*] Saved to {args.output}")


if __name__ == "__main__":
    main()
