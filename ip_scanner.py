import argparse
import ipaddress
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed


# ──────────────────────────────────────────────
#  Well-known service names (Extra Credit)
# ──────────────────────────────────────────────
SERVICE_NAMES = {
    20:   "FTP-Data",
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    67:   "DHCP",
    68:   "DHCP",
    69:   "TFTP",
    80:   "HTTP",
    110:  "POP3",
    119:  "NNTP",
    123:  "NTP",
    135:  "RPC",
    137:  "NetBIOS",
    138:  "NetBIOS",
    139:  "NetBIOS",
    143:  "IMAP",
    161:  "SNMP",
    194:  "IRC",
    389:  "LDAP",
    443:  "HTTPS",
    445:  "SMB",
    465:  "SMTPS",
    514:  "Syslog",
    515:  "LPD",
    587:  "SMTP",
    631:  "IPP",
    636:  "LDAPS",
    993:  "IMAPS",
    995:  "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9200: "Elasticsearch",
    27017:"MongoDB",
}


def get_service_name(port: int) -> str:
    """Return the service name for a port, falling back to socket's database."""
    if port in SERVICE_NAMES:
        return SERVICE_NAMES[port]
    try:
        return socket.getservbyport(port).upper()
    except OSError:
        return "Unknown"


# ──────────────────────────────────────────────
#  Port argument parser
# ──────────────────────────────────────────────
def parse_ports(port_arg: str) -> list[int]:
    """
    Parse the -p argument into a sorted list of unique port numbers.

    Accepts:
        "80"          → [80]
        "1-100"       → [1, 2, …, 100]
        "80,443,3306" → [80, 443, 3306]
        Combinations: "22,80,100-200,443"
    """
    ports = set()
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                start, end = int(start.strip()), int(end.strip())
                if not (1 <= start <= 65535 and 1 <= end <= 65535):
                    raise ValueError
                if start > end:
                    start, end = end, start
                ports.update(range(start, end + 1))
            except ValueError:
                print(f"[!] Invalid port range: '{part}' — skipping.", file=sys.stderr)
        else:
            try:
                p = int(part)
                if not (1 <= p <= 65535):
                    raise ValueError
                ports.add(p)
            except ValueError:
                print(f"[!] Invalid port: '{part}' — skipping.", file=sys.stderr)

    if not ports:
        print("[!] No valid ports parsed. Exiting.", file=sys.stderr)
        sys.exit(1)

    return sorted(ports)


# ──────────────────────────────────────────────
#  Host discovery (ping sweep)
# ──────────────────────────────────────────────
def ping_host(ip: str) -> tuple[str, bool]:
    """Ping a single host. Returns (ip, is_up)."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", str(ip)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
        )
        return (str(ip), result.returncode == 0)
    except subprocess.TimeoutExpired:
        return (str(ip), False)
    except Exception:
        return (str(ip), False)


def discover_hosts(network: ipaddress.IPv4Network) -> list[tuple[str, bool]]:
    """
    Ping-sweep every host address in the network concurrently.
    Returns list of (ip, is_up) sorted by IP address.
    """
    hosts = list(network.hosts())
    if not hosts:
        print("[!] Network has no host addresses.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Scanning {len(hosts)} host(s) in {network} …\n")
    results = {}

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(ping_host, str(ip)): str(ip) for ip in hosts}
        for future in as_completed(futures):
            ip, is_up = future.result()
            results[ip] = is_up

    # Sort by IP address numerically
    return sorted(results.items(), key=lambda x: ipaddress.IPv4Address(x[0]))


# ──────────────────────────────────────────────
#  Port scanning
# ──────────────────────────────────────────────
def scan_port(ip: str, port: int, timeout: float = 1.0) -> tuple[int, bool]:
    """Attempt a TCP connection to ip:port. Returns (port, is_open)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            return (port, result == 0)
    except (socket.timeout, ConnectionRefusedError, OSError):
        return (port, False)


def scan_ports(ip: str, ports: list[int]) -> list[int]:
    """
    Scan all requested ports on a host concurrently.
    Returns a sorted list of open port numbers.
    """
    open_ports = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, ip, p): p for p in ports}
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)
    return sorted(open_ports)


# ──────────────────────────────────────────────
#  Output formatting
# ──────────────────────────────────────────────
def print_results(host_results: list[tuple[str, bool, list[int]]]) -> None:
    """Pretty-print the scan results."""
    print("=" * 45)
    print("  SCAN RESULTS")
    print("=" * 45)

    up_count = sum(1 for _, up, _ in host_results if up)
    print(f"  Hosts scanned : {len(host_results)}")
    print(f"  Hosts UP      : {up_count}")
    print(f"  Hosts DOWN    : {len(host_results) - up_count}")
    print("=" * 45 + "\n")

    for ip, is_up, open_ports in host_results:
        status = "UP" if is_up else "DOWN"
        print(f"{ip:<18} ({status})")
        for port in open_ports:
            service = get_service_name(port)
            print(f"  - Port {port:<6} (OPEN - {service})")
        if is_up and not open_ports and open_ports is not None:
            print("  (no open ports found in scanned range)")


# ──────────────────────────────────────────────
#  Main
# ──────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="ip_scanner.py",
        description="Porthole — IP & Port Scanner for Cybersecurity class",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./ip_scanner.py 192.168.1.0/24
  ./ip_scanner.py -p 80 192.168.1.0/24
  ./ip_scanner.py -p 1-1024 10.0.0.0/28
  ./ip_scanner.py -p 22,80,443,3306 192.168.0.0/24
        """,
    )
    parser.add_argument(
        "cidr",
        help="Target network in CIDR notation (e.g. 192.168.1.0/24)",
    )
    parser.add_argument(
        "-p", "--ports",
        metavar="PORTS",
        help="Ports to scan: single (80), range (1-1024), or list (80,443,3306)",
        default=None,
    )

    args = parser.parse_args()

    # Validate CIDR
    try:
        network = ipaddress.IPv4Network(args.cidr, strict=False)
    except ValueError as e:
        print(f"[!] Invalid CIDR address: {e}", file=sys.stderr)
        sys.exit(1)

    # Parse ports if supplied
    ports_to_scan = parse_ports(args.ports) if args.ports else None

    if ports_to_scan:
        print(f"[*] Port scan requested for {len(ports_to_scan)} port(s).")

    # Step 1 — Host discovery
    host_statuses = discover_hosts(network)

    # Step 2 — Port scanning (only on UP hosts)
    host_results = []
    for ip, is_up in host_statuses:
        open_ports = []
        if is_up and ports_to_scan:
            print(f"[*] Scanning ports on {ip} …")
            open_ports = scan_ports(ip, ports_to_scan)
        host_results.append((ip, is_up, open_ports if ports_to_scan else None))

    # Step 3 — Print results
    print()
    # Rebuild host_results so DOWN hosts have empty list (not None) for clean output
    final_results = [
        (ip, up, ports if ports is not None else [])
        for ip, up, ports in host_results
    ]
    # Only show open ports section when -p was used
    print_results(
        [(ip, up, ports if args.ports else []) for ip, up, ports in final_results]
    )


if __name__ == "__main__":
    main()
