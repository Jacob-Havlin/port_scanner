# Porthole — IP & Port Scanner

**Cybersecurity Class | Porthole Assignment**

An extension of the *IP Freely* CIDR host-discovery script, upgraded with Nmap-style `-p` port scanning.

---

## Features

| Feature | Description |
|---|---|
| **Host Discovery** | Ping-sweeps every host in a CIDR range concurrently |
| **Port Scanning** | TCP connect scan on any combination of ports |
| **Flexible `-p` syntax** | Single ports, ranges, and comma-separated lists |
| **Service Names** | Displays the standard service name next to each open port *(Extra Credit)* |
| **Error Handling** | Timeouts, invalid IPs, and unreachable hosts are all handled gracefully |
| **Concurrent Scanning** | Uses `ThreadPoolExecutor` for fast parallel scanning |

---

## Requirements

- Python 3.10+
- Standard library only — **no third-party packages needed**
  - `socket` — TCP port scanning
  - `subprocess` — ping-based host discovery
  - `ipaddress` — CIDR parsing and host enumeration
  - `concurrent.futures` — parallel execution
  - `argparse` — CLI argument handling

---

## Installation

```bash
# Clone the repository
git clone https://github.com/WTCSC/ip-freely-Jacob-Havlin.git
cd ip-freely-Jacob-Havlin

# Make the script executable
chmod +x ip_scanner.py
```

---

## Usage

```
./ip_scanner.py [-p PORTS] <cidr>
```

### Arguments

| Argument | Description |
|---|---|
| `cidr` | Target network in CIDR notation (e.g. `192.168.1.0/24`) |
| `-p PORTS` | *Optional.* Ports to scan (see formats below) |

### Port Formats

```bash
-p 80           # Single port
-p 1-1024       # Range (inclusive)
-p 80,443,3306  # Comma-separated list
-p 22,80,100-200,443  # Mix of all formats
```

---

## Examples

```bash
# Host discovery only (no port scan)
./ip_scanner.py 192.168.1.0/24

# Scan port 80 on all discovered hosts
./ip_scanner.py -p 80 192.168.1.0/24

# Scan a port range
./ip_scanner.py -p 1-1024 10.0.0.0/28

# Scan specific ports
./ip_scanner.py -p 22,80,443,3306 192.168.0.0/24
```

---

## Sample Output

```
[*] Scanning 254 host(s) in 192.168.1.0/24 …

[*] Scanning ports on 192.168.1.10 …
[*] Scanning ports on 192.168.1.13 …

=============================================
  SCAN RESULTS
=============================================
  Hosts scanned : 254
  Hosts UP      : 4
  Hosts DOWN    : 250
=============================================

192.168.1.1        (UP)
  - Port 80     (OPEN - HTTP)
  - Port 443    (OPEN - HTTPS)
192.168.1.10       (UP)
  - Port 22     (OPEN - SSH)
  - Port 80     (OPEN - HTTP)
192.168.1.11       (DOWN)
192.168.1.13       (UP)
  - Port 80     (OPEN - HTTP)
  - Port 3306   (OPEN - MySQL)
```

---

## How It Works

### 1. Host Discovery
The script iterates over every host address in the provided CIDR block and sends a single `ping` (`ICMP echo`) to each one using `subprocess`. All pings run concurrently (up to 50 at a time) via a `ThreadPoolExecutor`.

### 2. Port Scanning
Only hosts confirmed as **UP** are port-scanned. For each host, the script attempts a **TCP connect** (`connect_ex`) on every requested port using Python's `socket` module. A `1-second timeout` is applied to each connection attempt. Up to 100 ports are scanned concurrently per host.

### 3. Service Detection *(Extra Credit)*
Port numbers are looked up in a built-in dictionary of ~40 well-known services. If a port isn't in the dictionary, Python's `socket.getservbyport()` is queried as a fallback.

---

## Error Handling

- Invalid CIDR input → clear error message and exit
- Invalid port numbers or ranges → skipped with a warning, scanning continues
- Unreachable hosts → marked as DOWN, no port scan attempted
- Connection timeouts → port treated as CLOSED/FILTERED
- Socket errors → caught and handled per-port

---

## Limitations

- Uses **TCP connect scan** only (no SYN/UDP scanning)
- Host discovery relies on ICMP ping — hosts with firewalls blocking ping may appear as DOWN
- Requires appropriate **network permissions** to send ICMP packets (may need `sudo` on some systems)

---

## License

MIT — for educational use.
