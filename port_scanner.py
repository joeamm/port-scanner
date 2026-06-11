#!/usr/bin/env python3
"""
Usage:
    python port_scanner.py <host> [start_port] [end_port]

Examples:
    python port_scanner.py example.com
    python port_scanner.py 192.168.1.1 1 1024
    python port_scanner.py scanme.nmap.org 20 100
"""

import socket
import sys
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


DEFAULT_START_PORT = 1
DEFAULT_END_PORT   = 1024
TIMEOUT_SECONDS    = 0.5   # How long to wait per port before giving up
MAX_THREADS        = 100   # How many ports to scan in parallel

COMMON_SERVICES = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP (Remote Desktop)",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP Alternate",
    8443: "HTTPS Alternate",
    27017:"MongoDB",
}


# Ports that are commonly exploited or should
# not be publicly exposed in most cases
RISKY_PORTS = {
    21:   "FTP transmits data in plaintext — credentials can be intercepted.",
    23:   "Telnet is unencrypted — replace with SSH immediately.",
    25:   "SMTP open to internet may allow spam relay.",
    445:  "SMB is frequently exploited (e.g. WannaCry ransomware).",
    3306: "MySQL should not be exposed publicly — restrict to localhost.",
    3389: "RDP is a common ransomware entry point — use VPN instead.",
    5432: "PostgreSQL should not be exposed publicly.",
    6379: "Redis has no auth by default — dangerous if public.",
    27017:"MongoDB has had many public exposure incidents.",
}


class Color:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def red(text):    return f"{Color.RED}{text}{Color.RESET}"
def green(text):  return f"{Color.GREEN}{text}{Color.RESET}"
def yellow(text): return f"{Color.YELLOW}{text}{Color.RESET}"
def cyan(text):   return f"{Color.CYAN}{text}{Color.RESET}"
def bold(text):   return f"{Color.BOLD}{text}{Color.RESET}"

def resolve_host(host):

    try:
        ip = socket.gethostbyname(host)
        return ip
    except socket.gaierror:
        print(red(f"\n[!] Could not resolve host: {host}"))
        print("    Check the address and try again.\n")
        sys.exit(1)

def scan_port(ip, port):

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT_SECONDS)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return port
        return None
    except Exception:
        return None

def scan_all_ports(ip, start_port, end_port):

    open_ports = []
    total = end_port - start_port + 1

    print(f"\n  Scanning {total} ports", end="", flush=True)

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        # Submit all port scans at once
        futures = {
            executor.submit(scan_port, ip, port): port
            for port in range(start_port, end_port + 1)
        }
        # Collect results as they finish
        completed = 0
        for future in as_completed(futures):
            completed += 1
            if completed % 100 == 0:
                print(".", end="", flush=True)  # Progress dots
            result = future.result()
            if result is not None:
                open_ports.append(result)

    print()  # Newline after progress dots
    return sorted(open_ports)


# REPORT GENERATION
def print_report(host, ip, start_port, end_port, open_ports, scan_duration):
    """
    Print a clean, color-coded report of scan results.
    This is what you'd show a client — clear, actionable, professional.
    """
    divider = "─" * 60

    print(f"\n{bold(divider)}")
    print(bold("  PORT SCAN REPORT"))
    print(bold(divider))
    print(f"  Target   : {cyan(host)} ({ip})")
    print(f"  Port range: {start_port} – {end_port}")
    print(f"  Scanned  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Duration : {scan_duration:.2f} seconds")
    print(bold(divider))

    if not open_ports:
        print(f"\n  {green('No open ports found.')} The target appears well-protected.\n")
        return

    print(f"\n  {bold('OPEN PORTS')}  ({len(open_ports)} found)\n")

    risky_found = []

    for port in open_ports:
        service = COMMON_SERVICES.get(port, "Unknown service")
        line = f"  {green('OPEN')}  Port {bold(str(port)):<8} {service}"

        if port in RISKY_PORTS:
            line += f"  {yellow('⚠ RISKY')}"
            risky_found.append(port)

        print(line)

    # Risk summary section
    if risky_found:
        print(f"\n{bold(divider)}")
        print(f"  {bold(red('SECURITY WARNINGS'))}\n")
        for port in risky_found:
            service = COMMON_SERVICES.get(port, "Unknown")
            advice  = RISKY_PORTS[port]
            print(f"  {red('!')} Port {port} ({service})")
            print(f"    {advice}\n")

    print(bold(divider))
    print(f"\n  Scan complete. {len(open_ports)} open port(s) found, "
          f"{len(risky_found)} warning(s).\n")

def main():
    # Parse command-line arguments
    if len(sys.argv) < 2:
        print(f"\n  Usage: python port_scanner.py <host> [start_port] [end_port]")
        print(f"  Example: python port_scanner.py scanme.nmap.org\n")
        sys.exit(1)

    host       = sys.argv[1]
    start_port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_START_PORT
    end_port   = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_END_PORT

    # Validate port range
    if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
        print(red("\n[!] Ports must be between 1 and 65535.\n"))
        sys.exit(1)
    if start_port > end_port:
        print(red("\n[!] Start port must be less than end port.\n"))
        sys.exit(1)

    # Resolve hostname to IP
    print(f"\n  Resolving {cyan(host)}...")
    ip = resolve_host(host)
    print(f"  Resolved to {cyan(ip)}")

    # Run the scan and time it
    start_time = datetime.datetime.now()
    open_ports = scan_all_ports(ip, start_port, end_port)
    duration   = (datetime.datetime.now() - start_time).total_seconds()

    # Print the report
    print_report(host, ip, start_port, end_port, open_ports, duration)

if __name__ == "__main__":
    main()
