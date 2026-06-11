# 🔍 Python Port Scanner

A fast, beginner-friendly network port scanner that identifies open ports, maps them to known services, and flags potentially dangerous exposures — with a clean color-coded terminal report.

Built as part of a cybersecurity freelance portfolio.

---

## What It Does

- Scans any IP address or domain for open ports (default: ports 1–1024)
- Identifies the service running on each open port (HTTP, SSH, FTP, etc.)
- Flags **risky ports** with plain-English explanations of why they're dangerous
- Uses multithreading to scan 1,000+ ports in seconds
- Outputs a clean, color-coded terminal report

---

## Example Output

```
  Resolving scanme.nmap.org...
  Resolved to 45.33.32.156
  Scanning 1024 ports ..........

  ──────────────────────────────────────────────────────────
  PORT SCAN REPORT
  ──────────────────────────────────────────────────────────
  Target    : scanme.nmap.org (45.33.32.156)
  Port range: 1 – 1024
  Scanned   : 2026-06-10 14:32:01
  Duration  : 4.81 seconds
  ──────────────────────────────────────────────────────────

  OPEN PORTS  (3 found)

  OPEN  Port 22      SSH
  OPEN  Port 80      HTTP
  OPEN  Port 21      FTP   ⚠ RISKY

  ──────────────────────────────────────────────────────────
  SECURITY WARNINGS

  ! Port 21 (FTP)
    FTP transmits data in plaintext — credentials can be intercepted.

  ──────────────────────────────────────────────────────────
  Scan complete. 3 open port(s) found, 1 warning(s).
```

---

## Quick Start

**No dependencies needed** — uses Python's built-in `socket` library only.

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/port-scanner.git
cd port-scanner

# Run on a domain (ports 1–1024 by default)
python port_scanner.py scanme.nmap.org

# Scan a custom port range
python port_scanner.py scanme.nmap.org 1 500

# Scan a specific IP
python port_scanner.py 192.168.1.1
```

> ⚠️ **Legal notice:** Only scan hosts you own or have explicit written permission to test. Unauthorized port scanning may be illegal in your jurisdiction.

---

## How It Works

| Step | What Happens |
|------|-------------|
| 1 | Hostname is resolved to an IP address via `socket.gethostbyname()` |
| 2 | A TCP connection attempt is made on each port using `socket.connect_ex()` |
| 3 | `ThreadPoolExecutor` runs up to 100 scans in parallel for speed |
| 4 | Open ports are matched against a known services map |
| 5 | Risky ports are flagged with security advice |
| 6 | Results are printed in a color-coded report |

---

## Risky Ports Detected

| Port | Service | Risk |
|------|---------|------|
| 21 | FTP | Plaintext credentials |
| 23 | Telnet | Fully unencrypted — replace with SSH |
| 445 | SMB | Exploited by WannaCry ransomware |
| 3389 | RDP | Common ransomware entry point |
| 3306 | MySQL | Should never be publicly exposed |
| 6379 | Redis | No auth by default |
| 27017 | MongoDB | History of public exposure incidents |

---

## Requirements

- Python 3.7+
- No external libraries needed

---

## About

Built by joe ammoun — Python developer with a Google Cybersecurity Professional Certificate.  
Available for freelance security audits, scripting, and automation projects.

💼 [Upwork](https://www.upwork.com/freelancers/~01620d7d3c7e1378b8?mp_source=share)  
🔗 [LinkedIn](https://www.linkedin.com/in/joe-ammoun-019850344)
