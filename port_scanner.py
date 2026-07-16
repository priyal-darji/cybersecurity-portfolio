#!/usr/bin/env python3
"""
Port Scanner
------------
A multi-threaded TCP port scanner for educational / authorized network
reconnaissance. Identifies open ports and maps them to their commonly
associated services.

⚠️  Only scan hosts you own or have explicit written permission to test.
    Unauthorized scanning may be illegal in your jurisdiction.

Usage:
    python port_scanner.py 127.0.0.1
    python port_scanner.py scanme.example.com --ports 1-1024
    python port_scanner.py 192.168.1.1 --ports 22,80,443,3306 --threads 100
"""

import argparse
import socket
import sys
import threading
import queue
import time

COMMON_SERVICES = {
    20: "FTP (data)", 21: "FTP (control)", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 123: "NTP", 135: "MSRPC",
    137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP (submission)", 631: "IPP", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle DB", 2049: "NFS",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt", 9200: "Elasticsearch",
    27017: "MongoDB",
}


def parse_ports(port_spec):
    """Accepts '80', '1-1024', or '22,80,443' and returns a sorted list of ints."""
    ports = set()
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


def scan_port(host, port, timeout, results, lock):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                service = COMMON_SERVICES.get(port, "unknown")
                with lock:
                    results.append((port, service))
    except socket.gaierror:
        raise
    except OSError:
        pass


def worker(q, host, timeout, results, lock):
    while True:
        try:
            port = q.get_nowait()
        except queue.Empty:
            return
        scan_port(host, port, timeout, results, lock)
        q.task_done()


def run_scan(host, ports, num_threads=50, timeout=0.7):
    try:
        resolved_ip = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"Error: could not resolve host '{host}'", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning {host} ({resolved_ip}) — {len(ports)} ports, {num_threads} threads")
    start = time.time()

    q = queue.Queue()
    for p in ports:
        q.put(p)

    results = []
    lock = threading.Lock()
    threads = []
    for _ in range(min(num_threads, len(ports) or 1)):
        t = threading.Thread(target=worker, args=(q, host, timeout, results, lock))
        t.daemon = True
        t.start()
        threads.append(t)

    q.join()
    elapsed = time.time() - start

    results.sort()
    print(f"\nScan complete in {elapsed:.2f}s. Open ports: {len(results)}\n")
    if results:
        print(f"{'PORT':<8}{'SERVICE'}")
        print("-" * 30)
        for port, service in results:
            print(f"{port:<8}{service}")
    else:
        print("No open ports found in the given range.")

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Scan a host for open TCP ports (authorized use only)."
    )
    parser.add_argument("host", help="Target hostname or IP address")
    parser.add_argument(
        "--ports", default="1-1024",
        help="Ports to scan: '80', '1-1024', or '22,80,443' (default: 1-1024)"
    )
    parser.add_argument("--threads", type=int, default=50, help="Number of worker threads (default: 50)")
    parser.add_argument("--timeout", type=float, default=0.7, help="Socket timeout in seconds (default: 0.7)")
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    if not ports:
        print("Error: no valid ports specified.", file=sys.stderr)
        sys.exit(1)

    run_scan(args.host, ports, num_threads=args.threads, timeout=args.timeout)


if __name__ == "__main__":
    main()
