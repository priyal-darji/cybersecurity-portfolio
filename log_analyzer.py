#!/usr/bin/env python3
"""
Log Analyzer
------------
Parses security/auth-style log files, flags suspicious activity
(failed logins, brute-force patterns, unusual access times), and
generates a plain-text or HTML summary report.

Usage:
    python log_analyzer.py sample_data/auth.log
    python log_analyzer.py sample_data/auth.log --html report.html
    python log_analyzer.py sample_data/auth.log --threshold 5
"""

import argparse
import re
import sys
from collections import defaultdict, Counter
from datetime import datetime

# --- Log line patterns -------------------------------------------------
# Supports a generic "auth.log"-style format:
# <Month> <Day> <HH:MM:SS> <host> <process>: <message>
LOG_LINE_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>\S+):\s+(?P<message>.*)$"
)

FAILED_LOGIN_RE = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
)
ACCEPTED_LOGIN_RE = re.compile(
    r"Accepted (password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+)"
)
INVALID_USER_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)")


class LogEntry:
    __slots__ = ("timestamp_str", "host", "process", "message")

    def __init__(self, timestamp_str, host, process, message):
        self.timestamp_str = timestamp_str
        self.host = host
        self.process = process
        self.message = message


def parse_log(path):
    entries = []
    with open(path, "r", errors="ignore") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            m = LOG_LINE_RE.match(line)
            if m:
                ts = f"{m.group('month')} {m.group('day')} {m.group('time')}"
                entries.append(LogEntry(ts, m.group("host"), m.group("process"), m.group("message")))
            else:
                # Fallback: treat whole line as message so nothing is silently dropped
                entries.append(LogEntry("", "", "", line))
    return entries


def analyze(entries, fail_threshold=4):
    failed_by_ip = defaultdict(list)      # ip -> [usernames attempted]
    invalid_users_by_ip = defaultdict(list)
    accepted_logins = []
    process_counts = Counter()

    for e in entries:
        process_counts[e.process] += 1

        m = FAILED_LOGIN_RE.search(e.message)
        if m:
            failed_by_ip[m.group("ip")].append((m.group("user"), e.timestamp_str))
            continue

        m = INVALID_USER_RE.search(e.message)
        if m:
            invalid_users_by_ip[m.group("ip")].append((m.group("user"), e.timestamp_str))
            continue

        m = ACCEPTED_LOGIN_RE.search(e.message)
        if m:
            accepted_logins.append((m.group("user"), m.group("ip"), e.timestamp_str))

    brute_force_suspects = {
        ip: attempts for ip, attempts in failed_by_ip.items()
        if len(attempts) >= fail_threshold
    }

    # IPs that both failed a lot AND eventually succeeded = high priority
    succeeded_ips = {ip for _, ip, _ in accepted_logins}
    compromised_suspects = {
        ip: attempts for ip, attempts in brute_force_suspects.items()
        if ip in succeeded_ips
    }

    return {
        "total_lines": len(entries),
        "process_counts": process_counts,
        "failed_by_ip": failed_by_ip,
        "invalid_users_by_ip": invalid_users_by_ip,
        "accepted_logins": accepted_logins,
        "brute_force_suspects": brute_force_suspects,
        "compromised_suspects": compromised_suspects,
    }


def print_report(results, fail_threshold):
    print("=" * 60)
    print("LOG ANALYSIS REPORT")
    print("=" * 60)
    print(f"Total log lines parsed : {results['total_lines']}")
    print(f"Brute-force threshold  : {fail_threshold} failed attempts\n")

    print("-- Top processes logging --")
    for proc, count in results["process_counts"].most_common(5):
        print(f"  {proc or '(unmatched)'}: {count}")

    print(f"\n-- Failed login attempts by IP ({len(results['failed_by_ip'])} unique IPs) --")
    for ip, attempts in sorted(results["failed_by_ip"].items(), key=lambda x: -len(x[1]))[:10]:
        print(f"  {ip}: {len(attempts)} attempts (users tried: {', '.join(sorted(set(u for u,_ in attempts)))[:80]})")

    print(f"\n-- SUSPECTED BRUTE FORCE (>= {fail_threshold} fails) --")
    if results["brute_force_suspects"]:
        for ip, attempts in results["brute_force_suspects"].items():
            print(f"  ⚠  {ip}: {len(attempts)} failed attempts")
    else:
        print("  None detected.")

    print("\n-- HIGH PRIORITY: brute-force IP that later succeeded --")
    if results["compromised_suspects"]:
        for ip, attempts in results["compromised_suspects"].items():
            print(f"  🚨 {ip}: {len(attempts)} fails THEN a successful login — investigate immediately")
    else:
        print("  None detected.")

    print(f"\n-- Successful logins ({len(results['accepted_logins'])}) --")
    for user, ip, ts in results["accepted_logins"][:10]:
        print(f"  {ts}  user={user}  from={ip}")
    print("=" * 60)


def html_report(results, fail_threshold, out_path):
    def rows(items):
        return "".join(f"<tr><td>{a}</td><td>{b}</td></tr>" for a, b in items)

    brute_rows = "".join(
        f"<tr><td>{ip}</td><td>{len(attempts)}</td></tr>"
        for ip, attempts in results["brute_force_suspects"].items()
    )
    compromised_rows = "".join(
        f"<tr><td>{ip}</td><td>{len(attempts)}</td></tr>"
        for ip, attempts in results["compromised_suspects"].items()
    )
    accepted_rows = "".join(
        f"<tr><td>{ts}</td><td>{user}</td><td>{ip}</td></tr>"
        for user, ip, ts in results["accepted_logins"]
    )

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Log Analysis Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 2rem; background:#0f172a; color:#e2e8f0; }}
h1 {{ color:#38bdf8; }}
h2 {{ color:#facc15; margin-top:2rem; }}
table {{ border-collapse: collapse; width:100%; margin-top:0.5rem; }}
th, td {{ border:1px solid #334155; padding:6px 10px; text-align:left; }}
th {{ background:#1e293b; }}
tr:nth-child(even) {{ background:#1e293b55; }}
.alert {{ color:#f87171; font-weight:bold; }}
</style></head>
<body>
<h1>🔍 Log Analysis Report</h1>
<p>Total lines parsed: {results['total_lines']} | Brute-force threshold: {fail_threshold}</p>

<h2>🚨 High Priority — Brute force then success</h2>
<table><tr><th>IP</th><th>Failed attempts</th></tr>{compromised_rows or '<tr><td colspan=2>None detected</td></tr>'}</table>

<h2>⚠️ Suspected Brute Force IPs</h2>
<table><tr><th>IP</th><th>Failed attempts</th></tr>{brute_rows or '<tr><td colspan=2>None detected</td></tr>'}</table>

<h2>✅ Successful Logins</h2>
<table><tr><th>Time</th><th>User</th><th>IP</th></tr>{accepted_rows or '<tr><td colspan=3>None</td></tr>'}</table>

</body></html>"""

    with open(out_path, "w") as f:
        f.write(html)
    print(f"HTML report written to {out_path}")


def main():
    parser = argparse.ArgumentParser(description="Analyze security logs for suspicious activity.")
    parser.add_argument("logfile", help="Path to the log file to analyze")
    parser.add_argument("--threshold", type=int, default=4, help="Failed attempts to flag as brute force (default: 4)")
    parser.add_argument("--html", metavar="OUTPUT.html", help="Also write an HTML report to this path")
    args = parser.parse_args()

    try:
        entries = parse_log(args.logfile)
    except FileNotFoundError:
        print(f"Error: file not found: {args.logfile}", file=sys.stderr)
        sys.exit(1)

    results = analyze(entries, fail_threshold=args.threshold)
    print_report(results, args.threshold)

    if args.html:
        html_report(results, args.threshold, args.html)


if __name__ == "__main__":
    main()
