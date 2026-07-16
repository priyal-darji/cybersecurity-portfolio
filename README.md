# 🔍 Log Analyzer

A Python tool that parses security/auth-style logs, detects suspicious
activity (repeated failed logins, brute-force patterns, invalid users,
and — most critically — brute force attempts that are followed by a
successful login), and generates a readable report in the terminal or
as HTML.

## Why this project

Reading raw logs by hand doesn't scale. This tool automates the first
pass a SOC analyst or sysadmin would do: "what's suspicious in here,
and what do I need to look at first?"

## Features

- Parses standard `auth.log`-style lines (works with real syslog output)
- Flags IPs with repeated failed login attempts (configurable threshold)
- **Highlights the highest-risk case**: an IP that brute-forced logins
  and then succeeded — a strong signal of a compromised account
- Generates a clean HTML report for sharing, or plain text for the terminal

## Usage

```bash
# Basic terminal report
python log_analyzer.py sample_data/auth.log

# Change the brute-force threshold (default: 4 failed attempts)
python log_analyzer.py sample_data/auth.log --threshold 5

# Also generate an HTML report
python log_analyzer.py sample_data/auth.log --html report.html
```

## Example output

```
🚨 HIGH PRIORITY: brute-force IP that later succeeded
  🚨 185.220.101.5: 5 fails THEN a successful login — investigate immediately
```

## Skills demonstrated

- Python (argparse, regex, data structures)
- Regex-based log parsing
- Security log analysis / threat triage logic

## Possible extensions

- Support JSON/CEF/Windows Event Log formats
- Add geo-IP lookups for suspicious IPs
- Send alerts to Slack/email when brute force is detected
- Persist findings to a database for historical trend analysis
