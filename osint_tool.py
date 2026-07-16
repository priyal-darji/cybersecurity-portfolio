#!/usr/bin/env python3
"""
OSINT Investigation Tool
-------------------------
Gathers publicly available information from multiple open sources to
support investigations: username presence across common platforms,
domain WHOIS/registration data, and basic email-format validation.

This tool only queries public endpoints (HTTP HEAD/GET requests to
public profile URLs, public WHOIS records). It does not bypass
authentication, scrape private data, or access anything not already
publicly visible.

⚠️  Use responsibly and in line with each platform's Terms of Service
    and applicable law (e.g. only for your own accounts, authorized
    investigations, or accounts that have made data public).

Usage:
    python osint_tool.py username johndoe123
    python osint_tool.py domain example.com
    python osint_tool.py email jdoe@example.com
"""

import argparse
import re
import socket
import sys

try:
    import requests
except ImportError:
    requests = None

# Public profile URL templates. %s is replaced with the username.
PLATFORMS = {
    "GitHub": "https://github.com/%s",
    "Twitter/X": "https://x.com/%s",
    "Instagram": "https://www.instagram.com/%s/",
    "Reddit": "https://www.reddit.com/user/%s",
    "LinkedIn": "https://www.linkedin.com/in/%s",
    "TikTok": "https://www.tiktok.com/@%s",
    "Medium": "https://medium.com/@%s",
    "GitLab": "https://gitlab.com/%s",
}

EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


def check_username(username, timeout=5):
    if requests is None:
        print("The 'requests' library is required for username checks.")
        print("Install it with: pip install requests")
        return []

    results = []
    headers = {"User-Agent": "Mozilla/5.0 (OSINT-Tool educational project)"}
    for platform, url_template in PLATFORMS.items():
        url = url_template % username
        try:
            resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            exists = resp.status_code == 200
            results.append((platform, url, exists, resp.status_code))
        except requests.RequestException as e:
            results.append((platform, url, None, f"error: {e}"))
    return results


def whois_lookup(domain):
    """Lightweight WHOIS lookup using the python-whois package if available,
    falling back to a note if it's not installed."""
    try:
        import whois  # python-whois package
    except ImportError:
        print("For full WHOIS data, install python-whois: pip install python-whois")
        return None

    try:
        data = whois.whois(domain)
        return data
    except Exception as e:
        print(f"WHOIS lookup failed: {e}")
        return None


def resolve_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        return None


def validate_email_format(email):
    return bool(EMAIL_RE.match(email))


def cmd_username(args):
    print(f"Checking username '{args.value}' across {len(PLATFORMS)} platforms...\n")
    results = check_username(args.value)
    found = 0
    for platform, url, exists, status in results:
        if exists:
            found += 1
            print(f"  ✅ {platform:<12} FOUND      {url}")
        elif exists is False:
            print(f"  ❌ {platform:<12} not found  (status {status})")
        else:
            print(f"  ⚠️  {platform:<12} {status}")
    print(f"\nSummary: found on {found}/{len(PLATFORMS)} checked platforms.")


def cmd_domain(args):
    domain = args.value
    print(f"Investigating domain: {domain}\n")

    ip = resolve_domain(domain)
    if ip:
        print(f"  Resolved IP address : {ip}")
    else:
        print("  Could not resolve domain (may not exist or DNS blocked).")

    whois_data = whois_lookup(domain)
    if whois_data:
        print(f"  Registrar           : {getattr(whois_data, 'registrar', 'N/A')}")
        print(f"  Creation date       : {getattr(whois_data, 'creation_date', 'N/A')}")
        print(f"  Expiration date     : {getattr(whois_data, 'expiration_date', 'N/A')}")
        print(f"  Name servers        : {getattr(whois_data, 'name_servers', 'N/A')}")


def cmd_email(args):
    email = args.value
    valid = validate_email_format(email)
    print(f"Email: {email}")
    print(f"Valid format: {'yes' if valid else 'no'}")
    if valid:
        domain = email.split("@", 1)[1]
        ip = resolve_domain(domain)
        if ip:
            print(f"Domain '{domain}' resolves to {ip} (mail domain appears active)")
        else:
            print(f"Domain '{domain}' does not resolve — likely invalid or fake domain")


def main():
    parser = argparse.ArgumentParser(
        description="Gather public OSINT: username presence, domain WHOIS, email format checks."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_user = subparsers.add_parser("username", help="Check username presence across platforms")
    p_user.add_argument("value", help="Username to check")
    p_user.set_defaults(func=cmd_username)

    p_domain = subparsers.add_parser("domain", help="Look up domain WHOIS/DNS info")
    p_domain.add_argument("value", help="Domain to investigate")
    p_domain.set_defaults(func=cmd_domain)

    p_email = subparsers.add_parser("email", help="Validate email format and check domain")
    p_email.add_argument("value", help="Email address to check")
    p_email.set_defaults(func=cmd_email)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
