#!/usr/bin/env python3
"""
URL & Phishing Detector
-----------------------
Analyzes a URL's structure for common phishing indicators and produces
a risk score (0-100) with an explanation of every signal that fired.

This is a heuristic, offline analyzer — it does NOT need to contact
any external API. That keeps it fast, free, and safe to run on
untrusted URLs (it never visits the link).

Usage:
    python phishing_detector.py "http://paypal-secure-login.verify-account.tk/login"
    python phishing_detector.py --file urls.txt
"""

import argparse
import ipaddress
import re
import sys
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "secure", "update", "confirm",
    "banking", "signin", "webscr", "password", "suspend", "urgent",
    "billing", "invoice", "unlock", "security-alert",
]

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".club", ".work",
    ".info", ".click", ".link",
}

KNOWN_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "netflix", "bankofamerica", "wellsfargo", "chase", "instagram",
    "linkedin", "outlook", "dropbox",
]

# Common homoglyph substitutions used in lookalike domains
HOMOGLYPHS = {
    "0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "vv": "w",
}


def is_ip_address(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def contains_homoglyph_trick(host):
    normalized = host.lower()
    for sub, real in HOMOGLYPHS.items():
        normalized = normalized.replace(sub, real)
    for brand in KNOWN_BRANDS:
        if brand in normalized and brand not in host.lower():
            return brand
    return None


def looks_like_brand_impersonation(host, brand_list=KNOWN_BRANDS):
    """Flags cases like 'paypal-secure.tk' or 'secure-paypal-login.com'
    where a brand name appears but the domain isn't actually that brand."""
    host_lower = host.lower()
    for brand in brand_list:
        if brand in host_lower:
            # Extract the registrable-ish domain (very rough, no PSL dependency)
            parts = host_lower.split(".")
            # crude check: is the brand the primary domain label right before the TLD?
            if len(parts) >= 2 and parts[-2] == brand:
                continue  # e.g. paypal.com -- looks legitimate structurally
            return brand
    return None


def analyze_url(url):
    findings = []
    score = 0

    parsed = urlparse(url if "://" in url else "http://" + url)
    host = parsed.hostname or ""
    path = parsed.path or ""
    full = url.lower()

    # 1. IP address instead of domain name
    if is_ip_address(host):
        score += 25
        findings.append(("IP address used instead of domain name", 25))

    # 2. No HTTPS
    if parsed.scheme != "https":
        score += 10
        findings.append(("Not using HTTPS", 10))

    # 3. Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            score += 15
            findings.append((f"Uses commonly-abused TLD '{tld}'", 15))
            break

    # 4. '@' symbol in URL (browsers ignore everything before it)
    if "@" in url:
        score += 20
        findings.append(("Contains '@' symbol (can hide the real destination)", 20))

    # 5. Excessive subdomains
    subdomain_count = max(host.count("."), 0)
    if subdomain_count >= 3:
        score += 10
        findings.append((f"Unusually deep subdomain structure ({subdomain_count} dots)", 10))

    # 6. Hyphens in domain (common in lookalike domains)
    if host.count("-") >= 2:
        score += 10
        findings.append((f"Multiple hyphens in domain ({host.count('-')})", 10))

    # 7. Suspicious keywords in path or host
    hit_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full]
    if hit_keywords:
        pts = min(15, 5 * len(hit_keywords))
        score += pts
        findings.append((f"Contains suspicious keyword(s): {', '.join(hit_keywords[:5])}", pts))

    # 8. Brand impersonation via homoglyphs
    homoglyph_brand = contains_homoglyph_trick(host)
    if homoglyph_brand:
        score += 25
        findings.append((f"Possible lookalike/homoglyph trick for brand '{homoglyph_brand}'", 25))

    # 9. Brand name present but not as the actual domain
    impersonated = looks_like_brand_impersonation(host)
    if impersonated:
        score += 20
        findings.append((f"Brand name '{impersonated}' present but domain structure looks fake", 20))

    # 10. Excessive URL length (phishing URLs are often long to hide the real domain)
    if len(url) > 75:
        score += 5
        findings.append((f"Unusually long URL ({len(url)} chars)", 5))

    score = min(score, 100)
    return {
        "url": url,
        "host": host,
        "score": score,
        "findings": findings,
        "risk_level": risk_level(score),
    }


def risk_level(score):
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "MINIMAL"


def print_result(result):
    print(f"\nURL: {result['url']}")
    print(f"Host: {result['host']}")
    print(f"Risk score: {result['score']}/100  ->  {result['risk_level']} RISK")
    if result["findings"]:
        print("Signals detected:")
        for desc, pts in result["findings"]:
            print(f"  [+{pts:>2}] {desc}")
    else:
        print("No suspicious signals detected.")


def main():
    parser = argparse.ArgumentParser(description="Heuristic phishing/URL risk analyzer.")
    parser.add_argument("url", nargs="?", help="A single URL to analyze")
    parser.add_argument("--file", help="Path to a text file with one URL per line")
    args = parser.parse_args()

    if not args.url and not args.file:
        parser.print_help()
        sys.exit(1)

    urls = []
    if args.url:
        urls.append(args.url)
    if args.file:
        with open(args.file) as f:
            urls.extend(line.strip() for line in f if line.strip())

    for url in urls:
        result = analyze_url(url)
        print_result(result)


if __name__ == "__main__":
    main()
