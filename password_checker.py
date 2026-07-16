#!/usr/bin/env python3
"""
Password Strength Checker
--------------------------
Evaluates password strength using length, character variety, entropy
estimation, common-password/dictionary checks, and pattern detection
(keyboard walks, repeated chars, sequences). Offers concrete
suggestions for improvement — never stores or transmits the password.

Usage:
    python password_checker.py
    python password_checker.py --password "Tr0ub4dor&3"
"""

import argparse
import getpass
import math
import re
import os

COMMON_PASSWORDS_FILE = os.path.join(os.path.dirname(__file__), "common_passwords.txt")

KEYBOARD_ROWS = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1234567890",
]


def load_common_passwords():
    try:
        with open(COMMON_PASSWORDS_FILE) as f:
            return {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        return set()


def has_keyboard_walk(password, min_run=4):
    lower = password.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - min_run + 1):
            chunk = row[i:i + min_run]
            if chunk in lower or chunk[::-1] in lower:
                return chunk
    return None


def has_sequential_chars(password, min_run=4):
    lower = password.lower()
    for i in range(len(lower) - min_run + 1):
        chunk = lower[i:i + min_run]
        if all(ord(chunk[j + 1]) - ord(chunk[j]) == 1 for j in range(len(chunk) - 1)):
            return chunk
        if all(ord(chunk[j]) - ord(chunk[j + 1]) == 1 for j in range(len(chunk) - 1)):
            return chunk
    return None


def has_repeated_chars(password, min_run=4):
    for i in range(len(password) - min_run + 1):
        if len(set(password[i:i + min_run])) == 1:
            return password[i:i + min_run]
    return None


def estimate_entropy(password):
    """Rough Shannon-style entropy estimate based on character pool size."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32
    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def check_password(password, common_passwords):
    issues = []
    suggestions = []
    score = 0  # out of 100

    length = len(password)

    # Length scoring
    if length < 8:
        issues.append("Too short (under 8 characters)")
        suggestions.append("Use at least 12 characters")
    elif length < 12:
        score += 15
        suggestions.append("Consider 12+ characters for stronger protection")
    else:
        score += 25

    # Character variety
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))
    variety = sum([has_lower, has_upper, has_digit, has_symbol])
    score += variety * 10

    if not has_upper:
        suggestions.append("Add an uppercase letter")
    if not has_lower:
        suggestions.append("Add a lowercase letter")
    if not has_digit:
        suggestions.append("Add a number")
    if not has_symbol:
        suggestions.append("Add a symbol (e.g. ! @ # $ %)")

    # Common password check
    if password.lower() in common_passwords:
        issues.append("This is one of the most commonly used passwords — trivially guessable")
        score = min(score, 10)

    # Pattern checks
    walk = has_keyboard_walk(password)
    if walk:
        issues.append(f"Contains a keyboard-walk pattern ('{walk}')")
        score -= 15

    seq = has_sequential_chars(password)
    if seq:
        issues.append(f"Contains a sequential character pattern ('{seq}')")
        score -= 15

    rep = has_repeated_chars(password)
    if rep:
        issues.append(f"Contains repeated characters ('{rep}')")
        score -= 10

    entropy = estimate_entropy(password)
    score = max(0, min(100, score))

    if entropy < 28:
        strength = "VERY WEAK"
    elif entropy < 36:
        strength = "WEAK"
    elif entropy < 60:
        strength = "MODERATE"
    elif entropy < 80:
        strength = "STRONG"
    else:
        strength = "VERY STRONG"

    if password.lower() in common_passwords:
        strength = "VERY WEAK"

    if not suggestions and not issues:
        suggestions.append("Looks solid — consider a passphrase (e.g. 4+ random words) for even easier-to-remember strength")

    return {
        "length": length,
        "entropy_bits": round(entropy, 1),
        "score": score,
        "strength": strength,
        "issues": issues,
        "suggestions": suggestions,
    }


def print_result(result):
    print("\n" + "=" * 50)
    print("PASSWORD STRENGTH REPORT")
    print("=" * 50)
    print(f"Length            : {result['length']} characters")
    print(f"Estimated entropy : {result['entropy_bits']} bits")
    print(f"Score             : {result['score']}/100")
    print(f"Strength rating   : {result['strength']}")

    if result["issues"]:
        print("\nIssues found:")
        for issue in result["issues"]:
            print(f"  ⚠  {issue}")

    if result["suggestions"]:
        print("\nSuggestions:")
        for s in result["suggestions"]:
            print(f"  → {s}")
    print("=" * 50)


def main():
    parser = argparse.ArgumentParser(description="Check password strength and get improvement suggestions.")
    parser.add_argument("--password", help="Password to check (omit to be prompted securely)")
    args = parser.parse_args()

    password = args.password or getpass.getpass("Enter password to check (input hidden): ")
    if not password:
        print("No password entered.")
        return

    common_passwords = load_common_passwords()
    result = check_password(password, common_passwords)
    print_result(result)


if __name__ == "__main__":
    main()
