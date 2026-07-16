# 🕵️ OSINT Investigation Tool

A Python CLI that pulls together open-source intelligence from
multiple public sources: checking whether a username exists across
common platforms, pulling WHOIS/DNS data for a domain, and validating
email address format + domain activity.

> ⚠️ **Ethics & legal note:** this tool only queries information that
> is already public (public profile pages, public WHOIS records). It
> does not log in, bypass authentication, or scrape private data. Use
> it only on your own accounts/domains or as part of an authorized
> investigation, and respect each platform's Terms of Service.

## Why this project

OSINT is a core skill in threat intelligence, incident response, and
investigations. This shows you can pull structured signal from
scattered public sources and automate the repetitive parts of that
research.

## Features

- **Username check** — tests presence across 8 platforms (GitHub,
  Twitter/X, Instagram, Reddit, LinkedIn, TikTok, Medium, GitLab)
- **Domain investigation** — DNS resolution + WHOIS (registrar,
  creation/expiration dates, name servers)
- **Email validation** — format check + verifies the domain is active

## Setup

```bash
pip install -r requirements.txt
```

## Usage

```bash
python osint_tool.py username johndoe123
python osint_tool.py domain example.com
python osint_tool.py email jdoe@example.com
```

## Example output

```
Checking username 'johndoe123' across 8 platforms...

  ✅ GitHub       FOUND      https://github.com/johndoe123
  ❌ Twitter/X    not found  (status 404)
  ✅ Reddit       FOUND      https://www.reddit.com/user/johndoe123
  ...

Summary: found on 2/8 checked platforms.
```

## Skills demonstrated

- OSINT methodology (multi-source public info gathering)
- Python `requests` for HTTP-based reconnaissance
- Basic DNS/WHOIS lookups
- Working ethically with public data and clear scope boundaries

## Possible extensions

- Add more platforms (Pinterest, YouTube, Twitch, etc.)
- Add breach-check integration (Have I Been Pwned API, with consent)
- Export findings to a structured JSON/PDF investigation report
- Add rate-limiting/backoff to be a good citizen of the platforms queried
