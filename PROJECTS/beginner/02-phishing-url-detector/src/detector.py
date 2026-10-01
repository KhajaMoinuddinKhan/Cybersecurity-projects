"""Score URLs with a few simple phishing clues."""
from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from dataclasses import dataclass
from urllib.parse import urlparse

# These words only add to the score. A match does not make a URL malicious.
SUSPICIOUS_TERMS = {
    "account",
    "bank",
    "confirm",
    "login",
    "password",
    "secure",
    "update",
    "verify",
}

@dataclass(frozen=True)
class URLResult:
    """Result returned for one URL."""

    score: int
    label: str
    reasons: tuple[str, ...]

def normalise_url(value: str) -> str:
    """Add http:// when the input has no scheme."""

    value = value.strip()
    # A scheme sits at the start; "://" later in a path or query is not one.
    if re.match(r"[a-zA-Z][a-zA-Z0-9+.\-]*://", value):
        return value
    if value.startswith("//"):
        return f"http:{value}"
    return f"http://{value}"

def is_ip_address(host: str) -> bool:
    """Check whether a host is an IP address."""

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def score_url(url: str) -> URLResult:
    """Score a URL and keep the reasons."""

    parsed = urlparse(normalise_url(url))
    host = (parsed.hostname or "").lower()
    path_and_query = f"{parsed.path}?{parsed.query}".lower()

    score = 0
    reasons: list[str] = []

    # Plain HTTP adds one point.
    if parsed.scheme != "https":
        score += 1
        reasons.append("does not use HTTPS")

    # Missing hosts and raw IP addresses are harder to trust at a glance.
    if not host:
        score += 2
        reasons.append("hostname is missing")
    elif is_ip_address(host):
        score += 2
        reasons.append("host is an IP address instead of a domain")

    # Long URLs can hide the important part of an address.
    if len(url) > 100:
        score += 1
        reasons.append("URL is unusually long")

    if host and not is_ip_address(host) and host.count(".") >= 3:
        score += 1
        reasons.append("contains many subdomain levels")

    if "@" in parsed.netloc:
        score += 2
        reasons.append("contains @ in the authority section")

    # Look for credential-themed words in the host and path.
    combined = f"{host} {path_and_query}"
    hits = sorted(
        term
        for term in SUSPICIOUS_TERMS
        if re.search(rf"\b{re.escape(term)}\b", combined)
    )
    if hits:
        score += min(2, len(hits))
        reasons.append("contains suspicious terms: " + ", ".join(hits))

    label = "Potentially suspicious" if score >= 3 else "Lower risk by these rules"
    return URLResult(score, label, tuple(reasons))

def main() -> None:
    """Score URLs passed on the command line."""

    parser = argparse.ArgumentParser(
        description="Score URLs using transparent phishing heuristics."
    )
    parser.add_argument("urls", nargs="+")
    args = parser.parse_args()

    invalid = False
    for raw in args.urls:
        try:
            result = score_url(raw)
        except ValueError as exc:
            print(f"Invalid URL {raw!r}: {exc}", file=sys.stderr)
            invalid = True
            continue
        print(f"\n{raw}\n  Score: {result.score}\n  Result: {result.label}")
        for reason in result.reasons:
            print(f"  - {reason}")
    if invalid:
        raise SystemExit(1)

if __name__ == "__main__":
    main()
