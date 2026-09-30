"""Transparent heuristic URL risk scoring for learning."""
from __future__ import annotations

import argparse
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse


# [SECTION] Detection rules
# These words are not automatically malicious. They simply increase the score when
# they appear in a URL because they are common in credential-themed phishing lures.
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


# [SECTION] Result model
@dataclass(frozen=True)
class URLResult:
    """Store the final score, label, and human-readable reasons for a URL."""

    score: int
    label: str
    reasons: tuple[str, ...]


# [SECTION] URL normalization
def normalise_url(value: str) -> str:
    """Add a default scheme when the user supplies only a hostname or path."""

    value = value.strip()
    return value if "://" in value else f"http://{value}"


def is_ip_address(host: str) -> bool:
    """Return True when the hostname is a valid IPv4 or IPv6 address."""

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# [SECTION] Heuristic scoring engine
def score_url(url: str) -> URLResult:
    """Score a URL using simple, explainable phishing indicators."""

    parsed = urlparse(normalise_url(url))
    host = (parsed.hostname or "").lower()
    path_and_query = f"{parsed.path}?{parsed.query}".lower()

    score = 0
    reasons: list[str] = []

    # Plain HTTP does not provide transport encryption or server authentication.
    if parsed.scheme != "https":
        score += 1
        reasons.append("does not use HTTPS")

    # A missing hostname is malformed; a raw IP is less trustworthy than a named site
    # for this simple learning heuristic.
    if not host:
        score += 2
        reasons.append("hostname is missing")
    elif is_ip_address(host):
        score += 2
        reasons.append("host is an IP address instead of a domain")

    # Very long URLs can hide important parts of the destination from a user.
    if len(url) > 100:
        score += 1
        reasons.append("URL is unusually long")

    # Count subdomain depth only for domain names, not dotted IPv4 addresses.
    if host and not is_ip_address(host) and host.count(".") >= 3:
        score += 1
        reasons.append("contains many subdomain levels")

    # The @ character can make the visible authority section confusing to users.
    if "@" in parsed.netloc:
        score += 2
        reasons.append("contains @ in the authority section")

    # Search both hostname and path/query for credential-themed terms.
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


# [SECTION] Command-line interface
def main() -> None:
    """Score one or more URLs supplied from the command line."""

    parser = argparse.ArgumentParser(
        description="Score URLs using transparent phishing heuristics."
    )
    parser.add_argument("urls", nargs="+")
    args = parser.parse_args()

    for raw in args.urls:
        result = score_url(raw)
        print(f"\n{raw}\n  Score: {result.score}\n  Result: {result.label}")
        for reason in result.reasons:
            print(f"  - {reason}")


if __name__ == "__main__":
    main()
