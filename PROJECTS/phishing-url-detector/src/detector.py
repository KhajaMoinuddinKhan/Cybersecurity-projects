"""Score URLs with transparent phishing clues, offline and by hand."""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import urlparse

# Credential-harvesting words. A match only adds to the score.
SUSPICIOUS_TERMS = {
    "account",
    "bank",
    "confirm",
    "login",
    "password",
    "secure",
    "signin",
    "update",
    "verify",
    "wallet",
}

# Top-level domains that appear disproportionately in abuse reports.
SUSPICIOUS_TLDS = {
    "bid",
    "buzz",
    "cam",
    "cf",
    "click",
    "country",
    "cricket",
    "cyou",
    "date",
    "download",
    "faith",
    "gdn",
    "gq",
    "icu",
    "link",
    "loan",
    "lol",
    "men",
    "ml",
    "monster",
    "mov",
    "online",
    "party",
    "quest",
    "racing",
    "rest",
    "review",
    "science",
    "sbs",
    "stream",
    "surf",
    "tk",
    "top",
    "trade",
    "webcam",
    "win",
    "work",
    "xyz",
    "zip",
}

# Hosts that hide the real destination behind a short link.
URL_SHORTENERS = {
    "adf.ly",
    "bit.do",
    "bit.ly",
    "bl.ink",
    "buff.ly",
    "clck.ru",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "lnkd.in",
    "mcaf.ee",
    "ow.ly",
    "po.st",
    "qr.ae",
    "rb.gy",
    "rebrand.ly",
    "s.id",
    "short.gy",
    "shorturl.at",
    "soo.gd",
    "su.pr",
    "t.co",
    "t.ly",
    "tiny.cc",
    "tinyurl.com",
    "trib.al",
    "urlz.fr",
    "v.gd",
}

# Registrable domains that end in two labels rather than one.
MULTI_LABEL_SUFFIXES = {
    "ac.uk",
    "co.id",
    "co.il",
    "co.in",
    "co.jp",
    "co.ke",
    "co.kr",
    "co.nz",
    "co.th",
    "co.uk",
    "co.za",
    "com.ar",
    "com.au",
    "com.br",
    "com.cn",
    "com.co",
    "com.eg",
    "com.hk",
    "com.mx",
    "com.my",
    "com.ng",
    "com.pe",
    "com.ph",
    "com.pk",
    "com.sa",
    "com.sg",
    "com.tr",
    "com.tw",
    "com.ua",
    "com.vn",
    "edu.au",
    "firm.in",
    "gen.in",
    "gov.au",
    "gov.uk",
    "me.uk",
    "ne.jp",
    "net.au",
    "net.br",
    "net.cn",
    "net.in",
    "net.nz",
    "net.uk",
    "or.jp",
    "or.kr",
    "org.au",
    "org.br",
    "org.cn",
    "org.in",
    "org.nz",
    "org.uk",
    "org.za",
    "sch.uk",
}

# Frequently impersonated brands, keyed by the label of their real domain.
BRANDS: dict[str, tuple[str, ...]] = {
    "adobe": ("adobe.com",),
    "airbnb": ("airbnb.com",),
    "alibaba": ("alibaba.com",),
    "aliexpress": ("aliexpress.com",),
    "amazon": ("amazon.com",),
    "americanexpress": ("americanexpress.com",),
    "apple": ("apple.com",),
    "bankofamerica": ("bankofamerica.com",),
    "barclays": ("barclays.co.uk",),
    "binance": ("binance.com",),
    "booking": ("booking.com",),
    "capitalone": ("capitalone.com",),
    "chase": ("chase.com",),
    "citibank": ("citibank.com",),
    "coinbase": ("coinbase.com",),
    "discord": ("discord.com",),
    "discover": ("discover.com",),
    "dhl": ("dhl.com",),
    "dropbox": ("dropbox.com",),
    "ebay": ("ebay.com",),
    "facebook": ("facebook.com",),
    "fedex": ("fedex.com",),
    "fidelity": ("fidelity.com",),
    "github": ("github.com",),
    "google": ("google.com",),
    "hotmail": ("hotmail.com",),
    "hsbc": ("hsbc.com",),
    "icloud": ("icloud.com",),
    "instagram": ("instagram.com",),
    "linkedin": ("linkedin.com",),
    "microsoft": ("microsoft.com",),
    "moneygram": ("moneygram.com",),
    "netflix": ("netflix.com",),
    "outlook": ("outlook.com",),
    "paypal": ("paypal.com",),
    "reddit": ("reddit.com",),
    "robinhood": ("robinhood.com",),
    "shopify": ("shopify.com",),
    "snapchat": ("snapchat.com",),
    "spotify": ("spotify.com",),
    "steampowered": ("steampowered.com",),
    "stripe": ("stripe.com",),
    "telegram": ("telegram.org",),
    "tiktok": ("tiktok.com",),
    "twitter": ("twitter.com",),
    "uber": ("uber.com",),
    "usps": ("usps.com",),
    "walmart": ("walmart.com",),
    "wellsfargo": ("wellsfargo.com",),
    "westernunion": ("westernunion.com",),
    "whatsapp": ("whatsapp.com",),
    "yahoo": ("yahoo.com",),
    "youtube": ("youtube.com",),
}

# A document or media extension sitting in front of an executable one.
DECEPTIVE_EXTENSION = re.compile(
    r"\.(?:pdf|doc|docx|xls|xlsx|ppt|pptx|jpg|jpeg|png|gif|txt|csv|rtf|odt|"
    r"mp3|mp4|wav|svg)"
    r"\.(?:exe|scr|bat|cmd|com|js|jse|vbs|vbe|msi|jar|ps1|hta|html|htm|php|"
    r"apk|zip|rar|iso|lnk|dll|img|bin)\b"
)

# Non-ASCII characters that a reader can mistake for a Latin letter.
_EXPLICIT_CONFUSABLES: dict[str, str] = {
    # Cyrillic
    "\u0430": "a",
    "\u0432": "b",
    "\u0433": "r",
    "\u0435": "e",
    "\u043a": "k",
    "\u043c": "m",
    "\u043d": "h",
    "\u043e": "o",
    "\u043f": "n",
    "\u0440": "p",
    "\u0441": "c",
    "\u0442": "t",
    "\u0443": "y",
    "\u0445": "x",
    "\u0455": "s",
    "\u0456": "i",
    "\u0458": "j",
    "\u04bb": "h",
    "\u04cf": "l",
    "\u0501": "d",
    "\u051b": "q",
    "\u051d": "w",
    # Greek
    "\u03b1": "a",
    "\u03b2": "b",
    "\u03b3": "y",
    "\u03b5": "e",
    "\u03b6": "z",
    "\u03b9": "i",
    "\u03ba": "k",
    "\u03bd": "v",
    "\u03bf": "o",
    "\u03c1": "p",
    "\u03c4": "t",
    "\u03c5": "u",
    "\u03c7": "x",
    "\u03f2": "c",
    # Latin lookalikes outside ASCII
    "\u0261": "g",
    "\u0269": "i",
    "\u026a": "i",
    "\u029f": "l",
    "\u1d00": "a",
    "\u1d0f": "o",
    "\u1d1c": "u",
}

def _fullwidth_confusables() -> dict[str, str]:
    """Map fullwidth ASCII letters and digits back to their plain forms."""

    mapping: dict[str, str] = {}
    for offset in range(26):
        mapping[chr(0xFF41 + offset)] = chr(ord("a") + offset)
        mapping[chr(0xFF21 + offset)] = chr(ord("a") + offset)
    for offset in range(10):
        mapping[chr(0xFF10 + offset)] = chr(ord("0") + offset)
    return mapping

HOMOGLYPHS: dict[str, str] = {**_EXPLICIT_CONFUSABLES, **_fullwidth_confusables()}

# Signal thresholds. Each one is a deliberate, documented cut-off.
LONG_URL_LIMIT = 100
SHORT_URL_LIMIT = 12
EXCESSIVE_SUBDOMAIN_DEPTH = 3
HEAVY_ENCODING_LIMIT = 4

# Score bands that turn the total into a verdict.
LOW_MAX_SCORE = 2
MEDIUM_MAX_SCORE = 5

VERDICT_LABELS = {
    "low": "Lower risk by these rules",
    "medium": "Potentially suspicious",
    "high": "High risk by these rules",
}

@dataclass(frozen=True)
class SignalOutcome:
    """Outcome of one signal check for one URL."""

    name: str
    title: str
    fired: bool
    points: int
    detail: str

@dataclass(frozen=True)
class URLResult:
    """Result returned for one URL."""

    url: str
    score: int
    verdict: str
    label: str
    reasons: tuple[str, ...]
    findings: tuple[SignalOutcome, ...]
    outcomes: tuple[SignalOutcome, ...]

def ascii_safe(text: str) -> str:
    """Escape non-ASCII text so any console can print it."""

    return text.encode("ascii", "backslashreplace").decode("ascii")

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

def registrable_domain(host: str) -> str:
    """Return the registrable domain (the last label plus its suffix)."""

    if not host or is_ip_address(host):
        return ""
    labels = host.split(".")
    if len(labels) < 2:
        return host
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])

def levenshtein(a: str, b: str) -> int:
    """Return the edit distance between two strings."""

    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, 1):
        current = [i]
        for j, char_b in enumerate(b, 1):
            current.append(
                min(
                    previous[j] + 1,
                    current[j - 1] + 1,
                    previous[j - 1] + (char_a != char_b),
                )
            )
        previous = current
    return previous[-1]

def homoglyph_normalise(text: str) -> str:
    """Replace lookalike characters with the Latin letters they imitate."""

    return "".join(HOMOGLYPHS.get(char, char) for char in text)

def decode_punycode_label(label: str) -> str:
    """Decode an xn-- label back to Unicode, leaving other labels alone."""

    if not label.startswith("xn--"):
        return label
    try:
        return label.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return label

def find_typosquat(label: str, registrable: str) -> tuple[str, str, str, int] | None:
    """Compare a domain label with the embedded brand list."""

    if not label:
        return None
    decoded = decode_punycode_label(label).lower()
    normalised = homoglyph_normalise(decoded)
    best: tuple[str, str, str, int] | None = None
    for brand, officials in BRANDS.items():
        if registrable in officials:
            # The URL is the real domain, so there is nothing to report.
            return None
        if normalised == brand:
            if decoded == brand:
                how = "reuses the name of the brand behind"
            else:
                how = "is a lookalike of the brand behind"
            return (brand, officials[0], how, 0)
        if len(brand) < 4:
            # Short names produce too many coincidental near-matches.
            continue
        distance = levenshtein(normalised, brand)
        if 1 <= distance <= 2 and abs(len(normalised) - len(brand)) <= 2:
            if best is None or distance < best[3]:
                best = (brand, officials[0], "looks like the brand behind", distance)
    return best

def verdict_for(score: int) -> str:
    """Turn a score into a low, medium, or high verdict."""

    if score <= LOW_MAX_SCORE:
        return "low"
    if score <= MEDIUM_MAX_SCORE:
        return "medium"
    return "high"

def _signal(name: str, title: str, fired: bool, points: int, detail: str) -> SignalOutcome:
    """Build one outcome, awarding points only when the signal fired."""

    return SignalOutcome(name, title, fired, points if fired else 0, detail)

def evaluate_url(url: str) -> tuple[SignalOutcome, ...]:
    """Run every signal against one URL and keep the outcome of each."""

    normalised = normalise_url(url)
    parsed = urlparse(normalised)
    host = (parsed.hostname or "").lower()
    try:
        port: int | None = parsed.port
    except ValueError:
        port = -1
    host_is_ip = bool(host) and is_ip_address(host)
    labels = [label for label in host.split(".") if label] if host else []
    registrable = registrable_domain(host)
    registrable_labels = registrable.split(".") if registrable else []
    if registrable_labels:
        subdomains = labels[: len(labels) - len(registrable_labels)]
    else:
        subdomains = []
    path = parsed.path or ""
    query = parsed.query or ""
    path_and_query = f"{path}?{query}".lower()
    host_display = ascii_safe(host)

    outcomes: list[SignalOutcome] = []

    # 1. Transport protection.
    if parsed.scheme != "https":
        outcomes.append(_signal("plain_http", "Transport security", True, 1, "does not use HTTPS"))
    else:
        outcomes.append(_signal("plain_http", "Transport security", False, 1, "URL uses HTTPS"))

    # 2. A missing host or a raw IP address.
    if not host:
        outcomes.append(_signal("missing_host", "Host presence", True, 2, "hostname is missing"))
    else:
        outcomes.append(_signal("missing_host", "Host presence", False, 2, f"host {host_display} is present"))

    if host and host_is_ip:
        outcomes.append(_signal("ip_host", "Host form (domain vs IP)", True, 2, "host is an IP address instead of a domain"))
    else:
        outcomes.append(_signal("ip_host", "Host form (domain vs IP)", False, 2, f"host {host_display} is not an IP address"))

    # 3. Unusual overall length, in either direction.
    if len(url) > LONG_URL_LIMIT:
        outcomes.append(_signal("long_url", "URL length (long)", True, 1, f"URL is unusually long ({len(url)} characters)"))
    else:
        outcomes.append(_signal("long_url", "URL length (long)", False, 1, f"URL is {len(url)} characters long"))
    if len(url) <= SHORT_URL_LIMIT:
        outcomes.append(_signal("short_url", "URL length (short)", True, 1, f"URL is unusually short ({len(url)} characters)"))
    else:
        outcomes.append(_signal("short_url", "URL length (short)", False, 1, f"URL is {len(url)} characters long"))

    # 4. Excessive subdomain depth.
    depth = len(subdomains)
    if depth >= EXCESSIVE_SUBDOMAIN_DEPTH:
        target = registrable or host
        outcomes.append(_signal("subdomain_depth", "Subdomain depth", True, 1, f"excessive subdomain depth ({depth} levels before {ascii_safe(target)})"))
    else:
        outcomes.append(_signal("subdomain_depth", "Subdomain depth", False, 1, f"{depth} subdomain level(s) before the registrable domain"))

    # 5. An @ in the authority section.
    if "@" in parsed.netloc:
        outcomes.append(_signal("at_in_authority", "Authority section", True, 2, "contains @ in the authority section"))
    else:
        outcomes.append(_signal("at_in_authority", "Authority section", False, 2, "authority section has no @"))

    # 6. A non-standard port.
    if port == -1:
        outcomes.append(_signal("nonstandard_port", "Port", True, 1, "authority contains an invalid port"))
    elif port is not None and port not in (80, 443):
        outcomes.append(_signal("nonstandard_port", "Port", True, 1, f"uses a non-standard port: {port}"))
    else:
        outcomes.append(_signal("nonstandard_port", "Port", False, 1, "uses a standard port or none"))

    # 7. Punycode (xn--) labels.
    punycode_labels = [label for label in labels if label.startswith("xn--")]
    if punycode_labels:
        decoded = decode_punycode_label(punycode_labels[0])
        detail = f"host contains a punycode label: {punycode_labels[0]}"
        if decoded != punycode_labels[0]:
            detail += f" (decodes to {ascii_safe(decoded)})"
        outcomes.append(_signal("punycode_label", "Punycode label", True, 2, detail))
    else:
        outcomes.append(_signal("punycode_label", "Punycode label", False, 2, "host has no punycode (xn--) label"))

    # 8. Lookalike Unicode characters.
    confusables = sorted({char for char in host if char in HOMOGLYPHS})
    if confusables:
        shown = ", ".join(f"{ascii_safe(char)}->{HOMOGLYPHS[char]}" for char in confusables)
        outcomes.append(_signal("homoglyph", "Lookalike characters", True, 3, f"host contains lookalike characters: {shown}"))
    else:
        outcomes.append(_signal("homoglyph", "Lookalike characters", False, 3, "host uses only plain ASCII letters"))

    # 9. Typosquatting against the embedded brand list.
    squat_label = registrable_labels[0] if registrable_labels else (labels[0] if labels else "")
    match = find_typosquat(squat_label, registrable) if (host and not host_is_ip) else None
    if match:
        _brand, official, how, distance = match
        detail = f"host {how} {official}"
        if distance:
            detail += f" (edit distance {distance})"
        outcomes.append(_signal("typosquat", "Brand resemblance", True, 3, detail))
    else:
        outcomes.append(_signal("typosquat", "Brand resemblance", False, 3, "host does not resemble an embedded brand"))

    # 10. A brand name parked in the subdomain or path.
    path_words = [word for word in re.split(r"[^a-z0-9]+", path.lower()) if word]
    brand_hits: list[tuple[str, str, str]] = []
    for brand, officials in BRANDS.items():
        if registrable in officials:
            continue
        if brand in subdomains:
            brand_hits.append((brand, "subdomain", officials[0]))
        elif brand in path_words:
            brand_hits.append((brand, "path", officials[0]))
    if brand_hits:
        shown = ", ".join(f"{brand} in the {where} (real domain {official})" for brand, where, official in brand_hits)
        outcomes.append(_signal("brand_in_host_or_path", "Brand away from its domain", True, 2, "brand name appears away from its domain: " + shown))
    else:
        outcomes.append(_signal("brand_in_host_or_path", "Brand away from its domain", False, 2, "no brand name appears in the subdomain or path"))

    # 11. A top-level domain that is frequently abused.
    tld = host.rsplit(".", 1)[-1] if ("." in host and not host_is_ip) else ""
    if tld in SUSPICIOUS_TLDS:
        outcomes.append(_signal("suspicious_tld", "Top-level domain", True, 1, f"uses a top-level domain often abused for phishing: .{tld}"))
    else:
        outcomes.append(_signal("suspicious_tld", "Top-level domain", False, 1, "top-level domain is not on the abused-TLD list"))

    # 12. A doubled or deceptive file extension.
    extension = DECEPTIVE_EXTENSION.search(path.lower())
    if extension:
        outcomes.append(_signal("deceptive_extension", "Doubled file extension", True, 3, f"path contains a deceptive doubled file extension: {extension.group(0)}"))
    else:
        outcomes.append(_signal("deceptive_extension", "Doubled file extension", False, 3, "path has no doubled file extension"))

    # 13. Heavy percent-encoding in the path.
    escapes = re.findall(r"%[0-9a-fA-F]{2}", path_and_query)
    if len(escapes) >= HEAVY_ENCODING_LIMIT:
        outcomes.append(_signal("heavy_encoding", "Percent-encoding", True, 1, f"path is heavily percent-encoded ({len(escapes)} escapes)"))
    else:
        outcomes.append(_signal("heavy_encoding", "Percent-encoding", False, 1, f"path has {len(escapes)} percent-escape(s)"))

    # 14. A known URL shortener.
    if host in URL_SHORTENERS or registrable in URL_SHORTENERS:
        outcomes.append(_signal("url_shortener", "URL shortener", True, 1, f"host is a known URL shortener: {host_display}"))
    else:
        outcomes.append(_signal("url_shortener", "URL shortener", False, 1, "host is not a known URL shortener"))

    # 15. Credential-harvesting words.
    combined = f"{host} {path_and_query}"
    hits = sorted(
        term
        for term in SUSPICIOUS_TERMS
        if re.search(rf"\b{re.escape(term)}\b", combined)
    )
    if hits:
        outcomes.append(_signal("suspicious_terms", "Credential-harvesting words", True, min(2, len(hits)), "contains suspicious terms: " + ", ".join(hits)))
    else:
        outcomes.append(_signal("suspicious_terms", "Credential-harvesting words", False, 2, "no credential-harvesting terms found"))

    return tuple(outcomes)

def score_url(url: str) -> URLResult:
    """Score a URL and keep every reason behind the number."""

    outcomes = evaluate_url(url)
    score = sum(outcome.points for outcome in outcomes)
    findings = tuple(outcome for outcome in outcomes if outcome.fired)
    verdict = verdict_for(score)
    return URLResult(
        url=url,
        score=score,
        verdict=verdict,
        label=VERDICT_LABELS[verdict],
        reasons=tuple(outcome.detail for outcome in findings),
        findings=findings,
        outcomes=outcomes,
    )

def read_url_lines(lines: Iterable[str]) -> list[str]:
    """Read one URL per line, ignoring blank lines and comments."""

    urls: list[str] = []
    for line in lines:
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        urls.append(text)
    return urls

def collect_urls(args: argparse.Namespace) -> list[str]:
    """Gather URLs from arguments, a file, or standard input."""

    urls = list(args.urls)
    if args.file == "-":
        urls.extend(read_url_lines(sys.stdin))
    elif args.file:
        try:
            with open(args.file, encoding="utf-8-sig") as handle:
                urls.extend(read_url_lines(handle))
        except OSError as exc:
            raise SystemExit(f"Could not read URL list: {exc}") from exc
    if not urls and not args.file and not sys.stdin.isatty():
        urls.extend(read_url_lines(sys.stdin))
    return urls

def print_result(raw: str, result: URLResult, verbose: bool) -> None:
    """Print one result in the default text format."""

    print(f"\n{ascii_safe(raw)}")
    print(f"  Score: {result.score}")
    print(f"  Verdict: {result.verdict}")
    print(f"  Result: {result.label}")
    if result.reasons:
        for reason in result.reasons:
            print(f"  - {reason}")
    else:
        print("  - no signals fired")
    if verbose:
        print("  Signals:")
        for outcome in result.outcomes:
            mark = "+" if outcome.fired else "-"
            points = f" (+{outcome.points})" if outcome.fired else ""
            print(f"    [{mark}] {outcome.title}{points}: {outcome.detail}")

def json_record(
    raw: str,
    result: URLResult | None,
    error: str | None,
    verbose: bool,
) -> dict[str, Any]:
    """Turn one result into a JSON-ready dictionary."""

    if result is None:
        return {"url": raw, "error": error}
    payload: dict[str, Any] = {
        "url": result.url,
        "score": result.score,
        "verdict": result.verdict,
        "label": result.label,
        "reasons": list(result.reasons),
        "findings": [
            {"name": outcome.name, "points": outcome.points, "reason": outcome.detail}
            for outcome in result.findings
        ],
    }
    if verbose:
        payload["signals"] = [
            {
                "name": outcome.name,
                "title": outcome.title,
                "fired": outcome.fired,
                "points": outcome.points,
                "detail": outcome.detail,
            }
            for outcome in result.outcomes
        ]
    return payload

def main() -> None:
    """Score URLs from the command line, a file, or standard input."""

    parser = argparse.ArgumentParser(
        description="Score URLs using transparent phishing heuristics."
    )
    parser.add_argument("urls", nargs="*", help="URLs to score")
    parser.add_argument(
        "-f", "--file", help="read URLs from FILE, one per line ('-' for stdin)"
    )
    parser.add_argument("--json", action="store_true", help="print results as JSON")
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="explain every signal, whether it fired or not",
    )
    args = parser.parse_args()

    urls = collect_urls(args)
    if not urls:
        parser.error("provide at least one URL, a --file, or pipe URLs on stdin")

    records: list[tuple[str, URLResult | None, str | None]] = []
    for raw in urls:
        try:
            result = score_url(raw)
        except ValueError as exc:
            records.append((raw, None, str(exc)))
        else:
            records.append((raw, result, None))

    summary = {
        "total": len(records),
        "scored": sum(1 for _, result, _ in records if result is not None),
        "low": 0,
        "medium": 0,
        "high": 0,
    }
    for _, result, _ in records:
        if result is not None:
            summary[result.verdict] += 1

    if args.json:
        payload = {
            "results": [
                json_record(raw, result, error, args.verbose)
                for raw, result, error in records
            ],
            "summary": summary,
        }
        print(json.dumps(payload, indent=2))
    else:
        for raw, result, error in records:
            if error is not None:
                print(f"Invalid URL {raw!r}: {error}", file=sys.stderr)
            else:
                assert result is not None
                print_result(raw, result, verbose=args.verbose)

    if any(error is not None for _, _, error in records):
        raise SystemExit(1)

if __name__ == "__main__":
    main()
