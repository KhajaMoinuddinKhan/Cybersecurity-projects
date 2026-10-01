"""Passive checks for public websites."""
from __future__ import annotations

import ipaddress
import socket
import ssl
from http.client import HTTPConnection, HTTPSConnection
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPHandler, HTTPSHandler, HTTPRedirectHandler, ProxyHandler, Request, build_opener


SECURITY_HEADERS = {
    "Content-Security-Policy": "Content Security Policy",
    "Strict-Transport-Security": "HSTS",
    "X-Content-Type-Options": "MIME sniffing protection",
    "X-Frame-Options": "Clickjacking protection",
    "Referrer-Policy": "Referrer policy",
    "Permissions-Policy": "Permissions policy",
}


def _finding(severity: str, category: str, message: str) -> dict[str, str]:
    return {"severity": severity, "category": category, "message": message}


def normalise_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("Enter a website address")
    return value if "://" in value else f"https://{value}"


def _public_ips(host: str, port: int) -> list[str]:
    try:
        literal = ipaddress.ip_address(host)
        addresses = [str(literal)]
    except ValueError:
        try:
            addresses = sorted(
                {
                    item[4][0]
                    for item in socket.getaddrinfo(
                        host,
                        port,
                        type=socket.SOCK_STREAM,
                        proto=socket.IPPROTO_TCP,
                    )
                }
            )
        except socket.gaierror as exc:
            raise ValueError(f"Could not resolve {host}") from exc

    if not addresses:
        raise ValueError(f"Could not resolve {host}")

    for address in addresses:
        if not ipaddress.ip_address(address).is_global:
            raise ValueError("Only public internet websites are allowed")

    return addresses


def validate_public_url(value: str) -> tuple[str, list[str]]:
    url = normalise_url(value)
    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http:// and https:// URLs are supported")
    if not parsed.hostname:
        raise ValueError("The URL needs a hostname")

    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing credentials are not supported")

    port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
    if port not in {80, 443}:
        raise ValueError("This quick check only uses ports 80 and 443")

    addresses = _public_ips(parsed.hostname, port)
    return url, addresses


def _public_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
    """Resolve once, validate all answers, then connect to a vetted IP address."""
    host, port = address
    addresses = _public_ips(host, port)
    last_error = None
    for ip in addresses:
        try:
            return socket.create_connection((ip, port), timeout, source_address)
        except OSError as exc:
            last_error = exc
    raise OSError(f"Could not connect to {host}: {last_error}")


class PublicHTTPConnection(HTTPConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = _public_connection


class PublicHTTPSConnection(HTTPSConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = _public_connection


class PublicHTTPHandler(HTTPHandler):
    def http_open(self, request):
        return self.do_open(PublicHTTPConnection, request)


class PublicHTTPSHandler(HTTPSHandler):
    def https_open(self, request):
        return self.do_open(PublicHTTPSConnection, request, context=self._context)


class PublicRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        checked_url = urljoin(req.full_url, newurl)
        validate_public_url(checked_url)
        return super().redirect_request(req, fp, code, msg, headers, checked_url)


def analyse_headers(headers: dict[str, str], is_https: bool) -> tuple[dict[str, bool], list[dict[str, str]], int]:
    present = {name.lower(): value for name, value in headers.items()}
    checks: dict[str, bool] = {}
    findings: list[dict[str, str]] = []
    score = 100

    for header, label in SECURITY_HEADERS.items():
        exists = bool(present.get(header.lower(), "").strip())
        checks[header] = exists
        if exists:
            continue
        if header == "Strict-Transport-Security" and not is_https:
            continue

        severity = "Medium" if header in {"Content-Security-Policy", "Strict-Transport-Security"} else "Low"
        score -= 12 if severity == "Medium" else 6
        findings.append(_finding(severity, "Security Header", f"Missing {label} header"))

    if not is_https:
        score -= 30
        findings.insert(0, _finding("High", "Transport Security", "The page is not using HTTPS"))

    server = present.get("server")
    if server:
        findings.append(
            _finding("Info", "Information Exposure", f"Server header is exposed: {server}")
        )

    return checks, findings, max(score, 0)


def inspect_tls(url: str, timeout: float = 5.0) -> dict[str, Any] | None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return None

    host = parsed.hostname
    port = parsed.port or 443
    addresses = _public_ips(host, port)
    context = ssl.create_default_context()

    with socket.create_connection((addresses[0], port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            cert = tls.getpeercert()
            cipher = tls.cipher()
            expires_text = cert.get("notAfter")
            expires = None
            days_left = None

            if expires_text:
                expires_dt = datetime.fromtimestamp(ssl.cert_time_to_seconds(expires_text), timezone.utc)
                expires = expires_dt.isoformat()
                days_left = (expires_dt - datetime.now(timezone.utc)).days

            return {
                "version": tls.version(),
                "cipher": cipher[0] if cipher else None,
                "expires": expires,
                "days_left": days_left,
            }


def inspect_website(value: str, timeout: float = 7.0) -> dict[str, Any]:
    url, _ = validate_public_url(value)
    opener = build_opener(ProxyHandler({}), PublicHTTPHandler(), PublicHTTPSHandler(), PublicRedirectHandler())
    response = None
    last_error: Exception | None = None

    for method in ("HEAD", "GET"):
        request = Request(
            url,
            method=method,
            headers={
                "User-Agent": "PurpleTeamDetectionLab/1.0",
                "Accept": "text/html,*/*;q=0.8",
            },
        )
        try:
            response = opener.open(request, timeout=timeout)
            break
        except HTTPError as exc:
            if exc.code == 405 and method == "HEAD":
                last_error = exc
                exc.close()
                continue
            response = exc
            break
        except URLError as exc:
            last_error = exc
            break

    if response is None:
        raise ValueError(f"Website request failed: {last_error}")

    try:
        final_url = response.geturl()
        validate_public_url(final_url)
        status = int(getattr(response, "status", getattr(response, "code", 0)))
        headers = {key: value for key, value in response.headers.items()}
    finally:
        response.close()

    is_https = urlparse(final_url).scheme == "https"
    checks, findings, score = analyse_headers(headers, is_https)

    tls: dict[str, Any] | None = None
    if is_https:
        try:
            tls = inspect_tls(final_url, timeout)
            if tls and isinstance(tls.get("days_left"), int):
                days_left = int(tls["days_left"])
                if days_left < 0:
                    score = max(score - 35, 0)
                    findings.insert(
                        0,
                        _finding("High", "TLS Certificate", "TLS certificate is expired"),
                    )
                elif days_left < 14:
                    score = max(score - 15, 0)
                    findings.append(
                        _finding(
                            "Medium",
                            "TLS Certificate",
                            f"TLS certificate expires in {days_left} days",
                        )
                    )
        except (OSError, ssl.SSLError, ValueError) as exc:
            score = max(score - 15, 0)
            findings.append(
                _finding("Medium", "TLS Certificate", f"TLS inspection failed: {exc}")
            )

    return {
        "requested_url": url,
        "final_url": final_url,
        "status": status,
        "https": is_https,
        "score": score,
        "headers": checks,
        "findings": findings,
        "tls": tls,
        "note": "Alerts above come from passive header and TLS checks, not exploit testing.",
    }
