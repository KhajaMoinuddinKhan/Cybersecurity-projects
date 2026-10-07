"""Reconnaissance and fingerprinting, behind the scope engine.

Every function here that opens a socket asks `Scope.authorize` first and returns
without one if the answer is no. That is the only reason this module takes a scope
at all: the check is not a courtesy at the top of a run, it is in front of every
connection, so there is no code path that reaches a target without passing it.

What is measured comes from what the target says. The service name is read from the
banner the target sends and the headers it returns, not from a table of port
numbers -- a table would be this project's opinion about what runs on 8080, and
the point of fingerprinting is to find out.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .scope import Scope

__all__ = ["Finding", "Service", "probe_port", "scan", "fetch", "Evidence"]

DEFAULT_TIMEOUT = 3.0


class Evidence:
    """What the target actually said, kept verbatim.

    A finding without evidence is an assertion. Everything the report shows about
    a target is something the target returned, stored as it arrived, so a reader
    can see the difference between what was observed and what was concluded.
    """

    def __init__(self):
        self.items: list[dict] = []

    def add(self, kind: str, detail: str, value: str = "") -> None:
        self.items.append({"kind": kind, "detail": detail, "value": value[:2000]})

    def as_list(self) -> list[dict]:
        return list(self.items)


@dataclass
class Service:
    host: str
    port: int
    open: bool = False
    banner: str = ""
    product: str = ""
    version: str = ""
    tls: dict = field(default_factory=dict)
    http: dict = field(default_factory=dict)
    error: str = ""

    @property
    def name(self) -> str:
        if self.product:
            return (self.product + (" " + self.version if self.version else "")).strip()
        return "unknown"


@dataclass
class Finding:
    """One thing worth reporting, with the evidence for it."""
    id: str
    title: str
    severity: str
    host: str
    port: int
    detail: str
    evidence: list[dict] = field(default_factory=list)
    cves: list[dict] = field(default_factory=list)
    remediation: str = ""
    business_impact: str = ""
    base_score: float | None = None

    def as_dict(self) -> dict:
        return {
            "id": self.id, "title": self.title, "severity": self.severity,
            "host": self.host, "port": self.port, "detail": self.detail,
            "evidence": self.evidence, "cves": self.cves,
            "remediation": self.remediation, "business_impact": self.business_impact,
            "base_score": self.base_score,
        }


def probe_port(scope: Scope, host: str, port: int, timeout: float = DEFAULT_TIMEOUT,
               at: datetime | None = None) -> Service:
    """Open one connection, if the engagement permits it.

    Returns a Service with `open` False and the scope's reason in `error` when the
    engagement refuses, so a caller can tell "the engagement said no" apart from
    "the port was shut" -- which are different things and belong differently in a
    report.
    """
    decision = scope.authorize(host, port, "connect", at=at)
    if not decision.allowed:
        return Service(host=host, port=port, error="refused by scope: " + decision.reason)

    service = Service(host=host, port=port)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            service.open = True
            sock.settimeout(timeout)
            try:
                service.banner = sock.recv(512).decode("utf-8", "replace").strip()
            except (socket.timeout, OSError):
                service.banner = ""
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        service.error = type(exc).__name__
    return service


def fetch(scope: Scope, host: str, port: int, path: str = "/", scheme: str = "http",
          timeout: float = DEFAULT_TIMEOUT, at: datetime | None = None,
          headers: dict | None = None) -> dict:
    """One HTTP request, if the engagement permits it.

    Returns a dict rather than raising, so a refused or failed request is recorded
    and the engagement carries on. The `refused` key is what separates a scope
    refusal from a target that did not answer.
    """
    decision = scope.authorize(host, port, "connect", at=at)
    if not decision.allowed:
        return {"ok": False, "refused": True, "reason": decision.reason, "path": path}

    url = "%s://%s:%d%s" % (scheme, host, port, path)
    request = Request(url, headers={"User-Agent": "scoped-assessment/1.0", **(headers or {})})
    try:
        context = None
        if scheme == "https":
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        with urlopen(request, timeout=timeout, context=context) as response:
            body = response.read(20000).decode("utf-8", "replace")
            return {"ok": True, "refused": False, "url": url, "status": response.status,
                    "headers": {k.lower(): v for k, v in response.headers.items()}, "body": body}
    except HTTPError as exc:
        return {"ok": False, "refused": False, "url": url, "status": exc.code,
                "headers": {k.lower(): v for k, v in (exc.headers or {}).items()},
                "body": exc.read(20000).decode("utf-8", "replace") if exc.fp else ""}
    except (URLError, OSError, ssl.SSLError) as exc:
        return {"ok": False, "refused": False, "url": url, "error": type(exc).__name__}


def fingerprint_http(scope: Scope, host: str, port: int, scheme: str = "http",
                     at: datetime | None = None) -> dict:
    """What the target says about itself in its headers and its landing page."""
    response = fetch(scope, host, port, "/", scheme=scheme, at=at)
    if response.get("refused"):
        return {"refused": True, "reason": response["reason"]}
    if not response.get("headers"):
        return {"error": response.get("error") or "no response"}

    headers = response["headers"]
    server = headers.get("server", "")
    product = version = ""
    if server:
        parts = server.split()
        product = parts[0]
        version = parts[1] if len(parts) > 1 else ""
    return {
        "status": response.get("status"),
        "server": server,
        "product": product,
        "version": version,
        "powered_by": headers.get("x-powered-by", ""),
        "headers": {k: v for k, v in headers.items() if k in
                    ("server", "x-powered-by", "x-aspnet-version", "via")},
        "body_sample": (response.get("body") or "")[:400],
    }


def fingerprint_tls(scope: Scope, host: str, port: int, at: datetime | None = None) -> dict:
    """What the endpoint will actually negotiate, from the handshake."""
    decision = scope.authorize(host, port, "connect", at=at)
    if not decision.allowed:
        return {"refused": True, "reason": decision.reason}
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                cipher = tls.cipher()
                certificate = tls.getpeercert()
                return {
                    "protocol": tls.version(),
                    "cipher": cipher[0] if cipher else "",
                    "bits": cipher[2] if cipher else None,
                    "subject": dict(x[0] for x in (certificate or {}).get("subject", ())),
                    "issuer": dict(x[0] for x in (certificate or {}).get("issuer", ())),
                }
    except (ssl.SSLError, OSError) as exc:
        return {"error": type(exc).__name__}


def scan(scope: Scope, host: str, ports, at: datetime | None = None,
         timeout: float = DEFAULT_TIMEOUT) -> list[Service]:
    """Probe every port the engagement permits, and record the refusals.

    A port the engagement does not list is not skipped silently: it comes back with
    the scope's reason, so the report can say the tool declined rather than imply
    the port was shut.
    """
    out = []
    for port in ports:
        service = probe_port(scope, host, port, timeout=timeout, at=at)
        if service.open and port in (80, 8080, 8000, 8099):
            service.http = fingerprint_http(scope, host, port, at=at)
            service.product = service.http.get("product", "") or service.product
            service.version = service.http.get("version", "") or service.version
        out.append(service)
    return out
