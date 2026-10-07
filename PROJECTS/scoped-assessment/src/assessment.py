"""The checks, each producing a finding with the evidence that justifies it.

A check here does three things and no more: it asks the target a question, it keeps
the answer, and it decides whether the answer is a finding. It does not guess, and
it does not describe what it did not see. Every finding carries the bytes the target
returned, so the report can show its work.

Exploitation stops at demonstration. The path traversal reads a file the lab placed
outside its document root and nothing else; there is no shell, no payload, no
attempt to go further. The framework is for assessing a system you own, and the
part that matters is the evidence and the write-up.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .scan import Evidence, Finding, fetch
from .scope import Scope

__all__ = ["assess_http", "CHECK_NAMES"]

CHECK_NAMES = ("version-disclosure", "reflected-input", "path-traversal")


def _now():
    return datetime.now(timezone.utc)


def assess_http(scope: Scope, host: str, port: int, scheme: str = "http",
                at: datetime | None = None) -> list[Finding]:
    """Run every HTTP check against one endpoint, returning what was found.

    A check whose request the engagement refuses produces no finding and says so in
    the audit log, which is the point of routing the request through the scope
    rather than around it.
    """
    at = at or _now()
    findings: list[Finding] = []

    landing = fetch(scope, host, port, "/", scheme=scheme, at=at)
    if landing.get("refused"):
        return findings
    headers = landing.get("headers") or {}

    # --- does the target name its own version? --------------------------
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    if server or powered:
        evidence = Evidence()
        evidence.add("header", "Server", server)
        if powered:
            evidence.add("header", "X-Powered-By", powered)
        versioned = len(server.split()) > 1 or "/" in server or powered
        findings.append(Finding(
            id="version-disclosure",
            title="The service names its own version",
            severity="Low" if versioned else "Info",
            host=host, port=port,
            detail=("The endpoint returns a product and version in its headers. That is "
                    "not a vulnerability on its own; it is what lets anyone choose which "
                    "vulnerabilities to try, without sending a single probing request."),
            evidence=evidence.as_list(),
            remediation=("Suppress or generalise the Server and X-Powered-By headers. "
                         "The version belongs in an inventory, not in a response."),
            business_impact=("An attacker can map the estate to known-vulnerable versions "
                             "before touching anything, which shortens the time between "
                             "choosing a target and succeeding against it."),
        ))

    # --- is a parameter reflected without being escaped? ------------------
    probe = "zq<\"'>zq"
    search = fetch(scope, host, port, "/search?q=" + probe, scheme=scheme, at=at)
    body = search.get("body") or ""
    if probe in body:
        evidence = Evidence()
        evidence.add("request", "GET /search?q=%s" % probe, "")
        evidence.add("response", "the probe came back unescaped in the page",
                     body[max(0, body.find(probe) - 60):body.find(probe) + len(probe) + 60])
        findings.append(Finding(
            id="reflected-input",
            title="A parameter is reflected into the page without escaping",
            severity="Medium",
            host=host, port=port,
            detail=("A value supplied in the query string is written into the response "
                    "verbatim, including its angle brackets and quotes. Reflected input "
                    "is the raw material of cross-site scripting; whether it is "
                    "exploitable depends on the surrounding page and the browser, which "
                    "this check does not attempt to decide."),
            evidence=evidence.as_list(),
            cves=[],
            remediation=("Encode output for the context it is written into, and prefer "
                         "templating that escapes by default. Do not filter the input as "
                         "a substitute for encoding the output."),
            business_impact=("A crafted link can run script in a victim's session in the "
                             "context of this site, which is how session tokens and "
                             "actions are taken over."),
        ))

    # --- does the file endpoint stay inside its root? ---------------------
    for name in ("../secret.txt", "..%2Fsecret.txt", "....//secret.txt"):
        attempt = fetch(scope, host, port, "/files?name=" + name, scheme=scheme, at=at)
        content = attempt.get("body") or ""
        if attempt.get("status") == 200 and "outside the document root" in content:
            evidence = Evidence()
            evidence.add("request", "GET /files?name=%s" % name, "")
            evidence.add("response", "the file outside the document root was returned",
                         content[:400])
            findings.append(Finding(
                id="path-traversal",
                title="The file endpoint can be walked out of its document root",
                severity="High",
                host=host, port=port,
                detail=("A file name supplied in the query string is joined to the document "
                        "root and read, with nothing confining the result to that root. A "
                        "sequence of parent references therefore reads files the service "
                        "was never meant to serve. The check stopped at the one file the "
                        "lab placed outside its root."),
                evidence=evidence.as_list(),
                remediation=("Resolve the requested path and verify the result is inside the "
                             "root before opening it, and serve files by identifier rather "
                             "than by name where the content is not public."),
                business_impact=("Any file the service account can read becomes readable "
                                 "remotely, which typically means configuration, keys and "
                                 "credentials rather than only content."),
            ))
            break

    return findings
