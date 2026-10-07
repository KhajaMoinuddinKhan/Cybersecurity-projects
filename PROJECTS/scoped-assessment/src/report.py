"""The report, which is the deliverable.

An assessment that produces a list of findings is not an assessment; it is a
scanner's output. What a client reads is a document that says what was in scope,
what was done, what was found, how bad it is, what it means to the business and
what to do about it -- in that order, because the reader is a person deciding what
to fix first and not an engineer replaying a session.

Two formats, from one structure. Markdown for the repository, HTML for reading.
Both carry the evidence verbatim, and both carry the refusals: what the tool
declined to do is part of the record of the engagement, and a report that showed
only what succeeded would be a report of a different engagement.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone

from .scan import Finding

__all__ = ["build", "to_markdown", "to_html", "SEVERITY_ORDER"]

SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Info")


def _rank(finding: Finding) -> int:
    try:
        return SEVERITY_ORDER.index(finding.severity)
    except ValueError:
        return len(SEVERITY_ORDER)


def build(scope, services, findings, refusals, generated_at=None) -> dict:
    """The one structure both formats are rendered from."""
    ordered = sorted(findings, key=lambda f: (_rank(f), -(f.base_score or 0), f.title))
    counts = {name: sum(1 for f in ordered if f.severity == name) for name in SEVERITY_ORDER}
    return {
        "engagement": scope.engagement,
        "generated_at": (generated_at or datetime.now(timezone.utc)).isoformat(timespec="seconds"),
        "scope": scope.as_dict(),
        "hosts": scope.hosts(),
        "services": [
            {"host": s.host, "port": s.port, "open": s.open, "name": s.name,
             "banner": s.banner[:200], "error": s.error, "http": s.http, "tls": s.tls}
            for s in services
        ],
        "findings": [f.as_dict() for f in ordered],
        "counts": counts,
        "total": len(ordered),
        "refusals": [r for r in refusals],
        "refusal_count": len(refusals),
    }


def _headline(document: dict) -> str:
    counts = document["counts"]
    parts = ["%d %s" % (counts[name], name.lower()) for name in SEVERITY_ORDER if counts[name]]
    if not parts:
        return "No findings were recorded."
    return "%d finding%s: %s." % (document["total"],
                                  "" if document["total"] == 1 else "s", ", ".join(parts))


def to_markdown(document: dict) -> str:
    lines = ["# Security assessment: %s" % document["engagement"], ""]
    lines.append("Generated %s." % document["generated_at"])
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(_headline(document))
    lines.append("")
    lines.append("| Severity | Findings |")
    lines.append("| --- | --- |")
    for name in SEVERITY_ORDER:
        lines.append("| %s | %d |" % (name, document["counts"][name]))
    lines.append("")

    lines.append("## Scope")
    lines.append("")
    lines.append("The engagement named %d target%s:" % (
        len(document["scope"]["targets"]), "" if len(document["scope"]["targets"]) == 1 else "s"))
    lines.append("")
    for target in document["scope"]["targets"]:
        ports = target.get("ports", "all")
        lines.append("- `%s` ports %s" % (target.get("host") or target.get("cidr"), ports))
    window = document["scope"]
    if window.get("window_start") or window.get("window_end"):
        lines.append("")
        lines.append("The window ran from %s to %s."
                     % (window.get("window_start") or "unset", window.get("window_end") or "unset"))
    lines.append("")
    lines.append("Actions permitted: %s." % ", ".join(document["scope"]["allowed_actions"]))
    lines.append("")

    lines.append("## Services observed")
    lines.append("")
    lines.append("| Host | Port | State | Service |")
    lines.append("| --- | --- | --- | --- |")
    for service in document["services"]:
        state = "open" if service["open"] else (service["error"] or "closed")
        lines.append("| %s | %d | %s | %s |" % (service["host"], service["port"], state,
                                                service["name"] or "-"))
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    if not document["findings"]:
        lines.append("Nothing was found within the permitted scope.")
        lines.append("")
    for index, finding in enumerate(document["findings"], 1):
        lines.append("### %d. %s" % (index, finding["title"]))
        lines.append("")
        lines.append("**Severity:** %s%s  " % (
            finding["severity"],
            " (CVSS %.1f)" % finding["base_score"] if finding["base_score"] else ""))
        lines.append("**Where:** %s port %d  " % (finding["host"], finding["port"]))
        lines.append("**Identifier:** `%s`" % finding["id"])
        lines.append("")
        lines.append(finding["detail"])
        lines.append("")
        if finding.get("cves"):
            lines.append("**Related CVEs**")
            lines.append("")
            for cve in finding["cves"]:
                agree = "" if cve.get("agrees") else " (NVD publishes %s)" % cve.get("published_score")
                lines.append("- `%s` %s -- %s%s" % (
                    cve["cve"], cve.get("computed_severity") or "",
                    (cve.get("summary") or "")[:180], agree))
            lines.append("")
        lines.append("**Evidence**")
        lines.append("")
        for item in finding["evidence"]:
            lines.append("- %s: %s" % (item["kind"], item["detail"]))
            if item.get("value"):
                lines.append("")
                lines.append("  ```")
                for line in str(item["value"]).splitlines():
                    lines.append("  " + line)
                lines.append("  ```")
        lines.append("")
        if finding.get("business_impact"):
            lines.append("**Business impact.** %s" % finding["business_impact"])
            lines.append("")
        if finding.get("remediation"):
            lines.append("**Remediation.** %s" % finding["remediation"])
            lines.append("")

    lines.append("## What the tool declined to do")
    lines.append("")
    if not document["refusal_count"]:
        lines.append("Nothing was refused: every action attempted was within the engagement.")
    else:
        lines.append("%d action%s refused by the scope engine, recorded as they happened:"
                     % (document["refusal_count"], "" if document["refusal_count"] == 1 else "s"))
        lines.append("")
        lines.append("| At | Host | Port | Action | Reason |")
        lines.append("| --- | --- | --- | --- | --- |")
        for refusal in document["refusals"]:
            lines.append("| %s | %s | %s | %s | %s |" % (
                refusal.get("at", ""), refusal.get("host", ""), refusal.get("port", ""),
                refusal.get("action", ""), refusal.get("reason", "")))
    lines.append("")
    return "\n".join(lines)


def to_html(document: dict) -> str:
    """The same document, as one self-contained page.

    Self-contained deliberately: no stylesheet is fetched, no font is downloaded
    and no script runs. A report about a client's security posture should not make
    a request to anybody when it is opened, and a reader should be able to keep it
    as a single file.
    """
    escape = html.escape
    parts = ["<!doctype html>", '<html lang="en"><head><meta charset="utf-8">',
             "<title>Security assessment: %s</title>" % escape(document["engagement"]),
             "<style>",
             ":root{color-scheme:dark}",
             "body{font:15px/1.55 system-ui,sans-serif;margin:0;padding:2.5rem;"
             "background:#000;color:#f2f0e9;max-width:64rem}",
             "h1,h2,h3{line-height:1.25}",
             "h1{border-bottom:1px solid #333;padding-bottom:.5rem}",
             "h2{margin-top:2.5rem;color:#ff4d12}",
             "code,pre{font-family:ui-monospace,monospace;font-size:.86em}",
             "pre{background:#111;border:1px solid #2a2a2a;padding:.75rem;overflow-x:auto}",
             "table{border-collapse:collapse;width:100%;margin:.75rem 0}",
             "th,td{border:1px solid #2a2a2a;padding:.4rem .6rem;text-align:left}",
             "th{background:#141414}",
             ".sev{display:inline-block;padding:.1rem .5rem;border-radius:3px;font-weight:600}",
             ".Critical{background:#ff3b30;color:#000}.High{background:#ff6b35;color:#000}",
             ".Medium{background:#ffb020;color:#000}.Low{background:#3ddc84;color:#000}",
             ".Info{background:#666;color:#fff}",
             ".finding{border-left:3px solid #333;padding-left:1rem;margin:1.5rem 0}",
             "</style></head><body>"]
    parts.append("<h1>Security assessment: %s</h1>" % escape(document["engagement"]))
    parts.append("<p>Generated %s.</p>" % escape(document["generated_at"]))
    parts.append("<h2>Summary</h2><p>%s</p>" % escape(_headline(document)))
    parts.append("<table><tr><th>Severity</th><th>Findings</th></tr>")
    for name in SEVERITY_ORDER:
        parts.append("<tr><td><span class='sev %s'>%s</span></td><td>%d</td></tr>"
                     % (name, name, document["counts"][name]))
    parts.append("</table>")

    parts.append("<h2>Scope</h2><ul>")
    for target in document["scope"]["targets"]:
        parts.append("<li><code>%s</code> ports %s</li>"
                     % (escape(str(target.get("host") or target.get("cidr"))),
                        escape(str(target.get("ports", "all")))))
    parts.append("</ul>")
    parts.append("<p>Actions permitted: %s.</p>"
                 % escape(", ".join(document["scope"]["allowed_actions"])))

    parts.append("<h2>Services observed</h2><table><tr><th>Host</th><th>Port</th>"
                 "<th>State</th><th>Service</th></tr>")
    for service in document["services"]:
        state = "open" if service["open"] else (service["error"] or "closed")
        parts.append("<tr><td>%s</td><td>%d</td><td>%s</td><td>%s</td></tr>"
                     % (escape(service["host"]), service["port"], escape(state),
                        escape(service["name"] or "-")))
    parts.append("</table>")

    parts.append("<h2>Findings</h2>")
    if not document["findings"]:
        parts.append("<p>Nothing was found within the permitted scope.</p>")
    for index, finding in enumerate(document["findings"], 1):
        parts.append("<div class='finding'>")
        parts.append("<h3>%d. %s</h3>" % (index, escape(finding["title"])))
        score_text = " (CVSS %.1f)" % finding["base_score"] if finding["base_score"] else ""
        parts.append("<p><span class='sev %s'>%s</span>%s &middot; <code>%s</code> "
                     "&middot; %s:%d</p>"
                     % (escape(finding["severity"]), escape(finding["severity"]),
                        escape(score_text), escape(finding["id"]),
                        escape(finding["host"]), finding["port"]))
        parts.append("<p>%s</p>" % escape(finding["detail"]))
        if finding.get("cves"):
            parts.append("<ul>")
            for cve in finding["cves"]:
                parts.append("<li><code>%s</code> %s</li>" % (escape(cve["cve"]),
                                                              escape((cve.get("summary") or "")[:200])))
            parts.append("</ul>")
        for item in finding["evidence"]:
            parts.append("<p><strong>%s:</strong> %s</p>" % (escape(item["kind"]),
                                                             escape(item["detail"])))
            if item.get("value"):
                parts.append("<pre>%s</pre>" % escape(str(item["value"])[:2000]))
        if finding.get("business_impact"):
            parts.append("<p><strong>Business impact.</strong> %s</p>"
                         % escape(finding["business_impact"]))
        if finding.get("remediation"):
            parts.append("<p><strong>Remediation.</strong> %s</p>" % escape(finding["remediation"]))
        parts.append("</div>")

    parts.append("<h2>What the tool declined to do</h2>")
    if not document["refusal_count"]:
        parts.append("<p>Nothing was refused: every action attempted was within the engagement.</p>")
    else:
        parts.append("<p>%d action%s refused by the scope engine, recorded as they happened.</p>"
                     % (document["refusal_count"], "" if document["refusal_count"] == 1 else "s"))
        parts.append("<table><tr><th>At</th><th>Host</th><th>Port</th><th>Action</th>"
                     "<th>Reason</th></tr>")
        for refusal in document["refusals"]:
            parts.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                escape(str(refusal.get("at", ""))), escape(str(refusal.get("host", ""))),
                escape(str(refusal.get("port", ""))), escape(str(refusal.get("action", ""))),
                escape(str(refusal.get("reason", "")))))
        parts.append("</table>")
    parts.append("</body></html>")
    return "\n".join(parts)
