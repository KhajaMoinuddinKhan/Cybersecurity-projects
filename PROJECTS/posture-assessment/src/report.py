"""The report: the register, the coverage, and the evidence behind each entry.

Two formats from one structure, as with the other tools in this repository, and the
HTML is a single self-contained page -- a document about an organisation's security
posture should not make a request to anybody when it is opened.

The report leads with the coverage table rather than the findings, because the first
question an auditor asks is what was checked and the second is what was found. A
report that opens with a finding count has answered the second question and left the
first one implicit, which is how a scan of three files becomes a claim about an
estate.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone

__all__ = ["build", "to_markdown", "to_html"]

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def build(policy, entries, summary, generated_at=None, sources=None) -> dict:
    return {
        "organisation": policy.organisation,
        "generated_at": (generated_at or datetime.now(timezone.utc)).isoformat(timespec="seconds"),
        "policy": {"source": policy.source, "version": policy.version,
                   "controls": len(policy.controls),
                   "environments": list(policy.environments)},
        "sources": sources or [],
        "register": [entry.as_dict() for entry in entries],
        "summary": summary,
    }


def _counts_line(counts: dict, order) -> str:
    parts = ["%d %s" % (counts[name], name) for name in order if counts.get(name)]
    return ", ".join(parts) if parts else "none"


def to_markdown(document: dict) -> str:
    summary = document["summary"]
    policy = document["policy"]
    lines = ["# Posture assessment: %s" % document["organisation"], ""]
    lines.append("Generated %s against policy version %s."
                 % (document["generated_at"], policy["version"]))
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("%d risk register entr%s across %d environment%s, from a policy of %d "
                 "controls."
                 % (summary["total"], "y" if summary["total"] == 1 else "ies",
                    len(summary["environments_assessed"]),
                    "" if len(summary["environments_assessed"]) == 1 else "s",
                    summary["controls_total"]))
    lines.append("")
    lines.append("| Severity | Entries |")
    lines.append("| --- | --- |")
    for name in _SEVERITY_ORDER:
        lines.append("| %s | %d |" % (name.title(), summary["by_severity"].get(name, 0)))
    lines.append("")

    lines.append("## What was checked")
    lines.append("")
    lines.append("The policy defines %d controls. Each names the environments it applies "
                 "to, and each is checked against every one of them from the same "
                 "definition." % summary["controls_total"])
    lines.append("")
    lines.append("| Environment | Controls checked | Entries raised |")
    lines.append("| --- | --- | --- |")
    for environment, count in summary["coverage"].items():
        lines.append("| %s | %d | %d |" % (environment, count,
                                           summary["by_environment"].get(environment, 0)))
    lines.append("")

    if document.get("sources"):
        lines.append("Artifacts and services assessed:")
        lines.append("")
        for source in document["sources"]:
            lines.append("- `%s` (%s)" % (source.get("target", ""), source.get("kind", "")))
        lines.append("")

    lines.append("## Risk register")
    lines.append("")
    if not document["register"]:
        lines.append("No entries. Every control the policy defines was satisfied by every "
                     "artifact assessed.")
        lines.append("")
    else:
        lines.append("| Ref | Rating | Environment | Control | ISO 27001 | NIST CSF | Owner | "
                     "Treatment |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
        for entry in document["register"]:
            lines.append("| %s | %s | %s | `%s` | %s | %s | %s | %s |" % (
                entry["reference"], entry["rating"], entry["environment"],
                entry["control"], entry["iso27001"] or "-", entry["nist_csf"] or "-",
                entry["owner"] or "-", entry["treatment"]))
        lines.append("")

    lines.append("### Mapping summary")
    lines.append("")
    lines.append("| ISO/IEC 27001:2022 Annex A | Entries |")
    lines.append("| --- | --- |")
    for control, count in sorted(summary["by_iso27001"].items()):
        lines.append("| %s | %d |" % (control, count))
    lines.append("")
    lines.append("| NIST CSF 2.0 function | Entries |")
    lines.append("| --- | --- |")
    for function, count in sorted(summary["by_nist_csf"].items()):
        lines.append("| %s | %d |" % (function, count))
    lines.append("")

    if summary.get("controls_satisfied"):
        lines.append("## Controls nothing violated")
        lines.append("")
        lines.append("Reported so that a satisfied control is distinguishable from one that "
                     "was never checked: %s." % ", ".join(
                         "`%s`" % c for c in summary["controls_satisfied"]))
        lines.append("")

    lines.append("## Findings")
    lines.append("")
    for entry in document["register"]:
        lines.append("### %s. %s" % (entry["reference"], entry["control_title"]))
        lines.append("")
        lines.append("**Rating:** %s  " % entry["rating"])
        lines.append("**Environment:** %s  " % entry["environment"])
        lines.append("**Where:** `%s`" % (entry["location"] or entry["target"]))
        lines.append("")
        if entry["cis"]:
            lines.append("**Standard:** %s  " % entry["cis"])
        lines.append("**ISO/IEC 27001:2022:** %s  " % (entry["iso27001"] or "-"))
        lines.append("**NIST CSF 2.0:** %s  " % (entry["nist_csf"] or "-"))
        lines.append("**Owner:** %s  " % (entry["owner"] or "-"))
        lines.append("**Treatment:** %s" % entry["treatment"])
        lines.append("")
        lines.append(entry["detail"])
        lines.append("")
        if entry["evidence"]:
            lines.append("**Evidence**")
            lines.append("")
            for item in entry["evidence"]:
                lines.append("- %s: %s" % (item["kind"], item["detail"]))
                if item.get("value"):
                    lines.append("")
                    lines.append("  ```")
                    for line in str(item["value"]).splitlines():
                        lines.append("  " + line)
                    lines.append("  ```")
            lines.append("")
    return "\n".join(lines)


def to_html(document: dict) -> str:
    escape = html.escape
    summary = document["summary"]
    parts = ["<!doctype html>", '<html lang="en"><head><meta charset="utf-8">',
             "<title>Posture assessment: %s</title>" % escape(document["organisation"]),
             "<style>",
             ":root{color-scheme:dark}",
             "body{font:15px/1.55 system-ui,sans-serif;margin:0;padding:2.5rem;"
             "background:#000;color:#f2f0e9;max-width:70rem}",
             "h1{border-bottom:1px solid #333;padding-bottom:.5rem}",
             "h2{margin-top:2.5rem;color:#ff4d12}h3{margin-top:2rem}",
             "code,pre{font-family:ui-monospace,monospace;font-size:.86em}",
             "pre{background:#111;border:1px solid #2a2a2a;padding:.75rem;overflow-x:auto}",
             "table{border-collapse:collapse;width:100%;margin:.75rem 0}",
             "th,td{border:1px solid #2a2a2a;padding:.4rem .6rem;text-align:left}",
             "th{background:#141414}",
             ".r{display:inline-block;padding:.1rem .5rem;border-radius:3px;font-weight:600}",
             ".Critical{background:#ff3b30;color:#000}.High{background:#ff6b35;color:#000}",
             ".Medium{background:#ffb020;color:#000}.Low{background:#3ddc84;color:#000}",
             ".Informational{background:#666;color:#fff}",
             "</style></head><body>"]
    parts.append("<h1>Posture assessment: %s</h1>" % escape(document["organisation"]))
    parts.append("<p>Generated %s against policy version %s.</p>"
                 % (escape(document["generated_at"]), document["policy"]["version"]))

    parts.append("<h2>Summary</h2><p>%d risk register entries across %d environments, from a "
                 "policy of %d controls.</p>"
                 % (summary["total"], len(summary["environments_assessed"]),
                    summary["controls_total"]))
    parts.append("<table><tr><th>Severity</th><th>Entries</th></tr>")
    for name in _SEVERITY_ORDER:
        parts.append("<tr><td>%s</td><td>%d</td></tr>"
                     % (name.title(), summary["by_severity"].get(name, 0)))
    parts.append("</table>")

    parts.append("<h2>What was checked</h2>")
    parts.append("<table><tr><th>Environment</th><th>Controls checked</th>"
                 "<th>Entries raised</th></tr>")
    for environment, count in summary["coverage"].items():
        parts.append("<tr><td>%s</td><td>%d</td><td>%d</td></tr>"
                     % (escape(environment), count,
                        summary["by_environment"].get(environment, 0)))
    parts.append("</table>")

    parts.append("<h2>Risk register</h2>")
    if not document["register"]:
        parts.append("<p>No entries.</p>")
    else:
        parts.append("<table><tr><th>Ref</th><th>Rating</th><th>Environment</th>"
                     "<th>Control</th><th>ISO 27001</th><th>NIST CSF</th><th>Owner</th></tr>")
        for entry in document["register"]:
            parts.append("<tr><td>%s</td><td><span class='r %s'>%s</span></td><td>%s</td>"
                         "<td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td></tr>"
                         % (escape(entry["reference"]), escape(entry["rating"]),
                            escape(entry["rating"]), escape(entry["environment"]),
                            escape(entry["control"]), escape(entry["iso27001"] or "-"),
                            escape(entry["nist_csf"] or "-"), escape(entry["owner"] or "-")))
        parts.append("</table>")

    parts.append("<h3>Mapping summary</h3>")
    parts.append("<table><tr><th>ISO/IEC 27001:2022 Annex A</th><th>Entries</th></tr>")
    for control, count in sorted(summary["by_iso27001"].items()):
        parts.append("<tr><td>%s</td><td>%d</td></tr>" % (escape(control), count))
    parts.append("</table>")
    parts.append("<table><tr><th>NIST CSF 2.0 function</th><th>Entries</th></tr>")
    for function, count in sorted(summary["by_nist_csf"].items()):
        parts.append("<tr><td>%s</td><td>%d</td></tr>" % (escape(function), count))
    parts.append("</table>")

    parts.append("<h2>Findings</h2>")
    for entry in document["register"]:
        parts.append("<h3>%s. %s</h3>" % (escape(entry["reference"]),
                                          escape(entry["control_title"])))
        parts.append("<p><span class='r %s'>%s</span> &middot; %s &middot; <code>%s</code>"
                     " &middot; owner %s</p>"
                     % (escape(entry["rating"]), escape(entry["rating"]),
                        escape(entry["environment"]),
                        escape(entry["location"] or entry["target"]),
                        escape(entry["owner"] or "-")))
        parts.append("<p>%s</p>" % escape(entry["detail"]))
        if entry["evidence"]:
            for item in entry["evidence"]:
                parts.append("<p><strong>%s:</strong> %s</p>"
                             % (escape(item["kind"]), escape(item["detail"])))
                if item.get("value"):
                    parts.append("<pre>%s</pre>" % escape(str(item["value"])[:1500]))
    parts.append("</body></html>")
    return "\n".join(parts)
