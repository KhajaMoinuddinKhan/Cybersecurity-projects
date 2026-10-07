"""The report: what is privileged, how it is reached, and what to fix.

Two formats from one structure, and the HTML is a single self-contained page -- a
document about a directory's attack surface should not make a request to anybody when
it is opened.

The order is deliberate. Crown jewels first, because they are the definition of the
problem and a reader has to agree with them before anything else is worth reading.
Then the routes, then what to fix. A report that opened with a list of paths would be
answering a question the reader has not yet agreed to.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone

__all__ = ["build", "to_markdown", "to_html"]


def build(graph, jewels, choke, cut, escalations=(), generated_at=None) -> dict:
    seeded = [jewel for jewel in jewels if not jewel.derived]
    derived = [jewel for jewel in jewels if jewel.derived]
    return {
        "generated_at": (generated_at or datetime.now(timezone.utc)).isoformat(timespec="seconds"),
        "source": graph.data.source,
        "forest": list(graph.data.domains),
        "objects": len(graph.data.nodes),
        "graph": graph.summary(),
        "counts": dict(graph.data.counts),
        "crown_jewels": {
            "total": len(jewels), "seeded": len(seeded), "derived": len(derived),
            "seeded_list": [j.as_dict(graph) for j in seeded],
            "derived_list": [j.as_dict(graph) for j in derived],
        },
        "choke_points": [point.as_dict() for point in choke["points"]],
        "choke_total": choke["total"],
        "cut": cut,
        "certificate_escalations": [e.as_dict() for e in escalations],
        "context": _context(graph),
    }


def _context(graph) -> dict:
    """What the graph holds but does not walk, and what it could not read."""
    by_kind = {}
    for edge in graph.edges:
        if not edge.traversable:
            by_kind[edge.kind] = by_kind.get(edge.kind, 0) + 1
    return {"non_traversable": by_kind,
            "unresolved": {sid: rights for sid, rights in graph.unknown_rights.items()}}


def _escalations_markdown(document: dict) -> list:
    """The certificate section, or nothing at all when there is nothing to say."""
    rows = document.get("certificate_escalations") or []
    if not rows:
        return []
    lines = ["## Certificate services", "",
             "An authority issues a certificate for whatever its templates permit, and a "
             "template that lets the requester choose the subject, or that carries an "
             "authentication purpose, is a route to any principal's identity. The "
             "conditions below are read from the template's own attributes, not from "
             "its name.", "",
             "| Template | Condition | Severity | Who can enroll | Why |",
             "| --- | --- | --- | --- | --- |"]
    for row in rows:
        enrollees = row.get("enrollees") or []
        who = ", ".join("`%s`" % e for e in enrollees[:3]) if enrollees else \
            "nobody outside the administrators"
        lines.append("| %s | %s | %s | %s | %s |" % (
            row["template"], ", ".join(row["conditions"]), row["severity"], who, row["note"]))
    return lines + [""]


def to_markdown(document: dict) -> str:
    crown = document["crown_jewels"]
    graph = document["graph"]
    lines = ["# Active Directory attack paths", ""]
    lines.append("Generated %s from %d collected object%s across %d domain%s."
                 % (document["generated_at"], document["objects"],
                    "" if document["objects"] == 1 else "s",
                    len(document["forest"]), "" if len(document["forest"]) == 1 else "s"))
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("The directory holds **%d objects** and **%d relationships**, of which "
                 "**%d can be walked** by an attacker. **%d objects are crown jewels**: "
                 "%d privileged on their own evidence and %d reached from those."
                 % (graph["nodes"], graph["edges"], graph["traversable"],
                    crown["total"], crown["seeded"], crown["derived"]))
    lines.append("")

    lines.append("## The forest")
    lines.append("")
    for domain in document["forest"]:
        lines.append("- `%s`" % domain)
    lines.append("")
    lines.append("Objects by type: %s." % ", ".join(
        "%s %d" % (kind, count) for kind, count in sorted(document["counts"].items())))
    lines.append("")

    lines.append("## Crown jewels")
    lines.append("")
    lines.append("An object is a crown jewel if controlling it yields control of the "
                 "domain. The seed set is derived from the well-known relative "
                 "identifiers, the directory's own adminCount attribute, replication "
                 "rights on a domain and domain controllers -- never from a group "
                 "name, so a renamed or localised privileged group is still found.")
    lines.append("")
    lines.append("### Privileged on their own evidence (%d)" % crown["seeded"])
    lines.append("")
    lines.append("| Type | Object | Why |")
    lines.append("| --- | --- | --- |")
    for jewel in crown["seeded_list"]:
        lines.append("| %s | `%s` | %s |" % (jewel["kind"], jewel["name"],
                                             "; ".join(jewel["reasons"])[:150]))
    lines.append("")

    lines.append("### Reached from those (%d)" % crown["derived"])
    lines.append("")
    if not crown["derived_list"]:
        lines.append("None: nothing outside the seed set can reach it.")
        lines.append("")
    else:
        lines.append("| Type | Object | Hops | Reaches |")
        lines.append("| --- | --- | --- | --- |")
        for jewel in crown["derived_list"]:
            lines.append("| %s | `%s` | %d | `%s` |" % (jewel["kind"], jewel["name"],
                                                         jewel["hops"], jewel["reaches"]))
        lines.append("")

    lines.extend(_escalations_markdown(document))

    lines.append("## The routes")
    lines.append("")
    lines.append("Each route below is a sequence an attacker can actually walk, one "
                 "step at a time. The shortest are shown first.")
    lines.append("")
    for jewel in crown["derived_list"][:25]:
        lines.append("### %s" % jewel["name"])
        lines.append("")
        lines.append("%d hop%s to `%s`." % (jewel["hops"],
                                            "" if jewel["hops"] == 1 else "s",
                                            jewel["reaches"]))
        lines.append("")
        lines.append("| Step | From | Right | To | What it grants |")
        lines.append("| --- | --- | --- | --- | --- |")
        for index, step in enumerate(jewel["steps"], 1):
            lines.append("| %d | `%s` | `%s` | `%s` | %s |"
                         % (index, step["from"], step["right"], step["to"],
                            (step["why"] or "")[:110]))
        lines.append("")

    lines.append("## What to fix")
    lines.append("")
    choke = document["choke_points"]
    if choke:
        lines.append("Each row is one object and how many routes lose their way to a "
                     "crown jewel if that object is fixed. Recomputed after each "
                     "removal rather than estimated, because routes are not "
                     "independent.")
        lines.append("")
        lines.append("| Type | Object | Routes cut | Of |")
        lines.append("| --- | --- | --- | --- |")
        for point in choke:
            lines.append("| %s | `%s` | %d | %d |" % (point["kind"], point["name"],
                                                      point["cuts"], point["attackers"]))
        lines.append("")

    cut = document["cut"]
    lines.append("### The smallest change")
    lines.append("")
    if cut.get("unbounded"):
        lines.append("**No set of intermediate objects disconnects these.** %s."
                     % cut["note"])
        lines.append("")
        if cut.get("direct"):
            lines.append("Reached in a single step, so the object itself has to be fixed:")
            lines.append("")
            lines.append("| From | Crown jewel |")
            lines.append("| --- | --- |")
            for item in cut["direct"]:
                lines.append("| `%s` | `%s` |" % (item["source"], item["sink"]))
            lines.append("")
    else:
        lines.append("Removing **%d object%s** disconnects every route, and %d is the "
                     "minimum: computed exactly with max-flow rather than approximated "
                     "greedily, and the flow value equals the cut size, which is what "
                     "makes it a proof rather than a suggestion."
                     % (cut["size"], "" if cut["size"] == 1 else "s", cut["size"]))
        lines.append("")
        lines.append("| Type | Object |")
        lines.append("| --- | --- |")
        for item in cut["cut"]:
            lines.append("| %s | `%s` |" % (item["kind"], item["name"]))
        lines.append("")

    context = document["context"]
    lines.append("## What this does not model")
    lines.append("")
    if context["non_traversable"]:
        lines.append("Relationships recorded but never walked, because neither grants "
                     "control of anything: %s. A trust permits authentication across it "
                     "and a container holding an object says nothing about who may "
                     "modify it. Treating either as an attack edge invents routes "
                     "nobody could take."
                     % ", ".join("%s (%d)" % (k, v)
                                 for k, v in sorted(context["non_traversable"].items())))
        lines.append("")
    if context["unresolved"]:
        lines.append("Rights found in the data that this does not know, and which were "
                     "therefore not turned into edges: %s. An unrecognised right is "
                     "reported rather than dropped, because treating an unknown right "
                     "as harmless is the same mistake as treating an unread rule as "
                     "clear." % ", ".join(sorted(
                         {r for rights in context["unresolved"].values() for r in rights})))
        lines.append("")
    unmodelled = document["graph"].get("unmodelled") or {}
    if unmodelled:
        lines.append("Fields the collector populated that this does not turn into a "
                     "route, named so that nothing is dropped in silence:")
        lines.append("")
        for field, detail in sorted(unmodelled.items()):
            lines.append("- **`%s`** -- %s. On: %s." % (
                field, detail["meaning"],
                ", ".join("`%s`" % o for o in detail["objects"][:3])))
        lines.append("")
    lines.append("Sessions are collected per machine and none were present in this "
                 "data, so no route here depends on one. Where they exist they are "
                 "walked in reverse -- compromising the machine yields whoever is "
                 "logged into it -- which is the direction that makes a session worth "
                 "finding.")
    lines.append("")
    return "\n".join(lines)


def to_html(document: dict) -> str:
    escape = html.escape
    crown = document["crown_jewels"]
    graph = document["graph"]
    cut = document["cut"]
    parts = ["<!doctype html>", '<html lang="en"><head><meta charset="utf-8">',
             "<title>Active Directory attack paths</title>", "<style>",
             ":root{color-scheme:dark}",
             "body{font:15px/1.55 system-ui,sans-serif;margin:0;padding:2.5rem;"
             "background:#000;color:#f2f0e9;max-width:72rem}",
             "h1{border-bottom:1px solid #333;padding-bottom:.5rem}",
             "h2{margin-top:2.5rem;color:#ff4d12}h3{margin-top:1.8rem}",
             "code,pre{font-family:ui-monospace,monospace;font-size:.86em}",
             "table{border-collapse:collapse;width:100%;margin:.75rem 0}",
             "th,td{border:1px solid #2a2a2a;padding:.4rem .6rem;text-align:left;"
             "vertical-align:top}",
             "th{background:#141414}",
             ".k{display:inline-block;padding:.05rem .4rem;border-radius:3px;"
             "background:#222;font-size:.8em}",
             "</style></head><body>"]
    parts.append("<h1>Active Directory attack paths</h1>")
    parts.append("<p>Generated %s from %d collected objects across %d domains.</p>"
                 % (escape(document["generated_at"]), document["objects"],
                    len(document["forest"])))
    parts.append("<h2>Summary</h2><p>The directory holds <strong>%d objects</strong> and "
                 "<strong>%d relationships</strong>, of which <strong>%d can be "
                 "walked</strong>. <strong>%d objects are crown jewels</strong>: %d "
                 "privileged on their own evidence, %d reached from those.</p>"
                 % (graph["nodes"], graph["edges"], graph["traversable"],
                    crown["total"], crown["seeded"], crown["derived"]))

    parts.append("<h2>Crown jewels</h2>")
    parts.append("<h3>Privileged on their own evidence (%d)</h3>" % crown["seeded"])
    parts.append("<table><tr><th>Type</th><th>Object</th><th>Why</th></tr>")
    for jewel in crown["seeded_list"]:
        parts.append("<tr><td>%s</td><td><code>%s</code></td><td>%s</td></tr>"
                     % (escape(jewel["kind"]), escape(jewel["name"]),
                        escape("; ".join(jewel["reasons"]))))
    parts.append("</table>")
    parts.append("<h3>Reached from those (%d)</h3>" % crown["derived"])
    if crown["derived_list"]:
        parts.append("<table><tr><th>Type</th><th>Object</th><th>Hops</th>"
                     "<th>Reaches</th></tr>")
        for jewel in crown["derived_list"]:
            parts.append("<tr><td>%s</td><td><code>%s</code></td><td>%d</td>"
                         "<td><code>%s</code></td></tr>"
                         % (escape(jewel["kind"]), escape(jewel["name"]), jewel["hops"],
                            escape(jewel["reaches"])))
        parts.append("</table>")

    rows = document.get("certificate_escalations") or []
    if rows:
        parts.append("<h2>Certificate services</h2><p>An authority issues a certificate "
                     "for whatever its templates permit, and a template that lets the "
                     "requester choose the subject, or that carries an authentication "
                     "purpose, is a route to any principal's identity. These conditions "
                     "are read from the template's own attributes, not its name.</p>")
        parts.append("<table><tr><th>Template</th><th>Condition</th><th>Severity</th>"
                     "<th>Who can enroll</th><th>Why</th></tr>")
        for row in rows:
            who = ", ".join(row.get("enrollees") or []) or "nobody outside the administrators"
            parts.append("<tr><td>%s</td><td>%s</td><td class=\"sev-%s\">%s</td><td>%s</td>"
                         "<td>%s</td></tr>"
                         % (escape(row["template"]), escape(", ".join(row["conditions"])),
                            escape(row["severity"].lower()), escape(row["severity"]),
                            escape(who), escape(row["note"])))
        parts.append("</table>")

    parts.append("<h2>The routes</h2>")
    for jewel in crown["derived_list"][:25]:
        parts.append("<h3>%s <span class='k'>%d hop(s)</span></h3>"
                     % (escape(jewel["name"]), jewel["hops"]))
        parts.append("<table><tr><th>From</th><th>Right</th><th>To</th><th>Grants</th></tr>")
        for step in jewel["steps"]:
            parts.append("<tr><td><code>%s</code></td><td><code>%s</code></td>"
                         "<td><code>%s</code></td><td>%s</td></tr>"
                         % (escape(step["from"]), escape(step["right"]),
                            escape(step["to"]), escape(step["why"] or "")))
        parts.append("</table>")

    parts.append("<h2>What to fix</h2>")
    if document["choke_points"]:
        parts.append("<table><tr><th>Type</th><th>Object</th><th>Routes cut</th>"
                     "<th>Of</th></tr>")
        for point in document["choke_points"]:
            parts.append("<tr><td>%s</td><td><code>%s</code></td><td>%d</td><td>%d</td></tr>"
                         % (escape(point["kind"]), escape(point["name"]),
                            point["cuts"], point["attackers"]))
        parts.append("</table>")
    parts.append("<h3>The smallest change</h3>")
    if cut.get("unbounded"):
        parts.append("<p><strong>No set of intermediate objects disconnects these.</strong> "
                     "%s</p>" % escape(cut["note"]))
        if cut.get("direct"):
            parts.append("<table><tr><th>From</th><th>Crown jewel</th></tr>")
            for item in cut["direct"]:
                parts.append("<tr><td><code>%s</code></td><td><code>%s</code></td></tr>"
                             % (escape(item["source"]), escape(item["sink"])))
            parts.append("</table>")
    else:
        parts.append("<p>Removing <strong>%d object(s)</strong> disconnects every route, "
                     "and that is the minimum, computed exactly with max-flow.</p>"
                     % cut["size"])
        parts.append("<table><tr><th>Type</th><th>Object</th></tr>")
        for item in cut["cut"]:
            parts.append("<tr><td>%s</td><td><code>%s</code></td></tr>"
                         % (escape(item["kind"]), escape(item["name"])))
        parts.append("</table>")

    context = document["context"]
    parts.append("<h2>What this does not model</h2>")
    if context["non_traversable"]:
        parts.append("<p>Recorded but never walked: %s.</p>"
                     % escape(", ".join("%s (%d)" % (k, v)
                                        for k, v in sorted(context["non_traversable"].items()))))
    if context["unresolved"]:
        parts.append("<p>Rights this does not know, reported rather than dropped: %s.</p>"
                     % escape(", ".join(sorted(
                         {r for rights in context["unresolved"].values() for r in rights}))))
    parts.append("</body></html>")
    return "\n".join(parts)
