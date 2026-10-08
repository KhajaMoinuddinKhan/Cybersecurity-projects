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


def build(graph, jewels, choke, cut, escalations=(), chains=(), managers=(),
          binding=None, trusts=(), unassessable=(), generated_at=None) -> dict:
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
        "cut": _named_cut(graph, cut),
        "certificate_escalations": [e.as_dict() for e in escalations],
        "certificate_chains": [c.as_dict() for c in chains],
        "authority_managers": list(managers),
        "certificate_binding": dict(binding or {}),
        "unfiltered_trusts": list(trusts),
        "unassessable_conditions": list(unassessable),
        "context": _context(graph),
    }


# How much of each section is shown. They are choices about the document rather than
# about the analysis, so they are named here and every one of them says what it left
# out -- a report that quietly drops seven routes reads exactly like one that had none.
ROUTES_SHOWN = 25
REASON_CHARS = 150
STEP_CHARS = 110
OBJECTS_PER_FIELD = 3


def _named_cut(graph, cut: dict) -> dict:
    """The cut with every object named, and the count of what the table leaves out.

    The table showed identifiers rather than names -- the same fault the certificate
    enrollment column had -- and it showed ten rows under a sentence saying forty-five
    objects reach a crown jewel in one step, with nothing to say the other thirty-five
    had been left out.
    """
    named = dict(cut)
    direct = []
    for item in cut.get("direct") or []:
        direct.append({"source": graph.name_of(item["source"]),
                       "sink": graph.name_of(item["sink"])})
    named["direct"] = direct
    return named


def _context(graph) -> dict:
    """What the graph holds but does not walk, and what it could not read."""
    by_kind = {}
    for edge in graph.edges:
        if not edge.traversable:
            by_kind[edge.kind] = by_kind.get(edge.kind, 0) + 1
    return {"non_traversable": by_kind,
            "unresolved": {sid: rights for sid, rights in graph.unknown_rights.items()}}


def _clip(text: str, width: int) -> str:
    """Shorten for a table cell, and say so. A silently truncated reason reads as the
    whole reason, which is the one thing a report must not do."""
    text = text or ""
    if len(text) <= width:
        return text
    return text[:width - 1].rstrip() + "\u2026"


def _unassessable_markdown(document: dict) -> list:
    """The conditions this collection cannot decide, named rather than omitted."""
    rows = document.get("unassessable_conditions") or []
    if not rows:
        return []
    lines = ["### Conditions this collection cannot decide", "",
             "A condition nobody can evaluate is not a condition that is absent. Each of "
             "these needs an object or a setting the collector did not read, and a report "
             "that simply did not mention them would read exactly like one where they "
             "were checked and came back clean.", "",
             "| Condition | Needs | Why nothing is claimed |", "| --- | --- | --- |"]
    for row in rows:
        lines.append("| %s | %s | %s |" % (row["condition"], row["needs"], row["why"]))
    lines.append("")
    return lines


def _trusts_markdown(document: dict) -> list:
    """Trusts that will accept an identifier from the other side."""
    trusts = document.get("unfiltered_trusts") or []
    if not trusts:
        return []
    lines = ["## Trusts that accept an identifier from the other side", "",
             "A trust permits authentication across it and grants nothing, which is why "
             "one is not walked as a route. SID filtering is what stops a principal "
             "carrying an identifier from the other domain being accepted there. Where "
             "it is off, the identifier is accepted, and the principal holds whatever "
             "that identifier was granted on the other side.", "",
             "| Domain | Trusts | Type | Direction |", "| --- | --- | --- | --- |"]
    for trust in trusts:
        lines.append("| `%s` | `%s` | %s | %s |" % (trust["domain"], trust["trusted"],
                                                    trust["trust_type"], trust["direction"]))
    lines.append("")
    return lines


def _binding_markdown(document: dict) -> list:
    """Whether a certificate can be accepted as another identity.

    Its own section rather than part of the certificate one: these settings are about
    what the authority and the machines will accept, which matters whether or not any
    template permits an escalation. The first version nested it inside the certificate
    section, which returns nothing when there are no escalations -- so a collection with
    unread settings and no vulnerable templates said nothing at all about either.
    """
    binding = document.get("certificate_binding") or {}
    if not binding:
        return []
    lines = ["## Certificate binding", "",
             "Two registry settings decide whether a certificate issued for one identity "
             "is accepted when presented for another. They are the difference between a "
             "stolen certificate being useless and being a logon.", ""]
    for entry in binding.get("collected") or []:
        lines.append("- `%s`: mapping methods `%s`, strong binding `%s`."
                     % (entry["computer"], entry["mapping"], entry["binding"]))
    missing = binding.get("missing") or []
    if missing:
        lines.append("- **Not read on %d machine(s): %s.** An uncollected setting is not "
                     "a setting that is off, so nothing is claimed about these."
                     % (len(missing), ", ".join("`%s`" % m for m in missing[:6])))
    lines.append("")
    return lines


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
        # A finding about who can change something names its holders; a finding about a
        # template names who can enroll in it. They are different questions and the
        # column said "nobody" for the first, which is the opposite of the truth.
        enrollees = (row.get("enrollee_names") or row.get("enrollees")
                     or row.get("principals") or [])
        who = ", ".join("`%s`" % e for e in enrollees[:3]) if enrollees else \
            "nobody outside the administrators"
        lines.append("| %s | %s | %s | %s | %s |" % (
            row["template"], ", ".join(row["conditions"]), row["severity"], who, row["note"]))

    chains = document.get("certificate_chains") or []
    if chains:
        lines.append("### Combinations")
        lines.append("")
        lines.append("Each template above is judged on its own attributes, and the "
                     "judgement is right. These are the pairs that are stronger than "
                     "either half, because the first is how you get the credential the "
                     "second accepts.")
        lines.append("")
        for chain in chains:
            lines.append("- **%s** (%s) -- %s" % (", ".join(chain["conditions"]),
                                                   chain["severity"], chain["note"]))
            lines.append("  Templates: %s" % ", ".join("`%s`" % x for x in chain["templates"]))
        lines.append("")
    managers = document.get("authority_managers") or []
    if managers:
        lines.append("### Who can change an authority")
        lines.append("")
        lines.append("The right to manage an authority is the right to enable a template "
                     "that is not enabled, so it combines with every condition above. "
                     "Only holders without administrative rights are listed.")
        lines.append("")
        lines.append("| Principal | Right | Authority |")
        lines.append("| --- | --- | --- |")
        for manager in managers:
            lines.append("| `%s` | `%s` | `%s` (%s) |" % (
                manager["principal"], manager["right"], manager["authority"],
                manager.get("authority_kind", "")))
        lines.append("")

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
                                             _clip("; ".join(jewel["reasons"]), REASON_CHARS)))
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
    lines.extend(_unassessable_markdown(document))
    lines.extend(_trusts_markdown(document))
    lines.extend(_binding_markdown(document))

    lines.append("## The routes")
    lines.append("")
    lines.append("Each route below is a sequence an attacker can actually walk, one "
                 "step at a time. The shortest are shown first.")
    lines.append("")
    if crown["derived"] > ROUTES_SHOWN:
        lines.append("Showing the %d shortest of %d. The remainder are in the crown "
                     "jewel table above, which is not truncated."
                     % (ROUTES_SHOWN, crown["derived"]))
        lines.append("")
    for jewel in crown["derived_list"][:ROUTES_SHOWN]:
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
                            _clip(step["why"], STEP_CHARS)))
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
                     % cut["note"].rstrip("."))
        lines.append("")
        if cut.get("direct"):
            lines.append("Reached in a single step, so the object itself has to be fixed:")
            lines.append("")
            lines.append("| From | Crown jewel |")
            lines.append("| --- | --- |")
            for item in cut["direct"]:
                lines.append("| `%s` | `%s` |" % (item["source"], item["sink"]))
            lines.append("")
            if cut.get("direct_total", 0) > len(cut["direct"]):
                lines.append("Showing %d of %d; the rest are in the crown jewel table "
                             "above." % (len(cut["direct"]), cut["direct_total"]))
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
    unresolved = document["graph"].get("unknown_references") or {}
    if unresolved:
        total = sum(len(v) for v in unresolved.values())
        lines.append("Relationships that point at objects the collection does not "
                     "contain: **%d identifier%s** across **%d object%s**. They are "
                     "named rather than dropped -- an unresolved reference is a fact "
                     "about the collection, and treating it as absent would silently "
                     "remove whatever it granted."
                     % (total, "" if total == 1 else "s",
                        len(unresolved), "" if len(unresolved) == 1 else "s"))
        lines.append("")
    unmodelled = document["graph"].get("unmodelled") or {}
    if unmodelled:
        lines.append("Fields the collector populated that this does not turn into a "
                     "route, named so that nothing is dropped in silence:")
        lines.append("")
        for field, detail in sorted(unmodelled.items()):
            lines.append("- **`%s`** -- %s. On: %s." % (
                field, detail["meaning"],
                ", ".join("`%s`" % o for o in detail["objects"][:OBJECTS_PER_FIELD])))
        lines.append("")
    # Derived, not asserted. This sentence said "none were present in this data" for
    # every collection, and then the session edges started being built and it became a
    # false statement about the data it was describing.
    sessions = graph["by_kind"].get("session", 0)
    if sessions:
        lines.append("Sessions are walked in reverse -- compromising the machine yields "
                     "whoever is logged into it, which is the direction that makes a "
                     "session worth finding. **%d session relationship%s** %s present in "
                     "this data, and every one of them is a route."
                     % (sessions, "" if sessions == 1 else "s", "is" if sessions == 1 else "are"))
    else:
        lines.append("Sessions are collected per machine and none were present in this "
                     "data, so no route here depends on one. Where they exist they are "
                     "walked in reverse -- compromising the machine yields whoever is "
                     "logged into it -- which is the direction that makes a session "
                     "worth finding.")
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

    parts.append("<h2>The forest</h2>")
    parts.append("<ul>%s</ul>" % "".join("<li><code>%s</code></li>" % escape(d)
                                         for d in document["forest"]))
    parts.append("<p>Objects by type: %s.</p>"
                 % escape(", ".join("%s %d" % (kind, count)
                                    for kind, count in sorted(document["counts"].items()))))

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
            who = ", ".join(row.get("enrollee_names") or row.get("enrollees") or []) \
                or "nobody outside the administrators"
            parts.append("<tr><td>%s</td><td>%s</td><td class=\"sev-%s\">%s</td><td>%s</td>"
                         "<td>%s</td></tr>"
                         % (escape(row["template"]), escape(", ".join(row["conditions"])),
                            escape(row["severity"].lower()), escape(row["severity"]),
                            escape(who), escape(row["note"])))
        parts.append("</table>")

    if crown["derived"] > ROUTES_SHOWN:
        parts.append("<p>Showing the %d shortest of %d. The remainder are in the crown "
                     "jewel table above, which is not truncated.</p>"
                     % (ROUTES_SHOWN, crown["derived"]))
        chains = document.get("certificate_chains") or []
        if chains:
            parts.append("<h3>Combinations</h3><p>Each template above is judged on its "
                         "own attributes, and the judgement is right. These are the pairs "
                         "that are stronger than either half, because the first is how "
                         "you get the credential the second accepts.</p><ul>")
            for chain in chains:
                parts.append("<li><strong>%s</strong> (%s) -- %s<br>Templates: %s</li>"
                             % (escape(", ".join(chain["conditions"])),
                                escape(chain["severity"]), escape(chain["note"]),
                                escape(", ".join(chain["templates"]))))
            parts.append("</ul>")
        managers = document.get("authority_managers") or []
        if managers:
            parts.append("<h3>Who can change an authority</h3><p>The right to manage an "
                         "authority is the right to enable a template that is not "
                         "enabled, so it combines with every condition above. Only "
                         "holders without administrative rights are listed.</p>"
                         "<table><tr><th>Principal</th><th>Right</th>"
                         "<th>Authority</th></tr>")
            for manager in managers:
                parts.append("<tr><td><code>%s</code></td><td><code>%s</code></td>"
                             "<td><code>%s</code> (%s)</td></tr>"
                             % (escape(manager["principal"]), escape(manager["right"]),
                                escape(manager["authority"]),
                                escape(manager.get("authority_kind", ""))))
            parts.append("</table>")

    if crown["derived"] > ROUTES_SHOWN:
        parts.append("<p>Showing the %d shortest of %d. The remainder are in the crown "
                     "jewel table above, which is not truncated.</p>"
                     % (ROUTES_SHOWN, crown["derived"]))
    unassessable = document.get("unassessable_conditions") or []
    if unassessable:
        parts.append("<h3>Conditions this collection cannot decide</h3>"
                     "<p>A condition nobody can evaluate is not a condition that is "
                     "absent. Each of these needs an object or a setting the collector "
                     "did not read.</p>"
                     "<table><tr><th>Condition</th><th>Needs</th>"
                     "<th>Why nothing is claimed</th></tr>")
        for row in unassessable:
            parts.append("<tr><td>%s</td><td>%s</td><td>%s</td></tr>"
                         % (escape(row["condition"]), escape(row["needs"]),
                            escape(row["why"])))
        parts.append("</table>")

    trusts = document.get("unfiltered_trusts") or []
    if trusts:
        parts.append("<h2>Trusts that accept an identifier from the other side</h2>"
                     "<p>A trust permits authentication across it and grants nothing, "
                     "which is why one is not walked as a route. SID filtering is what "
                     "stops a principal carrying an identifier from the other domain "
                     "being accepted there. Where it is off, the identifier is accepted, "
                     "and the principal holds whatever that identifier was granted on "
                     "the other side.</p>"
                     "<table><tr><th>Domain</th><th>Trusts</th><th>Type</th>"
                     "<th>Direction</th></tr>")
        for trust in trusts:
            parts.append("<tr><td><code>%s</code></td><td><code>%s</code></td><td>%s</td>"
                         "<td>%s</td></tr>"
                         % (escape(trust["domain"]), escape(trust["trusted"]),
                            escape(trust["trust_type"]), escape(trust["direction"])))
        parts.append("</table>")

    binding = document.get("certificate_binding") or {}
    if binding:
        parts.append("<h2>Certificate binding</h2><p>Two registry settings decide whether "
                     "a certificate issued for one identity is accepted when presented "
                     "for another. They are the difference between a stolen certificate "
                     "being useless and being a logon.</p><ul>")
        for entry in binding.get("collected") or []:
            parts.append("<li><code>%s</code>: mapping methods <code>%s</code>, strong "
                         "binding <code>%s</code>.</li>"
                         % (escape(entry["computer"]), escape(str(entry["mapping"])),
                            escape(str(entry["binding"]))))
        missing = binding.get("missing") or []
        if missing:
            parts.append("<li><strong>Not read on %d machine(s): %s.</strong> An "
                         "uncollected setting is not a setting that is off, so nothing "
                         "is claimed about these.</li>"
                         % (len(missing),
                            escape(", ".join(missing[:6]))))
        parts.append("</ul>")

    parts.append("<h2>The routes</h2>")
    for jewel in crown["derived_list"][:ROUTES_SHOWN]:
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
                     "%s.</p>" % escape(cut["note"].rstrip(".")))
        if cut.get("direct"):
            parts.append("<table><tr><th>From</th><th>Crown jewel</th></tr>")
            for item in cut["direct"]:
                parts.append("<tr><td><code>%s</code></td><td><code>%s</code></td></tr>"
                             % (escape(item["source"]), escape(item["sink"])))
            parts.append("</table>")
            if cut.get("direct_total", 0) > len(cut["direct"]):
                parts.append("<p>Showing %d of %d; the rest are in the crown jewel table "
                             "above.</p>" % (len(cut["direct"]), cut["direct_total"]))
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

    # The markdown report carries these and this one did not, which made the two
    # formats say different things about the same analysis.
    unmodelled = graph.get("unmodelled") or {}
    if unmodelled:
        parts.append("<p>Fields the collector populated that this does not turn into a "
                     "route, named so that nothing is dropped in silence:</p><ul>")
        for field, detail in sorted(unmodelled.items()):
            parts.append("<li><code>%s</code> -- %s. On: %s.</li>"
                         % (escape(field), escape(detail["meaning"]),
                            escape(", ".join(detail["objects"][:OBJECTS_PER_FIELD]))))
        parts.append("</ul>")
    sessions = graph["by_kind"].get("session", 0)
    if sessions:
        parts.append("<p>Sessions are walked in reverse -- compromising the machine yields "
                     "whoever is logged into it. <strong>%d session relationship%s</strong> "
                     "%s present in this data, and every one of them is a route.</p>"
                     % (sessions, "" if sessions == 1 else "s",
                        "is" if sessions == 1 else "are"))
    else:
        parts.append("<p>Sessions are collected per machine and none were present in this "
                     "data, so no route here depends on one.</p>")
    parts.append("</body></html>")
    return "\n".join(parts)
