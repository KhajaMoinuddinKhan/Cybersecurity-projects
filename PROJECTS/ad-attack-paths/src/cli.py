"""The command line: collector output in, an attack-path report out.

Several archives can be given at once, and they are merged into one directory. A
forest is not one domain: trusts run between domains and a compromise in one is a
route into another, so reading a single archive reports the trust as an unresolved
reference and misses everything beyond it. The first run of this did exactly that.

Nothing is defaulted that would change the answer. The data has to be named, because
an analysis that guessed which directory to look at would be analysing something
nobody asked about, and there is no bundled sample used as a fallback -- a tool that
quietly falls back to a fixture reports on the fixture.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import report as report_module
from .chokepoints import attacker_map, chokepoints, minimum_node_cut
from .graph import build_graph
from .schema import CollectorError, load_collector, load_forest
from .adcs import authority_managers, certificate_chains, certificate_escalations
from .tier0 import Tier0Error, crown_jewels

__all__ = ["main", "run_analysis"]


def run_analysis(paths, out_dir="attack-paths", include_derived=True,
                 deep_only_cut=False) -> dict:
    """Read the collections, build the graph, and write the report."""
    paths = [Path(p) for p in paths]
    data = load_forest(paths) if len(paths) > 1 else load_collector(paths[0])

    graph = build_graph(data)
    jewels = crown_jewels(data, graph, include_derived=include_derived)
    seeds = [jewel.sid for jewel in jewels if not jewel.derived]

    choke = chokepoints(graph, jewels, limit=25)

    # The cut is asked of the routes that need an intermediate object. A source that
    # reaches a crown jewel in one step cannot be cut at all, so including it makes
    # the flow unbounded -- which is the honest answer for that set and is reported
    # as such, but it says nothing about the routes that *could* be broken.
    reachers = attacker_map(graph, jewels, seeds)
    sources = list(reachers.keys())
    if deep_only_cut:
        sources = [sid for sid, path in reachers.items() if path.length >= 2]
    cut = minimum_node_cut(graph, sources=sources, sinks=seeds) if sources else {
        "cut": [], "size": 0, "unbounded": False,
        "note": "no object outside the crown-jewel set can reach it"}

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    # The escalation assessment needs the whole privileged set, including the objects
    # that only reach a crown jewel, because that set is what makes the write-rights
    # condition mean anything. It is computed here rather than reused from above so
    # that --seeds-only narrows the report without narrowing the assessment.
    privileged = {j.sid for j in crown_jewels(data, graph)}
    escalations = certificate_escalations(data, graph, privileged)
    chains = certificate_chains(escalations)
    managers = authority_managers(data, graph, privileged)

    document = report_module.build(graph, jewels, choke, cut, escalations, chains, managers,
                                   generated_at=datetime.now(timezone.utc))
    document["cut_sources"] = len(sources)
    (out / "report.md").write_text(report_module.to_markdown(document), encoding="utf-8")
    (out / "report.html").write_text(report_module.to_html(document), encoding="utf-8")
    (out / "findings.json").write_text(json.dumps(document, indent=1), encoding="utf-8")
    return document


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="ad-attack-paths",
        description="Work out what is privileged in an Active Directory forest and "
                    "how an attacker reaches it, from real collector output.")
    parser.add_argument("--data", action="append", required=True, metavar="PATH",
                        help="a SharpHound archive or a directory of its JSON files. "
                             "Give it more than once for a forest.")
    parser.add_argument("--out", default="attack-paths", help="where the report is written")
    parser.add_argument("--seeds-only", action="store_true",
                        help="report only the objects privileged on their own evidence, "
                             "without closing the set over what reaches them")
    parser.add_argument("--cut-deep-only", action="store_true",
                        help="compute the smallest set of objects to fix using only the "
                             "routes that need an intermediate object")
    args = parser.parse_args(argv)

    try:
        document = run_analysis(args.data, out_dir=args.out,
                                include_derived=not args.seeds_only,
                                deep_only_cut=args.cut_deep_only)
    except (CollectorError, Tier0Error) as exc:
        print("the collection could not be analysed, so nothing was reported: %s" % exc,
              file=sys.stderr)
        return 2

    crown = document["crown_jewels"]
    graph = document["graph"]
    print("%s: %d objects across %d domain(s)"
          % (", ".join(document["forest"]) or "the directory",
             document["objects"], len(document["forest"])))
    print("  %d relationships, %d of them walkable" % (graph["edges"], graph["traversable"]))
    print("  %d crown jewels: %d privileged on their own evidence, %d reached from those"
          % (crown["total"], crown["seeded"], crown["derived"]))
    if document["choke_points"]:
        top = document["choke_points"][0]
        print("  the largest choke point is %s, cutting %d of %d routes"
              % (top["name"], top["cuts"], top["attackers"]))
    cut = document["cut"]
    if cut.get("unbounded"):
        print("  no set of intermediate objects disconnects these: %d reach a crown "
              "jewel in a single step" % len(cut.get("direct") or []))
    else:
        print("  the smallest change is %d object(s)" % cut["size"])
    # Read from the document rather than from locals: the analysis function owns those
    # and they are not in scope here. This block referred to names that only existed
    # inside run_analysis, so every run printed the analysis and then died with a
    # NameError before its last line -- the report was already written, so nothing
    # looked wrong, and the exit code said 1 the whole time.
    escalations = document.get("certificate_escalations") or []
    if escalations:
        worst = escalations[0]
        print("  %d certificate template(s) permit an escalation, worst: %s (%s)"
              % (len(escalations), worst["template"], ", ".join(worst["conditions"])))
    chains = document.get("certificate_chains") or []
    if chains:
        print("  %d combination(s) are stronger than either half, worst: %s"
              % (len(chains), ", ".join(chains[0]["conditions"])))
    print("report written to %s" % Path(args.out).resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
