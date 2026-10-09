"""The command line: fuzz, triage what was found, and exploit it.

Three verbs, because there are three questions. `fuzz` asks whether the target can be
broken. `report` asks what was found and whether the pieces are distinct. `exploit` asks
whether a crash is worth anything, which is a question the first two cannot answer.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .build import (BuildError, available_targets, build, describe,
                    sanitizer_available)
from .corpus import minimise
from .crash import group
from .coverage import CoverageMap
from .engine import Engine
from .exploit import demonstrate
from .target import PersistentTarget

# Tidying up a reproducer costs a crashing run per attempt, and a crashing run costs a
# hundred times what an ordinary one does because the process dies and is started again.
# Bounded by the clock for that reason: the number of attempts is not what varies.
MINIMISE_SECONDS = 20.0

# The tokens the fuzzer is told about. Four bytes of tag are four bytes a random search
# will not find; everything past the tag is discovered from coverage.
DEFAULT_DICTIONARY = (b"RECS",)


def _load_seeds(paths) -> list:
    """Read the starting corpus. An empty corpus is allowed and is the interesting case:
    the search has to find the format from nothing."""
    seeds = []
    for path in paths or []:
        seeds.append(Path(path).read_bytes())
    return seeds


def _run_fuzz(args) -> int:
    toolchain = describe()
    if not toolchain["available"]:
        print(toolchain["reason"], file=sys.stderr)
        return 2
    try:
        executable = build(vulnerable=True, force=args.rebuild, target=args.target,
                           sanitize=args.sanitize)
    except BuildError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    coverage = CoverageMap(args.region)
    target = PersistentTarget(executable, coverage, timeout=args.timeout)
    engine = Engine(target, seed=args.seed, dictionary=DEFAULT_DICTIONARY)
    for seed in _load_seeds(args.seed_file) or [b""]:
        engine.add_seed(seed)

    started = time.time()
    last = [0.0]

    def on_event(result, stats):
        now = time.time()
        if now - last[0] < 1.0:
            return
        last[0] = now
        print("  %7d execs | %5d corpus | %5d edges | %3d crashes | %5.0f/s"
              % (stats.executions, len(engine.corpus), stats.edges_found,
                 len(engine.findings), stats.per_second), flush=True)

    try:
        stats = engine.run(budget=args.budget, stop_after_crashes=args.max_crashes,
                           on_event=on_event)
        if args.minimise:
            engine.minimise_findings(seconds=MINIMISE_SECONDS)
    finally:
        target.close()

    elapsed = time.time() - started
    print()
    print("  %d executions in %.1f seconds (%.0f/s)"
          % (stats.executions, elapsed, stats.executions / max(elapsed, 1e-9)))
    print("  corpus: %d inputs, %d bytes"
          % (len(engine.corpus), engine.corpus.total_bytes()))
    print("  coverage: %d edges" % coverage.total_edges)
    print("  crashes: %d distinct" % len(engine.findings))
    print("  the target was built %s a sanitizer"
          % ("with" if args.sanitize else "without"))
    if engine.learned:
        print("  the target named %d values it compares against" % len(engine.learned))
    if engine.stats.stepping_stones:
        print("  %d inputs kept only for their size" % engine.stats.stepping_stones)

    findings = group(engine.findings)
    for finding in findings:
        print("     %-18s %4d bytes  %s" % (finding.status, finding.size,
                                            finding.signature))
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "findings.json").write_text(json.dumps([
            {"signature": f.signature, "status": f.status, "size": f.size,
             "hex": f.data.hex(), "found_at_execution": f.executions,
             "edges": f.edges} for f in findings], indent=2), encoding="utf-8")
        for i, finding in enumerate(findings):
            (out / ("crash-%02d.bin" % i)).write_bytes(finding.data)
        print("  written to %s" % out)
    coverage.close()
    return 0


def _run_report(args) -> int:
    # `fuzz --out` writes a directory -- a JSON summary and the crashing inputs beside it
    # -- and `report` read a file, so the output of one was not the input of the other and
    # the pair failed on the first thing anybody would try. Both are accepted now.
    path = Path(args.findings)
    if path.is_dir():
        path = path / "findings.json"
    if not path.exists():
        print("no findings at %s" % args.findings, file=sys.stderr)
        return 2
    findings = json.loads(path.read_text(encoding="utf-8"))
    if not findings:
        print("no crashes were found")
        return 0
    print("  %d distinct crashes" % len(findings))
    for finding in findings:
        print("     %-18s %4d bytes  %s" % (finding["status"], finding["size"],
                                            finding["signature"]))
        print("        at execution %d, %d edges on the way in"
              % (finding["found_at_execution"], finding["edges"]))
    return 0


def _run_exploit(args) -> int:
    try:
        vulnerable = build(vulnerable=True, force=args.rebuild, exploit=True)
        patched = build(vulnerable=False, force=args.rebuild, exploit=True)
    except BuildError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    scratch = Path(args.out or ".")
    scratch.mkdir(parents=True, exist_ok=True)
    result = demonstrate(vulnerable, patched, scratch)

    if not result["vulnerable_reached"]:
        print("  the exploit did not take control: %s" % result["vulnerable_note"])
        return 1
    print("  stage one: the parser disclosed 0x%016X" % result["disclosed"])
    print("  the function it wants is %+d from there, so it aims at 0x%016X"
          % (result["delta"], result["target"]))
    print("  stage two: offset %d puts that address over the callback"
          % result["offset"])
    print("  vulnerable: %s" % result["vulnerable_note"])
    print("  patched:    %s%s" % (result["patched_note"],
                                  " (and did not crash)"
                                  if result["patched_crashed"] is False else ""))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="cgf", description="A coverage-guided fuzzer, and the exploit it finds.")
    sub = parser.add_subparsers(dest="command", required=True)

    fuzz = sub.add_parser("fuzz", help="search the target for crashes")
    fuzz.add_argument("--budget", type=int, default=20000,
                      help="how many executions to spend (default 20000)")
    fuzz.add_argument("--seed", type=int, default=0, help="the seed, for reproducing a run")
    fuzz.add_argument("--timeout", type=float, default=2.0,
                      help="seconds before a run is called a hang")
    fuzz.add_argument("--max-crashes", type=int, default=None,
                      help="stop after this many distinct crashes")
    fuzz.add_argument("--seed-file", action="append", metavar="FILE",
                      help="an input to start from; may be repeated")
    fuzz.add_argument("--region", default="cgf-coverage", help="shared-memory region name")
    fuzz.add_argument("--target", default="parser",
                      help="which target to fuzz; one of %s"
                           % ", ".join(available_targets()))
    fuzz.add_argument("--sanitize", action="store_true",
                      help="build the target with AddressSanitizer, which catches a "
                           "read or a write that leaves the memory the program has "
                           "(available: %s)" % sanitizer_available())
    fuzz.add_argument("--out", help="directory to write the crashing inputs to")
    fuzz.add_argument("--rebuild", action="store_true", help="rebuild the target")
    fuzz.add_argument("--minimise", action="store_true",
                      help="shrink each crashing input before writing it")
    fuzz.set_defaults(func=_run_fuzz)

    report = sub.add_parser("report", help="describe what a run found")
    report.add_argument("--findings", default="findings.json")
    report.set_defaults(func=_run_report)

    exploit = sub.add_parser("exploit", help="turn the crash into control")
    exploit.add_argument("--out", help="directory for the marker")
    exploit.add_argument("--rebuild", action="store_true")
    exploit.set_defaults(func=_run_exploit)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
