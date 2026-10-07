"""The command line: one engagement file in, one report out.

Everything the tool does happens through this, and everything it does is decided by
the engagement file. There is no flag that widens the scope -- a flag that could
would make the file advisory, and the whole claim of this framework is that it is
not.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import report as report_module
from .assessment import assess_http
from .crawl import crawl
from .scan import fingerprint_tls, scan
from .scope import ScopeError, load_scope
from .throttle import Throttle
from .vulns import CveError, NvdClient

__all__ = ["main", "run_engagement"]


def run_engagement(scope_path: str | Path, out_dir: str | Path,
                   lookup_cves: bool = False, timeout: float = 3.0,
                   cache_path: str | Path | None = None,
                   do_crawl: bool = True, rate: float = 10.0,
                   workers: int = 4, max_pages: int = 25) -> dict:
    """Run one engagement and write its report.

    Returns the document that was written, so a caller can assert on it without
    reading the files back.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    scope = load_scope(scope_path, audit_path=out / "audit.jsonl")
    at = datetime.now(timezone.utc)

    # Every port the engagement names, so the scan asks about what is permitted
    # rather than sweeping a range and discarding the refusals afterwards.
    ports: list[int] = []
    for target in scope.targets:
        listed = target.get("ports")
        if listed in (None, "all"):
            continue
        for port in listed:
            if int(port) not in ports:
                ports.append(int(port))

    # One throttle for the whole engagement, so the rate limit is a property of
    # the run rather than of each phase. A limit that reset between phases would
    # let a target be asked twice as often by splitting the work in two.
    throttle = Throttle(rate_per_second=rate, workers=workers)

    services = []
    findings = []
    crawls = []
    for host in scope.hosts():
        for service in scan(scope, host, ports, at=at, timeout=timeout):
            services.append(service)
            if not service.open:
                continue
            scheme = "https" if service.port in (443, 8443) else "http"
            if scheme == "https":
                service.tls = fingerprint_tls(scope, host, service.port, at=at)
            if do_crawl:
                result = crawl(scope, host, service.port, scheme=scheme, at=at,
                               throttle=throttle, max_pages=max_pages)
                result["host"] = host
                result["port"] = service.port
                crawls.append(result)
            findings.extend(assess_http(scope, host, service.port, scheme=scheme, at=at))

    if lookup_cves:
        client = NvdClient(cache_path=cache_path or (out / "nvd-cache.json"))
        for service in services:
            if not service.open or not service.product:
                continue
            try:
                records = client.for_product(service.product, service.version, limit=10)
            except CveError as exc:
                findings.append(_unlooked_up(service, str(exc)))
                continue
            if not records:
                continue
            best = max(records, key=lambda r: (r.computed_score or 0.0))
            findings.append(_cve_finding(service, records, best))

    document = report_module.build(scope, services, findings, scope.audit.refusals,
                                   generated_at=at, crawls=crawls,
                                   throttle=throttle.as_dict())
    (out / "report.md").write_text(report_module.to_markdown(document), encoding="utf-8")
    (out / "report.html").write_text(report_module.to_html(document), encoding="utf-8")
    (out / "engagement.json").write_text(json.dumps(document, indent=1), encoding="utf-8")
    return document


def _cve_finding(service, records, best):
    from .scan import Evidence, Finding
    evidence = Evidence()
    evidence.add("header", "the target reported %s" % service.name, service.banner[:200])
    evidence.add("lookup", "NVD returned %d CVE(s) for that product and version" % len(records), "")
    return Finding(
        id="known-cves-for-version",
        title="The reported version has published vulnerabilities",
        severity=best.computed_severity or "Unknown",
        host=service.host, port=service.port,
        detail=("The service names %s, and NVD returns published vulnerabilities for that "
                "product and version. The score is computed from NVD's published vector "
                "rather than copied from the feed. This is a lead, not a verdict: it does "
                "not confirm the target is exploitable, only that the version it claims is "
                "one with a history." % service.name),
        evidence=evidence.as_list(),
        cves=[record.as_dict() for record in records[:5]],
        base_score=best.computed_score,
        remediation=("Confirm the running version, then apply the vendor's fix for the "
                     "CVEs above, highest score first. If the version cannot be confirmed "
                     "from outside, confirm it from the inventory."),
        business_impact=("A version with published, scored vulnerabilities is the easiest "
                         "possible target: the work of finding it has already been done by "
                         "somebody else and is public."),
    )


def _unlooked_up(service, reason):
    from .scan import Evidence, Finding
    evidence = Evidence()
    evidence.add("lookup", "NVD could not be asked", reason)
    return Finding(
        id="cve-lookup-unavailable",
        title="The CVE lookup could not be completed",
        severity="Info",
        host=service.host, port=service.port,
        detail=("The service names %s, but NVD could not be reached, so no claim is made "
                "about which vulnerabilities apply to it. The gap is reported rather than "
                "left to look like an absence of findings." % service.name),
        evidence=evidence.as_list(),
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="scoped-assessment",
        description="Assess a target within the limits an engagement file sets.")
    parser.add_argument("--scope", required=True, help="the engagement file (YAML or JSON)")
    parser.add_argument("--out", default="assessment-output", help="where the report is written")
    parser.add_argument("--cves", action="store_true",
                        help="ask NVD about the versions the targets report")
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--no-crawl", action="store_true",
                        help="do not follow links; test only the known paths")
    parser.add_argument("--rate", type=float, default=10.0,
                        help="requests per second, per engagement (default 10)")
    parser.add_argument("--workers", type=int, default=4,
                        help="how many requests may be in flight at once (default 4)")
    parser.add_argument("--max-pages", type=int, default=25,
                        help="how many pages a crawl may read (default 25)")
    parser.add_argument("--cache", default=None, help="where to keep the NVD cache")
    args = parser.parse_args(argv)

    try:
        document = run_engagement(args.scope, args.out, lookup_cves=args.cves,
                                  timeout=args.timeout, cache_path=args.cache,
                                  do_crawl=not args.no_crawl, rate=args.rate,
                                  workers=args.workers, max_pages=args.max_pages)
    except ScopeError as exc:
        print("the engagement file is unusable, so nothing was attempted: %s" % exc,
              file=sys.stderr)
        return 2

    counts = document["counts"]
    print("%s: %d finding(s) -- %s"
          % (document["engagement"], document["total"],
             ", ".join("%d %s" % (counts[name], name.lower())
                       for name in report_module.SEVERITY_ORDER if counts[name]) or "none"))
    confirmed = sum(1 for f in document["findings"] if f["confirmed"])
    print("%d of those confirmed by a second observation" % confirmed)
    print("crawl: %d page(s) read, %d endpoint(s) found, %d link(s) not followed"
          % (document["crawl"]["pages_read"], len(document["crawl"]["endpoints"]),
             document["crawl"]["not_followed"]))
    print("%d action(s) refused by the scope engine" % document["refusal_count"])
    print("report written to %s" % Path(args.out).resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
