"""CVE lookup, against NVD, with the score computed rather than copied.

NVD publishes both a vector and a score. This module takes the vector and computes
the score itself, then records both -- so a reader can see that the number in the
report is arithmetic on a published vector rather than a number copied from a feed
and trusted. Where the two disagree the module says so instead of picking one.

Nothing here invents a vulnerability. A finding is attached to a CVE only when NVD
returns that CVE for the product and version the target actually reported.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .cvss import CvssError, score

__all__ = ["CveRecord", "NvdClient", "CveError"]

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "scoped-assessment/1.0 (an academic assessment framework)"


class CveError(Exception):
    """NVD could not be asked, so nothing may be claimed about a CVE."""


@dataclass(frozen=True)
class CveRecord:
    cve_id: str
    summary: str
    vector: str
    published_score: float | None
    published_severity: str
    computed_score: float | None
    computed_severity: str
    url: str
    # Whether the version falls inside the CVE's affected range, and which of
    # NVD's two structures said so. None means neither structure carried usable
    # data, which is not the same answer as "not affected".
    affected: bool | None = None
    match_source: str = ""
    match_detail: str = ""

    @property
    def agrees(self) -> bool:
        if self.published_score is None or self.computed_score is None:
            return False
        return abs(self.published_score - self.computed_score) < 0.05

    def as_dict(self) -> dict:
        return {
            "cve": self.cve_id, "summary": self.summary, "vector": self.vector,
            "published_score": self.published_score, "published_severity": self.published_severity,
            "affected": self.affected, "match_source": self.match_source,
            "match_detail": self.match_detail,
            "computed_score": self.computed_score, "computed_severity": self.computed_severity,
            "agrees": self.agrees, "url": self.url,
        }


class NvdClient:
    """NVD's 2.0 API, with a cache so a report can be re-generated offline.

    The cache is written as it is filled and read on the way in, which is what
    makes a report reproducible: re-running it does not depend on the feed being
    up, and the CVEs it cites are the ones that were current when it ran.
    """

    def __init__(self, cache_path: str | Path | None = None, timeout: float = 30.0):
        self.cache_path = Path(cache_path) if cache_path else None
        self.timeout = timeout
        self._cache: dict[str, dict] = {}
        if self.cache_path and self.cache_path.exists():
            try:
                self._cache = json.loads(self.cache_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                self._cache = {}

    def _get(self, url: str) -> dict:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except Exception as exc:                    # network, HTTP, or JSON
            raise CveError("NVD could not be reached: %s" % type(exc).__name__) from exc

    def _save(self) -> None:
        if self.cache_path:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(self._cache, indent=1), encoding="utf-8")

    @staticmethod
    def _record(raw: dict) -> CveRecord:
        cve = raw.get("cve") or {}
        cve_id = str(cve.get("id") or "")
        summary = ""
        for description in cve.get("descriptions") or []:
            if description.get("lang") == "en":
                summary = str(description.get("value") or "")
                break
        vector = ""
        published = None
        published_severity = ""
        for metric in (cve.get("metrics") or {}).get("cvssMetricV31") or []:
            data = metric.get("cvssData") or {}
            if str(data.get("vectorString", "")).startswith("CVSS:3.1/"):
                vector = data["vectorString"]
                published = float(data.get("baseScore") or 0.0)
                published_severity = str(data.get("baseSeverity") or "")
                break
        computed = None
        computed_severity = ""
        if vector:
            try:
                result = score(vector)
                computed, computed_severity = result.score, result.severity
            except CvssError:
                computed = None
        return CveRecord(cve_id=cve_id, summary=summary, vector=vector,
                         published_score=published, published_severity=published_severity,
                         computed_score=computed, computed_severity=computed_severity,
                         url="https://nvd.nist.gov/vuln/detail/%s" % cve_id)

    def by_id(self, cve_id: str) -> CveRecord | None:
        key = "id:%s" % cve_id.upper()
        if key not in self._cache:
            data = self._get("%s?cveId=%s" % (NVD_ENDPOINT, urllib.parse.quote(cve_id)))
            items = data.get("vulnerabilities") or []
            self._cache[key] = items[0] if items else {}
            self._save()
        raw = self._cache[key]
        return self._record(raw) if raw else None

    def for_cpe(self, cpe_text: str, limit: int = 40) -> list[CveRecord]:
        """CVEs whose affected range covers a specific CPE.

        This is the version-aware lookup, and it is the difference between a lead
        and a finding. NVD's `cpeName` filter returns a CVE when the CPE appears
        anywhere in its data -- including as a platform the CVE does not affect --
        so each result is then evaluated against the CVE's own `configurations` and
        `affected` blocks. A CVE the filter returned but whose ranges do not cover
        this version is reported with `affected` False rather than dropped, because
        the difference between "we checked and it is not in range" and "we never
        looked" is the thing a reader most needs to be able to see.
        """
        from .cpe import parse_cpe, verdict as cpe_verdict

        target = parse_cpe(cpe_text)
        key = "cpe:%s" % cpe_text.lower()
        if key not in self._cache:
            data = self._get("%s?cpeName=%s&resultsPerPage=%d"
                             % (NVD_ENDPOINT, urllib.parse.quote(cpe_text), limit))
            self._cache[key] = data.get("vulnerabilities") or []
            self._save()

        records = []
        for raw in self._cache[key]:
            record = self._record(raw)
            cve = raw.get("cve") or {}
            decision = cpe_verdict(cve.get("configurations"), cve.get("affected"), target)
            record.affected = decision["affected"]
            record.match_source = decision["source"]
            record.match_detail = ("the %s structure puts %s inside an affected range"
                                   % (decision["source"], target.version)
                                   if decision["affected"] is True else
                                   "the %s structure does not put %s inside an affected "
                                   "range" % (decision["source"], target.version)
                                   if decision["affected"] is False else
                                   "NVD publishes no affected-product data for this CVE, "
                                   "so nothing can be concluded from it either way")
            records.append(record)
        # Affected first, then by score: the reader wants what applies to them.
        records.sort(key=lambda r: (r.affected is not True, -(r.computed_score or 0.0)))
        return records

    def for_product(self, product: str, version: str = "", limit: int = 20) -> list[CveRecord]:
        """CVEs NVD returns for a keyword.

        A keyword search, so it is a starting point rather than proof, and the
        records it returns carry no verdict: `affected` stays None because nothing
        in this query compared a version. Use `for_cpe` when the target's CPE is
        known, which is whenever fingerprinting has run.
        """
        keyword = ("%s %s" % (product, version)).strip()
        key = "kw:%s" % keyword.lower()
        if key not in self._cache:
            data = self._get("%s?keywordSearch=%s&resultsPerPage=%d"
                             % (NVD_ENDPOINT, urllib.parse.quote(keyword), limit))
            self._cache[key] = data.get("vulnerabilities") or []
            self._save()
        return [self._record(raw) for raw in self._cache[key]]
