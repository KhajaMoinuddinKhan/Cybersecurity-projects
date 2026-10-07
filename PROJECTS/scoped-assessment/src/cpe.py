"""CPE matching and version comparison, so the tool can say "affected".

The difference between a lead and a finding is this module. Asking a feed for
"CVEs mentioning Apache 2.4" returns everything anybody ever wrote about Apache
2.4; asking whether a *specific* version falls inside a CVE's affected range
returns a statement about the system in front of you. The first is a search
result, the second is a finding.

NVD publishes both halves of what that needs. A CVE carries `configurations`, which
is a tree of CPE match criteria, and each criterion carries either an exact version
or a range expressed as `versionStartIncluding` and `versionEndExcluding` and their
siblings. This module evaluates that tree against the CPE a target was
fingerprinted as, and it implements the version comparison rather than asking NVD
to do it -- because a tool that outsources the comparison cannot explain its own
verdict, and because the comparison can then be checked against NVD's own answers.

Specification: NVD, "CPE Match Criteria" and the CPE 2.3 naming specification.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = ["CpeError", "Cpe", "parse_cpe", "compare_versions", "matches"]

# NVD uses these where a field is not stated. `*` means any, `-` means not
# applicable, and both behave the same way for matching purposes.
_WILDCARDS = ("*", "-", "")


class CpeError(ValueError):
    """The string is not a CPE 2.3 name."""


@dataclass(frozen=True)
class Cpe:
    part: str
    vendor: str
    product: str
    version: str
    update: str = "*"
    edition: str = "*"
    language: str = "*"
    sw_edition: str = "*"
    target_sw: str = "*"
    target_hw: str = "*"
    other: str = "*"

    @property
    def name(self) -> str:
        return "cpe:2.3:%s" % ":".join([
            self.part, self.vendor, self.product, self.version, self.update,
            self.edition, self.language, self.sw_edition, self.target_sw,
            self.target_hw, self.other])

    def as_dict(self) -> dict:
        return {"part": self.part, "vendor": self.vendor, "product": self.product,
                "version": self.version}


def parse_cpe(text: str) -> Cpe:
    """A CPE 2.3 formatted string, or an error naming what is wrong."""
    raw = str(text or "").strip()
    if not raw.lower().startswith("cpe:2.3:"):
        raise CpeError("only CPE 2.3 names are supported, got %r" % text)
    fields = raw.split(":")
    # cpe : 2.3 : part : vendor : product : version : update : edition :
    # language : sw_edition : target_sw : target_hw : other
    if len(fields) < 13:
        raise CpeError("a CPE 2.3 name has thirteen fields, got %d" % len(fields))
    body = fields[2:]
    part = body[0].strip().lower()
    if part not in ("a", "o", "h"):
        raise CpeError("the part must be a, o or h, got %r" % part)
    return Cpe(*[field.strip().lower() for field in body[:11]])


def _components(version: str) -> list:
    """A version split into comparable pieces.

    Split on the punctuation that separates version fields, and each piece is
    either an integer or a string. `2.4.49` is three integers; `1.0.2k` is two
    integers and a letter, which NVD's own ordering treats as greater than
    `1.0.2` and less than `1.0.3`.
    """
    # Split on the punctuation between fields, and then split a field that mixes
    # letters and digits -- `2k` is the second patch level and the eleventh letter
    # release, and treating it as one string made `1.0.2k` sort *below* `1.0.2`.
    # The differential test against NVD's answers caught that.
    pieces = []
    for chunk in re.split(r"[._\-+]", str(version or "").lower()):
        if not chunk:
            continue
        for part in re.findall(r"\d+|[^\d]+", chunk):
            pieces.append(int(part) if part.isdigit() else part)
    return pieces


def compare_versions(left: str, right: str) -> int:
    """-1, 0 or 1, comparing two versions the way NVD orders them.

    The rules that matter, and the ones a naive string comparison gets wrong:
    a longer version sharing a prefix is greater (`1.2.1` > `1.2`); a numeric
    component is compared as a number, not as text (`2.10` > `2.9`); and a
    numeric component outranks a non-numeric one at the same position
    (`1.0.2` > `1.0.alpha`).
    """
    a, b = _components(left), _components(right)
    for index in range(max(len(a), len(b))):
        if index >= len(a):
            return -1 if _non_zero(b[index:]) else 0
        if index >= len(b):
            return 1 if _non_zero(a[index:]) else 0
        one, two = a[index], b[index]
        if one == two:
            continue
        one_numeric, two_numeric = isinstance(one, int), isinstance(two, int)
        if one_numeric and two_numeric:
            return -1 if one < two else 1
        if one_numeric != two_numeric:
            # A numeric field outranks a non-numeric one at the same position, so
            # `1.0.2` is greater than `1.0.alpha`. This was inverted, and the
            # differential test against NVD's own answers is what caught it.
            return 1 if one_numeric else -1
        return -1 if str(one) < str(two) else 1
    return 0


def _non_zero(rest) -> bool:
    return any(piece != 0 and piece != "0" and piece != "" for piece in rest)


def _field_matches(pattern: str, value: str) -> bool:
    if pattern in _WILDCARDS:
        return True
    if value in _WILDCARDS:
        return True
    return pattern == value


def _criterion_matches(criterion: dict, target: Cpe) -> bool:
    """Does one `cpeMatch` criterion cover the target?

    The criteria is a CPE that may name an exact version or may leave the version
    as a wildcard and carry a range instead. Both forms are handled, and a
    criterion that is not marked vulnerable is not a match.
    """
    if not criterion.get("vulnerable", False):
        return False
    try:
        wanted = parse_cpe(criterion.get("criteria", ""))
    except CpeError:
        return False

    if not (_field_matches(wanted.part, target.part)
            and _field_matches(wanted.vendor, target.vendor)
            and _field_matches(wanted.product, target.product)):
        return False
    if not _field_matches(wanted.update, target.update):
        return False

    version = target.version
    if wanted.version not in _WILDCARDS:
        return compare_versions(version, wanted.version) == 0

    # a range rather than a fixed version
    start_including = criterion.get("versionStartIncluding")
    start_excluding = criterion.get("versionStartExcluding")
    end_including = criterion.get("versionEndIncluding")
    end_excluding = criterion.get("versionEndExcluding")
    if not any((start_including, start_excluding, end_including, end_excluding)):
        return True                      # a wildcard version with no range covers all

    if start_including and compare_versions(version, str(start_including)) < 0:
        return False
    if start_excluding and compare_versions(version, str(start_excluding)) <= 0:
        return False
    if end_including and compare_versions(version, str(end_including)) > 0:
        return False
    if end_excluding and compare_versions(version, str(end_excluding)) >= 0:
        return False
    return True


def matches(configurations, target: Cpe) -> bool:
    """Does a CVE's `configurations` block cover the target?

    The block is a list of configurations, each a list of nodes, each with an
    operator and a list of criteria. A configuration matches when all its nodes
    match; a node matches according to its own operator. Nested nodes are
    followed, because NVD uses them for the "product running on an affected
    platform" case.
    """
    if not configurations:
        return False
    for configuration in configurations:
        nodes = configuration.get("nodes") or []
        if not nodes:
            continue
        if all(_node_matches(node, target) for node in nodes):
            return True
    return False


def _node_matches(node: dict, target: Cpe) -> bool:
    result = _node_body_matches(node, target)
    return not result if node.get("negate") else result


def _node_body_matches(node: dict, target: Cpe) -> bool:
    results = []
    for criterion in node.get("cpeMatch") or []:
        results.append(_criterion_matches(criterion, target))
    for child in node.get("nodes") or []:
        results.append(_node_matches(child, target))
    if not results:
        return False
    return all(results) if str(node.get("operator", "OR")).upper() == "AND" else any(results)
