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

__all__ = ["CpeError", "Cpe", "parse_cpe", "compare_versions", "matches",
           "affected_matches", "verdict"]

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


# --- the newer structure ---------------------------------------------------
#
# NVD is migrating from CPE configurations to a CVE 5.0 `affected` structure, and a
# tool that reads only the old one silently answers "not affected" for every CVE
# published in the new form. That is the worst possible failure mode -- a quiet
# false negative -- so both structures are read, and a CVE that carries neither is
# reported as carrying no affected-product data rather than as not affecting
# anything.

def _normalise_product(text: str) -> str:
    """NVD writes "Palo Alto Networks" in one structure and `paloaltonetworks` in
    the other, so the two are compared after the same normalisation."""
    return (str(text or "").strip().lower()
            .replace(" ", "_").replace("-", "_").replace("/", "_"))


def _same_product(one: str, two: str) -> bool:
    """Two product or vendor names, compared the two ways NVD spells them.

    The `affected` structure uses the vendor's own name with spaces, and a CPE uses
    a single token with none: "Palo Alto Networks" against `paloaltonetworks`. A
    comparison that only collapsed spaces would miss every product whose name has
    more than one word, which is most of them.
    """
    one, two = _normalise_product(one), _normalise_product(two)
    if one == two:
        return True
    strip = lambda text: text.replace("_", "")
    return strip(one) == strip(two) and bool(strip(one))


def affected_matches(affected, target: Cpe) -> bool | None:
    """Does the CVE 5.0 `affected` block cover the target?

    Returns True, False, or None when the block carries no usable data -- `n/a`
    for the vendor, the product and the version, which NVD publishes for older
    CVEs and which cannot be matched to anything. None is not False: one is "this
    does not affect you" and the other is "nobody has said", and a report that
    treats them the same is guessing.
    """
    if not affected:
        return None
    usable = False
    for block in affected:
        for entry in block.get("affectedData") or []:
            vendor = _normalise_product(entry.get("vendor"))
            product = _normalise_product(entry.get("product"))
            if vendor in ("n_a", "na", "unknown", "") or product in ("n_a", "na", "unknown", ""):
                continue
            # The block carries real product names, so a product it does not name
            # is a product it says is not affected. That is a verdict, and it is
            # different from a block that names nothing at all.
            usable = True
            if not (_same_product(target.vendor, vendor)
                    and _same_product(target.product, product)):
                continue
            if _version_entry_covers(entry, target.version):
                return True
    return False if usable else None


def _version_entry_covers(entry: dict, version: str) -> bool:
    """Does one product's version list put `version` in the affected set?

    Each entry is a starting point with a status and an optional exclusive upper
    bound, and `changes` lists the points at which the status flips. The last
    entry whose start is at or below the version decides, which is how NVD
    describes a range that was patched and then reopened.
    """
    default = str(entry.get("defaultStatus") or "unknown").lower()
    chosen = None
    for candidate in entry.get("versions") or []:
        start = str(candidate.get("version") or "")
        if start.lower() in ("n/a", "all", ""):
            if start.lower() == "all":
                chosen = candidate
            continue
        if compare_versions(version, start) < 0:
            continue
        # A candidate with an upper bound describes a range and wins over a bare
        # point version; among ranges the latest start wins.
        bounded = bool(candidate.get("lessThan") or candidate.get("lessThanOrEqual"))
        chosen_bounded = bool(chosen and (chosen.get("lessThan") or chosen.get("lessThanOrEqual")))
        if chosen is None:
            chosen = candidate
        elif bounded and not chosen_bounded:
            chosen = candidate
        elif bounded == chosen_bounded and compare_versions(
                start, str(chosen.get("version") or "")) >= 0:
            chosen = candidate
    if chosen is None:
        return default == "affected"

    # An entry with no upper bound names that version, it does not open a range.
    # NVD writes {"version": "2020.1", "status": "affected"} to mean 2020.1 is
    # affected, not that everything from 2020.1 onward is -- and reading it the
    # second way reported the patched release as vulnerable. The differential test
    # against NVD's own answers is what caught it.
    upper = chosen.get("lessThan")
    upper_inclusive = chosen.get("lessThanOrEqual")
    if not upper and not upper_inclusive:
        if compare_versions(version, str(chosen.get("version") or "")) != 0:
            return False
        status = str(chosen.get("status") or default).lower()
        for change in chosen.get("changes") or []:
            at = change.get("at")
            if at and compare_versions(version, str(at)) >= 0:
                status = str(change.get("status") or status).lower()
        return status == "affected"

    status = str(chosen.get("status") or default).lower()
    if upper and compare_versions(version, str(upper)) >= 0:
        status = "unaffected"
    if upper_inclusive and compare_versions(version, str(upper_inclusive)) > 0:
        status = "unaffected"
    for change in chosen.get("changes") or []:
        at = change.get("at")
        if at and compare_versions(version, str(at)) >= 0:
            status = str(change.get("status") or status).lower()
    return status == "affected"


def verdict(configurations, affected, target: Cpe) -> dict:
    """The whole answer for one CVE against one target, and where it came from.

    A caller gets the decision and the structure that produced it, because a tool
    that says "not affected" has to be able to say which data it read to conclude
    that, and a CVE carrying neither structure is a different answer from a CVE
    that carries data saying no.
    """
    from_configurations = matches(configurations, target) if configurations else None
    from_affected = affected_matches(affected, target) if affected else None

    if from_configurations is True or from_affected is True:
        affected_flag, source = True, ("configurations" if from_configurations
                                       else "affected")
    elif from_configurations is False or from_affected is False:
        affected_flag = False
        source = ("configurations" if from_configurations is False else "affected")
        if from_configurations is False and from_affected is True:
            affected_flag, source = True, "affected"
    else:
        affected_flag, source = None, "none"
    return {"affected": affected_flag, "source": source,
            "configurations": from_configurations, "affected_block": from_affected}


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
