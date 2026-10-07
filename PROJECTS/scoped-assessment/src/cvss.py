"""CVSS v3.1 base scores, computed from the vector rather than looked up.

A report that states a severity has to be able to defend it. Copying a number out
of a feed makes the number somebody else's assertion; computing it from the
published vector makes it arithmetic that a reader can check, and it means the
tool still works when the feed is down.

The vectors themselves are not invented. They are what NVD publishes for each CVE,
and `tests/test_cvss.py` checks this implementation against NVD's own base scores
across a spread of real CVEs -- the same differential approach the cryptography
toolkit uses, for the same reason: an implementation that agrees with its own test
vectors has proved only that it is self-consistent.

Specification: FIRST, "Common Vulnerability Scoring System v3.1: Specification
Document", sections 7.1 (base metrics) and 7.4 (the base equation).
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

__all__ = ["CvssError", "BaseScore", "parse_vector", "score", "severity_of"]

# Section 7.1. Every weight in the specification, in one place, with the metric
# it belongs to. Nothing here is a threshold this module chose.
_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {
        # the values depend on Scope, which is why they are split here
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},
        "C": {"N": 0.85, "L": 0.68, "H": 0.50},
    },
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}

_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

# Section 5.1, verbatim from the specification.
_SEVERITY_BANDS = ((0.0, "None"), (0.1, "Low"), (4.0, "Medium"), (7.0, "High"), (9.0, "Critical"))


class CvssError(ValueError):
    """The vector is not a CVSS v3.1 base vector."""


@dataclass(frozen=True)
class BaseScore:
    vector: str
    score: float
    severity: str
    impact: float
    exploitability: float

    def as_dict(self) -> dict:
        return {"vector": self.vector, "base_score": self.score, "severity": self.severity,
                "impact": round(self.impact, 4), "exploitability": round(self.exploitability, 4)}


def parse_vector(vector: str) -> dict:
    """The base metrics of a v3.1 vector, or an error naming what is wrong.

    Temporal and environmental metrics are ignored rather than rejected: a CVE
    published with them still has a base vector underneath, and the base score is
    what this module claims to compute.
    """
    text = str(vector or "").strip()
    if not text.upper().startswith("CVSS:3.1/"):
        raise CvssError("only CVSS v3.1 base vectors are supported, got %r" % vector)
    metrics = {}
    for part in text.split("/")[1:]:
        if ":" not in part:
            raise CvssError("%r is not a metric" % part)
        name, value = part.split(":", 1)
        name, value = name.strip().upper(), value.strip().upper()
        if name in _REQUIRED:
            metrics[name] = value
    missing = [name for name in _REQUIRED if name not in metrics]
    if missing:
        raise CvssError("the vector is missing %s" % ", ".join(missing))
    for name, value in metrics.items():
        if name == "S":
            if value not in ("U", "C"):
                raise CvssError("S must be U or C, got %r" % value)
        elif name in ("C", "I", "A"):
            if value not in _WEIGHTS["CIA"]:
                raise CvssError("%s must be H, L or N, got %r" % (name, value))
        elif name == "PR":
            # PR's weights are nested under Scope, so the permitted values are the
            # keys of either half rather than of the metric itself
            if value not in _WEIGHTS["PR"]["U"]:
                raise CvssError("PR must be N, L or H, got %r" % value)
        elif value not in _WEIGHTS[name]:
            raise CvssError("%s must be one of %s, got %r"
                            % (name, ", ".join(sorted(_WEIGHTS[name])), value))
    return metrics


def _roundup(value: float) -> float:
    """The specification's Roundup, section 7.1.

    Ceiling to one decimal place, defined through integer arithmetic because
    floating point ceilings get this wrong on values that are already one decimal
    place: 4.0 must stay 4.0 and not become 4.1.
    """
    scaled = int(round(value * 100000))
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def score(vector: str) -> BaseScore:
    """The base score of a CVSS v3.1 vector, per section 7.4."""
    metrics = parse_vector(vector)
    scope_changed = metrics["S"] == "C"

    # Impact, section 7.4
    iss = 1.0 - ((1.0 - _WEIGHTS["CIA"][metrics["C"]])
                 * (1.0 - _WEIGHTS["CIA"][metrics["I"]])
                 * (1.0 - _WEIGHTS["CIA"][metrics["A"]]))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    # Exploitability, section 7.4
    exploitability = (8.22 * _WEIGHTS["AV"][metrics["AV"]]
                      * _WEIGHTS["AC"][metrics["AC"]]
                      * _WEIGHTS["PR"]["C" if scope_changed else "U"][metrics["PR"]]
                      * _WEIGHTS["UI"][metrics["UI"]])

    if impact <= 0:
        base = 0.0
    elif scope_changed:
        base = _roundup(min(1.08 * (impact + exploitability), 10.0))
    else:
        base = _roundup(min(impact + exploitability, 10.0))

    return BaseScore(vector=vector, score=base, severity=severity_of(base),
                     impact=impact, exploitability=exploitability)


def severity_of(base: float) -> str:
    """The qualitative band for a base score, section 5.1."""
    name = "None"
    for floor, label in _SEVERITY_BANDS:
        if base >= floor:
            name = label
    return name


# A CVSS v3.1 vector is a fixed shape; this is used to find one inside a string
# that carries other text, such as a feed's description.
VECTOR_PATTERN = re.compile(r"CVSS:3\.1/[A-Za-z:/.\-]+")
