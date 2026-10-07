"""A finding: which control, which environment, and what was actually seen.

One shape for all four assessors, because the point of the policy being shared is
that the results are comparable across environments. A finding always names the
control it violates, and the control carries the standard it implements -- so a
reader can go from a line in a Dockerfile to a CIS control to an ISO 27001 Annex A
control without the chain being asserted anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["Evidence", "Finding", "ORDER"]


ORDER = ("critical", "high", "medium", "low", "info")


class Evidence:
    """What was actually in the artifact, kept verbatim.

    A finding without evidence is an assertion about somebody's configuration, and
    the first thing they will do is ask where it says that.
    """

    def __init__(self):
        self.items: list[dict] = []

    def add(self, kind: str, detail: str, value: str = "") -> None:
        self.items.append({"kind": kind, "detail": detail, "value": str(value)[:1200]})

    def as_list(self) -> list[dict]:
        return list(self.items)


@dataclass
class Finding:
    control_id: str
    environment: str
    target: str
    detail: str
    severity: str
    evidence: list[dict] = field(default_factory=list)
    location: str = ""

    @property
    def rank(self) -> int:
        try:
            return ORDER.index(self.severity)
        except ValueError:
            return len(ORDER)

    def as_dict(self) -> dict:
        return {"control": self.control_id, "environment": self.environment,
                "target": self.target, "detail": self.detail,
                "severity": self.severity, "evidence": self.evidence,
                "location": self.location}


def make(control, environment: str, target: str, detail: str, evidence=None,
         location: str = "") -> Finding:
    """Build a finding from a control, so the severity comes from the policy.

    The severity is not chosen by the assessor. It is the policy's statement about
    how much the control matters, which means changing it is a policy change and not
    a code change -- and the four assessors cannot disagree about it.
    """
    return Finding(control_id=control.id, environment=environment, target=target,
                   detail=detail, severity=control.severity,
                   evidence=(evidence.as_list() if evidence is not None else []),
                   location=location)
