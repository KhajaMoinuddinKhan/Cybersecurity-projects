"""The risk register: what was found, who owns it, and what will be done.

A list of findings is not a risk register. A register says, for each thing, which
control it violates, which management-system control that maps to, who is accountable
for it, what treatment has been decided and whether it is open. That is the document
an auditor asks for, and it is the difference between a scan and a governance
artefact.

The mapping is not invented here: it comes from the policy. Each control carries its
ISO/IEC 27001:2022 Annex A reference and its NIST CSF 2.0 function, so a register
entry inherits both from the control it violates rather than being assigned them by
the assessor. One intention, one mapping, one owner.

The risk rating is derived from the control's severity rather than scored per
finding. That is a deliberate choice and worth stating: a per-finding likelihood
score would need an estimate of exploitability that nothing in this tool measures,
and inventing one would make the register look more precise than the evidence behind
it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["RegisterEntry", "build_register", "summarise"]

# Severity to a rating an auditor recognises. Derived, not estimated.
RATING = {"critical": "Critical", "high": "High", "medium": "Medium",
          "low": "Low", "info": "Informational"}

# The order the register is presented in: worst first, then by environment so a team
# reading it sees their own estate together.
_ENVIRONMENT_ORDER = ("container", "kubernetes", "iac", "iot")


@dataclass
class RegisterEntry:
    reference: str
    control_id: str
    control_title: str
    environment: str
    target: str
    location: str
    severity: str
    rating: str
    iso27001: str
    nist_csf: str
    cis: str
    owner: str
    treatment: str
    detail: str
    evidence: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"reference": self.reference, "control": self.control_id,
                "control_title": self.control_title, "environment": self.environment,
                "target": self.target, "location": self.location,
                "severity": self.severity, "rating": self.rating,
                "iso27001": self.iso27001, "nist_csf": self.nist_csf, "cis": self.cis,
                "owner": self.owner, "treatment": self.treatment,
                "detail": self.detail, "evidence": self.evidence}


def build_register(policy, findings) -> list:
    """Turn findings into register entries, with a stable reference for each.

    The reference is assigned by position after sorting, so it is the same every run
    for the same set of findings -- a register whose identifiers move between runs is
    one nobody can track a decision against.
    """
    from .findings import ORDER

    ordered = sorted(findings, key=lambda f: (
        ORDER.index(f.severity) if f.severity in ORDER else len(ORDER),
        _ENVIRONMENT_ORDER.index(f.environment)
        if f.environment in _ENVIRONMENT_ORDER else len(_ENVIRONMENT_ORDER),
        f.control_id, f.target, f.location))

    entries = []
    for index, finding in enumerate(ordered, 1):
        control = policy.by_id(finding.control_id)
        entries.append(RegisterEntry(
            reference="RISK-%03d" % index,
            control_id=control.id, control_title=control.title,
            environment=finding.environment, target=finding.target,
            location=finding.location, severity=finding.severity,
            rating=RATING.get(finding.severity, finding.severity.title()),
            iso27001=control.iso27001, nist_csf=control.nist_csf, cis=control.cis,
            owner=control.owner, treatment=control.treatment,
            detail=finding.detail, evidence=finding.evidence))
    return entries


def summarise(policy, entries) -> dict:
    """The counts an auditor asks for, and the gaps the register itself shows."""
    by_severity, by_environment, by_owner, by_iso, by_function = {}, {}, {}, {}, {}
    for entry in entries:
        by_severity[entry.severity] = by_severity.get(entry.severity, 0) + 1
        by_environment[entry.environment] = by_environment.get(entry.environment, 0) + 1
        by_owner[entry.owner] = by_owner.get(entry.owner, 0) + 1
        iso = entry.iso27001.split()[0] if entry.iso27001 else "unmapped"
        by_iso[iso] = by_iso.get(iso, 0) + 1
        function = entry.nist_csf.split()[0] if entry.nist_csf else "unmapped"
        by_function[function] = by_function.get(function, 0) + 1

    # Controls the policy defines that nothing violated. Reported because a register
    # showing only failures cannot distinguish a control that is satisfied from one
    # that was never checked, and that distinction is the point of the register.
    violated = {entry.control_id for entry in entries}
    satisfied = [c.id for c in policy.controls if c.id not in violated]

    return {
        "total": len(entries),
        "by_severity": by_severity,
        "by_environment": by_environment,
        "by_owner": by_owner,
        "by_iso27001": by_iso,
        "by_nist_csf": by_function,
        "controls_violated": sorted(violated),
        "controls_satisfied": satisfied,
        "controls_total": len(policy.controls),
        "environments_assessed": sorted(by_environment),
        "coverage": policy.coverage(),
    }
