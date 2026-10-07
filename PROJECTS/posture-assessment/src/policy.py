"""The policy, as data.

A control here is a value, not a paragraph in a document and not a rule buried in
one of the four assessors. That is the entire claim of this project: define the
intention once, state which environments it applies to, and let every assessor read
the same object. The alternative -- a Docker rule in one tool, a Kubernetes rule in
another and an IoT rule in a spreadsheet -- is three descriptions of one intention
that drift apart the first time somebody changes one of them.

The loader is deliberately strict about three things, because each of them is a way
a policy quietly stops being a policy:

  * A control that names an environment nothing implements is a claim rather than a
    control, so it is refused rather than loaded and never checked.
  * Two controls sharing an identifier make a finding ambiguous, so duplicates are
    refused.
  * A control with no intent is a rule without a reason, and a rule without a reason
    is the one somebody disables at three in the morning.

Standards referenced: CIS Docker Benchmark v1.6.0, CIS Kubernetes Benchmark v1.9.0,
ISO/IEC 27001:2022 Annex A, NIST CSF 2.0.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

__all__ = ["PolicyError", "Control", "Policy", "load_policy", "SEVERITIES",
           "DEFAULT_POLICY_PATH"]

SEVERITIES = ("critical", "high", "medium", "low", "info")

# The environments this platform knows how to assess. A control may only name one of
# these, and the loader checks that something implements each.
KNOWN_ENVIRONMENTS = ("container", "kubernetes", "iac", "iot")

DEFAULT_POLICY_PATH = Path(__file__).resolve().parent.parent / "policy" / "controls.yaml"


class PolicyError(ValueError):
    """The policy is not usable, and the message says which control and why."""


@dataclass(frozen=True)
class Control:
    """One intention, the environments it covers, and the standard it comes from."""

    id: str
    title: str
    intent: str
    applies_to: tuple
    severity: str
    remediation: str
    cis: str = ""
    iso27001: str = ""
    nist_csf: str = ""
    treatment: str = "mitigate"
    owner: str = ""

    def covers(self, environment: str) -> bool:
        return environment in self.applies_to

    @property
    def reference(self) -> str:
        """The external standard this control implements, for a reader to check."""
        return self.cis or self.iso27001 or ""

    def as_dict(self) -> dict:
        return {"id": self.id, "title": self.title, "severity": self.severity,
                "applies_to": list(self.applies_to), "cis": self.cis,
                "iso27001": self.iso27001, "nist_csf": self.nist_csf,
                "treatment": self.treatment, "owner": self.owner}


@dataclass
class Policy:
    version: int
    organisation: str
    environments: tuple
    controls: tuple
    source: str = ""
    _by_id: dict = field(default_factory=dict, repr=False)

    def __post_init__(self):
        self._by_id = {control.id: control for control in self.controls}

    def by_id(self, control_id: str) -> Control:
        try:
            return self._by_id[control_id]
        except KeyError:
            raise PolicyError("no control with id %r" % control_id) from None

    def for_environment(self, environment: str) -> tuple:
        """The controls that apply to one environment, in declaration order."""
        return tuple(c for c in self.controls if c.covers(environment))

    def coverage(self) -> dict:
        """How many controls each environment is checked against.

        Reported rather than assumed: an environment named in the policy with no
        controls behind it would be a claim the platform makes and never tests.
        """
        return {env: len(self.for_environment(env)) for env in self.environments}

    def as_dict(self) -> dict:
        return {"version": self.version, "organisation": self.organisation,
                "environments": list(self.environments),
                "controls": [c.as_dict() for c in self.controls],
                "coverage": self.coverage()}


def _require(mapping: dict, key: str, where: str):
    value = mapping.get(key)
    if value in (None, "", [], {}):
        raise PolicyError("%s is missing %r" % (where, key))
    return value


def load_policy(path: str | Path = DEFAULT_POLICY_PATH) -> Policy:
    """Read and validate the policy file."""
    path = Path(path)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise PolicyError("no policy at %s" % path) from None
    except yaml.YAMLError as exc:
        raise PolicyError("the policy is not valid YAML: %s" % exc) from None
    if not isinstance(raw, dict):
        raise PolicyError("the policy should be a mapping, got %s" % type(raw).__name__)

    version = raw.get("version")
    if version != 1:
        raise PolicyError("unsupported policy version %r; this reads version 1" % version)

    environments = tuple(_require(raw, "environments", "the policy"))
    unknown = [env for env in environments if env not in KNOWN_ENVIRONMENTS]
    if unknown:
        raise PolicyError("the policy names environments this platform cannot assess: %s"
                          % ", ".join(unknown))

    raw_controls = _require(raw, "controls", "the policy")
    if not isinstance(raw_controls, list):
        raise PolicyError("controls should be a list")

    controls = []
    seen = set()
    for index, entry in enumerate(raw_controls):
        where = "control %d" % (index + 1)
        if not isinstance(entry, dict):
            raise PolicyError("%s should be a mapping" % where)
        control_id = _require(entry, "id", where)
        where = "control %r" % control_id
        if control_id in seen:
            raise PolicyError("two controls share the id %r, which makes a finding "
                              "ambiguous" % control_id)
        seen.add(control_id)

        applies_to = tuple(_require(entry, "applies_to", where))
        unknown = [env for env in applies_to if env not in environments]
        if unknown:
            raise PolicyError("%s applies to %s, which the policy does not declare"
                              % (where, ", ".join(unknown)))

        severity = str(_require(entry, "severity", where)).lower()
        if severity not in SEVERITIES:
            raise PolicyError("%s has severity %r; expected one of %s"
                              % (where, severity, ", ".join(SEVERITIES)))

        controls.append(Control(
            id=control_id,
            title=str(_require(entry, "title", where)),
            intent=str(_require(entry, "intent", where)),
            applies_to=applies_to,
            severity=severity,
            remediation=str(_require(entry, "remediation", where)),
            cis=str(entry.get("cis") or ""),
            iso27001=str(entry.get("iso27001") or ""),
            nist_csf=str(entry.get("nist_csf") or ""),
            treatment=str(entry.get("treatment") or "mitigate"),
            owner=str(entry.get("owner") or ""),
        ))

    policy = Policy(version=version, organisation=str(raw.get("organisation") or ""),
                    environments=environments, controls=tuple(controls),
                    source=str(path))

    # Every declared environment has to have something behind it. An environment
    # named in the policy and checked by nothing is the platform claiming coverage
    # it does not have.
    for environment in environments:
        if not policy.for_environment(environment):
            raise PolicyError("the policy declares the %s environment but no control "
                              "applies to it" % environment)
    return policy
