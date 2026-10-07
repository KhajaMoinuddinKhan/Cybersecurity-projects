"""Certificate services escalation, derived from the templates rather than their names.

An authority issues a certificate for whatever the templates enabled on it permit, and
a template that lets the requester choose the subject, or that carries an
authentication purpose, is a route to any principal's identity. That is the whole of
the technique: request a certificate naming somebody else, authenticate with it.

The templates in this data are literally named `ESC1`, `ESC2`, `ESC3` and `ESC4`,
which is a gift and a trap. Matching those names would pass every test in this file
and would be worthless -- the same mistake as looking for the group called "Domain
Admins". The conditions below are read from the attributes that make each one true,
and there is a test asserting the detector finds these templates with the names
stripped off.

The conditions are the published ones, stated as attributes:

- a template that lets the **enrollee supply the subject** is a certificate for any
  identity, and if it also carries an **authentication purpose** that certificate is a
  logon as that identity. That is ESC1.
- a template carrying the **any purpose** purpose is accepted wherever any certificate
  would be, including authentication. That is ESC2.
- a template carrying the **certificate request agent** purpose lets its holder request
  certificates on behalf of others. That is ESC3.
- a template a **low-privileged principal can write** can be changed into any of the
  above. That is ESC4, and it is a property of the template's permissions rather than
  of its settings.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Extended key usages, by the identifier that appears in the template.
CLIENT_AUTHENTICATION = "1.3.6.1.5.5.7.3.2"
SMART_CARD_LOGON = "1.3.6.1.4.1.311.20.2.2"
ANY_PURPOSE = "2.5.29.37.0"
CERTIFICATE_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"

# An authentication purpose: a certificate carrying one of these is a logon.
AUTHENTICATION_EKUS = frozenset({CLIENT_AUTHENTICATION, SMART_CARD_LOGON, ANY_PURPOSE})

# Rights over a template that let its holder change it.
WRITE_RIGHTS = frozenset({"GenericAll", "GenericWrite", "WriteDacl", "WriteOwner",
                          "WriteProperty", "AllExtendedRights", "Owns"})

# Rights that let a principal obtain a certificate from a template. Enrollment is the
# one that matters: a template that permits an escalation nobody can enroll in is a
# configuration waiting to happen, and a template that permits one *and* grants
# enrollment to a wide group is a live route.
ENROLLMENT_RIGHTS = frozenset({"Enroll", "AutoEnroll", "GenericAll",
                               "AllExtendedRights", "Owns"})


@dataclass
class Escalation:
    """One template, and the conditions that make it dangerous."""

    template_sid: str
    template: str
    authority: str
    conditions: list = field(default_factory=list)
    # who can change the template (ESC4)
    principals: list = field(default_factory=list)
    # who can obtain a certificate from it -- the difference between a template that
    # permits an escalation and one somebody can actually use
    enrollees: list = field(default_factory=list)
    # The same principals by name. A report that prints SIDs makes the reader look each
    # one up, which is the work the report exists to save them.
    enrollee_names: list = field(default_factory=list)
    note: str = ""

    @property
    def severity(self) -> str:
        """Graded by what can actually be done, not by the condition's name.

        A template that permits an escalation nobody can enroll in is a misconfiguration
        waiting for one permission change; one that any authenticated principal can
        enroll in is a live route. Reporting both as Critical would put the two
        together, and the second is the one that matters.
        """
        if "ESC1" in self.conditions:
            return "Critical" if self.exploitable else "High"
        if "ESC4" in self.conditions or "ESC2" in self.conditions:
            return "High" if self.exploitable else "Medium"
        return "Medium" if self.exploitable else "Low"

    def describe(self) -> str:
        return "%s (%s)" % (self.template, ", ".join(self.conditions))

    @property
    def exploitable(self) -> bool:
        """Whether somebody can actually obtain a certificate from this template.

        A template whose conditions are met but which only its administrators can
        enroll in is a misconfiguration with no way in. One that any authenticated
        principal can enroll in is a live route, and the difference is worth stating
        rather than leaving to the reader to work out from the permissions.
        """
        return bool(self.enrollees)

    def as_dict(self) -> dict:
        """An explicit serialiser. `__dict__` would omit severity, which is a property
        and therefore not an instance attribute, and the report would key-error on it."""
        return {"template": self.template, "template_sid": self.template_sid,
                "authority": self.authority, "conditions": list(self.conditions),
                "principals": list(self.principals), "enrollees": list(self.enrollees),
                "enrollee_names": list(self.enrollee_names),
                "severity": self.severity, "exploitable": self.exploitable,
                "note": self.note}


def _ekus(properties: dict) -> set:
    """Every purpose the template carries, under whichever spelling the collector used."""
    found = set()
    for key in ("ekus", "effectiveekus", "certificateapplicationpolicy",
                "applicationpolicies"):
        for value in properties.get(key) or []:
            found.add(str(value))
    return found


def _supplies_own_subject(properties: dict) -> bool:
    """Whether the requester may choose the name that goes in the certificate.

    The collector states this twice -- as a boolean and as the name flag -- and either
    is enough. Reading only the boolean would miss a collector that set only the flag.
    """
    if properties.get("enrolleesuppliessubject") is True:
        return True
    flag = str(properties.get("certificatenameflag") or "")
    return "ENROLLEE_SUPPLIES_SUBJECT" in flag.upper()


def _authenticates(properties: dict) -> bool:
    """Whether a certificate from this template can be used to log on."""
    if properties.get("authenticationenabled") is False:
        return False
    return bool(_ekus(properties) & AUTHENTICATION_EKUS)


def assess_template(template, authorities=(), privileged=frozenset()) -> list:
    """The conditions a single template satisfies. Derived, never matched on its name."""
    properties = template.properties or {}
    ekus = _ekus(properties)
    conditions = []
    writers = _unprivileged_writers(template, privileged)

    if _supplies_own_subject(properties) and _authenticates(properties):
        conditions.append("ESC1")      # a certificate for any identity, usable to log on
    if ANY_PURPOSE in ekus:
        conditions.append("ESC2")      # accepted wherever any certificate would be
    if CERTIFICATE_REQUEST_AGENT in ekus:
        conditions.append("ESC3")      # may request certificates for others
    if writers:
        conditions.append("ESC4")      # a principal without rights can edit it

    if not conditions:
        return []
    note = {
        "ESC1": "the requester chooses the subject and the certificate authenticates, "
                "so this issues a logon as any principal",
        "ESC2": "the certificate carries the any-purpose purpose, so it is accepted "
                "wherever any certificate would be, authentication included",
        "ESC3": "the certificate carries the certificate request agent purpose, so its "
                "holder can request certificates on behalf of others",
        "ESC4": "a principal without administrative rights can write to this template, "
                "so it can be changed into any of the other conditions",
    }
    return [Escalation(
        template_sid=template.sid,
        template=template.name,
        authority=authorities[0] if authorities else "",
        conditions=conditions,
        principals=sorted(writers or {ace.principal_sid for ace in template.aces
                                      if ace.right in WRITE_RIGHTS}),
        enrollees=sorted({ace.principal_sid for ace in template.aces
                          if ace.right in ENROLLMENT_RIGHTS}),
        note="; ".join(note[c] for c in conditions),
    )]


def _unprivileged_writers(template, privileged) -> set:
    """The principals who can write to the template and are not already privileged.

    The filter is the condition, not a refinement of it. ESC4 is a template that a
    principal *without* administrative rights can edit; a template only its
    administrators can write to is the intended configuration, not a finding. Reading
    every write right as ESC4 reported twenty-five of the twenty-seven templates in
    this forest, including the ones for domain controllers and administrators -- which
    is worse than reporting nothing, because it buries the two that are real.

    Privileged means what it means everywhere else here: a crown jewel, or anything
    that can reach one. That set is computed before this runs.
    """
    return {ace.principal_sid for ace in template.aces
            if ace.right in WRITE_RIGHTS and ace.principal_sid not in privileged}


def certificate_escalations(data, graph, privileged=frozenset()) -> list:
    """Every template reachable from an enabled authority that satisfies a condition.

    `privileged` is the set of principals that are already a crown jewel or can reach
    one. It is what makes ESC4 mean anything, so a caller that omits it gets every
    write right reported as a finding and should not.
    """
    enabled_by = {}
    for node in data.nodes.values():
        if node.kind != "enterpriseca":
            continue
        for edge in graph.successors(node.sid):
            if edge.right == "EnabledOnCA":
                enabled_by.setdefault(edge.target, []).append(node.name)

    found = []
    for template in data.by_kind("certtemplate"):
        if template.sid not in enabled_by:
            continue          # a template nobody has enabled cannot issue anything
        for escalation in assess_template(template, enabled_by[template.sid], privileged):
            escalation.enrollee_names = [graph.name_of(sid) for sid in escalation.enrollees]
            escalation.principals = [graph.name_of(sid) for sid in escalation.principals]
            found.append(escalation)
    found.sort(key=lambda e: (e.severity, e.template))
    return found
