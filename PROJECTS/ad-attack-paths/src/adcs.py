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

# The policy flag that lets a requester put any name in the subject alternative name
# of a certificate, whatever the template says. A certificate authority carrying it
# will issue a logon as anybody from a template that was never meant to.
SAN_FLAG = "EDITF_ATTRIBUTESUBJECTALTNAME2"

# The policy flag that makes the authority use the request's subject rather than the
# template's, which is the same outcome by a different route.
SUBJECT_FLAG = "EDITF_SUBJECTALTNAMECHECKONREQUEST"

# Rights over a certificate authority or another public key object that let its holder
# change it, which is the authority itself.
PKI_WRITE_RIGHTS = frozenset({"GenericAll", "GenericWrite", "WriteDacl", "WriteOwner",
                              "WriteProperty", "Owns", "ManageCA", "ManageCertificates"})

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
        if "ESC1" in self.conditions or "ESC6" in self.conditions:
            return "Critical" if self.exploitable or "ESC6" in self.conditions else "High"
        # ESC5 and ESC7 are the authority itself being changeable by somebody who
        # should not be able to change it, which reaches every certificate it issues.
        # The first version graded them Low, which put a workstation that can rewrite
        # the authority's permissions below a template nobody can enroll in.
        if "ESC5" in self.conditions or "ESC7" in self.conditions:
            return "Critical" if self.principals else "Low"
        if "ESC4" in self.conditions or "ESC2" in self.conditions:
            return "High" if self.exploitable else "Medium"
        if "ESC15" in self.conditions:
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


def _schema_one_supplies_subject(properties: dict) -> bool:
    """Whether a version-one template lets the requester choose the subject.

    Version-one templates predate the name flags, so the subject is taken from the
    request rather than from the template, and the request can carry a subject
    alternative name that the authority copies into the certificate. A version-two
    template with the same intent is ESC1 and is caught there; this is the same outcome
    reached by the older schema, which the name flags do not describe at all.
    """
    try:
        version = int(properties.get("schemaversion"))
    except (TypeError, ValueError):
        return False
    if version != 1:
        return False
    return properties.get("enrolleesuppliessubject") is True


def assess_authority(authority, privileged=frozenset()) -> list:
    """The conditions that belong to the authority rather than to a template.

    ESC5 is a public key object a principal without administrative rights can write to,
    which is the authority's permissions being changeable by somebody who should not be
    able to change them. ESC6 is a policy flag that makes every template able to carry a
    chosen name, whether or not the template permits it. ESC7 is the authority being
    manageable by such a principal, which reaches the same place through its
    configuration.
    """
    found = []
    properties = authority.properties or {}
    flags = str(properties.get("flags") or "").upper()
    for flag, condition, note in (
            (SAN_FLAG, "ESC6",
             "the authority is flagged to accept a subject alternative name from the "
             "request, so every template it issues can carry a name the template does "
             "not permit"),
            (SUBJECT_FLAG, "ESC6",
             "the authority is flagged to take the subject from the request rather than "
             "the template, so a certificate can name anybody")):
        if flag in flags:
            found.append(Escalation(template_sid=authority.sid, template=authority.name,
                                    authority=authority.name, conditions=[condition],
                                    note=note))

    holders = {}
    for ace in authority.aces:
        if ace.right not in PKI_WRITE_RIGHTS or ace.principal_sid in privileged:
            continue
        holders.setdefault(ace.right, set()).add(ace.principal_sid)
    if holders:
        writers = sorted({sid for group in holders.values() for sid in group})
        found.append(Escalation(
            template_sid=authority.sid, template=authority.name,
            authority=authority.name, conditions=["ESC5", "ESC7"],
            principals=writers,
            note="a principal without administrative rights can change this authority's "
                 "permissions or its configuration (%s), and managing an authority is "
                 "enabling a template that is not enabled"
                 % ", ".join(sorted(holders))))
    return found


def assess_certificate_binding(data) -> dict:
    """Whether a certificate for one identity can be accepted as another.

    Two registry settings decide it, and they are the difference between a stolen
    certificate being useless and being a logon. Neither is populated in this data, and
    that is reported as unknown rather than as safe -- an uncollected setting is not a
    setting that is off, which is the same mistake as treating an unread rule as clear.
    """
    def reading(entry):
        """The value, or None when the collector did not read it.

        The registry entries are objects carrying a value, a Collected flag and a
        failure reason. The first version of this checked only whether a value was
        present, and every entry has one -- so three machines that were refused access
        were reported as read, with a value of zero, which is the most dangerous
        possible answer: it says weak binding is switched off when nobody knows.
        """
        if not isinstance(entry, dict):
            return entry
        if entry.get("Collected") is False:
            return None
        return entry.get("Value")

    seen = {"collected": [], "missing": []}
    for node in data.by_kind("computer"):
        registry = node.dc_registry or {}
        if not registry:
            continue
        mapping = reading(registry.get("CertificateMappingMethods"))
        binding = reading(registry.get("StrongCertificateBindingEnforcement"))
        if mapping is None and binding is None:
            seen["missing"].append(node.name)
        else:
            seen["collected"].append({"computer": node.name, "mapping": mapping,
                                      "binding": binding})
    return seen


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
    if _schema_one_supplies_subject(properties):
        conditions.append("ESC15")     # a version-one template takes the request's name

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
        "ESC15": "a version-one template takes the subject from the request, so the "
                 "request can name anybody -- the name flags do not describe this, "
                 "because the schema predates them",
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


@dataclass
class Chain:
    """Two conditions that combine into something neither is on its own.

    Each template is judged on its own attributes and the judgement is correct. The
    mistake is stopping there: a template that lets its holder request certificates on
    behalf of others is not itself a takeover, and a template that lets the requester
    choose the subject is not itself reachable. Together they are neither of those
    things -- the first is how you get the credential the second accepts.
    """

    templates: list = field(default_factory=list)
    conditions: list = field(default_factory=list)
    severity: str = "High"
    note: str = ""

    def as_dict(self) -> dict:
        return {"templates": list(self.templates), "conditions": list(self.conditions),
                "severity": self.severity, "note": self.note}


def certificate_chains(escalations) -> list:
    """The combinations, reported beside the individual findings rather than instead.

    Two are modelled, and both are stated as the sequence rather than as a label:

    - a **request agent** template beside one that lets the requester supply the
      subject: enrol in the first, and the certificate it issues is accepted by the
      second on behalf of anybody. Neither template is a takeover alone.
    - **manage the authority** beside anything else: the right to change an authority's
      configuration is the right to enable a template that was not enabled, so it
      combines with every condition present.
    """
    by_condition = {}
    for escalation in escalations:
        for condition in escalation.conditions:
            by_condition.setdefault(condition, []).append(escalation)

    chains = []
    if "ESC3" in by_condition and "ESC1" in by_condition:
        chains.append(Chain(
            templates=sorted({e.template for e in by_condition["ESC3"]} |
                             {e.template for e in by_condition["ESC1"]}),
            conditions=["ESC3", "ESC1"],
            severity="Critical",
            note="the request agent certificate from the first is accepted by the "
                 "second on behalf of any principal, so the pair issues a logon as "
                 "anybody -- neither template is a takeover on its own"))
    if "ESC3" in by_condition and "ESC2" in by_condition:
        chains.append(Chain(
            templates=sorted({e.template for e in by_condition["ESC3"]} |
                             {e.template for e in by_condition["ESC2"]}),
            conditions=["ESC3", "ESC2"],
            severity="High",
            note="the request agent certificate is accepted by the any-purpose "
                 "template on behalf of any principal"))
    return chains


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
    for authority in data.by_kind("enterpriseca"):
        found.extend(assess_authority(authority, privileged))
    for template in data.by_kind("certtemplate"):
        if template.sid not in enabled_by:
            continue          # a template nobody has enabled cannot issue anything
        found.extend(assess_template(template, enabled_by[template.sid], privileged))

    # Every finding, whichever assessment produced it, has its identifiers resolved to
    # names on the way out. The authority findings skipped this and printed a SID where
    # the template findings printed a name.
    for escalation in found:
        escalation.enrollee_names = [graph.name_of(sid) for sid in escalation.enrollees]
        escalation.principals = [graph.name_of(sid) for sid in escalation.principals]
    found.sort(key=lambda e: (e.severity, e.template))
    return found


def authority_managers(data, graph, privileged=frozenset()) -> list:
    """Who can change an authority's configuration, and what that means.

    The right to manage an authority is the right to enable a template that was not
    enabled, so it is not a condition of its own but a multiplier on every condition
    present. Reported separately because that is what it is.
    """
    managers = []
    for node in data.nodes.values():
        if node.kind != "enterpriseca":
            continue
        # The rights point *into* the authority: the holder is the source and the
        # authority is the target, so these are its predecessors and not its successors.
        for edge in graph.predecessors(node.sid):
            if edge.right not in ("ManageCA", "ManageCertificates"):
                continue
            if edge.source in privileged:
                continue          # an administrator managing the authority is intended
            # Three objects share the name ESSOS-CA -- the root, the intermediate and
            # the issuing authority -- so a name alone does not say which one this is.
            managers.append({"authority": node.name, "authority_sid": node.sid,
                             "authority_kind": node.kind,
                             "principal": graph.name_of(edge.source),
                             "principal_sid": edge.source,
                             "right": edge.right,
                             "note": "may change this authority's configuration, which "
                                     "includes enabling a template that is not enabled"})
    return managers
