"""The directory as a directed graph an attacker moves through.

Every edge answers one question: if I control the tail, do I reach the head? An
access control entry grants its holder rights over the object it protects, so it
becomes an edge from the holder to the object. A session runs the other way, because
controlling the machine yields the identity logged into it. Those two directions are
the whole of the model, and getting either backwards produces a graph that looks
plausible and finds paths nobody could walk.

The graph is deliberately not deduplicated by right. The same pair of objects can
hold several rights, and which ones matter is a question for the path search rather
than for the graph -- collapsing them here would throw away the reason a path is
possible, which is the thing a reader most wants to know.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from .rights import capability_of, right_for
from .schema import CollectorData, Node

__all__ = ["Edge", "AttackGraph", "build_graph"]


@dataclass(frozen=True)
class Edge:
    """One relationship between two objects, and whether an attacker can walk it.

    `traversable` is the field that matters. A trust and a container relationship are
    both real and both belong in a report, and neither is a way to move: a trust lets
    a principal authenticate in the other domain and does not give it control of
    anything there, and a container holding an object says nothing at all about who
    may modify the object. Treating either as an attack edge invents paths nobody
    could walk, which is worse than missing some -- a fabricated route through a
    container looked exactly like a real finding until it was read closely.
    """

    source: str
    target: str
    kind: str                  # ace / membership / session / trust / containment
    right: str = ""
    capability: str = ""
    note: str = ""
    traversable: bool = True

    def as_dict(self) -> dict:
        return {"source": self.source, "target": self.target, "kind": self.kind,
                "right": self.right, "capability": self.capability,
                "traversable": self.traversable, "note": self.note}


@dataclass
class AttackGraph:
    data: CollectorData
    outgoing: dict = field(default_factory=lambda: defaultdict(list))
    incoming: dict = field(default_factory=lambda: defaultdict(list))
    edges: list = field(default_factory=list)
    unknown_rights: dict = field(default_factory=dict)
    # Identifiers a relationship points at that the collection does not contain. Four
    # edge builders record these and none of them could: the attribute was never
    # declared, so any forest with an unresolved reference raised AttributeError and
    # the whole analysis died. Nothing in this data resolves badly, which is the only
    # reason it never happened here.
    unknown_references: dict = field(default_factory=dict)
    # Populated collector fields that produced no edge, by field name.
    unmodelled: dict = field(default_factory=dict)

    def add(self, edge: Edge) -> None:
        self.edges.append(edge)
        self.outgoing[edge.source].append(edge)
        self.incoming[edge.target].append(edge)

    def node(self, sid: str) -> Node | None:
        return self.data.get(sid)

    def name_of(self, sid: str) -> str:
        node = self.data.get(sid)
        return node.name if node and node.name else sid

    def successors(self, sid: str) -> list:
        """Only the edges an attacker can actually walk."""
        return [edge for edge in self.outgoing.get(sid, []) if edge.traversable]

    def predecessors(self, sid: str) -> list:
        return [edge for edge in self.incoming.get(sid, []) if edge.traversable]

    def context_for(self, sid: str) -> list:
        """The relationships that are real but are not routes."""
        return [edge for edge in self.outgoing.get(sid, []) if not edge.traversable]

    def reachable_from(self, sid: str) -> set:
        """Every object reachable by following edges, by breadth-first search."""
        seen, queue = set(), [sid]
        while queue:
            current = queue.pop(0)
            for edge in self.successors(current):
                if edge.target not in seen:
                    seen.add(edge.target)
                    queue.append(edge.target)
        return seen

    def summary(self) -> dict:
        by_kind = defaultdict(int)
        by_capability = defaultdict(int)
        for edge in self.edges:
            by_kind[edge.kind] += 1
            if edge.capability:
                by_capability[edge.capability] += 1
        return {"nodes": len(self.data.nodes), "edges": len(self.edges),
                "traversable": sum(1 for e in self.edges if e.traversable),
                "context": sum(1 for e in self.edges if not e.traversable),
                "by_kind": dict(by_kind), "by_capability": dict(by_capability),
                "unknown_rights": dict(self.unknown_rights),
                "unknown_references": {k: sorted(v) for k, v in self.unknown_references.items()},
                "unmodelled": dict(self.unmodelled)}


def build_graph(data: CollectorData) -> AttackGraph:
    """Turn collector output into the graph, with every edge justified by a right."""
    graph = AttackGraph(data=data)

    for node in data.nodes.values():
        _add_access_control_edges(graph, node)
        _add_membership_edges(graph, node)
        _add_session_edges(graph, node)
        _add_local_membership_edges(graph, node)
        _add_privilege_edges(graph, node)
        _add_service_principal_edges(graph, node)
        _add_primary_group_edges(graph, node)
        _add_delegation_edges(graph, node)
        _add_sid_history_edges(graph, node)
        _add_policy_change_edges(graph, node)
        _add_certificate_authority_edges(graph, node)
        _add_trust_edges(graph, node)
        _add_containment_edges(graph, node)

    # Policy links are resolved after everything else, because a policy reaches every
    # object underneath the container it is linked to and the containment tree has to
    # be complete before that can be walked.
    _add_policy_edges(graph)

    # What the collector collected and this did not use. A tool that reads a field and
    # silently drops it is worse than one that never read it, because the report looks
    # complete either way -- the same reason an unknown right is reported rather than
    # treated as harmless.
    graph.unmodelled = _unmodelled_fields(graph)

    # A right that appears in the data and not in the table is recorded rather than
    # dropped. Treating an unknown right as harmless is the same mistake as treating
    # an unread rule as clear, and a directory can carry rights this has never seen.
    for sid, rights in graph.unknown_rights.items():
        graph.unknown_rights[sid] = sorted(rights)
    return graph


def _add_access_control_edges(graph: AttackGraph, node: Node) -> None:
    """Every entry on an object is an edge from its holder to the object."""
    for ace in node.aces:
        right = right_for(ace.right)
        if right is None:
            graph.unknown_rights.setdefault(node.sid, set()).add(ace.right)
            continue
        # The holder has to be an object in the collection. An entry naming a principal
        # that was not collected produced an edge to nothing, and a traversal would
        # follow it to a node that does not exist.
        if ace.principal_sid not in graph.data.nodes:
            graph.unknown_references.setdefault(node.sid, set()).add(ace.principal_sid)
            continue
        if right.traverses == "forward":
            source, target = ace.principal_sid, node.sid
        else:
            source, target = node.sid, ace.principal_sid
        graph.add(Edge(source=source, target=target, kind="ace", right=right.name,
                       capability=right.capability, note=right.note))


def _add_membership_edges(graph: AttackGraph, node: Node) -> None:
    """A group's members, and the group each object names as its primary group.

    Both run member-to-group, because controlling the member puts you inside the
    group and therefore inside everything the group can reach.
    """
    if node.kind == "group":
        for member_sid in node.members:
            if member_sid not in graph.data.nodes:
                graph.unknown_references.setdefault(node.sid, set()).add(member_sid)
                continue
            graph.add(Edge(source=member_sid, target=node.sid, kind="membership",
                           right="MemberOf",
                           capability=capability_of("MemberOf"),
                           note="the member holds every right the group holds"))
    if node.primary_group and node.kind in ("user", "computer"):
        if node.primary_group not in graph.data.nodes:
            graph.unknown_references.setdefault(node.sid, set()).add(node.primary_group)
        else:
            graph.add(Edge(source=node.sid, target=node.primary_group, kind="membership",
                           right="MemberOf", capability=capability_of("MemberOf"),
                           note="the primary group is a membership the collector records "
                                "separately from the member list"))
    # SID history is handled in _add_sid_history_edges, which checks that the identifier
    # was collected. This function also added it, unconditionally, so a resolvable
    # history entry produced two edges for one relationship and an unresolvable one
    # produced an edge to nothing.


def _add_session_edges(graph: AttackGraph, node: Node) -> None:
    """A session runs machine-to-user: compromising the machine yields the user.

    Three collections carry sessions and the first is the one that is usually empty.
    The registry and privileged collections hold the real ones in this data, and
    reading only the first missed every session in the forest.
    """
    if node.kind != "computer":
        return
    for label, sessions in (("a session", node.sessions),
                            ("a session recorded in the registry", node.registry_sessions),
                            ("a privileged session", node.privileged_sessions)):
        for user_sid in sessions:
            graph.add(Edge(source=node.sid, target=user_sid, kind="session",
                           right="HasSession", capability=capability_of("HasSession"),
                           note="compromising this machine yields the credentials of "
                                "whoever is logged into it (%s)" % label))


def _add_local_membership_edges(graph: AttackGraph, node: Node) -> None:
    """Membership of a machine's local administrators group.

    The group is identified by its well-known relative identifier rather than by its
    name, for the same reason as everywhere else: the name is a label. 544 is the
    local administrators group on every Windows machine, whatever it is called in the
    language the machine runs.
    """
    if node.kind != "computer":
        return
    for group in node.local_groups:
        group_id = str(group.get("ObjectIdentifier") or "")
        if not group_id.endswith("-544"):
            continue
        for member in group.get("Results") or []:
            member_sid = str(member.get("ObjectIdentifier") or "") \
                if isinstance(member, dict) else str(member)
            if not member_sid:
                continue
            graph.add(Edge(source=member_sid, target=node.sid, kind="ace",
                           right="LocalAdminTo", capability="access",
                           note="a member of the machine's local administrators group, "
                                "which is local administrator on that machine"))


def _add_privilege_edges(graph: AttackGraph, node: Node) -> None:
    """A right held on a machine, which is escalation on that machine."""
    if node.kind != "computer":
        return
    for entry in node.user_rights:
        privilege = str(entry.get("Privilege") or "")
        right = right_for(privilege)
        if right is None:
            if privilege:
                graph.unknown_rights.setdefault(node.sid, set()).add(privilege)
            continue
        for holder in entry.get("Results") or []:
            holder_sid = str(holder.get("ObjectIdentifier") or "") \
                if isinstance(holder, dict) else str(holder)
            if not holder_sid:
                continue
            graph.add(Edge(source=holder_sid, target=node.sid, kind="ace",
                           right=right.name, capability=right.capability,
                           note=right.note))


def _add_service_principal_edges(graph: AttackGraph, node: Node) -> None:
    """A service principal name, and where it is hosted.

    An account with an SPN can have a service ticket requested for it by any
    authenticated principal, and that ticket is encrypted with the account's password
    -- so the account is attackable offline. The host the service runs on is the
    machine the ticket grants access to.
    """
    if node.kind != "user":
        return
    names = node.properties.get("serviceprincipalnames") or []
    if names and node.enabled:
        graph.add(Edge(source=node.sid, target=node.sid, kind="ace",
                       right="Kerberoastable", capability="credential",
                       note="holds %d service principal name(s), so any authenticated "
                            "principal can request a ticket encrypted with its password"
                            % len(names)))
    for target in node.spn_targets:
        if not isinstance(target, dict):
            continue
        computer_sid = str(target.get("ComputerSID") or "")
        if not computer_sid:
            continue
        if graph.data.get(computer_sid) is None:
            graph.unknown_references.setdefault(node.sid, set()).add(computer_sid)
            continue
        service = str(target.get("Service") or "")
        right = right_for("SQLAdmin") if "SQL" in service.upper() else None
        graph.add(Edge(source=node.sid, target=computer_sid, kind="ace",
                       right=(right.name if right else "SPNHost"),
                       capability=(right.capability if right else "access"),
                       note="the account's service principal name is hosted on this "
                            "machine as %s, so the service ticket grants access to it"
                            % (service or "an unnamed service")))


# Fields that carry relationships, and the edge kind that would use each one. A field
# here that arrives populated and produces nothing is data the tool collected and
# discarded, and the report says so by name.
RELATIONSHIP_FIELDS = {
    "HasSIDHistory": "sid history -- a principal holding another domain's identifier, "
                     "which is a way across a trust",
    "AllowedToDelegate": "constrained delegation -- this principal may delegate to "
                         "those services",
    "AllowedToAct": "resource-based delegation -- this principal may act on behalf of "
                    "others",
    "GPOChanges": "what a policy changes on the machines it applies to, which is the "
                  "local group membership it grants",
    "DCRegistryData": "domain controller registry settings, among them the certificate "
                      "mapping methods and whether strong certificate binding is "
                      "enforced -- a weak mapping is what lets a certificate for one "
                      "identity be accepted as another",
    "UserRights": "rights held on a machine",
    "LocalGroups": "local group membership on a machine",
}


def _unmodelled_fields(graph: AttackGraph) -> dict:
    """Populated relationship fields that produced no edge, by name and by object.

    Read from the parsed nodes rather than the raw files, so a field the parser never
    captured is reported too -- that is the case that would otherwise be invisible.
    """
    produced = {edge.right for edge in graph.edges} | {"MemberOf", "HasSession",
                                                       "LocalAdminTo", "GPOAppliesTo"}
    missing = {}
    for node in graph.data.nodes.values():
        for field_name, meaning in RELATIONSHIP_FIELDS.items():
            value = (node.properties.get(field_name)
                     or node.properties.get(field_name.lower()))
            if value in (None, [], {}, ""):
                continue
            if field_name in produced or field_name.lower() in {p.lower() for p in produced}:
                continue
            missing.setdefault(field_name, {"meaning": meaning, "objects": []})
            if len(missing[field_name]["objects"]) < 5:
                missing[field_name]["objects"].append(node.name or node.sid)
    return missing


def _add_primary_group_edges(graph: AttackGraph, node: Node) -> None:
    """The primary group, which is membership the member list does not carry.

    A directory records a principal's primary group as an attribute on the principal
    rather than as an entry in the group's member list, and the two are not kept in
    step: an object can be in a group this way and in no member list at all. A domain
    controller is a member of Domain Controllers through its primary group, so reading
    only member lists is relying on the collector having resolved it.
    """
    if not node.primary_group:
        return
    if graph.data.get(node.primary_group) is None:
        return          # already recorded by the membership builder
    graph.add(Edge(source=node.sid, target=node.primary_group, kind="membership",
                   right="MemberOf", capability="membership",
                   note="the primary group, which is membership recorded on the member "
                        "rather than in the group's member list"))


def _add_delegation_edges(graph: AttackGraph, node: Node) -> None:
    """Delegation, which is the right to be somebody else to a service.

    Constrained delegation names the services a principal may present itself to, and
    the whole of the technique is that it can present itself as *any* user there --
    including one with rights the principal does not have. Resource-based delegation is
    the same right written on the target rather than on the holder.

    Both run from the holder to the service, and both are real routes rather than
    context: the target service treats the delegation as that identity.
    """
    for service_sid in node.allowed_to_delegate:
        if graph.data.get(service_sid) is None:
            graph.unknown_references.setdefault(node.sid, set()).add(service_sid)
            continue
        graph.add(Edge(source=node.sid, target=service_sid, kind="ace",
                       right="AllowedToDelegate", capability="control",
                       note="constrained delegation: may present itself to this service "
                            "as any user, so it authenticates there as whoever it likes"))
    for identity_sid in node.allowed_to_act:
        if graph.data.get(identity_sid) is None:
            graph.unknown_references.setdefault(node.sid, set()).add(identity_sid)
            continue
        graph.add(Edge(source=node.sid, target=identity_sid, kind="ace",
                       right="AllowedToAct", capability="control",
                       note="resource-based delegation: this principal may act on behalf "
                            "of the identity named here"))


def _add_sid_history_edges(graph: AttackGraph, node: Node) -> None:
    """SID history: an identifier from another domain carried into this one.

    This is what actually crosses a trust. A trust on its own permits authentication
    and grants nothing, which is why it is not walked -- but a principal carrying a SID
    from the other side already holds whatever that identifier was granted there. The
    edge is from the principal to the identifier it carries, so the permissions granted
    to the identifier become reachable by the principal.
    """
    for carried in node.sid_history:
        target = graph.data.get(carried)
        if target is None:
            # The identifier is from another domain and that domain's objects are not
            # in this collection. That is a fact worth reporting, not a parse failure:
            # the permissions it carries cannot be resolved without the other domain.
            graph.unknown_references.setdefault(node.sid, set()).add(carried)
            continue
        graph.add(Edge(source=node.sid, target=carried, kind="membership",
                       right="HasSIDHistory", capability="membership",
                       note="holds this identifier from another domain, so everything "
                            "granted to it applies to this principal"))


def _add_policy_change_edges(graph: AttackGraph, node: Node) -> None:
    """What a policy grants on the machines it applies to.

    A policy that adds a principal to a machine's local administrators group is a
    policy that makes that principal an administrator of that machine. The change is
    recorded against the policy and names the computers it affects, so the edge runs
    from the principal to each affected machine.
    """
    changes = node.gpo_changes or {}
    if not changes:
        return
    granted = {"LocalAdmins": "LocalAdminTo", "RemoteDesktopUsers": "RemoteInteractiveLogonRight",
               "DcomUsers": "ExecuteCommand", "PSRemoteUsers": "ExecuteCommand"}
    affected = []
    for computer in changes.get("AffectedComputers") or []:
        sid = str(computer.get("ObjectIdentifier") or computer) \
            if isinstance(computer, dict) else str(computer)
        if sid:
            affected.append(sid)
    for key, right_name in granted.items():
        for member in changes.get(key) or []:
            member_sid = str(member.get("ObjectIdentifier") or member) \
                if isinstance(member, dict) else str(member)
            if not member_sid:
                continue
            for computer_sid in affected:
                if graph.data.get(computer_sid) is None:
                    graph.unknown_references.setdefault(member_sid, set()).add(computer_sid)
                    continue
                graph.add(Edge(source=member_sid, target=computer_sid, kind="ace",
                               right=right_name, capability=capability_of(right_name) or "access",
                               note="this policy adds the principal to the machine's %s "
                                    "group, so the policy grants it there" % key))


def _add_certificate_authority_edges(graph: AttackGraph, node: Node) -> None:
    """Certificate services: the machine it runs on, its own permissions, its templates.

    An authority issues certificates for whatever the templates enabled on it permit,
    so a template that allows a subject alternative name is a route to any principal's
    identity. That is the escalation this models the *surface* for: which authority,
    where it runs, who can change it, and which templates are live on it.
    """
    if node.kind != "enterpriseca":
        return
    host = node.hosting_computer
    if host and graph.data.get(host) is not None:
        graph.add(Edge(source=host, target=node.sid, kind="ace", right="HostsCA",
                       capability="control",
                       note="the certificate authority runs on this machine, so "
                            "controlling the machine is controlling every certificate "
                            "it issues"))
    for ace in node.ca_security:
        if not isinstance(ace, dict):
            continue
        principal = str(ace.get("PrincipalSID") or "")
        right = right_for(str(ace.get("RightName") or ""))
        if not principal:
            continue
        if graph.data.get(principal) is None:
            graph.unknown_references.setdefault(node.sid, set()).add(principal)
            continue
        if right is None:
            graph.unknown_rights.setdefault(node.sid, set()).add(
                str(ace.get("RightName") or "?"))
            continue
        graph.add(Edge(source=principal, target=node.sid, kind="ace", right=right.name,
                       capability=right.capability,
                       note="%s on the certificate authority -- %s"
                            % (right.name, right.note)))
    for template in node.cert_templates:
        template_id = str(template.get("ObjectIdentifier") or "")
        target = graph.data.get(template_id)
        if target is None:
            graph.unknown_references.setdefault(node.sid, set()).add(template_id)
            continue
        graph.add(Edge(source=node.sid, target=template_id, kind="ace",
                       right="EnabledOnCA", capability="control",
                       note="the template is enabled on the authority, so whoever can "
                            "edit it can issue certificates from it"))


def _add_policy_edges(graph: AttackGraph) -> None:
    """A policy reaches every object underneath the container it is linked to.

    This is the one case where containment *is* an attack edge, and it is worth being
    precise about why. Holding an object says nothing about who may modify it, so
    containment is never walked. But a policy linked to a container is applied to the
    computers and users inside it, so whoever can edit the policy changes the
    configuration of every one of them -- which is control of them. The edge is from
    the policy, not from the container, and the descendants are resolved transitively
    because a policy applies to a whole subtree.

    The targets are limited to accounts and machines, and that limit is the point. A
    policy configures computers and users; it does not grant control of a *group
    object*. Applying the edge to every descendant produced a path from the default
    domain policy to the domain administrators group, which is not something anybody
    can walk -- the same category error as walking containment itself, and it read
    just as convincingly.
    """
    policies = {}
    for node in graph.data.nodes.values():
        if node.kind == "gpo":
            policies[node.sid.lower()] = node

    for node in graph.data.nodes.values():
        if node.kind not in ("domain", "ou", "container", "site"):
            continue
        for link in node.links:
            if not isinstance(link, dict):
                continue
            guid = str(link.get("GUID") or "").strip("{}").lower()
            policy = policies.get(guid)
            if policy is None:
                continue
            for descendant in _descendants(graph, node.sid):
                target_node = graph.data.get(descendant)
                if target_node is None or target_node.kind not in ("user", "computer"):
                    continue      # a policy configures accounts and machines, not groups
                graph.add(Edge(source=policy.sid, target=descendant, kind="ace",
                               right="GPOAppliesTo", capability="control",
                               note="the policy is linked to %s, so it applies to this "
                                    "object and editing it changes this object"
                                    % graph.name_of(node.sid)))


def _descendants(graph: AttackGraph, root: str) -> set:
    """Everything under a container, transitively."""
    found, frontier = set(), [root]
    children = {}
    for node in graph.data.nodes.values():
        if node.contained_by:
            children.setdefault(node.contained_by, []).append(node.sid)
    while frontier:
        current = frontier.pop()
        for child in children.get(current, []):
            if child not in found:
                found.add(child)
                frontier.append(child)
    return found


def _add_trust_edges(graph: AttackGraph, node: Node) -> None:
    """A domain trust, in the direction an attacker can move along it."""
    if node.kind != "domain":
        return
    for trust in node.trusts:
        target_name = str(trust.get("TargetDomainName") or "").strip().upper()
        if not target_name:
            continue
        # The collector names the target domain rather than its SID, so the target
        # is resolved by name against the domains actually present. A trust to a
        # domain nobody collected is recorded as unresolved rather than invented.
        target = next((other for other in graph.data.by_kind("domain")
                       if other.name.upper() == target_name), None)
        if target is None:
            # A trust is a relationship, and the domain it names was not collected.
            # Reporting it as a right the table does not know put it in the wrong
            # section: there is nothing unrecognised about it.
            graph.unknown_references.setdefault(node.sid, set()).add(
                "%s (trusted domain not collected)" % target_name)
            continue
        direction = str(trust.get("TrustDirection") or "").strip()
        graph.add(Edge(source=node.sid, target=target.sid, kind="trust",
                       right="TrustedBy", capability="access", traversable=False,
                       note="a %s trust between %s and %s. A trust permits "
                            "authentication across it; it does not grant control of "
                            "anything, so it is context rather than a route"
                            % (direction or "direction-unspecified", node.name,
                               target.name)))


def _add_containment_edges(graph: AttackGraph, node: Node) -> None:
    """A policy or container reaching everything inside it."""
    if not node.contained_by:
        return
    container = graph.data.get(node.contained_by)
    if container is None:
        return
    graph.add(Edge(source=container.sid, target=node.sid, kind="containment",
                   right="Contains", capability="", traversable=False,
                   note="the container holds the object. This is structure, not a "
                        "right: holding an object says nothing about who may modify "
                        "it, so it is reported and never walked"))
