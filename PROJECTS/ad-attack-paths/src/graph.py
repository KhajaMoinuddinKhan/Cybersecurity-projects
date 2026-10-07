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
                "unknown_rights": dict(self.unknown_rights)}


def build_graph(data: CollectorData) -> AttackGraph:
    """Turn collector output into the graph, with every edge justified by a right."""
    graph = AttackGraph(data=data)

    for node in data.nodes.values():
        _add_access_control_edges(graph, node)
        _add_membership_edges(graph, node)
        _add_session_edges(graph, node)
        _add_trust_edges(graph, node)
        _add_containment_edges(graph, node)

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
            graph.add(Edge(source=member_sid, target=node.sid, kind="membership",
                           right="MemberOf",
                           capability=capability_of("MemberOf"),
                           note="the member holds every right the group holds"))
    if node.primary_group and node.kind in ("user", "computer"):
        graph.add(Edge(source=node.sid, target=node.primary_group, kind="membership",
                       right="MemberOf", capability=capability_of("MemberOf"),
                       note="the primary group is a membership the collector records "
                            "separately from the member list"))
    # SID history is a membership in reverse: the token carries the SID, so whoever
    # controls the object holding the history controls the principal.
    for history_sid in node.sid_history:
        graph.add(Edge(source=node.sid, target=history_sid, kind="membership",
                       right="HasSIDHistory", capability=capability_of("HasSIDHistory"),
                       note="the principal's token carries this SID"))


def _add_session_edges(graph: AttackGraph, node: Node) -> None:
    """A session runs machine-to-user: compromising the machine yields the user."""
    if node.kind != "computer":
        return
    for user_sid in node.sessions:
        graph.add(Edge(source=node.sid, target=user_sid, kind="session",
                       right="HasSession", capability=capability_of("HasSession"),
                       note="compromising this machine yields the credentials of "
                            "whoever is logged into it"))


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
            graph.unknown_rights.setdefault(node.sid, set()).add(
                "trust to %s (domain not collected)" % target_name)
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
