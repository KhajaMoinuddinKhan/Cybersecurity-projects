"""What counts as a crown jewel, worked out from the directory rather than listed.

The obvious way to write this is to look for the group called "Domain Admins" and
call it a day. That is wrong twice over: it hard-codes an answer the data already
contains, and it finds nothing in a directory that has renamed the group, or
localised it, or built its own privileged group instead. The name is a label; the
question is what the object can actually do.

So the seed set is derived from four things, none of which is a name:

  * the well-known relative identifiers -- 512, 516, 518, 519, 520, 521 -- which are
    part of the specification rather than part of any directory. Domain Admins is
    RID 512 in every domain whatever it is called;
  * the ``admincount`` attribute, which the directory itself sets on an object when
    it is placed in a protected group. That is the directory's own answer to "is
    this privileged", and it survives renaming;
  * holding both halves of replication on the domain object -- GetChanges with
    GetChangesAll -- because that is the ability to read every secret in the domain,
    which is domain control by another route;
  * being a domain controller, which holds the directory database.

Those are seeds. The set is then closed under the graph: anything from which a seed
can be reached is itself a crown jewel, because controlling it controls the seed.
That closure is the actual definition, and it is why a plain user with a write
permission over a domain controller is a crown jewel in this analysis even though
nothing about the user looks privileged.
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["Tier0Error", "CrownJewel", "WELL_KNOWN_PRIVILEGED_RIDS", "seed_set",
           "crown_jewels"]

# Relative identifiers that are privileged in every Active Directory domain. These
# are specification values, the same way a well-known port is: they identify the
# built-in groups and accounts wherever the directory is and whatever it calls them.
WELL_KNOWN_PRIVILEGED_RIDS = {
    "500": "the built-in Administrator account",
    "512": "the domain administrators group",
    "516": "the domain controllers group",
    "518": "the schema administrators group",
    "519": "the enterprise administrators group",
    "520": "the group policy creator owners group",
    "521": "the read-only domain controllers group",
    "498": "the enterprise read-only domain controllers group",
    "502": "the key distribution service group, which can read every key",
}


class Tier0Error(ValueError):
    """The crown-jewel set could not be derived, and says why."""


@dataclass
class CrownJewel:
    """One object that is worth controlling, and the reason it is.

    A seeded jewel is privileged on its own evidence. A derived one is not: it is an
    object from which a seeded one can be reached, and `path` is the route that makes
    it a jewel. That path is the finding -- "this account is a crown jewel because
    these three steps lead from it to Domain Admins" is the sentence the whole tool
    exists to produce.
    """

    sid: str
    name: str
    kind: str
    reasons: list = field(default_factory=list)
    derived: bool = False
    path: list = field(default_factory=list)      # edges from here to a seeded jewel
    reaches: str = ""                             # the seeded jewel it reaches

    @property
    def hops(self) -> int:
        return len(self.path)

    def as_dict(self, graph=None) -> dict:
        return {"sid": self.sid, "name": self.name, "kind": self.kind,
                "reasons": list(self.reasons), "derived": self.derived,
                "hops": self.hops, "reaches": self.reaches,
                "steps": [{"from": graph.name_of(e.source) if graph else e.source,
                           "to": graph.name_of(e.target) if graph else e.target,
                           "right": e.right or e.kind,
                           "capability": e.capability,
                           "why": e.note} for e in self.path]}


def seed_set(data) -> dict:
    """The objects that are privileged on their own evidence, with the reason."""
    reasons: dict = {}

    def note(sid: str, why: str) -> None:
        reasons.setdefault(sid, [])
        if why not in reasons[sid]:
            reasons[sid].append(why)

    for node in data.nodes.values():
        # the specification's own identifiers
        if node.rid in WELL_KNOWN_PRIVILEGED_RIDS:
            note(node.sid, "it is %s (RID %s)"
                 % (WELL_KNOWN_PRIVILEGED_RIDS[node.rid], node.rid))
        # the directory's own flag
        if node.admin_count:
            note(node.sid, "the directory marks it adminCount, so it sits in a "
                           "protected group")

    # replication rights on a domain: both halves are needed, and which principal
    # holds them comes out of the access control data rather than out of a name
    for domain in data.by_kind("domain"):
        holders: dict = {}
        for ace in domain.aces:
            holders.setdefault(ace.principal_sid, set()).add(ace.right)
        for principal, held in holders.items():
            if {"GetChanges", "GetChangesAll"} <= held or "DCSync" in held:
                note(principal, "it holds replication on %s, which reads every secret "
                                "in the domain" % (domain.name or domain.sid))

    # domain controllers hold the directory database itself
    dc_group_rids = {"516", "521", "498"}
    for group in data.by_kind("group"):
        if group.rid in dc_group_rids:
            note(group.sid, "it is %s (RID %s)"
                 % (WELL_KNOWN_PRIVILEGED_RIDS.get(group.rid, "a domain controller "
                    "group"), group.rid))
            for member_sid in group.members:
                member = data.get(member_sid)
                if member and member.kind == "computer":
                    note(member_sid, "it is a domain controller, and holds the "
                                     "directory database")
    return reasons


def crown_jewels(data, graph, include_derived: bool = True) -> list:
    """The seeds, closed under the graph.

    Anything that can reach a crown jewel is one, because controlling it controls
    the jewel. The closure runs to a fixed point: taking over a crown jewel reaches
    what *it* can reach, so the set grows until it stops growing.
    """
    seeds = seed_set(data)
    if not seeds:
        raise Tier0Error(
            "no privileged object could be derived from this data. The seed set comes "
            "from well-known relative identifiers, the adminCount attribute, "
            "replication rights on a domain and domain controllers; finding none of "
            "them means the archive is incomplete rather than that the domain is "
            "unprivileged, and reporting no crown jewels would be the wrong answer to "
            "give.")

    reasons = {sid: list(why) for sid, why in seeds.items()}
    routes = {sid: [] for sid in seeds}          # path from the jewel down to a seed
    frontier = list(seeds)
    derived = set()

    while frontier and include_derived:
        current = frontier.pop()
        # The closure runs one way. Everything that can *reach* a crown jewel is one,
        # because controlling it controls the jewel. Nothing a crown jewel can reach
        # is added: a domain administrator can reach a file share, and that does not
        # make the file share a thing worth protecting. Closing in both directions
        # was the first attempt and it swallowed three hundred of the three hundred
        # and thirty-one objects, which is the same as saying nothing.
        for edge in graph.predecessors(current):
            source = edge.source
            if source in reasons or data.get(source) is None:
                continue
            reasons[source] = ["it can reach %s, which is a crown jewel"
                               % graph.name_of(current)]
            routes[source] = [edge] + routes.get(current, [])
            derived.add(source)
            frontier.append(source)

    jewels = []
    for sid, why in reasons.items():
        node = data.get(sid)
        if node is None:
            continue
        route = routes.get(sid) or []
        jewels.append(CrownJewel(
            sid=sid, name=node.name or sid, kind=node.kind, reasons=why,
            derived=sid in derived, path=route,
            reaches=(graph.name_of(route[-1].target) if route else "")))
    # the shortest routes first: those are the ones worth reading, and the order is
    # fixed so the same forest always produces the same list
    jewels.sort(key=lambda jewel: (jewel.derived, jewel.hops, jewel.kind, jewel.name))
    return jewels
