"""Which objects to fix, rather than which to fix first.

A list of attack paths tells you what is wrong. It does not tell you what to change.
Almost every path in a real directory runs through a handful of objects, and finding
that handful is a different question from finding the paths -- it is a cut problem,
and it has an exact answer rather than a ranked guess.

Two analyses, because they answer different questions:

  * How much does removing *this one* object help? Counted by how many attackers lose
    their route to a crown jewel. Cheap, exact for one node, and the answer a reader
    wants when asking "what about this one".
  * What is the smallest set of objects whose removal disconnects every attacker from
    every crown jewel? That is a minimum node cut, and it is computed exactly with
    max-flow rather than estimated greedily. It is the strongest single statement
    this tool can make: here is the smallest change that closes every path found.

Both are computed on the graph as it is. Neither is a heuristic presented as an
answer, and where the exact answer is expensive the bound is reported rather than
hidden.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from .paths import shortest_path

__all__ = ["ChokePoint", "attacker_map", "removal_impact", "chokepoints",
           "minimum_node_cut", "routes_to_seeds"]


@dataclass
class ChokePoint:
    """One object, and how much closing it would do."""

    sid: str
    name: str
    kind: str
    cuts: int                       # attackers who lose every route when it is removed
    attackers: int                  # attackers who had a route before
    also_reachable: bool = False    # whether the object is itself reachable by others

    @property
    def share(self) -> float:
        return (self.cuts / self.attackers) if self.attackers else 0.0

    def as_dict(self) -> dict:
        return {"sid": self.sid, "name": self.name, "kind": self.kind,
                "cuts": self.cuts, "attackers": self.attackers,
                "share": round(self.share, 4)}


def routes_to_seeds(jewels) -> dict:
    """Every object that can reach a seeded crown jewel, with the route it takes.

    These are the derived crown jewels, and their routes are the findings. Asking the
    same question of objects *outside* the crown-jewel set returns nothing, and it
    returns nothing by construction rather than by accident: the set is closed under
    reachability, so anything that can reach a seed is already in it. Working from the
    routes the closure recorded is what makes the question mean something.
    """
    routes = {}
    for jewel in jewels:
        if jewel.derived and jewel.path:
            routes[jewel.sid] = jewel.path
    return routes


def attacker_map(graph, jewels, seeds=None) -> dict:
    """Every object that can reach one of `seeds`, by the shortest route.

    Where the seeded set is given, this finds everything that can reach it whether or
    not the closure was run -- which is what the cut needs, and what a caller asking
    "who can get to the domain admins" means.
    """
    if seeds is None:
        seeds = [jewel.sid for jewel in jewels if not jewel.derived]
    seeds = set(seeds)
    routes = {}
    for sid in graph.data.nodes:
        if sid in seeds:
            continue
        path = shortest_path(graph, sid, seeds)
        if path is not None:
            routes[sid] = path
    return routes


def removal_impact(graph, jewels, candidates=None) -> list:
    """For each object, how many attackers lose every route if it is removed.

    Recomputed from scratch after each removal rather than inferred, because routes
    are not independent: removing one object can make another irrelevant, and a count
    that ignored that would overstate the second.
    """
    seeds = [jewel.sid for jewel in jewels if not jewel.derived]
    if not seeds:
        return []
    routes = attacker_map(graph, jewels, seeds)
    if not routes:
        return []
    seed_set_ = set(seeds)

    # Candidates are the objects that sit *between* an attacker and a seed. An
    # attacker is not a candidate for its own route, and a seed is the destination.
    pool = candidates
    if pool is None:
        pool = set()
        for path in routes.values():
            pool.update(path.nodes)
        pool -= seed_set_

    impacts = []
    for candidate in pool:
        if candidate in seed_set_:
            continue
        cut = 0
        for sid in routes:
            if sid == candidate:
                continue
            if _reaches_without(graph, sid, seed_set_, blocked=candidate):
                continue
            cut += 1
        if cut:
            node = graph.data.get(candidate)
            impacts.append(ChokePoint(
                sid=candidate, name=(node.name if node else candidate),
                kind=(node.kind if node else "?"), cuts=cut, attackers=len(routes)))
    impacts.sort(key=lambda point: (-point.cuts, point.kind, point.name))
    return impacts


def _reaches_without(graph, start: str, targets: set, blocked: str) -> bool:
    """Breadth-first search with one object removed from the graph."""
    if start == blocked:
        return False
    if start in targets:
        return True
    seen = {start}
    queue = deque([start])
    while queue:
        current = queue.popleft()
        for edge in graph.successors(current):
            if edge.target == blocked or edge.target in seen:
                continue
            if edge.target in targets:
                return True
            seen.add(edge.target)
            queue.append(edge.target)
    return False


def chokepoints(graph, jewels, limit: int = 20) -> dict:
    """The objects whose removal does the most, ranked."""
    impacts = removal_impact(graph, jewels)
    return {"total": len(impacts), "shown": min(limit, len(impacts)),
            "truncated": len(impacts) > limit,
            "points": impacts[:limit]}


# --- the exact answer ------------------------------------------------------

def minimum_node_cut(graph, sources, sinks) -> dict:
    """The smallest set of objects whose removal disconnects every source from every
    sink, computed exactly.

    A minimum *node* cut, not an edge cut, because removing an object is what an
    administrator can actually do. Nodes are split into an in-half and an out-half
    joined by a single unit-capacity arc, so cutting that arc is removing the object;
    every real edge becomes an infinite-capacity arc between halves and can never be
    chosen. A super-source feeds the sources and a super-sink drains the sinks, both
    at infinite capacity so neither can be cut.

    Solved with Edmonds-Karp over unit capacities. The result is a genuine minimum
    rather than a greedy approximation.

    There is a case where no cut exists, and it is reported rather than papered over.
    If a source has a direct edge to a sink, the route from one to the other uses no
    removable object at all, so the flow is unbounded and no set of intermediate
    objects disconnects them. That is not a failure of the computation; it is the
    answer, and it says something useful: the object that reaches a crown jewel in
    one step is not on the way to a problem, it *is* the problem, and it has to be
    fixed rather than routed around.
    """
    sources = [s for s in sources if s in graph.data.nodes]
    sinks = [s for s in sinks if s in graph.data.nodes]
    if not sources or not sinks:
        return {"cut": [], "size": 0, "note": "no sources or no sinks were given"}
    if set(sources) & set(sinks):
        return {"cut": [], "size": 0,
                "note": "a source is already a sink, so no removal is needed"}

    INF = float("inf")
    # every node becomes "<sid>|in" and "<sid>|out"
    def in_of(sid): return sid + "|in"
    def out_of(sid): return sid + "|out"

    capacity: dict = {}
    adjacency: dict = {}

    def add_arc(u, v, cap):
        capacity[(u, v)] = capacity.get((u, v), 0) + cap
        capacity.setdefault((v, u), 0)
        adjacency.setdefault(u, set()).add(v)
        adjacency.setdefault(v, set()).add(u)

    for sid in graph.data.nodes:
        add_arc(in_of(sid), out_of(sid), 1)          # cutting this removes the object

    for edge in graph.edges:
        if edge.source not in graph.data.nodes or edge.target not in graph.data.nodes:
            continue
        add_arc(out_of(edge.source), in_of(edge.target), INF)

    SOURCE, SINK = "|super-source|", "|super-sink|"
    for sid in sources:
        add_arc(SOURCE, out_of(sid), INF)            # a source is not removable
    for sid in sinks:
        add_arc(in_of(sid), SINK, INF)               # nor is a sink

    # Edmonds-Karp: repeatedly find a shortest augmenting path in the residual graph
    flow = 0
    while True:
        parent = {SOURCE: None}
        queue = deque([SOURCE])
        while queue and SINK not in parent:
            current = queue.popleft()
            for nxt in adjacency.get(current, ()):
                if nxt in parent:
                    continue
                if capacity.get((current, nxt), 0) > 0:
                    parent[nxt] = current
                    queue.append(nxt)
        if SINK not in parent:
            break
        # the bottleneck along the path
        bottleneck = INF
        walk = SINK
        while parent[walk] is not None:
            bottleneck = min(bottleneck, capacity[(parent[walk], walk)])
            walk = parent[walk]
        walk = SINK
        while parent[walk] is not None:
            capacity[(parent[walk], walk)] -= bottleneck
            capacity[(walk, parent[walk])] = capacity.get((walk, parent[walk]), 0) + bottleneck
            walk = parent[walk]
        flow += bottleneck

    # the cut is the set of split arcs that are saturated and whose in-half is
    # reachable from the source in the residual graph
    reachable = {SOURCE}
    queue = deque([SOURCE])
    while queue:
        current = queue.popleft()
        for nxt in adjacency.get(current, ()):
            if nxt not in reachable and capacity.get((current, nxt), 0) > 0:
                reachable.add(nxt)
                queue.append(nxt)

    cut = []
    for sid in graph.data.nodes:
        if in_of(sid) in reachable and out_of(sid) not in reachable:
            node = graph.data.get(sid)
            cut.append({"sid": sid, "name": (node.name if node else sid),
                        "kind": (node.kind if node else "?")})
    cut.sort(key=lambda item: (item["kind"], item["name"]))

    # A route from a source straight to a sink uses no removable object, so the flow
    # never converges. Reporting "three objects" from a run like that would be an
    # invented answer; the honest one is that no intermediate object can break it.
    direct = [{"source": sid, "sink": target}
              for sid in sources for target in sinks
              if any(edge.target == target for edge in graph.successors(sid))]
    unbounded = flow == INF or bool(direct)
    if unbounded:
        return {"cut": [], "size": 0, "flow": "unbounded", "unbounded": True,
                # The list is shortened for the report and the count is not: ten rows
                # under a sentence saying forty-five is a table that lost thirty-five
                # findings without mentioning it.
                "direct": direct[:10], "direct_total": len(direct),
                "note": ("%d starting "
                         "object(s) reach a crown jewel in a single step, so those "
                         "objects have to be fixed rather than routed around"
                         % len(direct))}
    return {"cut": cut, "size": len(cut), "flow": flow, "unbounded": False,
            "note": ("the smallest set of objects whose removal disconnects every "
                     "attacker from every crown jewel")}
