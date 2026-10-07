"""Finding the ways in.

The metric is hops, and that is deliberate. A weighted model would need a number for
how hard each right is to abuse, and any such number is a guess dressed as a
measurement: nobody has measured how much harder WriteDacl is than GenericAll. Hop
count is a fact about the graph, it is reproducible, and a reader can count it.

The search is breadth-first, so the path it returns has the fewest steps. Where
several paths are equally short it returns the one whose steps are the most direct,
ordered by capability class, so the answer is stable across runs rather than
depending on dictionary order -- a result that changes between runs is one nobody
can review.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from .rights import CAPABILITIES

__all__ = ["Path", "shortest_path", "all_shortest_paths", "enumerate_paths",
           "reachability_report", "entry_points"]


@dataclass
class Path:
    """A sequence of objects and the edges between them."""

    steps: list = field(default_factory=list)      # edges, in order
    start: str = ""
    end: str = ""

    @property
    def length(self) -> int:
        return len(self.steps)

    @property
    def nodes(self) -> list:
        if not self.steps:
            return [self.start]
        return [self.start] + [edge.target for edge in self.steps]

    def describe(self, graph) -> list:
        """The path in words, one line per hop, for a reader to check."""
        lines = []
        current = self.start
        for edge in self.steps:
            lines.append({"from": graph.name_of(current),
                          "to": graph.name_of(edge.target),
                          "right": edge.right or edge.kind,
                          "capability": edge.capability,
                          "why": edge.note})
            current = edge.target
        return lines

    def as_dict(self, graph=None) -> dict:
        return {"start": self.start, "end": self.end, "hops": self.length,
                "nodes": [graph.name_of(n) for n in self.nodes] if graph else self.nodes,
                "rights": [edge.right or edge.kind for edge in self.steps],
                "steps": self.describe(graph) if graph else []}


def _order_key(edge) -> int:
    """Sort equally short paths by how directly their first step gives control."""
    try:
        return CAPABILITIES.index(edge.capability)
    except ValueError:
        return len(CAPABILITIES)


def shortest_path(graph, start: str, targets) -> Path | None:
    """The fewest-hop path from `start` to any of `targets`, or None.

    Breadth-first, so the first time a target is reached the path is the shortest
    one. Successors are visited in a stable order so the same graph always yields
    the same path.
    """
    targets = set(targets)
    if start in targets:
        return Path(steps=[], start=start, end=start)
    seen = {start}
    queue = deque([(start, [])])
    while queue:
        current, trail = queue.popleft()
        for edge in sorted(graph.successors(current), key=_order_key):
            if edge.target in seen:
                continue
            path = trail + [edge]
            if edge.target in targets:
                return Path(steps=path, start=start, end=edge.target)
            seen.add(edge.target)
            queue.append((edge.target, path))
    return None


def all_shortest_paths(graph, start: str, targets, limit: int = 5) -> list:
    """Every path of the minimum length, up to a limit.

    A single shortest path is a claim that one route exists; a reader deciding what
    to fix usually wants to know whether there are three others of the same length.
    """
    targets = set(targets)
    best = None
    found = []
    seen = {start: 0}
    queue = deque([(start, [])])
    while queue:
        current, trail = queue.popleft()
        if best is not None and len(trail) >= best:
            continue
        for edge in sorted(graph.successors(current), key=_order_key):
            path = trail + [edge]
            if edge.target in targets:
                if best is None:
                    best = len(path)
                if len(path) <= best and len(found) < limit:
                    found.append(Path(steps=path, start=start, end=edge.target))
                continue
            if seen.get(edge.target, 1 << 30) <= len(path):
                continue
            seen[edge.target] = len(path)
            queue.append((edge.target, path))
    return found


def enumerate_paths(graph, start: str, target: str, max_depth: int = 6,
                    limit: int = 50) -> list:
    """Every simple path from one object to one other, up to a depth and a count.

    Bounded on both, and the bound is reported rather than applied silently: an
    exhaustive enumeration of a directory this size does not terminate in a useful
    time, and a truncated list presented as complete would be a lie.
    """
    if max_depth < 1:
        return []
    found = []

    def walk(current: str, trail: list, on_trail: set):
        if len(found) >= limit or len(trail) > max_depth:
            return
        for edge in sorted(graph.successors(current), key=_order_key):
            if edge.target in on_trail:
                continue                       # a simple path visits nothing twice
            path = trail + [edge]
            if edge.target == target:
                found.append(Path(steps=path, start=start, end=target))
                if len(found) >= limit:
                    return
                continue
            on_trail.add(edge.target)
            walk(edge.target, path, on_trail)
            on_trail.discard(edge.target)

    walk(start, [], {start})
    return found


def entry_points(graph, jewels) -> list:
    """Where an attacker plausibly stands to begin with.

    Enabled accounts and machines that are not already crown jewels. Derived from the
    data rather than listed: a disabled account is not a starting point because
    nobody can log into it, and a crown jewel is not one because it is the
    destination. Nothing here names a particular account, which is what makes it work
    on a directory this tool has never seen.
    """
    jewel_sids = {jewel.sid for jewel in jewels}
    points = []
    for sid, node in graph.data.nodes.items():
        if sid in jewel_sids or not node.enabled:
            continue
        if node.kind in ("user", "computer"):
            points.append(sid)
    return sorted(points)


def reachability_report(graph, jewels, sources=None, limit: int = 25) -> dict:
    """How a set of starting points reaches a crown jewel, by the shortest route.

    The starting set matters and is not "everything", because in a graph closed under
    reachability nothing outside the set can reach it by construction. The useful
    question is asked from a position an attacker actually holds: an unprivileged
    account, a workstation, a service account. Pass those in, and the answer is the
    paths from where they stand.

    Ordered by hop count and then by name, so the list is the same on every run.
    """
    jewel_sids = {jewel.sid for jewel in jewels}
    entries = []
    pool = sources if sources is not None else [
        sid for sid in graph.data.nodes if sid not in jewel_sids]
    for sid in pool:
        node = graph.data.get(sid)
        if node is None or sid in jewel_sids:
            continue
        path = shortest_path(graph, sid, jewel_sids)
        if path is None:
            continue
        entries.append({"sid": sid, "name": node.name or sid, "kind": node.kind,
                        "hops": path.length, "path": path})
    entries.sort(key=lambda entry: (entry["hops"], entry["kind"], entry["name"]))
    return {"total": len(entries),
            "shown": min(limit, len(entries)),
            "truncated": len(entries) > limit,
            "entries": entries[:limit]}
