"""The inputs worth keeping, and the ones worth keeping most.

A corpus is not a list of every input the fuzzer has run -- it is the set that between
them reach every edge that has been reached. An input earns its place by covering
something nothing else covered, and that rule alone is what keeps the corpus from
growing without bound while the search keeps making progress.

Two things happen here beyond the adding.

*Minimisation.* A corpus entry is often hundreds of bytes that reach a new edge near
the end, with the rest along for the ride. Trimming it to the smallest input that still
reaches that edge makes every subsequent mutation more likely to land somewhere useful,
because a mutation on a forty-byte input is far more likely to matter than the same
mutation on a four-hundred-byte one.

*Favouring.* When several entries reach the same edge, the shortest is the one worth
mutating, because it says the same thing with less noise. This is a heuristic and it is
not always right -- sometimes the long input reaches the edge through a path the short
one cannot -- so the rest are kept rather than discarded.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field


@dataclass
class Entry:
    """One input, and what it is for."""

    data: bytes
    edges: int = 0          # how many edges it reached
    new_edges: int = 0      # how many of them nothing had reached before
    executions: int = 0     # how many times it has been chosen as a parent
    found_by: str = "seed"
    # What that input was told it was missing, from the run that found it. Mutating it
    # later is guided by these rather than by the input's shape.
    comparisons: list = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.data)


@dataclass
class Corpus:
    """The set of inputs the search is built on."""

    entries: list = field(default_factory=list)
    _seen: set = field(default_factory=set)

    def add(self, data: bytes, edges: int = 0, new_edges: int = 0,
            found_by: str = "mutation", comparisons: list = None) -> bool:
        """Keep an input if it is not a duplicate. Returns whether it was kept.

        Duplicates are rejected on the bytes, not on the coverage: two inputs that reach
        the same edges by different bytes are both worth having, because they will
        mutate differently.
        """
        if data in self._seen:
            return False
        self._seen.add(data)
        self.entries.append(Entry(data=data, edges=edges, new_edges=new_edges,
                                  found_by=found_by,
                                  comparisons=list(comparisons or [])))
        return True

    def __len__(self) -> int:
        return len(self.entries)

    def largest(self) -> int:
        return max((e.size for e in self.entries), default=0)

    def add_stepping_stone(self, data: bytes, edges: int = 0,
                           comparisons: list = None, factor: float = 1.5) -> bool:
        """Keep an input because it is much longer than anything else, not because it
        found anything.

        Some defects only exist in a long input -- a bound checked in arithmetic that
        wraps needs a count in the thousands, and a count in the thousands needs an input
        of thousands of bytes to go with it. A search that only keeps inputs which found
        new edges cannot get there: an input that is merely longer reaches the same edges
        as the short one it grew from, so it is discarded, and every mutation starts again
        from something small.

        So a new size record is worth keeping on its own. It is kept only when it is
        substantially longer than the current longest, which makes the ladder logarithmic
        rather than a new entry for every byte, and it is a stepping stone rather than a
        discovery -- the weighting treats it as worth one edge, so the search climbs
        through it instead of settling on it.
        """
        if not data or len(data) < self.largest() * factor:
            return False
        return self.add(data, edges=edges, new_edges=0, found_by="stepping stone",
                        comparisons=comparisons)

    def __iter__(self):
        return iter(self.entries)

    def choose(self, rng: random.Random) -> Entry:
        """Pick a parent: the ones that found the most, and the ones least tried.

        Weighting by how much an entry found is right and it is not enough. An entry
        that found twenty new edges early keeps being chosen forever, and the entries
        found later -- which are the ones closer to the deeper paths, because they were
        found later -- are never fuzzed at all. That is what this search did: it
        plateaued with eleven entries and forty-six edges and never moved, because one
        early winner was taking almost every slot.

        So the choice is by how much an entry found *per time it has been tried*. A
        productive entry still gets picked more often, and every entry gets picked:
        an input that has never been fuzzed has a ratio of zero and goes first.

        The stepping stones are held back rather than mixed in. They found nothing, so
        under the rule above they would be chosen last -- and they need to be chosen
        sometimes or the search never reaches the sizes a size-dependent defect needs.
        Giving them a share of the budget outright is the only way to have both, and it
        has to be a small share: left in the ordinary weighting they are chosen almost
        always, because a large input is nearly always one that has never been tried and
        the ratio rewards that. That is what happened, and it took the search's attention
        off the small inputs that find coverage and it stopped finding anything at all.
        """
        if not self.entries:
            raise ValueError("the corpus is empty")
        stones = [e for e in self.entries if e.found_by == "stepping stone"]
        ordinary = [e for e in self.entries if e.found_by != "stepping stone"]
        if stones and (not ordinary or rng.random() < 0.1):
            # A tenth of the budget climbs the size ladder, and no more.
            return rng.choices(stones, weights=[1 for _ in stones], k=1)[0]
        if not ordinary:
            return rng.choices(self.entries, weights=[1 for _ in self.entries], k=1)[0]
        if rng.random() < 0.25:
            return rng.choices(ordinary,
                               weights=[max(1, e.new_edges) for e in ordinary],
                               k=1)[0]
        return min(ordinary, key=lambda e: (e.executions + 1) / max(1, e.new_edges))

    def total_bytes(self) -> int:
        return sum(e.size for e in self.entries)


def minimise(data: bytes, reaches, rounds: int = 4) -> bytes:
    """Shrink an input while it still reaches what it reached.

    `reaches` is a callable returning whether a candidate still covers the edges the
    original did. The search is coarse to fine: whole halves first, then single bytes.
    It is not guaranteed minimal -- finding the true minimum is expensive and this is
    not where the budget belongs -- but it is reliably much smaller than what it
    started as, and it terminates.
    """
    best = bytes(data)
    if not reaches(best):
        return best

    # Halves: try dropping each half, keep any drop that still reaches.
    for _ in range(rounds):
        improved = False
        for cut in (2, 3, 4, 8):
            size = max(1, len(best) // cut)
            for start in range(0, len(best), size):
                candidate = best[:start] + best[start + size:]
                if candidate and reaches(candidate):
                    best = candidate
                    improved = True
                    break
            if improved:
                break
        if not improved:
            break

    # Then single bytes, which catches the one-byte field that was padding.
    index = 0
    while index < len(best):
        candidate = best[:index] + best[index + 1:]
        if candidate and reaches(candidate):
            best = candidate
        else:
            index += 1
    return best
