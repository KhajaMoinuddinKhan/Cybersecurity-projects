"""The search loop: choose an input, change it, run it, and decide what that told us.

The loop is short and the interesting part is the decision in the middle. After a run
there are three questions, and the answers are what make this coverage-guided rather
than random:

1. Did it crash? If so it is saved, and the path that reached it is recorded, because
   two inputs that fail the same way are one defect.
2. Did it reach an edge nothing reached before? If so it joins the corpus, because an
   input that teaches the search something new is the most valuable thing a fuzzer can
   produce, and mutating it is how the search moves forward.
3. Neither? Then it is discarded. This is the case that matters and the one that is
   easy to get wrong: an input that reached nothing new must not be kept, or the corpus
   fills with inputs that are all the same shape and the search stops moving.

The scheduler adds one more idea. Every input in the corpus is worth mutating, but not
equally, and the weighting is by how much it found. That is what keeps the search
building on its own discoveries instead of wandering evenly over everything it has.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from pathlib import Path

from .corpus import Corpus, minimise
from .mutate import Mutator
from .target import Target


@dataclass
class Finding:
    """A crash, and enough about it to be worth reporting."""

    data: bytes
    signature: str
    status: str
    exit_code: int
    edges: int
    executions: int        # how many runs had happened when it was found
    found_by: str = "mutation"

    @property
    def size(self) -> int:
        return len(self.data)


@dataclass
class Stats:
    executions: int = 0
    crashes: int = 0
    corpus_additions: int = 0
    edges_found: int = 0
    started: float = 0.0
    elapsed: float = 0.0

    @property
    def per_second(self) -> float:
        return self.executions / self.elapsed if self.elapsed > 0 else 0.0


class Engine:
    """The fuzzer."""

    def __init__(self, target: Target, seed: int = 0, dictionary: tuple = (),
                 max_length: int = 1 << 16, verbose: bool = False):
        self.target = target
        self.rng = random.Random(seed)
        self.mutator = Mutator(seed=seed, dictionary=dictionary, max_length=max_length)
        self.corpus = Corpus()
        self.findings: dict = {}          # signature -> Finding
        self.stats = Stats()
        self.verbose = verbose
        self.seed = seed

    def add_seed(self, data: bytes) -> bool:
        """Start the corpus with an input. Its coverage is measured, not assumed."""
        outcome = self.target.run(data)
        new = self.target.coverage.new_coverage(outcome.coverage)
        self.stats.executions += 1
        self.stats.edges_found += new
        return self.corpus.add(data, edges=outcome.edges, new_edges=new,
                               found_by="seed")

    def _record_crash(self, outcome, data: bytes, found_by: str) -> Finding:
        """Save a crash, or note that it is one already known.

        Bucketing is by the coverage signature rather than the exit code. Two inputs
        that reach the same edges and die the same way are one defect; two inputs that
        die with the same code after different paths are not, and the exit code alone
        could not tell them apart.
        """
        signature = self.target.coverage.signature(outcome.coverage)
        if signature in self.findings:
            existing = self.findings[signature]
            # Keep the smaller input: it is the more useful reproducer.
            if len(data) < existing.size:
                existing.data = data
            return existing
        finding = Finding(data=data, signature=signature, status=outcome.status,
                          exit_code=outcome.exit_code,
                          edges=self.target.coverage.count(outcome.coverage),
                          executions=self.stats.executions, found_by=found_by)
        self.findings[signature] = finding
        self.stats.crashes += 1
        return finding

    def step(self) -> dict:
        """One execution. Returns what happened, for a caller that wants to watch."""
        parent = self.corpus.choose(self.rng)
        parent.executions += 1
        other = None
        if len(self.corpus) > 1 and self.rng.random() < 0.25:
            other = self.corpus.choose(self.rng).data
        candidate = bytes(self.mutator.generate(parent.data, other))

        outcome = self.target.run(candidate)
        self.stats.executions += 1
        self.stats.elapsed = time.time() - self.stats.started

        if outcome.crashed:
            finding = self._record_crash(outcome, candidate, "mutation")
            return {"kind": "crash", "finding": finding, "new_edges": 0}

        new = self.target.coverage.new_coverage(outcome.coverage)
        if new:
            self.stats.edges_found += new
            if self.corpus.add(candidate, edges=outcome.edges, new_edges=new):
                self.stats.corpus_additions += 1
                return {"kind": "coverage", "new_edges": new, "data": candidate}
        return {"kind": "nothing", "new_edges": 0}

    def run(self, budget: int = 20000, stop_after_crashes: int = None,
            on_event=None) -> Stats:
        """Run until the budget is spent or enough crashes are found."""
        self.stats.started = time.time()
        while self.stats.executions < budget:
            result = self.step()
            self.stats.elapsed = time.time() - self.stats.started
            if on_event:
                on_event(result, self.stats)
            if stop_after_crashes and len(self.findings) >= stop_after_crashes:
                break
        self.stats.elapsed = time.time() - self.stats.started
        return self.stats

    def minimise_findings(self, rounds: int = 3) -> None:
        """Shrink every crash to the smallest input that still crashes the same way.

        A reproducer that is four hundred bytes of noise around a one-byte trigger is
        not a reproducer anybody will read. The test is not "does it still crash" but
        "does it still crash the same way", because a smaller input that fails
        differently is a different defect and would be a lie.
        """
        for finding in self.findings.values():
            original = finding.signature

            def still_same(candidate: bytes) -> bool:
                outcome = self.target.run(candidate)
                return (outcome.crashed
                        and self.target.coverage.signature(outcome.coverage) == original)

            finding.data = minimise(finding.data, still_same, rounds=rounds)
