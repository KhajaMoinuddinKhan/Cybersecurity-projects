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

# Bounds on a pass whose cost is positions times values. The span is how far into an
# input it walks -- fields live near the front and a sixty-thousand-byte input would
# spend the whole budget setting bytes that are not fields -- and the value cap keeps a
# large harvest from making the pass unaffordable.
DETERMINISTIC_SPAN = 64
DETERMINISTIC_VALUES = 64
DETERMINISTIC_MAX = 8192
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
    stepping_stones: int = 0
    deterministic: int = 0
    edges_found: int = 0
    started: float = 0.0
    elapsed: float = 0.0
    timed_out: bool = False

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
        # The values the target has compared against, which are the tokens it revealed
        # rather than ones it was given. They are the format's magic numbers and field
        # values, learned one comparison at a time.
        self.learned: set = set()
        # Runs of single-byte constants, joined. A tag is four bytes and the parser
        # compares them one at a time, so the comparisons name four values and never
        # name the word they make. Joining consecutive ones recovers the word: the
        # parser compared 82, then 69, then 67, then 83, and what it was reading was
        # "RECS". Without this the search learns all four bytes and never assembles
        # them -- which is what it did, reaching fifteen edges out of a parser whose
        # whole first check is four bytes it already knew.
        self.sequences: set = set()
        # The deliberate pass for each newly kept entry, and how far through the corpus
        # that has been done. Tracked by index: a drained queue is an empty list and not
        # nothing, so a check for nothing would fire once and never again.
        self._pending: list = []
        self._walked = 0
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

    def harvest(self, comparisons: list) -> int:
        """Take the constants the target compared against and keep them as tokens.

        A value the program compared an input byte against is a value the program wants,
        which makes it worth trying elsewhere -- in another position, in another input,
        at another length.

        The width is not what makes a value worth keeping; its size is. A length is
        compared at the width of a `size_t`, which is eight bytes, and the value it is
        compared against is a small number like five. Skipping eight-byte comparisons
        because eight bytes is usually an address threw away the single most useful
        constant in the program -- the one the search has to satisfy before it can reach
        anything else -- and the search then learned nothing at all and never started.
        A value that fits in four bytes is data whatever width it was compared at; one
        that does not is a pointer or a hash and is left alone.
        """
        before = len(self.learned) + len(self.sequences)
        for a, b, width, is_constant in comparisons:
            if not is_constant:
                continue
            for value in (a, b):
                if value and value < (1 << 32):
                    self.learned.add(value)

        # Then the same values read as a sequence, which is what recovers a magic number
        # from a parser that walks it one byte at a time.
        #
        # Two things had to be right for this to work, and neither was.
        #
        # The width is not one. `if (d[0] != 'R')` is compiled as a four-byte comparison
        # of the loaded byte against the constant, because that is the natural width of
        # the operation, so a filter for single-byte comparisons matched none of them.
        #
        # And a run has to be a run of *matches*. A parser comparing a byte it is reading
        # against a constant produces equal operands when the byte is right and unequal
        # ones when it is wrong; requiring them equal is what separates the bytes of a
        # magic number from the checks that merely happen to be narrow, like `size < 5`
        # and `pointer != NULL`, which are also small constants and are not data.
        # And the third thing that had to be right, which was the one that mattered: the
        # comparisons that are not data must be *ignored* rather than treated as a break.
        # A parser comparing a magic number produces its byte comparisons interleaved with
        # everything else it is doing -- null checks, size checks, pointer arithmetic --
        # and the four bytes of a tag are never adjacent in the list. Resetting on
        # anything else meant the run never reached two, and the four bytes it had
        # correctly identified were never joined into the word they spell.
        run = bytearray()
        for a, b, width, is_constant in comparisons:
            if not (is_constant and 0 < a < 256):
                continue                    # not a data comparison: neither joins nor breaks
            if a == b:
                run.append(a)
                if len(run) >= 2:
                    for take in range(2, min(len(run), 8) + 1):
                        self.sequences.add(bytes(run[-take:]))
            else:
                run = bytearray()           # a data comparison that failed ends the run
        return len(self.learned) + len(self.sequences) - before

    def deterministic(self, entry) -> list:
        """Every input that puts one wanted value at one position of an entry.

        This is the answer to the thing that made the search unreliable, and the thing is
        this: a comparison says what value the program wanted and never says where it
        wanted it. The parser here compares `input[2]` against 'C', and all the search
        learns is that 67 is wanted somewhere. Placing it somewhere at random is a
        shotgun, and a magic number is four bytes that have to be in four particular
        places in a particular order -- so the search knew all four bytes of the tag and
        reached twelve edges of a parser whose first check is four bytes it already knew.

        Trying each wanted value at each position in turn is what closes that. The
        position comes from the loop rather than from the comparison, which is enough:
        the values are few and the positions are bounded, and one of the combinations is
        the one the program wanted.

        It chains, and that is what makes it work rather than merely run. Setting a
        position to a value that earns new coverage keeps the result, and the result is
        walked in its turn, so a tag is built a byte at a time and each byte is a
        starting point for the next. The first version of this tried only boundary
        values, which builds a length field and does not build a word; it was measured,
        found to change nothing, and removed. The values are the point.
        """
        wanted = [v for v in sorted(self.learned) if 0 < v < 256][:DETERMINISTIC_VALUES]
        if not wanted:
            return []
        out = []
        data = bytearray(entry.data)
        limit = min(len(data), DETERMINISTIC_SPAN)
        for position in range(limit):
            for value in wanted:
                candidate = bytes(data[:position]) + bytes([value]) + bytes(data[position + 1:])
                if candidate != entry.data:
                    out.append(candidate)
        # The learned words go in whole, at each position, which is what puts a tag
        # somewhere it can be read rather than a byte at a time.
        for position in range(min(limit, DETERMINISTIC_SPAN)):
            for word in sorted(self.sequences)[:DETERMINISTIC_VALUES]:
                if position + len(word) > len(data):
                    continue
                candidate = bytes(data[:position]) + word + bytes(data[position + len(word):])
                if candidate != entry.data:
                    out.append(candidate)
        return out

    def step(self) -> dict:
        """One execution. Returns what happened, for a caller that wants to watch."""
        # Anything newly kept is walked before havoc touches it again, so a field is set
        # deliberately while the rest of the input is still right.
        if not self._pending and self._walked < len(self.corpus.entries):
            while self._walked < len(self.corpus.entries):
                entry = self.corpus.entries[self._walked]
                self._walked += 1
                if entry.found_by != "stepping stone" and entry.size <= DETERMINISTIC_MAX:
                    self._pending = self.deterministic(entry)
                    if self._pending:
                        break
        if self._pending:
            candidate = self._pending.pop(0)
            outcome = self.target.run(candidate)
            self.stats.executions += 1
            self.stats.deterministic += 1
            self.stats.elapsed = time.time() - self.stats.started
            self.harvest(self.target.coverage.comparisons())
            if outcome.crashed:
                return {"kind": "crash",
                        "finding": self._record_crash(outcome, candidate, "deterministic"),
                        "new_edges": 0}
            new = self.target.coverage.new_coverage(outcome.coverage)
            if new:
                self.stats.edges_found += new
                self.corpus.add(candidate, edges=outcome.edges, new_edges=new,
                                comparisons=self.target.coverage.comparisons(),
                                found_by="deterministic")
                return {"kind": "coverage", "new_edges": new, "data": candidate}
            return {"kind": "nothing", "new_edges": 0}
        return self._havoc_step()

    def _havoc_step(self) -> dict:
        """One execution of the random stage, after the deliberate one has finished."""
        parent = self.corpus.choose(self.rng)
        parent.executions += 1
        other = None
        if len(self.corpus) > 1 and self.rng.random() < 0.25:
            other = self.corpus.choose(self.rng).data
        # The comparisons from the parent's last run are what make this mutation guided:
        # they say what that input was missing.
        candidate = bytes(self.mutator.generate(
            parent.data, other, comparisons=parent.comparisons,
            tokens=tuple(sorted(self.learned)) + tuple(sorted(self.sequences))))

        outcome = self.target.run(candidate)
        self.stats.executions += 1
        self.stats.elapsed = time.time() - self.stats.started
        self.harvest(self.target.coverage.comparisons())

        if outcome.crashed:
            finding = self._record_crash(outcome, candidate, "mutation")
            return {"kind": "crash", "finding": finding, "new_edges": 0}

        new = self.target.coverage.new_coverage(outcome.coverage)
        # The comparisons are kept with the entry, so mutating it later is guided by what
        # that specific input was told it was missing.
        comparisons = self.target.coverage.comparisons()
        if new:
            self.stats.edges_found += new
            if self.corpus.add(candidate, edges=outcome.edges, new_edges=new,
                               comparisons=comparisons):
                self.stats.corpus_additions += 1
                return {"kind": "coverage", "new_edges": new, "data": candidate}
        # Nothing new, but a much longer input is a stepping stone to the sizes a
        # size-dependent defect needs, and it would never be kept otherwise.
        if self.corpus.add_stepping_stone(candidate, edges=outcome.edges,
                                          comparisons=comparisons):
            self.stats.corpus_additions += 1
            self.stats.stepping_stones += 1
            return {"kind": "growth", "new_edges": 0, "data": candidate}
        return {"kind": "nothing", "new_edges": 0}

    def run(self, budget: int = 20000, stop_after_crashes: int = None,
            on_event=None, time_limit: float = None) -> Stats:
        """Run until the budget is spent, enough crashes are found, or time runs out.

        The execution budget is the ordinary way to bound a search and it is not
        sufficient on its own. An execution is supposed to be cheap and a target that
        has stopped answering makes it expensive -- so a budget of twenty thousand is a
        second of work or an hour of waiting, depending on the target, and nothing about
        the number says which. The time limit is the bound that cannot be defeated by
        the thing being measured, and a caller that leaves it out is trusting the target
        to behave.
        """
        self.stats.started = time.time()
        self.stats.timed_out = False
        while self.stats.executions < budget:
            result = self.step()
            self.stats.elapsed = time.time() - self.stats.started
            if on_event:
                on_event(result, self.stats)
            if stop_after_crashes and len(self.findings) >= stop_after_crashes:
                break
            if time_limit is not None and self.stats.elapsed > time_limit:
                self.stats.timed_out = True
                break
        self.stats.elapsed = time.time() - self.stats.started
        return self.stats

    def minimise_findings(self, rounds: int = 3, seconds: float = None) -> None:
        """Shrink every crash to the smallest input that still crashes the same way.

        A reproducer that is four hundred bytes of noise around a one-byte trigger is
        not a reproducer anybody will read. The test is not "does it still crash" but
        "does it still crash the same way", because a smaller input that fails
        differently is a different defect and would be a lie.
        """
        # A deadline across all of them rather than one each, so the cost of tidying up
        # does not scale with the number of defects found. The first crash is the one
        # worth reading; the rest can stay as they are.
        deadline = None if seconds is None else time.monotonic() + seconds
        for finding in self.findings.values():
            if deadline is not None and time.monotonic() > deadline:
                break
            original = finding.signature

            def still_same(candidate: bytes) -> bool:
                outcome = self.target.run(candidate)
                return (outcome.crashed
                        and self.target.coverage.signature(outcome.coverage) == original)

            finding.data = minimise(finding.data, still_same, rounds=rounds,
                                    deadline=deadline)
