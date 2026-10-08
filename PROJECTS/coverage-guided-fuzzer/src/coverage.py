"""The coverage map, shared with the target process.

The instrumentation writes into the target's own memory, so the map has to travel back
to the fuzzer across a process boundary. A named shared-memory region is what carries it:
the target maps it by name, writes the map, and exits; the fuzzer reads the same pages.

A coverage-guided fuzzer's judgement about whether an input is interesting is only as
good as this map. Two things make it useful:

*Edges, not lines.* The compiler inserts a call on every edge, so the map records which
transitions were taken rather than which statements ran. A line executed from two
different call sites is two different edges, and the difference between them is exactly
what tells a fuzzer that it has found a new way through the code.

*The whole run, not the last write.* The map is a set of bits, so a loop that runs a
thousand times sets the same bit as a loop that runs once. That is deliberate: the
fuzzer is looking for *new* paths, not for counts, and a count would make every input
look interesting the moment any loop ran a different number of times.

The map is handled as a Python integer rather than as bytes. The set operations a fuzzer
needs -- union, difference, count -- are then single C-level operations on a big integer
instead of loops over sixty-four thousand bytes in Python, which is the difference
between the bookkeeping costing milliseconds per execution and costing microseconds. At
the scale a fuzzer runs at, that is not a micro-optimisation; it is the difference
between a tool that finishes and one that does not.
"""

from __future__ import annotations

import hashlib
from multiprocessing import shared_memory

MAP_SIZE = 65536
# The map, the edge counter the runtime maintains, the comparison count, padding, then
# the comparisons themselves: two eight-byte operands and a four-byte width each.
MAX_COMPARISONS = 512
COMPARISON_SIZE = 20
COUNTER_OFFSET = MAP_SIZE
COMPARISON_COUNT_OFFSET = MAP_SIZE + 8
COMPARISON_DATA_OFFSET = MAP_SIZE + 16
REGION_SIZE = MAP_SIZE + 16 + MAX_COMPARISONS * COMPARISON_SIZE
MAP_BITS = MAP_SIZE * 8


class CoverageMap:
    """The shared region, and the bookkeeping that turns it into guidance."""

    def __init__(self, name: str = "cgf-coverage"):
        self.name = name
        try:
            self._shm = shared_memory.SharedMemory(name=name, create=True,
                                                   size=REGION_SIZE)
        except FileExistsError:
            # A previous run left it behind; its contents are worthless anyway.
            stale = shared_memory.SharedMemory(name=name)
            stale.close()
            stale.unlink()
            self._shm = shared_memory.SharedMemory(name=name, create=True,
                                                   size=REGION_SIZE)
        self.buf = self._shm.buf
        # `virgin` is the union of every edge ever seen, as a bit set. An input is
        # interesting when it sets a bit here that is not yet set, which is the whole of
        # the feedback rule.
        self.virgin = 0
        self.total_edges = 0
        self._blank = b"\x00" * MAP_SIZE

    def clear(self) -> None:
        """Reset before an execution, so what is read afterwards is that run's alone.

        A single slice assignment rather than a loop: the loop is what made this cost
        milliseconds. The comparison count is reset with the map, so a run's comparisons
        are its own and the buffer does not accumulate across the corpus.
        """
        self.buf[:MAP_SIZE] = self._blank
        self.buf[COMPARISON_COUNT_OFFSET:COMPARISON_COUNT_OFFSET + 4] = b"\x00\x00\x00\x00"

    def read(self) -> bytes:
        return bytes(self.buf[:MAP_SIZE])

    def edges(self) -> int:
        return int.from_bytes(bytes(self.buf[COUNTER_OFFSET:REGION_SIZE]), "little")

    def as_bits(self, map_bytes: bytes) -> int:
        """The map as a bit set, which is how the interesting parts are compared."""
        return int.from_bytes(map_bytes, "big")

    def count(self, map_bytes: bytes) -> int:
        """How many edges this run reached.

        The runtime keeps a counter of its own, but it counts every edge the process has
        ever set rather than the ones this run reached -- it is never reset, because
        resetting it would mean touching shared memory inside every execution. Reading it
        as though it were a per-run figure reports the process's history rather than the
        input's, which is what it was doing: twenty-nine edges reported as two hundred
        and forty-one. The map itself is the authority, and counting its bits is a single
        operation on a big integer.
        """
        return self.as_bits(map_bytes).bit_count()

    def new_coverage(self, map_bytes: bytes) -> int:
        """How many edges this run reached that nothing before it did.

        Returns the count and updates the union, so an input that is interesting once is
        not interesting again for the same reason.
        """
        bits = self.as_bits(map_bytes)
        fresh = bits & ~self.virgin
        if fresh:
            self.virgin |= bits
            self.total_edges = self.virgin.bit_count()
            return fresh.bit_count()
        return 0

    def reset(self) -> None:
        """Forget everything seen, so a search can start from nothing.

        What a search discovers is held here rather than in the search, and a caller who
        runs two searches against one map is running the second one with the first one's
        knowledge. That is not a defect in either -- it is what a shared map means -- but
        it does mean that comparing two searches requires resetting this first, and a
        comparison made without it is comparing a search against a search that had a head
        start.
        """
        self.virgin = 0
        self.total_edges = 0

    def comparisons(self) -> list:
        """The comparisons this run made, as (a, b, width) triples.

        This is what the target was looking at rather than where it went, and it is the
        half of the feedback that closes the gap between "that input was rejected" and
        "that input was rejected because the first byte should have been R". A fuzzer
        given only the first has to find four bytes out of four billion; given the second
        it is told them, one comparison at a time, and it never has to be told the format
        in advance.

        The fourth element says whether the first operand came from the program rather
        than from the input, which is what makes a comparison name an expected value
        instead of merely recording two numbers that were read.
        """
        count = int.from_bytes(
            bytes(self.buf[COMPARISON_COUNT_OFFSET:COMPARISON_COUNT_OFFSET + 4]), "little")
        count = min(count, MAX_COMPARISONS)
        out = []
        for i in range(count):
            start = COMPARISON_DATA_OFFSET + i * COMPARISON_SIZE
            slot = bytes(self.buf[start:start + COMPARISON_SIZE])
            a = int.from_bytes(slot[0:8], "little")
            b = int.from_bytes(slot[8:16], "little")
            width = int.from_bytes(slot[16:18], "little")
            constant = slot[18] != 0
            out.append((a, b, width, constant))
        return out

    def signature(self, map_bytes: bytes) -> str:
        """A short identifier for the shape of a run, used to bucket crashes.

        Hashing the map rather than the input is what makes two inputs that fail the
        same way collapse into one report: they took the same path to the failure, so
        they are one defect however different their bytes are.
        """
        return hashlib.sha1(map_bytes).hexdigest()[:16]

    def close(self) -> None:
        try:
            self._shm.close()
            self._shm.unlink()
        except (FileNotFoundError, BufferError):
            pass
