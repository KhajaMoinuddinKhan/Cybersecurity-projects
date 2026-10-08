"""Turning one input into the next one.

A fuzzer is a search, and this is the step that moves through the space. The mutations
here are the ones that have earned their place in the twenty years since they were
first written down, and they are worth understanding as a set rather than as a list.

*Small changes* -- a bit flipped, a byte set to a boundary value, a small number added
-- are what find off-by-one errors, wrong comparisons, and length fields that are one
byte short. They are cheap and they almost never make the input invalid, so the target
keeps going and coverage keeps accumulating.

*Large changes* -- a block deleted, a block cloned, two inputs spliced -- are what find
missing validation, because they produce inputs that are structurally wrong in ways a
human would not write by hand.

*Boundary values* are separate from the arithmetic because the interesting numbers are
not random: zero, one, the maximum and minimum of each width, and the powers of two
either side of them. A comparison against 32 is found by trying 31, 32 and 33, not by
trying a thousand random bytes.

*The dictionary* is the one piece of the input format the fuzzer is told rather than
learns. Four bytes of magic are four bytes a random search will not find; telling it
they exist is the difference between finding the parser in a second and never finding
it at all. Everything past the magic -- the count, the types, the lengths -- is left to
be discovered from coverage, which is what keeps this a fuzzer rather than a script
that already knows the answer.

Everything takes a `random.Random`, so a run is reproducible from its seed. A fuzzer
whose findings cannot be reproduced is not evidence of anything.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

# Values that sit on the boundaries a comparison is likely to be written against.
INTERESTING_8 = (0, 1, 2, 3, 4, 8, 16, 31, 32, 33, 63, 64, 65, 100, 127, 128, 129,
                 191, 192, 254, 255)
INTERESTING_16 = (0, 1, 255, 256, 257, 512, 1024, 4095, 4096, 4097, 32767, 32768,
                  32769, 65534, 65535)
INTERESTING_32 = (0, 1, 65535, 65536, 65537, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF)

# How far the arithmetic mutations move a value.
ARITHMETIC_STEPS = (1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096,
                    0x7FFF, 0xFFFF)


@dataclass
class Mutator:
    """The mutation engine, seeded so that a run can be repeated exactly."""

    seed: int = 0
    dictionary: tuple = ()
    max_length: int = 1 << 16
    rng: random.Random = field(init=False)

    def __post_init__(self):
        self.rng = random.Random(self.seed)

    # -- the small changes -------------------------------------------------------
    def flip_bits(self, data: bytearray) -> bytearray:
        if not data:
            return data
        # One to four bits, because a single flipped bit is often still valid input and
        # four at once is often not -- the pair covers both a typo and a small field
        # being corrupted.
        count = 1 << self.rng.randrange(4)
        for _ in range(count):
            index = self.rng.randrange(len(data))
            data[index] ^= 1 << self.rng.randrange(8)
        return data

    def set_byte(self, data: bytearray) -> bytearray:
        if not data:
            return data
        data[self.rng.randrange(len(data))] = self.rng.choice(INTERESTING_8)
        return data

    def arithmetic(self, data: bytearray, width: int = 1) -> bytearray:
        """Add or subtract a small number, at a width the format might use.

        This is what finds a length that is compared with the wrong constant: the value
        only has to move by one to cross a boundary.
        """
        if len(data) < width:
            return data
        index = self.rng.randrange(len(data) - width + 1)
        current = int.from_bytes(data[index:index + width], "little")
        step = self.rng.choice(ARITHMETIC_STEPS)
        if self.rng.random() < 0.5:
            step = -step
        new = (current + step) & ((1 << (width * 8)) - 1)
        data[index:index + width] = new.to_bytes(width, "little")
        return data

    def set_interesting(self, data: bytearray, width: int = 1) -> bytearray:
        if len(data) < width:
            return data
        table = {1: INTERESTING_8, 2: INTERESTING_16, 4: INTERESTING_32}[width]
        index = self.rng.randrange(len(data) - width + 1)
        data[index:index + width] = self.rng.choice(table).to_bytes(width, "little")
        return data

    # -- the large changes -------------------------------------------------------
    def delete_block(self, data: bytearray) -> bytearray:
        if len(data) < 2:
            return data
        start = self.rng.randrange(len(data))
        end = min(len(data), start + self.rng.randrange(1, len(data) - start + 1))
        del data[start:end]
        return data

    def clone_block(self, data: bytearray) -> bytearray:
        if not data:
            return data
        start = self.rng.randrange(len(data))
        end = min(len(data), start + self.rng.randrange(1, 33))
        return data[:end] + data[start:end] + data[end:]

    def overwrite_block(self, data: bytearray) -> bytearray:
        if not data:
            return data
        start = self.rng.randrange(len(data))
        end = min(len(data), start + self.rng.randrange(1, 33))
        value = self.rng.randrange(256)
        for i in range(start, end):
            data[i] = value
        return data

    def insert_bytes(self, data: bytearray) -> bytearray:
        if not data:
            return data
        index = self.rng.randrange(len(data) + 1)
        addition = bytes(self.rng.randrange(256)
                         for _ in range(self.rng.randrange(1, 17)))
        return data[:index] + addition + data[index:]

    def splice(self, data: bytearray, other: bytes) -> bytearray:
        """Take a prefix of one input and a suffix of another.

        Splicing is how a fuzzer combines two inputs that each got partway through the
        parser, which is how it reaches states neither of them reached alone.
        """
        if not data or not other:
            return data
        cut = self.rng.randrange(len(data))
        take = self.rng.randrange(len(other))
        return data[:cut] + bytearray(other[take:])

    # -- the dictionary ----------------------------------------------------------
    def insert_dictionary(self, data: bytearray) -> bytearray:
        """Drop a known token in, which is the only thing the fuzzer is told.

        Without this, four bytes of magic are four bytes that have to be found by
        chance, and a random search over four bytes is a search over four billion.
        """
        if not self.dictionary:
            return data
        token = self.rng.choice(self.dictionary)
        if not data:
            return bytearray(token)
        index = self.rng.randrange(len(data) + 1)
        return data[:index] + bytearray(token) + data[index:]

    # -- the composition ---------------------------------------------------------
    def havoc(self, data: bytes, other: bytes = None, rounds: int = None) -> bytearray:
        """A stack of the mutations above, which is what most of the budget goes on.

        Any single mutation is a weak search on its own. Applying several in sequence is
        what produces the inputs that are both valid enough to reach deep into the
        parser and wrong enough to break it.
        """
        result = bytearray(data)
        operations = [
            lambda d: self.flip_bits(d),
            lambda d: self.set_byte(d),
            lambda d: self.arithmetic(d, 1),
            lambda d: self.arithmetic(d, 2),
            lambda d: self.arithmetic(d, 4),
            lambda d: self.set_interesting(d, 1),
            lambda d: self.set_interesting(d, 2),
            lambda d: self.delete_block(d),
            lambda d: self.clone_block(d),
            lambda d: self.overwrite_block(d),
            lambda d: self.insert_bytes(d),
            lambda d: self.insert_dictionary(d),
            lambda d: self.splice(d, other) if other else d,
        ]
        if rounds is None:
            # The depth is drawn from a distribution rather than fixed, because the two
            # ends of it do different work. A single operation is what finds a boundary
            # that is one byte out; a long stack is what builds an input that is
            # structurally valid and still wrong, which is the only way to reach a
            # comparison that needs several fields to be right at once. A fuzzer that
            # only ever applies a handful of operations reaches the shallow paths and
            # stops, which is what this one did: it covered the parser up to the point
            # where a length field has to be large *and* the input has to be long enough
            # to hold what the length claims, and then it plateaued.
            rounds = (self.rng.randrange(1, 9) if self.rng.random() < 0.5
                      else self.rng.randrange(8, 129))
        for _ in range(rounds):
            result = self.rng.choice(operations)(result)
            if len(result) > self.max_length:
                result = result[:self.max_length]
        return result

    def generate(self, data: bytes, other: bytes = None) -> bytearray:
        """One new input, from one or two existing ones."""
        return self.havoc(data, other)
