"""The fuzzer, tested against the things it claims to be.

The tests are written to fail if a claim stops being true, not to walk the code. Three
of them are the load-bearing ones and the rest support them:

*The search finds the defect from nothing.* Given an empty seed and the four bytes of
tag, it has to reach a crash. If coverage guidance stopped working -- if the feedback
were noise, or the corpus kept everything, or the scheduler stopped weighting -- this is
the test that goes red.

*The coverage is real.* Two inputs that take different paths must produce different
maps, and the same input must produce the same map. A map that never changed would make
every input look interesting and the guidance would be a fiction.

*The exploit takes control.* Not "the input crashes" but "the instruction pointer ends up
where the attacker put it", and the fixed build must not.
"""

import pytest

from src.build import describe
from src.coverage import CoverageMap
from src.corpus import Corpus, minimise
from src.crash import group
from src.engine import Engine
from src.exploit import demonstrate, find_offset
from src.mutate import INTERESTING_8, Mutator

# A search that cannot finish in this is a search that is not working, and a test that
# waits for it is a test that has stopped reporting. Every run of the engine in this
# file is bounded by one of these.
SEARCH_SECONDS = 90
from src.target import PersistentTarget, Target

TAG = b"RECS"
# A valid record with a name short enough to be stored properly.
GOOD = TAG + bytes([1, 1, 4]) + b"ABcd"
# A name longer than the thirty-two byte buffer, which is the defect.
OVERFLOW = TAG + bytes([1, 1, 200]) + b"A" * 200


# --- the target and the coverage it reports ------------------------------------------

def test_the_same_input_produces_the_same_coverage(coverage_map, vulnerable):
    with PersistentTarget(vulnerable, coverage_map) as target:
        first = target.run(GOOD)
        second = target.run(GOOD)
    assert first.coverage == second.coverage
    assert not first.crashed and not second.crashed


def test_different_inputs_produce_different_coverage(coverage_map, vulnerable):
    """The feedback is only guidance if it distinguishes paths."""
    with PersistentTarget(vulnerable, coverage_map) as target:
        short = target.run(TAG + bytes([1, 2, 0]))
        long = target.run(TAG + bytes([1, 1, 20]) + b"B" * 20)
    assert short.coverage != long.coverage


def test_the_coverage_map_is_not_empty(coverage_map, vulnerable):
    with PersistentTarget(vulnerable, coverage_map) as target:
        outcome = target.run(GOOD)
    assert sum(1 for byte in outcome.coverage if byte) > 0


def test_a_long_name_crashes_the_vulnerable_build(coverage_map, vulnerable):
    with PersistentTarget(vulnerable, coverage_map) as target:
        outcome = target.run(OVERFLOW)
    assert outcome.crashed


def test_the_same_name_does_not_crash_the_fixed_build(coverage_map, patched):
    """The fix is a bound on the copy, so the input is accepted rather than rejected."""
    with PersistentTarget(patched, coverage_map) as target:
        outcome = target.run(OVERFLOW)
    assert not outcome.crashed


def test_a_crash_still_carries_the_coverage_that_reached_it(coverage_map, vulnerable):
    """The path into a crash is what makes crashes comparable to each other, and it only
    survives because the map is written into shared memory rather than copied out at the
    end -- which a dead process cannot do."""
    with PersistentTarget(vulnerable, coverage_map) as target:
        outcome = target.run(OVERFLOW)
    assert outcome.crashed
    assert sum(1 for byte in outcome.coverage if byte) > 0


def test_the_target_recovers_after_a_crash(coverage_map, vulnerable):
    with PersistentTarget(vulnerable, coverage_map) as target:
        target.run(OVERFLOW)
        after = target.run(GOOD)
    assert not after.crashed
    assert target.restarts >= 1


def test_no_input_is_reported_as_a_crash_merely_for_its_length(coverage_map, vulnerable):
    """The regression that matters most, because it was invisible.

    A pipe on this platform is a text-mode stream by default, and a text-mode stream
    treats 0x1A as end-of-file. The four-byte length header is written little-endian, so
    every length from 26 to 31 has 0x1A as its low byte -- and the target read that
    header, saw end-of-file, and exited cleanly, which the fuzzer reported as a crash.
    The crashes were reproducible, which is what made them convincing.

    The check is every byte value at that length. An input made of nothing but zeroes
    cannot reach the parser's first comparison, so nothing here may be reported.
    """
    with PersistentTarget(vulnerable, coverage_map) as target:
        for value in range(256):
            outcome = target.run(bytes([value]) * 26)
            assert not outcome.crashed,                 "an input of 0x%02x bytes was reported as a crash" % value


def test_a_body_byte_that_text_mode_would_mangle_is_delivered_intact(coverage_map,
                                                                     vulnerable):
    """0x1A ends a text-mode stream and 0x0D is rewritten. Both are ordinary bytes in
    the data a fuzzer sends, so the stream has to be binary at both ends."""
    with PersistentTarget(vulnerable, coverage_map) as target:
        for body in (b"\x1a" * 20, b"\x0d" * 20, b"\x0d\x0a" * 10):
            outcome = target.run(b"RECS" + bytes([1, 1, len(body)]) + body)
            assert not outcome.crashed


def test_the_length_the_target_sees_is_the_length_that_was_sent(coverage_map, vulnerable):
    """A length is a four-byte little-endian number, and every value of its low byte has
    to survive the trip."""
    with PersistentTarget(vulnerable, coverage_map) as target:
        for length in (1, 11, 25, 26, 27, 31, 32, 33, 63, 64, 255, 256):
            outcome = target.run(b"Q" * length)
            assert not outcome.crashed, "a %d-byte input was reported as a crash" % length


def test_a_run_that_never_answers_is_recorded_rather_than_waited_on(coverage_map,
                                                                    vulnerable):
    """A corrupted run can spin. A fuzzer that waits for it is a fuzzer that has stopped."""
    with PersistentTarget(vulnerable, coverage_map, timeout=0.25) as target:
        outcome = target.run(OVERFLOW)
    assert outcome.crashed
    assert target.restarts >= 1


# --- the feedback rule ---------------------------------------------------------------

def test_an_input_that_reaches_nothing_new_is_not_interesting(coverage_map, vulnerable):
    with PersistentTarget(vulnerable, coverage_map) as target:
        outcome = target.run(GOOD)
        first = coverage_map.new_coverage(outcome.coverage)
        second = coverage_map.new_coverage(outcome.coverage)
    assert first > 0
    assert second == 0, "the same path must not be interesting twice"


def test_the_union_of_edges_only_grows(coverage_map, vulnerable):
    with PersistentTarget(vulnerable, coverage_map) as target:
        seen = []
        for payload in (GOOD, TAG + bytes([1, 1, 8]) + b"B" * 8,
                        TAG + bytes([2, 4, 0, 0, 0, 42])):
            outcome = target.run(payload)
            coverage_map.new_coverage(outcome.coverage)
            seen.append(coverage_map.total_edges)
    assert seen == sorted(seen)


def test_the_same_defect_reached_twice_is_reported_once(coverage_map, vulnerable):
    """Bucketing collapses duplicates, which is the whole reason for it.

    Two inputs are one defect when they reach the same edges and die the same way, and the
    same input always does. What is not claimed -- and cannot be, honestly -- is that two
    *different* inputs which overrun the same buffer are one defect: the overrun corrupts
    the stack, and what the process does next is a property of the compiled code rather
    than of the input. Two of them may take different paths out of the same corruption,
    and reporting them separately is the safe direction to be wrong in.

    So this feeds one crashing input twice and requires one finding, not two.
    """
    record = TAG + bytes([1, 1, 200]) + b"A" * 200
    with PersistentTarget(vulnerable, coverage_map) as target:
        engine = Engine(target, seed=1, dictionary=(TAG,))
        first = engine._record_crash(target.run(record), record, "mutation")
        second = engine._record_crash(target.run(record), record, "mutation")
    assert len(engine.findings) == 1, "the same defect was reported twice"
    assert first.signature == second.signature
    assert engine.stats.crashes == 1, "the duplicate was counted as a second crash"


def test_the_signature_describes_the_path_and_not_the_exit_code(coverage_map, vulnerable):
    """A signature derived from how the process ended would collapse every crash of a
    kind into one, which is the opposite of what it is for."""
    record = TAG + bytes([1, 1, 200]) + b"A" * 200
    with PersistentTarget(vulnerable, coverage_map) as target:
        crashed = target.run(record)
        clean = target.run(GOOD)
    assert crashed.crashed and not clean.crashed
    assert (coverage_map.signature(crashed.coverage)
            != coverage_map.signature(clean.coverage))


# --- the mutation engine -------------------------------------------------------------

def test_a_run_is_reproducible_from_its_seed():
    one = [bytes(Mutator(seed=99, dictionary=(TAG,)).generate(GOOD, GOOD))
           for _ in range(20)]
    two = [bytes(Mutator(seed=99, dictionary=(TAG,)).generate(GOOD, GOOD))
           for _ in range(20)]
    assert one == two


def test_different_seeds_produce_different_work():
    one = {bytes(Mutator(seed=1, dictionary=(TAG,)).generate(GOOD, GOOD))
           for _ in range(50)}
    two = {bytes(Mutator(seed=2, dictionary=(TAG,)).generate(GOOD, GOOD))
           for _ in range(50)}
    assert one != two


def test_mutation_produces_varied_output():
    mutator = Mutator(seed=5, dictionary=(TAG,))
    produced = {bytes(mutator.generate(GOOD, GOOD)) for _ in range(300)}
    assert len(produced) > 250, "mutations are not exploring"


def test_every_mutation_primitive_changes_something():
    """A primitive that returns its input unchanged is dead weight in the budget."""
    mutator = Mutator(seed=3, dictionary=(TAG,))
    for name in ("flip_bits", "set_byte", "delete_block", "clone_block",
                 "insert_bytes", "insert_dictionary"):
        before = bytearray(GOOD)
        after = getattr(mutator, name)(bytearray(GOOD))
        assert bytes(after) != bytes(before), "%s does nothing" % name


def test_the_dictionary_is_used():
    """The tag is four bytes a random search will not find, so the one thing the fuzzer
    is told has to actually reach the output."""
    mutator = Mutator(seed=11, dictionary=(TAG,))
    carrying = sum(1 for _ in range(300) if TAG in bytes(mutator.generate(GOOD, GOOD)))
    assert carrying > 50


def test_boundary_values_are_the_ones_a_comparison_would_use():
    """Thirty-two is the buffer size, so thirty-one and thirty-three are the values that
    matter -- not a thousand random bytes."""
    assert 32 in INTERESTING_8
    assert 33 in INTERESTING_8
    assert 31 in INTERESTING_8
    assert 0 in INTERESTING_8 and 255 in INTERESTING_8


def test_splicing_combines_two_inputs():
    mutator = Mutator(seed=8, dictionary=(TAG,))
    other = TAG + bytes([1, 1, 30]) + b"Z" * 30
    joined = mutator.splice(bytearray(GOOD), other)
    assert bytes(joined) != GOOD
    assert b"Z" in bytes(joined) or len(joined) != len(GOOD)


# --- the corpus ----------------------------------------------------------------------

def test_the_corpus_rejects_a_duplicate():
    corpus = Corpus()
    assert corpus.add(b"one")
    assert not corpus.add(b"one")
    assert len(corpus) == 1


def test_the_corpus_prefers_the_inputs_that_found_the_most():
    """The weighting is the difference between building on discoveries and wandering."""
    import random
    corpus = Corpus()
    corpus.add(b"quiet", new_edges=1)
    corpus.add(b"loud", new_edges=50)
    rng = random.Random(0)
    picked = [corpus.choose(rng).data for _ in range(2000)]
    assert picked.count(b"loud") > picked.count(b"quiet") * 5


def test_minimisation_shrinks_an_input_and_keeps_the_property():
    """Minimising to something that fails differently would be substitution, not
    minimisation, so the test is that the property is unchanged."""
    target_bytes = b"RECS\x01\x01\xc8" + b"A" * 200

    def still_the_same(candidate):
        return candidate.startswith(TAG) and len(candidate) > 40

    smaller = minimise(target_bytes, still_the_same)
    assert len(smaller) < len(target_bytes)
    assert still_the_same(smaller)


def test_minimisation_refuses_an_input_that_does_not_have_the_property():
    original = b"not the right shape"
    assert minimise(original, lambda candidate: False) == original


# --- the search ----------------------------------------------------------------------

def test_the_fuzzer_finds_the_defect_from_an_empty_seed(coverage_map, vulnerable):
    """The load-bearing test. Nothing is handed to the search except the tag.

    How many executions it takes is a property of the compiled target rather than of the
    search -- the same source built two ways has different code and so a different
    landscape to cross -- so the budget is generous and the bound that matters is the one
    in time. What is asserted is that the defect is reached, not how quickly.
    """
    with PersistentTarget(vulnerable, coverage_map) as target:
        engine = Engine(target, seed=4, dictionary=(TAG,))
        engine.add_seed(b"")
        engine.run(budget=120000, time_limit=SEARCH_SECONDS, stop_after_crashes=1)
    assert engine.findings, "the search did not reach the defect"
    assert engine.stats.edges_found > 20, "coverage guidance found almost nothing"


def test_the_search_builds_a_corpus_rather_than_keeping_everything(coverage_map,
                                                                   vulnerable):
    with PersistentTarget(vulnerable, coverage_map) as target:
        engine = Engine(target, seed=6, dictionary=(TAG,))
        engine.add_seed(b"")
        engine.run(budget=3000, time_limit=60)
    assert len(engine.corpus) > 1, "nothing was learned"
    assert len(engine.corpus) < engine.stats.executions / 10, \
        "the corpus is keeping almost everything, so the rule is not filtering"


def test_a_crash_is_recorded_with_the_path_that_reached_it(coverage_map, vulnerable):
    with PersistentTarget(vulnerable, coverage_map) as target:
        engine = Engine(target, seed=5, dictionary=(TAG,))
        engine.add_seed(b"")
        engine.run(budget=4000, time_limit=60, stop_after_crashes=1)
    assert engine.findings
    for finding in engine.findings.values():
        assert finding.edges > 0, "a crash without a path cannot be compared to another"
        assert finding.status


def test_the_same_seed_reproduces_the_same_search(coverage_map, vulnerable):
    def search():
        with PersistentTarget(vulnerable, coverage_map) as target:
            engine = Engine(target, seed=42, dictionary=(TAG,))
            engine.add_seed(b"")
            engine.run(budget=800, time_limit=60)
        return sorted(f.data for f in engine.findings.values())

    assert search() == search()


def test_grouping_puts_the_aimable_failures_before_the_hangs():
    class Fake:
        def __init__(self, status, size):
            self.status, self.size, self.signature = status, size, status

    grouped = group({"a": Fake("timeout", 5), "b": Fake("access violation", 9),
                     "c": Fake("illegal instruction", 2)})
    assert [f.status for f in grouped][-1] == "timeout"


# --- the exploit ----------------------------------------------------------------------

def test_the_overflow_takes_control_of_the_vulnerable_build(exploit_builds, tmp_path):
    """Not "it crashes" but "the instruction pointer went where the attacker put it"."""
    vulnerable, _ = exploit_builds
    found = find_offset(vulnerable, tmp_path)
    assert found.reached, found.note


def test_the_fixed_build_does_not_take_control_and_does_not_crash(exploit_builds,
                                                                  tmp_path):
    """A fix that turned a takeover into a crash would not be a fix."""
    vulnerable, patched = exploit_builds
    result = demonstrate(vulnerable, patched, tmp_path)
    assert result["vulnerable_reached"]
    assert result["patched_reached"] is False
    assert result["patched_crashed"] is False


def test_the_offset_is_found_by_measurement(exploit_builds, tmp_path):
    """The distance from the buffer to the pointer depends on the compiler, so it is
    measured rather than assumed."""
    vulnerable, _ = exploit_builds
    found = find_offset(vulnerable, tmp_path)
    assert found.offset >= 32, "the pointer cannot sit inside the buffer"
    assert found.address != 0, "the harness reports the address it used"


def test_the_exploit_reports_a_usable_address(exploit_builds, tmp_path):
    vulnerable, patched = exploit_builds
    result = demonstrate(vulnerable, patched, tmp_path)
    assert result["address"] > 0x1000


# --- the toolchain ---------------------------------------------------------------------

def test_the_toolchain_is_reported_or_refused_clearly():
    found = describe()
    assert set(found) == {"available", "compiler", "reason"}
    if found["available"]:
        assert found["compiler"] and found["reason"] is None
    else:
        assert found["reason"], "a refusal has to say what was looked for"
