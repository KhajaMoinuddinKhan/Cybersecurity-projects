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

import json
import pytest

from src.build import (BuildError, available_targets, build, describe,
                       sanitizer_available)
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
from src.target import ForkServerTarget, PersistentTarget, Target

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


# --- what the comparisons teach it ------------------------------------------------

def test_the_tag_is_recovered_from_the_comparisons(coverage_map, vulnerable):
    """A parser walks a magic number one byte at a time, so the comparisons name four
    values and never name the word they make. Joining consecutive matched constants
    recovers it.

    Three things had to be right and each was wrong in turn. The width is not one --
    `d[0] != 'R'` is compiled as a four-byte comparison, so a filter for single-byte
    comparisons matched none of the tag. The run has to be a run of *matches*, which is
    what separates a byte of the magic number from a null check, both of which are small
    constants. And the comparisons that are not data have to be ignored rather than
    treated as a break: the four bytes of a tag are never adjacent in the list, so
    resetting on anything else meant the run never reached two and the four bytes it had
    correctly identified were never joined.
    """
    engine = Engine(None, seed=4, dictionary=())
    good = b"RECS" + bytes([1, 1, 4]) + b"ABcd"
    with PersistentTarget(vulnerable, coverage_map) as target:
        target.run(good)
        engine.harvest(target.coverage.comparisons())
    assert b"RECS" in engine.sequences, \
        "the tag was not recovered; it learned %r" % sorted(engine.sequences)[:8]
    for learned in (b"RE", b"REC"):
        assert learned in engine.sequences


def test_the_sequences_reach_the_search(coverage_map, vulnerable):
    """And they are not merely collected: a sequence is offered to the mutator as a
    token, so the word is tried whole rather than a byte at a time."""
    engine = Engine(None, seed=4, dictionary=())
    with PersistentTarget(vulnerable, coverage_map) as target:
        target.run(b"RECS" + bytes([1, 1, 4]) + b"ABcd")
        engine.harvest(target.coverage.comparisons())
    tokens = tuple(sorted(engine.learned)) + tuple(sorted(engine.sequences))
    assert any(isinstance(x, bytes) and x == b"RECS" for x in tokens), \
        "the tag is not among the tokens the mutator is given"


def test_the_search_reaches_the_parser_from_every_seed():
    """The parser needs a magic number, a count, a type and a length right at once, and
    the search used to reach it in about a third of runs.

    The reason was that a comparison says what value the program wanted and never says
    where it wanted it, so the wanted bytes were placed at random offsets and a magic
    number is four bytes in four particular places in a particular order. The deliberate
    pass tries each wanted value at each position, which is where the position comes
    from. Four seeds here rather than one, because the whole point is that one seed was
    what hid this.
    """
    exe = build(vulnerable=True, force=True, target="parser")
    for seed in (1, 3, 7, 99):
        # A map of its own per seed. A shared one carries the edges an earlier seed
        # already found, so "new coverage" stops being new and the search stalls for a
        # reason that has nothing to do with the seed.
        coverage = CoverageMap("cgf-reliability-%d" % seed)
        with PersistentTarget(exe, coverage) as target:
            engine = Engine(target, seed=seed, dictionary=())
            engine.add_seed(b"")
            engine.run(budget=150000, time_limit=SEARCH_SECONDS, stop_after_crashes=1)
        coverage.close()
        assert engine.findings, \
            "seed %d did not reach the parser within the budget" % seed


def test_the_deliberate_pass_tries_the_wanted_values_where_they_are_wanted(coverage_map,
                                                                          vulnerable):
    """It is not enough to try boundary values at each position -- that builds a length
    field and does not build a word. The values that came from the comparisons are the
    ones that matter, and they are what the pass walks each position with."""
    engine = Engine(None, seed=4, dictionary=())
    with PersistentTarget(vulnerable, coverage_map) as target:
        target.run(b"RECS" + bytes([1, 1, 4]) + b"ABcd")
        engine.harvest(target.coverage.comparisons())
    partial = b"RE\x9cO\x01\x00\x00ABCD"
    engine.corpus.add(partial, edges=0, new_edges=1)
    candidates = engine.deterministic(engine.corpus.entries[-1])
    assert any(c[:3] == b"REC" for c in candidates), \
        "the pass never put the wanted byte where the parser reads it"


# --- tidying up, and reading back --------------------------------------------------

def test_minimising_stops_when_the_clock_does():
    """A crashing run costs about a hundred milliseconds, because the process dies and is
    started again, while a run that does not crash costs a tenth of a millisecond. So the
    cost of tidying a reproducer is set by the clock and not by the number of attempts,
    and an attempt budget of two thousand was two hundred seconds for one crash.

    Here every trial is slow on purpose, which is what a crashing run is.
    """
    import time as _time
    data = b"A" * 4000 + b"TRIGGER"
    calls = []

    def slow(candidate):
        calls.append(1)
        _time.sleep(0.01)               # what a crashing run costs, exaggerated
        return b"TRIGGER" in candidate

    start = _time.monotonic()
    minimise(data, slow, deadline=_time.monotonic() + 0.5)
    took = _time.monotonic() - start
    assert took < 3.0, "minimising ran for %.1fs against a half-second deadline" % took
    assert len(calls) < 400, "it made %d trials against a half-second deadline" % len(calls)


def test_minimising_still_shrinks_when_it_has_the_time():
    """The bound must not be an excuse not to work: given the time, it still shrinks."""
    data = b"X" * 4096 + b"KEEP" + b"Y" * 4096
    out = minimise(data, lambda c: b"KEEP" in c)
    assert b"KEEP" in out
    assert len(out) < len(data) // 2, "it did not shrink: %d of %d" % (len(out), len(data))


def test_the_report_reads_what_the_fuzz_wrote(tmp_path):
    """`fuzz --out` writes a directory and `report` read a file, so the output of one was
    not the input of the other. Both shapes are accepted."""
    out = tmp_path / "findings"
    out.mkdir()
    (out / "findings.json").write_text(json.dumps([
        {"signature": "abcd1234", "status": "access violation", "size": 40,
         "hex": "41" * 40, "found_at_execution": 7, "edges": 12}]), encoding="utf-8")
    from src.cli import main
    for target in (str(out), str(out / "findings.json")):
        assert main(["report", "--findings", target]) == 0, "report failed on %s" % target


# --- the fork server --------------------------------------------------------------

def test_the_fork_server_is_refused_where_there_is_no_fork(coverage_map, vulnerable):
    """Refusing is the answer. A caller that asked for one and silently got something
    else would be measuring the wrong thing and would not know."""
    import os as _os
    if _os.name != "nt":
        pytest.skip("this platform has fork, so there is nothing to refuse")
    with pytest.raises(ValueError) as raised:
        ForkServerTarget(vulnerable, coverage_map)
    assert "no fork" in str(raised.value)


def test_the_fork_server_runs_inputs_and_survives_a_crash(coverage_map, vulnerable):
    """The other thing it buys, and it is worth as much as the speed: a crash takes the
    child and not the server, so the search is never interrupted by the thing it is
    searching for and there is no restart to pay for."""
    import os as _os
    if _os.name == "nt":
        pytest.skip("this platform has no fork")
    with ForkServerTarget(vulnerable, coverage_map) as target:
        good = target.run(GOOD)
        crash = target.run(OVERFLOW)
        after = target.run(GOOD)
    assert not good.crashed
    assert crash.crashed, "the overflow did not crash through the fork server"
    assert not after.crashed, "the server did not survive the crash"
    assert target.crashes == 1


def test_the_fork_server_gives_the_search_what_it_needs(coverage_map):
    import os as _os
    if _os.name == "nt":
        pytest.skip("this platform has no fork")
    exe = build(vulnerable=True, force=True)
    with ForkServerTarget(exe, coverage_map) as target:
        engine = Engine(target, seed=4, dictionary=())
        engine.add_seed(b"")
        engine.run(budget=60000, time_limit=SEARCH_SECONDS, stop_after_crashes=1)
    assert engine.findings, "the search did not reach the defect through the server"


def test_the_fork_server_reports_a_signal_as_a_signal(coverage_map, vulnerable):
    """A child killed by a signal is reported the way a shell reports it, and turned
    back into a signal rather than left as a number over a hundred."""
    import os as _os
    if _os.name == "nt":
        pytest.skip("this platform has no fork")
    with ForkServerTarget(vulnerable, coverage_map) as target:
        crash = target.run(OVERFLOW)
    assert crash.crashed
    assert crash.exit_code is not None and crash.exit_code < 0, \
        "a signal was reported as an exit code: %r" % crash.exit_code
    assert "killed by" in crash.status


# --- what the comparisons teach it ----------------------------------------------

def test_the_target_names_the_values_it_compares_against(coverage_map, vulnerable):
    """The comparisons are the half of the feedback that says what the program wanted,
    rather than only where it went."""
    with PersistentTarget(vulnerable, coverage_map) as target:
        target.run(TAG + bytes([1, 1, 4]) + b"ABcd")
        comparisons = coverage_map.comparisons()
    assert comparisons, "no comparisons were reported at all"
    constants = [a for a, b, width, is_constant in comparisons if is_constant]
    assert constants, "no comparison was against a constant"
    for byte in TAG:
        assert byte in constants, \
            "the target never named %d, which is one of the tag's bytes" % byte


def test_the_search_learns_the_tag_without_being_told_it(coverage_map, vulnerable):
    """The load-bearing test for the comparison feedback.

    An empty dictionary is the honest starting point: the search is told nothing about
    the format and has to find the tag the way it finds everything else. It can, because
    the parser compares each byte of it against a constant and the comparison names the
    constant.
    """
    with PersistentTarget(vulnerable, coverage_map) as target:
        engine = Engine(target, seed=4, dictionary=())
        engine.add_seed(b"")
        engine.run(budget=200000, time_limit=SEARCH_SECONDS, stop_after_crashes=1)
    for byte in TAG:
        assert byte in engine.learned, \
            "the search never learned %d, one of the tag's bytes" % byte
    assert engine.findings, "and it did not reach the defect either"


def test_a_learned_token_reaches_the_mutations():
    """A value learned from a comparison has to be usable, not merely recorded."""
    mutator = Mutator(seed=3)
    produced = {bytes(mutator.insert_learned(bytearray(b"AAAA"), (0x52,)))
                for _ in range(50)}
    assert any(b"\x52" in p for p in produced), "the learned token never appears"


def test_solving_a_comparison_rewrites_the_byte_the_program_read():
    """The guided mutation: the program compared a byte of the input against a constant,
    so the mutation writes the constant over that byte."""
    mutator = Mutator(seed=1)
    # the target read 0x58 ('X') and wanted 0x52 ('R')
    comparisons = [(0x52, 0x58, 1, True)]
    result = bytes(mutator.solve_comparison(b"XXXX", comparisons))
    assert result == b"RXXX" or result == b"XRXX" or result == b"XXRX" or result == b"XXXR"


def test_a_comparison_between_two_read_values_is_not_used():
    """Only a comparison against a constant names something the program wanted."""
    mutator = Mutator(seed=1)
    not_constant = [(0x52, 0x58, 1, False)]
    assert bytes(mutator.solve_comparison(b"XXXX", not_constant)) == b"XXXX"


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
        engine.run(budget=60000, time_limit=SEARCH_SECONDS, stop_after_crashes=1)
    assert engine.findings
    for finding in engine.findings.values():
        assert finding.edges > 0, "a crash without a path cannot be compared to another"
        assert finding.status


def test_the_same_seed_reproduces_the_same_search(coverage_map, vulnerable):
    """A search is reproducible from its seed, and its state is more than the seed.

    What a search has discovered lives in the coverage map, so running two searches
    against one map runs the second with the first's knowledge and the two are not
    comparable. The map is reset between them, which is what makes this a comparison of
    two searches rather than a comparison of a search against a search with a head start.
    """

    def search():
        coverage_map.reset()
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
    assert found.disclosed > 0x1000, "the disclosure has to name a real address"
    assert found.target > 0x1000, "and the exploit has to aim somewhere real"


def test_the_exploit_aims_using_what_the_parser_disclosed(exploit_builds, tmp_path):
    """The address is not known in advance and is not assumed: it is read out of the
    parser and used. An exploit that worked without it would not be using it."""
    vulnerable, patched = exploit_builds
    result = demonstrate(vulnerable, patched, tmp_path)
    assert result["vulnerable_reached"]
    assert result["disclosed"] > 0x1000, "nothing was disclosed"
    assert result["target"] != result["disclosed"], \
        "the exploit aimed at the disclosed address rather than computing from it"
    assert result["target"] == result["disclosed"] + result["delta"]


def test_the_fixed_build_removes_the_disclosure(exploit_builds, tmp_path):
    """The fix is two things, and the second is what stops the exploit. A build that
    bounded the copy but still handed out an address would still be leaking."""
    vulnerable, patched = exploit_builds
    result = demonstrate(vulnerable, patched, tmp_path)
    assert result["patched_reached"] is False
    assert "disclosure is gone" in (result["patched_note"] or ""), \
        "the fix did not remove the disclosure: %s" % result["patched_note"]


def test_the_disclosure_names_the_function_the_parser_stores(exploit_builds, tmp_path):
    """The disclosed address has to be the one the parser stored, and the way to check
    that is to use it: the harness computes where the function it wants must be from what
    was disclosed, compares that against the function's real address, and refuses to go
    on if they disagree. A disclosure that named the wrong thing would stop it there.

    This is read through the harness rather than by loading the target as a library,
    because a position-independent executable cannot be loaded as one -- which is true on
    the platform this runs on in CI and is not a fact about the disclosure.
    """
    vulnerable, _ = exploit_builds
    found = find_offset(vulnerable, tmp_path)
    assert found.reached, found.note
    assert found.disclosed > 0x1000, "nothing real was disclosed"
    assert found.target == found.disclosed + found.delta


# --- a second target, and the search reaching it --------------------------------

def test_more_than_one_target_is_shipped():
    """A fuzzer that has only ever been pointed at the program it was written for has
    not been tested in the way that matters, so the target is a parameter and more than
    one is shipped."""
    names = available_targets()
    assert "parser" in names
    assert len(names) > 1, "there is nothing to check the claim against"


def test_the_second_target_builds(toolchain):
    exe = build(vulnerable=True, force=True, target="interval")
    assert exe.exists()
    patched = build(vulnerable=False, force=True, target="interval")
    assert patched.exists() and patched != exe


def test_the_search_finds_a_defect_in_a_target_it_was_not_written_for(coverage_map):
    """The point of the second target. The search is told nothing -- no dictionary, no
    seed beyond the empty input -- and the target is a different format with a different
    bug class from the one this was developed against."""
    exe = build(vulnerable=True, force=True, target="interval")
    with PersistentTarget(exe, coverage_map, timeout=2.0) as target:
        engine = Engine(target, seed=4, dictionary=())
        engine.add_seed(b"")
        engine.run(budget=300000, time_limit=SEARCH_SECONDS, stop_after_crashes=1)
    assert engine.findings, "the search did not reach the second target's defect"


def test_the_fixed_second_target_is_not_broken(coverage_map):
    exe = build(vulnerable=False, force=True, target="interval")
    with PersistentTarget(exe, coverage_map, timeout=2.0) as target:
        engine = Engine(target, seed=4, dictionary=())
        engine.add_seed(b"")
        engine.run(budget=60000, time_limit=SEARCH_SECONDS, stop_after_crashes=1)
    assert not engine.findings, "the fixed build still crashes"


def test_an_unknown_target_is_refused_clearly():
    from src.build import BuildError, target_directory
    try:
        target_directory("no-such-target")
    except BuildError as exc:
        assert "no target named" in str(exc)
    else:
        raise AssertionError("an unknown target was accepted")


# --- reaching defects that need a large input -----------------------------------

def test_growth_compounds_to_a_large_input():
    """Every other mutation changes an input by a few bytes, which is the wrong shape for
    a defect that only exists in a long one.

    One application roughly doubles, so the thing to check is that applying it repeatedly
    compounds -- which is what makes a long input reachable in a handful of mutations
    rather than hundreds that all have to survive.
    """
    mutator = Mutator(seed=5)
    data = bytearray(b"ABCD")
    sizes = [len(data)]
    for _ in range(6):
        data = mutator.grow(data)
        sizes.append(len(data))
    assert sizes == sorted(sizes), "growth shrank the input"
    assert sizes[-1] >= 4 * 8, "six applications of a doubling did not compound: %s" % sizes


def test_field_mutations_aim_at_the_start():
    """A field that decides everything is usually at the front, and a position chosen
    uniformly over a long input almost never lands on it."""
    mutator = Mutator(seed=9)
    big = bytearray(b"\x01\x00" + b"\x11" * 4000)
    at_start = 0
    for _ in range(400):
        before = bytes(big[:64])
        after = bytes(mutator.set_interesting(bytearray(big), 2)[:64])
        if after != before:
            at_start += 1
    assert at_start > 100, "the start of the input is barely being touched"


def test_a_size_record_is_kept_and_a_small_change_is_not():
    corpus = Corpus()
    corpus.add(b"x" * 100, new_edges=5)
    assert not corpus.add_stepping_stone(b"y" * 110), "a small increase was kept"
    assert corpus.add_stepping_stone(b"y" * 200), "a large increase was not kept"
    assert any(e.found_by == "stepping stone" for e in corpus)


def test_stepping_stones_do_not_crowd_out_the_real_discoveries():
    """Left in the ordinary weighting they are chosen almost always, because a large
    input is nearly always one that has never been tried. That happened, and the search
    stopped finding anything."""
    import random
    corpus = Corpus()
    for i in range(10):
        corpus.add(bytes([i]) * 10, new_edges=5)
    corpus.add_stepping_stone(b"z" * 1000)
    rng = random.Random(0)
    chosen = [corpus.choose(rng) for _ in range(2000)]
    stones = sum(1 for e in chosen if e.found_by == "stepping stone")
    assert stones < len(chosen) // 4, "the stepping stones took over the search"
    assert stones > 0, "and they were never tried at all"


# --- the sanitizer ---------------------------------------------------------------

def test_whether_a_sanitizer_can_be_linked_is_answered_rather_than_assumed():
    """It links on one platform here and not the other, and a build that quietly went
    without one would make the report claim a precision it does not have."""
    assert isinstance(sanitizer_available(), bool)


def test_a_sanitizer_build_is_refused_when_it_cannot_be_linked(toolchain):
    """Asking for one where it does not link has to fail loudly. A silent fallback to a
    build without it is a report that says a defect was caught by a sanitizer when the
    sanitizer was never there."""
    if sanitizer_available():
        return          # it links here, so there is nothing to refuse
    with pytest.raises(BuildError) as raised:
        build(vulnerable=True, force=True, target="interval", sanitize=True)
    assert "cannot link a sanitizer" in str(raised.value)


def test_a_sanitizer_build_catches_what_the_plain_one_only_dies_of(toolchain):
    """The whole reason for it. A read past the end of an input is a read past the end of
    the memory the program was given, and the plain build dies of it without saying where
    or what -- or, worse, does not die at all, because the read stayed inside the buffer
    the harness happened to hand over."""
    if not sanitizer_available():
        pytest.skip("this toolchain cannot link a sanitizer")
    from multiprocessing import shared_memory
    exe = build(vulnerable=True, force=True, target="interval", sanitize=True)
    assert exe.exists()
    region = shared_memory.SharedMemory(name="cgf-test-asan", create=True, size=75792)
    try:
        # 16384 * 4 wraps to zero in sixteen bits, so the check accepts it on any input
        # at all, and the loop reads sixteen thousand intervals out of two bytes.
        payload = (16384).to_bytes(2, "little")
        scratch = exe.parent / "asan-input.bin"
        scratch.write_bytes(payload)
        import subprocess as sp
        done = sp.run([str(exe), "cgf-test-asan", str(scratch)], capture_output=True,
                      text=True, timeout=60)
        said = (done.stderr or "") + (done.stdout or "")
        assert "AddressSanitizer" in said, "the sanitizer said nothing"
        assert "overflow" in said, "and did not name an overflow"
        assert "cgf_parse" in said, "and did not say where"
    finally:
        region.close()
        region.unlink()


# --- the toolchain ---------------------------------------------------------------------

def test_the_toolchain_is_reported_or_refused_clearly():
    found = describe()
    assert set(found) == {"available", "compiler", "reason"}
    if found["available"]:
        assert found["compiler"] and found["reason"] is None
    else:
        assert found["reason"], "a refusal has to say what was looked for"
