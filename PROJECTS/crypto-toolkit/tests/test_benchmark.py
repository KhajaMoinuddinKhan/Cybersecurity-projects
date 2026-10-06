"""The benchmark, and the security figures it is not allowed to invent.

A benchmark is the easiest thing in this repository to fake: a timing is a
number that looks authoritative and cannot be checked by reading it. So the
tests here do not assert timings -- they assert the things that would make the
timings meaningless if they were wrong: that the sizes are the real ones, that
the security strengths come from the standards, and that a row exists for every
scheme the report claims to cover.
"""

from __future__ import annotations

import pytest

from src.benchmark import (
    SECURITY_STRENGTHS,
    benchmark_mlkem,
    benchmark_rsa,
    format_report,
    run,
)
from src.mlkem import MLKEM_512, MLKEM_768, MLKEM_1024


@pytest.fixture(scope="module")
def small_run() -> dict:
    """One small measurement, shared: RSA key generation is the slow part."""
    return run(rsa_bits=(1024,), include_toy=False,
               keygen_iterations=1, mlkem_keygen_iterations=1, operation_iterations=2)


def test_every_security_strength_is_quoted_from_a_standard():
    """No figure may be a number this project chose.

    RSA's come from NIST SP 800-57 Part 1 Rev 5 Table 2 and ML-KEM's from the
    security categories of FIPS 203 Section 8. A row whose source names neither
    is a figure someone made up.
    """
    for name, (strength, source) in SECURITY_STRENGTHS.items():
        if name == "ML-KEM-toy":
            assert strength == 0 and "not a standard" in source
            continue
        assert "SP 800-57" in source or "FIPS 203" in source, name
        assert strength in (80, 112, 128, 192, 256), name


def test_the_rsa_strengths_are_the_published_ones():
    """SP 800-57 Table 2 rates a 2048-bit modulus at 112 bits and 3072 at 128."""
    assert SECURITY_STRENGTHS["RSA-2048"][0] == 112
    assert SECURITY_STRENGTHS["RSA-3072"][0] == 128


def test_the_mlkem_strengths_are_the_security_categories():
    """FIPS 203 Section 8: categories 1, 3 and 5."""
    assert SECURITY_STRENGTHS["ML-KEM-512"][0] == 128
    assert SECURITY_STRENGTHS["ML-KEM-768"][0] == 192
    assert SECURITY_STRENGTHS["ML-KEM-1024"][0] == 256


def test_the_measured_mlkem_sizes_are_the_parameter_sets():
    """The sizes in the report are measured from real keys, and must equal the
    sizes the standard specifies -- otherwise the table is reporting something
    other than what it ran."""
    rows = {row.name: row for row in benchmark_mlkem(
        (MLKEM_512, MLKEM_768, MLKEM_1024), keygen_iterations=1, operation_iterations=1)}
    for parameters in (MLKEM_512, MLKEM_768, MLKEM_1024):
        row = rows[parameters.name]
        assert row.public_key_bytes == parameters.encapsulation_key_bytes
        assert row.private_key_bytes == parameters.decapsulation_key_bytes
        assert row.ciphertext_bytes == parameters.ciphertext_bytes


def test_a_timing_is_a_positive_number_of_milliseconds(small_run):
    """Not a correctness claim, a sanity one: a zero would mean the timer was
    read wrong, and a negative would mean the clock went backwards."""
    for row in small_run["rsa"] + small_run["mlkem"]:
        for field in ("keygen_ms", "encapsulate_ms", "decapsulate_ms"):
            assert row[field] > 0, (row["name"], field)


def test_the_report_covers_every_scheme_it_claims_to(small_run):
    names = [row["name"] for row in small_run["rsa"] + small_run["mlkem"]]
    assert "RSA-1024" in names
    for parameters in (MLKEM_512, MLKEM_768, MLKEM_1024):
        assert parameters.name in names


def test_the_toy_set_is_off_unless_asked_for(small_run):
    assert all(row["name"] != "ML-KEM-toy" for row in small_run["mlkem"])


def test_the_toy_set_is_labelled_when_it_is_asked_for():
    result = run(rsa_bits=(1024,), include_toy=True, keygen_iterations=1,
                 mlkem_keygen_iterations=1, operation_iterations=1)
    toy = next(row for row in result["mlkem"] if row["name"] == "ML-KEM-toy")
    assert toy["security_bits"] == 0
    assert "NOT a standard set" in format_report(result)


def test_the_report_states_the_caveats_rather_than_only_numbers(small_run):
    """A table of numbers with no qualification is how a benchmark overclaims."""
    report = format_report(small_run)
    assert "wall-clock measurements" in report
    assert "quoted from the standards" in report
    assert "not a claim about optimised libraries" in report
    assert len(small_run["notes"]) >= 4
    for note in small_run["notes"]:
        assert len(note) > 40, "a caveat too short to say anything is not a caveat"


def test_the_report_lines_up_and_prints_every_row(small_run):
    report = format_report(small_run)
    lines = report.splitlines()
    assert lines[0].startswith("scheme")
    for row in small_run["rsa"] + small_run["mlkem"]:
        assert any(line.startswith(row["name"]) for line in lines), row["name"]


def test_a_key_size_the_table_does_not_cover_gets_no_number():
    """The benchmark must not interpolate a strength for an uncited size.

    A 1536-bit modulus is a real key size and is not in SP 800-57 Table 2, so
    the honest answer is that no strength is claimed for it.
    """
    from src.benchmark import security_strength_for
    strength, source = security_strength_for("RSA-1536")
    assert strength is None
    assert "no strength is claimed" in source
    rows = benchmark_rsa((1536,), keygen_iterations=1, operation_iterations=1)
    assert rows[0].security_bits is None
    assert "not quoted" in format_report({"rsa": [rows[0].as_dict()], "mlkem": [], "notes": ["x"]})


def test_rsa_rows_report_the_key_size_that_was_asked_for():
    rows = benchmark_rsa((1024,), keygen_iterations=1, operation_iterations=1)
    assert len(rows) == 1
    assert rows[0].name == "RSA-1024"
    assert rows[0].public_key_bytes == 128
