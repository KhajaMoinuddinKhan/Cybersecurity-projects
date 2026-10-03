import hashlib
from pathlib import Path

import pytest

from src.cracker import (
    CrackResult,
    brute_candidates,
    brute_space,
    check_brute_length,
    crack_hash,
    crack_target,
    crack_targets,
    detect_algorithms,
    digest_text,
    hashes_per_second,
    mangle,
    ntlm_digest,
    parse_target,
    report_dict,
    require_algorithm,
    resolve_algorithms,
    rule_append_numeric,
    rule_append_punctuation,
    rule_capitalise,
    rule_leetspeak,
    rule_uppercase,
    wordlist_candidates,
)


def test_finds_candidate_from_supplied_values():
    result = crack_hash(digest_text("correct horse", "sha256"), ["nope", "correct horse"])
    assert result.match == "correct horse"
    assert result.attempts == 2


def test_reports_no_match_without_inventing_a_value():
    result = crack_hash(digest_text("different", "sha256"), ["one", "two"])
    assert result.match is None
    assert result.attempts == 2


def test_wordlist_is_streamed_and_blank_lines_are_skipped(tmp_path: Path):
    path = tmp_path / "words.txt"
    path.write_text("\none\n\ntwo\n")
    assert list(wordlist_candidates(path)) == ["one", "two"]


def test_invalid_digest_is_rejected():
    with pytest.raises(ValueError, match="valid sha256"):
        crack_hash("not-a-digest", [], algorithm="sha256")


def test_unsupported_algorithm_names_the_choices():
    with pytest.raises(ValueError, match="Unsupported algorithm 'crc32'"):
        require_algorithm("crc32")
    assert require_algorithm("SHA256") == "sha256"


# --- algorithm auto-detection -------------------------------------------------


def test_detects_algorithm_from_digest_length():
    assert detect_algorithms("a" * 40) == ("sha1",)
    assert detect_algorithms("a" * 64) == ("sha256",)
    assert detect_algorithms("a" * 96) == ("sha384",)
    assert detect_algorithms("a" * 128) == ("sha512",)


def test_md5_and_ntlm_lengths_are_ambiguous():
    assert detect_algorithms("a" * 32) == ("md5", "ntlm")


def test_unrecognised_digest_length_is_rejected():
    with pytest.raises(ValueError, match="matches no supported algorithm"):
        detect_algorithms("a" * 10)


def test_non_hexadecimal_digest_is_rejected():
    with pytest.raises(ValueError, match="not a hexadecimal digest"):
        detect_algorithms("z" * 64)


def test_all_resolves_an_ambiguous_digest():
    assert resolve_algorithms("a" * 32, try_all=True) == ("md5", "ntlm")


def test_ambiguous_digest_needs_a_choice():
    with pytest.raises(ValueError, match="pass --algorithm or --all"):
        resolve_algorithms("a" * 32)


def test_explicit_algorithm_overrides_detection():
    assert resolve_algorithms("a" * 32, algorithm="ntlm") == ("ntlm",)
    assert resolve_algorithms("a" * 64, algorithm="md5") == ("md5",)


def test_crack_target_auto_detects_the_algorithm():
    digest = digest_text("hunter", "sha256")
    results = crack_target(digest, lambda: iter(["nope", "hunter"]))
    assert [result.algorithm for result in results] == ["sha256"]
    assert results[0].match == "hunter"


# --- NTLM ---------------------------------------------------------------------


def test_ntlm_matches_the_known_vector():
    assert ntlm_digest("password") == "8846f7eaee8fb117ad06bdd830b7586c"
    assert digest_text("password", "ntlm") == "8846f7eaee8fb117ad06bdd830b7586c"


def test_ntlm_candidate_is_recovered():
    result = crack_hash(ntlm_digest("password"), ["nope", "password"], algorithm="ntlm")
    assert result.match == "password"
    assert result.algorithm == "ntlm"


def test_ntlm_rejects_a_salt():
    with pytest.raises(ValueError, match="NTLM hashes are unsalted"):
        digest_text("password", "ntlm", salt="pepper")


# --- salted hashes ------------------------------------------------------------


def test_parse_target_recognises_hash_salt_layout():
    digest = "5f4dcc3b5aa765d61d8327deb882cf99"
    assert parse_target(f"{digest}:pepper") == (digest, "pepper", "suffix")


def test_parse_target_recognises_salt_hash_layout():
    digest = "5f4dcc3b5aa765d61d8327deb882cf99"
    assert parse_target(f"pepper:{digest}") == (digest, "pepper", "prefix")


def test_salted_digest_appends_and_prepends():
    assert digest_text("password", "md5", salt="pepper", salt_position="suffix") == hashlib.md5(b"passwordpepper").hexdigest()
    assert digest_text("password", "md5", salt="pepper", salt_position="prefix") == hashlib.md5(b"pepperpassword").hexdigest()


def test_salted_targets_are_cracked_in_either_layout():
    suffix = hashlib.md5(b"passwordpepper").hexdigest()
    prefix = hashlib.md5(b"pepperpassword").hexdigest()
    for target in (f"{suffix}:pepper", f"pepper:{prefix}"):
        results = crack_target(target, lambda: iter(["nope", "password"]), algorithm="md5")
        assert results[0].match == "password"
        assert results[0].salt == "pepper"


def test_explicit_salt_uses_the_requested_position():
    digest = hashlib.md5(b"pepperpassword").hexdigest()
    results = crack_target(digest, lambda: iter(["password"]), algorithm="md5", salt="pepper", salt_position="prefix")
    assert results[0].match == "password"
    assert results[0].salt_position == "prefix"


def test_ambiguous_salted_layout_needs_a_position():
    target = "a" * 32 + ":" + "b" * 32
    with pytest.raises(ValueError, match="ambiguous"):
        parse_target(target)
    assert parse_target(target, salt_position="suffix") == ("a" * 32, "b" * 32, "suffix")


def test_crack_target_refuses_ntlm_with_a_salt():
    with pytest.raises(ValueError, match="unsalted"):
        crack_target(ntlm_digest("password"), lambda: iter(["password"]), algorithm="ntlm", salt="pepper")


# --- mangling rules -----------------------------------------------------------


def test_capitalise_rule():
    assert rule_capitalise("summer") == ["Summer"]


def test_uppercase_rule():
    assert rule_uppercase("summer") == ["SUMMER"]


def test_append_numeric_rule():
    assert rule_append_numeric("summer") == ["summer1", "summer12", "summer123", "summer1234"]


def test_append_punctuation_rule():
    assert rule_append_punctuation("summer") == ["summer!", "summer.", "summer?", "summer@", "summer#"]


def test_leetspeak_rule():
    variants = rule_leetspeak("password")
    assert "p4ssword" in variants
    assert "passw0rd" in variants
    assert "p455w0rd" in variants


def test_mangle_includes_the_base_word_and_deduplicates():
    variants = mangle("summer")
    assert variants[0] == "summer"
    assert "Summer" in variants
    assert len(variants) == len(set(variants))


def test_mangle_can_select_a_subset_of_rules():
    assert mangle("summer", ["capitalise"]) == ["summer", "Summer"]


def test_rules_recover_a_mangled_candidate():
    result = crack_hash(hashlib.md5(b"Password").hexdigest(), mangle("password"), algorithm="md5")
    assert result.match == "Password"


# --- bounded brute force ------------------------------------------------------


def test_brute_space_counts_lowercase_alphanumeric():
    assert brute_space(1) == 36
    assert brute_space(2) == 36 + 36 ** 2
    assert brute_space(4) == 1_727_604


def test_brute_guard_refuses_and_names_the_search_space():
    with pytest.raises(ValueError, match="62,193,780 candidates"):
        check_brute_length(5)
    assert check_brute_length(4) == 1_727_604


def test_brute_guard_rejects_a_nonpositive_length():
    with pytest.raises(ValueError, match="at least 1"):
        brute_space(0)


def test_brute_candidates_cover_short_strings():
    values = list(brute_candidates(2))
    assert len(values) == 36 + 36 ** 2
    assert values[:3] == ["a", "b", "c"]
    assert "ab" in values


def test_brute_recovers_a_short_candidate():
    result = crack_hash(hashlib.md5(b"ab").hexdigest(), brute_candidates(2), algorithm="md5")
    assert result.match == "ab"
    assert result.attempts == 38


# --- multiple targets and the work report ------------------------------------


def test_multiple_targets_are_reported_separately():
    targets = [digest_text("one", "sha1"), digest_text("two", "sha256")]
    results, errors = crack_targets(targets, lambda: iter(["one", "two"]))
    assert errors == []
    assert [(result.algorithm, result.match) for result in results] == [("sha1", "one"), ("sha256", "two")]


def test_crack_targets_keeps_per_target_errors_separate():
    results, errors = crack_targets(["not-a-digest"], lambda: iter(["one"]))
    assert results == []
    assert errors and errors[0][0] == "not-a-digest"


def test_report_dict_summarises_the_work():
    results, errors = crack_targets([digest_text("one", "sha256")], lambda: iter(["one"]))
    report = report_dict(results, errors)
    assert report["targets"] == 1
    assert report["matched"] == 1
    assert report["total_attempts"] == 1
    assert report["results"][0]["match"] == "one"
    assert report["results"][0]["algorithm"] == "sha256"


# --- rate calculation ---------------------------------------------------------


def test_hashes_per_second():
    assert hashes_per_second(1000, 0.5) == 2000.0
    assert hashes_per_second(5, 0) == 0.0


def test_result_rate_matches_the_helper():
    result = CrackResult("md5", 1000, None, 0.5)
    assert result.hashes_per_second == 2000.0


def test_a_result_keeps_its_target_and_salt_for_reporting():
    result = crack_hash(hashlib.md5(b"passwordpepper").hexdigest(), ["password"], algorithm="md5", salt="pepper")
    assert result.target == hashlib.md5(b"passwordpepper").hexdigest()
    assert result.salt == "pepper"
    assert result.salt_position == "suffix"
