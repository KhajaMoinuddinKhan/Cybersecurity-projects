from pathlib import Path
import pytest
from src.cracker import crack_hash, digest_text, wordlist_candidates


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
        crack_hash("not-a-digest", [])
