"""The parts of the recorder the first suite did not reach.

Every test here feeds the recorder an explicit iterable of keys, so nothing in this
file can capture a real keystroke: the module's whole claim is that it records only a
foreground terminal it was told to record, and a test that needed a real terminal to
make its point would be proving the opposite.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from pathlib import Path

import pytest

from src import keylogger
from src.keylogger import display_key, iter_char_stream, record_session


def rows(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


# --- how a key is labelled -------------------------------------------------

@pytest.mark.parametrize("character,label", [
    ("\x1b", "ESC"), ("\r", "ENTER"), ("\n", "ENTER"), ("\t", "TAB"),
    ("\x7f", "BACKSPACE"), ("\b", "BACKSPACE"), ("\x03", "CTRL-C"),
    ("a", "a"), ("7", "7"), (" ", " "), ("é", "é"),
])
def test_each_control_character_gets_its_own_label(character, label):
    """One wrong mapping puts the wrong key in the record, which is the only thing
    the record is for."""
    assert display_key(character) == label


def test_a_non_printable_character_is_shown_as_its_code_point():
    """A key with no name is still recorded, as its code point rather than dropped
    or written as a raw byte that would break the line."""
    assert display_key("\x01") == "U+0001"
    assert display_key("\x00") == "U+0000"


def test_an_empty_read_is_labelled_as_the_end_of_input():
    assert display_key("") == "EOF"


# --- when a session stops --------------------------------------------------

def test_the_stop_key_ends_the_session_and_nothing_after_it_is_recorded(tmp_path):
    """Press Esc and the recording stops there. Everything sent afterwards belongs
    to the next thing the user types and is not part of this session."""
    output = tmp_path / "events.jsonl"
    count = record_session(output, keys=iter(["a", "b", "\x1b", "c", "d"]))
    assert count == 3
    assert [row["key"] for row in rows(output)] == ["a", "b", "ESC"]


def test_the_stop_key_is_matched_whatever_its_case(tmp_path):
    """The stop key is compared after upper-casing both sides, so a configured
    stop key of 'esc' catches an ESC rather than quietly never firing."""
    output = tmp_path / "events.jsonl"
    assert record_session(output, keys=iter(["a", "\x1b", "b"]), stop_key="esc") == 2
    assert [row["key"] for row in rows(output)] == ["a", "ESC"]


def test_a_different_stop_key_is_honoured(tmp_path):
    output = tmp_path / "events.jsonl"
    assert record_session(output, keys=iter(["x", "Q", "y"]), stop_key="q") == 2
    assert [row["key"] for row in rows(output)] == ["x", "Q"]


def test_a_session_with_no_stop_key_runs_to_the_end_of_its_input(tmp_path):
    output = tmp_path / "events.jsonl"
    assert record_session(output, keys=iter(list("hello")), stop_key="\x00") == 5


# --- what lands on disk ----------------------------------------------------

def test_every_event_is_one_valid_json_line(tmp_path):
    output = tmp_path / "events.jsonl"
    record_session(output, keys=iter(list("abc")), stop_key="\x00")
    lines = output.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    for line in lines:
        event = json.loads(line)          # would raise if a line were not one event
        assert set(event) == {"timestamp", "key"}


def test_the_timestamps_are_iso_utc_and_do_not_go_backwards(tmp_path):
    """The record is a sequence. Timestamps that parse but move backwards would make
    the sequence meaningless without making it invalid."""
    output = tmp_path / "events.jsonl"
    record_session(output, keys=iter(list("abcd")), stop_key="\x00")
    stamps = [datetime.fromisoformat(row["timestamp"]) for row in rows(output)]
    assert all(stamp.tzinfo is not None for stamp in stamps)
    assert stamps == sorted(stamps)


def test_a_non_ascii_key_survives_the_round_trip(tmp_path):
    """The writer passes ensure_ascii=False, so the file holds the character rather
    than an escape sequence -- and it has to read back as the same character."""
    output = tmp_path / "events.jsonl"
    record_session(output, keys=iter(["é", "→"]), stop_key="\x00")
    assert [row["key"] for row in rows(output)] == ["é", "→"]


def test_the_output_directory_is_created_when_it_does_not_exist(tmp_path):
    output = tmp_path / "a" / "b" / "events.jsonl"
    record_session(output, keys=iter(["a", "\x1b"]))
    assert output.exists()


def test_appending_to_a_file_that_ends_in_a_newline_adds_no_blank_line(tmp_path):
    """The other half of the separator logic: a file already ending in a newline must
    not gain an empty line, which would be an unparseable event."""
    output = tmp_path / "events.jsonl"
    output.write_text('{"timestamp":"x","key":"old"}\n', encoding="utf-8")
    record_session(output, keys=iter(["n", "\x1b"]))
    text = output.read_text(encoding="utf-8")
    assert "" not in text.splitlines()
    assert len(text.splitlines()) == 3


def test_events_are_on_disk_before_the_session_ends(tmp_path):
    """Each event is flushed as it happens, so a session that dies mid-way does not
    take the events before the failure with it."""
    output = tmp_path / "events.jsonl"

    def failing_keys():
        yield "a"
        yield "b"
        raise OSError("the terminal went away")

    with pytest.raises(OSError):
        record_session(output, keys=failing_keys())
    assert [row["key"] for row in rows(output)] == ["a", "b"]


# --- the guards ------------------------------------------------------------

def test_the_character_stream_yields_nothing_at_immediate_end_of_input():
    assert list(iter_char_stream(lambda: "")) == []


def test_an_interactive_terminal_is_accepted(monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(keylogger, "windows_console_attached", lambda: True)
    keylogger.require_interactive_terminal()      # returns rather than raising


@pytest.mark.skipif(os.name != "nt", reason="the console check is Windows only")
def test_the_console_check_answers_with_a_boolean():
    assert isinstance(keylogger.windows_console_attached(), bool)


# --- the command line ------------------------------------------------------

def test_recording_without_consent_is_refused(monkeypatch, tmp_path, capsys):
    """Recording a terminal you were not authorized to record is the failure this
    tool exists to be incapable of, so the gate is a test rather than a comment."""
    output = tmp_path / "events.jsonl"
    monkeypatch.setattr(sys, "argv", ["keylogger", "--output", str(output)])
    with pytest.raises(SystemExit) as refusal:
        keylogger.main()
    assert "--consent" in str(refusal.value)
    assert not output.exists()


def test_consent_on_a_non_interactive_stdin_stops_with_a_message(monkeypatch, tmp_path, capsys):
    """Consent is necessary and not sufficient: piping a file in with --consent has
    to be refused too, or the flag would be a way round the terminal check."""
    output = tmp_path / "events.jsonl"
    monkeypatch.setattr(sys, "argv", ["keylogger", "--consent", "--output", str(output)])
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)
    with pytest.raises(SystemExit) as refusal:
        keylogger.main()
    assert "interactive terminal" in str(refusal.value)
    assert capsys.readouterr().out == ""
