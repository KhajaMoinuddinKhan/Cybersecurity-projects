import json
import os
import sys
from pathlib import Path

import pytest

from src import keylogger
from src.keylogger import display_key, record_session


def test_special_keys_are_readable():
    assert display_key("\x1b") == "ESC"
    assert display_key("\n") == "ENTER"
    assert display_key("a") == "a"


def test_record_session_writes_real_timestamps_and_keys(tmp_path: Path):
    output = tmp_path / "events.jsonl"
    count = record_session(output, keys=iter(["a", "\n", "\x1b"]))
    rows = [json.loads(line) for line in output.read_text().splitlines()]
    assert count == 3
    assert [row["key"] for row in rows] == ["a", "ENTER", "ESC"]
    assert all("T" in row["timestamp"] for row in rows)


def test_interactive_input_is_required(monkeypatch, tmp_path):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    from src import keylogger
    with pytest.raises(RuntimeError, match="interactive terminal"):
        keylogger.record_session(tmp_path / "events.jsonl")


def test_empty_read_is_labelled_instead_of_crashing():
    assert display_key("") == "EOF"


def test_refused_terminal_does_not_create_the_output_file(monkeypatch, tmp_path):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    output = tmp_path / "events.jsonl"
    with pytest.raises(RuntimeError, match="interactive terminal"):
        record_session(output)
    assert not output.exists()


def test_character_stream_stops_at_end_of_input():
    from src.keylogger import iter_char_stream

    characters = iter(["a", "b", "", "c"])
    assert list(iter_char_stream(lambda: next(characters))) == ["a", "b"]


class FakeTerminal:
    """Minimal unix-style terminal that reports end of input like Ctrl+D."""

    def __init__(self, characters):
        self.characters = list(characters)

    def isatty(self):
        return True

    def fileno(self):
        return 0

    def read(self, size=1):
        return self.characters.pop(0) if self.characters else ""


class FakeTermios:
    TCSADRAIN = 1

    def __init__(self):
        self.restored = None

    def tcgetattr(self, descriptor):
        return ["saved-settings"]

    def tcsetattr(self, descriptor, when, attributes):
        self.restored = (when, attributes)


class FakeTty:
    def setcbreak(self, descriptor):
        self.descriptor = descriptor


@pytest.mark.skipif(os.name == "nt", reason="unix terminal mode only")
def test_end_of_input_ends_a_unix_style_session(monkeypatch, tmp_path):
    monkeypatch.setattr(keylogger, "windows_console_attached", lambda: True)
    monkeypatch.setitem(sys.modules, "termios", FakeTermios())
    monkeypatch.setitem(sys.modules, "tty", FakeTty())
    monkeypatch.setattr(sys, "stdin", FakeTerminal(["a", "b"]))  # then end of input
    output = tmp_path / "events.jsonl"
    assert record_session(output) == 2
    rows = [json.loads(line) for line in output.read_text().splitlines()]
    assert [row["key"] for row in rows] == ["a", "b"]


def test_interrupt_keeps_events_already_written(tmp_path):
    def interrupted_keys():
        yield "a"
        yield "b"
        raise KeyboardInterrupt

    output = tmp_path / "events.jsonl"
    assert record_session(output, keys=interrupted_keys()) == 2
    rows = [json.loads(line) for line in output.read_text().splitlines()]
    assert [row["key"] for row in rows] == ["a", "b"]


@pytest.mark.skipif(os.name != "nt", reason="Windows character devices only")
def test_windows_character_device_is_not_accepted_as_a_console(monkeypatch):
    nul = open(os.devnull, "r")
    monkeypatch.setattr(sys, "stdin", nul)
    assert nul.isatty() is True  # Windows reports NUL as a tty...
    with pytest.raises(RuntimeError, match="interactive terminal"):
        keylogger.require_interactive_terminal()  # ...but it has no console input buffer


def test_a_refused_run_does_not_announce_that_recording_started(monkeypatch, tmp_path, capsys):
    """The banner must not appear on a run that is going to be refused.

    The refusal was already covered at record_session level, which left main()
    free to print the start message first and fail afterwards.
    """
    output = tmp_path / "events.jsonl"
    monkeypatch.setattr(sys, "argv", ["keylogger", "--consent", "--output", str(output)])
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)

    with pytest.raises(SystemExit) as refusal:
        keylogger.main()

    # SystemExit carries the message; it only reaches stderr when the interpreter
    # actually exits, so under pytest it is read off the exception.
    assert "interactive terminal" in str(refusal.value)

    captured = capsys.readouterr()
    assert captured.out == ""  # nothing was announced
    assert not output.exists()
