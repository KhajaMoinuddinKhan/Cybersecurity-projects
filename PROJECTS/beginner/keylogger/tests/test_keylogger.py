import json
from pathlib import Path

import pytest

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
