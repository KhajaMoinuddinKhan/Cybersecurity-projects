"""Regression: appending must keep one JSON event per line."""
import json
from pathlib import Path

from src.keylogger import record_session


def test_appending_to_a_file_without_a_trailing_newline_keeps_jsonl_valid(tmp_path: Path):
    output = tmp_path / "events.jsonl"
    output.write_bytes(b'{"old":1}')  # existing content, no trailing newline

    assert record_session(output, keys=iter(["x", "\x1b"])) == 2

    lines = output.read_text(encoding="utf-8").splitlines()
    assert lines[0] == '{"old":1}'
    rows = [json.loads(line) for line in lines if line]
    assert [row["key"] for row in rows[1:]] == ["x", "ESC"]
