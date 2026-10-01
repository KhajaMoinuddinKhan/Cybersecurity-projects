"""Command-line and feed errors must say what is actually wrong."""
import sys

import pytest

from src import aggregator


def test_empty_search_is_reported_as_empty_text(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["aggregator", "--search", ""])
    with pytest.raises(SystemExit) as exit_info:
        aggregator.main()
    assert exit_info.value.code == 2
    assert "Search text must not be empty" in capsys.readouterr().err


def test_no_options_still_asks_for_one(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["aggregator"])
    with pytest.raises(SystemExit) as exit_info:
        aggregator.main()
    assert exit_info.value.code == 2
    assert "Use --feed and/or --search" in capsys.readouterr().err


def test_undecodable_feed_names_the_file(tmp_path):
    path = tmp_path / "latin1.csv"
    path.write_bytes(b"type,value\nip,192.0.2.99\n")
    assert aggregator.read_utf8_text(path).startswith("type,value")
    bad = tmp_path / "bad.csv"
    bad.write_bytes(b"type,value\nip,\xff\xfe\n")
    with pytest.raises(ValueError, match="bad.csv is not valid UTF-8 text"):
        aggregator.read_feed(bad)
