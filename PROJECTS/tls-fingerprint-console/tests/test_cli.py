"""Tests for the command line, mostly about what it does when it cannot read
the capture it was handed.

The verbs are thin and the interesting behaviour is at the edges. The capture
reader raises ``ValueError`` with a readable sentence in it, so the command has
to catch that and print the sentence rather than six frames of its own code --
which is exactly what it used to do instead.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fixtures.make_pcap import make_classic_pcap  # noqa: E402
from src import cli  # noqa: E402


def test_analyse_missing_capture_reports_a_sentence_not_a_traceback(tmp_path, capsys):
    missing = str(tmp_path / "nope.pcap")
    code = cli.main(["analyse", missing, "--db", str(tmp_path / "c.db")])
    captured = capsys.readouterr()
    assert code == 1
    assert "could not read" in captured.err
    assert "nope.pcap" in captured.err
    assert "Traceback" not in captured.err


def test_analyse_a_file_that_is_not_a_capture_reports_a_sentence(tmp_path, capsys):
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"NOTAPCAP" * 8)
    code = cli.main(["analyse", str(bad), "--db", str(tmp_path / "c.db")])
    captured = capsys.readouterr()
    assert code == 1
    assert "could not read" in captured.err
    assert "Traceback" not in captured.err


def test_analyse_a_real_capture_succeeds(tmp_path, capsys):
    path = make_classic_pcap(str(tmp_path / "ok.pcap"))
    code = cli.main(["analyse", path, "--db", str(tmp_path / "c.db")])
    captured = capsys.readouterr()
    assert code == 0
    assert "events" in captured.out
    assert "fingerprints" in captured.out


def test_analyse_does_not_leave_the_store_open_on_failure(tmp_path):
    db = str(tmp_path / "c.db")
    assert cli.main(["analyse", str(tmp_path / "nope.pcap"), "--db", db]) == 1
    # The store was opened before the read failed; the failure path closes it,
    # so a second run against the same file must not trip over a locked handle.
    assert cli.main(["analyse", str(tmp_path / "nope.pcap"), "--db", db]) == 1
