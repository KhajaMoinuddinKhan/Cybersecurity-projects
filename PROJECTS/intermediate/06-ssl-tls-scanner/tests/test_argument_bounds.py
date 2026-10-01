"""Port and timeout values must be usable before any socket is opened."""
import sys

import pytest

from src import scanner
from src.scanner import port_number, scan, timeout_seconds


def test_port_outside_the_tcp_range_is_rejected():
    for bad in (70000, -1, "not-a-port", None):
        with pytest.raises(ValueError):
            port_number(bad)
    assert port_number("443") == 443
    assert port_number(0) == 0


def test_timeout_must_be_a_positive_finite_number():
    for bad in (0, -1, float("inf"), float("nan"), "soon"):
        with pytest.raises(ValueError):
            timeout_seconds(bad)
    assert timeout_seconds("2.5") == 2.5


def test_scan_refuses_an_out_of_range_port_before_connecting():
    with pytest.raises(ValueError, match="between 0 and 65535"):
        scan("example.test", 70000)


def test_cli_reports_a_bad_port_with_its_usage(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["scanner", "example.test", "--port", "70000"])
    with pytest.raises(SystemExit) as exit_info:
        scanner.main()
    assert exit_info.value.code == 2
    assert "between 0 and 65535" in capsys.readouterr().err
