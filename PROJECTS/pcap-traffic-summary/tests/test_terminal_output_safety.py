"""A name taken from a capture must not be able to drive the terminal."""
import subprocess
import sys

import pytest

pytest.importorskip("scapy")
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.utils import wrpcap

from src.analyze_pcap import printable


def test_printable_leaves_normal_text_alone():
    assert printable("example.test") == "example.test"


def test_printable_escapes_control_characters():
    assert printable("bad\x1b[31m.test") == "bad\\x1b[31m.test"
    assert printable("line\nbreak") == "line\\x0abreak"


def test_a_capture_cannot_rewrite_the_terminal(tmp_path):
    capture = tmp_path / "escape.pcap"
    wrpcap(str(capture), [
        IP(src="192.0.2.1", dst="192.0.2.2") / UDP(dport=53)
        / DNS(qr=0, qd=DNSQR(qname="bad\x1b[31mred.test")),
    ])
    result = subprocess.run(
        [sys.executable, "-m", "src.analyze_pcap", str(capture)] + [],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert "\x1b" not in result.stdout          # no raw escape reached the terminal
    assert "\\x1b" in result.stdout            # the analyst sees it escaped
