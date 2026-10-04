"""Tests for the live-capture path in ``src/capture.py``.

This module exists to bind Npcap's ``wpcap.dll`` with ctypes, so its tests must
run where that driver is absent -- CI is Linux.  Every assertion here either
needs no driver at all (the selection logic, the filter string, the loopback
decode path) or is guarded behind ``capture.available()``.
"""

import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fixtures import make_pcap  # noqa: E402
from src import capture  # noqa: E402

LINKTYPE_NULL = 0
LINKTYPE_LOOP = 108


# ------------------------------------------------------------------ the driver

def test_available_returns_a_bool_and_does_not_raise():
    try:
        value = capture.available()
    except Exception as exc:
        pytest.fail(
            "capture.available() raised %s: %s -- it must return a bool on every "
            "platform.  On a host where ctypes.WinDLL does not exist (Linux) "
            "_load() must also catch AttributeError, not only OSError."
            % (type(exc).__name__, exc)
        )
    assert isinstance(value, bool)


def test_load_raises_capture_unavailable_when_no_dll_can_be_loaded(monkeypatch):
    # Point the loader at a library that cannot exist, so the "driver absent"
    # branch runs even on this Windows host.  The error must name the driver.
    monkeypatch.setattr(capture, "DLL_CANDIDATES", (r"C:\no\such\dir\wpcap.dll",))
    with pytest.raises(capture.CaptureUnavailable) as excinfo:
        capture._load()
    message = str(excinfo.value)
    assert "Npcap" in message
    assert "wpcap.dll" in message


def test_load_reports_a_missing_driver_on_this_platform():
    # The literal contract: when the driver really is absent, _load() names it.
    if capture.available():
        pytest.skip("a capture driver is installed on this host")
    with pytest.raises(capture.CaptureUnavailable) as excinfo:
        capture._load()
    assert "Npcap" in str(excinfo.value)
    assert "wpcap.dll" in str(excinfo.value)


# --------------------------------------------------------- interface selection

IFACES = [
    {"index": 0, "name": r"\Device\NPF_{AAAA-0000}", "description": "WAN Miniport (IP)"},
    {"index": 1, "name": r"\Device\NPF_{BBBB-1111}",
     "description": "Wi-Fi Direct Virtual Adapter"},
    {"index": 2, "name": r"\Device\NPF_{CCCC-2222}",
     "description": "Intel(R) Ethernet Connection I219-V"},
    {"index": 3, "name": r"\Device\NPF_{DDDD-3333}",
     "description": "Microsoft Wi-Fi Direct Virtual Adapter #2"},
]


def test_pick_interface_by_index():
    assert capture.pick_interface("2", interfaces=IFACES)["index"] == 2


def test_pick_interface_by_description_substring_is_case_insensitive():
    assert capture.pick_interface("ethernet", interfaces=IFACES)["index"] == 2


def test_pick_interface_by_device_name_substring():
    assert capture.pick_interface("{CCCC-2222}", interfaces=IFACES)["index"] == 2


def test_pick_interface_rejects_an_out_of_range_index():
    with pytest.raises(capture.CaptureUnavailable) as excinfo:
        capture.pick_interface("9", interfaces=IFACES)
    message = str(excinfo.value)
    assert "9" in message
    assert "index" in message.lower()


def test_pick_interface_rejects_an_unknown_hint():
    with pytest.raises(capture.CaptureUnavailable) as excinfo:
        capture.pick_interface("no-such-adapter", interfaces=IFACES)
    assert "no-such-adapter" in str(excinfo.value)


def test_pick_interface_rejects_an_empty_list():
    with pytest.raises(capture.CaptureUnavailable):
        capture.pick_interface(interfaces=[])


def test_pick_interface_default_skips_pseudo_adapters():
    chosen = capture.pick_interface(None, interfaces=IFACES)
    assert chosen["index"] == 2
    assert "ethernet" in chosen["description"].lower()


def test_pick_interface_default_returns_one_even_if_all_are_pseudo():
    only_pseudo = [IFACES[0], IFACES[1], IFACES[3]]
    chosen = capture.pick_interface(None, interfaces=only_pseudo)
    assert chosen in only_pseudo


# --------------------------------------------------------------- default filter

def test_default_filter_covers_tls_over_tcp_and_quic_over_udp():
    """The filter must watch both transports.

    A TCP-only filter silently excludes every HTTP/3 handshake, which is why
    the filter is asserted on both halves rather than just on the TLS ports.
    """
    f = capture.DEFAULT_FILTER
    assert "tcp" in f and "udp" in f, "QUIC is UDP; a tcp-only filter cannot see it"
    for port in (443, 8443, 993, 995, 465, 587, 636, 853, 8883, 9443):
        assert "port %d" % port in f, "TLS port %d missing" % port
    for port in capture.QUIC_PORTS:
        assert "port %d" % port in f, "QUIC port %d missing" % port
    # it must actually be a BPF expression, not a sentence
    assert f.count("(") == f.count(")"), "unbalanced parentheses in the filter"

def test_livecapture_open_on_a_nonexistent_device_raises():
    if not capture.available():
        pytest.skip("no capture driver on this host")
    cap = capture.LiveCapture(r"\Device\NPF_{DOES-NOT-EXIST-0000}")
    with pytest.raises(capture.CaptureUnavailable):
        cap.open()


def _loopback_raw_frame():
    """Four address-family bytes then a real IPv4/TCP packet carrying a hello."""
    ip = make_pcap._ipv4_header(
        make_pcap.IPV4_CLIENT, make_pcap.IPV4_SERVER, 6,
        make_pcap._tcp(make_pcap.TLS_CLIENT_PORT, make_pcap.TLS_SERVER_PORT,
                       1000, 0, 0x18, payload=make_pcap.build_client_hello_record()),
    )
    return struct.pack("<I", 2) + ip


def test_loopback_null_linktype_uses_the_raw_ip_path():
    cap = capture.LiveCapture("loopback")
    cap.linktype = LINKTYPE_NULL  # set directly: the capture is never opened
    packet = cap._decode(_loopback_raw_frame(), 1234.5)
    assert packet is not None
    assert packet["protocol"] == "tcp"
    assert packet["src_ip"] == make_pcap.IPV4_CLIENT
    assert packet["dst_ip"] == make_pcap.IPV4_SERVER
    assert packet["src_port"] == make_pcap.TLS_CLIENT_PORT
    assert packet["dst_port"] == make_pcap.TLS_SERVER_PORT
    assert packet["payload"] == make_pcap.build_client_hello_record()


def test_loopback_loop_linktype_uses_the_raw_ip_path():
    cap = capture.LiveCapture("loopback")
    cap.linktype = LINKTYPE_LOOP
    packet = cap._decode(_loopback_raw_frame(), 0.0)
    assert packet is not None
    assert packet["protocol"] == "tcp"
    assert packet["dst_port"] == make_pcap.TLS_SERVER_PORT
