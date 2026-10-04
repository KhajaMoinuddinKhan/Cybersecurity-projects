"""Round-trip tests for the pure-Python pcap reader."""

import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fixtures import make_pcap  # noqa: E402
from src.pcap import read_pcap, reassemble_streams  # noqa: E402

C_IP = make_pcap.IPV4_CLIENT
S_IP = make_pcap.IPV4_SERVER


def test_read_classic_pcap_basic_fields():
    packets = read_pcap(make_pcap.make_classic_pcap())
    assert len(packets) >= 10
    for pkt in packets:
        assert isinstance(pkt["ts"], float)
        assert isinstance(pkt["payload"], (bytes, bytearray))
        assert pkt["protocol"] in ("tcp", "udp")

    syns = [p for p in packets
            if p["protocol"] == "tcp" and "SYN" in p["flags"]
            and "ACK" not in p["flags"]]
    assert syns
    syn = syns[0]
    assert syn["src_ip"] == C_IP
    assert syn["dst_ip"] == S_IP
    assert syn["src_port"] == make_pcap.TLS_CLIENT_PORT
    assert syn["dst_port"] == make_pcap.TLS_SERVER_PORT
    assert syn["window"] == make_pcap.TCP_SYN_WINDOW
    assert syn["mss"] == make_pcap.TCP_SYN_MSS
    assert syn["window_scale"] == make_pcap.TCP_SYN_WINDOW_SCALE
    assert syn["tcp_options"] == make_pcap.TCP_SYN_OPTIONS_KINDS
    assert syn["payload"] == b""

    syn_ack = [p for p in packets
               if p["protocol"] == "tcp" and "SYN" in p["flags"]
               and "ACK" in p["flags"]]
    assert syn_ack
    assert syn_ack[0]["src_port"] == make_pcap.TLS_SERVER_PORT


def test_udp_packet_parsed():
    packets = read_pcap(make_pcap.make_classic_pcap())
    udp = [p for p in packets if p["protocol"] == "udp"]
    assert len(udp) == 1
    assert udp[0]["src_port"] == make_pcap.DNS_CLIENT_PORT
    assert udp[0]["dst_port"] == make_pcap.DNS_SERVER_PORT
    assert udp[0]["payload"] == make_pcap.DNS_PAYLOAD
    assert udp[0]["tcp_options"] == []
    assert udp[0]["mss"] is None


def test_reassemble_streams_classic():
    packets = read_pcap(make_pcap.make_classic_pcap())
    streams = reassemble_streams(packets)
    ch = make_pcap.build_client_hello_record()
    sh = make_pcap.build_server_hello_record()
    cert = make_pcap.build_certificate_record()
    http = make_pcap.build_http_get()

    client = [s for s in streams
              if s["src_port"] == make_pcap.TLS_CLIENT_PORT
              and s["dst_port"] == make_pcap.TLS_SERVER_PORT]
    assert len(client) == 1
    assert client[0]["payload"] == ch

    server = [s for s in streams
              if s["src_port"] == make_pcap.TLS_SERVER_PORT
              and s["dst_port"] == make_pcap.TLS_CLIENT_PORT]
    assert len(server) == 1
    assert server[0]["payload"] == sh + cert

    web = [s for s in streams if s["dst_port"] == make_pcap.HTTP_SERVER_PORT]
    assert len(web) == 1
    assert web[0]["payload"] == http

    # pure ACKs (empty payload) never produce a stream
    assert all(s["payload"] for s in streams)


def test_pcapng_roundtrip():
    packets = read_pcap(make_pcap.make_pcapng())
    classic = read_pcap(make_pcap.make_classic_pcap())
    assert len(packets) == len(classic)
    streams = reassemble_streams(packets)
    client = [s for s in streams if s["src_port"] == make_pcap.TLS_CLIENT_PORT]
    assert len(client) == 1
    assert client[0]["payload"] == make_pcap.build_client_hello_record()
    server = [s for s in streams if s["src_port"] == make_pcap.TLS_SERVER_PORT]
    assert server[0]["payload"] == (make_pcap.build_server_hello_record()
                                    + make_pcap.build_certificate_record())


def test_ipv6_path():
    packets = read_pcap(make_pcap.make_ipv6_pcap())
    assert packets
    assert all(":" in p["src_ip"] and ":" in p["dst_ip"] for p in packets)
    client = [p for p in packets
              if p["src_port"] == make_pcap.TLS_CLIENT_PORT and p["payload"]]
    assert client
    assert client[0]["src_ip"] == make_pcap.IPV6_CLIENT
    assert client[0]["dst_ip"] == make_pcap.IPV6_SERVER

    streams = reassemble_streams(packets)
    client_stream = [s for s in streams if s["src_port"] == make_pcap.TLS_CLIENT_PORT]
    assert client_stream[0]["payload"] == make_pcap.build_client_hello_record()


def test_vlan_tagged_frames_parse():
    packets = read_pcap(make_pcap.make_vlan_pcap())
    assert packets
    ch = make_pcap.build_client_hello_record()
    tagged = [p for p in packets
              if p["src_port"] == make_pcap.TLS_CLIENT_PORT and p["payload"] == ch]
    assert tagged
    assert tagged[0]["dst_ip"] == S_IP
    assert tagged[0]["dst_port"] == make_pcap.TLS_SERVER_PORT
    # VLAN does not confuse the UDP decode either
    udp = [p for p in packets if p["protocol"] == "udp"]
    assert udp and udp[0]["payload"] == make_pcap.DNS_PAYLOAD


def test_truncated_file_raises_valueerror():
    path = make_pcap.make_truncated_pcap()
    try:
        read_pcap(path)
    except ValueError as exc:
        assert "truncat" in str(exc).lower()
    except struct.error:  # pragma: no cover
        pytest.fail("reader leaked a struct.error instead of ValueError")
    else:
        pytest.fail("truncated capture did not raise")


def test_bad_magic_raises_valueerror():
    with pytest.raises(ValueError):
        read_pcap(make_pcap.make_bad_magic_pcap())


def test_missing_file_raises_oserror():
    with pytest.raises(OSError):
        read_pcap(os.path.join(make_pcap._default_dir(), "does-not-exist.pcap"))

def test_unsupported_link_type_is_reported_not_silently_dropped(tmp_path):
    """A capture this reader cannot decode must say so, not return nothing."""
    import struct
    path = tmp_path / "sll.pcap"
    header = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 113)  # Linux SLL
    packet = struct.pack("<IIII", 0, 0, 8, 8) + b"\x00" * 8
    path.write_bytes(header + packet)
    with pytest.raises(ValueError) as exc:
        read_pcap(str(path))
    assert "113" in str(exc.value)
