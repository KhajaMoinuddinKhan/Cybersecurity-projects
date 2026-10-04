"""Live sensor tests (``src/live.py``).

The sensor is driven with REAL packets read back from the synthetic capture,
never with mocks: the store is a real :class:`~src.store.Store` on a tmp_path
database and the corpus is the real bundled one.

Two of these tests are regressions for defects that made the live path useless:

  * a flow was emitted the instant the server answered, so the JA4X (which
    arrives in a *later* packet) was never seen;
  * a replayed capture's old timestamps were compared against the wall clock,
    so every flow was expired before it could emit.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fixtures import make_pcap  # noqa: E402
from src import ja4 as ja4mod  # noqa: E402
from src import live as livemod  # noqa: E402
from src import tls as tlsmod  # noqa: E402
from src.corpus import load_corpus  # noqa: E402
from src.pcap import decode_frame, read_pcap  # noqa: E402
from src.store import Store  # noqa: E402

CORPUS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "corpus"
)
LINKTYPE_ETHERNET = 1


@pytest.fixture
def corpus():
    return load_corpus(CORPUS_DIR)


@pytest.fixture
def store(tmp_path):
    st = Store(str(tmp_path / "console.db"))
    yield st
    st.close()


def _classic_packets():
    return read_pcap(make_pcap.make_classic_pcap())


def _events(items):
    return [i for i in items if isinstance(i, dict) and "fingerprints" in i]


def _alerts(items):
    return [i for i in items if isinstance(i, dict) and "fingerprints" not in i]


def _feed_all(sensor, packets):
    emitted = []
    for packet in packets:
        emitted.extend(sensor.feed(packet))
    return emitted


# --------------------------------------------------------------- the main path

def test_sensor_emits_tls_and_http_flows_with_all_their_fingerprints(corpus, store):
    packets = _classic_packets()
    sensor = livemod.LiveSensor(store, corpus, grace=2.0)

    emitted = _feed_all(sensor, packets)
    # Emission is on quiescence, not on arrival: nothing fires mid-stream.
    assert emitted == []

    sensor.clock += 10.0
    emitted.extend(sensor.tick())
    emitted.extend(sensor.flush())

    events = _events(emitted)
    assert len(events) == 2, "exactly the TLS and the HTTP flow must emit"

    by_port = {e["dst_port"]: e for e in events}
    assert set(by_port) == {443, 80}

    tls = by_port[443]
    # The regression the emit-on-quiescence fix addressed: all six arrive.
    for kind in ("ja3", "ja3s", "ja4", "ja4s", "ja4t", "ja4x"):
        assert kind in tls["fingerprints"], "the TLS event is missing %s" % kind
    assert tls["sni"] == "example.com"
    assert tls["src_ip"] == make_pcap.IPV4_CLIENT
    assert tls["dst_ip"] == make_pcap.IPV4_SERVER

    http = by_port[80]
    assert "ja4h" in http["fingerprints"]
    assert http["user_agent"]
    assert http["dst_ip"] == make_pcap.IPV4_SERVER

    stats = store.stats()
    assert stats["events"] >= 2
    assert stats["alerts"] >= 1


def test_a_bare_syn_flow_never_emits(corpus, store):
    packets = _classic_packets()
    syn = [p for p in packets
           if p["protocol"] == "tcp" and "SYN" in p["flags"] and "ACK" not in p["flags"]
           and p["dst_port"] == make_pcap.TLS_SERVER_PORT][0]

    sensor = livemod.LiveSensor(store, corpus, grace=2.0)
    emitted = sensor.feed(syn)
    sensor.clock += 10.0
    emitted.extend(sensor.tick())
    emitted.extend(sensor.flush())

    assert _events(emitted) == [], "a bare SYN carries only ja4t and must not emit"
    assert store.stats()["events"] == 0


# ------------------------------------------------------------- the packet clock

def test_packets_with_old_timestamps_still_emit(corpus, store):
    """The regression the emit-before-expire fix addressed.

    A replayed capture carries the timestamps of when it was recorded.  With a
    small TTL those flows are already "stale" by the wall clock, so they must be
    emitted (they were fingerprinted) before they are retired for age.
    """
    packets = _classic_packets()
    for i, packet in enumerate(packets):
        packet["ts"] = 1_000_000.0 + i * 0.001

    sensor = livemod.LiveSensor(store, corpus, grace=2.0, ttl=5.0)
    emitted = _feed_all(sensor, packets)

    # The packet clock, not the wall clock, judged liveness during the feed.
    assert sensor.stats()["expired"] == 0
    assert _events(emitted) == []

    sensor.clock += 10.0
    emitted.extend(sensor.tick())
    emitted.extend(sensor.flush())

    events = _events(emitted)
    assert len(events) == 2, "old timestamps must not silently drop every flow"
    assert {e["dst_port"] for e in events} == {443, 80}


# ---------------------------------------------------------- TCP fragmentation

def test_a_client_hello_split_across_segments_still_fingerprints(corpus, store):
    ch = make_pcap.build_client_hello_record()
    half = len(ch) // 2
    parts = [ch[:half], ch[half:]]

    def frame(seq, payload):
        return make_pcap._frame(
            4, make_pcap.IPV4_CLIENT, make_pcap.IPV4_SERVER, 6,
            make_pcap._tcp(make_pcap.TLS_CLIENT_PORT, make_pcap.TLS_SERVER_PORT,
                           seq, 5001, 0x18, make_pcap.TCP_SYN_WINDOW, b"", payload))

    syn = make_pcap._frame(
        4, make_pcap.IPV4_CLIENT, make_pcap.IPV4_SERVER, 6,
        make_pcap._tcp(make_pcap.TLS_CLIENT_PORT, make_pcap.TLS_SERVER_PORT,
                       1000, 0, 0x02, make_pcap.TCP_SYN_WINDOW,
                       make_pcap.build_tcp_syn_options()))

    frames = [syn, frame(1001, parts[0]), frame(1001 + len(parts[0]), parts[1])]
    packets = [decode_frame(f, LINKTYPE_ETHERNET, 1700000000.0 + i * 0.001)
               for i, f in enumerate(frames)]

    sensor = livemod.LiveSensor(store, corpus, grace=2.0)
    sensor.feed(packets[0])            # SYN
    sensor.feed(packets[1])            # first half of the ClientHello

    flow = list(sensor.flows.values())[0]
    assert "ja3" not in flow["fingerprints"], "a truncated record must not fingerprint"

    sensor.feed(packets[2])            # second half completes the record
    flow = list(sensor.flows.values())[0]
    assert flow["fingerprints"].get("ja3"), "the completed record must fingerprint"
    assert flow["fingerprints"].get("ja4")

    sensor.clock += 10.0
    events = _events(sensor.tick() + sensor.flush())
    assert len(events) == 1
    assert events[0]["fingerprints"]["ja3"] == flow["fingerprints"]["ja3"]


# ------------------------------------------------------------------- endpoints

def test_ja4t_comes_from_the_syn_and_both_endpoints_are_populated(corpus, store):
    packets = _classic_packets()
    sensor = livemod.LiveSensor(store, corpus, grace=2.0)
    _feed_all(sensor, packets)
    sensor.clock += 10.0
    events = _events(sensor.tick() + sensor.flush())

    http = [e for e in events if e["dst_port"] == make_pcap.HTTP_SERVER_PORT][0]
    assert "ja4t" in http["fingerprints"]

    syn = [p for p in packets
           if p["protocol"] == "tcp" and p["dst_port"] == make_pcap.HTTP_SERVER_PORT
           and "SYN" in p["flags"] and "ACK" not in p["flags"]][0]
    assert http["fingerprints"]["ja4t"] == ja4mod.ja4t(tlsmod.parse_tcp_syn(syn))

    # The regression: the SYN must populate BOTH ends, or the HTTP event is
    # emitted with an empty destination.
    assert http["src_ip"] == make_pcap.IPV4_CLIENT
    assert http["src_port"] == make_pcap.HTTP_CLIENT_PORT
    assert http["dst_ip"] == make_pcap.IPV4_SERVER
    assert http["dst_port"] == make_pcap.HTTP_SERVER_PORT


# ---------------------------------------------------------------- os_by_ja3

def test_os_by_ja3_is_honoured_and_raises_an_os_mismatch(corpus, store):
    sensor = livemod.LiveSensor(store, corpus)
    # The bundled salesforce list is the OSX/*nix client list, so every JA3 in
    # it maps to the unix family.
    unix_ja3 = next(v for v, family in sensor.os_by_ja3.items() if family == "unix")
    assert unix_ja3

    # A single real flow cannot carry both a TLS ClientHello and a plaintext
    # User-Agent -- the sensor reads the request only when there is no JA4 -- so
    # plant the flow state the sensor itself would build, then let it emit.
    client = (make_pcap.IPV4_CLIENT, make_pcap.HTTP_CLIENT_PORT)
    server = (make_pcap.IPV4_SERVER, make_pcap.HTTP_SERVER_PORT)
    key = tuple(sorted([client, server]))
    flow = sensor._new_flow(key, client, server, 1700000000.0)
    flow["client"] = client
    flow["server"] = server
    flow["hello_ts"] = 1700000000.0
    flow["fingerprints"]["ja3"] = unix_ja3
    flow["user_agent"] = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/120.0 Safari/537.36")
    sensor.flows[key] = flow

    items = sensor.flush()
    assert any(a["rule"] == "os_mismatch" for a in _alerts(items))
    assert any(a["rule"] == "os_mismatch" for a in store.alerts())
    assert store.stats()["alerts"] >= 1


# --------------------------------------------------------- ceilings and limits

def test_an_oversized_payload_does_not_raise_and_the_ceiling_engages(corpus, store):
    sensor = livemod.LiveSensor(store, corpus)
    src = (make_pcap.IPV4_CLIENT, 50000)
    packet = {
        "ts": 1700000000.0,
        "src_ip": make_pcap.IPV4_CLIENT, "dst_ip": make_pcap.IPV4_SERVER,
        "src_port": 50000, "dst_port": make_pcap.TLS_SERVER_PORT,
        "protocol": "tcp", "flags": "PSH,ACK",
        "seq": 1, "ack": 1, "window": 65535, "tcp_options": [],
        "mss": None, "window_scale": None,
        "payload": b"\x00" * (livemod.MAX_BUFFER + 4096),
    }
    sensor.feed(packet)  # must not raise
    flow = list(sensor.flows.values())[0]
    buffered = len(flow["buf"][src])
    assert buffered > 0

    # Once the buffer is at the ceiling a further payload must not grow it.
    sensor.feed(packet)
    assert len(flow["buf"][src]) == buffered, "the ceiling must stop further growth"


def test_more_flows_than_the_cap_stays_bounded_and_does_not_raise(corpus, store):
    sensor = livemod.LiveSensor(store, corpus)
    for i in range(livemod.MAX_FLOWS + 200):
        sensor.feed({
            "ts": 1700000000.0 + i * 0.001,
            "src_ip": "10.0.%d.%d" % (i // 256, i % 256),
            "dst_ip": make_pcap.IPV4_SERVER,
            "src_port": 40000 + (i % 1000),
            "dst_port": make_pcap.TLS_SERVER_PORT,
            "protocol": "tcp", "flags": "SYN",
            "seq": 0, "ack": 0, "window": 65535,
            "tcp_options": [2, 4, 8, 1, 3], "mss": 1460, "window_scale": 7,
            "payload": b"",
        })
    assert sensor.stats()["in_flight"] <= livemod.MAX_FLOWS
    assert sensor.counters["dropped"] > 0


# ------------------------------------------------------------------- counters

def test_stats_expose_the_counters_and_move_sensibly(corpus, store):
    packets = _classic_packets()
    sensor = livemod.LiveSensor(store, corpus, grace=2.0)
    _feed_all(sensor, packets)

    stats = sensor.stats()
    for key in ("packets", "bytes", "flows", "events", "alerts",
                "expired", "dropped", "in_flight"):
        assert key in stats
    assert stats["packets"] == len(packets)
    assert stats["flows"] == 2
    assert stats["bytes"] > 0
    assert stats["events"] == 0
    assert stats["in_flight"] == 2

    sensor.clock += 10.0
    sensor.tick()
    after = sensor.stats()
    assert after["events"] == 2
    assert after["alerts"] >= 1
    assert after["expired"] == 2
    assert after["in_flight"] == 0
