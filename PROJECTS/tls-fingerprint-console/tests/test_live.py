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

# ------------------------------------------------------------------ QUIC

RFC_QUIC_INITIAL = (
    "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11"
    "d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399"
    "1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c"
    "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212"
    "30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5"
    "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208"
    "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec"
    "4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3"
    "485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db"
    "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c"
    "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8"
    "9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556"
    "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74"
    "68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a"
    "c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00"
    "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632"
    "291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964"
    "25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd"
    "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff"
    "ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198"
    "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd"
    "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73"
    "203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f"
    "cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e"
    "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade"
    "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047"
    "90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2"
    "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4"
    "40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0"
    "6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e"
    "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0"
    "be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400"
    "54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab"
    "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9"
    "f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4"
    "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064"
    "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241"
    "e221af44860018ab0856972e194cd934"
)


def _udp_packet(payload, ts=1_700_000_000.0, sport=54321, dport=443):
    return {"ts": ts, "src_ip": "192.0.2.10", "src_port": sport,
            "dst_ip": "198.51.100.20", "dst_port": dport, "protocol": "udp",
            "payload": payload, "flags": "", "seq": 0, "ack": 0, "window": 0,
            "tcp_options": [], "mss": None, "window_scale": None}


def test_sensor_fingerprints_a_quic_datagram(tmp_path):
    """QUIC is TLS over UDP. The RFC's own protected Initial must fingerprint."""
    quic = pytest.importorskip("src.quic")
    if not quic.HAVE_CRYPTO:
        pytest.skip("no crypto library, so QUIC Initial packets cannot be decrypted")
    store = Store(str(tmp_path / "quic.db"))
    sensor = livemod.LiveSensor(store, load_corpus(CORPUS_DIR), grace=0.0)
    out = sensor.feed(_udp_packet(bytes.fromhex(RFC_QUIC_INITIAL)))
    events = [e for e in out if "fingerprints" in e]
    assert len(events) == 1, "one QUIC datagram must produce one event"
    e = events[0]
    assert e["transport"] == "quic"
    assert e["sni"] == "example.com"
    assert e["alpn"] == "alpn"
    assert e["dst_port"] == 443
    # the 'q' prefix is the JA4 protocol character for QUIC
    assert e["fingerprints"]["ja4"].startswith("q13"), e["fingerprints"]["ja4"]
    assert len(e["fingerprints"]["ja3"]) == 32
    assert store.stats()["events"] == 1


def test_a_non_quic_udp_datagram_produces_nothing(tmp_path):
    store = Store(str(tmp_path / "nou.db"))
    sensor = livemod.LiveSensor(store, load_corpus(CORPUS_DIR), grace=0.0)
    assert sensor.feed(_udp_packet(b"\x00\x01\x02 this is not quic at all")) == []
    assert sensor.feed(_udp_packet(b"")) == []
    assert store.stats()["events"] == 0


def test_quic_and_tcp_events_are_labelled_by_transport(tmp_path):
    """A consumer must be able to tell a QUIC event from a TCP one."""
    quic = pytest.importorskip("src.quic")
    if not quic.HAVE_CRYPTO:
        pytest.skip("no crypto library")
    store = Store(str(tmp_path / "both.db"))
    sensor = livemod.LiveSensor(store, load_corpus(CORPUS_DIR), grace=0.0)
    sensor.feed(_udp_packet(bytes.fromhex(RFC_QUIC_INITIAL)))
    for pk in read_pcap(make_pcap.make_classic_pcap()):
        sensor.feed(pk)
    sensor.clock = (sensor.clock or 0) + 5.0
    sensor.tick()
    sensor.flush()
    transports = {e["transport"] for e in store.events() if e.get("transport")}
    assert "quic" in transports and "tcp" in transports
