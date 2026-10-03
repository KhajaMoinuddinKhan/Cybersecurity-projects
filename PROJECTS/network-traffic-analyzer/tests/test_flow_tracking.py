"""Packets are grouped into 5-tuple conversations with their own totals."""
from src.analyzer import PacketRecord, summarize


def _labelled(flow):
    return f"{flow['source']}:{flow['source_port']}->{flow['destination']}:{flow['destination_port']}/{flow['protocol']}"


def test_flows_group_by_five_tuple_with_time_and_totals():
    report = summarize([
        PacketRecord("TCP", "10.0.0.1", "10.0.0.2", 443, None, source_port=50000, size=100, timestamp=1.0),
        PacketRecord("TCP", "10.0.0.1", "10.0.0.2", 443, None, source_port=50000, size=100, timestamp=1.5),
        PacketRecord("TCP", "10.0.0.2", "10.0.0.1", 50000, None, source_port=443, size=60, timestamp=2.0),
        PacketRecord("UDP", "10.0.0.1", "10.0.0.3", 53, None, source_port=40000, size=70, timestamp=3.0),
    ])
    flows = {_labelled(flow): flow for flow in report["top_flows"]}
    assert len(report["top_flows"]) == 3       # the reverse direction is a separate flow
    outbound = flows["10.0.0.1:50000->10.0.0.2:443/TCP"]
    assert outbound["packets"] == 2
    assert outbound["bytes"] == 200
    assert outbound["first_timestamp"] == 1.0
    assert outbound["last_timestamp"] == 1.5
    assert outbound["duration_seconds"] == 0.5
    reverse = flows["10.0.0.2:443->10.0.0.1:50000/TCP"]
    assert reverse["packets"] == 1 and reverse["bytes"] == 60


def test_top_flows_are_ordered_by_bytes():
    report = summarize([
        PacketRecord("UDP", "10.0.0.1", "10.0.0.2", 53, None, source_port=1, size=10, timestamp=1.0),
        PacketRecord("UDP", "10.0.0.3", "10.0.0.4", 53, None, source_port=2, size=500, timestamp=1.0),
    ])
    assert [flow["bytes"] for flow in report["top_flows"]] == [500, 10]
    assert report["top_flows"][0]["destination"] == "10.0.0.4"


def test_a_flow_without_timestamps_reports_no_duration():
    report = summarize([
        PacketRecord("TCP", "10.0.0.1", "10.0.0.2", 443, None, source_port=1, size=10),
    ])
    assert report["top_flows"][0]["first_timestamp"] is None
    assert report["top_flows"][0]["duration_seconds"] is None
