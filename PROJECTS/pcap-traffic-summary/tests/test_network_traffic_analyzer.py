from src.analyze_pcap import TrafficRecord, summarize_records

def test_summary_counts_protocols_hosts_ports_and_dns():
    records=[
        TrafficRecord("TCP","10.0.0.1","10.0.0.2",443),
        TrafficRecord("tcp","10.0.0.1","10.0.0.3",443),
        TrafficRecord("UDP","10.0.0.4","10.0.0.5",53,"example.test."),
    ]
    summary=summarize_records(records)
    assert summary["packet_count"]==3
    assert summary["protocols"]["TCP"]==2
    assert summary["source_hosts"]["10.0.0.1"]==2
    assert summary["destination_ports"][443]==2
    assert summary["dns_queries"]==["example.test"]
