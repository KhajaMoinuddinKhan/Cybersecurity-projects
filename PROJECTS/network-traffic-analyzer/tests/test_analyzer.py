from src.analyzer import PacketRecord, summarize


def test_summary_is_based_on_observed_records():
    result = summarize([
        PacketRecord("TCP", "10.0.0.1", "10.0.0.2", 443, None),
        PacketRecord("UDP", "10.0.0.1", "10.0.0.3", 53, "example.test."),
        PacketRecord("UDP", "10.0.0.1", "10.0.0.3", 53, "example.test."),
    ])
    assert result["packet_count"] == 3
    assert result["protocols"] == {"UDP": 2, "TCP": 1}
    assert result["dns_queries"] == {"example.test": 2}
    assert result["destination_ports"] == {"53": 2, "443": 1}


def test_empty_capture_has_empty_observed_sections():
    result = summarize([])
    assert result["packet_count"] == 0
    assert result["protocols"] == {}
    assert result["dns_queries"] == {}
