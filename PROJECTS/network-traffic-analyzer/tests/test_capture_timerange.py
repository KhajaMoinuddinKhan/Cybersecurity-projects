"""The report carries the capture time range and the rates measured over it."""
import pytest

from src.analyzer import PacketRecord, summarize


def test_time_range_and_rates():
    report = summarize([
        PacketRecord("TCP", "10.0.0.1", "10.0.0.2", 443, None, source_port=1, size=100, timestamp=10.0),
        PacketRecord("TCP", "10.0.0.1", "10.0.0.2", 443, None, source_port=1, size=50, timestamp=12.5),
        PacketRecord("TCP", "10.0.0.1", "10.0.0.2", 443, None, source_port=1, size=50, timestamp=11.0),
    ])
    assert report["first_timestamp"] == 10.0
    assert report["last_timestamp"] == 12.5
    assert report["duration_seconds"] == pytest.approx(2.5)
    assert report["average_packets_per_second"] == pytest.approx(1.2)
    assert report["average_bytes_per_second"] == pytest.approx(80.0)


def test_records_without_timestamps_leave_the_range_empty():
    report = summarize([PacketRecord("TCP", "10.0.0.1", "10.0.0.2", 443, None)])
    assert report["first_timestamp"] is None
    assert report["last_timestamp"] is None
    assert report["duration_seconds"] is None
    assert report["average_packets_per_second"] is None


def test_a_capture_spanning_no_measurable_time_has_no_rate():
    report = summarize([PacketRecord("TCP", "10.0.0.1", "10.0.0.2", 443, None, size=60, timestamp=5.0)])
    assert report["duration_seconds"] == 0.0
    assert report["average_packets_per_second"] is None
    assert report["average_bytes_per_second"] is None
