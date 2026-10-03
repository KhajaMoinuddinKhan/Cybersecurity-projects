"""Tests for the canonical event schema and per-source normalisation."""
from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.app import dashboard_snapshot, ingest_payloads, normalise_payload
from src.schema import (
    CANONICAL_FIELDS,
    REQUIRED_FIELDS,
    SUPPORTED_SOURCES,
    coerce_timestamp,
    describe_schema,
    detect_source,
    from_generic_json,
    from_pcap_flow,
    from_sysmon,
    from_windows_event_log,
    normalise_event,
    normalise_severity,
    to_payload,
)
from src.windows_collector import windows_event_to_payload


def _windows_payload() -> dict:
    return windows_event_to_payload(
        "Security",
        {
            "RecordId": 4421,
            "Id": 4625,
            "TimeCreated": "2026-10-01T15:10:00+00:00",
            "Level": "Information",
            "Provider": "Microsoft-Windows-Security-Auditing",
            "Machine": "DESKTOP-LAB",
            "User": "S-1-5-18",
            "Message": "An account failed to log on.",
            "Xml": """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <EventData>
              <Data Name="TargetUserName">admin</Data>
              <Data Name="IpAddress">192.0.2.25</Data>
            </EventData>
            </Event>""",
        },
    )


def _sysmon_record(event_id: str, data: dict) -> dict:
    inner = "".join(
        f'<Data Name="{name}">{value}</Data>' for name, value in data.items()
    )
    return {
        "RecordId": 10,
        "Id": event_id,
        "TimeCreated": "2026-10-01T15:10:00Z",
        "Level": "Information",
        "Provider": "Microsoft-Windows-Sysmon",
        "Machine": "LAB-PC",
        "Message": "Sysmon event",
        "Xml": f"<Event><EventData>{inner}</EventData></Event>",
    }


def _pcap_flow_payload() -> dict:
    return {
        "timestamp": "2026-10-01T12:00:00",
        "channel": "network",
        "provider": "pcap:cap.pcap",
        "event_id": "FLOW",
        "level": "Information",
        "severity": "Low",
        "username": "unknown",
        "host": "LAB-PC",
        "source_ip": "10.0.0.5",
        "message": "TCP 10.0.0.5:1234 -> 93.184.216.34:443 (https), 5 packet(s), 1.2 KB",
        "record_id": "",
        "source": "pcap",
        "is_alert": False,
        "rule_name": "",
        "external_id": "x",
        "fields": {
            "protocol": "TCP",
            "source_address": "10.0.0.5",
            "destination_address": "93.184.216.34",
            "source_port": "1234",
            "destination_port": "443",
            "packets": "5",
            "bytes": "1234",
            "capture": "cap.pcap",
        },
    }


def _pcap_dns_payload() -> dict:
    return {
        "timestamp": "2026-10-01T12:00:00",
        "channel": "network",
        "provider": "pcap",
        "event_id": "DNS",
        "level": "Information",
        "severity": "Low",
        "username": "unknown",
        "host": "LAB-PC",
        "source_ip": "unknown",
        "message": "DNS query for example.com (1 time(s))",
        "source": "pcap",
        "is_alert": False,
        "fields": {"protocol": "DNS", "query_name": "example.com", "queries": "1", "capture": "cap.pcap"},
    }


# --- canonical shape -------------------------------------------------------

def test_canonical_record_has_exactly_the_documented_fields():
    event = normalise_event({"message": "One"})
    assert list(event) == list(CANONICAL_FIELDS)
    assert set(event) == {
        "timestamp", "host_id", "source", "event_type", "severity", "message",
        "user", "process", "command_line", "src_ip", "dst_ip", "dst_port",
        "dns_query", "file_hash", "rule_id", "techniques", "raw",
    }


def test_missing_optional_fields_become_none():
    event = normalise_event({"message": "One"})
    for name in ("host_id", "event_type", "user", "process", "command_line",
                 "src_ip", "dst_ip", "dst_port", "dns_query", "file_hash", "rule_id"):
        assert event[name] is None, name
    assert event["techniques"] == []


def test_unknown_fields_are_preserved_in_raw():
    payload = {"message": "One", "weird": {"nested": [1, 2]}, "count": 3}
    event = normalise_event(payload)
    assert event["raw"] == payload
    assert event["raw"]["weird"] == {"nested": [1, 2]}


# --- generic-json ----------------------------------------------------------

def test_generic_flat_payload_maps():
    event = normalise_event({"message": "One", "severity": "Low", "user": "bob"})
    assert event["source"] == "generic-json"
    assert event["message"] == "One"
    assert event["severity"] == "Low"
    assert event["user"] == "bob"


def test_generic_aliases_resolve():
    event = normalise_event(
        {
            "event": "Two",
            "level": "Warning",
            "hostname": "H",
            "ip": "10.1.1.1",
            "event_id": 77,
            "command": "cmd /c whoami",
            "techniques": "T1059.001, T1053",
        }
    )
    assert event["message"] == "Two"
    assert event["severity"] == "Medium"
    assert event["host_id"] == "H"
    assert event["src_ip"] == "10.1.1.1"
    assert event["event_type"] == "77"
    assert event["command_line"] == "cmd /c whoami"
    assert event["techniques"] == ["T1059.001", "T1053"]


def test_techniques_accepts_list_and_comma_string():
    assert normalise_event({"message": "m", "techniques": ["T1", "T2"]})["techniques"] == ["T1", "T2"]
    assert normalise_event({"message": "m", "techniques": "T1,T2"})["techniques"] == ["T1", "T2"]
    assert normalise_event({"message": "m", "techniques": "T1"})["techniques"] == ["T1"]


def test_dst_port_is_coerced_to_integer():
    assert normalise_event({"message": "m", "dst_port": "443"})["dst_port"] == 443
    assert normalise_event({"message": "m", "destination_port": 53})["dst_port"] == 53
    assert normalise_event({"message": "m"})["dst_port"] is None


def test_placeholder_values_are_normalised_to_none():
    event = normalise_event({"message": "m", "username": "unknown", "source_ip": "local", "host": "localhost"})
    assert event["user"] is None
    assert event["host_id"] is None
    assert event["src_ip"] == "local"


def test_generic_mapper_called_directly():
    event = from_generic_json({"message": "One"})
    assert event["source"] == "generic-json"
    assert event["message"] == "One"


# --- windows-event-log -----------------------------------------------------

def test_windows_payload_maps():
    event = normalise_event(_windows_payload())
    assert event["source"] == "windows-event-log"
    assert event["event_type"] == "Security:4625"
    assert event["user"] == "admin"
    assert event["src_ip"] == "192.0.2.25"
    assert event["host_id"] == "DESKTOP-LAB"
    assert event["severity"] in ("High", "Medium", "Low")
    assert event["timestamp"] == "2026-10-01 15:10:00"


def test_windows_raw_record_maps():
    record = {
        "RecordId": 4421,
        "Id": 4625,
        "TimeCreated": "2026-10-01T15:10:00+00:00",
        "Level": "Information",
        "Provider": "Microsoft-Windows-Security-Auditing",
        "Machine": "DESKTOP-LAB",
        "User": "S-1-5-18",
        "Message": "An account failed to log on.",
        "Xml": """<Event><EventData>
          <Data Name="TargetUserName">admin</Data>
          <Data Name="IpAddress">192.0.2.25</Data>
        </EventData></Event>""",
    }
    event = normalise_event(record)
    assert event["source"] == "windows-event-log"
    assert event["event_type"] == "4625"
    assert event["user"] == "admin"
    assert event["src_ip"] == "192.0.2.25"
    assert event["host_id"] == "DESKTOP-LAB"


def test_windows_mapper_called_directly():
    event = from_windows_event_log(_windows_payload())
    assert event["event_type"] == "Security:4625"
    assert event["message"] == "An account failed to log on."


# --- sysmon ----------------------------------------------------------------

def test_sysmon_process_create_maps():
    event = normalise_event(
        _sysmon_record(
            "1",
            {
                "Image": r"C:\Windows\System32\cmd.exe",
                "CommandLine": "cmd.exe /c whoami",
                "User": r"DESKTOP\user",
            },
        )
    )
    assert event["source"] == "sysmon"
    assert event["event_type"] == "ProcessCreate"
    assert event["process"] == r"C:\Windows\System32\cmd.exe"
    assert event["command_line"] == "cmd.exe /c whoami"
    assert event["user"] == r"DESKTOP\user"


def test_sysmon_network_connect_maps():
    event = normalise_event(
        _sysmon_record(
            "3",
            {"Image": "evil.exe", "SourceIp": "10.0.0.5", "DestinationIp": "8.8.8.8", "DestinationPort": "53"},
        )
    )
    assert event["event_type"] == "NetworkConnect"
    assert event["src_ip"] == "10.0.0.5"
    assert event["dst_ip"] == "8.8.8.8"
    assert event["dst_port"] == 53


def test_sysmon_dns_query_maps():
    event = normalise_event(_sysmon_record("22", {"QueryName": "example.com", "Image": "chrome.exe"}))
    assert event["event_type"] == "DnsQuery"
    assert event["dns_query"] == "example.com"


def test_sysmon_file_hash_prefers_sha256():
    event = normalise_event(_sysmon_record("11", {"Image": "x.exe", "Hashes": "MD5=aaaa, SHA256=bbbb"}))
    assert event["file_hash"] == "bbbb"


def test_sysmon_detected_by_channel_even_when_source_says_windows():
    payload = _windows_payload()
    payload["channel"] = "Microsoft-Windows-Sysmon/Operational"
    payload["source"] = "windows-event-log"
    payload["event_id"] = "1"
    payload["fields"] = {"Image": "cmd.exe", "CommandLine": "cmd /c whoami"}
    assert detect_source(payload) == "sysmon"
    assert normalise_event(payload)["source"] == "sysmon"


def test_sysmon_mapper_called_directly():
    event = from_sysmon(_sysmon_record("3", {"Image": "evil.exe", "DestinationPort": "4444"}))
    assert event["event_type"] == "NetworkConnect"
    assert event["dst_port"] == 4444


def test_unknown_sysmon_event_id_falls_back_to_a_numbered_type():
    event = normalise_event(_sysmon_record("99", {"Image": "x"}))
    assert event["event_type"] == "sysmon:99"


# --- pcap-flow -------------------------------------------------------------

def test_pcap_flow_maps():
    event = normalise_event(_pcap_flow_payload())
    assert event["source"] == "pcap-flow"
    assert event["event_type"] == "network-flow"
    assert event["src_ip"] == "10.0.0.5"
    assert event["dst_ip"] == "93.184.216.34"
    assert event["dst_port"] == 443
    assert event["user"] is None
    assert event["host_id"] == "LAB-PC"


def test_pcap_dns_maps():
    event = normalise_event(_pcap_dns_payload())
    assert event["source"] == "pcap-flow"
    assert event["event_type"] == "dns-query"
    assert event["dns_query"] == "example.com"
    assert event["src_ip"] is None


def test_pcap_mapper_called_directly():
    event = from_pcap_flow(_pcap_flow_payload())
    assert event["event_type"] == "network-flow"


# --- source detection ------------------------------------------------------

def test_auto_detects_each_source():
    assert detect_source({"message": "x"}) == "generic-json"
    assert detect_source(_windows_payload()) == "windows-event-log"
    assert detect_source({"source": "windows-event-log", "message": "x"}) == "windows-event-log"
    assert detect_source(_sysmon_record("1", {"Image": "x"})) == "sysmon"
    assert detect_source(_pcap_flow_payload()) == "pcap-flow"
    assert detect_source({"channel": "network", "message": "x"}) == "pcap-flow"


def test_explicit_source_overrides_detection():
    # A flat record the detector would call generic-json, forced through Sysmon.
    event = normalise_event({"message": "x", "Image": "cmd.exe"}, source="sysmon")
    assert event["source"] == "sysmon"


def test_source_aliases_are_accepted():
    assert normalise_event({"message": "x"}, source="pcap")["source"] == "pcap-flow"
    assert normalise_event({"message": "x"}, source="windows")["source"] == "windows-event-log"


# --- describe_schema -------------------------------------------------------

def test_describe_schema_documents_every_field():
    schema = describe_schema()
    names = [field["name"] for field in schema["fields"]]
    assert names == list(CANONICAL_FIELDS)
    assert schema["required"] == list(REQUIRED_FIELDS) == ["message"]
    assert schema["sources"] == list(SUPPORTED_SOURCES)
    for field in schema["fields"]:
        assert field["type"]
        assert field["description"]
        assert isinstance(field["required"], bool)
    assert schema["fields"][5]["name"] == "message"
    assert schema["fields"][5]["required"] is True


# --- timestamps ------------------------------------------------------------

def test_coerce_timestamp_formats():
    assert coerce_timestamp("2026-10-01T15:10:00Z") == "2026-10-01 15:10:00"
    assert coerce_timestamp("2026-10-01T15:10:00+00:00") == "2026-10-01 15:10:00"
    assert coerce_timestamp("2026-10-01T15:10:00.0000000Z") == "2026-10-01 15:10:00"
    assert coerce_timestamp("2026-10-01 15:10:00") == "2026-10-01 15:10:00"
    # An offset is converted to UTC.
    assert coerce_timestamp("2026-10-01T20:40:00+05:30") == "2026-10-01 15:10:00"


def test_coerce_timestamp_empty_is_now():
    before = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    result = coerce_timestamp(None)
    after = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    assert before <= result <= after
    assert len(result) == 19 and result[4] == "-" and result[13] == ":"
    assert len(coerce_timestamp("")) == 19


def test_coerce_timestamp_accepts_epoch_seconds():
    assert coerce_timestamp(0) == "1970-01-01 00:00:00"


def test_severity_synonyms_and_level_fallback():
    assert normalise_severity("high") == "High"
    assert normalise_event({"message": "m", "severity": "critical"})["severity"] == "High"
    assert normalise_event({"message": "m", "severity": "warning"})["severity"] == "Medium"
    assert normalise_event({"message": "m", "level": "Error"})["severity"] == "High"
    assert normalise_event({"message": "m"})["severity"] == "Low"


# --- error paths -----------------------------------------------------------

def test_non_dict_raises():
    with pytest.raises(ValueError, match="JSON object"):
        normalise_event([1, 2, 3])  # type: ignore[arg-type]


def test_missing_message_raises_naming_the_field():
    with pytest.raises(ValueError, match="message"):
        normalise_event({"severity": "Low"})
    with pytest.raises(ValueError, match="message"):
        normalise_event({"message": "   "})


def test_unknown_source_raises():
    with pytest.raises(ValueError, match="Unknown source"):
        normalise_event({"message": "x"}, source="not-a-source")


def test_invalid_source_argument_raises():
    with pytest.raises(ValueError, match="source must be a non-empty string"):
        normalise_event({"message": "x"}, source="")


def test_invalid_severity_raises():
    with pytest.raises(ValueError, match="Unsupported severity"):
        normalise_event({"message": "x", "severity": "Bananas"})


def test_invalid_timestamp_raises():
    with pytest.raises(ValueError, match="Invalid timestamp"):
        normalise_event({"message": "x", "timestamp": "not-a-date"})


def test_invalid_dst_port_raises():
    with pytest.raises(ValueError, match="Invalid dst_port"):
        normalise_event({"message": "x", "dst_port": "https"})
    with pytest.raises(ValueError, match="Invalid dst_port"):
        normalise_event({"message": "x", "dst_port": 70000})


def test_detect_source_rejects_non_dict():
    with pytest.raises(ValueError, match="JSON object"):
        detect_source("nope")  # type: ignore[arg-type]


# --- backward compatibility ------------------------------------------------

# The exact shapes app.normalise_payload already accepts.
FLAT_PAYLOADS = [
    {"message": "One"},
    {"event": "Two"},
    {"message": "Three", "severity": "High"},
    {"message": "Four", "severity": "Medium", "user": "bob", "hostname": "H", "ip": "10.0.0.1", "event_id": "77"},
    {"message": "Five", "username": "alice", "host": "H", "source_ip": "192.0.2.9", "raw_log": {"a": 1}},
    {"message": "Six", "is_alert": True, "rule_id": "R-1", "techniques": ["T1059.001"]},
]


@pytest.mark.parametrize("payload", FLAT_PAYLOADS)
def test_flat_payloads_accepted_by_normalise_payload_are_accepted(payload):
    event = normalise_event(payload)
    assert event["message"] == (payload.get("message") or payload.get("event"))
    assert event["raw"] == payload


@pytest.mark.parametrize("payload", FLAT_PAYLOADS)
def test_round_trip_through_normalise_payload(payload):
    event = normalise_event(payload)
    row = normalise_payload(to_payload(event))
    assert row[9] == (payload.get("message") or payload.get("event"))
    assert row[5] in ("High", "Medium", "Low")


def test_canonical_event_ingests_and_reaches_the_dashboard(tmp_path: Path):
    db = tmp_path / "live.db"
    event = normalise_event(
        {
            "message": "Failed logon",
            "severity": "Medium",
            "channel": "Security",
            "provider": "Security-Auditing",
            "event_id": "4625",
            "user": "admin",
            "ip": "192.0.2.10",
            "is_alert": True,
            "rule_name": "Failed Windows logon",
        }
    )
    inserted = ingest_payloads(db, [to_payload(event)])
    assert inserted == 1
    snapshot = dashboard_snapshot(db)
    assert snapshot["counts"]["Total"] == 1
    assert snapshot["alert_count"] == 1
    assert snapshot["events"][0]["message"] == "Failed logon"
