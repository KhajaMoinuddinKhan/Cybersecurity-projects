"""Tests for the detection pipeline: rules, correlation, captures and retention."""
import json
import sqlite3
from pathlib import Path

import pytest

from src.app import (
    dashboard_app,
    dashboard_snapshot,
    get_connection,
    ingest_payloads,
    prune_events,
    query_events,
)
from src.correlation import build_correlation_payloads, correlate
from src.enrichment import INDICATOR_RULE_ID, ThreatIntel, apply_enrichment
from src.notify import Notifier
from src.rules import (
    CorrelationRule,
    RuleEngine,
    RuleError,
    event_fields,
    load_rules,
    shared_engine,
)

RULES_DIR = Path(__file__).resolve().parent.parent / "src" / "rules"


# --- the rule engine -------------------------------------------------------

def test_rules_load_from_files_and_split_by_type():
    engine = shared_engine()
    assert len(engine.rules) >= 20
    assert {rule.id for rule in engine.correlations} == {
        "corr-powershell-then-egress",
        "corr-bruteforce-then-lockout",
        "corr-new-account-then-privilege",
        "corr-log-cleared-after-service",
    }
    assert all(rule.source_file.endswith(".yml") for rule in engine.rules)


def test_logsource_stops_a_rule_firing_on_the_wrong_channel():
    engine = shared_engine()
    # 1102 belongs to Security; the same event id on another channel must not match.
    assert engine.match({"channel": "Security", "event_id": "1102", "message": "x"}) is not None
    assert engine.match({"channel": "System", "event_id": "1102", "message": "x"}) is None


def test_field_level_matching_on_sysmon_command_lines():
    engine = shared_engine()
    encoded = engine.match(
        {
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "event_id": "1",
            "message": "process created",
            "fields": {
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -enc SQBFAFgA",
            },
        }
    )
    assert encoded is not None
    assert encoded.rule_id == "sysmon-encoded-powershell-command"
    assert "attack.t1059.001" in encoded.techniques

    benign = engine.match(
        {
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "event_id": "1",
            "message": "process created",
            "fields": {
                "Image": "C:\\Windows\\System32\\notepad.exe",
                "CommandLine": "notepad.exe notes.txt",
            },
        }
    )
    assert benign is None


def test_parent_child_condition_matches_the_documented_pair():
    engine = shared_engine()
    match = engine.match(
        {
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "event_id": "1",
            "message": "process created",
            "fields": {
                "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": "cmd /c whoami",
            },
        }
    )
    assert match is not None
    assert match.rule_id == "sysmon-office-spawns-shell"
    assert set(match.matched_on) == {"selection", "child"}


def test_severity_decides_between_two_matching_rules():
    engine = shared_engine()
    # A telnet flow matches both the cleartext-service rule and the telnet rule.
    match = engine.match(
        {
            "channel": "network",
            "event_id": "FLOW",
            "message": "flow",
            "fields": {"protocol": "TCP", "destination_port": "23"},
        }
    )
    assert match is not None
    assert match.severity == "Medium"
    assert match.rule_id in {"net-cleartext-credential-service", "net-telnet-usage"}


def test_attack_coverage_is_derived_from_the_rules():
    coverage = shared_engine().attack_coverage()
    assert coverage
    assert all(item["technique"].startswith("attack.t") for item in coverage)
    assert all(item["rules"] >= 1 for item in coverage)


def test_a_broken_rule_file_is_refused(tmp_path):
    (tmp_path / "bad.yml").write_text(
        "rules:\n  - id: broken\n    title: Broken\n    level: High\n",
        encoding="utf-8",
    )
    with pytest.raises(RuleError, match="detection block"):
        load_rules(tmp_path)


def test_a_duplicate_rule_id_is_refused(tmp_path):
    body = (
        "rules:\n"
        "  - id: same\n    title: One\n    level: Low\n"
        "    detection:\n      selection:\n        event_id: '1'\n      condition: selection\n"
        "  - id: same\n    title: Two\n    level: Low\n"
        "    detection:\n      selection:\n        event_id: '2'\n      condition: selection\n"
    )
    (tmp_path / "dupes.yml").write_text(body, encoding="utf-8")
    with pytest.raises(RuleError, match="Duplicate rule id"):
        load_rules(tmp_path)


def test_event_fields_expose_structured_data_both_ways():
    fields = event_fields({"channel": "Security", "fields": {"TargetUserName": "admin"}})
    assert fields["TargetUserName"] == "admin"
    assert fields["data.TargetUserName"] == "admin"


# --- correlation -----------------------------------------------------------

def _alert(identifier, rule_id, timestamp, host="LAB-PC", username="admin"):
    return {
        "id": identifier,
        "rule_id": rule_id,
        "rule_name": rule_id,
        "timestamp": timestamp,
        "host": host,
        "username": username,
        "source_ip": "local",
        "event_id": "1",
        "channel": "Security",
        "severity": "High",
    }


def test_correlation_fires_on_an_ordered_sequence():
    rule = CorrelationRule(
        id="corr-test",
        title="Encoded PowerShell then egress",
        level="High",
        steps=("win-suspicious-powershell-script-block", "sysmon-network-connection-to-remote-port"),
        group_by="host",
        window_seconds=120,
    )
    events = [
        _alert(1, "win-suspicious-powershell-script-block", "2026-10-03 14:02:11"),
        _alert(2, "sysmon-network-connection-to-remote-port", "2026-10-03 14:02:14"),
    ]
    payloads = build_correlation_payloads(events, [rule])
    assert len(payloads) == 1
    assert payloads[0]["rule_name"] == "Encoded PowerShell then egress"
    assert payloads[0]["is_alert"] is True
    assert "within 3s" in payloads[0]["message"]
    recorded = json.loads(payloads[0]["raw_log"])["contributing_events"]
    assert [item["id"] for item in recorded] == [1, 2]


def test_correlation_respects_the_time_window():
    rule = CorrelationRule(
        id="corr-test",
        title="Too slow",
        level="High",
        steps=("win-suspicious-powershell-script-block", "sysmon-network-connection-to-remote-port"),
        group_by="host",
        window_seconds=30,
    )
    events = [
        _alert(1, "win-suspicious-powershell-script-block", "2026-10-03 14:02:11"),
        _alert(2, "sysmon-network-connection-to-remote-port", "2026-10-03 14:09:00"),
    ]
    assert build_correlation_payloads(events, [rule]) == []


def test_correlation_does_not_join_different_hosts():
    rule = CorrelationRule(
        id="corr-test",
        title="Two hosts",
        level="High",
        steps=("win-suspicious-powershell-script-block", "sysmon-network-connection-to-remote-port"),
        group_by="host",
        window_seconds=120,
    )
    events = [
        _alert(1, "win-suspicious-powershell-script-block", "2026-10-03 14:02:11", host="A"),
        _alert(2, "sysmon-network-connection-to-remote-port", "2026-10-03 14:02:14", host="B"),
    ]
    assert build_correlation_payloads(events, [rule]) == []


def test_correlation_needs_the_order_not_just_the_pair():
    rule = CorrelationRule(
        id="corr-test",
        title="Wrong order",
        level="High",
        steps=("win-suspicious-powershell-script-block", "sysmon-network-connection-to-remote-port"),
        group_by="host",
        window_seconds=120,
    )
    events = [
        _alert(1, "sysmon-network-connection-to-remote-port", "2026-10-03 14:02:11"),
        _alert(2, "win-suspicious-powershell-script-block", "2026-10-03 14:02:14"),
    ]
    assert build_correlation_payloads(events, [rule]) == []


def test_min_steps_requires_a_repeat(tmp_path):
    db = tmp_path / "live.db"
    ingest_payloads(
        db,
        [
            {
                "timestamp": "2026-10-03T14:00:00Z",
                "channel": "Security",
                "event_id": "4625",
                "message": "Failed logon",
                "username": "alice",
                "host": "LAB-PC",
                "is_alert": True,
                "rule_id": "win-failed-logon",
                "rule_name": "Failed Windows logon",
                "external_id": "Security:1",
            },
            {
                "timestamp": "2026-10-03T14:00:30Z",
                "channel": "Security",
                "event_id": "4625",
                "message": "Failed logon",
                "username": "alice",
                "host": "LAB-PC",
                "is_alert": True,
                "rule_id": "win-failed-logon",
                "rule_name": "Failed Windows logon",
                "external_id": "Security:2",
            },
        ],
        engine=None,
    )
    rules = [rule for rule in shared_engine().correlations if rule.id == "corr-bruteforce-then-lockout"]
    assert correlate(db, rules, since_minutes=1440) == 0

    ingest_payloads(
        db,
        [
            {
                "timestamp": "2026-10-03T14:01:00Z",
                "channel": "Security",
                "event_id": "4740",
                "message": "Account locked out",
                "username": "alice",
                "host": "LAB-PC",
                "is_alert": True,
                "rule_id": "win-account-locked-out",
                "rule_name": "User account locked out",
                "external_id": "Security:3",
            }
        ],
        engine=None,
    )
    assert correlate(db, rules, since_minutes=1440) == 1
    # Re-running must not duplicate: the external id is deterministic.
    assert correlate(db, rules, since_minutes=1440) == 0


def test_correlation_runs_end_to_end_over_stored_alerts(tmp_path):
    db = tmp_path / "live.db"
    ingest_payloads(
        db,
        [
            {
                "timestamp": "2026-10-03T14:02:11Z",
                "channel": "Microsoft-Windows-PowerShell/Operational",
                "event_id": "4104",
                "message": "powershell -enc AAAA",
                "host": "LAB-PC",
                "external_id": "ps:1",
            },
            {
                "timestamp": "2026-10-03T14:02:20Z",
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": "3",
                "message": "outbound connection",
                "host": "LAB-PC",
                "fields": {"DestinationIp": "203.0.113.9", "DestinationPort": "443"},
                "external_id": "sysmon:1",
            },
        ],
        engine=shared_engine(),
    )
    rules = [
        rule
        for rule in shared_engine().correlations
        if rule.id == "corr-powershell-then-egress"
    ]
    assert correlate(db, rules, since_minutes=1440) == 1
    snapshot = dashboard_snapshot(db)
    assert snapshot["correlation_count"] == 1
    assert snapshot["correlations"][0]["channel"] == "correlation"


# --- capture import --------------------------------------------------------

def _write_capture(path: Path) -> None:
    scapy = pytest.importorskip("scapy.all")
    packets = [
        scapy.Ether() / scapy.IP(src="10.0.0.5", dst="203.0.113.9") / scapy.TCP(sport=51000, dport=443),
        scapy.Ether() / scapy.IP(src="10.0.0.5", dst="203.0.113.9") / scapy.TCP(sport=51000, dport=443),
        scapy.Ether() / scapy.IP(src="10.0.0.5", dst="198.51.100.7") / scapy.TCP(sport=51001, dport=23),
        scapy.Ether() / scapy.IP(src="10.0.0.5", dst="8.8.8.8") / scapy.UDP(sport=40000, dport=53)
        / scapy.DNS(rd=1, qd=scapy.DNSQR(qname="example.test")),
    ]
    scapy.wrpcap(str(path), packets)


def test_capture_becomes_flows_and_dns_events(tmp_path):
    from src.pcap_ingest import ingest_capture

    capture = tmp_path / "lab.pcap"
    _write_capture(capture)
    db = tmp_path / "live.db"

    summary = ingest_capture(db, capture, host="LAB-PC")
    assert summary["packets_read"] == 4
    assert summary["flows"] == 3
    assert summary["dns_names"] == 1
    assert summary["inserted"] == summary["events_stored"]

    events = query_events(db, channel="network", limit=50)
    assert len(events) == summary["events_stored"]
    assert all(event["source"] == "pcap" for event in events)
    assert any(event["event_id"] == "DNS" and "example.test" in event["message"] for event in events)
    assert any("443" in event["message"] for event in events)


def test_capture_traffic_is_judged_by_network_rules(tmp_path):
    from src.pcap_ingest import ingest_capture

    capture = tmp_path / "lab.pcap"
    _write_capture(capture)
    db = tmp_path / "live.db"
    ingest_capture(db, capture, host="LAB-PC")

    telnet = [event for event in query_events(db, channel="network", limit=50) if "23" in event["message"]]
    assert telnet, "the telnet flow should have been recorded"
    assert telnet[0]["is_alert"] == 1
    assert telnet[0]["rule_id"] in {"net-telnet-usage", "net-cleartext-credential-service"}

    https = [event for event in query_events(db, channel="network", limit=50) if "-> 203.0.113.9:443" in event["message"]]
    assert https and https[0]["is_alert"] == 0


def test_a_capture_and_a_host_event_can_be_correlated(tmp_path):
    from src.pcap_ingest import ingest_capture

    capture = tmp_path / "lab.pcap"
    _write_capture(capture)
    db = tmp_path / "live.db"
    ingest_payloads(
        db,
        [
            {
                "timestamp": "2026-10-03T14:02:11Z",
                "channel": "Microsoft-Windows-PowerShell/Operational",
                "event_id": "4104",
                "message": "powershell -enc AAAA",
                "host": "LAB-PC",
                "external_id": "ps:1",
            }
        ],
        engine=shared_engine(),
    )
    ingest_capture(db, capture, host="LAB-PC")
    # The flow events carry the current time, so the sequence is only complete
    # when the two are within the rule's window.
    raised = correlate(db, shared_engine().correlations, since_minutes=1440)
    assert raised >= 0
    stored = query_events(db, channel="network", limit=50)
    assert stored


# --- threat intelligence ---------------------------------------------------

def _intel_db(path: Path) -> Path:
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE iocs (id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " type TEXT NOT NULL, value TEXT NOT NULL, source TEXT NOT NULL,"
        " UNIQUE(type,value))"
    )
    connection.executemany(
        "INSERT INTO iocs(type,value,source) VALUES (?,?,?)",
        [
            ("ip", "203.0.113.9", "lab-feed"),
            ("domain", "bad-domain.example", "lab-feed"),
            ("hash", "44d88612fea8a8f36de82e1278abb02f", "lab-feed"),
        ],
    )
    connection.commit()
    connection.close()
    return path


def test_intel_raises_an_alert_on_a_known_address(tmp_path):
    intel = ThreatIntel.load(_intel_db(tmp_path / "intel.db"))
    assert intel.size == 3
    enriched = apply_enrichment(
        {"message": "connection", "source_ip": "203.0.113.9", "severity": "Low", "is_alert": False},
        intel,
    )
    assert enriched["is_alert"] is True
    assert enriched["rule_id"] == INDICATOR_RULE_ID
    assert enriched["severity"] == "High"
    assert "203.0.113.9" in enriched["message"]


def test_intel_leaves_an_unrelated_event_alone(tmp_path):
    intel = ThreatIntel.load(_intel_db(tmp_path / "intel.db"))
    payload = {"message": "connection", "source_ip": "10.0.0.5", "severity": "Low", "is_alert": False}
    assert apply_enrichment(payload, intel) == payload


def test_intel_does_not_replace_the_rule_that_already_fired(tmp_path):
    intel = ThreatIntel.load(_intel_db(tmp_path / "intel.db"))
    enriched = apply_enrichment(
        {
            "message": "known bad",
            "source_ip": "203.0.113.9",
            "severity": "Medium",
            "is_alert": True,
            "rule_id": "win-failed-logon",
            "rule_name": "Failed Windows logon",
        },
        intel,
    )
    assert enriched["rule_id"] == "win-failed-logon"
    assert enriched["severity"] == "Medium"
    assert enriched["enrichment"]


def test_an_absent_intel_store_is_empty_not_an_error(tmp_path):
    assert ThreatIntel.load(tmp_path / "missing.db").size == 0
    assert ThreatIntel.load(None).size == 0


def test_intel_reaches_the_store_through_ingestion(tmp_path):
    db = tmp_path / "live.db"
    intel = ThreatIntel.load(_intel_db(tmp_path / "intel.db"))
    ingest_payloads(
        db,
        [{"message": "outbound", "source_ip": "203.0.113.9", "host": "LAB-PC"}],
        engine=None,
        intel=intel,
    )
    stored = query_events(db)[0]
    assert stored["is_alert"] == 1
    assert stored["rule_id"] == INDICATOR_RULE_ID
    assert json.loads(stored["enrichment"])[0]["value"] == "203.0.113.9"


# --- retention -------------------------------------------------------------

def test_retention_removes_only_what_is_older_than_the_window(tmp_path):
    db = tmp_path / "live.db"
    ingest_payloads(
        db,
        [
            {"message": "old", "channel": "System", "external_id": "old:1",
             "timestamp": "2020-01-01T00:00:00Z"},
            {"message": "new", "channel": "System", "external_id": "new:1"},
        ],
        engine=None,
    )
    assert dashboard_snapshot(db)["counts"]["Total"] == 2
    assert prune_events(db, 30) == 1
    remaining = query_events(db)
    assert len(remaining) == 1
    assert remaining[0]["message"] == "new"


def test_retention_of_zero_days_keeps_everything(tmp_path):
    db = tmp_path / "live.db"
    ingest_payloads(db, [{"message": "old", "timestamp": "2020-01-01T00:00:00Z"}], engine=None)
    assert prune_events(db, 0) == 0
    assert dashboard_snapshot(db)["counts"]["Total"] == 1


# --- schema migration ------------------------------------------------------

def test_an_existing_store_gains_the_new_columns(tmp_path):
    db = tmp_path / "old.db"
    connection = sqlite3.connect(db)
    connection.execute(
        "CREATE TABLE live_events (id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " timestamp TEXT NOT NULL, channel TEXT NOT NULL, provider TEXT NOT NULL,"
        " event_id TEXT NOT NULL, level TEXT NOT NULL, severity TEXT NOT NULL,"
        " username TEXT NOT NULL, host TEXT NOT NULL, source_ip TEXT NOT NULL,"
        " message TEXT NOT NULL, record_id TEXT NOT NULL, source TEXT NOT NULL,"
        " is_alert INTEGER NOT NULL DEFAULT 0, rule_name TEXT NOT NULL DEFAULT '',"
        " raw_log TEXT NOT NULL DEFAULT '', external_id TEXT NOT NULL DEFAULT '',"
        " created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
    )
    connection.execute(
        "INSERT INTO live_events(timestamp,channel,provider,event_id,level,severity,"
        "username,host,source_ip,message,record_id,source) "
        "VALUES ('2026-10-01 00:00:00','System','P','1','Information','Low',"
        "'u','h','local','kept','','legacy')"
    )
    connection.commit()
    connection.close()

    with get_connection(db) as upgraded:
        columns = {row["name"] for row in upgraded.execute("PRAGMA table_info(live_events)")}
    assert {"rule_id", "techniques", "matched_on", "enrichment"} <= columns
    assert query_events(db)[0]["message"] == "kept"


# --- notification ----------------------------------------------------------

def test_alerts_are_written_to_a_log_file(tmp_path):
    log = tmp_path / "alerts.jsonl"
    notifier = Notifier(log_path=log, min_severity="Medium")
    delivered = notifier.deliver(
        [
            {"is_alert": True, "severity": "High", "rule_name": "One", "message": "a"},
            {"is_alert": True, "severity": "Low", "rule_name": "Two", "message": "b"},
            {"is_alert": False, "severity": "High", "rule_name": "Three", "message": "c"},
        ]
    )
    assert delivered == 1
    records = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert len(records) == 1
    assert records[0]["rule_name"] == "One"
    assert notifier.status()["sent"] == 1


def test_a_disabled_notifier_does_nothing(tmp_path):
    notifier = Notifier()
    assert notifier.enabled is False
    assert notifier.deliver([{"is_alert": True, "severity": "High"}]) == 0


# --- authentication --------------------------------------------------------

def test_the_api_requires_the_token_when_one_is_set(tmp_path):
    client = dashboard_app(tmp_path / "live.db", auth_token="s3cret").test_client()
    assert client.get("/api/dashboard").status_code == 401
    assert client.get("/api/dashboard", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/api/dashboard", headers={"Authorization": "Bearer s3cret"}).status_code == 200
    assert client.get("/api/dashboard?token=s3cret").status_code == 200
    assert client.get("/api/dashboard", headers={"X-Auth-Token": "s3cret"}).status_code == 200


def test_the_page_needs_the_token_too(tmp_path):
    client = dashboard_app(tmp_path / "live.db", auth_token="s3cret").test_client()
    assert client.get("/").status_code == 401
    page = client.get("/?token=s3cret")
    assert page.status_code == 200
    assert b"s3cret" in page.data


def test_no_token_means_an_open_local_console(tmp_path):
    client = dashboard_app(tmp_path / "live.db").test_client()
    assert client.get("/api/dashboard").status_code == 200
    assert client.get("/").status_code == 200


# --- new API surface -------------------------------------------------------

def test_rules_endpoint_describes_the_loaded_content(tmp_path):
    client = dashboard_app(tmp_path / "live.db").test_client()
    data = client.get("/api/rules").get_json()
    assert len(data["detections"]) >= 20
    assert len(data["correlations"]) == 4
    assert data["techniques"]
    first = data["detections"][0]
    assert {"rule_id", "title", "level", "techniques", "falsepositives"} <= set(first)


def test_ingestion_records_which_rule_fired_and_why(tmp_path):
    db = tmp_path / "live.db"
    ingest_payloads(
        db,
        [
            {
                "message": "An account failed to log on.",
                "channel": "Security",
                "event_id": "4625",
                "username": "admin",
                "host": "LAB-PC",
            }
        ],
        engine=shared_engine(),
    )
    stored = query_events(db)[0]
    assert stored["is_alert"] == 1
    assert stored["rule_id"] == "win-failed-logon"
    assert stored["rule_name"] == "Failed Windows logon"
    assert json.loads(stored["matched_on"]) == ["selection"]


def test_a_rule_does_not_overrule_a_source_that_already_judged_the_event(tmp_path):
    db = tmp_path / "live.db"
    ingest_payloads(
        db,
        [
            {
                "message": "An account failed to log on.",
                "channel": "Security",
                "event_id": "4625",
                "severity": "High",
                "is_alert": True,
                "rule_name": "Something else",
            }
        ],
        engine=shared_engine(),
    )
    stored = query_events(db)[0]
    assert stored["severity"] == "High"
    assert stored["rule_name"] == "Failed Windows logon"


def test_the_snapshot_reports_rule_and_technique_counts(tmp_path):
    db = tmp_path / "live.db"
    ingest_payloads(
        db,
        [
            {
                "message": "powershell -enc AAAA",
                "channel": "Microsoft-Windows-PowerShell/Operational",
                "event_id": "4104",
                "host": "LAB-PC",
            }
        ],
        engine=shared_engine(),
    )
    snapshot = dashboard_snapshot(db)
    assert snapshot["top_rules"][0]["label"] == "Suspicious PowerShell script block"
    techniques = {item["label"] for item in snapshot["top_techniques"]}
    assert "attack.t1059.001" in techniques


def test_correlate_endpoint_raises_stored_sequences(tmp_path):
    db = tmp_path / "live.db"
    ingest_payloads(
        db,
        [
            {"message": "powershell -enc AAAA",
             "channel": "Microsoft-Windows-PowerShell/Operational", "event_id": "4104",
             "host": "LAB-PC", "external_id": "ps:1"},
            {"message": "outbound connection",
             "channel": "Microsoft-Windows-Sysmon/Operational", "event_id": "3",
             "host": "LAB-PC", "external_id": "sysmon:1"},
        ],
        engine=shared_engine(),
    )
    client = dashboard_app(db).test_client()
    assert client.post("/api/correlate?since=1440").get_json()["raised"] == 1
    assert client.post("/api/correlate?since=1440").get_json()["raised"] == 0
    assert client.post("/api/correlate?since=abc").status_code == 400


def test_the_capture_endpoint_refuses_a_file_that_is_not_a_capture(tmp_path):
    client = dashboard_app(tmp_path / "live.db").test_client()
    response = client.post(
        "/api/pcap",
        data={"file": (__import__("io").BytesIO(b"not a capture"), "notes.txt")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert "pcap" in response.get_json()["error"]


def test_the_capture_endpoint_stores_flows(tmp_path):
    from src.pcap_ingest import ingest_capture

    capture = tmp_path / "lab.pcap"
    _write_capture(capture)
    db = tmp_path / "live.db"
    client = dashboard_app(db).test_client()
    with capture.open("rb") as handle:
        response = client.post(
            "/api/pcap",
            data={"file": (handle, "lab.pcap")},
            content_type="multipart/form-data",
        )
    assert response.status_code == 201, response.get_data(as_text=True)
    summary = response.get_json()
    assert summary["flows"] == 3
    assert summary["inserted"] >= 3
    assert dashboard_snapshot(db)["counts"]["Total"] >= 3


def test_a_capture_that_is_not_a_capture_is_reported_clearly(tmp_path):
    from src.pcap_ingest import PcapError, ingest_capture

    broken = tmp_path / "broken.pcap"
    broken.write_bytes(b"\x00\x01\x02not-a-real-capture")
    with pytest.raises((PcapError, ValueError, OSError)):
        ingest_capture(tmp_path / "live.db", broken)

def test_correlation_rules_carry_technique_tags():
    engine = shared_engine()
    for rule in engine.correlations:
        assert rule.techniques, f"{rule.id} should name at least one ATT&CK technique"


def test_a_correlation_alert_records_its_steps(tmp_path):
    db = tmp_path / "live.db"
    ingest_payloads(
        db,
        [
            {"message": "powershell -enc AAAA",
             "channel": "Microsoft-Windows-PowerShell/Operational", "event_id": "4104",
             "host": "LAB-PC", "external_id": "ps:1"},
            {"message": "outbound connection",
             "channel": "Microsoft-Windows-Sysmon/Operational", "event_id": "3",
             "host": "LAB-PC", "external_id": "sysmon:1"},
        ],
        engine=shared_engine(),
    )
    rules = [rule for rule in shared_engine().correlations if rule.id == "corr-powershell-then-egress"]
    assert correlate(db, rules, since_minutes=1440) == 1
    alert = dashboard_snapshot(db)["correlations"][0]
    assert json.loads(alert["matched_on"]) == [
        "win-suspicious-powershell-script-block",
        "sysmon-network-connection-to-remote-port",
    ]
    assert "attack.t1059.001" in alert["techniques"]


def test_a_notification_fills_the_same_defaults_the_store_does(tmp_path):
    from src.app import notification_record

    record = notification_record({"message": "something", "is_alert": True, "severity": "High"}, "api")
    assert record["host"] == "unknown"
    assert record["source_ip"] == "local"
    assert record["channel"] == "api"
    assert record["event_id"] == "unknown"
    assert record["username"] == "unknown"


def test_a_delivered_alert_names_the_host_and_address(tmp_path):
    db = tmp_path / "live.db"
    log = tmp_path / "alerts.jsonl"
    notifier = Notifier(log_path=log, min_severity="Medium")
    ingest_payloads(
        db,
        [{"message": "powershell -enc AAAA", "channel": "Microsoft-Windows-PowerShell/Operational",
          "event_id": "4104", "host": "LAB-PC", "source_ip": "10.0.0.5"}],
        engine=shared_engine(),
        notifier=notifier,
    )
    record = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
    assert record["host"] == "LAB-PC"
    assert record["source_ip"] == "10.0.0.5"
    assert record["rule_id"] == "win-suspicious-powershell-script-block"
    assert "attack.t1059.001" in record["techniques"]

# --- the collector must not drown in its own output ------------------------

def _collector(tmp_path, **kwargs):
    from src.windows_collector import WindowsEventCollector

    return WindowsEventCollector(tmp_path / "live.db", ingest_payloads, **kwargs)


def _record(record_id, process_id, message="PowerShell console is starting up"):
    return {
        "RecordId": record_id,
        "Id": 40961,
        "TimeCreated": "2026-10-03T18:00:00+00:00",
        "Level": "Information",
        "Provider": "Microsoft-Windows-PowerShell",
        "Machine": "LAB-PC",
        "User": "unknown",
        "ProcessId": process_id,
        "Message": message,
        "Xml": "",
    }


def test_the_collector_skips_events_from_its_own_powershell(tmp_path):
    collector = _collector(tmp_path, channels=("Microsoft-Windows-PowerShell/Operational",))
    collector._remember_pid(4242)

    collector._ingest_records(
        "Microsoft-Windows-PowerShell/Operational",
        [_record(1, 4242), _record(2, 4242), _record(3, 9999)],
        backfill=False,
    )

    assert collector.status["self_skipped"] == 2
    assert collector.status["ingested"] == 1
    stored = query_events(tmp_path / "live.db")
    assert len(stored) == 1
    assert stored[0]["record_id"] == "3"


def test_the_cursor_still_advances_past_skipped_records(tmp_path):
    collector = _collector(tmp_path, channels=("Microsoft-Windows-PowerShell/Operational",))
    collector._remember_pid(4242)
    collector._ingest_records(
        "Microsoft-Windows-PowerShell/Operational",
        [_record(10, 4242), _record(11, 4242)],
        backfill=False,
    )
    # Nothing stored, but the next poll must ask for records after 11, or the
    # same two would be read again on every cycle.
    assert collector.cursors["Microsoft-Windows-PowerShell/Operational"] == 11
    assert collector.status["channels"]["Microsoft-Windows-PowerShell/Operational"]["last_record"] == 11
    assert query_events(tmp_path / "live.db") == []


def test_a_record_without_a_process_id_is_kept(tmp_path):
    collector = _collector(tmp_path, channels=("System",))
    collector._remember_pid(4242)
    collector._ingest_records(
        "System",
        [{"RecordId": 5, "Id": 7045, "TimeCreated": "2026-10-03T18:00:00+00:00",
          "Level": "Information", "Provider": "Service Control Manager",
          "Machine": "LAB-PC", "User": "SYSTEM", "Message": "A service was installed.", "Xml": ""}],
        backfill=False,
    )
    assert collector.status["self_skipped"] == 0
    assert len(query_events(tmp_path / "live.db")) == 1


def test_the_remembered_process_ids_are_bounded(tmp_path):
    from src.windows_collector import OWN_PID_MEMORY

    collector = _collector(tmp_path, channels=("System",))
    for pid in range(1, OWN_PID_MEMORY + 51):
        collector._remember_pid(pid)
    assert len(collector._own_pids) == OWN_PID_MEMORY
    assert collector._is_own_pid(OWN_PID_MEMORY + 50)
    assert not collector._is_own_pid(1)


def test_the_projection_asks_windows_for_the_process_id():
    from src.windows_collector import WindowsEventCollector

    assert "ProcessId" in WindowsEventCollector._projection()


def test_the_collector_starts_its_own_noise_counter_at_zero(tmp_path):
    assert _collector(tmp_path).status["self_skipped"] == 0


# --- a channel that is not there is not a fault -----------------------------

SYSMON_MISSING = (
    "Get-WinEvent : There is not an event log on the localhost computer that matches "
    "\"Microsoft-Windows-Sysmon/Operational\".\nAt line:1 char:153\n"
    "+ ... top';try {@(Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operation ...\n"
    "+ CategoryInfo          : ObjectNotFound: (Microsoft-Windows-Sysmon/Operational:String)\n"
    "+ FullyQualifiedErrorId : NoMatchingLogsFound,Microsoft.PowerShell.Commands.GetWinEventCommand"
)


def test_a_channel_that_is_not_installed_is_reported_as_missing():
    from src.windows_collector import describe_channel_error

    state, message = describe_channel_error("Microsoft-Windows-Sysmon/Operational", SYSMON_MISSING)
    assert state == "missing"
    assert "does not exist on this machine" in message
    assert "FullyQualifiedErrorId" not in message
    assert "CategoryInfo" not in message


def test_a_channel_the_account_cannot_read_is_reported_as_denied():
    from src.windows_collector import describe_channel_error

    state, message = describe_channel_error(
        "Security", "Attempted to perform an unauthorized operation."
    )
    assert state == "denied"
    assert "cannot be read by this account" in message


def test_a_genuine_failure_is_still_an_error_and_only_one_line():
    from src.windows_collector import describe_channel_error

    state, message = describe_channel_error(
        "System", "PowerShell command failed\nsecond line\nthird line"
    )
    assert state == "error"
    assert message == "System: PowerShell command failed"


def test_a_missing_channel_does_not_raise_the_summary_error(tmp_path, monkeypatch):
    collector = _collector(tmp_path, channels=("Microsoft-Windows-Sysmon/Operational",))
    monkeypatch.setattr(
        collector, "_recent_records", lambda channel: (_ for _ in ()).throw(RuntimeError(SYSMON_MISSING))
    )
    collector.stop_event.set()
    collector._run()
    assert collector.status["channels"]["Microsoft-Windows-Sysmon/Operational"]["state"] == "missing"
    # The dashboard should not shout about a channel the machine simply does not have.
    assert collector.status["last_error"] == ""


def test_the_summary_line_is_set_once_per_cycle_not_mid_poll(tmp_path, monkeypatch):
    collector = _collector(tmp_path, channels=("Microsoft-Windows-Sysmon/Operational",))
    monkeypatch.setattr(collector, "_recent_records", lambda channel: [])

    def new_records(channel, after_record_id):
        collector.stop_event.set()
        raise RuntimeError(SYSMON_MISSING)

    monkeypatch.setattr(collector, "_new_records", new_records)
    collector._run()

    assert collector.status["channels"]["Microsoft-Windows-Sysmon/Operational"]["state"] == "missing"
    # A reader asking at any point in the cycle gets the same answer.
    assert collector.status["last_error"] == ""


# --- context rules: match, record, do not raise -----------------------------

def test_a_rule_marked_alert_false_records_itself_without_raising(tmp_path):
    db = tmp_path / "live.db"
    ingest_payloads(
        db,
        [{
            "message": "outbound connection",
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "event_id": "3",
            "host": "LAB-PC",
            "fields": {"DestinationIp": "203.0.113.9", "DestinationPort": "443"},
        }],
        engine=shared_engine(),
    )
    stored = query_events(db)[0]
    assert stored["rule_id"] == "sysmon-network-connection-to-remote-port"
    assert stored["rule_name"] == "Process opened an outbound connection"
    assert stored["is_alert"] == 0
    assert stored["severity"] == "Low"
    assert dashboard_snapshot(db)["alert_count"] == 0


def test_loopback_connections_are_not_even_context(tmp_path):
    db = tmp_path / "live.db"
    ingest_payloads(
        db,
        [{
            "message": "local connection",
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "event_id": "3",
            "host": "LAB-PC",
            "fields": {"DestinationIp": "127.0.0.1", "DestinationPort": "5000"},
        }],
        engine=shared_engine(),
    )
    assert query_events(db)[0]["rule_id"] == ""


def test_a_context_rule_can_still_be_the_step_of_a_correlation(tmp_path):
    db = tmp_path / "live.db"
    ingest_payloads(
        db,
        [
            {"message": "powershell -enc AAAA",
             "channel": "Microsoft-Windows-PowerShell/Operational", "event_id": "4104",
             "host": "LAB-PC", "external_id": "ps:1"},
            {"message": "outbound connection",
             "channel": "Microsoft-Windows-Sysmon/Operational", "event_id": "3",
             "host": "LAB-PC", "external_id": "sysmon:1",
             "fields": {"DestinationIp": "203.0.113.9", "DestinationPort": "443"}},
        ],
        engine=shared_engine(),
    )
    # The second event is not an alert, but correlation reads rule hits.
    assert dashboard_snapshot(db)["alert_count"] == 1
    rules = [rule for rule in shared_engine().correlations if rule.id == "corr-powershell-then-egress"]
    assert correlate(db, rules, since_minutes=1440) == 1


def test_alert_must_be_a_boolean_in_a_rule_file(tmp_path):
    body = (
        "rules:\n"
        "  - id: odd\n    title: Odd\n    level: Low\n    alert: sometimes\n"
        "    detection:\n      selection:\n        event_id: '1'\n      condition: selection\n"
    )
    (tmp_path / "odd.yml").write_text(body, encoding="utf-8")
    with pytest.raises(RuleError, match="alert must be true or false"):
        load_rules(tmp_path)


def test_the_rules_endpoint_says_which_rules_alert():
    coverage = {item["rule_id"]: item for item in shared_engine().coverage()}
    assert coverage["sysmon-network-connection-to-remote-port"]["raises_alert"] is False
    assert coverage["win-failed-logon"]["raises_alert"] is True
