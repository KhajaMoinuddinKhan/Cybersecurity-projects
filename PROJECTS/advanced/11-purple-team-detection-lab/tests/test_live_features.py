import json
from pathlib import Path
from src.dashboard import DashboardHandler
from src.live import ingest
from src.storage import alert_stats, import_iocs, list_events


def event(event_id="live-1", source="198.51.100.23"):
    return {"event_id":event_id,"timestamp":"2026-10-01T10:00:00Z","event_type":"network_connection","source":source,"user":"analyst","host":"workstation","data":{"direction":"outbound","bytes_out":60000000}}


def test_live_ingestion_persists_events_and_ioc_alert(tmp_path):
    db=tmp_path/"live.db"; rules=Path(__file__).parents[1]/"rules"/"detection_rules.json"
    import_iocs(db, [("ip","198.51.100.23","feed-test")])
    result=ingest(db,rules,[event()])
    assert result["accepted"]==1
    assert result["threat_matches"]==1
    assert result["alerts_created"]>=1
    assert alert_stats(db)["events"]==1
    assert list_events(db)[0]["event_id"]=="live-1"


def test_live_duplicate_event_is_ignored(tmp_path):
    db=tmp_path/"live.db"; rules=Path(__file__).parents[1]/"rules"/"detection_rules.json"
    assert ingest(db,rules,[event()])["accepted"]==1
    assert ingest(db,rules,[event()])["accepted"]==0
