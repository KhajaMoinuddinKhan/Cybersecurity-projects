import json
import pytest
from src.event_io import load_events
from src.models import SecurityEvent


def record(timestamp="2026-10-01T10:00:00Z"):
    return dict(event_id="one", timestamp=timestamp, event_type="auth_failure", source="lab", user="user", host="host")


def test_mixed_timezone_events_are_normalized(tmp_path):
    first = record("2026-10-01T10:00:00")
    second = {**record("2026-10-01T11:00:00+02:00"), "event_id": "two"}
    path = tmp_path / "events.json"
    path.write_text(json.dumps([first, second]))
    events = load_events(path)
    assert [e.event_id for e in events] == ["two", "one"]
    assert all(e.timestamp.utcoffset().total_seconds() == 0 for e in events)


@pytest.mark.parametrize("value", [None, [], {}, " "])
def test_required_event_fields_reject_invalid_values(value):
    with pytest.raises(ValueError):
        SecurityEvent.from_dict({**record(), "host": value})
