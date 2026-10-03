"""Multi-host ingestion, accounts and triage, exercised through the HTTP surface.

These tests drive the console the way an operator and an agent actually do: a
host is enrolled, an agent ships events with the key it was given, a user signs
in, and the detections that result are triaged. The existing suites cover the
pipeline and the individual modules; this one covers the wiring between them.
"""
import json

import pytest

from src import auth, hosts, triage
from src.app import SESSION_COOKIE, dashboard_app, get_connection

# A Sysmon process-creation record with an encoded command line, which is what
# the shipped sysmon-encoded-powershell-command rule looks for.
ENCODED_POWERSHELL = {
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider": "Microsoft-Windows-Sysmon",
    "event_id": "1",
    "level": "Information",
    "message": "Process Create",
    "fields": {
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -enc JABhAGIAYwA=",
    },
}


def build(tmp_path):
    """A console over its own store."""

    db = tmp_path / "siem.db"
    app = dashboard_app(db)
    app.config.update(TESTING=True)
    return db, app


def enrol(db, name="web-01", **kwargs):
    with get_connection(db) as connection:
        record = hosts.enrol_host(connection, name, **kwargs)
        connection.commit()
    return record


def add_user(db, username="analyst1", password="CorrectHorse9!", role="analyst"):
    with get_connection(db) as connection:
        user = auth.create_user(connection, username, password, role, actor="setup")
        connection.commit()
    return user


def sign_in(client, username="analyst1", password="CorrectHorse9!"):
    response = client.post("/login", data={"username": username, "password": password})
    assert response.status_code in (302, 200), response.data
    return response


def ship(client, key, events, host_id="web-01"):
    return client.post(
        "/api/ingest",
        json={"host_id": host_id, "agent_version": "1.2.3", "platform": "windows", "events": events},
        headers={"Authorization": f"Bearer {key}"},
    )


# ------------------------------------------------------------------ open until claimed

def test_the_console_is_open_until_the_first_account_exists(tmp_path):
    db, app = build(tmp_path)
    client = app.test_client()
    assert client.get("/api/dashboard").status_code == 200
    assert client.get("/api/me").status_code == 401


def test_a_created_account_makes_the_console_require_a_session(tmp_path):
    db, app = build(tmp_path)
    add_user(db)
    client = app.test_client()
    assert client.get("/api/dashboard").status_code == 401
    assert client.get("/api/hosts").status_code == 401
    # The page itself and the identity probe stay reachable, so the page can
    # offer the sign-in form.
    assert client.get("/").status_code == 200
    assert client.get("/api/me").status_code == 401


# -------------------------------------------------------------------------- sign in

def test_signing_in_reports_the_user_and_role(tmp_path):
    db, app = build(tmp_path)
    add_user(db)
    client = app.test_client()
    sign_in(client)
    me = client.get("/api/me")
    assert me.status_code == 200
    assert me.get_json() == {"username": "analyst1", "role": "analyst"}


def test_a_wrong_password_is_refused(tmp_path):
    db, app = build(tmp_path)
    add_user(db)
    client = app.test_client()
    assert client.post("/login", data={"username": "analyst1", "password": "nope"}).status_code == 401
    assert client.get("/api/me").status_code == 401


def test_signing_out_ends_the_session(tmp_path):
    db, app = build(tmp_path)
    add_user(db)
    client = app.test_client()
    sign_in(client)
    assert client.get("/api/me").status_code == 200
    client.post("/logout")
    assert client.get("/api/me").status_code == 401


# ----------------------------------------------------------------------- ingestion

def test_an_agent_with_its_key_can_ship_events(tmp_path):
    db, app = build(tmp_path)
    host = enrol(db)
    client = app.test_client()
    response = ship(client, host["key"], [ENCODED_POWERSHELL])
    assert response.status_code == 202, response.data
    body = response.get_json()
    assert body["accepted"] == 1 and body["rejected"] == 0

    with get_connection(db) as connection:
        row = connection.execute(
            "SELECT host, host_id, channel FROM live_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
    assert row["host"] == "web-01"
    assert row["host_id"] == str(host["host_id"])


def test_an_agent_with_the_wrong_key_is_refused(tmp_path):
    db, app = build(tmp_path)
    enrol(db)
    client = app.test_client()
    assert ship(client, "hk_not-the-key", [ENCODED_POWERSHELL]).status_code == 401


def test_an_unenrolled_host_name_is_refused(tmp_path):
    db, app = build(tmp_path)
    host = enrol(db, name="web-01")
    client = app.test_client()
    response = ship(client, host["key"], [ENCODED_POWERSHELL], host_id="not-enrolled")
    assert response.status_code == 401


def test_a_disabled_host_is_refused(tmp_path):
    db, app = build(tmp_path)
    host = enrol(db)
    with get_connection(db) as connection:
        hosts.disable_host(connection, host["host_id"])
        connection.commit()
    client = app.test_client()
    assert ship(client, host["key"], [ENCODED_POWERSHELL]).status_code == 403


def test_ingesting_records_the_host_as_reporting(tmp_path):
    db, app = build(tmp_path)
    host = enrol(db)
    client = app.test_client()
    ship(client, host["key"], [ENCODED_POWERSHELL, ENCODED_POWERSHELL])

    signed = app.test_client()
    add_user(db, role="admin")
    signed.post("/login", data={"username": "analyst1", "password": "CorrectHorse9!"})
    payload = signed.get("/api/hosts").get_json()
    assert payload["summary"]["total"] == 1
    row = payload["hosts"][0]
    assert row["name"] == "web-01"
    assert row["status"] == "online"
    assert row["event_count"] == 2
    assert row["agent_version"] == "1.2.3"


# -------------------------------------------------------------------------- triage

def detection_id(client):
    body = client.get("/api/detections").get_json()
    assert body["detections"], body
    return body["detections"][0]["id"]


def test_a_shipped_event_becomes_a_detection(tmp_path):
    db, app = build(tmp_path)
    host = enrol(db)
    ship(app.test_client(), host["key"], [ENCODED_POWERSHELL])
    add_user(db)
    client = app.test_client()
    sign_in(client)
    body = client.get("/api/detections").get_json()
    assert body["total"] == 1
    detection = body["detections"][0]
    assert detection["rule_id"] == "sysmon-encoded-powershell-command"
    assert detection["host_id"] == "web-01"
    assert detection["status"] == "new"
    assert detection["title"]


def test_status_and_notes_round_trip(tmp_path):
    db, app = build(tmp_path)
    host = enrol(db)
    ship(app.test_client(), host["key"], [ENCODED_POWERSHELL])
    add_user(db)
    client = app.test_client()
    sign_in(client)
    identifier = detection_id(client)

    assert client.post(
        f"/api/detections/{identifier}/status",
        json={"status": "investigating", "assignee": "analyst1"},
    ).status_code == 200
    assert client.post(
        f"/api/detections/{identifier}/notes", json={"text": "checked the host"}
    ).status_code == 201

    detection = client.get("/api/detections").get_json()["detections"][0]
    assert detection["status"] == "investigating"
    assert detection["assignee"] == "analyst1"
    assert detection["note_count"] == 1

    notes = client.get(f"/api/detections/{identifier}/notes").get_json()["notes"]
    assert [note["text"] for note in notes] == ["checked the host"]
    assert notes[0]["author"] == "analyst1"


def test_a_bad_status_is_refused(tmp_path):
    db, app = build(tmp_path)
    host = enrol(db)
    ship(app.test_client(), host["key"], [ENCODED_POWERSHELL])
    add_user(db)
    client = app.test_client()
    sign_in(client)
    identifier = detection_id(client)
    assert client.post(
        f"/api/detections/{identifier}/status", json={"status": "banana"}
    ).status_code == 400


def test_a_suppression_hides_the_detection_but_keeps_the_event(tmp_path):
    db, app = build(tmp_path)
    host = enrol(db)
    ship(app.test_client(), host["key"], [ENCODED_POWERSHELL])
    add_user(db)
    client = app.test_client()
    sign_in(client)
    assert client.get("/api/detections").get_json()["total"] == 1

    created = client.post(
        "/api/suppressions",
        json={"rule_id": "sysmon-encoded-powershell-command", "host_id": "web-01",
              "scope": "host", "reason": "lab noise", "expires_days": 30},
    )
    assert created.status_code == 201, created.data
    identifier = created.get_json()["suppression"]["id"]

    body = client.get("/api/detections").get_json()
    assert body["total"] == 0
    assert body["summary"]["Suppressed"] == 1

    # The event is still stored and still classified; only the queue hides it.
    with get_connection(db) as connection:
        kept = connection.execute(
            "SELECT is_alert, rule_id FROM live_events WHERE rule_id = ?",
            ("sysmon-encoded-powershell-command",),
        ).fetchone()
    assert kept["is_alert"] == 1

    assert client.delete(f"/api/suppressions/{identifier}").status_code == 200
    assert client.get("/api/detections").get_json()["total"] == 1


# ----------------------------------------------------------------------------- roles

def test_a_viewer_may_read_the_queue_but_not_triage_it(tmp_path):
    db, app = build(tmp_path)
    host = enrol(db)
    ship(app.test_client(), host["key"], [ENCODED_POWERSHELL])
    add_user(db, username="watcher", password="CorrectHorse9!", role="viewer")
    client = app.test_client()
    client.post("/login", data={"username": "watcher", "password": "CorrectHorse9!"})

    assert client.get("/api/detections").status_code == 200
    assert client.get("/api/audit").status_code == 403
    assert client.get("/api/suppressions").status_code == 200
    assert client.post(
        "/api/suppressions", json={"rule_id": "x", "scope": "global"}
    ).status_code == 403
    identifier = detection_id(client)
    assert client.post(
        f"/api/detections/{identifier}/status", json={"status": "closed"}
    ).status_code == 403


def test_an_admin_may_read_the_audit_log(tmp_path):
    db, app = build(tmp_path)
    add_user(db, username="root", password="CorrectHorse9!", role="admin")
    client = app.test_client()
    client.post("/login", data={"username": "root", "password": "CorrectHorse9!"})
    body = client.get("/api/audit").get_json()
    assert body["total"] >= 1
    actions = {entry["action"] for entry in body["entries"]}
    assert "user_create" in actions


def test_only_an_admin_may_enrol_a_host(tmp_path):
    db, app = build(tmp_path)
    add_user(db)
    client = app.test_client()
    sign_in(client)
    assert client.post("/api/hosts", json={"name": "new-box"}).status_code == 403

    add_user(db, username="root", password="CorrectHorse9!", role="admin")
    admin = app.test_client()
    admin.post("/login", data={"username": "root", "password": "CorrectHorse9!"})
    created = admin.post("/api/hosts", json={"name": "new-box", "platform": "linux"})
    assert created.status_code == 201, created.data
    assert created.get_json()["key"].startswith("hk_")


def test_ingesting_an_unusable_event_reports_it_rather_than_storing_it(tmp_path):
    db, app = build(tmp_path)
    host = enrol(db)
    client = app.test_client()
    response = ship(client, host["key"], [ENCODED_POWERSHELL, {"no_message": True}, "not-an-object"])
    assert response.status_code == 202
    body = response.get_json()
    assert body["accepted"] == 1
    assert body["rejected"] == 2
    assert len(body["errors"]) == 2
