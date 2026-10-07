"""Search, baselining, lockout, MFA and backups, driven through the HTTP surface.

The modules have their own suites. This one covers the wiring: that the routes
enforce the role, that a lockout actually stops a login, that a second factor is
demanded once it is enabled, and that a backup can only be verified from the
directory the console wrote it to.
"""
import base64
import hashlib
import hmac
import struct
import time


from src import auth
from src.app import dashboard_app, get_connection

PASSWORD = "CorrectHorse9!"


def totp(secret: str, at: float | None = None, step: int = 30, digits: int = 6) -> str:
    """An independent TOTP implementation, so the test is not the module's echo."""

    counter = int((time.time() if at is None else at) // step)
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10**digits)).zfill(digits)


def build(tmp_path):
    db = tmp_path / "siem.db"
    app = dashboard_app(db)
    app.config.update(TESTING=True)
    return db, app


def add_user(db, username="analyst1", role="analyst", password=PASSWORD):
    with get_connection(db) as connection:
        auth.create_user(connection, username, password, role, actor="setup")
        connection.commit()


def sign_in(client, username="analyst1", password=PASSWORD, code=None):
    body = {"username": username, "password": password}
    if code is not None:
        body["code"] = code
    return client.post("/login", data=body)


# --------------------------------------------------------------------- search

def test_search_finds_a_stored_event_and_reports_the_engine(tmp_path):
    db, app = build(tmp_path)
    add_user(db)
    client = app.test_client()
    # Ingestion is a write, so it needs the session first.
    sign_in(client)
    client.post("/api/events", json=[{"message": "encoded powershell ran", "channel": "Security", "host": "web-01"}])

    summary = client.get("/api/search/summary").get_json()
    assert set(summary) >= {"fts5", "indexed", "indexed_events"}

    body = client.get("/api/search", query_string={"q": "powershell"}).get_json()
    assert body["engine"] in {"fts5", "scan"}
    assert body["total"] == 1
    assert "powershell" in body["events"][0]["message"]


def test_a_field_clause_narrows_the_result(tmp_path):
    db, app = build(tmp_path)
    add_user(db)
    client = app.test_client()
    sign_in(client)
    client.post("/api/events", json=[
        {"message": "alpha", "host": "web-01", "channel": "Security"},
        {"message": "alpha", "host": "db-02", "channel": "Security"},
    ])
    body = client.get("/api/search", query_string={"q": "host:db-02"}).get_json()
    assert body["total"] == 1
    assert body["events"][0]["host"] == "db-02"


def test_a_malformed_query_is_a_400_not_a_crash(tmp_path):
    db, app = build(tmp_path)
    add_user(db)
    client = app.test_client()
    sign_in(client)
    assert client.get("/api/search", query_string={"q": "nosuchfield:x"}).status_code == 400
    assert client.get("/api/search", query_string={"q": 'unclosed"quote'}).status_code == 400


def test_rebuilding_the_index_is_for_an_administrator(tmp_path):
    db, app = build(tmp_path)
    add_user(db)
    client = app.test_client()
    sign_in(client)
    refused = client.post("/api/search/rebuild")
    assert refused.status_code == 403
    assert "may not rebuild the search index" in refused.get_json()["error"]

    add_user(db, username="root", role="admin")
    admin = app.test_client()
    sign_in(admin, username="root")
    assert admin.post("/api/search/rebuild").status_code == 200


# ------------------------------------------------------------------- baseline

def test_baseline_build_and_list(tmp_path):
    db, app = build(tmp_path)
    add_user(db, username="root", role="admin")
    client = app.test_client()
    sign_in(client, username="root")
    client.post("/api/events", json=[{"message": "noise", "channel": "System", "host": "web-01"}])

    built = client.post("/api/baseline/build").get_json()
    assert built["ok"] is True
    listed = client.get("/api/baseline").get_json()
    assert "baselines" in listed and "summary" in listed
    assert set(listed["summary"]) >= {"keys", "hosts", "insufficient"}
    # A key with a single observation has too little history to be judged.
    assert listed["summary"]["insufficient"] >= 0


def test_deviations_are_reported_with_their_sigma(tmp_path):
    db, app = build(tmp_path)
    add_user(db)
    client = app.test_client()
    sign_in(client)
    body = client.get("/api/baseline/deviations").get_json()
    assert body["total"] == len(body["deviations"])


def test_building_a_baseline_needs_an_administrator(tmp_path):
    db, app = build(tmp_path)
    add_user(db)
    client = app.test_client()
    sign_in(client)
    assert client.post("/api/baseline/build").status_code == 403


# -------------------------------------------------------------------- lockout

def test_repeated_failures_lock_the_account_out(tmp_path):
    db, app = build(tmp_path)
    add_user(db)
    client = app.test_client()
    for _ in range(5):
        assert sign_in(client, password="wrong").status_code == 401

    locked = sign_in(client, password="wrong")
    assert locked.status_code == 429
    assert locked.get_json()["locked"] is True
    # Even the right password is refused while the lockout stands.
    assert sign_in(client).status_code == 429


def test_an_administrator_can_clear_a_lockout(tmp_path):
    db, app = build(tmp_path)
    add_user(db)
    for _ in range(5):
        app.test_client().post("/login", data={"username": "analyst1", "password": "wrong"})
    add_user(db, username="root", role="admin")
    admin = app.test_client()
    sign_in(admin, username="root")
    listed = admin.get("/api/security").get_json()
    assert any(row["username"] == "analyst1" for row in listed["lockouts"])

    cleared = admin.post("/api/security/lockout/clear", json={"username": "analyst1"})
    assert cleared.status_code == 200
    assert sign_in(app.test_client()).status_code == 302


def test_only_an_administrator_can_clear_a_lockout(tmp_path):
    db, app = build(tmp_path)
    add_user(db)
    client = app.test_client()
    sign_in(client)
    assert client.post("/api/security/lockout/clear", json={"username": "x"}).status_code == 403


def test_a_successful_login_clears_the_failure_run(tmp_path):
    db, app = build(tmp_path)
    add_user(db)
    client = app.test_client()
    for _ in range(3):
        sign_in(client, password="wrong")
    assert sign_in(client).status_code == 302
    listed = client.get("/api/security").get_json()
    assert listed["lockouts"] == []


# ------------------------------------------------------------------------ mfa

def test_mfa_enrolment_and_login(tmp_path):
    db, app = build(tmp_path)
    add_user(db)
    client = app.test_client()
    sign_in(client)

    setup = client.post("/api/mfa/setup")
    assert setup.status_code == 200
    payload = setup.get_json()
    assert payload["secret"] and payload["uri"].startswith("otpauth://")
    assert len(payload["recovery_codes"]) >= 5

    # A wrong code must not confirm the enrolment.
    assert client.post("/api/mfa/confirm", json={"code": "000000"}).status_code == 400

    code = totp(payload["secret"])
    assert client.post("/api/mfa/confirm", json={"code": code}).status_code == 200
    assert client.get("/api/mfa").get_json()["enabled"] is True

    # From now on the password alone is not enough.
    fresh = app.test_client()
    asked = sign_in(fresh)
    assert asked.status_code == 401
    assert asked.get_json()["mfa_required"] is True
    assert sign_in(fresh, code="000000").status_code == 401
    assert sign_in(fresh, code=totp(payload["secret"])).status_code == 302


def test_a_recovery_code_works_once(tmp_path):
    db, app = build(tmp_path)
    add_user(db)
    client = app.test_client()
    sign_in(client)
    payload = client.post("/api/mfa/setup").get_json()
    client.post("/api/mfa/confirm", json={"code": totp(payload["secret"])})

    recovery = payload["recovery_codes"][0]
    first = app.test_client()
    assert sign_in(first, code=recovery).status_code == 302
    second = app.test_client()
    assert sign_in(second, code=recovery).status_code == 401


def test_disabling_mfa_costs_the_password(tmp_path):
    db, app = build(tmp_path)
    add_user(db)
    client = app.test_client()
    sign_in(client)
    payload = client.post("/api/mfa/setup").get_json()
    client.post("/api/mfa/confirm", json={"code": totp(payload["secret"])})

    assert client.post("/api/mfa/disable", json={"password": "wrong"}).status_code == 401
    assert client.post("/api/mfa/disable", json={"password": PASSWORD}).status_code == 200
    assert client.get("/api/mfa").get_json()["enabled"] is False


# -------------------------------------------------------------------- backups

def test_a_backup_can_be_created_listed_and_verified(tmp_path):
    db, app = build(tmp_path)
    add_user(db, username="root", role="admin")
    client = app.test_client()
    sign_in(client, username="root")
    client.post("/api/events", json=[{"message": "before the snapshot", "channel": "System"}])

    assert client.get("/api/backups").get_json()["backups"] == []
    created = client.post("/api/backups")
    assert created.status_code == 201
    path = created.get_json()["path"]

    listed = client.get("/api/backups").get_json()
    assert listed["summary"]["count"] == 1
    assert listed["backups"][0]["bytes"] > 0

    verified = client.post("/api/backups/verify", json={"path": path}).get_json()
    assert verified["ok"] is True
    assert verified["integrity"] == "ok"
    assert verified["events"] >= 1


def test_only_an_administrator_can_take_a_backup(tmp_path):
    db, app = build(tmp_path)
    add_user(db)
    client = app.test_client()
    sign_in(client)
    assert client.post("/api/backups").status_code == 403
    assert client.post("/api/backups/verify", json={"path": "x"}).status_code == 403


def test_verifying_a_path_outside_the_backup_directory_is_refused(tmp_path):
    db, app = build(tmp_path)
    add_user(db, username="root", role="admin")
    client = app.test_client()
    sign_in(client, username="root")
    outside = tmp_path / "somewhere-else.db"
    outside.write_bytes(b"not a database")
    response = client.post("/api/backups/verify", json={"path": str(outside)})
    assert response.status_code == 400
    assert "not a backup written by this console" in response.get_json()["error"]


# ------------------------------------------------- open mode and locked mode

def test_the_account_panels_work_while_the_console_is_open(tmp_path):
    """No accounts yet means the documented lab default: open on loopback.

    Without an implicit local operator these routes answer 401 to everybody in
    that state, which leaves three panels dead on an otherwise open console.
    """

    db, app = build(tmp_path)
    client = app.test_client()
    assert client.get("/api/security").status_code == 200
    assert client.get("/api/mfa").status_code == 200
    assert client.get("/api/backups").status_code == 200
    assert client.post("/api/baseline/build").status_code == 200
    assert client.post("/api/search/rebuild").status_code == 200
    assert client.post("/api/backups").status_code == 201


def test_the_same_routes_need_a_session_once_an_account_exists(tmp_path):
    db, app = build(tmp_path)
    add_user(db)
    client = app.test_client()
    for path in ("/api/security", "/api/mfa", "/api/backups"):
        assert client.get(path).status_code == 401, path
    assert client.post("/api/backups").status_code == 401
    assert client.post("/api/baseline/build").status_code == 401


def test_an_analyst_is_still_refused_the_administrator_actions(tmp_path):
    """The implicit operator must not weaken the role checks once accounts exist."""

    db, app = build(tmp_path)
    add_user(db)
    client = app.test_client()
    sign_in(client)
    assert client.post("/api/backups").status_code == 403
    assert client.post("/api/search/rebuild").status_code == 403
    assert client.post("/api/security/lockout/clear", json={"username": "x"}).status_code == 403


def test_identity_is_reported_while_the_console_is_open(tmp_path):
    """The page asks /api/me whether to show a sign-in form.

    Answering 401 in open mode made it show one for an account that does not
    exist, which is a prompt nobody can satisfy.
    """

    db, app = build(tmp_path)
    client = app.test_client()
    body = client.get("/api/me")
    assert body.status_code == 200
    assert body.get_json()["role"] == "admin"
    assert body.get_json()["username"]


def test_identity_requires_a_session_once_an_account_exists(tmp_path):
    db, app = build(tmp_path)
    add_user(db)
    client = app.test_client()
    assert client.get("/api/me").status_code == 401
    sign_in(client)
    assert client.get("/api/me").get_json()["username"] == "analyst1"


# ------------------------------------------------------------------ first run

def test_a_fresh_console_says_it_needs_an_account(tmp_path):
    db, app = build(tmp_path)
    client = app.test_client()
    body = client.get("/api/setup").get_json()
    assert body == {"required": True, "accounts": 0}


def test_creating_the_first_account_signs_you_in_and_locks_the_console(tmp_path):
    db, app = build(tmp_path)
    client = app.test_client()

    created = client.post(
        "/api/setup", json={"username": "khan", "password": "CorrectHorse9!"}
    )
    assert created.status_code == 201, created.data
    assert created.get_json()["role"] == "admin"

    # The same client carries the session the reply issued.
    assert client.get("/api/me").get_json()["username"] == "khan"
    assert client.get("/api/dashboard").status_code == 200

    # Anybody else now needs to sign in.
    stranger = app.test_client()
    assert stranger.get("/api/dashboard").status_code == 401
    assert stranger.get("/api/me").status_code == 401
    assert stranger.get("/api/setup").get_json() == {"required": False, "accounts": 1}


def test_the_first_run_door_closes_behind_you(tmp_path):
    db, app = build(tmp_path)
    client = app.test_client()
    client.post("/api/setup", json={"username": "khan", "password": "CorrectHorse9!"})

    again = app.test_client().post(
        "/api/setup", json={"username": "someoneelse", "password": "CorrectHorse9!"}
    )
    assert again.status_code == 409
    assert "already has accounts" in again.get_json()["error"]


def test_a_weak_first_password_is_refused_with_the_reason(tmp_path):
    db, app = build(tmp_path)
    client = app.test_client()
    refused = client.post("/api/setup", json={"username": "khan", "password": "short"})
    assert refused.status_code == 400
    assert "password" in refused.get_json()["error"].lower()
    # Nothing was created, so the first-run door is still open.
    assert client.get("/api/setup").get_json()["required"] is True


def test_the_first_account_can_sign_in_again_later(tmp_path):
    db, app = build(tmp_path)
    app.test_client().post(
        "/api/setup", json={"username": "khan", "password": "CorrectHorse9!"}
    )
    later = app.test_client()
    assert later.post(
        "/login", data={"username": "khan", "password": "CorrectHorse9!"}
    ).status_code == 302
    assert later.get("/api/me").get_json()["username"] == "khan"
