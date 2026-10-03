"""The search query language, the FTS5 index and the honest fallback path.

Every test drives the public functions against a real SQLite store created by
``app.get_connection``, so the module is exercised against the same schema the
running console uses. The FTS5 path and the ``scan`` fallback are both covered:
the fallback is reached here by replacing ``search.fts5_supported`` with a
function that returns ``False``, which is how the module itself decides whether
an FTS5 build is available.
"""

import sqlite3

import pytest

from src import search
from src.app import get_connection
from src.search import (
    FTS_TABLE,
    FREE_TEXT_COLUMNS,
    SUPPORTED_FIELDS,
    ensure_schema,
    fts5_supported,
    parse_query,
    rebuild_index,
    search_events,
    search_summary,
)

# A value carrying an SQL string quote and a statement separator. Fed through a
# field it must be treated as data, never as SQL.
MALICIOUS = "x'; DROP TABLE live_events;--"


def make_conn(tmp_path):
    conn = get_connection(tmp_path / "live.db")
    ensure_schema(conn)
    return conn


def make_conn_without_fts(tmp_path, monkeypatch):
    """A store built as if this SQLite build had no FTS5."""
    monkeypatch.setattr(search, "fts5_supported", lambda conn: False)
    conn = get_connection(tmp_path / "live.db")
    ensure_schema(conn)
    return conn


def add_event(
    conn,
    message="Failed login for admin from 10.0.0.5",
    host="LAB-A",
    username="admin",
    channel="Security",
    provider="MS-Windows",
    severity="High",
    source_ip="10.0.0.5",
    rule_name="Brute Force",
    rule_id="r-1",
    host_id="1",
    timestamp="2026-10-01 12:00:00",
    is_alert=1,
):
    """Insert one stored event and return its row id."""

    cursor = conn.execute(
        "INSERT INTO live_events(timestamp,channel,provider,event_id,level,severity,username,host,"
        "source_ip,message,record_id,source,is_alert,rule_name,raw_log,external_id,rule_id,"
        "techniques,matched_on,enrichment,host_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            timestamp, channel, provider, "4625", "Information", severity, username, host,
            source_ip, message, "", "test", is_alert, rule_name, "", "", rule_id, "", "", "", host_id,
        ),
    )
    conn.commit()
    return cursor.lastrowid


def count(conn, sql="SELECT COUNT(*) FROM live_events"):
    return int(conn.execute(sql).fetchone()[0])


def drop_index(conn):
    """Remove the FTS table and its triggers, as a store that never had them."""

    for trigger in ("search_events_ai", "search_events_ad", "search_events_au"):
        conn.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    conn.execute(f"DROP TABLE IF EXISTS {FTS_TABLE}")
    conn.commit()


# --------------------------------------------------------------------------- #
# parse_query: the happy path
# --------------------------------------------------------------------------- #

def test_parse_free_text_terms():
    parsed = parse_query("failed login")
    assert parsed["raw"] == "failed login"
    assert [term["value"] for term in parsed["terms"]] == ["failed", "login"]
    assert all(term["negated"] is False for term in parsed["terms"])
    assert parsed["clauses"] == []


def test_parse_every_field_clause():
    parsed = parse_query(
        "host:LAB-A host_id:1 severity:High channel:Security rule:Brute "
        "user:admin source_ip:10.0.0.5 message:hello after:2026-10-01 before:2026-10-02"
    )
    fields = [clause["field"] for clause in parsed["clauses"]]
    assert fields == [
        "host", "host_id", "severity", "channel", "rule", "user",
        "source_ip", "message", "after", "before",
    ]
    assert parsed["terms"] == []


def test_parse_field_clause_kinds():
    parsed = parse_query("host:LAB-A after:2026-10-01")
    text_clause, date_clause = parsed["clauses"]
    assert text_clause["kind"] == "text"
    assert date_clause["kind"] == "date"
    assert date_clause["raw_value"] == "2026-10-01"
    assert date_clause["value"] == "2026-10-01 00:00:00"


def test_parse_negation_on_clause_and_term():
    parsed = parse_query("-host:LAB-A -failed")
    assert parsed["clauses"][0]["negated"] is True
    assert parsed["clauses"][0]["field"] == "host"
    assert parsed["terms"][0] == {"value": "failed", "negated": True}


def test_parse_quoted_value_with_spaces():
    parsed = parse_query('host:"LAB A"')
    assert parsed["clauses"][0]["value"] == "LAB A"


def test_parse_quoted_free_text_with_colon():
    parsed = parse_query('"http://example"')
    assert parsed["terms"][0]["value"] == "http://example"


def test_parse_escaped_quote_inside_quoted_value():
    parsed = parse_query('message:"say \\"hi\\""')
    assert parsed["clauses"][0]["value"] == 'say "hi"'


def test_parse_keeps_wildcards():
    parsed = parse_query("host:LAB* message:*failed*")
    assert parsed["clauses"][0]["value"] == "LAB*"
    assert parsed["clauses"][1]["value"] == "*failed*"


def test_parse_field_names_are_case_insensitive():
    parsed = parse_query("HOST:LAB-A Severity:High")
    assert [clause["field"] for clause in parsed["clauses"]] == ["host", "severity"]


def test_parse_empty_and_whitespace_only_queries():
    assert parse_query("") == {"raw": "", "terms": [], "clauses": []}
    assert parse_query("   \t ") == {"raw": "   \t ", "terms": [], "clauses": []}


def test_parse_multiple_tokens_with_mixed_spacing():
    parsed = parse_query("  admin   host:LAB-A   -failed ")
    assert [term["value"] for term in parsed["terms"]] == ["admin", "failed"]
    assert parsed["terms"][0]["negated"] is False
    assert parsed["terms"][1]["negated"] is True
    assert [clause["value"] for clause in parsed["clauses"]] == ["LAB-A"]


def test_parse_date_with_time_and_offset_normalised_to_utc():
    assert parse_query('after:"2026-10-01 12:30:00"')["clauses"][0]["value"] == "2026-10-01 12:30:00"
    assert parse_query("after:2026-10-01T12:30:00Z")["clauses"][0]["value"] == "2026-10-01 12:30:00"
    assert parse_query("after:2026-10-01T12:30:00+05:30")["clauses"][0]["value"] == "2026-10-01 07:00:00"


def test_unquoted_date_value_with_a_space_splits_into_a_term():
    # Documented behaviour: a value with a space must be quoted, otherwise the
    # time is read as a separate free-text term.
    parsed = parse_query("after:2026-10-01 12:00")
    assert parsed["clauses"][0]["value"] == "2026-10-01 00:00:00"
    assert [term["value"] for term in parsed["terms"]] == ["12:00"]


def test_parse_quoted_date_with_space():
    parsed = parse_query('after:"2026-10-01 12:30:00"')
    assert parsed["clauses"][0]["value"] == "2026-10-01 12:30:00"


def test_parse_supported_fields_constant_matches_grammar():
    assert set(SUPPORTED_FIELDS) == {
        "host", "host_id", "severity", "channel", "rule", "user",
        "source_ip", "message", "after", "before",
    }


# --------------------------------------------------------------------------- #
# parse_query: the error paths
# --------------------------------------------------------------------------- #

def test_parse_unknown_field_names_the_token():
    with pytest.raises(ValueError) as excinfo:
        parse_query("bogus:value")
    message = str(excinfo.value)
    assert "bogus" in message
    assert "bogus:value" in message


def test_parse_unknown_field_rejects_a_url_shaped_term():
    # A leading ``name:`` is always read as a field clause, so a bare URL is an
    # unknown field and must be quoted to be searched literally.
    with pytest.raises(ValueError) as excinfo:
        parse_query("http://example")
    assert "http" in str(excinfo.value)
    assert parse_query('"http://example"')["terms"][0]["value"] == "http://example"


def test_parse_unclosed_quote_names_the_token():
    with pytest.raises(ValueError) as excinfo:
        parse_query('host:"LAB-A')
    assert "Unclosed quote" in str(excinfo.value)
    assert "LAB-A" in str(excinfo.value)


def test_parse_unclosed_quote_in_free_text():
    with pytest.raises(ValueError) as excinfo:
        parse_query('"failed')
    assert "Unclosed quote" in str(excinfo.value)


def test_parse_bad_date_names_the_token():
    with pytest.raises(ValueError) as excinfo:
        parse_query("after:notadate")
    assert "after:notadate" in str(excinfo.value)
    assert "Invalid date" in str(excinfo.value)


def test_parse_impossible_date_is_rejected():
    with pytest.raises(ValueError):
        parse_query("before:2026-13-40")


def test_parse_wildcard_in_date_is_rejected():
    with pytest.raises(ValueError) as excinfo:
        parse_query("after:2026-*")
    assert "cannot contain" in str(excinfo.value)


def test_parse_missing_value_names_the_token():
    with pytest.raises(ValueError) as excinfo:
        parse_query("host:")
    assert "host:" in str(excinfo.value)
    assert "Missing value" in str(excinfo.value)


def test_parse_missing_value_for_date_field():
    with pytest.raises(ValueError):
        parse_query("after:")


def test_parse_bare_minus_is_rejected():
    with pytest.raises(ValueError) as excinfo:
        parse_query("-")
    assert "bare '-'" in str(excinfo.value)


def test_parse_bare_minus_before_space_is_rejected():
    with pytest.raises(ValueError):
        parse_query("- host:LAB-A")


def test_parse_non_string_query_is_rejected():
    with pytest.raises(ValueError):
        parse_query(None)
    with pytest.raises(ValueError):
        parse_query(123)


def test_parse_leading_colon_is_a_free_text_term():
    assert parse_query(":foo")["terms"][0]["value"] == ":foo"


# --------------------------------------------------------------------------- #
# search_events: the free-text part
# --------------------------------------------------------------------------- #

def six_column_events(conn):
    """One event per searchable column, each carrying a unique token."""

    for column, word in (
        ("message", "alpha"),
        ("rule_name", "bravo"),
        ("channel", "charlie"),
        ("provider", "delta"),
        ("username", "echo"),
        ("host", "foxtrot"),
    ):
        values = {
            "message": "zulu",
            "rule_name": "zulu",
            "channel": "zulu",
            "provider": "zulu",
            "username": "zulu",
            "host": "zulu",
        }
        values[column] = word
        add_event(conn, **values)


@pytest.mark.parametrize("word", ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"])
def test_free_text_searches_every_column_on_the_fts5_engine(tmp_path, word):
    conn = make_conn(tmp_path)
    six_column_events(conn)
    result = search_events(conn, word)
    assert result["engine"] == "fts5"
    assert result["total"] == 1


@pytest.mark.parametrize("word", ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"])
def test_free_text_searches_every_column_on_the_scan_engine(tmp_path, monkeypatch, word):
    conn = make_conn_without_fts(tmp_path, monkeypatch)
    six_column_events(conn)
    result = search_events(conn, word)
    assert result["engine"] == "scan"
    assert result["total"] == 1


def test_free_text_requires_every_positive_term(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn, message="failed login for admin")
    add_event(conn, message="failed service start", host="LAB-B")
    assert search_events(conn, "failed login")["total"] == 1


def test_free_text_substring_on_the_scan_engine(tmp_path, monkeypatch):
    conn = make_conn_without_fts(tmp_path, monkeypatch)
    add_event(conn, message="Failed login for admin")
    assert search_events(conn, "failed")["total"] == 1
    assert search_events(conn, "logi")["total"] == 1


def test_free_text_prefix_wildcard_on_the_fts5_engine(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn, message="admin logged in")
    add_event(conn, message="bob logged in", host="LAB-B", username="bob")
    result = search_events(conn, "adm*")
    assert result["engine"] == "fts5"
    assert result["total"] == 1


def test_free_text_internal_wildcard_forces_the_scan_engine(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn, message="admin logged in")
    result = search_events(conn, "ad*in")
    assert result["engine"] == "scan"
    assert result["total"] == 1


def test_free_text_quoted_phrase(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn, message="failed login for admin")
    add_event(conn, message="login failed later", host="LAB-B")
    assert search_events(conn, '"failed login"')["total"] == 1


def test_negated_free_text_excludes_matches(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn, message="admin logged in")
    add_event(conn, message="bob logged in", host="LAB-B", username="bob")
    result = search_events(conn, "-admin")
    assert result["engine"] == "fts5"
    assert result["total"] == 1
    assert result["events"][0]["host"] == "LAB-B"


# --------------------------------------------------------------------------- #
# search_events: the field clauses
# --------------------------------------------------------------------------- #

def test_field_clause_host_matches_exactly(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn, host="LAB-A")
    add_event(conn, host="LAB-B")
    assert search_events(conn, "host:LAB-A")["total"] == 1


def test_field_clause_host_wildcard(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn, host="LAB-A")
    add_event(conn, host="LAB-B")
    add_event(conn, host="SRV-1")
    assert search_events(conn, "host:LAB*")["total"] == 2


def test_field_clause_host_id(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn, host_id="7")
    add_event(conn, host_id="8")
    assert search_events(conn, "host_id:7")["total"] == 1


def test_field_clause_severity_is_case_insensitive(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn, severity="High")
    add_event(conn, severity="Low")
    assert search_events(conn, "severity:high")["total"] == 1
    assert search_events(conn, "severity:Low")["total"] == 1


def test_field_clause_channel(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn, channel="Security")
    add_event(conn, channel="Sysmon")
    assert search_events(conn, "channel:Sysmon")["total"] == 1


def test_field_clause_rule_matches_name_or_id(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn, rule_name="Brute Force", rule_id="r-1")
    add_event(conn, rule_name="Other", rule_id="r-2")
    assert search_events(conn, 'rule:"Brute Force"')["total"] == 1
    assert search_events(conn, "rule:*Force*")["total"] == 1
    assert search_events(conn, "rule:r-2")["total"] == 1


def test_field_clause_user(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn, username="admin")
    add_event(conn, username="bob")
    assert search_events(conn, "user:bob")["total"] == 1


def test_field_clause_source_ip(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn, source_ip="10.0.0.5")
    add_event(conn, source_ip="192.168.1.9")
    assert search_events(conn, "source_ip:10.0.0.5")["total"] == 1


def test_field_clause_message(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn, message="failed login")
    add_event(conn, message="successful logon")
    assert search_events(conn, "message:*logon*")["total"] == 1
    assert search_events(conn, "message:failed login")["total"] == 0  # value must be quoted for spaces


def test_field_clause_quoted_message_with_spaces(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn, message="failed login")
    assert search_events(conn, 'message:"failed login"')["total"] == 1


def test_negated_field_clause(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn, host="LAB-A")
    add_event(conn, host="LAB-B")
    result = search_events(conn, "-host:LAB-A")
    assert result["total"] == 1
    assert result["events"][0]["host"] == "LAB-B"


def test_combined_free_text_and_field_clause(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn, message="admin logged in", host="LAB-A")
    add_event(conn, message="admin logged in", host="LAB-B")
    result = search_events(conn, "admin host:LAB-A")
    assert result["engine"] == "fts5"
    assert result["total"] == 1


# --------------------------------------------------------------------------- #
# search_events: dates
# --------------------------------------------------------------------------- #

def test_after_is_inclusive(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn, timestamp="2026-10-01 00:00:00")
    add_event(conn, timestamp="2026-09-30 23:59:59", host="LAB-B")
    assert search_events(conn, "after:2026-10-01")["total"] == 1


def test_before_is_exclusive(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn, timestamp="2026-10-02 00:00:00")
    add_event(conn, timestamp="2026-10-01 23:59:59", host="LAB-B")
    result = search_events(conn, "before:2026-10-02")
    assert result["total"] == 1
    assert result["events"][0]["host"] == "LAB-B"


def test_date_range_and_negation(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn, timestamp="2026-10-01 10:00:00")
    add_event(conn, timestamp="2026-10-02 10:00:00", host="LAB-B")
    add_event(conn, timestamp="2026-10-03 10:00:00", host="LAB-C")
    assert search_events(conn, "after:2026-10-02 before:2026-10-03")["total"] == 1
    assert search_events(conn, "-after:2026-10-02")["total"] == 1


def test_date_with_time_and_offset(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn, timestamp="2026-10-01 08:00:00")
    add_event(conn, timestamp="2026-10-01 06:00:00", host="LAB-B")
    # 12:00+05:30 is 06:30 UTC, so the 08:00 event is after it and the 06:00 one is not.
    assert search_events(conn, "after:2026-10-01T12:00:00+05:30")["total"] == 1


# --------------------------------------------------------------------------- #
# search_events: result shape, ordering and paging
# --------------------------------------------------------------------------- #

def test_result_shape_and_parsed(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn)
    result = search_events(conn, "host:LAB-A")
    assert set(result) == {"events", "total", "parsed", "engine"}
    assert result["parsed"]["clauses"][0]["field"] == "host"
    assert result["events"][0]["host"] == "LAB-A"


def test_events_are_newest_first(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn, host="LAB-A", timestamp="2026-10-01 10:00:00")
    add_event(conn, host="LAB-B", timestamp="2026-10-03 10:00:00")
    add_event(conn, host="LAB-C", timestamp="2026-10-02 10:00:00")
    hosts = [event["host"] for event in search_events(conn, "")["events"]]
    assert hosts == ["LAB-B", "LAB-C", "LAB-A"]


def test_total_counts_all_matches_while_paging(tmp_path):
    conn = make_conn(tmp_path)
    for index in range(5):
        add_event(conn, host=f"LAB-{index}", message="shared token")
    result = search_events(conn, "shared", limit=2, offset=0)
    assert result["total"] == 5
    assert len(result["events"]) == 2
    page = search_events(conn, "shared", limit=2, offset=4)
    assert page["total"] == 5
    assert len(page["events"]) == 1
    empty = search_events(conn, "shared", limit=2, offset=99)
    assert empty["total"] == 5
    assert empty["events"] == []


def test_empty_query_matches_everything(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn)
    add_event(conn, host="LAB-B")
    result = search_events(conn, "")
    assert result["engine"] == "scan"
    assert result["total"] == 2


def test_limit_and_offset_validation(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn)
    with pytest.raises(ValueError):
        search_events(conn, "", limit=0)
    with pytest.raises(ValueError):
        search_events(conn, "", limit=-1)
    with pytest.raises(ValueError):
        search_events(conn, "", offset=-1)
    with pytest.raises(ValueError):
        search_events(conn, "", limit="many")
    with pytest.raises(ValueError):
        search_events(conn, "", limit=True)


def test_search_raises_on_a_bad_query(tmp_path):
    conn = make_conn(tmp_path)
    with pytest.raises(ValueError):
        search_events(conn, "bogus:value")


# --------------------------------------------------------------------------- #
# LIKE metacharacters are treated as data
# --------------------------------------------------------------------------- #

def test_percent_and_underscore_in_values_are_literal(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn, message="disk 100% full")
    add_event(conn, message="user a_b logged in", host="LAB-B")
    add_event(conn, message="user aXb logged in", host="LAB-C")
    assert search_events(conn, "message:*100%*")["total"] == 1
    # ``_`` is literal, not a single-character wildcard: it matches a_b, not aXb.
    assert search_events(conn, "message:*a_b*")["total"] == 1
    assert search_events(conn, "message:*aXb*")["total"] == 1


# --------------------------------------------------------------------------- #
# The engine that runs, and the difference between the two
# --------------------------------------------------------------------------- #

def test_engine_is_scan_when_there_is_no_free_text(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn)
    assert search_events(conn, "host:LAB-A")["engine"] == "scan"


def test_engine_is_scan_when_fts5_is_unavailable(tmp_path, monkeypatch):
    conn = make_conn_without_fts(tmp_path, monkeypatch)
    add_event(conn)
    result = search_events(conn, "admin")
    assert result["engine"] == "scan"
    assert result["total"] == 1


def test_engine_is_scan_when_the_index_is_missing(tmp_path):
    conn = make_conn(tmp_path)
    drop_index(conn)
    add_event(conn)
    result = search_events(conn, "admin")
    assert result["engine"] == "scan"
    assert result["total"] == 1


def test_engines_differ_on_a_substring_and_that_is_reported(tmp_path, monkeypatch):
    # The scan engine matches substrings; FTS5 matches whole tokens. The two
    # answers genuinely differ, and ``engine`` says which one ran.
    conn_fts = make_conn(tmp_path)
    add_event(conn_fts, message="admin logged in")
    fts_result = search_events(conn_fts, "dmin")
    assert fts_result["engine"] == "fts5"
    assert fts_result["total"] == 0

    other = tmp_path / "scan"
    other.mkdir()
    conn_scan = make_conn_without_fts(other, monkeypatch)
    add_event(conn_scan, message="admin logged in")
    scan_result = search_events(conn_scan, "dmin")
    assert scan_result["engine"] == "scan"
    assert scan_result["total"] == 1


def test_fts5_supported_is_true_on_this_build(tmp_path):
    conn = make_conn(tmp_path)
    assert fts5_supported(conn) is True


# --------------------------------------------------------------------------- #
# The FTS5 index: schema, triggers, rebuild, summary
# --------------------------------------------------------------------------- #

def test_ensure_schema_creates_the_index_and_triggers(tmp_path):
    conn = make_conn(tmp_path)
    tables = {
        str(row[0])
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    triggers = {
        str(row[0])
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")
    }
    assert FTS_TABLE in tables
    assert {"search_events_ai", "search_events_ad", "search_events_au"} <= triggers


def test_ensure_schema_is_idempotent(tmp_path):
    conn = make_conn(tmp_path)
    ensure_schema(conn)
    ensure_schema(conn)
    assert count(conn, f"SELECT COUNT(*) FROM {FTS_TABLE}") == 0


def test_ensure_schema_creates_no_index_without_fts5(tmp_path, monkeypatch):
    conn = make_conn_without_fts(tmp_path, monkeypatch)
    tables = {
        str(row[0])
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    assert FTS_TABLE not in tables


def test_triggers_index_new_events(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn, message="a brand new event")
    assert count(conn, f"SELECT COUNT(*) FROM {FTS_TABLE}") == 1
    assert search_events(conn, "brand")["engine"] == "fts5"
    assert search_events(conn, "brand")["total"] == 1


def test_triggers_remove_deleted_events(tmp_path):
    conn = make_conn(tmp_path)
    row_id = add_event(conn, message="transient event")
    conn.execute("DELETE FROM live_events WHERE id = ?", (row_id,))
    conn.commit()
    assert count(conn, f"SELECT COUNT(*) FROM {FTS_TABLE}") == 0
    assert search_events(conn, "transient")["total"] == 0


def test_triggers_update_changed_events(tmp_path):
    conn = make_conn(tmp_path)
    row_id = add_event(conn, message="original wording")
    conn.execute("UPDATE live_events SET message = ? WHERE id = ?", ("replaced wording", row_id))
    conn.commit()
    assert search_events(conn, "original")["total"] == 0
    assert search_events(conn, "replaced")["total"] == 1


def test_rebuild_index_populates_and_reports(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn, message="one")
    add_event(conn, message="two", host="LAB-B")
    result = rebuild_index(conn)
    assert result == {
        "fts5_available": True,
        "index_exists": True,
        "rows_processed": 2,
        "indexed_events": 2,
    }
    assert count(conn, f"SELECT COUNT(*) FROM {FTS_TABLE}") == 2


def test_rebuild_index_recovers_a_store_built_before_the_index_existed(tmp_path):
    # Events inserted while the index did not exist are not indexed by the
    # triggers, so the index is behind until rebuild_index runs.
    conn = make_conn(tmp_path)
    drop_index(conn)
    add_event(conn, message="pre-existing event")
    ensure_schema(conn)
    assert search_summary(conn)["index_behind"] is True
    assert search_events(conn, "pre-existing")["engine"] == "scan"
    assert search_events(conn, "pre-existing")["total"] == 1

    rebuilt = rebuild_index(conn)
    assert rebuilt["rows_processed"] == 1
    assert search_summary(conn)["index_behind"] is False
    assert search_events(conn, "pre-existing")["engine"] == "fts5"
    assert search_events(conn, "pre-existing")["total"] == 1


def test_rebuild_index_without_fts5_reports_zero(tmp_path, monkeypatch):
    conn = make_conn_without_fts(tmp_path, monkeypatch)
    add_event(conn)
    assert rebuild_index(conn) == {
        "fts5_available": False,
        "index_exists": False,
        "rows_processed": 0,
        "indexed_events": 0,
    }


def test_search_summary_reports_state(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn)
    summary = search_summary(conn)
    assert summary["fts5_available"] is True
    assert summary["index_exists"] is True
    assert summary["indexed_events"] == 1
    assert summary["events_total"] == 1
    assert summary["index_behind"] is False


def test_search_summary_without_fts5(tmp_path, monkeypatch):
    conn = make_conn_without_fts(tmp_path, monkeypatch)
    add_event(conn)
    summary = search_summary(conn)
    assert summary["fts5_available"] is False
    assert summary["index_exists"] is False
    assert summary["indexed_events"] == 0
    assert summary["events_total"] == 1
    assert summary["index_behind"] is False


def test_search_summary_reports_a_behind_index(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn)
    add_event(conn, host="LAB-B")
    conn.execute(f"DELETE FROM {FTS_TABLE}")
    conn.commit()
    summary = search_summary(conn)
    assert summary["indexed_events"] == 0
    assert summary["events_total"] == 2
    assert summary["index_behind"] is True


def test_a_behind_index_falls_back_to_scan(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn, message="admin logged in")
    add_event(conn, message="admin logged out", host="LAB-B")
    conn.execute(f"DELETE FROM {FTS_TABLE}")
    conn.commit()
    result = search_events(conn, "admin")
    assert result["engine"] == "scan"
    assert result["total"] == 2
    rebuild_index(conn)
    assert search_events(conn, "admin")["engine"] == "fts5"
    assert search_events(conn, "admin")["total"] == 2


# --------------------------------------------------------------------------- #
# SQL injection is impossible because every clause is parameterised
# --------------------------------------------------------------------------- #

TEXT_FIELDS = ("host", "host_id", "severity", "channel", "rule", "user", "source_ip", "message")


@pytest.mark.parametrize("field", TEXT_FIELDS)
def test_injection_through_each_text_field_is_parameterised(tmp_path, field):
    conn = make_conn(tmp_path)
    add_event(conn)
    before = count(conn)

    # The value is quoted so the quote and the semicolon stay one token.
    result = search_events(conn, f'{field}:"{MALICIOUS}"')

    assert result["total"] == 0
    assert count(conn) == before
    assert conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'live_events'"
    ).fetchone() is not None


def test_injection_through_free_text_is_parameterised(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn)
    before = count(conn)
    result = search_events(conn, f'"{MALICIOUS}"')
    assert result["total"] == 0
    assert count(conn) == before
    assert conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'live_events'"
    ).fetchone() is not None


@pytest.mark.parametrize("field", ["after", "before"])
def test_injection_through_a_date_field_is_rejected_not_executed(tmp_path, field):
    conn = make_conn(tmp_path)
    add_event(conn)
    before = count(conn)

    # A date field cannot carry a string at all: the value is refused by the
    # date parser before any SQL is built, so it can never reach the database.
    with pytest.raises(ValueError):
        search_events(conn, f'{field}:"{MALICIOUS}"')

    assert count(conn) == before
    assert conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'live_events'"
    ).fetchone() is not None


def test_injection_is_never_a_sqlite_error(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn)
    for field in TEXT_FIELDS:
        try:
            search_events(conn, f'{field}:"{MALICIOUS}"')
        except sqlite3.Error as exc:  # pragma: no cover - only on a real failure
            pytest.fail(f"{field} produced a SQLite error: {exc!r}")


def test_fts_query_syntax_cannot_be_injected(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn, message="admin logged in")
    # A term that looks like FTS5 syntax is treated as literal text by the
    # quoting in _fts_term; it must not raise and must not match by accident.
    result = search_events(conn, 'admin" OR "bob')
    assert result["engine"] == "fts5"
    assert result["total"] == 0

    # An unquoted ``OR`` is three separate free-text terms, AND-ed, so it does
    # not behave as a boolean operator either.
    assert search_events(conn, "admin OR bob")["total"] == 0


def test_backslash_in_a_value_is_matched_literally(tmp_path):
    conn = make_conn(tmp_path)
    add_event(conn, message="path\\file opened")
    # A backslash in the value is escaped for LIKE (the escape character), so it
    # matches a literal backslash rather than breaking the pattern.
    assert search_events(conn, "message:*path\\file*")["total"] == 1
