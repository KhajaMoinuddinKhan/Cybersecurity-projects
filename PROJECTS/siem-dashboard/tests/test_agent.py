"""The forwarding agent: collection, shipping, and the durable spool.

Everything here runs without the internet. Shipping is exercised either through
an injected poster or against a throwaway HTTP server on 127.0.0.1, and the
event sources are injected or written to a temporary file.
"""
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from src import agent

PROJECT_ROOT = Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------- #
# A throwaway /api/ingest server, so ship_batch's real HTTP path is tested.
# --------------------------------------------------------------------------- #

class IngestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        body = json.loads(raw)
        self.server.requests.append(
            {
                "path": self.path,
                "auth": self.headers.get("Authorization"),
                "body": body,
            }
        )
        if self.headers.get("Authorization") != f"Bearer {self.server.expected_key}":
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self._write(b'{"error": "bad key"}')
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self._write(
            json.dumps(
                {"accepted": len(body.get("events", [])), "rejected": 0, "errors": []}
            ).encode()
        )

    def _write(self, body):
        """A client that goes away mid-response is not a test failure.

        socketserver prints a full traceback for it otherwise, which is noise
        in a suite whose output is meant to be readable.
        """
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            self.close_connection = True

    def log_message(self, *args):  # keep pytest output clean
        pass


@pytest.fixture
def ingest_server():
    server = HTTPServer(("127.0.0.1", 0), IngestHandler)
    server.requests = []
    server.expected_key = "good"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


def base_url(server):
    return f"http://127.0.0.1:{server.server_address[1]}"


def collecting(*events):
    """A fake collector returning the given events on every call."""
    return lambda: [dict(event) for event in events]


def recording_poster(sink, *, accepted=None):
    """A fake poster that records batches and reports them accepted."""

    def poster(server, host_id, key, events, timeout):
        sink.append({"server": server, "host_id": host_id, "key": key, "events": list(events)})
        count = len(events) if accepted is None else accepted
        return {"accepted": count, "rejected": 0, "errors": []}

    return poster


def failing_poster(message="server down"):
    def poster(server, host_id, key, events, timeout):
        raise agent.ShipError(message)

    return poster


# --------------------------------------------------------------------------- #
# ship_batch: the wire contract
# --------------------------------------------------------------------------- #

def test_ship_batch_posts_the_documented_body_and_returns_the_response(ingest_server):
    response = agent.ship_batch(
        base_url(ingest_server),
        "web-01",
        "good",
        [{"message": "a"}, {"message": "b"}],
        timeout=5,
    )
    assert response == {"accepted": 2, "rejected": 0, "errors": []}
    sent = ingest_server.requests[-1]
    assert sent["path"] == "/api/ingest"
    assert sent["auth"] == "Bearer good"
    assert set(sent["body"]) == {"host_id", "agent_version", "platform", "events"}
    assert sent["body"]["host_id"] == "web-01"
    assert sent["body"]["agent_version"] == agent.AGENT_VERSION
    assert sent["body"]["platform"]
    assert [event["message"] for event in sent["body"]["events"]] == ["a", "b"]


def test_ship_batch_strips_a_trailing_slash_from_the_server(ingest_server):
    agent.ship_batch(base_url(ingest_server) + "/", "h", "good", [{"message": "a"}], 5)
    assert ingest_server.requests[-1]["path"] == "/api/ingest"


def test_ship_batch_raises_ship_error_on_a_bad_key(ingest_server):
    with pytest.raises(agent.ShipError) as caught:
        agent.ship_batch(base_url(ingest_server), "h", "wrong", [{"message": "a"}], 5)
    assert "401" in str(caught.value)


def test_ship_batch_raises_ship_error_when_the_server_is_unreachable():
    # Port 1 on loopback refuses the connection on every platform we run on.
    with pytest.raises(agent.ShipError) as caught:
        agent.ship_batch("http://127.0.0.1:1", "h", "k", [{"message": "a"}], timeout=1)
    assert "could not reach" in str(caught.value)


def test_ship_batch_rejects_missing_arguments():
    with pytest.raises(ValueError):
        agent.ship_batch("", "h", "k", [], 5)
    with pytest.raises(ValueError):
        agent.ship_batch("http://127.0.0.1:1", "", "k", [], 5)
    with pytest.raises(ValueError):
        agent.ship_batch("http://127.0.0.1:1", "h", "k", {"not": "a list"}, 5)


# --------------------------------------------------------------------------- #
# collect_events: the file source
# --------------------------------------------------------------------------- #

def test_file_source_tails_jsonl_incrementally(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(json.dumps({"message": "one"}) + "\n", encoding="utf-8")
    state = {}
    first = agent.collect_events("file", file_path=path, state=state)
    assert [event["message"] for event in first] == ["one"]

    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps({"message": "two"}) + "\n")
    second = agent.collect_events("file", file_path=path, state=state)
    assert [event["message"] for event in second] == ["two"]

    # Nothing new means nothing returned.
    assert agent.collect_events("file", file_path=path, state=state) == []


def test_file_source_holds_a_line_until_its_newline_arrives(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(json.dumps({"message": "partial"}), encoding="utf-8")  # no newline
    state = {}
    assert agent.collect_events("file", file_path=path, state=state) == []
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("\n")
    assert [event["message"] for event in agent.collect_events("file", file_path=path, state=state)] == [
        "partial"
    ]


def test_file_source_reads_csv_with_a_header(tmp_path):
    path = tmp_path / "events.csv"
    path.write_text("message,severity,channel\nhello,High,Security\n", encoding="utf-8")
    events = agent.collect_events("file", file_path=path, state={})
    assert len(events) == 1
    assert events[0]["message"] == "hello"
    assert events[0]["severity"] == "High"
    assert events[0]["channel"] == "Security"
    assert events[0]["source"] == "agent-file"


def test_file_source_skips_malformed_lines_and_counts_them(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(
        json.dumps({"message": "good"}) + "\n" + "{not json}\n" + "12345\n",
        encoding="utf-8",
    )
    state = {}
    events = agent.collect_events("file", file_path=path, state=state)
    assert [event["message"] for event in events] == ["good"]
    assert state["file_errors"] == 2


def test_file_source_restarts_after_the_file_is_truncated(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(json.dumps({"message": "old and long enough"}) + "\n", encoding="utf-8")
    state = {}
    assert len(agent.collect_events("file", file_path=path, state=state)) == 1
    path.write_text(json.dumps({"message": "new"}) + "\n", encoding="utf-8")
    events = agent.collect_events("file", file_path=path, state=state)
    assert [event["message"] for event in events] == ["new"]


def test_file_source_fills_required_canonical_keys(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(json.dumps({"event": "bare"}) + "\n", encoding="utf-8")
    event = agent.collect_events("file", file_path=path, state={})[0]
    for key in ("timestamp", "message", "severity", "channel", "provider", "is_alert", "source"):
        assert key in event
    assert event["message"] == "bare"
    assert event["is_alert"] is False


def test_collect_events_rejects_bad_input():
    with pytest.raises(ValueError):
        agent.collect_events("smtp")
    with pytest.raises(ValueError):
        agent.collect_events("file")  # no file_path
    with pytest.raises(ValueError):
        agent.collect_events("file", file_path="x", collector=lambda: [], limit=0)


def test_collect_events_uses_an_injected_collector():
    events = agent.collect_events("windows", collector=lambda: [{"message": "x"}])
    assert [event["message"] for event in events] == ["x"]


def test_collect_events_honours_the_limit():
    many = lambda: [{"message": str(i)} for i in range(10)]
    assert len(agent.collect_events("windows", collector=many, limit=3)) == 3


# --------------------------------------------------------------------------- #
# The spool
# --------------------------------------------------------------------------- #

def test_spool_append_read_size_and_clear_round_trip(tmp_path):
    spool = tmp_path / "spool.jsonl"
    assert agent.spool_size(spool) == 0
    assert agent.spool_append(spool, [{"a": 1}, {"b": 2}]) == 2
    assert agent.spool_read(spool) == [{"a": 1}, {"b": 2}]
    assert agent.spool_size(spool) > 0
    agent.spool_clear(spool)
    assert not spool.exists()
    assert agent.spool_read(spool) == []


def test_spool_read_skips_a_torn_final_line(tmp_path):
    spool = tmp_path / "spool.jsonl"
    spool.write_text('{"a": 1}\n{"torn":\n', encoding="utf-8")
    assert agent.spool_read(spool) == [{"a": 1}]


def test_spool_trim_drops_the_oldest_entries(tmp_path):
    spool = tmp_path / "spool.jsonl"
    agent.spool_append(spool, [{"n": i, "pad": "x" * 40} for i in range(10)])
    dropped = agent.spool_trim(spool, 200)
    assert dropped > 0
    assert agent.spool_size(spool) <= 200
    remaining = agent.spool_read(spool)
    # Whatever survived must be the newest entries, oldest first.
    assert remaining == sorted(remaining, key=lambda event: event["n"])


def test_spool_trim_is_a_noop_under_the_bound(tmp_path):
    spool = tmp_path / "spool.jsonl"
    agent.spool_append(spool, [{"a": 1}])
    assert agent.spool_trim(spool, 10_000) == 0
    assert agent.spool_trim(spool, 0) == 0  # disabled


# --------------------------------------------------------------------------- #
# run_agent: one cycle and the loop
# --------------------------------------------------------------------------- #

def test_run_agent_once_ships_and_reports(tmp_path):
    printed = []
    summary = agent.run_agent(
        "http://siem.invalid",
        "web-01",
        "key",
        collector=collecting({"message": "a"}, {"message": "b"}),
        poster=recording_poster([]),
        spool_path=tmp_path / "spool.jsonl",
        once=True,
        out=printed.append,
    )
    assert summary["ok"] is True
    assert summary["cycles"] == 1
    assert summary["collected"] == 2
    assert summary["shipped"] == 2
    assert summary["acknowledged"] == 2
    assert summary["spool_bytes"] == 0
    assert not (tmp_path / "spool.jsonl").exists()
    assert "collected=2" in printed[0]
    assert "shipped=2" in printed[0]
    assert "spooled=0" in printed[0]
    assert "ack=2" in printed[0]
    assert "spool_bytes=0" in printed[0]


def test_run_agent_spools_when_shipping_fails(tmp_path):
    spool = tmp_path / "spool.jsonl"
    summary = agent.run_agent(
        "http://siem.invalid",
        "web-01",
        "key",
        collector=collecting({"message": "lost"}),
        poster=failing_poster(),
        spool_path=spool,
        once=True,
        out=lambda line: None,
    )
    assert summary["ok"] is False
    assert summary["shipped"] == 0
    assert summary["spooled"] == 1
    assert "server down" in summary["last_error"]
    assert agent.spool_read(spool) == [{"message": "lost"}]


def test_run_agent_drains_the_spool_before_new_events(tmp_path):
    spool = tmp_path / "spool.jsonl"
    agent.spool_append(spool, [{"message": "backlog"}])
    batches = []
    summary = agent.run_agent(
        "http://siem.invalid",
        "web-01",
        "key",
        collector=collecting({"message": "fresh"}),
        poster=recording_poster(batches),
        spool_path=spool,
        once=True,
        out=lambda line: None,
    )
    assert summary["shipped"] == 2
    assert summary["spooled"] == 0
    assert not spool.exists()
    # The backlog is sent first, oldest first, then the new event.
    assert [[event["message"] for event in batch["events"]] for batch in batches] == [
        ["backlog"],
        ["fresh"],
    ]


def test_run_agent_keeps_the_spool_when_the_drain_fails(tmp_path):
    spool = tmp_path / "spool.jsonl"
    agent.spool_append(spool, [{"message": "backlog"}])
    summary = agent.run_agent(
        "http://siem.invalid",
        "web-01",
        "key",
        collector=collecting({"message": "fresh"}),
        poster=failing_poster(),
        spool_path=spool,
        once=True,
        out=lambda line: None,
    )
    assert summary["ok"] is False
    # Both the un-drained backlog and the new event are still on disk, in order.
    assert [event["message"] for event in agent.spool_read(spool)] == ["backlog", "fresh"]


def test_run_agent_bounds_the_spool_and_reports_drops(tmp_path):
    spool = tmp_path / "spool.jsonl"
    events = [{"message": "X" * 60, "n": i} for i in range(20)]
    summary = agent.run_agent(
        "http://siem.invalid",
        "web-01",
        "key",
        collector=collecting(*events),
        poster=failing_poster(),
        spool_path=spool,
        max_spool_bytes=250,
        once=True,
        out=lambda line: None,
    )
    assert summary["dropped"] > 0
    assert summary["spool_bytes"] <= 250
    assert agent.spool_size(spool) <= 250


def test_run_agent_splits_events_into_batches(tmp_path):
    batches = []
    summary = agent.run_agent(
        "http://siem.invalid",
        "web-01",
        "key",
        collector=collecting(*[{"message": str(i)} for i in range(5)]),
        poster=recording_poster(batches),
        spool_path=tmp_path / "spool.jsonl",
        batch_size=2,
        once=True,
        out=lambda line: None,
    )
    assert summary["shipped"] == 5
    assert [len(batch["events"]) for batch in batches] == [2, 2, 1]


def test_run_agent_loops_on_the_interval(tmp_path):
    sleeps = []
    summary = agent.run_agent(
        "http://siem.invalid",
        "web-01",
        "key",
        collector=collecting({"message": "tick"}),
        poster=recording_poster([]),
        spool_path=tmp_path / "spool.jsonl",
        interval=7.0,
        max_cycles=3,
        sleep=sleeps.append,
        out=lambda line: None,
    )
    assert summary["cycles"] == 3
    assert summary["shipped"] == 3
    assert sleeps == [7.0, 7.0]  # no sleep after the final cycle


def test_run_agent_rejects_bad_arguments(tmp_path):
    with pytest.raises(ValueError):
        agent.run_agent("", "h", "k", once=True)
    with pytest.raises(ValueError):
        agent.run_agent("http://x", "", "k", once=True)
    with pytest.raises(ValueError):
        agent.run_agent("http://x", "h", "k", source="smtp", once=True)
    with pytest.raises(ValueError):
        agent.run_agent("http://x", "h", "k", source="file", once=True)  # no file_path
    with pytest.raises(ValueError):
        agent.run_agent("http://x", "h", "k", batch_size=0, once=True)
    with pytest.raises(ValueError):
        agent.run_agent("http://x", "h", "k", interval=-1, once=True)


# --------------------------------------------------------------------------- #
# The command line
# --------------------------------------------------------------------------- #

def test_parser_defaults_match_the_documented_interface():
    args = agent.build_parser().parse_args(["--server", "http://x", "--host-id", "h", "--key", "k"])
    assert args.source == "windows"
    assert args.interval == agent.DEFAULT_INTERVAL
    assert args.spool == agent.DEFAULT_SPOOL_PATH
    assert args.batch_size == agent.DEFAULT_BATCH_SIZE
    assert args.once is False


def test_parser_rejects_an_unknown_source():
    with pytest.raises(SystemExit):
        agent.build_parser().parse_args(
            ["--server", "http://x", "--host-id", "h", "--key", "k", "--source", "smtp"]
        )


def test_main_requires_a_file_for_the_file_source(monkeypatch):
    monkeypatch.delenv("SIEM_AGENT_KEY", raising=False)
    with pytest.raises(SystemExit):
        agent.main(["--server", "http://x", "--host-id", "h", "--key", "k", "--source", "file"])


def test_main_requires_a_key(monkeypatch):
    monkeypatch.delenv("SIEM_AGENT_KEY", raising=False)
    with pytest.raises(SystemExit):
        agent.main(["--server", "http://x", "--host-id", "h"])


def test_module_runs_as_a_command(tmp_path, ingest_server):
    path = tmp_path / "events.jsonl"
    path.write_text(json.dumps({"message": "from the cli"}) + "\n", encoding="utf-8")
    environment = {
        key: value
        for key, value in __import__("os").environ.items()
        if key.upper() not in {"PYTHONHOME", "PYTHONSTARTUP", "VIRTUAL_ENV", "CONDA_PREFIX"}
    }
    environment["PYTHONPATH"] = "."
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "src.agent",
            "--server",
            base_url(ingest_server),
            "--host-id",
            "cli-host",
            "--key",
            "good",
            "--source",
            "file",
            "--file",
            str(path),
            "--once",
        ],
        cwd=str(PROJECT_ROOT),
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert "collected=1" in result.stdout
    assert ingest_server.requests[-1]["body"]["host_id"] == "cli-host"
    assert [event["message"] for event in ingest_server.requests[-1]["body"]["events"]] == [
        "from the cli"
    ]


def test_module_help_exits_cleanly():
    environment = {
        key: value
        for key, value in __import__("os").environ.items()
        if key.upper() not in {"PYTHONHOME", "PYTHONSTARTUP", "VIRTUAL_ENV", "CONDA_PREFIX"}
    }
    environment["PYTHONPATH"] = "."
    result = subprocess.run(
        [sys.executable, "-m", "src.agent", "--help"],
        cwd=str(PROJECT_ROOT),
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0
    assert "--host-id" in result.stdout
