"""SQLite-backed storage for the TLS Fingerprint Console.

Three tables:

* ``events``       - one row per ingested event, fingerprint columns inline.
* ``alerts``       - one row per emitted alert.
* ``fingerprints`` - one row per (kind, value) pair, kept up to date on every
  event insert so ``seen_before`` is a single indexed lookup.

Row counts are always obtained with explicit ``SELECT COUNT(*)`` (or an
executemany ``rowcount``); ``sqlite3.total_changes`` is deliberately not used
because triggers would make it count index writes as well.
"""

from __future__ import annotations

import sqlite3
import threading
import time

FP_KINDS = ("ja3", "ja3s", "ja4", "ja4s", "ja4x", "ja4t", "ja4h")

_EVENT_COLS = ("ts", "src_ip", "dst_ip", "src_port", "dst_port", "sni",
               "alpn", "user_agent", "ja3", "ja3s", "ja4", "ja4s", "ja4x",
               "ja4t", "ja4h", "category", "intel_name",
               # transport and the QUIC/ECH fields are part of what an event is,
               # not decoration: without them a stored event cannot say it came
               # from HTTP/3, and the ECH flag -- which the ech_obscured rule
               # reads -- would vanish the moment the event was written.
               "transport", "quic_version", "ech")

_TOP_FP_LIMIT = 10


def _int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _num(value, default):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else default


class Store:
    def __init__(self, path):
        self.path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        try:
            self._conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.Error:  # e.g. :memory:
            pass
        self._init_schema()

    # ------------------------------------------------------------------ schema
    def _init_schema(self):
        with self._lock:
            c = self._conn
            c.execute(
                """CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL, src_ip TEXT, dst_ip TEXT, src_port INTEGER,
                    dst_port INTEGER, sni TEXT, alpn TEXT, user_agent TEXT,
                    ja3 TEXT, ja3s TEXT, ja4 TEXT, ja4s TEXT, ja4x TEXT,
                    ja4t TEXT, ja4h TEXT, category TEXT, intel_name TEXT,
                    transport TEXT, quic_version INTEGER, ech INTEGER
                )"""
            )
            c.execute(
                """CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL, rule TEXT, severity TEXT, title TEXT, detail TEXT,
                    src_ip TEXT, fp_kind TEXT, fp_value TEXT
                )"""
            )
            c.execute(
                """CREATE TABLE IF NOT EXISTS fingerprints (
                    kind TEXT NOT NULL, value TEXT NOT NULL,
                    first_seen REAL, last_seen REAL, count INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (kind, value)
                )"""
            )
            c.commit()
            self._migrate()

    def _migrate(self):
        """Add columns an older database is missing.

        ``CREATE TABLE IF NOT EXISTS`` leaves an existing table alone, so a
        store written before a column was introduced would raise on every
        insert afterwards. Adding the missing columns keeps an existing
        console's history readable instead of making the operator start over.
        """
        want = {
            "transport": "TEXT",
            "quic_version": "INTEGER",
            "ech": "INTEGER",
        }
        with self._lock:
            try:
                have = {r[1] for r in self._conn.execute("PRAGMA table_info(events)")}
            except sqlite3.Error:
                return
            for column, kind in want.items():
                if column in have:
                    continue
                try:
                    self._conn.execute("ALTER TABLE events ADD COLUMN %s %s" % (column, kind))
                except sqlite3.Error:
                    pass
            try:
                self._conn.commit()
            except sqlite3.Error:
                pass

    # ------------------------------------------------------------------ writes
    def add_event(self, event):
        """Insert an event and maintain the fingerprints index.  Tolerant of
        malformed input: missing/None fields are simply stored as NULL."""
        if not isinstance(event, dict):
            event = {}
        fps = event.get("fingerprints")
        if not isinstance(fps, dict):
            fps = {}
        ts = _num(event.get("ts"), time.time())

        row = (
            ts,
            event.get("src_ip"), event.get("dst_ip"),
            event.get("src_port"), event.get("dst_port"),
            event.get("sni"), event.get("alpn"), event.get("user_agent"),
            fps.get("ja3"), fps.get("ja3s"), fps.get("ja4"), fps.get("ja4s"),
            fps.get("ja4x"), fps.get("ja4t"), fps.get("ja4h"),
            event.get("category"), event.get("intel_name"),
            event.get("transport"),
            _int_or_none(event.get("quic_version")),
            1 if event.get("ech") else 0,
        )
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO events ({cols}) VALUES ({ph})".format(
                    cols=", ".join(_EVENT_COLS),
                    ph=", ".join("?" for _ in _EVENT_COLS)),
                row,
            )
            event_id = cur.lastrowid

            fp_rows = []
            for kind in FP_KINDS:
                value = fps.get(kind)
                if isinstance(value, str) and value:
                    fp_rows.append((kind, value, ts, ts))
            if fp_rows:
                self._conn.executemany(
                    """INSERT INTO fingerprints (kind, value, first_seen, last_seen, count)
                       VALUES (?, ?, ?, ?, 1)
                       ON CONFLICT(kind, value) DO UPDATE SET
                           last_seen = excluded.last_seen,
                           count = fingerprints.count + 1""",
                    fp_rows,
                )
            self._conn.commit()
        return event_id

    def add_alert(self, alert):
        if not isinstance(alert, dict):
            alert = {}
        ts = _num(alert.get("ts"), time.time())
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO alerts (ts, rule, severity, title, detail,
                                       src_ip, fp_kind, fp_value)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (ts, alert.get("rule"), alert.get("severity"), alert.get("title"),
                 alert.get("detail"), alert.get("src_ip"), alert.get("fp_kind"),
                 alert.get("fp_value")),
            )
            self._conn.commit()
        return cur.lastrowid

    # ------------------------------------------------------------------ reads
    def events(self):
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM events ORDER BY id").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["fingerprints"] = {k: d[k] for k in FP_KINDS if d.get(k)}
            d["ech"] = bool(d.get("ech"))
            out.append(d)
        return out

    def alerts(self):
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM alerts ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    def fingerprints(self):
        with self._lock:
            rows = self._conn.execute(
                """SELECT kind, value, first_seen, last_seen, count
                   FROM fingerprints ORDER BY count DESC, kind, value""").fetchall()
        return [dict(r) for r in rows]

    def seen_before(self, kind, value):
        if not kind or not value:
            return False
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM fingerprints WHERE kind = ? AND value = ? LIMIT 1",
                (kind, value)).fetchone()
        return row is not None

    def stats(self):
        with self._lock:
            c = self._conn
            events = int(c.execute("SELECT COUNT(*) FROM events").fetchone()[0])
            alerts = int(c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])
            fingerprints = int(c.execute("SELECT COUNT(*) FROM fingerprints").fetchone()[0])
            by_rule = [
                {"rule": r["rule"], "count": r["n"]}
                for r in c.execute(
                    """SELECT rule, COUNT(*) AS n FROM alerts
                       GROUP BY rule ORDER BY n DESC, rule""")
            ]
            by_sev = [
                {"severity": r["severity"], "count": r["n"]}
                for r in c.execute(
                    """SELECT severity, COUNT(*) AS n FROM alerts
                       GROUP BY severity ORDER BY n DESC, severity""")
            ]
            top = [
                {"kind": r["kind"], "value": r["value"], "count": r["count"]}
                for r in c.execute(
                    """SELECT kind, value, count FROM fingerprints
                       ORDER BY count DESC, kind, value LIMIT ?""",
                    (_TOP_FP_LIMIT,))
            ]
        return {
            "events": events,
            "alerts": alerts,
            "alerts_by_rule": by_rule,
            "alerts_by_severity": by_sev,
            "fingerprints": fingerprints,
            "top_fingerprints": top,
        }

    # ------------------------------------------------------------------ life
    def close(self):
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False
