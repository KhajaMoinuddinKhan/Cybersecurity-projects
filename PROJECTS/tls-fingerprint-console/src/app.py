"""Flask application factory for the TLS Fingerprint Console.

``create_app(store, corpus)`` wires the API and the single-file console UI onto
a fresh :class:`flask.Flask` instance.  ``store`` and ``corpus`` are injected so
the app is fully testable with in-memory fakes and so it never hard-imports the
parallel modules at import time.

The optional ``rules_module`` argument defaults to ``src.rules`` when it can be
imported and to a no-op evaluator otherwise, which keeps the app importable
before every sibling module has landed.
"""

from __future__ import annotations

import csv
import io
import json

from flask import Flask, Response, jsonify, render_template, request

# The capture scope this console is configured for.  It lives in app.config so
# callers/tests can override it without touching the routes.
DEFAULT_SCOPE = {
    "mode": "passive",
    "interface": None,
    "capture_file": None,
    "note": (
        "Passive. This console reads an existing capture file or events posted "
        "to its API, and it never transmits traffic. Live capture is available "
        "from the command line with 'python -m src.cli watch', which needs a "
        "capture driver and normally an elevated shell; see GET /api/capture "
        "for whether this machine can do it."
    ),
}

_INTEL_SEARCH_CAP = 200
_INTEL_SAMPLE = 50


class _NoRules:
    """Fallback evaluator used when ``src.rules`` is unavailable."""

    @staticmethod
    def evaluate(event, ctx):  # pragma: no cover - trivial
        return []


def _resolve_rules(rules_module):
    if rules_module is not None:
        return rules_module
    try:
        from . import rules as _rules  # local import: never break at module load

        return _rules
    except Exception:  # pragma: no cover - depends on sibling module presence
        return _NoRules()


def _as_int(value, default=None):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _alerts_newest_first(alerts):
    alerts = list(alerts)
    if not alerts:
        return alerts
    if any("ts" in a for a in alerts):
        alerts.sort(key=lambda a: a.get("ts") or 0, reverse=True)
    else:
        alerts.reverse()
    return alerts


def _events_newest_first(events):
    events = list(events)
    if not events:
        return events
    if any("ts" in e for e in events):
        events.sort(key=lambda e: e.get("ts") or 0, reverse=True)
    else:
        events.reverse()
    return events


def _counter(items, key):
    counts = {}
    for item in items:
        name = item.get(key)
        if name is None:
            continue
        counts[name] = counts.get(name, 0) + 1
    return counts


def _by(items, key, out_key):
    counts = _counter(items, key)
    return [{out_key: k, "count": v} for k, v in sorted(counts.items(), key=lambda kv: (-kv[1], str(kv[0])))]


def _entry_dict(entry):
    if isinstance(entry, dict):
        return entry
    # Support Entry-like objects via attribute access.
    return {
        "kind": getattr(entry, "kind", None),
        "value": getattr(entry, "value", None),
        "category": getattr(entry, "category", None),
        "name": getattr(entry, "name", None),
        "source": getattr(entry, "source", None),
        "license": getattr(entry, "license", None),
    }


def os_by_ja3(corpus):
    """Map a JA3 to the OS family its intel source names.

    Only the bundled salesforce list names an OS family, and it is the
    OSX/*nix client list, so every entry in it is a Unix-family stack.  No
    source in this corpus names Windows, so no JA3 is ever mapped to Windows.
    macOS and Linux are deliberately not separated -- a JA3 cannot tell them
    apart, and a map that guessed would manufacture mismatches.
    """
    mapping = {}
    entries = getattr(corpus, "entries", None)
    if not callable(entries):
        return mapping
    try:
        for entry in entries():
            kind = getattr(entry, "kind", None)
            value = getattr(entry, "value", None)
            if kind != "ja3" or not value:
                continue
            blob = "%s %s" % (getattr(entry, "source", ""), getattr(entry, "name", ""))
            blob = blob.lower()
            if "osx" in blob or "nix" in blob:
                mapping[value] = "unix"
    except Exception:
        return mapping
    return mapping


def _capture_unavailable():
    """The documented /api/capture shape when no capture driver is present."""
    return {
        "driver_available": False,
        "driver_note": (
            "Npcap is not installed, so live capture is unavailable; install "
            "Npcap (the driver Wireshark ships) to enable it."
        ),
        "interface_count": 0,
        "interfaces": [],
        "selected": None,
        "default_filter": "",
        "mode": "file",
        "note": (
            "File and ingest modes are active: the console reads an existing "
            "capture file or explicitly ingested events."
        ),
    }


def create_app(store, corpus, rules_module=None):
    app = Flask(__name__)
    app.config.setdefault("CAPTURE_SCOPE", dict(DEFAULT_SCOPE))
    app.config["RULES_MODULE"] = _resolve_rules(rules_module)

    # ------------------------------------------------------------------ UI
    @app.get("/")
    def index():
        return render_template("console.html")

    # --------------------------------------------------------------- health
    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok"})

    # ---------------------------------------------------------------- stats
    @app.get("/api/stats")
    def stats():
        events = store.events()
        alerts = store.alerts()
        fps = store.fingerprints()
        payload = {
            "events": len(events),
            "alerts": len(alerts),
            "alerts_by_rule": _by(alerts, "rule", "rule"),
            "alerts_by_severity": _by(alerts, "severity", "severity"),
            "fingerprints": len(fps),
            "intel": corpus.stats(),
        }
        return jsonify(payload)

    # --------------------------------------------------------------- alerts
    @app.get("/api/alerts")
    def alerts():
        items = _alerts_newest_first(store.alerts())

        rule = request.args.get("rule")
        if rule:
            items = [a for a in items if str(a.get("rule", "")).lower() == rule.lower()]

        severity = request.args.get("severity")
        if severity:
            items = [a for a in items if str(a.get("severity", "")).lower() == severity.lower()]

        limit = _as_int(request.args.get("limit"))
        if limit is not None and limit >= 0:
            items = items[:limit]

        return jsonify({"count": len(items), "alerts": items})

    # --------------------------------------------------------------- events
    @app.get("/api/events")
    def events():
        items = _events_newest_first(store.events())

        sni = request.args.get("sni")
        if sni:
            needle = sni.lower()
            items = [e for e in items if needle in str(e.get("sni") or "").lower()]

        limit = _as_int(request.args.get("limit"))
        if limit is not None and limit >= 0:
            items = items[:limit]

        return jsonify({"count": len(items), "events": items})

    # --------------------------------------------------------- fingerprints
    @app.get("/api/fingerprints")
    def fingerprints():
        fps = [_entry_dict(f) for f in store.fingerprints()]
        fps.sort(key=lambda f: f.get("count") or 0, reverse=True)
        return jsonify({"count": len(fps), "fingerprints": fps})

    # ---------------------------------------------------------------- intel
    @app.get("/api/intel")
    def intel():
        stats_obj = corpus.stats() or {}
        payload = dict(stats_obj)
        entries = [_entry_dict(e) for e in corpus.entries()]
        payload["sample"] = entries[:_INTEL_SAMPLE]
        payload["sample_size"] = len(payload["sample"])
        return jsonify(payload)

    @app.get("/api/intel/search")
    def intel_search():
        q = (request.args.get("q") or "").strip()
        kind = (request.args.get("kind") or "").strip().lower()

        entries = [_entry_dict(e) for e in corpus.entries()]

        if kind:
            entries = [e for e in entries if str(e.get("kind") or "").lower() == kind]

        if not q:
            capped = entries[:_INTEL_SEARCH_CAP]
            return jsonify(
                {
                    "query": "",
                    "kind": kind or None,
                    "count": len(capped),
                    "total_matches": len(entries),
                    "capped": len(entries) > _INTEL_SEARCH_CAP,
                    "note": "Empty query: showing the first %d entries; the corpus is open." % _INTEL_SEARCH_CAP,
                    "entries": capped,
                }
            )

        needle = q.lower()
        matches = []
        for e in entries:
            hay_value = str(e.get("value") or "").lower()
            hay_name = str(e.get("name") or "").lower()
            if needle in hay_value or needle in hay_name:
                matches.append(e)

        capped = matches[:_INTEL_SEARCH_CAP]
        return jsonify(
            {
                "query": q,
                "kind": kind or None,
                "count": len(capped),
                "total_matches": len(matches),
                "capped": len(matches) > _INTEL_SEARCH_CAP,
                "entries": capped,
            }
        )

    # ---------------------------------------------------------------- scope
    @app.get("/api/scope")
    def scope():
        configured = app.config.get("CAPTURE_SCOPE") or {}
        merged = dict(DEFAULT_SCOPE)
        merged.update(configured)
        merged.setdefault("mode", "passive")
        return jsonify(
            {
                "mode": merged.get("mode"),
                "interface": merged.get("interface"),
                "capture_file": merged.get("capture_file"),
                "note": merged.get("note"),
            }
        )

    # -------------------------------------------------------------- capture
    @app.get("/api/capture")
    def capture_state():
        """Report the live-capture state without ever failing.

        ``src.capture`` is imported lazily and every driver call is guarded, so
        this endpoint answers 200 with ``driver_available: false`` on a machine
        with no Npcap (Linux/CI) instead of raising a 500.
        """
        try:
            from . import capture as _capture
        except Exception:
            _capture = None

        if _capture is None:
            return jsonify(_capture_unavailable())

        try:
            driver_available = bool(_capture.available())
        except Exception:
            driver_available = False

        if not driver_available:
            return jsonify(_capture_unavailable())

        interfaces = []
        try:
            interfaces = list(_capture.list_interfaces() or [])
        except Exception:
            interfaces = []

        selected = None
        try:
            selected = _capture.pick_interface(interfaces=interfaces)
        except Exception:
            selected = None

        default_filter = ""
        try:
            default_filter = getattr(_capture, "DEFAULT_FILTER", "") or ""
        except Exception:
            default_filter = ""

        return jsonify(
            {
                "driver_available": True,
                "driver_note": (
                    "Npcap is present, so live capture is available from a "
                    "network interface."
                ),
                "interface_count": len(interfaces),
                "interfaces": interfaces,
                "selected": selected,
                "default_filter": default_filter,
                "mode": "live",
                "note": (
                    "Live capture is available: the console can read packets "
                    "straight from a network interface."
                ),
            }
        )

    # --------------------------------------------------------------- export
    @app.get("/api/export")
    def export():
        fmt = (request.args.get("format") or "json").strip().lower()
        events_list = _events_newest_first(store.events())
        alerts_list = _alerts_newest_first(store.alerts())

        if fmt == "json":
            body = json.dumps(
                {"events": events_list, "alerts": alerts_list},
                indent=2,
                default=str,
            )
            resp = Response(body, mimetype="application/json")
            resp.headers["Content-Disposition"] = 'attachment; filename="tls-console-export.json"'
            return resp

        if fmt == "csv":
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(["section", "ts", "src_ip", "dst_ip", "rule", "severity", "title", "detail", "sni"])
            for a in alerts_list:
                writer.writerow(
                    [
                        "alert",
                        a.get("ts", ""),
                        a.get("src_ip", ""),
                        a.get("dst_ip", ""),
                        a.get("rule", ""),
                        a.get("severity", ""),
                        a.get("title", ""),
                        a.get("detail", ""),
                        a.get("sni", ""),
                    ]
                )
            for e in events_list:
                writer.writerow(
                    [
                        "event",
                        e.get("ts", ""),
                        e.get("src_ip", ""),
                        e.get("dst_ip", ""),
                        "",
                        "",
                        e.get("fingerprint_kind", ""),
                        e.get("fingerprint_value", ""),
                        e.get("sni", ""),
                    ]
                )
            resp = Response(buf.getvalue(), mimetype="text/csv")
            resp.headers["Content-Disposition"] = 'attachment; filename="tls-console-export.csv"'
            return resp

        return jsonify({"error": "unsupported format: %r (expected json or csv)" % fmt}), 400

    # --------------------------------------------------------------- ingest
    @app.post("/api/ingest")
    def ingest():
        payload = request.get_json(silent=True)
        if payload is None:
            return jsonify({"error": "request body must be valid JSON"}), 400
        if not isinstance(payload, dict):
            return jsonify({"error": "request body must be a JSON object"}), 400

        events_in = payload.get("events")
        if events_in is None:
            return jsonify({"error": "missing 'events' key"}), 400
        if not isinstance(events_in, list):
            return jsonify({"error": "'events' must be a list"}), 400

        rules = app.config["RULES_MODULE"]
        ctx = {
            "store": store,
            "corpus": corpus,
            "seen_before": store.seen_before,
            "os_by_ja3": os_by_ja3(corpus),
        }

        accepted = 0
        alert_count = 0
        for event in events_in:
            if not isinstance(event, dict):
                return jsonify({"error": "every event must be a JSON object"}), 400

            # The rules run BEFORE the event is written.  first_seen asks the
            # store whether it has seen a fingerprint before, so storing the
            # event first would make that answer always yes and silence the
            # rule completely -- which is exactly what happened until this
            # ordering was corrected.
            try:
                produced = rules.evaluate(event, ctx) or []
            except Exception as exc:  # a broken rule must not drop the event
                produced = [
                    {
                        "rule": "rule_error",
                        "severity": "low",
                        "title": "Rule evaluation failed",
                        "detail": str(exc),
                    }
                ]

            store.add_event(event)
            accepted += 1

            for alert in produced:
                alert = dict(alert)
                alert.setdefault("src_ip", event.get("src_ip"))
                alert.setdefault("dst_ip", event.get("dst_ip"))
                alert.setdefault("sni", event.get("sni"))
                if "ts" not in alert and event.get("ts") is not None:
                    alert["ts"] = event.get("ts")
                alert.setdefault(
                    "fp_kind",
                    event.get("fingerprint_kind") or event.get("kind"),
                )
                alert.setdefault(
                    "fp_value",
                    event.get("fingerprint_value") or event.get("value"),
                )
                store.add_alert(alert)
                alert_count += 1

        return jsonify({"accepted": accepted, "alerts": alert_count})

    # ------------------------------------------------------------- 404 JSON
    @app.errorhandler(404)
    def not_found(_err):
        return jsonify({"error": "not found", "path": request.path}), 404

    @app.errorhandler(405)
    def method_not_allowed(_err):
        return jsonify({"error": "method not allowed", "path": request.path}), 405

    @app.errorhandler(400)
    def bad_request(err):
        return jsonify({"error": str(getattr(err, "description", "bad request"))}), 400

    return app
