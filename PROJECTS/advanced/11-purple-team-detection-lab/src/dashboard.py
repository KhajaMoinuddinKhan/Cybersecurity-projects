"""Local analyst dashboard using Python's HTTP server."""
from __future__ import annotations

import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

from .storage import alert_stats, list_alerts


CSS = """
:root{color-scheme:dark;--bg:#07111f;--panel:#0d1b2d;--line:#1d3550;--text:#e8f1fb;--muted:#8da2b8;--cyan:#48cae4;--red:#ff5d73;--amber:#f4b942;--green:#4dd599}
*{box-sizing:border-box}body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:radial-gradient(circle at top right,#102942 0,#07111f 42%);color:var(--text)}
a{color:inherit;text-decoration:none}.shell{max-width:1320px;margin:auto;padding:34px 24px 60px}.top{display:flex;justify-content:space-between;gap:24px;align-items:flex-start;margin-bottom:28px}.eyebrow{font-size:12px;letter-spacing:.22em;color:var(--cyan);text-transform:uppercase}.title{font-size:34px;margin:8px 0 6px}.sub{color:var(--muted);max-width:720px;line-height:1.6}.status{border:1px solid #24516c;background:#0b2030;padding:9px 13px;border-radius:999px;color:#8de3f3;font-size:12px}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px}.card,.panel{background:rgba(13,27,45,.92);border:1px solid var(--line);border-radius:16px}.card{padding:18px}.card .label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em}.card .value{font-size:30px;font-weight:700;margin-top:8px}.grid{display:grid;grid-template-columns:1.7fr 1fr;gap:18px;margin-bottom:18px}.panel{padding:18px}.panel h2{font-size:15px;margin:0 0 14px}.filters{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px}.filters a,.filters button,.filters input{border:1px solid #27415d;background:#0a1727;color:var(--text);border-radius:10px;padding:9px 11px}.filters a.active{border-color:var(--cyan);color:var(--cyan)}.filters input{min-width:240px}.filters button{cursor:pointer}.tech{display:flex;justify-content:space-between;border-top:1px solid var(--line);padding:11px 0;color:var(--muted)}.tech:first-of-type{border-top:0}.bar{height:8px;background:#11283b;border-radius:99px;overflow:hidden;margin-top:7px}.fill{height:100%;background:linear-gradient(90deg,#48cae4,#6c63ff)}table{width:100%;border-collapse:collapse;font-size:13px}th{text-align:left;color:var(--muted);font-weight:600;padding:11px 10px;border-bottom:1px solid var(--line)}td{padding:13px 10px;border-bottom:1px solid #152b40;vertical-align:top}.sev{display:inline-block;padding:5px 8px;border-radius:999px;font-size:11px;font-weight:700}.High{background:#3a1821;color:#ff93a4}.Medium{background:#342911;color:#ffd36f}.Low{background:#103027;color:#7be3b5}.rule{font-weight:700}.desc{color:var(--muted);margin-top:4px;max-width:520px}.mono{font-family:Consolas,monospace;color:#b9d6f2}.empty{padding:26px;color:var(--muted)}@media(max-width:900px){.cards{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr}.top{flex-direction:column}}@media(max-width:560px){.cards{grid-template-columns:1fr}.shell{padding:22px 14px}}
"""


def render_dashboard(db_path: Path, severity: str = "", search: str = "") -> str:
    alerts = list_alerts(db_path, severity=severity or None, search=search or None)
    stats = alert_stats(db_path)
    max_technique = max([int(item["count"]) for item in stats["techniques"]] or [1])

    rows = []
    for alert in alerts:
        event_count = len(alert["event_ids"])
        rows.append(
            f"""<tr>
<td><span class="sev {html.escape(str(alert['severity']))}">{html.escape(str(alert['severity']))}</span></td>
<td><div class="rule">{html.escape(str(alert['title']))}</div><div class="desc">{html.escape(str(alert['description']))}</div></td>
<td><div class="mono">{html.escape(str(alert['technique_id']))}</div>{html.escape(str(alert['technique_name']))}</td>
<td>{html.escape(str(alert['host']))}<br><span class="mono">{html.escape(str(alert['source']))}</span></td>
<td>{html.escape(str(alert['username']))}</td>
<td>{event_count}</td>
<td class="mono">{html.escape(str(alert['last_seen']))[:16].replace('T',' ')}</td>
</tr>"""
        )

    severity_links = []
    for value, label in (("", "All"), ("High", "High"), ("Medium", "Medium"), ("Low", "Low")):
        active = " active" if severity == value else ""
        params = {}
        if value:
            params["severity"] = value
        if search:
            params["search"] = search
        query = "/?" + urlencode(params) if params else "/"
        severity_links.append(f'<a class="{active.strip()}" href="{html.escape(query)}">{label}</a>')

    techniques = []
    for item in stats["techniques"]:
        width = (int(item["count"]) / max_technique) * 100
        techniques.append(
            f"""<div class="tech"><span><span class="mono">{html.escape(str(item['technique_id']))}</span><br>{html.escape(str(item['technique_name']))}</span><strong>{item['count']}</strong></div><div class="bar"><div class="fill" style="width:{width:.0f}%"></div></div>"""
        )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Purple Team Detection Lab</title><style>{CSS}</style></head>
<body><main class="shell">
<section class="top"><div><div class="eyebrow">Detection engineering lab</div><h1 class="title">Purple Team Detection Lab</h1><p class="sub">Correlated alerts from synthetic endpoint, authentication, and network telemetry. Rules include MITRE ATT&CK mappings and explainable matching logic.</p></div><div class="status">LOCAL LAB ONLINE</div></section>
<section class="cards"><div class="card"><div class="label">Total alerts</div><div class="value">{stats['total']}</div></div><div class="card"><div class="label">High severity</div><div class="value">{stats['high']}</div></div><div class="card"><div class="label">Medium severity</div><div class="value">{stats['medium']}</div></div><div class="card"><div class="label">Techniques mapped</div><div class="value">{len(stats['techniques'])}</div></div></section>
<section class="grid"><div class="panel"><h2>Analyst filters</h2><form class="filters" method="get">{''.join(severity_links)}<input type="text" name="search" value="{html.escape(search)}" placeholder="Search title, host, user, source"><input type="hidden" name="severity" value="{html.escape(severity)}"><button type="submit">Search</button></form><p class="sub">Showing {len(alerts)} alert(s).</p></div><div class="panel"><h2>ATT&CK coverage</h2>{''.join(techniques) or '<div class="empty">No techniques yet.</div>'}</div></section>
<section class="panel"><h2>Detection queue</h2><div style="overflow:auto"><table><thead><tr><th>Severity</th><th>Detection</th><th>ATT&CK</th><th>Host / Source</th><th>User</th><th>Events</th><th>Last seen</th></tr></thead><tbody>{''.join(rows) if rows else '<tr><td colspan="7" class="empty">No alerts match the current filters.</td></tr>'}</tbody></table></div></section>
</main></body></html>"""


class DashboardHandler(BaseHTTPRequestHandler):
    db_path = Path("purple_lab.db")

    def _send(self, body: bytes, content_type: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)

        if parsed.path == "/health":
            self._send(b'{"status":"ok"}', "application/json")
            return

        if parsed.path == "/api/alerts":
            severity = query.get("severity", [""])[0]
            search = query.get("search", [""])[0]
            body = json.dumps(
                list_alerts(self.db_path, severity=severity or None, search=search or None),
                default=str,
            ).encode("utf-8")
            self._send(body, "application/json")
            return

        if parsed.path == "/api/stats":
            body = json.dumps(alert_stats(self.db_path)).encode("utf-8")
            self._send(body, "application/json")
            return

        if parsed.path != "/":
            self._send(b"Not found", "text/plain", 404)
            return

        severity = query.get("severity", [""])[0].title()
        if severity not in {"", "High", "Medium", "Low"}:
            severity = ""
        search = query.get("search", [""])[0].strip()
        body = render_dashboard(self.db_path, severity, search).encode("utf-8")
        self._send(body, "text/html; charset=utf-8")

    def log_message(self, format: str, *args: object) -> None:
        return


def serve(db_path: Path, host: str = "127.0.0.1", port: int = 8080) -> None:
    handler = type("ConfiguredDashboardHandler", (DashboardHandler,), {"db_path": db_path})
    server = ThreadingHTTPServer((host, port), handler)
    print(f"Dashboard: http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
