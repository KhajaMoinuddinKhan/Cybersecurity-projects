"""Local analyst dashboard using Python's HTTP server."""
from __future__ import annotations

import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

from .storage import alert_stats, list_alerts
from .website_check import inspect_website


CSS = """
:root{color-scheme:dark;--bg:#050505;--panel:#0c0c0e;--panel2:#111114;--line:#2b171a;--line2:#472026;--text:#f4f4f5;--muted:#919197;--red:#ff334f;--red2:#c40f2d;--amber:#ffb74d;--green:#4ade80}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:radial-gradient(circle at 80% -10%,#30050d 0,#0a0506 28%,#050505 60%);color:var(--text)}
a{color:inherit;text-decoration:none}.shell{max-width:1400px;margin:auto;padding:34px 24px 70px}.top{display:flex;justify-content:space-between;gap:24px;align-items:flex-start;margin-bottom:26px}.eyebrow{font-size:11px;letter-spacing:.24em;color:var(--red);text-transform:uppercase}.title{font-size:38px;letter-spacing:-.03em;margin:8px 0 7px}.sub{color:var(--muted);max-width:760px;line-height:1.65}.status{border:1px solid #6f1e2d;background:#1b090d;padding:9px 13px;border-radius:999px;color:#ff8b9d;font-size:11px;letter-spacing:.1em;box-shadow:0 0 30px rgba(255,51,79,.08)}
.nav{display:flex;gap:8px;margin:0 0 18px}.nav a{padding:9px 12px;border:1px solid var(--line);border-radius:9px;background:#0a0a0c;color:var(--muted)}.nav a:hover{border-color:var(--red2);color:white}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:13px;margin-bottom:18px}.card,.panel{background:linear-gradient(180deg,rgba(17,17,20,.97),rgba(10,10,12,.97));border:1px solid var(--line);border-radius:14px;box-shadow:0 12px 38px rgba(0,0,0,.23)}.card{padding:18px;position:relative;overflow:hidden}.card:before{content:"";position:absolute;left:0;top:0;bottom:0;width:2px;background:var(--red)}.card .label{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.1em}.card .value{font-size:31px;font-weight:750;margin-top:7px}.grid{display:grid;grid-template-columns:1.55fr 1fr;gap:16px;margin-bottom:16px}.panel{padding:18px}.panel h2{font-size:15px;margin:0 0 14px}.panel h3{font-size:13px;margin:18px 0 8px;color:#d4d4d8}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}.filters a,.filters button,.filters input,.site-form input,.site-form button{border:1px solid #302024;background:#09090b;color:var(--text);border-radius:9px;padding:10px 12px;transition:.18s ease}.filters a:hover,.filters button:hover,.site-form button:hover{border-color:var(--red);box-shadow:0 0 18px rgba(255,51,79,.08)}.filters a.active{border-color:var(--red);background:#1d090e;color:#ff9aaa}.filters input{min-width:250px}.filters button,.site-form button{cursor:pointer}
.tech{display:flex;justify-content:space-between;border-top:1px solid var(--line);padding:10px 0;color:var(--muted)}.tech:first-of-type{border-top:0}.bar{height:7px;background:#1a0d10;border-radius:99px;overflow:hidden;margin-top:5px}.fill{height:100%;background:linear-gradient(90deg,#9e0c26,#ff334f)}
table{width:100%;border-collapse:collapse;font-size:13px}th{text-align:left;color:var(--muted);font-weight:600;padding:11px 10px;border-bottom:1px solid var(--line2)}td{padding:13px 10px;border-bottom:1px solid #201114;vertical-align:top}.alert-row:hover{background:#12090b}.sev{display:inline-block;padding:5px 8px;border-radius:999px;font-size:10px;font-weight:800;letter-spacing:.06em}.High{background:#3d0b14;color:#ff7d90;border:1px solid #64202d}.Medium{background:#382309;color:#ffc76d}.Low{background:#102719;color:#72e99c}.Info{background:#19191d;color:#b8b8c0}.rule{font-weight:700}.desc{color:var(--muted);margin-top:4px;max-width:520px}.mono{font-family:Consolas,monospace;color:#d8b4bd}.empty{padding:26px;color:var(--muted)}
details{margin-top:6px}summary{cursor:pointer;color:#c7a0a8;font-size:11px}.website{scroll-margin-top:18px}.site-form{display:grid;grid-template-columns:1fr auto;gap:10px}.site-form input{width:100%;font-size:14px}.site-form button{background:linear-gradient(180deg,#a60f28,#73091c);border-color:#b91c35;font-weight:700;padding-left:18px;padding-right:18px}.small{font-size:12px;color:var(--muted);line-height:1.55}.scan-result{margin-top:15px;display:none}.scan-result.show{display:block}.scan-head{display:flex;justify-content:space-between;gap:12px;align-items:center;border-bottom:1px solid var(--line);padding-bottom:13px;margin-bottom:13px}.score{font-size:28px;font-weight:800;color:var(--red)}.result-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:9px;margin-bottom:13px}.mini{border:1px solid var(--line);background:#08080a;border-radius:10px;padding:11px}.mini .k{font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}.mini .v{font-size:13px;margin-top:6px;word-break:break-word}.checks{display:grid;grid-template-columns:repeat(2,1fr);gap:7px}.check{display:flex;justify-content:space-between;gap:10px;border:1px solid #211417;border-radius:9px;padding:9px 11px;background:#09090b}.ok{color:var(--green)}.bad{color:#ff6b7e}.finding{display:flex;gap:10px;align-items:flex-start;padding:9px 0;border-top:1px solid #211417}.finding:first-child{border-top:0}.loading{color:#ff9aaa}.error{color:#ff7d90;border:1px solid #64202d;background:#1d090e;padding:11px;border-radius:9px}
@media(max-width:920px){.cards{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr}.top{flex-direction:column}.result-grid{grid-template-columns:repeat(2,1fr)}}@media(max-width:580px){.cards,.result-grid,.checks{grid-template-columns:1fr}.shell{padding:22px 14px}.site-form{grid-template-columns:1fr}}
"""

SCRIPT = """
function esc(value){
  return String(value ?? "").replace(/[&<>"']/g, function(ch){
    return {"&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;","'":"&#39;"}[ch];
  });
}
function labelClass(sev){ return ["High","Medium","Low","Info"].includes(sev) ? sev : "Info"; }
async function runWebsiteCheck(event){
  event.preventDefault();
  const input=document.getElementById("website-url");
  const box=document.getElementById("scan-result");
  box.className="scan-result show";
  box.innerHTML='<div class="loading">Checking the website...</div>';
  try{
    const response=await fetch("/api/website-check?url="+encodeURIComponent(input.value));
    const data=await response.json();
    if(!response.ok){ throw new Error(data.error || "Website check failed"); }

    let headers="";
    Object.entries(data.headers).forEach(function(entry){
      headers += '<div class="check"><span>'+esc(entry[0])+'</span><strong class="'+(entry[1]?'ok':'bad')+'">'+(entry[1]?'Present':'Missing')+'</strong></div>';
    });

    let findings="";
    data.findings.forEach(function(item){
      findings += '<div class="finding"><span class="sev '+labelClass(item.severity)+'">'+esc(item.severity)+'</span><span>'+esc(item.message)+'</span></div>';
    });
    if(!findings){ findings='<div class="finding"><span class="ok">No issues found by these passive checks.</span></div>'; }

    const tls=data.tls || {};
    box.innerHTML =
      '<div class="scan-head"><div><div class="eyebrow">Website quick check</div><div class="rule">'+esc(data.final_url)+'</div></div><div><span class="score">'+esc(data.score)+'</span><span class="small"> / 100</span></div></div>'+
      '<div class="result-grid">'+
      '<div class="mini"><div class="k">HTTP status</div><div class="v">'+esc(data.status)+'</div></div>'+
      '<div class="mini"><div class="k">HTTPS</div><div class="v">'+(data.https?'<span class="ok">Enabled</span>':'<span class="bad">Not enabled</span>')+'</div></div>'+
      '<div class="mini"><div class="k">TLS</div><div class="v">'+esc(tls.version || "N/A")+'</div></div>'+
      '<div class="mini"><div class="k">Certificate</div><div class="v">'+esc(tls.days_left == null ? "N/A" : tls.days_left+" days left")+'</div></div>'+
      '</div>'+
      '<h3>Security headers</h3><div class="checks">'+headers+'</div>'+
      '<h3>Findings</h3><div>'+findings+'</div>'+
      '<p class="small">'+esc(data.note)+'</p>';
  }catch(error){
    box.innerHTML='<div class="error">'+esc(error.message)+'</div>';
  }
}
"""


def render_dashboard(db_path: Path, severity: str = "", search: str = "") -> str:
    alerts = list_alerts(db_path, severity=severity or None, search=search or None)
    stats = alert_stats(db_path)
    max_technique = max([int(item["count"]) for item in stats["techniques"]] or [1])

    rows = []
    for alert in alerts:
        event_ids = ", ".join(str(item) for item in alert["event_ids"])
        rows.append(
            f"""<tr class="alert-row">
<td><span class="sev {html.escape(str(alert['severity']))}">{html.escape(str(alert['severity']))}</span></td>
<td><div class="rule">{html.escape(str(alert['title']))}</div><div class="desc">{html.escape(str(alert['description']))}</div><details><summary>Matched events</summary><div class="mono">{html.escape(event_ids)}</div></details></td>
<td><div class="mono">{html.escape(str(alert['technique_id']))}</div>{html.escape(str(alert['technique_name']))}</td>
<td>{html.escape(str(alert['host']))}<br><span class="mono">{html.escape(str(alert['source']))}</span></td>
<td>{html.escape(str(alert['username']))}</td>
<td>{len(alert['event_ids'])}</td>
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
<section class="top"><div><div class="eyebrow">Purple team security console</div><h1 class="title">Purple Team Detection Lab</h1><p class="sub">Correlated alerts from synthetic telemetry, ATT&CK-mapped detections, and a passive public-website security check.</p></div><div class="status">LOCAL LAB ONLINE</div></section>
<nav class="nav"><a href="#detections">Detection queue</a><a href="#website-check">Website check</a></nav>
<section class="cards"><div class="card"><div class="label">Total alerts</div><div class="value">{stats['total']}</div></div><div class="card"><div class="label">High severity</div><div class="value">{stats['high']}</div></div><div class="card"><div class="label">Medium severity</div><div class="value">{stats['medium']}</div></div><div class="card"><div class="label">ATT&CK techniques</div><div class="value">{len(stats['techniques'])}</div></div></section>
<section class="grid"><div class="panel"><h2>Analyst filters</h2><form class="filters" method="get">{''.join(severity_links)}<input type="text" name="search" value="{html.escape(search)}" placeholder="Search alert, host, user or source"><input type="hidden" name="severity" value="{html.escape(severity)}"><button type="submit">Search</button></form><p class="small">Showing {len(alerts)} alert(s). Expand any detection to see the event IDs that triggered it.</p></div><div class="panel"><h2>ATT&CK coverage</h2>{''.join(techniques) or '<div class="empty">No techniques yet.</div>'}</div></section>
<section class="panel website" id="website-check"><h2>Website quick check</h2><p class="small">Paste a public website. The lab checks HTTP status, HTTPS/TLS, certificate expiry and common security headers. It does not send exploit payloads or scan private network addresses.</p><form class="site-form" onsubmit="runWebsiteCheck(event)"><input id="website-url" type="text" placeholder="https://example.com" autocomplete="off"><button type="submit">Check website</button></form><div id="scan-result" class="scan-result"></div></section>
<section class="panel" id="detections" style="margin-top:16px"><h2>Detection queue</h2><div style="overflow:auto"><table><thead><tr><th>Severity</th><th>Detection</th><th>ATT&CK</th><th>Host / Source</th><th>User</th><th>Events</th><th>Last seen</th></tr></thead><tbody>{''.join(rows) if rows else '<tr><td colspan="7" class="empty">No alerts match the current filters.</td></tr>'}</tbody></table></div></section>
</main><script>{SCRIPT}</script></body></html>"""


class DashboardHandler(BaseHTTPRequestHandler):
    db_path = Path("purple_lab.db")

    def _send(self, body: bytes, content_type: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, data: object, status: int = 200) -> None:
        self._send(json.dumps(data, default=str).encode("utf-8"), "application/json", status)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)

        if parsed.path == "/health":
            self._json({"status": "ok"})
            return

        if parsed.path == "/api/alerts":
            severity = query.get("severity", [""])[0]
            search = query.get("search", [""])[0]
            self._json(list_alerts(self.db_path, severity=severity or None, search=search or None))
            return

        if parsed.path == "/api/stats":
            self._json(alert_stats(self.db_path))
            return

        if parsed.path == "/api/website-check":
            target = query.get("url", [""])[0]
            try:
                self._json(inspect_website(target))
            except (ValueError, OSError) as exc:
                self._json({"error": str(exc)}, 400)
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


def serve(db_path: Path, host: str = "127.0.0.1", port: int = 8000) -> None:
    handler = type("ConfiguredDashboardHandler", (DashboardHandler,), {"db_path": db_path})
    server = ThreadingHTTPServer((host, port), handler)
    print(f"Dashboard: http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
