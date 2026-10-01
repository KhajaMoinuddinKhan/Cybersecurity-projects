"""Local analyst dashboard using Python's HTTP server."""
from __future__ import annotations

import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .storage import alert_stats, list_alerts
from .website_check import inspect_website


CSS = """
:root{color-scheme:dark;--bg:#050505;--panel:#0c0c0e;--line:#2b171a;--line2:#472026;--text:#f4f4f5;--muted:#919197;--red:#ff334f;--red2:#c40f2d;--amber:#ffb74d;--green:#4ade80}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:radial-gradient(circle at 80% -10%,#30050d 0,#0a0506 28%,#050505 60%);color:var(--text)}
a{color:inherit;text-decoration:none}.shell{max-width:1400px;margin:auto;padding:34px 24px 70px}.top{display:flex;justify-content:space-between;gap:24px;align-items:flex-start;margin-bottom:26px}.eyebrow{font-size:11px;letter-spacing:.24em;color:var(--red);text-transform:uppercase}.title{font-size:38px;letter-spacing:-.03em;margin:8px 0 7px}.sub{color:var(--muted);max-width:780px;line-height:1.65}.status{border:1px solid #6f1e2d;background:#1b090d;padding:9px 13px;border-radius:999px;color:#ff8b9d;font-size:11px;letter-spacing:.1em}
.nav{display:flex;gap:8px;margin:0 0 18px;flex-wrap:wrap}.nav a{padding:9px 12px;border:1px solid var(--line);border-radius:9px;background:#0a0a0c;color:var(--muted)}.nav a:hover{border-color:var(--red2);color:white}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:13px;margin:16px 0 18px}.card,.panel{background:linear-gradient(180deg,rgba(17,17,20,.97),rgba(10,10,12,.97));border:1px solid var(--line);border-radius:14px;box-shadow:0 12px 38px rgba(0,0,0,.23)}.card{padding:18px;position:relative;overflow:hidden}.card:before{content:"";position:absolute;left:0;top:0;bottom:0;width:2px;background:var(--red)}.card .label{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.1em}.card .value{font-size:31px;font-weight:750;margin-top:7px}
.panel{padding:18px}.panel h2{font-size:15px;margin:0 0 14px}.panel h3{font-size:13px;margin:18px 0 8px;color:#d4d4d8}.section-gap{margin-top:16px}.small{font-size:12px;color:var(--muted);line-height:1.55}
.site-form{display:grid;grid-template-columns:1fr auto;gap:10px}.site-form input,.site-form button,.alert-tools input,.alert-tools button{border:1px solid #302024;background:#09090b;color:var(--text);border-radius:9px;padding:10px 12px;transition:.18s ease}.site-form input{width:100%;font-size:14px}.site-form button,.alert-tools button{cursor:pointer;background:linear-gradient(180deg,#a60f28,#73091c);border-color:#b91c35;font-weight:700;padding-left:18px;padding-right:18px}.site-form button:hover,.alert-tools button:hover{border-color:var(--red);box-shadow:0 0 18px rgba(255,51,79,.12)}
.scan-result{margin-top:15px;display:none}.scan-result.show{display:block}.scan-head{display:flex;justify-content:space-between;gap:12px;align-items:center;border-bottom:1px solid var(--line);padding-bottom:13px;margin-bottom:13px}.score{font-size:28px;font-weight:800;color:var(--red)}.result-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:9px;margin-bottom:13px}.mini{border:1px solid var(--line);background:#08080a;border-radius:10px;padding:11px}.mini .k{font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}.mini .v{font-size:13px;margin-top:6px;word-break:break-word}.checks{display:grid;grid-template-columns:repeat(2,1fr);gap:7px}.check{display:flex;justify-content:space-between;gap:10px;border:1px solid #211417;border-radius:9px;padding:9px 11px;background:#09090b}.ok{color:var(--green)}.bad{color:#ff6b7e}.loading{color:#ff9aaa}.error{color:#ff7d90;border:1px solid #64202d;background:#1d090e;padding:11px;border-radius:9px}
.alert-tools{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}.alert-tools button{background:#09090b;font-weight:500;padding:9px 11px}.alert-tools button.active{border-color:var(--red);background:#1d090e;color:#ff9aaa}.alert-tools input{min-width:260px;flex:1}
table{width:100%;border-collapse:collapse;font-size:13px}th{text-align:left;color:var(--muted);font-weight:600;padding:11px 10px;border-bottom:1px solid var(--line2)}td{padding:13px 10px;border-bottom:1px solid #201114;vertical-align:top}.alert-row:hover{background:#12090b}.sev{display:inline-block;padding:5px 8px;border-radius:999px;font-size:10px;font-weight:800;letter-spacing:.06em}.High{background:#3d0b14;color:#ff7d90;border:1px solid #64202d}.Medium{background:#382309;color:#ffc76d}.Low{background:#102719;color:#72e99c}.Info{background:#19191d;color:#b8b8c0}.rule{font-weight:700}.desc{color:var(--muted);margin-top:4px;max-width:640px}.mono{font-family:Consolas,monospace;color:#d8b4bd}.empty{padding:26px;color:var(--muted)}
.lab-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.tech{display:flex;justify-content:space-between;border-top:1px solid var(--line);padding:10px 0;color:var(--muted)}.tech:first-of-type{border-top:0}.bar{height:7px;background:#1a0d10;border-radius:99px;overflow:hidden;margin-top:5px}.fill{height:100%;background:linear-gradient(90deg,#9e0c26,#ff334f)}details.lab{margin-top:16px}details.lab>summary{cursor:pointer;padding:18px;list-style:none;font-weight:700}details.lab>summary::-webkit-details-marker{display:none}details.lab[open]>summary{border-bottom:1px solid var(--line)}
@media(max-width:920px){.cards{grid-template-columns:repeat(2,1fr)}.lab-grid{grid-template-columns:1fr}.top{flex-direction:column}.result-grid{grid-template-columns:repeat(2,1fr)}}@media(max-width:580px){.cards,.result-grid,.checks{grid-template-columns:1fr}.shell{padding:22px 14px}.site-form{grid-template-columns:1fr}.alert-tools input{min-width:100%}}
"""

SCRIPT = """
let websiteFindings = [];
let websiteTarget = "";
let websiteSeverity = "All";

function esc(value){
  return String(value ?? "").replace(/[&<>"']/g, function(ch){
    return {"&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;","'":"&#39;"}[ch];
  });
}

function labelClass(sev){
  return ["High","Medium","Low","Info"].includes(sev) ? sev : "Info";
}

function counts(){
  const result={High:0,Medium:0,Low:0,Info:0};
  websiteFindings.forEach(function(item){
    if(result[item.severity] !== undefined){ result[item.severity] += 1; }
  });
  return result;
}

function updateWebsiteCards(){
  const c=counts();
  document.getElementById("website-total").textContent=websiteFindings.length;
  document.getElementById("website-high").textContent=c.High;
  document.getElementById("website-medium").textContent=c.Medium;
  document.getElementById("website-low").textContent=c.Low;

  ["All","High","Medium","Low","Info"].forEach(function(name){
    const button=document.querySelector('[data-severity="'+name+'"]');
    if(!button){ return; }
    const number=name==="All" ? websiteFindings.length : c[name];
    button.textContent=name+" ("+number+")";
  });
}

function setWebsiteSeverity(value){
  websiteSeverity=value;
  document.querySelectorAll("[data-severity]").forEach(function(button){
    button.classList.toggle("active", button.dataset.severity===value);
  });
  renderWebsiteAlerts();
}

function renderWebsiteAlerts(){
  const body=document.getElementById("website-alert-body");
  const search=document.getElementById("website-alert-search").value.trim().toLowerCase();
  const filtered=websiteFindings.filter(function(item){
    const severityMatch=websiteSeverity==="All" || item.severity===websiteSeverity;
    const text=(item.category+" "+item.message+" "+websiteTarget).toLowerCase();
    return severityMatch && (!search || text.includes(search));
  });

  document.getElementById("website-showing").textContent=
    "Showing "+filtered.length+" of "+websiteFindings.length+" alert(s) for the current website.";

  if(!websiteTarget){
    body.innerHTML='<tr><td colspan="4" class="empty">Scan a website to generate alerts.</td></tr>';
    return;
  }
  if(!filtered.length){
    body.innerHTML='<tr><td colspan="4" class="empty">No alerts match the current filter.</td></tr>';
    return;
  }

  body.innerHTML=filtered.map(function(item,index){
    return '<tr class="alert-row">'+
      '<td><span class="sev '+labelClass(item.severity)+'">'+esc(item.severity)+'</span></td>'+
      '<td class="mono">WEB-'+String(index+1).padStart(3,"0")+'</td>'+
      '<td><div class="rule">'+esc(item.category)+'</div><div class="desc">'+esc(item.message)+'</div></td>'+
      '<td class="mono">'+esc(websiteTarget)+'</td>'+
      '</tr>';
  }).join("");
}

let websiteRequestId=0;
async function runWebsiteCheck(event){
  event.preventDefault();
  const requestId=++websiteRequestId;
  const input=document.getElementById("website-url");
  const box=document.getElementById("scan-result");
  box.className="scan-result show";
  box.innerHTML='<div class="loading">Checking the website...</div>';

  try{
    const response=await fetch("/api/website-check?url="+encodeURIComponent(input.value));
    const data=await response.json();
    if(requestId!==websiteRequestId) return;
    if(!response.ok){ throw new Error(data.error || "Website check failed"); }

    websiteFindings=data.findings || [];
    websiteTarget=data.final_url || input.value;
    websiteSeverity="All";
    document.getElementById("website-alert-search").value="";
    updateWebsiteCards();
    setWebsiteSeverity("All");

    let headers="";
    Object.entries(data.headers).forEach(function(entry){
      headers += '<div class="check"><span>'+esc(entry[0])+'</span><strong class="'+(entry[1]?'ok':'bad')+'">'+(entry[1]?'Present':'Missing')+'</strong></div>';
    });

    const tls=data.tls || {};
    box.innerHTML =
      '<div class="scan-head"><div><div class="eyebrow">Website scan complete</div><div class="rule">'+esc(data.final_url)+'</div></div><div><span class="score">'+esc(data.score)+'</span><span class="small"> / 100</span></div></div>'+
      '<div class="result-grid">'+
      '<div class="mini"><div class="k">HTTP status</div><div class="v">'+esc(data.status)+'</div></div>'+
      '<div class="mini"><div class="k">HTTPS</div><div class="v">'+(data.https?'<span class="ok">Enabled</span>':'<span class="bad">Not enabled</span>')+'</div></div>'+
      '<div class="mini"><div class="k">TLS</div><div class="v">'+esc(tls.version || "N/A")+'</div></div>'+
      '<div class="mini"><div class="k">Certificate</div><div class="v">'+esc(tls.days_left == null ? "N/A" : tls.days_left+" days left")+'</div></div>'+
      '</div>'+
      '<h3>Security headers</h3><div class="checks">'+headers+'</div>'+
      '<p class="small">'+esc(data.note)+'</p>';

    document.getElementById("website-alerts").scrollIntoView({behavior:"smooth",block:"start"});
  }catch(error){
    if(requestId!==websiteRequestId) return;
    websiteFindings=[];
    websiteTarget="";
    updateWebsiteCards();
    renderWebsiteAlerts();
    box.innerHTML='<div class="error">'+esc(error.message)+'</div>';
  }
}
"""


def _render_lab_rows(db_path: Path) -> tuple[str, str]:
    alerts = list_alerts(db_path)
    stats = alert_stats(db_path)
    rows = []

    for alert in alerts:
        event_ids = ", ".join(str(item) for item in alert["event_ids"])
        rows.append(
            f"""<tr class="alert-row">
<td><span class="sev {html.escape(str(alert['severity']))}">{html.escape(str(alert['severity']))}</span></td>
<td><div class="rule">{html.escape(str(alert['title']))}</div><div class="desc">{html.escape(str(alert['description']))}</div></td>
<td><div class="mono">{html.escape(str(alert['technique_id']))}</div>{html.escape(str(alert['technique_name']))}</td>
<td class="mono">{html.escape(event_ids)}</td>
</tr>"""
        )

    max_technique = max([int(item["count"]) for item in stats["techniques"]] or [1])
    techniques = []
    for item in stats["techniques"]:
        width = (int(item["count"]) / max_technique) * 100
        techniques.append(
            f"""<div class="tech"><span><span class="mono">{html.escape(str(item['technique_id']))}</span><br>{html.escape(str(item['technique_name']))}</span><strong>{item['count']}</strong></div><div class="bar"><div class="fill" style="width:{width:.0f}%"></div></div>"""
        )

    return (
        "".join(rows) or '<tr><td colspan="4" class="empty">Run the event detector to populate this lab section.</td></tr>',
        "".join(techniques) or '<div class="empty">No ATT&CK techniques yet.</div>',
    )


def render_dashboard(db_path: Path) -> str:
    lab_rows, techniques = _render_lab_rows(db_path)

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Purple Team Detection Lab</title><style>{CSS}</style></head>
<body><main class="shell">
<section class="top"><div><div class="eyebrow">Purple team security console</div><h1 class="title">Purple Team Detection Lab</h1><p class="sub">Scan a public website and turn its passive security findings into live dashboard alerts. The original synthetic event-correlation lab is still available below.</p></div><div class="status">LOCAL LAB ONLINE</div></section>
<nav class="nav"><a href="#website-check">Website scan</a><a href="#website-alerts">Website alerts</a><a href="#event-lab">Event lab</a></nav>

<section class="panel" id="website-check"><h2>Website security check</h2><p class="small">Paste a public website. The lab checks HTTP status, HTTPS/TLS, certificate expiry and common security headers. The alert counters and queue below are generated from this website scan.</p><form class="site-form" onsubmit="runWebsiteCheck(event)"><input id="website-url" type="text" placeholder="https://example.com" autocomplete="off"><button type="submit">Scan website</button></form><div id="scan-result" class="scan-result"></div></section>

<section class="cards" id="website-alerts">
<div class="card"><div class="label">Website alerts</div><div class="value" id="website-total">0</div></div>
<div class="card"><div class="label">High severity</div><div class="value" id="website-high">0</div></div>
<div class="card"><div class="label">Medium severity</div><div class="value" id="website-medium">0</div></div>
<div class="card"><div class="label">Low severity</div><div class="value" id="website-low">0</div></div>
</section>

<section class="panel"><h2>Website alert filters</h2><div class="alert-tools">
<button type="button" class="active" data-severity="All" onclick="setWebsiteSeverity('All')">All (0)</button>
<button type="button" data-severity="High" onclick="setWebsiteSeverity('High')">High (0)</button>
<button type="button" data-severity="Medium" onclick="setWebsiteSeverity('Medium')">Medium (0)</button>
<button type="button" data-severity="Low" onclick="setWebsiteSeverity('Low')">Low (0)</button>
<button type="button" data-severity="Info" onclick="setWebsiteSeverity('Info')">Info (0)</button>
<input id="website-alert-search" type="text" placeholder="Search website alerts" oninput="renderWebsiteAlerts()">
</div><p class="small" id="website-showing">Scan a website to populate the alert queue.</p></section>

<section class="panel section-gap"><h2>Website alert queue</h2><div style="overflow:auto"><table><thead><tr><th>Severity</th><th>Alert ID</th><th>Finding</th><th>Website</th></tr></thead><tbody id="website-alert-body"><tr><td colspan="4" class="empty">Scan a website to generate alerts.</td></tr></tbody></table></div></section>

<details class="panel lab" id="event-lab"><summary>Synthetic event detection lab</summary><div style="padding:18px">
<div class="lab-grid"><div><h2>ATT&CK coverage</h2>{techniques}</div><div><h2>About this section</h2><p class="small">This is the original event-correlation side of the project. It uses the sample endpoint, authentication and network events from the repository. These alerts are separate from the website alerts above.</p></div></div>
<div style="overflow:auto;margin-top:16px"><table><thead><tr><th>Severity</th><th>Detection</th><th>ATT&CK</th><th>Matched events</th></tr></thead><tbody>{lab_rows}</tbody></table></div>
</div></details>

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
            self._json(list_alerts(self.db_path))
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

        body = render_dashboard(self.db_path).encode("utf-8")
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
