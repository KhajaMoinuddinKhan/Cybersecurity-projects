"""Optional real alert notification webhook."""
from __future__ import annotations
import json, os
from urllib.request import Request, urlopen

def send_alerts(alerts, timeout=10):
    url=os.getenv("PURPLE_ALERT_WEBHOOK_URL")
    if not url or not alerts: return {"sent":False,"reason":"PURPLE_ALERT_WEBHOOK_URL is not configured"}
    payload={"source":"purple-team-detection-lab","alerts":[{"rule_id":a.rule_id,"title":a.title,"severity":a.severity,"technique_id":a.technique_id,"event_ids":list(a.event_ids),"host":a.host,"user":a.user,"source":a.source} for a in alerts]}
    request=Request(url,data=json.dumps(payload).encode(),headers={"Content-Type":"application/json","User-Agent":"PurpleTeamDetectionLab/1.0"},method="POST")
    with urlopen(request,timeout=timeout) as response: return {"sent":True,"status":response.status}
