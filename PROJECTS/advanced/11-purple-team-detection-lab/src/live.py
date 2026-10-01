"""Live ingestion pipeline shared by HTTP and command-line entry points."""
from __future__ import annotations
from datetime import timezone
from .event_io import load_rules
from .engine import run_detection
from .models import Alert, SecurityEvent
from .storage import append_events, find_iocs, list_events, save_alerts

def _values(event: SecurityEvent):
    values=[event.source,event.user,event.host,event.event_type]
    def walk(value):
        if isinstance(value,dict):
            for v in value.values(): walk(v)
        elif isinstance(value,(str,int,float)): values.append(str(value))
    walk(event.data); return values

def ingest(db_path, rules_path, payloads):
    if not isinstance(payloads,list) or not all(isinstance(p,dict) for p in payloads): raise ValueError("Send a list of event objects")
    events=[SecurityEvent.from_dict(item) for item in payloads]
    inserted=append_events(db_path,events)
    stored=[]
    for row in list_events(db_path,5000):
        from datetime import datetime
        stored.append(SecurityEvent(row['event_id'],datetime.fromisoformat(row['timestamp']),row['event_type'],row['source'],row['username'],row['host'],row['data']))
    alerts=run_detection(stored,load_rules(rules_path))
    matches=[]
    for event in events:
        for kind,value,source in find_iocs(db_path,_values(event)):
            matches.append(Alert(f"TI-{kind.upper()}",f"Threat-intelligence match: {value}",f"Incoming event value matched an indicator from {source}.","High","T1588","Obtain Capabilities", event.timestamp,event.timestamp,value,(event.event_id,),event.host,event.user,event.source))
    new_ids={event.event_id for event in events}
    all_alerts=[a for a in alerts if new_ids.intersection(a.event_ids)] + matches
    saved=save_alerts(db_path,all_alerts)
    return {"accepted":inserted,"alerts_created":saved,"threat_matches":len(matches),"_alerts":all_alerts}
