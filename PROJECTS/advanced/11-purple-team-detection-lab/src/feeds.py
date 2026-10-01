"""Fetch configured CSV/JSON threat-intelligence feeds."""
from __future__ import annotations
import csv, io, json, os
from urllib.request import Request, urlopen
from .storage import import_iocs

VALID_TYPES={"ip","domain","hash","url"}

def configured_urls() -> list[str]: return [u.strip() for u in os.getenv("PURPLE_THREAT_FEED_URLS", "").split(",") if u.strip()]

def parse_feed(content: bytes, name: str) -> list[tuple[str,str,str]]:
    text=content.decode("utf-8-sig"); source=name
    if name.lower().endswith(".json") or text.lstrip().startswith("["):
        data=json.loads(text)
        if isinstance(data,dict): data=data.get("indicators",data.get("data",[]))
        if not isinstance(data,list): raise ValueError("Threat feed JSON must be a list")
        rows=[(str(x.get("type","")),str(x.get("value","")),str(x.get("source") or source)) for x in data if isinstance(x,dict)]
    else:
        rows=[(str(r.get("type","")),str(r.get("value","")),str(r.get("source") or source)) for r in csv.DictReader(io.StringIO(text))]
    clean=[]
    for kind,value,origin in rows:
        if kind.strip().lower() in VALID_TYPES and value.strip(): clean.append((kind.strip().lower(),value.strip(),origin.strip() or source))
    return clean

def refresh_feeds(db_path):
    results=[]
    for url in configured_urls():
        request=Request(url,headers={"User-Agent":"PurpleTeamDetectionLab/1.0"})
        with urlopen(request,timeout=15) as response: rows=parse_feed(response.read(5_000_001),url)
        results.append({"url":url,"read":len(rows),"inserted":import_iocs(db_path,rows)})
    return results
