
import sys, os, tempfile
sys.path.insert(0, r"C:\Users\Khan's\Documents\Cybersecurity-projects\PROJECTS\scoped-assessment")
from lab import LabServer
from src.cli import run_engagement

with LabServer(port=0) as lab:
    out = tempfile.mkdtemp()
    eng = os.path.join(out, "engagement.json")
    open(eng, "w").write('{"engagement":"Loopback lab assessment",'
                         '"targets":[{"host":"127.0.0.1","ports":[%d]}],'
                         '"allowed_actions":["connect"]}' % lab.port)
    doc = run_engagement(eng, out, rate=50.0, workers=4)
    print("%s: %d finding(s), %d confirmed" % (doc["engagement"], doc["total"], doc["confirmed"]))
    for f in doc["findings"]:
        print("   %-8s %-7s %s" % (f["severity"], "CONFIRMED" if f["confirmed"] else "observed",
                                   f["title"][:58]))
    print("\ncrawl: %d pages, %d endpoints, %d links not followed"
          % (doc["crawl"]["pages_read"], len(doc["crawl"]["endpoints"]),
             doc["crawl"]["not_followed"]))
    print("endpoints:", [e["path"] for e in doc["crawl"]["endpoints"]])
    print("not followed:", [(s["url"], s["reason"]) for s in doc["crawl"]["skipped"]])
    print("throttle:", doc["throttle"])
    md = open(os.path.join(out,"report.md"), encoding="utf-8").read()
    print("\nreport.md %d bytes, report.html %d bytes"
          % (len(md), len(open(os.path.join(out,"report.html"), encoding="utf-8").read())))
    print("\n=== summary + crawl sections ===")
    i = md.find("## Summary"); j = md.find("## Services observed")
    print(md[i:j][:900])
