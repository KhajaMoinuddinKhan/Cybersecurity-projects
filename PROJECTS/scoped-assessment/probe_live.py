
import sys, os, tempfile
sys.path.insert(0, r"C:\Users\Khan's\Documents\Cybersecurity-projects\PROJECTS\scoped-assessment")
from lab import LabServer
from src.cli import run_engagement
from src.assessment import CHECKS, CONFIRMABLE

print("registry: %d checks, %d confirmable" % (len(CHECKS), len(CONFIRMABLE)))
with LabServer(port=0) as lab:
    out = tempfile.mkdtemp()
    eng = os.path.join(out, "engagement.json")
    open(eng, "w").write('{"engagement":"Loopback lab assessment",'
                         '"targets":[{"host":"127.0.0.1","ports":[%d]}],'
                         '"allowed_actions":["connect"]}' % lab.port)
    doc = run_engagement(eng, out, rate=50.0, workers=4)
    print("\n%d findings, %d confirmed" % (doc["total"], doc["confirmed"]))
    for f in doc["findings"]:
        print("   %-8s %-9s %s" % (f["severity"],
              "CONFIRMED" if f["confirmed"] else "observed", f["title"][:56]))
    print("\ncrawl: %d pages, %d endpoints, %d not followed"
          % (doc["crawl"]["pages_read"], len(doc["crawl"]["endpoints"]),
             doc["crawl"]["not_followed"]))
    print("paths:", sorted({e["path"] for e in doc["crawl"]["endpoints"]}))
    print("not followed:", [s["url"].split(str(lab.port))[-1] for s in doc["crawl"]["skipped"]])
