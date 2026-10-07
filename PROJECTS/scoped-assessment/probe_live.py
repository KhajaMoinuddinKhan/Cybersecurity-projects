
import sys, json, tempfile, os
sys.path.insert(0, r"C:\Users\Khan's\Documents\Cybersecurity-projects\PROJECTS\scoped-assessment")
from lab import LabServer
from src.cli import run_engagement
from src.scope import load_scope

with LabServer(port=8099) as lab:
    print("the lab is listening on", lab.base_url)
    out = tempfile.mkdtemp()
    doc = run_engagement(r"C:\Users\Khan's\Documents\Cybersecurity-projects\PROJECTS\scoped-assessment\examples\lab-engagement.yaml",
                         out, lookup_cves=False)
    print("\n%s: %d finding(s)" % (doc["engagement"], doc["total"]))
    for f in doc["findings"]:
        print("   %-10s %-52s %s:%d" % (f["severity"], f["title"][:52], f["host"], f["port"]))
    print("refusals:", doc["refusal_count"])
    print("\nservices observed:")
    for s in doc["services"]:
        print("   %s:%d open=%s service=%s" % (s["host"], s["port"], s["open"], s["name"]))
    md = open(os.path.join(out,"report.md"), encoding="utf-8").read()
    print("\nreport.md is %d bytes; report.html is %d bytes"
          % (len(md), len(open(os.path.join(out,"report.html"), encoding="utf-8").read())))
    print("\n--- the first 1500 characters of the report ---")
    print(md[:1500])
