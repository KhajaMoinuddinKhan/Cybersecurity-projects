
import sys, json, urllib.request
sys.path.insert(0, r"C:\Users\Khan's\Documents\Cybersecurity-projects\PROJECTS\scoped-assessment")
from src.cpe import parse_cpe, matches, compare_versions

# real NVD data for CVE-2021-41773 (Apache httpd 2.4.49)
url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-41773"
req = urllib.request.Request(url, headers={"User-Agent": "cpe-check"})
cve = json.loads(urllib.request.urlopen(req, timeout=45).read().decode())["vulnerabilities"][0]["cve"]
configs = cve.get("configurations")

cases = [
    ("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", True,  "the exact affected version"),
    ("cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*", False, "the version after the fix"),
    ("cpe:2.3:a:apache:http_server:2.4.48:*:*:*:*:*:*:*", False, "the version before"),
    ("cpe:2.3:o:fedoraproject:fedora:34:*:*:*:*:*:*:*",   True,  "a platform NVD also lists"),
    ("cpe:2.3:a:nginx:nginx:1.21.0:*:*:*:*:*:*:*",        False, "a different product"),
]
print("=== my matcher against the real configurations block ===")
for cpe, expected, why in cases:
    got = matches(configs, parse_cpe(cpe))
    print("  %-5s %-52s %s" % ("OK" if got == expected else "WRONG", why, got))

print("\n=== version ordering ===")
for a, b, expected in (("2.4.49","2.4.50",-1), ("2.10","2.9",1), ("1.2.1","1.2",1),
                       ("1.0.2k","1.0.2",1), ("1.0.2","1.0.3",-1), ("1.0","1.0",0)):
    got = compare_versions(a,b)
    print("  %-5s %-10s vs %-10s -> %s" % ("OK" if got==expected else "WRONG", a, b, got))
