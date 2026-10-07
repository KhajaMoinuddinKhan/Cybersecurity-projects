# Scoped assessment framework

An assessment tool whose first job is to refuse.

Everything it does is decided by an engagement file: which hosts, which ports, which
actions, and between which two moments. Anything outside that is refused, and the
refusal is written to an append-only log as it happens. What comes out the other end
is a report a client could read — scope, method, findings, evidence, severity,
business impact and remediation — rather than a list of ports.

The scope check is not a courtesy at the top of a run. It sits in front of every
connection, in one function, so there is no code path that reaches a target without
passing it. A scanner that checks its scope at the end has already done the thing it
was checking about.

## What it does

Reconnaissance opens a connection to each port the engagement lists and keeps what
the target says back. Fingerprinting reads the service name and version out of the
headers and the TLS handshake rather than out of a table of port numbers, because a
table would be this project's opinion about what runs on 8080 and the point of
fingerprinting is to find out.

Three checks then ask the target questions it can answer badly:

- **Version disclosure** — the service names its own version, which is what lets
  somebody choose which vulnerabilities to try without sending a probing request.
- **Reflected input** — a parameter comes back in the page with its angle brackets
  and quotes intact. That is the raw material of cross-site scripting; whether it is
  exploitable depends on the page and the browser, which the check does not decide.
- **Path traversal** — a file name is joined to a document root and read with nothing
  confining the result to that root, so a sequence of parent references reaches files
  the service was never meant to serve.

Each finding carries the bytes that justify it. A finding without evidence is an
assertion, and the report shows the difference between what was observed and what was
concluded.

Exploitation stops at demonstration. The traversal reads the one file the lab placed
outside its document root and nothing else: no shell, no payload, no attempt to go
further. The framework is for assessing a system you own, and the part that matters is
the evidence and the write-up.

## CVSS, computed rather than copied

A report that states a severity has to be able to defend it. The framework takes the
CVSS v3.1 vector NVD publishes for a CVE and computes the base score itself, then
records both — so a reader can see that the number is arithmetic on a published vector
rather than a number copied out of a feed and trusted. Where the two disagree the
report says so instead of choosing.

`tests/test_cvss.py` checks the implementation against NVD's own scores across sixteen
real CVEs, chosen to span every severity band and both halves of the Scope branch,
which is where the base equation is easiest to get wrong. The vectors are NVD's;
nothing in that file was written here. This is the same differential approach the
cryptography toolkit uses, for the same reason: an implementation that agrees with its
own test vectors has proved only that it is self-consistent.

## The lab

`lab/` is a small application that is deliberately vulnerable, and it is what the
tests run against. Each flaw is placed, documented and mapped to the CVE whose
behaviour it imitates, so the report has something real to report and the framework
has something real to measure itself against. It binds to loopback and refuses to bind
anywhere else — that refusal is a check, not a comment, because a deliberately
vulnerable server a network can reach is a liability rather than a lab.

## An engagement file

```yaml
engagement: Loopback lab assessment

targets:
  - host: 127.0.0.1
    ports: [8099]

allowed_actions:
  - connect

window:
  start: 2020-01-01T00:00:00+00:00
  end: 2030-01-01T00:00:00+00:00
```

The defaults refuse. A host that is not named is not permitted, a port that is not
listed is not permitted, an action that is not allowed is not permitted, and a moment
outside the window is not permitted. Nothing is permitted by being absent from a deny
list, because a deny list can only ever be as complete as the person who wrote it.

A target must be named as the address it is. Host names are refused even when they
resolve inside the engagement, because a name can be repointed after the file was
written, and a scope engine that resolves names can be aimed at something the
engagement never named.

Omitting the window leaves the engagement unlimited in time. That is the one field
whose absence cannot widen what is reachable, only when.

## Running it

```
python -m src.cli --scope examples/lab-engagement.yaml --out assessment-output
```

`--cves` additionally asks NVD about the versions the targets report, and caches the
answers so a report can be regenerated without the feed being up. The output is
`report.md`, `report.html` and the audit log; the HTML is a single self-contained page
with no stylesheet, no font and no script, because a report about a client's security
posture should not make a request to anybody when it is opened.

## What the tool declined to do

Every decision the scope engine makes is written to `audit.jsonl` as it happens, not
summarised at the end, so a crash mid-engagement does not lose the record of what was
attempted. The report carries the refusals in their own section. A refusal that is not
recorded is indistinguishable from an action that never happened, and the record of
what a tool declined to do is the part an engagement's client actually wants to see.

## Limits

The CVE mapping is a keyword lookup, so it is a lead rather than a verdict: the report
says NVD returned these CVEs for this product and version, not that the target is
certainly affected. Anything stronger needs version comparison this framework does not
attempt, and pretending otherwise would be the same overreach as a scanner that calls
itself a zero-day finder.

The three checks are three checks. They are the ones the lab is built to answer, and
the framework is a demonstration of scope enforcement and reporting rather than a
substitute for a real scanner's coverage.

No authentication, session handling or rate limiting is attempted, so an assessment of
a system that dislikes being scanned should be run with that in mind.
