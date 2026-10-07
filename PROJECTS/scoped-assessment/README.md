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

A crawl then follows the application's own links, because a scanner that tests three
paths tests the three paths somebody typed. What an application actually exposes is
what it links to, so the crawl walks them within the engagement, records every form
and its fields, and keeps a list of the links it deliberately did not follow. Links
whose path suggests they would change state -- `logout`, `delete`, `reset` and the
rest -- are recorded and skipped, because a crawler that follows every link it finds
will eventually follow a `?action=delete`, and an assessment that deleted a record
has caused the incident it was hired to find.

Eleven checks then ask the target questions it can answer badly:

- **Version disclosure** — the service names its own version, which is what lets
  somebody choose which vulnerabilities to try without sending a probing request.
- **Missing security headers** — no content policy, no type checking, no framing rule.
  One absence is a gap; four is a posture.
- **Insecure cookie** — a session cookie set without `Secure`, `HttpOnly` or `SameSite`,
  each of which closes a specific route to stealing the session.
- **Directory listing** — a folder that lists its contents, which turns guessing at
  file names into reading them.
- **Version control exposed** — a repository directory served as files, from which the
  source can be reconstructed one object at a time, including commits that were made
  and then reverted.
- **Dotfile exposed** — a configuration file readable over HTTP.
- **Dangerous method** — TRACE answered, which echoes a request back to whoever sent it.
- **Open redirect** — a parameter used as the redirect destination without being checked.
- **Error disclosure** — a failure that names a path on the server's disk.
- **Reflected input** — a parameter that comes back with its angle brackets intact.
- **Path traversal** — a file name joined to a document root with nothing confining the
  result to it.

Each finding carries the bytes that justify it. A finding without evidence is an
assertion, and the report shows the difference between what was observed and what was
concluded.

## Confirmed, and observed

Two words are kept apart throughout, because conflating them is how a scanner becomes
untrustworthy. A check *observes* something. A finding is *confirmed* only when a
second, independent observation distinguishes the flaw from a coincidence:

- the traversal returns a marker that exists only in the file outside the document root;
- the redirect's `Location` names a host that is not this one;
- the listing names an entry which the server then actually serves;
- the repository file's contents match the format of a git reference.

Some things cannot be confirmed and say so. The missing-header finding is an absence,
and there is no second observation of nothing, so it is reported as observed rather
than borrowing the confidence of the checks that can look again. The report prints
which is which, and the summary line counts them.

## How hard the target is pushed

An assessment tool that opens as many connections as it can is a denial-of-service
tool with a report attached. Being allowed to connect to a host is not permission to
hammer it, so the tool sets its own limits: a token bucket caps the request rate and a
bounded worker pool caps how many are in flight at once. Both are properties of the
whole engagement rather than of each phase, because a limit that reset between phases
would let a target be asked twice as often by splitting the work in two.

The report states the rate it used and how many requests it made, so the reader can
see the restraint rather than take it on trust.

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

`--no-crawl` tests only the known paths without following links. `--rate` and
`--workers` set the load limits, defaulting to ten requests a second with four in
flight; the CLI refuses a worker count above thirty-two, because more than that is not
a rate limit but an incident.

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

Eleven checks are eleven checks. They are the ones the lab is built to answer, and the
framework is a demonstration of scope enforcement and reporting rather than a
substitute for a real scanner's coverage. The crawl is a link follower with a regular
expression behind it, so a link built by JavaScript is invisible to it and the report
does not claim to have found what it cannot see.

No authentication, session handling or rate limiting is attempted, so an assessment of
a system that dislikes being scanned should be run with that in mind.
