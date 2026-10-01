# Concepts

- A URL is split into a scheme, host, path, query, and authority section.
- Plain HTTP does not provide the transport protection expected from HTTPS.
- Raw IP hosts, deep subdomains, and an `@` character can make a destination harder to judge at a glance.
- Credential-themed words can raise suspicion when they appear in a host, path, or query.
- A heuristic score is an explanation aid, not a final verdict on a site.

## Interpreting the evidence

The first example scores zero under these rules. The second adds points for HTTP, an IP-address host, and credential-themed words. A score of three or more receives the label `Potentially suspicious`. A lower score means fewer matching clues; it does not mean the destination is safe.

The score is a heuristic, not a probability. Legitimate login pages can trigger rules, and a malicious page can use a short, ordinary HTTPS address. The tool does not inspect page content, redirects, certificates, domain age, or lookalike Unicode characters.

[Back to the project guide](../README.md)
