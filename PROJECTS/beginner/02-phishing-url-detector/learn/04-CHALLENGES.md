# Challenges

- A benign URL can match a suspicious rule, so false positives are expected.
- HTTPS reduces transport risk but does not prove that a site is trustworthy.
- Attackers can use wording that is not present in the fixed term set.
- The project does not fetch pages, inspect content, or use reputation services.

## Working within the scope

The score is a heuristic, not a probability. Legitimate login pages can trigger rules, and a malicious page can use a short, ordinary HTTPS address. The tool does not inspect page content, redirects, certificates, domain age, or lookalike Unicode characters.

Compare `https://example.com/about` with `http://192.0.2.10/login/verify`, then change one part at a time. Removing HTTP or a suspicious word should change the score for a reason you can explain. That is more useful than treating the final label as a verdict.

[Back to the project guide](../README.md)
