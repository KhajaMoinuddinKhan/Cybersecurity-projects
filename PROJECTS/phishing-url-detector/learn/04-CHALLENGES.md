# Challenges

- A benign URL can match a suspicious rule, so false positives are expected.
- HTTPS reduces transport risk but does not prove that a site is trustworthy.
- Attackers can use wording that is not present in the fixed term set.
- The brand, TLD and shortener lists are small and embedded, so they go stale and miss anything not in them.
- Edit distance cannot tell a typo from a deliberately different name, and it can call a harmless domain a typosquat.
- The homoglyph map covers the common confusable characters, not every Unicode character that can resemble a letter.
- The thresholds for length, subdomain depth and percent-encoding are fixed cut-offs, not tuned values.
- The project does not fetch pages, inspect content, or use reputation services.

## Working within the scope

The score is a heuristic, not a probability. Legitimate login pages can trigger rules, and a malicious page can use a short, ordinary HTTPS address. The tool does not inspect page content, redirects, certificates, domain age, or the full set of lookalike characters.

Compare `https://example.com/about` with `http://192.0.2.10/login/verify`, then change one part at a time. Removing HTTP or a suspicious word should change the score for a reason you can explain. Then try a near-miss host such as `paypa1.com` and a punycode host such as `xn--pypal-4ve.com` and read which brand the tool says each one resembles. That is more useful than treating the final band as a verdict.

[Back to the project guide](../README.md)
