# Concepts

- A URL is split into a scheme, host, path, query, and authority section.
- Plain HTTP does not provide the transport protection expected from HTTPS.
- Raw IP hosts, deep subdomains, an `@` character, and a non-standard port can make a destination harder to judge at a glance.
- A punycode label begins with `xn--`; the same name can also be written directly in Unicode, where characters from other scripts stand in for Latin letters.
- Typosquatting is a near miss on a real name. Edit distance measures how many single-character changes separate two strings, so `paypa1` sits one edit from `paypal`.
- The registrable domain is the last label plus its public suffix, so `login.example.co.uk` has the registrable domain `example.co.uk`. A brand name in a subdomain or path, while the registrable domain belongs to someone else, is a common trick.
- A verdict band summarises the fired rules; it is a label on a heuristic, not a probability.

## Interpreting the evidence

The first example scores zero under these rules. The second adds points for HTTP, an IP-address host, and credential-themed words, and lands in the medium band. A third example such as `http://paypa1.com/login/verify` adds the brand-resemblance signal and reaches the high band. A lower score means fewer matching clues; it does not mean the destination is safe.

**Points are not probabilities.** Adding the weights of the signals that fired produces a number that orders URLs against each other under this rule set. It says nothing about the chance that a given URL is malicious, and the bands are thresholds on that ordering rather than calibrated risks. Two consequences follow, and both matter in practice: a legitimate sign-in page on an unfamiliar domain can score as high as a phishing page, and a phishing page hosted on a clean, short, well-established HTTPS address can score zero.

[Back to the project guide](../README.md)
