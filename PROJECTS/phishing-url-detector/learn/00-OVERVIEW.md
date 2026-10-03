# Overview

Phishing URL Detector gives a URL a simple risk score based on visible URL properties. It checks the scheme, hostname form, URL length in both directions, subdomain depth, authority text, port, credential-themed words, punycode and lookalike characters, typosquatting against a small brand list, brands parked in a subdomain or path, the top-level domain, doubled file extensions, heavy percent-encoding, and known shorteners. Every check records a reason, and the total falls into a low, medium or high band.

## A useful first exercise

Compare `https://example.com/about` with `http://192.0.2.10/login/verify`, then change one part at a time. Removing HTTP or a suspicious word should change the score for a reason you can explain. Then try `http://paypa1.com/login/verify` and `http://xn--pypal-4ve.com/login`, where the host is a near miss or a lookalike for a real brand. Reading the named reasons is more useful than treating the final band as a verdict.

Run the tool with `-v` to see every check, including the ones that did not fire, and with `--json` when you want the same information as data.

The score is a heuristic, not a probability. Legitimate login pages can trigger rules, and a malicious page can use a short, ordinary HTTPS address. The brand, TLD and shortener lists are small and embedded, so the tool misses names that are not in them and can flag a site that merely resembles one. It does not inspect page content, redirects, certificates, or domain age, and it never makes a network request.

[Back to the project guide](../README.md)
