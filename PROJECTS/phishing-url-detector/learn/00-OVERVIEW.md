# Overview

Phishing URL Detector gives a URL a simple risk score based on visible URL properties. It checks the scheme, hostname form, URL length, subdomain depth, authority text, and credential-themed words, then prints the reasons behind the score.

## A useful first exercise

Compare `https://example.com/about` with `http://192.0.2.10/login/verify`, then change one part at a time. Removing HTTP or a suspicious word should change the score for a reason you can explain. That is more useful than treating the final label as a verdict.

The score is a heuristic, not a probability. Legitimate login pages can trigger rules, and a malicious page can use a short, ordinary HTTPS address. The tool does not inspect page content, redirects, certificates, domain age, or lookalike Unicode characters.

[Back to the project guide](../README.md)
