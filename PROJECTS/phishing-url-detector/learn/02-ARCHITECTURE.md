# Architecture

1. The command line accepts one or more URLs.
2. `normalise_url()` adds a default scheme when the input omits one.
3. `urlparse()` separates the URL into fields.
4. `score_url()` applies each visible rule and records its reasons.
5. The command line prints the score, label, and reasons for every URL.

## Follow one run

`urlparse()` separates the address into components. The detector checks HTTPS use, missing or IP-based hosts, overall length, subdomain depth, `@` in the authority, and words such as login or verify. Each matching check adds a stated number of points and a human-readable reason. `URLResult` keeps the score and its explanation together.

Pass one or more quoted URLs on the command line. Quotes keep characters such as `&` from being interpreted by your shell. The detector works offline: it does not resolve the host, open the page, or send the URL to a reputation service. Inputs without a scheme are treated as HTTP.

[Back to the project guide](../README.md)
