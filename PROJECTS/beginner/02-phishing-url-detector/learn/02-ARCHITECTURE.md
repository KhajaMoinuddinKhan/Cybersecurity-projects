# Architecture

1. The command line accepts one or more URLs.
2. `normalise_url()` adds a default scheme when the input omits one.
3. `urlparse()` separates the URL into fields.
4. `score_url()` applies each visible rule and records its reasons.
5. The command line prints the score, label, and reasons for every URL.
