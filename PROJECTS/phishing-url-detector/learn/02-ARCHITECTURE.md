# Architecture

1. The command line accepts URLs as arguments, from a file (`-f`), or from standard input.
2. `normalise_url()` adds a default scheme when the input omits one.
3. `urlparse()` separates the URL into fields, and `registrable_domain()` works out the domain the URL really belongs to.
4. `evaluate_url()` runs every signal and records the outcome of each, whether it fired or not.
5. `score_url()` sums the points of the fired signals, picks a verdict band, and keeps the reasons.
6. The command line prints each result as text, or as JSON when `--json` is given.

## Follow one run

`urlparse()` separates the address into components. The detector checks HTTPS use, missing or IP-based hosts, length in both directions, subdomain depth, `@` in the authority, the port, punycode labels, lookalike characters, brand resemblance, brands away from their domain, the top-level domain, doubled file extensions, percent-encoding, known shorteners, and credential-themed words. Each matching check adds a stated number of points and a human-readable reason, and each outcome is kept so `-v` can show the checks that stayed quiet too.

`URLResult` keeps the score, the verdict and its label, the fired reasons, the fired findings, and every outcome together. `SignalOutcome` holds one check's name, its title, whether it fired, the points it awarded, and a sentence explaining what it saw.

Pass one or more quoted URLs on the command line, name a file with `-f`, or pipe URLs on standard input. Quotes keep characters such as `&` from being interpreted by your shell. The detector works offline: it does not resolve the host, open the page, or send the URL to a reputation service. Inputs without a scheme are treated as HTTP.

[Back to the project guide](../README.md)
