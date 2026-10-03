# Phishing URL Detector

Paste in a URL and get back a small score with the reasons that produced it. That is the whole idea, and the reasons matter more than the number: a score you cannot explain is not much use when you are deciding whether to click something.

This is a rule-based scorer over the text of the URL. It is not a trained classifier, and a low score is not a guarantee of safety. It judges the string you give it and nothing else: nothing is submitted to a reputation service, nothing is fetched, and no URL is opened in a browser.

## Running it

No dependencies beyond the standard library. Pass one or more URLs:

```console
python -m src.detector "https://example.com/about"
python -m src.detector "https://example.com/about" "http://192.0.2.10/login/verify"
```

You can also read a list of URLs from a file or from standard input, one URL per line. Blank lines and lines starting with `#` are ignored:

```console
python -m src.detector -f urls.txt
python -m src.detector -f - < urls.txt
cat urls.txt | python -m src.detector
```

Add `--json` for machine-readable output and `-v`/`--verbose` to see every signal, including the ones that did not fire:

```console
python -m src.detector --json "http://xn--pypal-4ve.com/login"
python -m src.detector -v "http://paypa1.com/login/verify"
```

## Reading the result

Each URL is scored on its own and printed with its findings, a verdict, and a score band:

```
https://example.com/about
  Score: 0
  Verdict: low
  Result: Lower risk by these rules
  - no signals fired

http://192.0.2.10/login/verify
  Score: 5
  Verdict: medium
  Result: Potentially suspicious
  - does not use HTTPS
  - host is an IP address instead of a domain
  - contains suspicious terms: login, verify
```

Verbose mode names every check and says what it saw, whether or not it fired:

```
http://paypa1.com/login/verify
  Score: 6
  Verdict: high
  Result: High risk by these rules
  - does not use HTTPS
  - host looks like the brand behind paypal.com (edit distance 1)
  - contains suspicious terms: login, verify
  Signals:
    [+] Transport security (+1): does not use HTTPS
    [-] Host presence: host paypa1.com is present
    [-] Host form (domain vs IP): host paypa1.com is not an IP address
    ...
    [+] Brand resemblance (+3): host looks like the brand behind paypal.com (edit distance 1)
    [-] URL shortener: host is not a known URL shortener
    [+] Credential-harvesting words (+2): contains suspicious terms: login, verify
```

## What each signal looks for

Every signal is a stated number of points and a plain-English reason. A match never makes a URL malicious on its own.

| Signal | Points | What it notices |
| --- | --- | --- |
| Transport security | 1 | The scheme is not `https`. |
| Host presence | 2 | No hostname could be read. |
| Host form (domain vs IP) | 2 | The host is a raw IP address instead of a name. |
| URL length (long) | 1 | The URL is longer than 100 characters. |
| URL length (short) | 1 | The URL is 12 characters or fewer. |
| Subdomain depth | 1 | Three or more labels sit in front of the registrable domain. |
| Authority section | 2 | The authority contains `@`, which browsers read as credentials. |
| Port | 1 | The port is present and is not 80 or 443 (an unparseable port also counts). |
| Punycode label | 2 | A host label starts with `xn--`. The decoded form is shown when it can be recovered. |
| Lookalike characters | 3 | The host contains a non-ASCII character that resembles a Latin letter, such as a Cyrillic `a`. |
| Brand resemblance | 3 | The registrable domain looks like, or is a lookalike of, an embedded brand (edit distance up to 2, or the same name under another domain). The brand is named. |
| Brand away from its domain | 2 | A brand name appears in a subdomain or path while the registrable domain belongs to someone else. |
| Top-level domain | 1 | The TLD is on an embedded list of frequently abused TLDs (`.tk`, `.zip`, `.top`, and similar). |
| Doubled file extension | 3 | The path pairs a document extension with an executable or page one, such as `.pdf.exe` or `.docx.html`. |
| Percent-encoding | 1 | The path or query holds four or more `%xx` escapes. |
| URL shortener | 1 | The host is a known shortener such as `bit.ly`. |
| Credential-harvesting words | 1 or 2 | The host, path or query contains words like `login`, `verify`, `account`, `secure`, `update`, `wallet` or `signin` (two points from two distinct words). |

The score is the sum of the points of the signals that fired. It is capped in no other way, so a URL that trips many checks simply scores high.

## Verdict bands

| Score | Verdict | Result line |
| --- | --- | --- |
| 0-2 | `low` | Lower risk by these rules |
| 3-5 | `medium` | Potentially suspicious |
| 6 or more | `high` | High risk by these rules |

The band is a summary of the fired rules, not a probability. `medium` and `high` mean "several of these particular clues were present", and `low` means "few or none were", not "safe".

## Input handling

You do not need to type the scheme. `example.com` and `//example.com/about` are both treated as HTTP, which is what a browser would assume. A scheme is only recognised where a scheme can appear, at the very start of the string, so a URL that carries another URL in its query string is parsed correctly:

```
example.com/redirect?url=http://evil.com
  Score: 1
  Verdict: low
  Result: Lower risk by these rules
  - does not use HTTPS
```

Output is kept to ASCII: any non-ASCII character in a URL or reason is shown in its `\uXXXX` form, so the tool prints safely on any console.

## JSON output

`--json` prints one object with a `results` list and a `summary`. Each result carries the score, verdict, fired reasons and the findings behind them; `--json -v` adds a `signals` array with every check and its outcome. A URL that cannot be parsed appears with an `error` field, and the exit status is nonzero if any input was invalid.

## What it does not do

This is not a phishing classifier. It does not resolve DNS, follow redirects, inspect page content, check certificates or domain age, or consult a blocklist. The brand, TLD, shortener and lookalike lists are small and embedded, so they miss brands and TLDs that are not in them, and they can flag a legitimate site that merely resembles one. Edit distance can call a harmless name a typosquat. A score of zero means none of these particular clues fired, not that a link is safe. Treat the output as a second opinion on a decision you are still making yourself.

## Tests

```console
python -m pytest -q tests
```

Tests cover the documented examples, malformed input, scheme-less and protocol-relative URLs, a URL with `://` inside its path, each signal in isolation and on a clean URL, the verdict bands, batch input from a file and from standard input, JSON output, and verbose mode.
