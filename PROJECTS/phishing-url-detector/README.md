# Phishing URL Detector

Paste in a URL and get back a small score with the reasons that produced it. That is the whole idea, and the reasons matter more than the number: a score you cannot explain is not much use when you are deciding whether to click something.

The checks are deliberately simple and local. Nothing is submitted to a reputation service, nothing is fetched, and no URL is opened in a browser.

## Running it

No dependencies beyond the standard library. Pass one or more URLs:

```console
python -m src.detector "https://example.com/about"
python -m src.detector "https://example.com/about" "http://192.0.2.10/login/verify"
```

## Reading the result

Each URL is scored on its own and printed with its findings:

```
https://example.com/about
  Score: 0
  Result: Lower risk by these rules

http://192.0.2.10/login/verify
  Score: 5
  Result: Potentially suspicious
  - does not use HTTPS
  - host is an IP address instead of a domain
  - contains suspicious terms: login, verify
```

The clues it looks for are the cheap ones that catch a lot of low-effort attempts: plain HTTP, a raw IP address where a domain name belongs, words like `login`, `verify` or `password` in the path, excessive subdomains, and similar patterns. Each clue adds to the score and is named in the output, so you can disagree with a specific reason instead of arguing with a verdict.

## Input handling

You do not need to type the scheme. `example.com` and `//example.com/about` are both treated as HTTP, which is what a browser would assume. A scheme is only recognised where a scheme can appear, at the very start of the string, so a URL that carries another URL in its query string is parsed correctly:

```
example.com/redirect?url=http://evil.com
  Score: 1
  Result: Lower risk by these rules
  - does not use HTTPS
```

## What it does not do

This is not a phishing classifier. It does not resolve DNS, follow redirects, inspect page content, or check a blocklist, and it has no idea whether a domain was registered last week. A score of zero means none of these particular clues fired, not that a link is safe. Treat the output as a second opinion on a decision you are still making yourself.

## Tests

```console
python -m pytest -q tests
```

Tests cover the documented examples, malformed input, scheme-less and protocol-relative URLs, and a URL with `://` inside its path.
