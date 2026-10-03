# Implementation

- `SignalOutcome` records one check: its machine name, a title, whether it fired, the points it awarded, and a detail sentence. `URLResult` collects the score, the verdict, the fired reasons, the fired findings, and all outcomes.
- `ipaddress.ip_address()` distinguishes IP hosts from domain names, and `registrable_domain()` strips subdomains while respecting a small set of two-label suffixes such as `co.uk`.
- `levenshtein()` computes edit distance with a rolling row, and `homoglyph_normalise()` maps lookalike characters back to the Latin letters they imitate. `decode_punycode_label()` turns an `xn--` label back into Unicode with the standard `idna` codec.
- `find_typosquat()` compares the registrable label against the embedded brand list: an exact name under another domain, a homoglyph or punycode lookalike, or an edit distance of one or two. Real brand domains are exempted.
- Regular expressions match whole suspicious words instead of loose substrings, and a separate pattern catches a document extension in front of an executable one.
- `ascii_safe()` escapes non-ASCII text so reasons print safely on any console, and JSON output relies on the encoder's own escaping.
- The scoring rules stay in one function, `evaluate_url()`, so a reader can trace how the result was produced.

## Inputs and failure handling

Pass one or more quoted URLs on the command line, read a list with `-f file`, `-f -` for standard input, or pipe URLs in with no arguments. Quotes keep characters such as `&` from being interpreted by your shell. Blank lines and lines starting with `#` are skipped. The detector works offline: it does not resolve the host, open the page, or send the URL to a reputation service. Inputs without a scheme are treated as HTTP.

Malformed addresses, such as an unmatched IPv6 bracket, are reported individually. In text mode they go to standard error, in JSON mode they appear with an `error` field, and the command exits with a nonzero status if any URL could not be parsed. Later inputs are still checked. Review the hostname yourself before visiting an unfamiliar address.

[Back to the project guide](../README.md)
