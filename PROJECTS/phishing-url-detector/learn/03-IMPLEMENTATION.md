# Implementation

- `URLResult` stores the score, label, and explanation list.
- `ipaddress.ip_address()` distinguishes IP hosts from domain names.
- Regular expressions match whole suspicious words instead of loose substrings.
- Subdomain depth is checked only for domain names, not dotted IP addresses.
- The scoring rules stay in one function so a reader can trace how the result was produced.

## Inputs and failure handling

Pass one or more quoted URLs on the command line. Quotes keep characters such as `&` from being interpreted by your shell. The detector works offline: it does not resolve the host, open the page, or send the URL to a reputation service. Inputs without a scheme are treated as HTTP.

Malformed addresses, such as an unmatched IPv6 bracket, are reported individually. The command continues checking later inputs and exits with a nonzero status if any URL could not be parsed. Review the hostname yourself before visiting an unfamiliar address.

[Back to the project guide](../README.md)
