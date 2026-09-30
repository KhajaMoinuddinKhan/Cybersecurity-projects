# Implementation

- `URLResult` stores the score, label, and explanation list.
- `ipaddress.ip_address()` distinguishes IP hosts from domain names.
- Regular expressions match whole suspicious words instead of loose substrings.
- Subdomain depth is checked only for domain names, not dotted IP addresses.
- The scoring rules stay in one function so a reader can trace how the result was produced.
