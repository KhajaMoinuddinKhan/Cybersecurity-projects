# Implementation

Protocol detection checks TCP before UDP and falls back to IP or OTHER. DNS names are decoded with replacement for malformed bytes and trailing dots are normalized. Top lists are capped for readability, while the packet total still covers the complete capture.

The JSON output uses string keys for destination ports so it can be consumed consistently by JavaScript and other JSON tools.
