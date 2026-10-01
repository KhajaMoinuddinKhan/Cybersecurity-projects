# Architecture

1. The command line accepts a synthetic asset JSON file.
2. `load_assets()` checks the top-level structure and each asset record.
3. `review_assets()` walks the assets and applies the configured rules.
4. The command line prints the inventory before the findings.
5. Each finding includes a severity, asset name, and message.

## Follow one run

`load_assets()` checks the top-level structure and ensures every asset is an object. `review_assets()` applies the small configured rule set. Tag data that is not an object produces an explicit finding and is treated as missing metadata for the remaining checks, rather than crashing the entire review.

The file must contain an object with an `assets` list. Each asset is an object that can include `provider`, `type`, `name`, `public`, `region`, and `tags`. Use a JSON boolean for `public` and an object for tags. The bundled file contains synthetic training data; an actual export must be mapped into this schema before use.

[Back to the project guide](../README.md)
