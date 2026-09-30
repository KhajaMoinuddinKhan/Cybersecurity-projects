# Architecture

1. The command line accepts a synthetic asset JSON file.
2. `load_assets()` checks the top-level structure and each asset record.
3. `review_assets()` walks the assets and applies the configured rules.
4. The command line prints the inventory before the findings.
5. Each finding includes a severity, asset name, and message.
