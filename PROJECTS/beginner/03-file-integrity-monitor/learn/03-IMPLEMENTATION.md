# Implementation

- `sha256_file()` reads files in one-megabyte chunks.
- `build_baseline()` sorts discovered paths so the saved data is stable.
- `save_baseline()` writes formatted JSON and `load_baseline()` checks the top-level structure.
- `compare_baseline()` compares hashes for existing files and separately finds new and missing paths.
