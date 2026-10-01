# Implementation

- `sha256_file()` reads files in one-megabyte chunks.
- `build_baseline()` sorts discovered paths so the saved data is stable.
- `save_baseline()` writes formatted JSON and `load_baseline()` checks the top-level structure.
- `compare_baseline()` compares hashes for existing files and separately finds new and missing paths.

## Inputs and failure handling

Create a folder called `watched` and put a few files in it before running the commands. The first command records their current contents; the second compares them with that saved state. The baseline path is relative to your terminal directory unless you provide an absolute path.

Use `--create` only when you intend to accept the current files as the new baseline; it overwrites the chosen baseline file. Keep a trusted copy separate from the data being monitored. Fix file-access or invalid-baseline errors before treating a comparison as complete.

[Back to the project guide](../README.md)
