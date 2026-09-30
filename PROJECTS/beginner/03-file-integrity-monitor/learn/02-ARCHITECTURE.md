# Architecture

1. Create mode walks the target folder and hashes each file.
2. The baseline is saved as JSON with each relative path, hash, and size.
3. Compare mode loads the saved baseline and builds a fresh view of the folder.
4. `compare_baseline()` compares both views and returns sorted change records.
5. The command line prints the detected changes.
