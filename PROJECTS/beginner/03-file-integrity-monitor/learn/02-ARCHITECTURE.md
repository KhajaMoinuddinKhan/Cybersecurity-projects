# Architecture

1. Create mode walks the target folder and hashes each file.
2. The baseline is saved as JSON with each relative path, hash, and size.
3. Compare mode loads the saved baseline and builds a fresh view of the folder.
4. `compare_baseline()` compares both views and returns sorted change records.
5. The command line prints the detected changes.

## Follow one run

`sha256_file()` reads one-megabyte chunks so a large individual file does not have to fit in memory. `build_baseline()` records relative paths, hashes, and sizes in a stable order. The comparison builds a fresh inventory and checks both directions so deleted files are not missed. Baseline loading validates each stored digest before comparison.

Create a folder called `watched` and put a few files in it before running the commands. The first command records their current contents; the second compares them with that saved state. The baseline path is relative to your terminal directory unless you provide an absolute path.

[Back to the project guide](../README.md)
