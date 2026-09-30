# Architecture

1. The command line accepts a saved Docker inspect JSON file.
2. `load_json()` accepts either one inspect object or Docker's list form.
3. `audit_container()` reads host, network, and container configuration fields.
4. Each matched rule produces a severity and message.
5. The command line prints the findings.
