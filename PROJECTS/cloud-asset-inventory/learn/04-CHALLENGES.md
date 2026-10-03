# Challenges

- The project reads exports and does not connect to live cloud accounts, so the inventory is only as current as the files.
- Auto-detection is structural: an empty list, or a document that happens to use one of the recognised keys for something else, defaults to the generic shape.
- A public or encryption flag needs service-specific context before it can be judged as a real risk; an absent flag is unknown, not safe.
- Tag presence does not prove that metadata is correct, and the storage markers are a heuristic over the resource-type string.
- The rule set covers a small set of inventory and governance checks.

## Working within the scope

The program does not authenticate to a cloud provider or discover resources. It reviews only the data you give it, which can be incomplete or out of date. A public flag does not describe actual firewall reachability, and a populated tag can still contain incorrect information. The GCP exposure check is a literal member test for `allUsers` and `allAuthenticatedUsers`; it does not evaluate conditions or inherited policy. Severity is a review priority, not a modelled risk score. The tool also does not deduplicate across files, so a resource present in two exports is listed twice.

Run the bundled fixtures and note which resources lack ownership, environment, or region information and which are marked public or unencrypted. Fix one field in a copy and compare the findings. Leave the public flag alone unless the underlying exposure actually changed; editing inventory metadata does not change cloud configuration.

[Back to the project guide](../README.md)
