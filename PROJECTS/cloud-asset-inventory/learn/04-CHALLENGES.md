# Challenges

- The project reads a synthetic export and does not connect to live cloud accounts.
- A public flag needs service-specific context before it can be judged as a real risk.
- Tag presence does not prove that metadata is correct.
- The rule set covers a small set of inventory and governance checks.

## Working within the scope

The program does not authenticate to a cloud provider or discover resources. It reviews only the data you give it, which can be incomplete or out of date. A public flag does not describe actual firewall reachability, and a populated tag can still contain incorrect information. Global resources may legitimately need a different region policy.

Run the bundled fixture and note which resources lack ownership, environment, or region information. Add those fields in a copy and compare the findings. Leave the public flag alone unless the underlying exposure actually changed; editing inventory metadata does not change cloud configuration.

[Back to the project guide](../README.md)
