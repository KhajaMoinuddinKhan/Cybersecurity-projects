# Overview

Cloud Asset Inventory reads a synthetic JSON asset export and prints the resources it contains. It flags assets marked public, missing Owner or Environment tags, malformed tag data, and missing region information.

## A useful first exercise

Run the bundled fixture and note which resources lack ownership, environment, or region information. Add those fields in a copy and compare the findings. Leave the public flag alone unless the underlying exposure actually changed; editing inventory metadata does not change cloud configuration.

The program does not authenticate to a cloud provider or discover resources. It reviews only the data you give it, which can be incomplete or out of date. A public flag does not describe actual firewall reachability, and a populated tag can still contain incorrect information. Global resources may legitimately need a different region policy.

[Back to the project guide](../README.md)
