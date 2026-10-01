# Challenges

- `rdpcap()` loads the capture before the analyzer summarizes it, so very large files can use substantial memory.
- Encrypted traffic hides application content from this project.
- Packets outside the handled protocols fall back to a general category.
- A statistical summary gives context, but it does not decide whether traffic is malicious.

## Working within the scope

This is a traffic summary, not an intrusion detector. A busy host or unusual port needs context before you can call it suspicious. Encrypted application content stays encrypted, and DNS names are available only when the capture exposes them. Scapy loads the capture into memory, so large captures may need to be split before analysis.

Start with a capture containing one DNS question and its reply. Expect two packets but one DNS query. Add a TCP connection and check that its destination port appears separately. This makes it easier to distinguish transport counts from application-level observations.

[Back to the project guide](../README.md)
