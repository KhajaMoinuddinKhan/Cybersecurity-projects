# Network Traffic Analyzer

This project reads a PCAP file that you provide and summarizes what the capture actually contains. It counts protocols, identifies the busiest source and destination addresses, reports destination ports, and counts DNS question names. It does not manufacture traffic, fetch a sample capture, or sniff your network automatically.

## Run it

Install Scapy in the same Python environment used for the command:

```powershell
python -m pip install -r requirements.txt
python -m src.analyzer path\to\capture.pcap
python -m src.analyzer path\to\capture.pcap --json
```

Use a PCAP captured on a network you are authorized to inspect. The analyzer uses Scapy's streaming `PcapReader`, so it processes one packet at a time rather than loading the entire capture into memory. A large capture can still take time because every packet is inspected.

## Read the result

The report contains only observed values. `packet_count` is the number of packets read. Protocols, sources, destinations, and ports are sorted by their observed frequency. DNS replies are not counted as queries; a request and its reply still contribute to the packet and protocol totals. An empty or filtered capture is reported as empty instead of being filled with demo numbers.

The JSON mode is useful when another local tool needs the report. The human-readable mode is intended for a quick investigation in a terminal.

## How it works

`packet_record()` extracts IPv4 or IPv6 addresses, TCP or UDP destination ports, and DNS question names. `summarize()` updates counters as records arrive. `analyze_pcap()` connects those pieces to Scapy's streaming reader and closes the file when the scan ends.

The analyzer is descriptive. A frequent address or port is a lead for investigation, not proof of malicious activity. Encrypted application contents remain encrypted, and a capture can miss traffic that was not recorded.

## Tests

```console
python -m pytest -q tests
```

The tests verify aggregation with controlled packet records. A capture-file test should be run on a machine where Scapy can initialize its packet layers and read the supplied PCAP.
