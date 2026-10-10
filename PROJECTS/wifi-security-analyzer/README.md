# Wi-Fi Security Analyzer

The analyzer reads nearby access-point advertisements through Windows Native Wi-Fi. It requests a scan on one selected wireless adapter, waits for the operating system's completion notification, then reads the BSS list returned by that same adapter. The report is built only from those observations; an empty result stays empty, and an incomplete or malformed native record is not replaced with a sample or a guessed value.

This is an assessment of advertised link-layer settings, not a packet sniffer or a monitor-mode receiver. The operating system and driver control the scan and may transmit their ordinary discovery probes. The analyzer does not craft frames, associate with access points, disconnect clients, capture credentials, crack passwords, or inject traffic. It can see only what the chosen adapter and driver report at that time, so a scan is not a complete survey of every radio nearby.

The report keeps the SSID bytes as hexadecimal as well as showing a display string, which avoids confusing an empty or non-UTF-8 SSID with missing data. It includes the observed BSSID, signal measurements, center frequency, the band and channel derived from that frequency, PHY and BSS identifiers, beacon timestamps, regulatory-domain flag, advertised rate values, capability bits, and the original information-element bytes. RSN, legacy WPA and WPS elements are parsed with length checks. Unknown selectors stay unknown; malformed security data is called unassessable rather than open. WPS and management-frame-protection observations are reported as configuration facts, not as proof that a network can be exploited.

A fresh baseline is optional. The operator must name every BSSID to include, and each must be present in the live scan that creates the file. The analyzer never adopts everything nearby as trusted by default. Baselines are local JSON files; they are not signed, so protect and review them as configuration. Replacing an existing file requires an explicit `--overwrite-baseline` flag. A new BSSID advertising a non-empty SSID already in the baseline is only a review candidate: mesh systems, roaming, hardware changes, and impersonation can produce similar observations. A security-profile difference is reported separately, and only evidence of a weaker advertised profile is labeled a downgrade.

Run `python -m src.cli interfaces` to see the interface GUIDs Windows exposes. When there is exactly one connected interface, the scan uses it; when there is one interface total, it can use that adapter even while disconnected. With multiple plausible adapters, the tool refuses to guess and asks for a GUID.

```text
python -m src.cli scan
python -m src.cli scan --interface YOUR_INTERFACE_GUID --json
python -m src.cli scan --baseline approved-networks.json
python -m src.cli scan --create-baseline approved-networks.json --include-bssid YOUR_OBSERVED_BSSID
python -m src.cli scan --create-baseline approved-networks.json --include-bssid YOUR_OBSERVED_BSSID --overwrite-baseline
```

Windows privacy controls can deny WLAN scanning. If access is denied, check Location services and the setting that allows desktop apps to access location, then retry. A scan that times out or is denied exits with an error rather than reporting cached data as a fresh scan. JSON output is intended for review and automation; the raw SSID and information-element bytes are retained so downstream users can inspect the evidence instead of relying only on labels.
