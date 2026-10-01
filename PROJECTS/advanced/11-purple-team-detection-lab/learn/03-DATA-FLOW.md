# Data flow

1. Load synthetic events from JSON.
2. Load and validate the detection rules.
3. Apply each rule to the event stream.
4. Correlate threshold rules by group and time window.
5. Save alerts to SQLite.
6. Read the alerts from the command line, dashboard, or JSON API.
7. When a public website is entered, run passive HTTP, TLS, and security-header checks and return the result to the dashboard.

## Trace evidence through one run

The event loader rejects duplicate IDs and normalizes timestamps to UTC before sorting. Rule loading validates supported types, operators, and threshold settings. Detection returns alerts containing a time range and supporting event IDs. Replacing stored alerts happens in one transaction, so a failed write does not intentionally leave half of the new report.

For website checks, URL validation is followed by connection-time IP validation, HTTP inspection, header analysis, and a separate verified TLS inspection where applicable. Redirects go through the same public-address boundary. The returned score describes configured checks; it is not collected telemetry and should not be confused with a measured compromise probability.

[Run the lab](../README.md)
