# Data flow

1. Load synthetic events from JSON.
2. Load and validate the detection rules.
3. Apply each rule to the event stream.
4. Correlate threshold rules by group and time window.
5. Save alerts to SQLite.
6. Read the alerts from the command line, dashboard, or JSON API.
7. When a public website is entered, run passive HTTP, TLS, and security-header checks and return the result to the dashboard.
