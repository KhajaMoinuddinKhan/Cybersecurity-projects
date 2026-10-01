# Data flow

1. Load synthetic events from JSON.
2. Load and validate the rule file.
3. Apply each rule to the event stream.
4. Correlate threshold rules by group and time window.
5. Save alerts to SQLite.
6. Read the stored alerts from the command line, dashboard, or JSON API.
