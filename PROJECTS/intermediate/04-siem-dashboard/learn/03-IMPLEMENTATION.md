# Implementation

- `SAMPLE_EVENTS` is the single source for the demo data.
- `normalise_severity()` accepts supported values in a consistent form.
- `reset_events()` clears stored rows and restarts the local event ID sequence.
- `query_events()` builds parameterized filters and escapes literal search characters.
- `severity_counts()` reads grouped counts and the full row total from SQLite.
- `dashboard_app()` connects the data layer to the Flask routes and template.
