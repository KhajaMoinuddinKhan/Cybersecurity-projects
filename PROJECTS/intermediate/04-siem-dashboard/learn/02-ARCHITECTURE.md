# Architecture

1. The seed utility loads the shared synthetic event set into SQLite.
2. Validation normalizes each event before it reaches the database.
3. The query layer applies optional severity and text filters.
4. Flask passes the selected rows and severity counts to the HTML template.
5. The template and CSS render the local dashboard.
