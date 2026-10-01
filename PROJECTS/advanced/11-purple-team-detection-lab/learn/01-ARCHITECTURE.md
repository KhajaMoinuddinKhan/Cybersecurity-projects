# Architecture

The project has four main parts. Event loading turns JSON records into typed Python objects. The detection engine evaluates match and threshold rules. SQLite stores the alerts. A local HTTP server provides the analyst dashboard and JSON endpoints.
