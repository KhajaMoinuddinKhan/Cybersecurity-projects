# Architecture

The project has five main parts. Event loading turns JSON records into typed Python objects. The detection engine evaluates match and threshold rules. SQLite stores the alerts. The website checker performs passive HTTPS, TLS, status, and header checks against public websites. A local HTTP server provides the analyst dashboard and JSON endpoints.
