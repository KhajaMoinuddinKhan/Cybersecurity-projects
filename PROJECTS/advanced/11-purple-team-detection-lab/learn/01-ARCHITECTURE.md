# Architecture

The project has five main parts. Event loading turns JSON records into typed Python objects. The detection engine evaluates match and threshold rules. SQLite stores the alerts. The website checker performs passive HTTPS, TLS, status, and header checks against public websites. A local HTTP server provides the analyst dashboard and JSON endpoints.

## Keep responsibilities separate

The event pipeline moves through loading, validation, detection, and storage before the dashboard reads its results. The rule engine works with typed objects rather than raw files, so correlation tests can focus on grouping and timestamps. SQLite stores the alert explanation and evidence IDs; retain the original event file for full evidence.

Website checks do not pass through this detection pipeline. The HTTP handler returns a fresh passive result, and JavaScript organizes its findings in the browser. A page refresh clears that website queue while stored event alerts remain in SQLite.

[Run the lab](../README.md)
