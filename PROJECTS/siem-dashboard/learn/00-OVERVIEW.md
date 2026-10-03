# Overview

MKMK Live SIEM collects Windows Event Log and Sysmon telemetry, classifies it against detection rules loaded from files, correlates the results into sequences, stores everything in SQLite, and serves a live analyst dashboard. It starts empty unless real records are available, and nothing on the page is decorative: every number comes from stored data.

The pipeline has five stages, and it is worth naming them because every panel on the page maps to one. Collection reads the event channels. Classification decides which events matter and why. Storage keeps them. Correlation looks across the stored results for sequences no single event could show. Presentation is the dashboard.

## From counts to evidence

A useful session starts with collector health, because a channel that is not connected explains an empty panel better than any investigation will. From there the route is a time window or a channel, then the detection queue, then the individual event.

Open the raw record before deciding what an alert means. A service installation can be expected maintenance or an unexpected persistence mechanism. An LSASS read can be a security product doing its job or someone dumping credentials. The dashboard provides the event context and the rule that matched; it does not provide the final judgment, and it should not pretend to.

[Run instructions and troubleshooting](../README.md)

