# Overview

Purple Team Detection Lab takes synthetic security events, applies detection rules, correlates related activity, and stores the resulting alerts in SQLite. The project focuses on detection engineering and analyst review rather than offensive execution.

## An investigation you can repeat

Run detect against the bundled event file, read summary, and open the dashboard. Pick an alert and follow its event IDs back into the source JSON. Ask which exact condition matched and what legitimate activity could produce the same fields. The purpose of the lab is to make that reasoning visible, not to label every unusual event as an attack.

The sample events are deliberately synthetic. Your own normalized event files can use the same pipeline, but the lab has no live endpoint collector. The website checker is a separate on-demand workflow that uses actual HTTP and TLS observations.

[Run the lab](../README.md)
