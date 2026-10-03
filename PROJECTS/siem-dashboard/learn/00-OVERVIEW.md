# Overview

MKMK Live SIEM collects Windows Event Log and Sysmon telemetry, classifies it against detection rules loaded from files, correlates the results into sequences, stores everything in one SQLite file, and serves a live analyst dashboard. It is no longer one machine. A console collects the host it runs on, agents on other machines forward theirs, and the server keeps accounts, a host inventory, a triage queue, an indexed search, per-host baselines, lockout and multi-factor authentication, and backups beside the events. Nothing on the page is decorative: every number comes from stored data, and when a panel cannot be reached it says so instead of showing a zero.

An install starts unclaimed. There are no accounts, so the page offers to create the first administrator rather than asking for credentials that do not exist yet, and from the moment that account exists the console requires a sign-in and records who did what. That single decision is the difference between a dashboard anybody who can reach the port may read and one that keeps an account of its own use.

The pipeline has five stages, and it is worth naming them because every panel on the page maps to one. Collection reads the event channels, locally or through an agent. Classification decides which events matter and why. Storage keeps them. Correlation looks across the stored results for sequences no single event could show. Presentation is the dashboard, now with the accounts, triage and the second wave of tools that turn a viewer into an analyst.

## From counts to evidence

A useful session starts with collector health and the host inventory, because a channel that is not connected or a host that has never reported explains an empty panel better than any investigation will. From there the route is a time window or a channel, then the triage queue, then the individual detection, then the raw event. When a question needs a shape rather than a name, the search panel's query language and the baseline panel's view of what is normal for a host are the two ways to ask something the rules cannot answer.

Open the raw record before deciding what an alert means. A service installation can be expected maintenance or an unexpected persistence mechanism. An LSASS read can be a security product doing its job or someone dumping credentials. The dashboard provides the event context and the rule that matched; it does not provide the final judgment, and it should not pretend to. Working a detection means moving it through a status, leaving a note the next analyst can read, and, when the rule is simply noisy on this host, applying a suppression that hides it from the queue without pretending the rule is wrong.

[Run instructions and troubleshooting](../README.md)

[Back to the project guide](../README.md)
