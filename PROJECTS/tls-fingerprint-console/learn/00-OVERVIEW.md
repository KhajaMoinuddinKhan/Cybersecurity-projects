# Overview

The TLS Fingerprint Console answers one question with the material a capture already contains: which TLS clients were present, and do any of them match something already known? It reads the handshakes out of a capture file or a live interface, reduces each one to a fingerprint, checks that fingerprint against a bundled corpus, runs seven rules over the result, and puts the whole thing behind a console. It never decrypts the session and it never transmits traffic; the live path only listens. The handshake itself is sent in the clear on TCP, and where it is not — inside a QUIC Initial packet, which is encrypted — the console reads it anyway, because a QUIC Initial's keys come from a public salt and the connection ID and are therefore no secret from anyone who can see the packet.

## What a run leaves behind

An `analyse` run writes two things to a SQLite store: one event per flow it could fingerprint, and one alert per rule that fired. The event carries the endpoints, the server name, the negotiated ALPN, the User-Agent when one was readable, whether the handshake came over TCP or QUIC, and the fingerprints themselves. The alert carries a rule name, a severity, a title and a detail sentence that names the value which triggered it. The console is a view over exactly those two tables plus the corpus, so what you see on the page is what the run stored and nothing inferred at display time. A `watch` run writes the same two things, as the handshakes arrive rather than all at once, so the console can be showing the results of a capture that is still running.

The console has six views, and they map to three questions in sequence. Overview and Fingerprints tell you what is present — how much arrived and what clients it came from. Alerts tells you what the rules made of it. Intel and Export are the reference set and the way out; Scope is the reminder of what the tool is allowed to look at.

## A first exercise

Run `demo` to fill a store with a synthetic capture, then `serve` and read the console top to bottom. The Overview shows a handful of fingerprints; Fingerprints shows which kinds they are; Alerts shows a first_seen for each new value and, depending on the capture, a known_bad when a value lands on the malware list. Then open Intel and search for one of the values you saw, which is the loop the tool exists for: observe a fingerprint, ask whether anyone has named it, and read the licence and source of whoever did. When you want that same loop against real traffic, `python -m src.cli interfaces` lists what this machine can capture from and `python -m src.cli watch` fingerprints handshakes live; both need Npcap installed, and `watch` normally needs an elevated shell.

The rest of these notes take the project apart. The next note explains what a fingerprint actually is and why a passive reader can compute one at all; the two after that follow the code from bytes to console and record the decisions that were not obvious; the last is honest about where the tool was wrong before it was right, and about the boundaries it does not cross.

[Back to the project guide](../README.md)
