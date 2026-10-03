# Overview

Packet captures preserve network observations for later review. A useful first pass answers more than one question: which protocols occurred, how much data moved, which hosts carried it, which pairs of hosts held a conversation, and when the capture ran. This project keeps that first pass small and traceable.

It accepts an existing capture and reports only what it sees. Every ranking is derived from the packets in the file, every byte total is the sum of captured frame lengths, and the timeline is built from the capture's own timestamps. That makes the result reproducible without pretending to have live network access when no capture was supplied, and without inventing a figure the file does not contain.

The report stays streaming: it reads one packet at a time and keeps counters, so a large capture costs time rather than memory.

[Back to the project guide](../README.md)
