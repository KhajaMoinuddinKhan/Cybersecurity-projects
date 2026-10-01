# Overview

Packet captures preserve network observations for later review. A useful first pass is often a count: which protocols occurred, which hosts were active, and which names were queried. This project keeps that first pass small and traceable.

It accepts an existing capture and reports only what it sees. That makes the result reproducible without pretending to have live network access when no capture was supplied.
