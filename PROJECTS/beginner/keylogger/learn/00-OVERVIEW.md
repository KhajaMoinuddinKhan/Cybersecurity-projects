# Overview

Keyboard monitoring is sensitive because the same low-level input can represent harmless debugging or private credentials. This project keeps the boundary visible: the operator starts it with `--consent`, sees the recording message, uses the foreground terminal, and stops with Esc.

The useful lesson is the lifecycle around an input stream: check that the input is interactive, read events, serialize each event, flush durable output, and restore terminal state when the session ends.
