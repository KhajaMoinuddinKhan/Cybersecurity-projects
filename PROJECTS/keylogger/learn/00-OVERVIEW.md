# Overview

Keyboard input is one of the most sensitive streams a computer produces. The same low-level mechanism that makes a debugging session possible also captures whatever a person types next, including a password they did not intend to hand over. This project takes that seriously by making the boundary visible rather than hiding it.

The recorder runs in the foreground terminal that launched it, prints a message while it is running, and stops when you press Escape. There is no background hook, no start-up persistence, no hidden window, no reading of other applications, and no network path of any kind. `--consent` is required, and it is not a formality: it is the point at which the operator states that they own the terminal or are authorised to monitor it.

## What the project teaches

The interesting engineering is not the keystroke capture, which is a few lines. It is the lifecycle around an input stream: refusing to start when the input is not a real terminal, reading events one at a time, labelling control characters so the output is readable later, writing durable output that can be followed while the session is still running, and restoring the terminal when the session ends — including when it ends badly.

## What it is not

It is not a stealth keylogger, not a credential collector, and not an endpoint sensor. It captures the terminal that started it and nothing else. That limitation is the design, not a missing feature, and there is deliberately no mode that removes it.

[Back to the project guide](../README.md)
