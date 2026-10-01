# Implementation

The program uses only the Python standard library. JSONL lets another local tool follow a growing session without waiting for a closing JSON array. `Path.parent.mkdir()` makes an explicitly chosen output directory usable, and `flush()` reduces the amount of data held only in a process buffer.

Tests pass an iterator of known characters to the recorder; the live input function is kept separate so tests never need to capture real keyboard input.
