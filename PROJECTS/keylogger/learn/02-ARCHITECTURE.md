# Architecture

The program is four functions with one responsibility each, which keeps the platform-specific parts away from the logic that can be tested anywhere.

**`require_interactive_terminal()`** is the gate. It asks whether standard input is a terminal, and on Windows it asks a second question, because the first one is not trustworthy there. It is called before anything else, including before the output file is created.

**`iter_terminal_keys()`** owns input. On Windows it reads wide characters through `msvcrt` and consumes the second byte of a special-key sequence so arrow keys and function keys do not split into two nonsense events. On Unix it puts the terminal into cbreak mode, reads one character at a time, and restores the previous settings in a `finally` block so an interrupted session does not leave the shell in raw mode.

**`display_key()`** is a pure function mapping a raw character to a readable label. It has no state and no I/O, which is what makes it the easiest part of the project to test exhaustively.

**`record_session()`** is the pipeline: it takes an iterator of raw characters, timestamps each one, writes a JSON object per line, flushes, and stops when the configured stop key arrives. It accepts an injected iterator, which is how the tests exercise the whole write path without a human at a keyboard.

The command line layer handles consent, prints the start message and turns failures into a clean exit rather than a traceback.

[Back to the project guide](../README.md)
