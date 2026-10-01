# Architecture

`iter_terminal_keys()` owns platform-specific input. `display_key()` converts control characters to readable labels. `record_session()` adds a UTC timestamp, writes one JSON object per line, flushes it, and stops when the selected key arrives. The CLI is responsible for consent and user-facing errors.

The terminal restoration path is important on Unix-like systems. If the process is interrupted, the `finally` block returns the terminal to its previous settings instead of leaving the shell in raw input mode.
