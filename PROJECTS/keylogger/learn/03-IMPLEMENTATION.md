# Implementation

**Validation runs before the banner, not after.** The terminal check happens before the start message is printed. The reason is that a run which is going to be refused must not announce that recording has started — a message saying "recording started" followed immediately by a failure is worse than no message, because it describes a session that never existed.

**The output file is created only after validation.** A refused run leaves nothing behind, not even an empty file. That matters when the refusal happens because the input was redirected: an empty file in the working directory would be an unexplained artefact of a run that did nothing.

**Appending is repaired, not assumed.** If the target file already exists and does not end with a newline, a separator is written first. Without it the first new event would join the last line of the previous session and produce a line that is not valid JSON, which silently breaks every reader downstream.

**The terminal check is stricter on Windows.** `isatty()` on Windows is a character-device test, so the NUL device reports as a terminal. A recorder that trusted it would sit waiting for a keypress that can never arrive on a redirected run. The program therefore also asks the console for its input mode through `GetConsoleMode`, which succeeds only for a genuine console input buffer.

**Interrupts are a normal ending.** `Ctrl+C` is caught and treated as the end of the session rather than an error, so everything already recorded stays on disk and the operator gets no traceback for stopping the program the way the program told them to.

**The tests inject the input.** Passing an iterator of known characters into `record_session()` covers labelling, timestamps, JSONL shape, the append repair, the stop key and the interrupt path without ever needing real keyboard input. The refusal path is tested by making standard input a non-terminal, and one test uses the real NUL device on Windows to prove the second console check is doing work.

[Back to the project guide](../README.md)
