# Concepts

**A terminal key event is a character, not a keyboard.** The recorder reads what the console hands to the process, which is a filtered and interpreted stream rather than a record of every physical key press. Modifier combinations, for example, usually arrive as control bytes rather than as separate events.

**Special keys need labels.** A newline arrives as a carriage return or a line feed, a backspace as a delete or a backspace byte, and an arrow key as a multi-byte escape sequence. Stored raw, those are unreadable when the file is opened later, so each is mapped to a readable name and anything else unprintable is recorded by its code point.

**JSONL is the right shape for a live stream.** One JSON object per line means a second process can follow a growing file and parse each line as it appears, which a single JSON array cannot do without waiting for the closing bracket. It also means a truncated file — one that was cut off mid-session — is still readable up to the last complete line.

**Flushing is a durability choice.** Buffered output would be lost if the process were killed, so each event is flushed as it is written. The cost is a system call per keystroke, which is irrelevant at typing speed and would matter if this were recording a machine instead of a person.

**UTC timestamps make sessions comparable.** A local-time stamp from a laptop that travelled is ambiguous. Storing UTC removes the question, and the offset is available to any reader that wants to render it locally.

**Consent is a control, not a notice.** The flag, the start message and the visible stop key are functional parts of the program: without the flag nothing is recorded, and the stop key is the operator's guarantee that they can end the session without killing a process.

[Back to the project guide](../README.md)
