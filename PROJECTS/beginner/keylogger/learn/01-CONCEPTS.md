# Concepts

A terminal key event is a character returned by the console, not a global observation of every keyboard device. Special keys need labels because a newline or escape byte is difficult to understand when read back from a text file. UTC timestamps make sessions from different machines comparable.

Explicit consent and a visible stop control are part of the design. They are functional boundaries, not documentation added after the code. The recorder has no remote destination and no persistence mechanism, so its output remains a local audit file.
