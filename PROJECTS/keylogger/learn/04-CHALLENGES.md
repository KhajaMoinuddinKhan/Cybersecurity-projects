# Challenges

**Windows lies about terminals.** The most instructive problem in this project is that `sys.stdin.isatty()` returns true for the NUL device and other character handles on Windows, because the implementation is a character-device check rather than a console check. A recorder that trusted it would accept a redirected run and then block forever waiting for input that cannot arrive. The fix is a second question — asking the console for its input mode — and the reason it is worth documenting is that the bug would present as a hang, not as an error.

**A message that outran its check.** The start banner was originally printed before the terminal was validated, so a run that recorded nothing announced that recording had started and then failed with the refusal. The file guarantee held, so nothing was left behind, but the message described a session that never existed. The tests covered the refusal at the recording level and the no-file guarantee, but nothing exercised the command line, which is exactly how the banner slipped in front of the check. It is a good example of a test suite that covers the logic thoroughly and the entry point not at all.

**Special keys arrive in pieces.** On Windows an arrow key is delivered as two bytes, the first of which is a marker. Read naively, one key press becomes two events, one of them meaningless. The second byte has to be consumed as part of the first event and labelled together.

**Terminal state is borrowed, not owned.** On Unix the program changes terminal settings to read characters as they arrive, and every path out of that code — normal end, end of input, `Ctrl+C`, an unexpected exception — has to restore the previous settings. Missing one path leaves the user with a shell that no longer echoes what they type, which is alarming and hard to diagnose if you do not know what caused it.

**Appending into a file that does not end cleanly.** A previous session that was killed mid-write can leave a file whose last line has no trailing newline. Appending directly to it produces one corrupt line rather than two valid ones, and the failure is invisible until something tries to parse the file.

**The data is sensitive by construction.** The output is a record of what a person typed, which may include anything they typed. It should be protected or deleted after an authorised test, and it should never be committed to a repository. This is a property of the artefact rather than a bug, and it is the reason the project has no default output path pointing somewhere convenient.

**What the project deliberately does not solve.** Global capture, stealth, persistence, encryption and remote collection are all absent, and adding any of them would change what the program is. That is a boundary rather than a gap in coverage.

[Back to the project guide](../README.md)
