# Consent-based terminal key recorder

Keyboard input is one of the most sensitive streams a computer produces, so this project is built around a single idea: recording it should be visible, deliberate, and limited to a terminal you are actually sitting in.

It records keystrokes from the foreground terminal that launched it, writes them as JSONL to a file you name, prints a message while it runs, and stops when you press Escape. It does not install a background hook, start with the system, hide a window, read other applications, or send anything over a network. There is no mode that does those things.

## Running it

Standard library only. The `--consent` flag is required and is not a formality: it is the point at which you confirm you own the terminal or are authorised to monitor it.

```console
python -m src.keylogger --consent --output key-events.jsonl
```

Press **Esc** (or **Ctrl+C**) to stop. Do not type passwords or anything else sensitive while it is recording.

## What it records

Each line is one key event with the UTC time it was received:

```json
{"timestamp": "2026-10-01T21:47:44.560576+00:00", "key": "h"}
{"timestamp": "2026-10-01T21:47:45.427754+00:00", "key": "ENTER"}
{"timestamp": "2026-10-01T21:47:46.429035+00:00", "key": "BACKSPACE"}
{"timestamp": "2026-10-01T21:47:47.029695+00:00", "key": "ESC"}
```

Printable characters appear as themselves. Control keys get readable labels: `ENTER`, `TAB`, `BACKSPACE`, `ESC`, `CTRL-C`, and `SPECIAL-xx` for Windows special-key sequences. The file is appended to and flushed after every event, so you can watch a session while it is still running, and choose a new filename when you want a clean file.

## The guards

Two checks run before anything is written:

- **The terminal must be interactive.** If standard input is a pipe, a file, or the Windows NUL device, the program refuses and exits. The Windows check is not just `isatty()`, because Windows reports character devices like NUL as terminals; it also asks the console for its input mode, which only succeeds for a real console. Without that second check, a redirected run would sit there waiting for a keypress that can never arrive.
- **Validation happens before the output file is created.** A refused run leaves nothing behind, not even an empty file.

Stopping is deliberate too. `Ctrl+C` ends the session cleanly and keeps the events already written instead of dumping a traceback, and on macOS and Linux the terminal settings are restored in a `finally` block, including when the session ends early or the process fails.

## What this is not

This is not a stealth keylogger, a credential collector, or an endpoint sensor. It captures the terminal that started it and nothing else, which is also why it is a reasonable way to learn what keyboard events actually look like: the output is your own typing, in a window you can see, for as long as you keep it open.

## Tests

```console
python -m pytest -q tests
```

The tests use controlled key sequences rather than a person's typing, and cover key labelling, JSONL writing, the refusal path for a non-interactive terminal, the file-not-created guarantee, end-of-input handling, and Ctrl+C behaviour.
