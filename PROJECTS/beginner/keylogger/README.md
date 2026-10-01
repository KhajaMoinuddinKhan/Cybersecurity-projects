# Consent-based terminal key recorder

This project demonstrates how keyboard events can be captured from a terminal that you explicitly own or are authorized to monitor. It is intentionally visible and local: the program runs in the foreground, prints a start message, stops when you press **Esc**, writes JSONL to the path you choose, and never sends keystrokes over a network. It does not install a background hook, start with Windows, hide its window, or record other applications.

## Run it

Open a terminal in this project directory. Do not type passwords or other sensitive information while recording.

```powershell
python -m src.keylogger --consent --output key-events.jsonl
```

Press **Esc** to stop. Every line contains the UTC time at which the terminal returned the key and a readable key label. The file is appended to, so choose a new filename when you want a separate session.

The `--consent` switch is deliberate. Only use this tool on your own terminal or with clear permission from the people involved. If standard input is redirected, the program refuses to run. That prevents a pipeline or password prompt from becoming an accidental recording source.

## What the output means

A recorded line looks like this:

```json
{"timestamp": "2026-10-01T18:00:00+00:00", "key": "ENTER"}
```

The timestamp is generated when the key is received. The key is the actual character or a label such as `ENTER`, `TAB`, `BACKSPACE`, or `ESC`. There are no sample keystrokes or fixed counters in the program.

## How it works

On Windows the tool reads the foreground console through `msvcrt`. On macOS and Linux it temporarily puts the terminal into cbreak mode, reads one character at a time, and restores the terminal settings in a `finally` block. The JSONL writer flushes each event so a running session is inspectable while it is in progress.

This is a learning and debugging tool for a terminal you control. It is not a stealth keylogger, credential collector, surveillance tool, or enterprise endpoint sensor. It does not capture global keyboard activity outside the terminal that launched it.

## Tests

```console
python -m pytest -q tests
```

The tests use controlled key sequences to verify formatting and JSONL writing. They do not capture a person’s real keystrokes.
