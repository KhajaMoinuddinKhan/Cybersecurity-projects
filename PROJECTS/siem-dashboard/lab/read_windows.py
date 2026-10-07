
import json, os, sys
import traceback
from pathlib import Path
for key in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"):
    os.environ.pop(key, None)
SIEM = str(Path(__file__).resolve().parent.parent)
sys.path.insert(0, SIEM)

WORK = os.environ.get("SIEM_LAB_WORK") or str(Path(__file__).resolve().parent / "out")
os.makedirs(WORK, exist_ok=True)
LOG = os.path.join(WORK, "read.log")
log = open(LOG, "w", encoding="utf-8", buffering=1)
def progress(msg):
    log.write(msg + "\n")

try:
    from src.lab import read_window, reset_reader_pids, CaptureError
    reset_reader_pids()
    plan = json.load(open(os.path.join(WORK, "windows.json"), encoding="utf-8"))

    corpus, unreadable_any = [], set()
    for index, window in enumerate(plan["windows"], 1):
        events, notes = [], []
        for channel in plan["channels"]:
            got, readable = read_window(channel, window["started"] - 1.0,
                                        window["ended"] + 1.5)
            if not readable:
                unreadable_any.add(channel)
                notes.append(channel)
            events.extend(got)
        progress("  [%2d/%2d] %-11s %4d events%s"
                 % (index, len(plan["windows"]), window["label"], len(events),
                    "  unreadable: " + ",".join(notes) if notes else ""))
        corpus.append({"label": window["label"], "technique": window["technique"],
                       "started": window["started"], "ended": window["ended"],
                       "events": events})

    if unreadable_any:
        raise CaptureError("these channels could not be read: %s" % ", ".join(sorted(unreadable_any)))
    payload = {"windows": corpus, "channels": plan["channels"],
               "unreadable": [], "blocked_techniques": []}
    json.dump(payload, open(os.path.join(WORK, "corpus.json"), "w", encoding="utf-8"), indent=1)
    progress("reader done: %d windows, %d events"
             % (len(corpus), sum(len(w["events"]) for w in corpus)))
except Exception:
    progress("FAILED:")
    progress(traceback.format_exc())
log.close()
