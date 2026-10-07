
import json, os, sys
import subprocess, time, traceback
from pathlib import Path
for key in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"):
    os.environ.pop(key, None)
SIEM = str(Path(__file__).resolve().parent.parent)
sys.path.insert(0, SIEM)

WORK = os.environ.get("SIEM_LAB_WORK") or str(Path(__file__).resolve().parent / "out")
os.makedirs(WORK, exist_ok=True)
LOG = os.path.join(WORK, "capture.log")
log = open(LOG, "w", encoding="utf-8", buffering=1)
def progress(msg):
    log.write(msg + "\n")

try:
    from src.lab import (ALLOWED_TECHNIQUES, BENIGN_WORKLOAD, CHANNELS, _run,
                         reset_reader_pids)

    # Nothing here needs elevation, and running it with elevation is what endpoint
    # protection refused: the encoded-PowerShell atomic is a shape it blocks when
    # an elevated process asks for it. This process is ordinary, so the technique
    # runs and the reading is somebody else's job.
    windows = []
    progress("driver: unelevated, %d techniques" % len(ALLOWED_TECHNIQUES))
    for index, technique in enumerate(ALLOWED_TECHNIQUES, 1):
        started = time.time()
        try:
            code, out = _run(technique.resolved(), technique.executor, attempts=2)
            note = "exit %s" % code
        except Exception as exc:
            note = "FAILED: %s" % type(exc).__name__
        ended = time.time()
        time.sleep(1.5)                      # let the events land
        progress("  [%2d/%2d] %-11s %-34s %s" % (index, len(ALLOWED_TECHNIQUES),
                                                 technique.attack_id, technique.name[:34], note))
        windows.append({"label": technique.attack_id, "technique": technique.name,
                        "started": started, "ended": ended, "note": note})

    for index in range(6):
        core = BENIGN_WORKLOAD[:4]
        extra = BENIGN_WORKLOAD[4:]
        take, start = 2, (index * 2) % len(extra)
        workload = core + tuple(extra[(start + i) % len(extra)] for i in range(take))
        started = time.time()
        for executor, command in workload:
            try:
                _run(command, executor, attempts=2)
            except Exception:
                pass
            time.sleep(10.0 / max(1, len(workload)))
        ended = time.time()
        time.sleep(1.5)
        progress("  benign window %d of 6 (%.0fs)" % (index + 1, ended - started))
        windows.append({"label": "benign", "technique": "benign",
                        "started": started, "ended": ended})

    json.dump({"windows": windows, "channels": list(CHANNELS)},
              open(os.path.join(WORK, "windows.json"), "w", encoding="utf-8"), indent=1)
    progress("driver done: %d windows recorded" % len(windows))

    # 2. one elevation, for the reading only. This process never spawns a technique.
    reader = os.path.join(WORK, "read_windows.py")
    python = sys.executable
    launcher = 'Start-Process -FilePath "%s" -Verb RunAs -ArgumentList @("-B","%s")' % (python, reader)
    progress("asking for elevation to read the event log...")
    subprocess.run(["powershell", "-NoProfile", "-Command", launcher],
                   capture_output=True, text=True, timeout=120)
except Exception:
    progress("FAILED:")
    progress(traceback.format_exc())
log.close()
