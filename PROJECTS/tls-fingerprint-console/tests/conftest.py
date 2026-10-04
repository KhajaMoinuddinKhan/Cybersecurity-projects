"""Point pytest's temporary directories at a writable, project-local path.

pytest's ``tmp_path`` fixture creates a per-session directory under the system
temp directory and, at startup, scans the parent to clean up the ones left by
earlier runs. On a machine where that parent holds directories this process
cannot read -- which is what happens when an earlier run was elevated and the
current one is not -- the scan raises PermissionError, and every test that uses
``tmp_path`` errors during setup before a single assertion runs. The failures
look like test failures and are nothing of the sort.

Anchoring the base directory inside the project sidesteps the shared parent
entirely, so the suite behaves the same on a laptop, in CI, and on a machine
whose temp directory has accumulated other people's leftovers.
"""
from __future__ import annotations

import pathlib


def pytest_configure(config):
    # An explicit --basetemp on the command line always wins.
    if getattr(config.option, "basetemp", None):
        return
    base = pathlib.Path(__file__).resolve().parent.parent / ".pytest_tmp"
    try:
        base.mkdir(parents=True, exist_ok=True)
    except OSError:
        # Fall back to pytest's own choice rather than breaking collection.
        return
    config.option.basetemp = str(base)
