"""Put the project root on sys.path and keep pytest's temp files local.

Every project in this repository is a standalone ``src`` package, so the tests
import the package from the project root rather than from an installed copy.
pytest's ``tmp_path`` is anchored inside the project for the same reason the
other projects do it: the shared system temp directory on some machines holds
directories this process cannot read, and the cleanup scan fails on them.
"""
from __future__ import annotations

import os
import pathlib
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def pytest_configure(config):
    if getattr(config.option, "basetemp", None):
        return
    base = pathlib.Path(__file__).resolve().parent.parent / ".pytest_tmp"
    try:
        base.mkdir(parents=True, exist_ok=True)
    except OSError:
        return
    config.option.basetemp = str(base)
