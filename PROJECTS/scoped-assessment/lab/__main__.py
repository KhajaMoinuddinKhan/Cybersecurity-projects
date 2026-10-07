"""Start the lab from the command line.

A lab that can only be started by the test suite is a fixture, not a lab. This is
what makes `python -m lab` work, so the target can be run in one terminal and the
assessment against it in another -- which is the arrangement the framework is meant
to be used in, and the one the report describes.
"""

from __future__ import annotations

import os

from . import BANNER, FLAWS, serve

if __name__ == "__main__":
    print("the lab claims to be %s and declares %d flaws" % (BANNER, len(FLAWS)))
    for flaw in FLAWS:
        print("  %-32s %s" % (flaw["id"], flaw["detail"][:64]))
    print()
    serve(int(os.environ.get("LAB_PORT") or 8099))
