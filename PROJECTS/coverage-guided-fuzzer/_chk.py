
import sys
sys.path.insert(0, sys.argv[1])
from src.build import build, describe
print("toolchain:", describe())
for v in (True, False):
    for ex in (False, True):
        try:
            p = build(vulnerable=v, force=True, exploit=ex)
            print("  %-10s %-8s -> %s" % ("vulnerable" if v else "patched",
                                          "exploit" if ex else "fuzzer", p.name))
        except Exception as e:
            print("  %-10s %-8s -> %s: %s" % ("vulnerable" if v else "patched",
                                              "exploit" if ex else "fuzzer",
                                              type(e).__name__, str(e)[:200]))
