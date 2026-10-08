"""Compiling the instrumented target, and refusing clearly when there is no compiler.

The target has to be compiled rather than interpreted, because the coverage comes from
the compiler: it inserts a call on every edge and the fuzzer answers it. A fuzzer that
interpreted its target could not do that, so the toolchain is a prerequisite and this
module says so rather than quietly falling back to something that is not fuzzing.

`zig cc` is used because it is the one C compiler that arrives through pip, which means
the whole thing works on a machine with no toolchain installed -- including CI. Any
system compiler would do just as well and is used if it is there.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
TARGET_DIR = PROJECT / "target"
BUILD_DIR = PROJECT / "build"


class BuildError(RuntimeError):
    """The target could not be built, with the reason the compiler gave."""


def compiler() -> list:
    """The command prefix that compiles C, or a refusal naming what was looked for.

    Ordered by preference: a system compiler first, because it is faster and it is what
    a reader would expect, then the one that arrives through pip.
    """
    for name in ("cc", "gcc", "clang"):
        found = shutil.which(name)
        if found:
            return [found]
    # `zig cc` ships a clang and a linker and needs nothing else installed.
    try:
        probe = subprocess.run([sys.executable, "-m", "ziglang", "version"],
                               capture_output=True, text=True, timeout=120)
        if probe.returncode == 0:
            return [sys.executable, "-m", "ziglang", "cc"]
    except (OSError, subprocess.SubprocessError):
        pass
    raise BuildError(
        "no C compiler was found. The coverage comes from the compiler, so one is "
        "required: install gcc or clang, or `pip install ziglang`, which brings its "
        "own. Looked for cc, gcc and clang on the path, and for ziglang as a module."
    )


def _extension() -> str:
    return ".exe" if os.name == "nt" else ""


def build(name: str = "target", vulnerable: bool = True, force: bool = False,
          exploit: bool = False) -> Path:
    """Compile the instrumented target and return the library.

    `vulnerable` selects the build. Both are compiled from the same source: the fixed
    build defines BOUNDED, which makes the copy respect the destination buffer. Keeping
    one source means the difference between the two builds is one line, so the exploit
    is demonstrating a fix rather than a different program.
    """
    BUILD_DIR.mkdir(exist_ok=True)
    suffix = "vulnerable" if vulnerable else "patched"
    if exploit:
        suffix += "-exploit"
    output = BUILD_DIR / ("%s-%s%s" % (name, suffix, _extension()))
    # The target is instrumented and the driver is not, and that separation is the
    # point rather than a detail. The coverage is meant to describe the target; a driver
    # compiled the same way contributes its own edges, and its edges depend on things
    # that have nothing to do with the input -- a pipe read that returns in one piece or
    # two, a file that is cached or not. Measured together, the same input produces
    # different coverage on different runs, and a fuzzer whose feedback is not a function
    # of its input is not guiding anything.
    # What is instrumented is decided here rather than by an attribute, because the
    # attribute is a request and this is a fact.
    #
    # The runtime implements the callback that the instrumentation calls on every edge.
    # If it is compiled with the same flag, every call to the callback is a call to
    # itself: infinite recursion, a stack overflow, and a program that dies before it
    # reads its first input and records no coverage at all. One compiler excludes the
    # callback on its own and another does not, and the attribute that was supposed to
    # say so is honoured for `-finstrument-functions` and not for coverage.
    #
    # Compiling it separately without the flag cannot be misread by any compiler.
    instrumented = [TARGET_DIR / "parser.c"]
    uninstrumented = [TARGET_DIR / "coverage_runtime.c"]
    driver = (TARGET_DIR / "exploit_harness.c" if exploit
              else TARGET_DIR / "runner.c")
    for source in instrumented + uninstrumented + [driver]:
        if not source.exists():
            raise BuildError("the target source is missing: %s" % source)

    if output.exists() and not force:
        return output

    # No optimisation, and that is a choice rather than a limitation. At -O0 nothing is
    # inlined, so every statement is its own edge and the feedback the fuzzer gets is
    # finer-grained -- which is the thing that makes coverage guidance work. An optimised
    # build also makes zig link a sanitizer runtime that its pip package does not ship on
    # Windows, so -O1 and above do not link here at all.
    common = ["-O0", "-g"]                # -g so a crash can be attributed to a line
    if not vulnerable:
        common.append("-DBOUNDED")

    # Separate compilation, because the instrumentation flag cannot be turned off per
    # file on one command line and three groups of files need three answers.
    objects = []
    groups = [(instrumented, True), (uninstrumented, False), ([driver], False)]
    for index, (sources, with_coverage) in enumerate(groups):
        for source in sources:
            obj = BUILD_DIR / ("%s-%s-%d.obj" % (name, suffix, index))
            step = compiler() + common + (["-fsanitize-coverage=trace-pc,trace-cmp"]
                                          if with_coverage else [])
            step += ["-c", str(source), "-o", str(obj)]
            done = subprocess.run(step, capture_output=True, text=True, timeout=900)
            if done.returncode or not obj.exists():
                raise BuildError("the compiler refused %s:\n%s"
                                 % (source.name,
                                    done.stderr.strip() or done.stdout.strip()))
            objects.append(obj)

    link = compiler() + common + [str(o) for o in objects] + ["-o", str(output)]
    done = subprocess.run(link, capture_output=True, text=True, timeout=900)
    if done.returncode or not output.exists():
        raise BuildError("the linker refused the target:\n%s"
                         % (done.stderr.strip() or done.stdout.strip()))
    return output


def describe() -> dict:
    """What a caller can report about the toolchain without building anything."""
    try:
        found = compiler()
    except BuildError as exc:
        return {"available": False, "compiler": None, "reason": str(exc)}
    return {"available": True, "compiler": " ".join(found), "reason": None}
