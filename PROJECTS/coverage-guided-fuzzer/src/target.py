"""Running inputs against the target and reporting what happened.

The target runs as a process of its own. That is the only way a memory-safety defect
can be fuzzed at all: a defect in the fuzzer's own process takes the fuzzer down with
it, and the run after the crash is the one that matters.

Two ways to drive it, and they are the same target through the same instrumentation.
`Target` starts a process per input, which is simple and slow -- around twenty-eight
milliseconds an execution on this platform, nearly all of it the spawn. `PersistentTarget`
starts one process and feeds it inputs down a pipe, which is what libFuzzer calls
persistent mode and what every fuzzer needs on a platform without fork. It is the
default for that reason: the same work at a hundredfold less overhead.

The persistent form has one consequence that has to be handled rather than wished away.
A crash ends the process, so the loop dies with it and the next input has nowhere to go.
That is detected -- the pipe closes -- and the answer is to start a new process and
carry on. Nothing is lost, because the coverage from the run that crashed was written
into shared memory before the crash happened, and the fuzzer reads it from there.
"""

from __future__ import annotations

import os
import queue
import subprocess
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

# Windows reports a structured exception as a status code in the exit code. Anything
# with the high bit set is the process dying rather than returning.
_CRASH_FLOOR = 0x80000000

# `personality(ADDR_NO_RANDOMIZE)`, which is how a process asks not to be randomised.
# Linux only, and ignored everywhere else.
_ADDR_NO_RANDOMIZE = 0x0040000


def _resolve_personality():
    """The `personality` call, resolved once at import so the child does almost nothing.

    The function below runs in a forked child, and a forked child of a program with
    threads is a place where very little is safe: it holds copies of every lock the other
    threads were holding, and taking one that will never be released is a deadlock. An
    import is exactly the kind of work that takes locks. Resolving the symbol here, while
    the program is single-threaded and nothing is held, leaves the child with one call to
    make and nothing to acquire.
    """
    if os.name == "nt":
        return None
    try:
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        return libc.personality
    except (OSError, AttributeError):
        return None


_PERSONALITY = _resolve_personality()


def _unrandomised():
    """Ask the platform not to randomise the address space of the process about to start.

    This is not a convenience. A fuzzer decides whether two crashes are the same defect by
    comparing the path each took, and a path that goes through a corrupted stack is a path
    through whatever the corruption happened to point at. With the layout randomised, that
    is a different place on every run: the same input, run twice, reaches different edges
    on the way down and is reported as two defects. The signature stops meaning anything
    exactly for the crashes it exists to group.

    Turning the randomisation off for the target makes a crash reproducible, which is what
    a crash has to be before anything can be said about it. It is the target's layout that
    is fixed and not the fuzzer's, so nothing about the search is made easier by it.
    """
    if _PERSONALITY is None:
        return
    try:
        _PERSONALITY(_ADDR_NO_RANDOMIZE)
    except OSError:
        pass


@dataclass
class Outcome:
    """What one execution produced."""

    crashed: bool
    exit_code: int | None
    coverage: bytes
    edges: int
    timed_out: bool = False

    @property
    def status(self) -> str:
        if self.timed_out:
            return "timeout"
        if not self.crashed:
            return "ok"
        if self.exit_code is None:
            # It stopped answering and the platform would not say how it ended. Naming a
            # cause here would be a guess, and a guess is what a crash report must not be.
            return "died without a code"
        if self.exit_code < 0:
            # On a platform that reports a signal as a negative number, that number is
            # the signal. Printing it as a status code gives 0xFFFFFFF5, which reads as a
            # Windows exception and is not one.
            import signal as _signal
            try:
                return "killed by %s" % _signal.Signals(-self.exit_code).name
            except ValueError:
                return "killed by signal %d" % -self.exit_code
        known = {
            0xC0000005: "access violation",
            0xC000001D: "illegal instruction",
            0xC0000409: "stack buffer overrun",
            0xC00000FD: "stack exhaustion",
            0xC0000094: "integer divide by zero",
        }
        return known.get(self.exit_code & 0xFFFFFFFF,
                         "status 0x%08X" % (self.exit_code & 0xFFFFFFFF))


class Target:
    """The compiled target, and the loop that feeds it."""

    def __init__(self, executable: Path, coverage, timeout: float = 5.0,
                 scratch: Path = None):
        self.executable = Path(executable)
        self.coverage = coverage
        self.timeout = timeout
        self.scratch = Path(scratch) if scratch else Path(tempfile.mkdtemp(
            prefix="cgf-"))
        self.scratch.mkdir(parents=True, exist_ok=True)
        self._input_path = self.scratch / "input.bin"
        self.executions = 0

    def run(self, data: bytes) -> Outcome:
        """Feed one input to the target and read back what it did.

        The input goes through a file rather than a pipe because the target is a
        command-line program, and the file is rewritten in place rather than recreated
        so that the name stays valid for the shared region's lifetime.
        """
        self._input_path.write_bytes(data)
        self.coverage.clear()
        try:
            result = subprocess.run(
                [str(self.executable), self.coverage.name, str(self._input_path)],
                capture_output=True, timeout=self.timeout,
                # No console window per execution; the target is headless.
                creationflags=0x08000000 if os.name == "nt" else 0,
            )
            code = result.returncode
        except subprocess.TimeoutExpired:
            self.executions += 1
            return Outcome(crashed=True, exit_code=0, coverage=b"",
                           edges=0, timed_out=True)

        self.executions += 1
        coverage = self.coverage.read()
        return Outcome(
            crashed=code != 0 and (code & 0xFFFFFFFF) >= _CRASH_FLOOR,
            exit_code=code,
            coverage=coverage,
            edges=self.coverage.count(coverage),
        )


class PersistentTarget:
    """The target in a long-lived process, fed through a pipe.

    The protocol is four bytes of little-endian length, then that many bytes of input,
    then one status byte back. A crash means the status byte never arrives, which is how
    a death is told apart from a slow run without relying on an exit code that a
    persistent process does not produce.

    Reads happen on a thread and the reply is waited for with a timeout, which is not
    optional. A corrupted run does not always die promptly: overwriting a parser's own
    loop counters makes it spin, and the input that does that takes seconds to fail
    where every other input takes microseconds. A read with no timeout turns one such
    input into a fuzzer that never returns, which is a worse outcome than the crash it
    was looking for. A run that does not answer in time is killed and recorded as a
    timeout, which is a finding in its own right.
    """

    def __init__(self, executable: Path, coverage, timeout: float = 2.0):
        self.executable = Path(executable)
        self.coverage = coverage
        self.timeout = timeout
        self.executions = 0
        self.restarts = 0
        self.timeouts = 0
        self._process = None
        self._replies = None
        self._reader = None
        self._start()

    def _start(self) -> None:
        self._process = subprocess.Popen(
            [str(self.executable), "--persistent", self.coverage.name],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            creationflags=0x08000000 if os.name == "nt" else 0,
            preexec_fn=_unrandomised if _PERSONALITY is not None else None,
        )
        self._replies = queue.Queue()
        self._reader = threading.Thread(target=self._read_replies, daemon=True)
        self._reader.start()
        self._warm_up()

    def _warm_up(self) -> None:
        """Spend one execution reaching the steady state.

        The first run through the target after it starts takes one edge that no later
        run takes -- a one-time initialisation on the way to a library call, resolved
        once and not again. It is reproducible across processes, which is how it was
        found, and it is worth one throwaway execution to remove: without this, the
        first input of every run is credited with an edge that has nothing to do with
        it, and an input that reaches no new edges looks as though it reached one.
        """
        try:
            self._process.stdin.write((4).to_bytes(4, "little"))
            self._process.stdin.write(b"WARM")
            self._process.stdin.flush()
            self._replies.get(timeout=self.timeout)
        except (BrokenPipeError, OSError, ValueError, queue.Empty):
            pass

    def _read_replies(self) -> None:
        """Read status bytes until the pipe closes, which is how a death arrives."""
        stream = self._process.stdout
        while True:
            try:
                status = stream.read(1)
            except (OSError, ValueError):
                break
            if status == b"":
                break
            self._replies.put(status)
        self._replies.put(None)   # the end of the conversation

    # The end of the conversation, as the target understands it: a length no input can
    # have, so that a length of zero stays available for the empty input.
    QUIT = (0xFFFFFFFF).to_bytes(4, "little")

    def _stop(self) -> None:
        """End the process, and do it in an order that does not deadlock.

        The order is the whole of it. Killing first, then waiting, then letting go of
        the streams is what this has to be, because of how a buffered reader behaves: a
        thread blocked in `read` holds the stream's lock, and closing the stream waits
        for that lock. Closing before killing therefore blocks for as long as the reader
        is blocked, which is forever when the process it is reading from is still
        running. That mistake cost four seconds on every crash -- the cost of one
        restart, multiplied by every restart in the run, which was most of the run.
        """
        process, self._process = self._process, None
        if process is None:
            return
        try:
            # Ask it to stop, which it will do between inputs. Killing is the fallback
            # rather than the first move, because a process that is killed while it is
            # running is a crash as far as anything watching is concerned.
            if process.stdin is not None and process.poll() is None:
                process.stdin.write(self.QUIT)
                process.stdin.flush()
                process.wait(timeout=2)
        except (BrokenPipeError, OSError, ValueError, subprocess.TimeoutExpired):
            pass
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        # Now the reader has reached the end of the pipe and has let go of the lock, so
        # closing and joining are immediate. Neither is waited on for long, because
        # neither can block once the process is gone.
        if self._reader is not None:
            self._reader.join(timeout=2)
        for stream in (process.stdin, process.stdout):
            try:
                stream.close()
            except (OSError, ValueError):
                pass

    def _reap(self) -> int:
        """The exit code, waiting briefly for it if the process has only just died.

        The reader sees the end of the pipe the moment the child dies, which is slightly
        before the platform has finished recording how it died. Reading the code at that
        instant gives nothing, and treating nothing as zero reports a crash as a clean
        exit -- which is exactly what happened: every crash was recorded with an exit
        code of zero and reported as "status 0x00000000".
        """
        process = self._process
        if process is None:
            return None
        code = process.poll()
        if code is None:
            try:
                code = process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                code = None
        return code

    def run(self, data: bytes) -> Outcome:
        """Send one input and read back what happened.

        A dead process is a crash, and the coverage of the run that killed it is already
        in the shared region, so it is read before anything is restarted.
        """
        if len(data) > 1 << 20:
            data = data[:1 << 20]
        self.coverage.clear()
        dead = False
        timed_out = False
        try:
            self._process.stdin.write(len(data).to_bytes(4, "little"))
            self._process.stdin.write(data)
            self._process.stdin.flush()
        except (BrokenPipeError, OSError, ValueError):
            dead = True

        if not dead:
            try:
                reply = self._replies.get(timeout=self.timeout)
                dead = reply is None
            except queue.Empty:
                # The run is still going. It is not going to finish in a useful time,
                # and the process has to go: there is no way to interrupt a thread that
                # is blocked on a pipe.
                timed_out = True

        self.executions += 1
        coverage = self.coverage.read()

        if dead or timed_out:
            # What the process did, or nothing if it is still running. A fallback code
            # here would be a fabrication: a run that was killed for taking too long has
            # not told us how it ended, and reporting an access violation for it is
            # inventing a finding. The status says "timeout" when there is no code.
            exit_code = self._reap()
            self._stop()
            self.restarts += 1
            if timed_out:
                self.timeouts += 1
            self._start()
            return Outcome(crashed=True, exit_code=exit_code,
                           coverage=coverage, edges=self.coverage.count(coverage),
                           timed_out=timed_out)
        return Outcome(crashed=False, exit_code=0, coverage=coverage,
                       edges=self.coverage.count(coverage))

    def close(self) -> None:
        self._stop()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
