# Coverage-guided fuzzer

A fuzzer that searches a compiled program for the input that breaks it, and then answers
the question the crash raises: whether it is worth anything.

Fuzzing is a search, and the thing that makes this one work is that the search is not
blind. The target is compiled with instrumentation that reports two things on every run:
which edges it took, and what it compared. The edges say where the program went. The
comparisons say what it wanted, and that second half is what turns a search over four
billion possible first bytes into being told, one comparison at a time, that the first
byte should have been `R`.

## What it does

**It finds defects without being told anything about the format.** The search starts from
an empty input and an empty dictionary. It has to find the tag, the record count, the type
byte and a length longer than the buffer, and it does — because the parser compares each
byte of the tag against a constant and the comparison names the constant. The format is
learned from the target rather than handed to it.

**It finds them in more than one target.** A fuzzer that has only ever been pointed at the
program it was written for has not been tested in the way that matters, so the target is a
parameter. Two are shipped, with different formats and different bug classes:

| target | format | the defect |
|---|---|---|
| `parser` | a tagged record container | a name is copied into a buffer without checking it fits, and a function pointer sits immediately after it |
| `interval` | a count and that many intervals | a size is computed in sixteen-bit arithmetic, so the check it feeds wraps and the count then indexes a fixed array |

Both are found from an empty seed with nothing supplied, and neither is found in the fixed
build.

**The coverage is real.** The compiler inserts a call on every edge and the fuzzer answers
it, so what comes back is the set of transitions a run took rather than a measure of how
much code ran. Two inputs that take different paths produce different maps; the same input
always produces the same map, in the same process and across processes.

**Crashes are bucketed by the path that reached them.** Two inputs that fail the same way
are one defect however different their bytes are. That only works because the coverage of
a crashing run survives the crash — the map is written into shared memory rather than
copied out at the end, and a process that has just died cannot copy anything.

**The crash is turned into control.** The `parser` target has two defects and the exploit
needs both. The overflow puts a function pointer under the attacker's bytes; a disclosure
record writes its structure back out including the address it stored. The exploit reads
that address, works out from it where the function it wants must be, and only then builds
the payload. Nothing about the address is assumed: the offset is a property of the binary
and is read from the binary, and the base comes from the disclosure. The same payload
against the fixed build stops at the first stage, because the fix removes the disclosure
as well as the missing bound.

## How the pieces fit

The target is compiled twice from one source. The difference between the two builds is a
guard on two copies, so the exploit is demonstrating a fix rather than a different
program.

Three groups of files are compiled separately, and what is instrumented is decided by the
build rather than by an attribute a compiler may or may not honour: the target gets the
instrumentation, the runtime that answers it does not, and neither does the driver. The
runtime being uninstrumented is not a detail — if it is compiled with the flag, every call
to a callback is a call to itself, which is infinite recursion and a program that dies
before reading its first input.

The target runs as a process of its own, because a defect in the same process as the
search takes the search down with it. Two ways to drive it, and the difference is what
each costs and what each survives:

- **A persistent process**, fed inputs down a pipe. A crash ends it, and the fuzzer
  notices and starts another; the coverage and comparisons from the run that died were
  written into shared memory before it died, so nothing about the crash is lost. This is
  the faster of the two on the machine this was measured on, at about 8,400 executions a
  second against 3,100.
- **A fork server**, where the platform has `fork`. The process is started once and
  stopped one step before reading, and each execution forks it -- so the child begins
  where the image mapping and the runtime initialisation were already finished. It is
  slower here than the persistent process, which was not what was expected, and the
  reason is that the persistent process forks nothing at all while the fork server pays
  for a fork and a wait per execution. What it buys instead is a child that has never run
  anything before, and a crash that takes the child rather than the server, so the search
  is never interrupted by the thing it is searching for.

The address space of the target is not randomised, and that is deliberate. A crash through
a corrupted stack goes wherever the corruption pointed, so with the layout randomised the
same input reaches different edges on every run and is reported as two defects — the
signature stops meaning anything for exactly the crashes it exists to group.

## What it does not do

**There is no fork server.** The persistent process removes most of the cost of starting
one per input, but a fork server removes the rest by forking a child that is already past
initialisation, and the platform this is developed on has no `fork`.

**The sanitizer is available on one platform and not the other.** AddressSanitizer
catches a read or a write that leaves the memory a program has, at the point it happens,
and names the function it happened in; the plain build dies of the same defect without
saying where, or does not die at all. It links here on Linux and not on Windows, and the
build asks rather than assuming — a request for it where it cannot be linked is refused
rather than quietly producing a build without one, because a report that says a sanitizer
caught something when it was never there is worse than no sanitizer.

The target is handed a buffer of exactly its input's length for the same reason. A parser
given a megabyte of scratch to overrun will read past its input and stay inside the
allocation, nothing faults, and a defect of that shape is invisible — which is not
hypothetical: the first version of the `interval` target had exactly that and was
correctly not detected.

**A corrupted run can be slow.** Overwriting a parser's own loop counters makes it spin,
and a run like that takes hundreds of milliseconds to fail where every other input takes
microseconds. The fuzzer kills those and records them as hangs, which is a finding in its
own right, but it is a real cost.

**Both targets are reached from an empty seed, in every run.** The interval target between
the second and two-hundredth execution; the parser between the eighteen-hundredth and the
eighteen-thousandth, across sixteen seeds each. Getting there took finding the thing that
made the parser unreliable, and it is worth naming because it is the kind of mistake that
looks like bad luck.

A comparison says what value a program wanted and never says where it wanted it. The
parser compares its third byte against `C`, and all the search learned was that 67 was
wanted somewhere -- so it placed the wanted bytes at random offsets, and a magic number is
four bytes in four particular places in a particular order. The search knew all four bytes
of the tag and reached twelve edges of a parser whose first check is four bytes it already
knew. Trying each wanted value at each position is what closes the gap: the position comes
from the loop rather than from the comparison, which is enough, because the values are few
and the positions are bounded. Setting a position to a value that earns new coverage keeps
the result and walks it in turn, so the tag is built a byte at a time and each byte is a
starting point for the next.

**The fork server is slower than the persistent process here, not faster.** That is the
opposite of the usual result and it is what was measured: a fork and a wait per execution
costs more than a pipe round trip when the process on the other end of the pipe is already
running. A fork server is normally reached for because persistent mode is not available
or not safe for the target, not because it is quick.

**The second target is still one this author wrote.** It is a different format and a
different bug class, and finding it says more than finding the first one does, but it is
not software nobody involved had seen before. That is the test this has still not passed.
