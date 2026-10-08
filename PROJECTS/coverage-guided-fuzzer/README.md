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
search takes the search down with it. One process is started and fed inputs down a pipe
rather than a process per input; a crash ends that process, and the fuzzer notices and
starts another. The coverage and the comparisons from the run that died were written into
shared memory before it died, so nothing about the crash is lost.

The address space of the target is not randomised, and that is deliberate. A crash through
a corrupted stack goes wherever the corruption pointed, so with the layout randomised the
same input reaches different edges on every run and is reported as two defects — the
signature stops meaning anything for exactly the crashes it exists to group.

## What it does not do

**There is no fork server.** The persistent process removes most of the cost of starting
one per input, but a fork server removes the rest by forking a child that is already past
initialisation, and the platform this is developed on has no `fork`.

**There is no sanitizer.** AddressSanitizer would catch a read or a write that leaves the
memory a program has, at the point it happens. It does not initialise in a process on this
platform, so the crash detection is the process dying, and the report says so rather than
implying a precision it does not have. One consequence is worth naming: a read that goes
past the end of an *input* without leaving the buffer the harness handed over is not
detected here at all, and a defect of that shape would be invisible to this fuzzer.

**A corrupted run can be slow.** Overwriting a parser's own loop counters makes it spin,
and a run like that takes hundreds of milliseconds to fail where every other input takes
microseconds. The fuzzer kills those and records them as hangs, which is a finding in its
own right, but it is a real cost.

**The second target is still one this author wrote.** It is a different format and a
different bug class, and finding it says more than finding the first one does, but it is
not software nobody involved had seen before. That is the test this has still not passed.
