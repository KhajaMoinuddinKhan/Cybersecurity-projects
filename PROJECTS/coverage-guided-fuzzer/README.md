# Coverage-guided fuzzer

A fuzzer that searches a compiled program for the input that breaks it, and then answers
the question the crash raises: whether it is worth anything.

Fuzzing is a search, and the thing that makes this one work is that the search is not
blind. The target is compiled with instrumentation that reports which edges it took on
each run, and that report is what tells the search whether it is getting closer. An
input that reaches somewhere nothing has reached before is kept and built on; an input
that reaches nothing new is thrown away. Over a few thousand executions that turns a
search over a space too large to enumerate into one that walks straight at the defect.

The target is a parser for a small record format, and it has a genuine defect: it checks
that a record fits inside the input before reading it, and never checks that a name fits
the buffer it is copied into. A name longer than thirty-two bytes runs off the end of the
buffer and into a function pointer that sits immediately after it, which is how this kind
of bug actually happens and why it gets exploited rather than merely reported.

## What it does

**It finds the defect from nothing.** The search starts from an empty input and is told
four bytes of tag. Everything else -- the count, the type byte, a length longer than the
buffer -- is discovered from coverage. Nothing is planted, and nothing tells the search
where to look.

**The coverage is real.** The compiler inserts a call on every edge and the fuzzer
answers it, so what comes back is the set of transitions a run took rather than a
measurement of how much code ran. Two inputs that take different paths produce different
maps; the same input always produces the same map, in the same process and across
processes.

**Crashes are bucketed by the path that reached them.** Two inputs that fail the same way
are one defect however different their bytes are, and two inputs that die with the same
exit code after different paths are two. That distinction only exists because the coverage
of a crashing run survives the crash, which it does because the map is written into shared
memory rather than copied out at the end -- and a process that has just died cannot copy
anything.

**The crash is turned into control.** The target exports a function the parser never
calls, and the exploit makes it run. That is the difference between showing that a program
is broken and showing that an attacker can aim it. The same input against the fixed build
reaches nothing and does not crash, because the fix is a bound on the copy rather than a
check that rejects the input -- and a fix that turned a takeover into a crash would not be
a fix.

## How the pieces fit

The target is compiled twice from one source. The difference between the two builds is a
single line, so the exploit is demonstrating a fix rather than a different program.

The target runs as a process of its own, because a defect in the same process as the
search takes the search down with it. One process is started and fed inputs down a pipe
rather than a process per input, which is what makes the throughput usable on a platform
with no `fork`; a crash ends that process, and the fuzzer notices the pipe close and
starts another. The coverage from the run that died was written into shared memory before
it died, so nothing about the crash is lost.

The fuzzer itself is separable and the pieces are worth naming: a mutation engine that
turns one input into the next, a corpus that keeps the inputs that taught it something, a
scheduler that prefers the inputs that taught it the most, and a loop that decides which
of those three a given execution belongs to. The decision in the middle is the whole of
it -- an input that reached nothing new must not be kept, or the corpus fills with inputs
that are all the same shape and the search stops moving.

## The exploit

The overflow lands on a function pointer rather than a return address, which is the
variant that gets exploited in practice: the pointer is used immediately, so control
transfers without the attacker first having to work around the register saves and stack
cookies that stand between a return address and its use.

Two things about the exploit are worth stating plainly, because they are choices.

The offset from the buffer to the pointer is measured rather than assumed. It depends on
the compiler and the structure's layout, and hard-coding it would produce an exploit that
works on the machine it was written on and nowhere else.

The address control transfers to has to come from inside the process. Address space
layout randomisation means the same function sits somewhere different every time a
program starts, so an address read from a loader in another process is that process's
address and a payload built from it lands nowhere. A real exploit solves this with a
leak; rather than invent one, the harness runs inside the target's own process, where the
address it reads is the address that will be used. That isolates the question being asked
to whether a crafted input takes control, rather than where the process happened to be
loaded.

## What it does not do

**There is no fork server.** The persistent process removes most of the cost of starting
one per input, but a fork server removes the rest by forking a child that is already past
initialisation, and Windows has no `fork`. The throughput here is real and it is not the
throughput of a fuzzer on a platform that has one.

**There is no sanitizer.** AddressSanitizer would turn the overflow into an immediate,
precise abort instead of letting a corrupted process run on until something breaks.
It was tried and it does not initialise in a process on this platform -- it fails before
the first input is read -- so the crash detection is the process dying, and the report
says so rather than implying a precision it does not have.

**A corrupted run can be slow.** Overwriting a parser's own loop counters makes it spin,
and a run like that takes hundreds of milliseconds to fail where every other input takes
microseconds. The fuzzer kills those and records them as hangs, which is a finding in its
own right, but it is a real cost and it is most of the difference between the throughput
on the steady state and the throughput on a whole run.

**The dictionary is given the tag.** Four bytes of magic are four bytes a random search
will not find, and telling the search they exist is the difference between finding the
parser in a second and never finding it. Everything past the tag is discovered.
