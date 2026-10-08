"""What a crash is, and reducing it to the smallest thing that still causes it.

A crash on its own is not a finding. The interesting questions are whether it is a
different defect from the ones already known, and what the smallest input is that still
causes it -- and both of those are answered here rather than by reading the crash dump.

*Bucketing* is by the path, not the exit code. Two inputs that reach the same edges and
then die are one defect, however different their bytes are; two inputs that die with the
same code after different paths are two. The exit code alone cannot tell those apart,
which is why the coverage of the crashing run is kept -- it is the thing that survived
the crash because it was written into shared memory rather than copied out at the end.

*Minimisation* keeps the crash the same, not merely the crash. Shrinking an input until
it fails differently is not minimisation, it is substitution: the smaller input is a
different defect wearing the first one's name. The check is that the signature is
unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Triage:
    """One distinct defect, with the reproducer that demonstrates it."""

    signature: str
    status: str
    exit_code: int
    data: bytes
    edges: int = 0
    executions: int = 0
    found_by: str = "mutation"
    duplicates: int = 0
    history: list = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def exploitable(self) -> bool:
        """Whether this class of failure is one an attacker can aim.

        A crash from a bad read or a corrupted return address is control the attacker
        has influenced. A timeout is a hang, which is a denial of service and not a
        takeover, and the two are worth telling apart rather than listing together.
        """
        return self.status in ("access violation", "illegal instruction",
                               "stack buffer overrun")


def group(findings: dict) -> list:
    """Turn the fuzzer's findings into a sorted list of defects, worst first."""
    order = {"stack buffer overrun": 0, "illegal instruction": 1,
             "access violation": 2, "timeout": 3}
    return sorted(findings.values(),
                  key=lambda f: (order.get(f.status, 9), f.size))
