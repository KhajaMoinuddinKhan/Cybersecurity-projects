"""Load management: how fast the tool is allowed to ask, and how many at once.

An assessment tool that opens as many connections as it can is a denial-of-service
tool with a report attached. Being allowed to connect to a host is not permission
to hammer it, and the two are separate decisions -- which is why the rate limit
lives here, beside the scope engine, rather than being left to whatever the
operating system will tolerate.

Two controls, both honest about what they do:

  - A token bucket caps the request rate. Tokens are replenished at a fixed rate
    and a request takes one; when the bucket is empty the caller waits. The rate
    is the long-run average, so a burst is possible up to the bucket's capacity,
    which is what a bucket is for.
  - A bounded worker pool caps concurrency. The rate limit controls how often, and
    this controls how many at once, and both matter: a hundred requests a second
    issued one at a time is gentle, and the same hundred issued at once is not.

Nothing here knows about scope. Scope decides whether an action may happen; this
decides how often, and keeping the two apart is what stops "we were allowed to
connect" from quietly becoming "we were allowed to flood".
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

__all__ = ["Throttle", "TokenBucket", "RateExceeded"]


class RateExceeded(RuntimeError):
    """The caller asked for more than the engagement permits."""


class TokenBucket:
    """A rate limiter that allows a burst up to its capacity.

    Implemented with a lock rather than a timer thread, so a caller that waits is
    the only thing that ever sleeps and the process has no background thread to
    leak. `acquire` returns the seconds it waited, which is worth having: a report
    can then say how much the target was spared rather than only that it was.
    """

    def __init__(self, rate_per_second: float, capacity: float | None = None):
        if rate_per_second <= 0:
            raise ValueError("the rate must be greater than zero")
        self.rate = float(rate_per_second)
        self.capacity = float(capacity if capacity is not None else max(1.0, rate_per_second))
        self._tokens = self.capacity
        self._updated = time.monotonic()
        self._lock = threading.Lock()
        self.waited = 0.0

    def acquire(self, tokens: float = 1.0) -> float:
        """Take a token, waiting if there is none. Returns the seconds waited."""
        if tokens > self.capacity:
            raise RateExceeded("a request of %.2f tokens exceeds the bucket's capacity of %.2f"
                               % (tokens, self.capacity))
        waited = 0.0
        while True:
            with self._lock:
                now = time.monotonic()
                self._tokens = min(self.capacity,
                                   self._tokens + (now - self._updated) * self.rate)
                self._updated = now
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    self.waited += waited
                    return waited
                deficit = tokens - self._tokens
                nap = deficit / self.rate
            time.sleep(min(nap, 1.0))
            waited += min(nap, 1.0)


@dataclass
class Throttle:
    """The pair of limits, and a pool that obeys both.

    `run` takes an iterable of callables and returns their results in order, which
    keeps a caller's code linear while the work happens concurrently. Order is
    preserved deliberately: a report that listed findings in whatever order the
    threads finished would be different every run, and a finding list that changes
    between runs is one nobody can review.
    """

    rate_per_second: float = 10.0
    workers: int = 4
    bucket: TokenBucket = field(init=False)
    waited: float = 0.0
    completed: int = 0

    def __post_init__(self):
        if self.workers < 1:
            raise ValueError("there has to be at least one worker")
        if self.workers > 32:
            raise ValueError("more than 32 workers is not a rate limit, it is an incident")
        self.bucket = TokenBucket(self.rate_per_second)

    def acquire(self) -> float:
        waited = self.bucket.acquire()
        self.waited += waited
        return waited

    def run(self, jobs):
        """Run the jobs, at most `workers` at once and at most `rate_per_second`
        a second. Returns results in the order the jobs were given."""
        jobs = list(jobs)
        if not jobs:
            return []
        if self.workers == 1 or len(jobs) == 1:
            results = []
            for job in jobs:
                self.acquire()
                results.append(job())
                self.completed += 1
            return results

        def guarded(job):
            self.acquire()
            value = job()
            with self.bucket._lock:
                self.completed += 1
            return value

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            return list(pool.map(guarded, jobs))

    def as_dict(self) -> dict:
        return {"rate_per_second": self.rate_per_second, "workers": self.workers,
                "requests": self.completed, "seconds_waited": round(self.waited, 3)}
