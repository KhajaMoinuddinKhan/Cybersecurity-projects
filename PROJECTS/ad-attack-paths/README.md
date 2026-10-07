# Active Directory attack paths

What is privileged in a directory, how an attacker reaches it, and the smallest change
that closes the routes.

A list of attack paths tells you what is wrong. It does not tell you what to change.
Almost every path in a real directory runs through a handful of objects, and finding
that handful is a different question from finding the paths -- it is a cut problem, and
it has an exact answer rather than a ranked guess.

## The data is real

Three SharpHound archives collected against the GOADv2 lab, vendored in `data/` with
their provenance. They were checked for credentials before being committed: every field
that could carry one is empty throughout.

Testing against real collector output rather than files written here is the point. The
shapes that broke this were the ones nobody would have invented:

- **sessions are nested** under a `Results` key inside a collection record, so reading
  the field as a list yields nothing and raises nothing;
- **`ContainedBy` points at a GUID** while accounts, groups and domains are keyed by
  SID, and **forty containment references point at objects the collector never
  collected**;
- **no group in any of the three domains carries the `highvalue` flag**, so anything
  that read that flag would have found nothing and reported a clean forest.

## What counts as a crown jewel

The obvious approach is to look for the group called "Domain Admins". That is wrong
twice over: it hard-codes an answer the data already contains, and it finds nothing in
a directory that has renamed the group, or localised it, or built its own privileged
group instead. The name is a label; the question is what the object can do.

The seed set is derived from four things, none of which is a name:

- the **well-known relative identifiers** -- 512, 516, 518, 519, 520, 521 -- which are
  part of the specification rather than part of any directory;
- the **`adminCount` attribute**, which the directory itself sets on an object placed in
  a protected group and which survives renaming;
- holding **both halves of replication** on a domain -- `GetChanges` with
  `GetChangesAll` -- which is reading every secret in the domain;
- being a **domain controller**, which holds the directory database.

The set is then closed under the graph: anything from which a seed can be reached is
itself a crown jewel, because controlling it controls the seed. That closure is the
actual definition, and it is why a plain user with a write permission over a domain
controller is a crown jewel here even though nothing about the user looks privileged.

The closure runs **one way only**. A domain administrator can reach a file share, and
that does not make the file share worth protecting. Closing in both directions was the
first attempt and it swallowed three hundred of the three hundred and thirty-one
objects in one domain, which is the same as saying nothing.

## What is not an attack edge

A trust and a container relationship are both real, both belong in a report, and
neither is a way to move. A trust permits authentication across it and does not grant
control of anything there; a container holding an object says nothing about who may
modify it.

Treating either as an attack edge invents paths nobody could walk, and a fabricated
route through a container looked exactly like a real finding until it was read closely.
Both are recorded, reported, and never traversed.

## The edges that are real

An access control entry sits on the object it protects and names the principal holding
the right, so the traversal runs **principal to object** -- the opposite of how the
entry reads. A reader who takes the entry at face value builds the graph backwards.

A session runs the other way, **machine to user**, because compromising the machine
yields the credentials of whoever is logged into it. That is the direction that makes a
session worth finding, and it is the reverse of how the collector writes it.

`src/rights.py` states what each of the forty rights grants and which way it runs. That
table is domain knowledge, written down once so every part of the tool agrees about it
-- the same kind of table as the CVSS weights or the CIS control numbers in the other
projects. Nothing in it says which paths exist in a given directory.

## The metric is hops

A weighted model would need a number for how hard each right is to abuse, and any such
number is a guess dressed as a measurement: nobody has measured how much harder
`WriteDacl` is than `GenericAll`. Hop count is a fact about the graph, it is
reproducible, and a reader can count it. Where several paths are equally short the
search returns a stable one, so the answer does not change between runs.

## What to fix

Two analyses, because they answer different questions.

**Choke points** -- how many routes lose their way to a crown jewel if one object is
fixed. Recomputed after each removal rather than estimated, because routes are not
independent: removing one object can make another irrelevant, and a count that ignored
that would overstate the second.

**The smallest change** -- the minimum set of objects whose removal disconnects every
route. That is a minimum *node* cut, solved exactly with max-flow over a node-split
graph rather than approximated greedily, and the flow value equalling the cut size is
what makes it a proof rather than a suggestion.

There is a case where no cut exists and it is reported rather than papered over. If a
starting object reaches a crown jewel in a single step, no set of intermediate objects
disconnects them, and the honest answer is that those objects have to be fixed rather
than routed around.

## Running it

```
python -m src.cli --data data/ESSOS_....zip --data data/NORTH_....zip \
    --data data/SEVENKINGDOMS_....zip --out attack-paths
```

Give `--data` more than once for a forest. A forest is not one domain: trusts run
between domains and a compromise in one is a route into another, so reading a single
archive reports the trust as an unresolved reference and misses everything beyond it.

`--seeds-only` reports only the objects privileged on their own evidence.
`--cut-deep-only` computes the smallest change using only the routes that need an
intermediate object.

## The fields that were parsed and never used

An audit of which collector fields actually produce edges found four that were read and
then thrown away, and three of them carried real paths:

- **`RegistrySessions`** holds the sessions in this data. The `Sessions` field is empty
  throughout the forest, and reading only that missed every session in it. The registry
  and privileged collections are read now, and the first route this found was a
  workstation whose session belongs to a privileged account.
- **`LocalGroups`** gives membership of a machine's local administrators group,
  identified by RID 544 rather than by name for the same reason as everywhere else.
- **`SPNTargets`** is where an account's service principal name is hosted, which is a
  credential route: any authenticated principal can request a service ticket encrypted
  with that account's password.
- **GPO `Links`** are policy abuse. A policy linked to a container applies to the
  computers and users inside it, so editing the policy configures them. This is the one
  case where containment *is* an attack edge, and it is from the policy rather than from
  the container.

That last one nearly went in wrong. Applying the edge to every descendant produced a
path from the default domain policy to the domain administrators group, which is not
something anybody can walk: a policy configures computers and users, and does not grant
control of a group object. It read exactly as convincingly as the real paths beside it.

## What it reads and does not use

A collector returns fields this does not turn into routes, and the report names them
rather than dropping them. `AllowedToDelegate` and `AllowedToAct` are delegation;
`HasSIDHistory` is a principal holding another domain's identifier, which is a way
across a trust; `GPOChanges` is the local group membership a policy grants. None of
them is populated in this data, so nothing is reported here -- but a tool that reads a
field and silently discards it produces a report that looks complete either way, which
is the same failure as treating an unread rule as clear.

Trusts are recorded and reported and deliberately not walked. A trust permits
authentication across it and does not grant control of anything in the other domain,
so treating it as a route invents paths. What actually crosses a trust is SID history
or a compromised trust key, and that is the field above rather than the trust itself.

## What crosses a trust

A trust on its own permits authentication and grants nothing, so it is recorded and
never walked. What crosses one is an identifier carried from the other side, and SID
filtering is the mechanism that stops it being accepted. Where filtering is off, a
principal holding a SID from the other domain *is* that identifier there, and holds
whatever it was granted. Every trust in this data has filtering off, and that is
reported as its own section rather than left implicit in a decision not to walk it.

## Certificate binding

Two registry settings decide whether a certificate issued for one identity is accepted
when presented for another, which is the difference between a stolen certificate being
useless and being a logon. They are read, and where the collection was refused them the
report says so rather than reporting a value: an uncollected setting is not a setting
that is off, and saying otherwise is the most dangerous answer available.

## Limits

The tool reads what the collector collected. Sessions, local group membership and
registry data are collected per machine and are often refused -- this data has
`ErrorAccessDenied` on the privileged session collection for four of the five machines,
so the routes here understate what is present rather than overstate it.

Certificate services rights are modelled -- `Enroll`, `ManageCA`, `ManageCertificates`
-- but the escalation techniques built on them are not enumerated. A certificate
template that permits a subject alternative name is a route to any principal's identity
and this does not chase that chain.

Rights the table does not know are reported rather than dropped. Treating an unknown
right as harmless is the same mistake as treating an unread rule as clear.
