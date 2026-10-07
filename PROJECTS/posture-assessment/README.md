# Posture assessment with policy as code

One policy, four environments, and a register an auditor would accept.

The problem this solves is not that container scanners are rare. It is that the
organisation's intentions live in four places at once: a Docker rule in one tool, a
Kubernetes rule in another, a cloud rule in a third, and a paragraph in a spreadsheet
that nobody runs. They describe the same intention, and they drift apart the first
time somebody changes one of them.

So the intention is written once. `policy/controls.yaml` defines twelve controls, each
naming the environments it applies to, the standard it comes from and the owner who
is accountable for it. Four assessors read that one file. A finding therefore inherits
its severity, its ISO 27001 Annex A control, its NIST CSF function and its owner from
the control it violates, rather than being assigned any of them by the assessor that
happened to notice it.

## The controls

Each one names a real reference, so a reader can check the mapping instead of taking
it on trust:

| Control | Applies to | Reference | ISO/IEC 27001:2022 | NIST CSF 2.0 |
| --- | --- | --- | --- | --- |
| Workloads do not run as root | container, kubernetes, iac | CIS Docker 4.1 | A.8.2 | PR.AA |
| Containers are not privileged | container, kubernetes | CIS Docker 5.4 | A.8.2 | PR.PS |
| Services refuse anonymous access | iot, kubernetes, iac | CIS K8s 5.1.1 | A.8.5 | PR.AA |
| Default credentials are not in use | iot, container, iac | CIS Docker 4.1 | A.8.5 | PR.AA |
| Workloads do not share the host network | container, kubernetes | CIS Docker 5.10 | A.8.20 | PR.IR |
| Management interfaces are not reachable | iot, iac, kubernetes | CIS K8s 5.2.2 | A.8.20 | PR.IR |
| The root filesystem is read-only | container, kubernetes | CIS Docker 5.12 | A.8.9 | PR.PS |
| Images are pinned to a version | container, kubernetes, iac | CIS Docker 4.7 | A.8.9 | ID.AM |
| A firmware update path exists | iot | — | A.8.8 | ID.RA |
| Workloads declare resource limits | container, kubernetes | CIS K8s 5.2.2 | A.8.6 | PR.IR |
| Secrets are not written into configuration | all four | CIS Docker 4.10 | A.8.24 | PR.DS |
| Cloud identities are scoped | iac, kubernetes | CIS K8s 5.1.3 | A.8.2 | PR.AA |

The loader refuses a policy that would quietly stop being one: a control naming an
environment nothing implements, an environment with no controls behind it, two
controls sharing an identifier, and a control with no stated intent. A rule without a
reason is the one somebody disables at three in the morning.

## The four assessors

**Containers** read Dockerfiles and compose files as text. Nothing is built and no
daemon is involved, which is deliberate: the question is whether the configuration
describes something safe, and building the image to ask would mean running the thing
under assessment.

**Kubernetes** reads manifests and follows every workload kind that carries a pod
template, checking the pod-level security context as well as the container-level one,
because Kubernetes merges them and a setting in either place is a setting. It also
reads `Role`, `ClusterRole` and `RoleBinding` objects, because a wildcard permission
is a posture finding whether or not a workload uses it.

**Infrastructure as code** reads Terraform. This is the one environment where a control
can be enforced before anything is deployed, and the one where a mistake is cheapest
to fix. The parser is a block reader rather than an HCL evaluator, and the limit is
stated rather than hidden: a rule whose ports arrive from a variable is reported as
**unknown**, not as clear. Reading it as clear would be a false negative, and a false
negative is the failure mode that matters for a tool whose job is to tell you what is
wrong.

**IoT** talks to a real MQTT broker. The questions that matter about a small device are
not answerable from a configuration file -- whether the broker accepts a connection
from anybody, and whether it accepts the credential printed in its own manual, are
properties of the running thing. The MQTT client is written here in the standard
library, so the assessment needs no third-party package, and it distinguishes three
answers that are easy to conflate: accepted, refused, and no answer at all. The third
is reported as unknown, because an unreachable broker and a secure one look identical
from a socket.

## The register

Findings become register entries with a stable reference, an owner, a treatment
decision, and the ISO and CSF mappings inherited from the control. The rating is
derived from the control's severity rather than scored per finding, which is a
deliberate choice worth stating: a per-finding likelihood score would need an estimate
of exploitability that nothing here measures, and inventing one would make the register
look more precise than the evidence behind it.

The report also lists the controls **nothing violated**, because a register showing
only failures cannot distinguish a control that is satisfied from one that was never
checked, and that distinction is the point of the register.

## What the lab contains

`lab/` holds real artifacts with real mistakes: a Dockerfile with no `USER`
instruction, a compose file that sets `network_mode: host`, a manifest that publishes
a NodePort on 22 and grants a wildcard role, and Terraform that opens port 22 to
`0.0.0.0/0` and writes a password as a literal. Each is a genuine mistake rather than
a contrived one -- the Terraform rule is what a rule written at three in the morning
looks like.

`lab/lab.json` records what is in there and which control each flaw is meant to
violate. The assessors are never told any of it; the tests read it, so a fixture that
stops exercising a control fails rather than passing quietly.

The broker runs in two configurations, and both are needed: one that accepts
connections from anybody, and one that refuses them. A check that fires on the
vulnerable configuration and also on the hardened one is not detecting anything, and
there is no way to tell the two apart from the first case alone.

## Running it

```
python -m src.cli --policy policy/controls.yaml \
    --dockerfile lab/Dockerfile.vulnerable \
    --kubernetes lab/deployment.vulnerable.yaml \
    --terraform lab/main.tf \
    --inventory lab/inventory.json \
    --mqtt 127.0.0.1:1883 \
    --out posture-output
```

`python -m lab` starts the broker on loopback, which is the configuration the IoT arm
is meant to be pointed at. `--no-default-credentials` skips the published
default-credential check for a broker you would rather not have probed.

## Limits

The assessors read configuration, not running state. A container that is configured
safely and running unsafely is not something this can see, because seeing it would
mean querying a daemon and the daemon is not what is being assessed.

The Terraform reader does not resolve variables, `locals`, module outputs or a
remote state file, and it says so at every point where that matters.

The IoT arm assesses a broker and a declared device inventory. It does not enumerate a
network, fingerprint firmware, or discover devices -- those need a network position
this tool does not take, and a discovery step that guessed would produce an inventory
nobody had verified.
