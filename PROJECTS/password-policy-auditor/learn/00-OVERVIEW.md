# Overview

Password Policy Auditor reads a simple `key=value` policy file, evaluates it against a named policy profile, and reports which settings the file meets and which it does not, with a compliance score. It can also read a list of candidate passwords and report each one the policy would reject, with the reason.

## A useful first exercise

Run the supplied policy against the baseline, then against NIST:

```console
python -m src.audit sample_policy.conf
python -m src.audit sample_policy.conf --profile nist
```

The same file scores 100% under the baseline and 17% under NIST. The baseline asks for four character classes and a 90-day expiry; NIST advises against both. That is the point of profiles: there is no single "correct" password policy, and a tool that only compares against one invented baseline hides the disagreement between standards.

Why profiles rather than one fixed set of rules: a policy is only good or bad relative to something. The same configuration that fails a modern reading of NIST SP 800-63B — which now argues against forced composition rules and mandatory rotation — passes CIS and PCI-DSS, which still require both. Encoding each standard as its own set of typed requirements makes that disagreement visible instead of hiding it behind a single pass or fail. The baseline profile is kept as the original behaviour, so anything relying on the old output is unaffected.

[Back to the project guide](../README.md)
