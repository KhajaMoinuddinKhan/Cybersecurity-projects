# Overview

Password Policy Auditor reads a simple `key=value` policy file and compares supported settings with a visible baseline. It checks minimum length, character requirements, password age, and password reuse limits, then reports each setting as pass or review.

## A useful first exercise

Run the supplied policy, then lower `reuse_limit` to 3 in a copy. Only that setting should change to review if the other values stay the same. This illustrates why different policy fields need different comparison directions, rather than one generic greater-than check.

The baseline is an illustrative project choice, not a claim of compliance or current best practice. It uses length 12, four character-class requirements, a maximum age of 90 days, and reuse history of 5. Choose a real policy separately for your environment; a passing result here does not measure password strength, MFA, breach detection, or account recovery.

[Back to the project guide](../README.md)
