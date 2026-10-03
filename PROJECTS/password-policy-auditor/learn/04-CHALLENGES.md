# Challenges

- No single profile is the "right" policy; the standards genuinely disagree, and NIST's modern guidance reverses older habits.
- The profile values are a reading of published recommendations, not a certification, and standards carry nuances the model simplifies.
- The common-password list is a tiny illustrative sample, not a breach corpus.
- The pattern checks are heuristics that both miss weak passwords and flag strong ones.
- The password mode audits a list you supply; it cannot tell you what passwords real users chose.

## Working within the scope

NIST SP 800-63B advises against composition rules and mandatory expiry, while the baseline, CIS and PCI-DSS ask for them. Modelling that required a comparison direction and a way to say "absence is compliant", rather than one greater-than check for every field. Running the same file under different profiles shows how much a result depends on the reference you chose.

The bundled policy is a teaching example. It does not read a live directory, a credential store, or an enforced operating-system policy, and a passing result does not measure password strength, MFA, breach detection, or account recovery. Before relying on a profile, read the current text of the standard it claims to represent.

[Back to the project guide](../README.md)
