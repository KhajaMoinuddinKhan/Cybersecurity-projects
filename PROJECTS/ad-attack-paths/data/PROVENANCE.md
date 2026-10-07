# Where this data came from

These are real BloodHound collector archives, not files written for this project.
They are the sample data published for BloodHound Community Edition, collected with
SharpHound against the GOADv2 lab, and republished at:

    https://github.com/m4lwhere/Bloodhound-CE-Sample-Data

Three domains, with trusts between them:

| Archive | Domain | Users | Groups | Computers | Trusts |
| --- | --- | --- | --- | --- | --- |
| `ESSOS_...zip` | ESSOS.LOCAL | 13 | 89 | 2 | SEVENKINGDOMS.LOCAL |
| `NORTH_...zip` | NORTH.SEVENKINGDOMS.LOCAL | 16 | 84 | 2 | SEVENKINGDOMS.LOCAL |
| `SEVENKINGDOMS_...zip` | SEVENKINGDOMS.LOCAL | 15 | 87 | 1 | NORTH, ESSOS |

They are vendored rather than downloaded so that the tests run offline and so that
the exact bytes the results were computed from are in the repository. A result that
cannot be re-derived from the committed input is not a result anybody can check.

The archives were checked for credentials before being committed: every field that
could carry one (`userpassword`, `unicodepassword`, `unixpassword`, `sfupassword`,
`gmsa`) is empty throughout. This is lab data for a deliberately vulnerable
training range, and it carries no secrets.

The collector format is the one SharpHound writes: one JSON file per object type,
each of the shape `{"meta": {...}, "data": [...]}`. `meta.version` is 6 in all
three archives.
