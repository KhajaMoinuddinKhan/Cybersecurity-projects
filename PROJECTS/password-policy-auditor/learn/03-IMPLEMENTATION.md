# Implementation

- `RECOMMENDED` keeps the reference values in one visible dictionary.
- The parser ignores blank lines and comments.
- Boolean text becomes Python booleans and other accepted values become integers.
- Minimum length, maximum age, and reuse history use separate comparison rules.
- Missing or incompatible values are returned for review.

## Inputs and failure handling

The file uses one `key=value` setting per line. Blank lines and lines beginning with `#` are ignored. Values are integers or `true`/`false`. The bundled policy is a teaching example; the tool does not read or change Windows, Linux, or directory-service password settings.

Use booleans for `require_upper`, `require_lower`, `require_digit`, and `require_symbol`, and integers for the numeric settings. A malformed line identifies its line number. Numeric values such as zero maximum age receive review under this example policy.

[Back to the project guide](../README.md)
