# Detection rules

Rules are stored in JSON so the detection logic is easy to inspect and change. Match rules look for specific event properties. Threshold rules group matching events by a field such as source address and raise an alert when enough events occur inside a time window.

## Read a rule as a hypothesis

For DET-001, the hypothesis is that several authentication failures from one source within a short interval deserve investigation. The engine first checks event_type, groups matches by source, sorts by timestamp, and counts events inside the inclusive window. It emits non-overlapping batches: events already used for an alert are not reused in the next one.

For match rules, all conditions must hold on the same event. Text comparisons are case-insensitive, contains is a substring check, in expects a list, and greater_or_equal converts comparable values to numbers. These choices matter: an -enc substring is broader than a parsed PowerShell argument. Add both positive and negative examples when tuning a rule.

[Run the lab](../README.md)
