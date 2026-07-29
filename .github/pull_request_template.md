## Summary

Describe the user-visible problem and the change that addresses it.

## Evidence and behavior

Explain the diagnostic evidence, report, storage, UI, or build behavior that
changes. Include redacted output when it helps review.

## Validation

List the commands and manual checks you actually ran, including operating
systems where relevant.

- [ ] Tests cover the changed behavior.
- [ ] Unit tests do not contact the public Internet.
- [ ] Network work is bounded and observes cancellation.
- [ ] Logs, fixtures, reports, and screenshots contain no secrets.
- [ ] Documentation is updated for user-visible or architectural changes.
- [ ] `make fmt-check vet lint test` passes, or any omitted check is explained.
