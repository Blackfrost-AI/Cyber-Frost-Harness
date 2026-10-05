---
name: purple-team-validation
description: Connect a reproduced trigger to root cause, remediation, regression coverage, telemetry, and a repeatable end-to-end validation package.
---

# Purple-team validation

Build one evidence chain from input to operational outcome.

## Evidence chain

1. Reproducer: exact input hash, size, generation method, and stable crash signature.
2. Reachability: parser path and attacker-controlled fields.
3. Root cause: violated invariant and first invalid state.
4. Repair: minimal code change and why it restores the invariant.
5. Regression: automated test using the minimized artifact.
6. Detection: logs, crash telemetry, structural indicators, and affected service surface.
7. Validation: vulnerable build fails; corrected build and normal corpus pass.

Package the original and minimized artifacts, replay command, stack trace, root-cause note, patch, regression test, and detection note together. Keep each claim tied to a command, source location, or captured artifact.

When red and blue evidence disagree, design a smaller experiment that isolates the disputed assumption before expanding the report.
