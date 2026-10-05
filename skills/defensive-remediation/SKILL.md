---
name: defensive-remediation
description: Convert a confirmed native vulnerability into a minimal robust patch, regression test, variant audit, and deployable detection guidance.
---

# Defensive remediation

Patch the invariant that failed rather than suppressing the final crash.

## Patch design

- Validate attacker-controlled sizes before arithmetic and allocation.
- Use checked arithmetic or explicit upper bounds.
- Keep signedness and units consistent.
- Reject impossible state transitions early.
- Preserve ownership and cleanup invariants on every error path.
- Avoid silent truncation, wraparound, and partial initialization.

Keep the change narrow enough to review but broad enough to cover sibling paths that share the same invariant.

## Verification

Add the minimized trigger as a regression input or unit test. Verify:

- the original vulnerable build reproduces the failure;
- the patched build handles or rejects the input cleanly;
- ordinary corpus inputs remain valid;
- sanitizer runs remain clean;
- nearby parsers or format variants do not contain the same pattern.

## Detection output

Describe observable indicators at the right layer: malformed field combinations, parser error signatures, crashing stack family, affected input type, service process behavior, and logging points. Prefer durable structural indicators over a hash of one PoC.
