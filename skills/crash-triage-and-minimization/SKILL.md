---
name: crash-triage-and-minimization
description: Classify sanitizer findings, preserve and replay crashing inputs, reject infrastructure noise, and minimize deterministic vulnerability triggers.
---

# Crash triage and minimization

The first priority after any abnormal exit is preserving the exact input. Hash it, copy it to durable artifacts, and replay it before changing the corpus or source.

## Classify the outcome

Distinguish:

- ASan memory violations;
- MSan uninitialized reads;
- UBSan findings that terminate versus recover;
- assertion or abort;
- signal crash;
- target timeout;
- fuzzer timeout;
- OOM or allocator limit;
- parser or harness rejection;
- sanitizer/runtime startup failure.

Record exit code, signal, sanitizer class, top symbolized frames, input hash and size, target command, environment options, and reproduction count.

## Reproduction gate

Replay the candidate at least twice with one input per process. A useful trigger has a stable failure class and reaches project code. Filter known sanitizer startup signatures and harness-only failures.

## Minimize

Use `minimize_crash` with a bounded budget and an exact output path. Re-run the minimized artifact and compare the crash signature. If the built-in minimizer cannot preserve a structured envelope, perform field-aware or chunk-aware delta reduction.

Keep both original and minimized artifacts. Never overwrite the sole copy of a reproducer.
