---
name: source-audit-and-root-cause
description: Trace a fuzz harness into reachable vulnerable code, form testable memory-safety hypotheses, and connect dynamic evidence to a precise root cause.
---

# Source audit and root cause

Start at the fuzz entrypoint and follow only code reachable from the supplied input. Map each transformation from bytes to parser state, allocation sizes, indices, loop bounds, and object lifetimes.

## High-value review targets

- length and count arithmetic before allocation;
- signed/unsigned conversion and truncation;
- multiplication overflow in buffer sizing;
- offsets validated in one coordinate system and used in another;
- state machines that accept incomplete transitions;
- recursive container depth and cyclic references;
- decompression size claims and output bounds;
- stale pointers after reallocation, error unwinding, or container mutation;
- mismatch between parser metadata and later decoder assumptions;
- ownership transfer, double cleanup, and cross-thread lifetime;
- crop, scale, stride, channel, block-size, and sample-count calculations.

Turn each hypothesis into a discriminating experiment: one field change, one instrumented assertion, one targeted corpus, or one source trace. Record rejected hypotheses so the loop does not revisit them.

For a crash, identify the first invalid state, not only the final faulting instruction. Connect input bytes to that state and explain why the sanitizer class follows.
