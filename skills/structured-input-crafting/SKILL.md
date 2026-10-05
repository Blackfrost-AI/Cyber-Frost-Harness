---
name: structured-input-crafting
description: Construct and mutate valid structured inputs, including container formats and serialized fuzz-test domains, when raw byte mutation cannot cross parser gates.
---

# Structured input crafting

Derive the input grammar from the harness before writing a generator.

## Recover the contract

Trace the harness entrypoint through deserialization and argument construction. Record:

- top-level magic or serialization header;
- field order and primitive encodings;
- length, count, offset, alignment, and checksum rules;
- nested object boundaries;
- enums, ranges, and conditional fields;
- format dispatch and rejection messages;
- size or complexity caps imposed before the vulnerable code.

For tuple/domain fuzzers, read both the declared domain and the compatibility-mode serializer. Reuse project serializer code or a small native encoder when available. Validate one minimal accepted object before adding mutation logic.

## Generation strategy

Build inputs in layers:

1. minimal accepted envelope;
2. one semantically valid payload;
3. controlled variations of a single structural field;
4. boundary combinations near allocations, arithmetic, loops, and indexing;
5. coverage-guided mutations that preserve the envelope.

Favor round-trip checks and parser diagnostics. Save the generator, its parameters, and the exact output bytes. When a candidate is rejected before target logic, fix the envelope instead of increasing random mutations.
