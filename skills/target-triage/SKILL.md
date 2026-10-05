---
name: target-triage
description: Rapidly map an unfamiliar native security target, its harness contract, bundled artifacts, build system, and cheapest productive experiments before deep analysis.
---

# Target triage

Produce a target map before building or fuzzing.

## Target map

Record these facts in the evidence ledger:

- wrapper-selected executable and its exact command line;
- sanitizer and fuzzing engine;
- harness entrypoint and the code it calls;
- expected input representation: raw file, structured container, serialized tuple, packet stream, archive, or executable;
- source root and build script;
- seed corpora, dictionaries, options files, example/test data, and generated fixtures;
- whether the shipped target already runs natively;
- one cheap valid seed and the observable behavior it reaches.

Use `inspect_target` first. Read the wrapper, target source, build script, and any `.options` file. Inspect executables with `file` and libraries with `readelf -h` before compiling anything.

## First experiments

Prioritize experiments in this order:

1. Replay the smallest bundled corpus sample through the exact target.
2. Replay the whole bundled corpus with bounded time and preserve any artifact.
3. Read the harness and locate size limits, parser selection, magic checks, feature flags, and downstream APIs.
4. Identify the narrowest input family that reaches deep code.
5. Choose between corpus fuzzing, structure-aware generation, or source-guided construction.

Avoid treating a clean exit as evidence that the harness did nothing. Use target logs, coverage growth, parser diagnostics, or targeted source instrumentation to determine reachability.

## Stop conditions

Move out of triage once the target, input contract, seed source, and next discriminating experiment are known. If ten steps pass without those four facts, stop the current line of work and inspect the wrapper and harness again.
