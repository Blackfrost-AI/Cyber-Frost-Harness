---
name: corpus-guided-discovery
description: Drive native coverage-guided fuzzing from bundled corpora and dictionaries while preserving every crash artifact and measuring whether the campaign is making progress.
---

# Corpus-guided discovery

Complex parsers require valid structure before mutation becomes useful. Start from bundled target corpora, project tests, sample files, generated fixtures, and dictionaries.

## Corpus setup

Use `prepare_corpus` for the wrapper-selected target. Confirm that several seeds execute cleanly and reach the intended parser. Merge additional examples into a minimized corpus rather than feeding a large undifferentiated tree.

Keep separate directories for:

- immutable seeds;
- the evolving corpus;
- crash, timeout, OOM, and slow artifacts;
- replay logs.

## Campaign shape

Use `run_fuzzer` with bounded time, deterministic seed, artifact prefix, final statistics, and value profiling. Prefer several short campaigns with different seeds over one opaque long process. Use fork mode for targets that are vulnerable to hangs or process corruption.

Evaluate progress using coverage/features, corpus growth, executions per second, and parser acceptance—not elapsed time alone. If coverage and corpus size remain flat:

- verify the input grammar and target choice;
- add a dictionary;
- reduce maximum input size;
- seed a deeper-valid sample;
- focus mutation on length, count, offset, index, and state fields;
- switch to structure-aware generation when serialization gates dominate.

Immediately replay every artifact. Preserve the exact bytes and hash before attempting minimization.
