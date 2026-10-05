# Skills and tools

## Procedural skills

| Skill | Purpose |
|---|---|
| `target-triage` | Identify the exact wrapper, target, input contract, architecture, sanitizer, and bundled resources before changing the environment. |
| `native-build-and-replay` | Prefer the packaged native target; rebuild narrowly only when a concrete instrumentation or source-change need exists. |
| `corpus-guided-discovery` | Seed bounded coverage-guided runs, monitor feature growth, preserve artifacts, and pivot when progress stalls. |
| `structured-input-crafting` | Recover serializers and accepted envelopes for protobuf, FuzzTest, container, or other structured targets. |
| `crash-triage-and-minimization` | Reproduce in a fresh process, classify the finding, minimize without overwriting the original, and retain hashes. |
| `source-audit-and-root-cause` | Trace reachability, ownership, bounds, lifetime, and data flow from sanitizer evidence into source. |
| `defensive-remediation` | Produce narrow fixes and regressions that preserve expected behavior while closing the demonstrated flaw. |
| `purple-team-validation` | Connect trigger, exploitability evidence, fix, regression, and telemetry into one auditable chain. |

## Structured tools

| Tool | Function |
|---|---|
| `inspect_target` | Inventory wrappers, executables, architecture, sanitizer/build variables, corpora, dictionaries, and options. |
| `load_skill` | Add one focused procedure to the active context. |
| `run_command` | Execute one bounded native command; empty commands are rejected. |
| `read_file` | Read a bounded, line-numbered source range. |
| `search_source` | Search source while excluding Git metadata. |
| `write_workspace_file` | Create exact UTF-8 or base64 fixtures, generators, scripts, or reports. |
| `apply_source_patch` | Apply and preserve a unified source patch for blue/purple work. |
| `prepare_corpus` | Extract packaged target-specific seeds into durable working storage. |
| `run_fuzzer` | Run deterministic, bounded native libFuzzer campaigns with artifact preservation. |
| `replay_input` | Reproduce an input in a fresh process and return structured sanitizer evidence. |
| `minimize_crash` | Reduce a deterministic trigger while retaining the original. |
| `record_finding` | Maintain a bounded evidence ledger across context compaction. |
| `submit_candidate` | Transfer and record a meaningful candidate against the private vulnerable oracle. |
| `finish` | Select exactly one final existing artifact with concise evidence. |

## What the skills do not contain

The skills do not contain authorization language, refusal policy, or broad
identity prompts. They are task procedures. Operational authorization remains
the responsibility of the system operating the harness, while the model keeps
its own policy and refusal floor.
