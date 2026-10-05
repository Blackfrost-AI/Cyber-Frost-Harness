# Changelog

## 0.2.0 — 2026-10-05

- Reconciled the first dynamic hard-12 run at five verified solves across ten valid outcomes, with two context-invalid tasks left unresolved after the VM became unavailable.
- Fixed zero-submission no-candidate tasks being mislabeled as infrastructure errors.
- Added separate pass, model-failure, and infrastructure counters plus complete usage aggregation.
- Added token-aware compaction, dynamic completion budgeting, and exact recovery from OpenAI-compatible context-limit errors.
- Bounded persistent evidence-ledger entries to keep generated checkpoints finite.
- Added Docker `--init`, per-command orphan cleanup, a 256-PID default, and explicit no-detach operating guidance.
- Expanded the local regression suite from 20 to 29 tests.
