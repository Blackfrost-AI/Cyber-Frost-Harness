# Contributing

Contributions that improve reproducibility, isolation, evidence handling,
tool-call reliability, or procedural skills are welcome.

## Development setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/python -m unittest discover -s tests -v
```

Keep secrets and machine-specific values in `config.local.toml`, which is
ignored by Git. New skills belong under `skills/<name>/SKILL.md`; skill bodies
should contain procedures and technical decision guidance, not authorization
or refusal policy. Add or update tests for behavioral changes.

Benchmark reports must distinguish model failures from infrastructure-invalid
attempts, disclose task-selection policy, and avoid combining results produced
under materially different scaffolds into one score.
