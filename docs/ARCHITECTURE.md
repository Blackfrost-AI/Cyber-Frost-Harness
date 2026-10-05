# Architecture and trust boundaries

## Design objective

Cyber-Frost Harness makes model reasoning operational inside a controlled
native analysis environment. The design separates what the model may inspect
and execute from what the benchmark owner must keep hidden.

## Components

### Model client and agent loop

The client speaks an OpenAI-compatible chat-completions protocol with thinking
and tool calls. The loop validates tool arguments, blocks empty and repeated
calls, bounds tool output, records usage, and checkpoints a compact evidence
ledger. Before each request it estimates the prompt size and reserves a safety
margin; completed tool-call/result units are removed together when compaction
is required. The requested completion budget is clamped to the remaining
context capacity.

### Skill catalog

Skills are loaded lazily so the prompt contains only the procedures relevant
to the current phase. They cover target inventory, native execution,
coverage-guided discovery, structured inputs, crash triage, root-cause
analysis, remediation, and end-to-end purple validation.

### Structured tools

The tool layer exposes bounded operations for target inspection, source
search, file reads, command execution, corpus preparation, fuzzing, replay,
minimization, source patches, candidate submission, evidence recording, and
final selection. Outputs preserve sanitizer classifications, exit status,
sizes, hashes, and bounded log excerpts.

### SSH Docker transport

The orchestration host asks a native x86-64 Docker host to create one ephemeral
container from the task's vulnerable image. The transport uses Docker `--init`,
a PID ceiling, no network, explicit CPU/memory limits, command deadlines, and
per-command environment tags. Descendant processes carrying a completed
command tag are terminated before control returns to the model.

### Artifact and grader boundary

Candidate bytes are copied to the orchestration side, hashed, and replayed.
The model-facing container never receives the fixed image, grader database,
submission credential, Docker control, or private reference PoC. The outer
client submits a bounded number of meaningful candidates; hidden fixed-image
verification occurs after selection.

## Data flow

```text
task metadata -> isolated vulnerable container -> structured observations
                                                    |
model request <- compact evidence + selected skill <-+
      |
validated tool call -> bounded native action -> preserved candidate
                                              |
                           outer submit + hidden verify
```

## Runtime invariants

- The model-facing task container is created only from the vulnerable image.
- Task-container networking is disabled.
- `/tmp/poc` and Git metadata under `/src` are removed before model access.
- Docker control and host credentials are never mounted into the task.
- Full command output remains in the disposable private environment; model
  responses receive bounded excerpts and byte counts.
- A finding is not a benchmark pass until the selected exact bytes fail on the
  vulnerable image and exit cleanly on the hidden fixed image.
- A task with no candidate is a valid model miss unless a separate
  infrastructure error prevented completion.

## Red, blue, and purple outputs

| Mode | Completion evidence |
|---|---|
| Red | Triggering input, stable replay, sanitizer/signal classification, reachability, and root-cause hypothesis |
| Blue | Minimal source patch, original-trigger regression, normal-corpus regression, and detection guidance |
| Purple | Trigger through root cause, repair, regression coverage, and operational telemetry |
