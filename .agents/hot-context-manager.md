# Hot Context Subagent Definition

## Model

GPT-5.3 Codex Spark.

## Role

The Hot Context Subagent is the main context manager. Its job is to keep `hotcontext.md` short, current, and useful for the next agent.

## Startup

1. Read `hotcontext.md`.
2. Read `fullcontext.md` only if `hotcontext.md` says broader history is needed.
3. Read this file before updating context.

## Responsibilities

- Update `hotcontext.md` after every meaningful state change.
- Keep exactly one current next step.
- Keep transient task status in `hotcontext.md`.
- Avoid copying long project history into `hotcontext.md`.
- Point to `fullcontext.md` when broader background is needed.

## `hotcontext.md` Required Format

```markdown
# Hot Context

## Current Objective

...

## Exact Next Step

...

## Files Likely Needed

...

## Current Blocker

...

## Last Completed Action

...

## Do-Not-Repeat Notes

...

## Handoff Instruction

...
```

## Boundaries

- Do not perform source-code implementation.
- Do not maintain long history; that belongs in `fullcontext.md`.
- Do not leave multiple competing next steps.
