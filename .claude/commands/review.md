---
description: Pre-PR review — runs reviewer (code) and manifest-reviewer (deploy/) as parallel subagents, then merges the verdicts.
argument-hint: [optional focus area]
---

Run BOTH subagents in a **single message with two parallel Agent tool calls** so they execute
concurrently. Do NOT run them sequentially.

1. **`reviewer` subagent** — Go code correctness, auth-policy boundaries, scoreboard logic,
   test coverage, style consistency, cross-repo contract drift.
2. **`manifest-reviewer` subagent** — `deploy/**/*.yaml` invariants: replica count, strategy,
   UID 65532, image tag, base/ placeholders, SecurityContext, kustomize build.

Pass any focus area to the reviewer: $ARGUMENTS

After BOTH complete, present a **merged report**:

```
## Overall Verdict
APPROVE / APPROVE WITH NITS / REQUEST CHANGES
(blocked if either agent returns REQUEST CHANGES)

## Blocking (must-fix)
<combined list from both agents, prefixed with [code] or [manifest]>

## Non-blocking
<combined list>

## Nits
<combined list>

## Coverage
- Code review: <verdict from reviewer>
- Manifest review: <verdict from manifest-reviewer>
```

Do NOT implement fixes. Surface findings only. Match the user's language.
