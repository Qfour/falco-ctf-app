---
description: Go コードのみのレビュー — reviewer subagent 単独。manifest 変更がないパターン A/C 向け。
argument-hint: [optional focus area]
---

Run the `reviewer` subagent to review Go code changes on the current branch against main.

Brief the reviewer with this context:
- Project: falco-ctf-app — scoreboard (SQLite + Falco webhook ingest) / auth-policy (X-Auth-Request-Email prefix-exact check)
- Hard Invariants to verify: I1 (scoreboard replicas:1 + Recreate), I2/I3 (runAsUser 65532, fsGroup 65532), I8 (auth-policy prefix-exact — NEVER relax), I4/I5 (image tag = git SHA)
- Cross-repo contract: `/falco/events` JSON schema (falcosidekick standard) must not change without platform-side PR
- Rules: `.claude/rules/falco-ctf-app-conventions.md`
- Focus area from user: $ARGUMENTS

After the agent responds, present findings:

```
## Overall Verdict
APPROVE / APPROVE WITH NITS / REQUEST CHANGES

## Blocking (must-fix)

## Non-blocking

## Nits
```

Do NOT implement fixes. Surface findings only. Match the user's language.
