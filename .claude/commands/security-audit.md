---
description: Delegate to the Opus security-reviewer subagent for a deep security review of the working branch. Anchored to the project's threat model (cross-user workspace isolation, flag integrity, falco webhook trust).
argument-hint: [optional focus area]
---

Use the `security-reviewer` subagent (Opus) to audit the changes on
this branch against the falco-ctf-app threat model. The agent loads
the threat model from its own definition and the project conventions
from CLAUDE.md / AGENTS.md / .claude/rules/.

If the user supplied a focus area (a specific threat, a file, a
service), pass it forward: $ARGUMENTS

The agent will produce severity-ranked findings (CRITICAL / HIGH /
MEDIUM / LOW) with exploit sketches and suggested mitigations. Do not
write exploit code or fixes — surface the findings and let the user
decide.
