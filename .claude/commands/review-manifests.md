---
description: Delegate to manifest-reviewer subagent for Helm chart review. Use when only charts/ files changed.
argument-hint: [optional chart name or concern]
---

Use the `manifest-reviewer` subagent (Opus) to review only the `charts/` changes on this branch.

If the user specified a focus area, pass it forward: $ARGUMENTS

Output the manifest verdict as-is. Do not implement fixes.
