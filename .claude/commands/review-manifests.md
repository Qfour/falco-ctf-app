---
description: Delegate to manifest-reviewer subagent for Kustomize/deploy-only review. Use when only deploy/ files changed.
argument-hint: [optional overlay name or concern]
---

Use the `manifest-reviewer` subagent (Opus) to review only the `deploy/` changes on this branch.

If the user specified a focus area, pass it forward: $ARGUMENTS

Output the manifest verdict as-is. Do not implement fixes.
