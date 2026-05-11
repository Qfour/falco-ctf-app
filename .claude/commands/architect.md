---
description: Delegate to the Opus architect subagent for design / refactor proposals and root-cause analysis. Returns a proposal, not code.
argument-hint: <question or topic>
---

Use the `architect` subagent (Opus, design-only) to investigate the
following question and return a proposal:

$ARGUMENTS

After the agent responds, **do not implement** until the user picks an
option. The architect's job is to surface options; implementation
happens in the main Sonnet session afterwards.
