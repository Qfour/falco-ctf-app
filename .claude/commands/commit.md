---
description: Delegate to the Haiku committer subagent to create a git commit from the working tree. Does not push.
argument-hint: [optional context for the commit message]
---

Use the `committer` subagent (Haiku) to commit the current working tree.

If the user supplied additional context, pass it forward so the agent
can fold it into the commit message: $ARGUMENTS

After commit, do not push unless the user explicitly asks.
