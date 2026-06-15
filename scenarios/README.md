# scenarios/ — event compositions

A **challenge** (`challenges/<NN>-slug>/`) is a reusable unit. A **scenario**
selects and sequences a subset of them into one event, sized for a time budget.
This lets the same challenge library serve different formats without forking
content.

```
scenarios/<name>/
├── scenario.yaml   # id, title, ordered challenge ids (machine-read)
├── playbook.md     # (optional) facilitator run-of-show / timing
└── debrief.md      # (optional) post-event walkthrough
```

`scenario.yaml` is the only machine-consumed file:

```yaml
id: killchain-2h
title: "..."
challenges: [02-credential-files, 01-initial-recon, ...]
```

## How the scoreboard uses it

The scoreboard bakes `scenarios/` into its image. Set `SCENARIO_FILE` (chart
value `env.scenarioFile`) to a manifest path to restrict scoring + `/api/state`
to that scenario's challenges:

```
SCENARIO_FILE=/app/scenarios/killchain-2h/scenario.yaml
```

Unset = all challenges (the default / full library). Restrict is fail-closed:
a scenario referencing a missing challenge id won't start.

## Current scenarios

| name | challenges | use |
|---|---|---|
| `nimbusbreach-full` | all 10 (trigger + evade + boss) | long-form (~3h+), advanced |
| `killchain-2h` | 6 (curated kill-chain) | 2-hour beginner event (30m intro / 60m CTF / 30m debrief) |

Add a new format = add a `scenarios/<name>/` dir; never delete challenges.
