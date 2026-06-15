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
id: intro-2h
title: "..."
challenges: [01-initial-recon, 02-credential-files, 03-stealth-read, ...]
```

## Ordering principle

Challenges 01–10 ARE the canonical, unified storyline (recon → cred access →
evade → harvest → … → exfil boss). **Scenarios keep that ascending order** —
they select a subset, never reorder it. This keeps the narrative aligned with
the scoreboard, which always sorts challenges by id. Non-beginner editions use
the full unified track; the beginner edition is just a shorter ascending slice.

## How the scoreboard uses it

The scoreboard bakes `scenarios/` into its image. Set `SCENARIO_FILE` (chart
value `env.scenarioFile`) to a manifest path to restrict scoring + `/api/state`
to that scenario's challenges:

```
SCENARIO_FILE=/app/scenarios/intro-2h/scenario.yaml
```

Unset = all challenges (the default / full library). Restrict is fail-closed:
a scenario referencing a missing challenge id won't start.

## Current scenarios

| name | challenges | use |
|---|---|---|
| `nimbusbreach-full` | all 10, ascending (trigger + evade + boss) | **unified standard track** — every non-beginner edition (long-form ~3h+, advanced) |
| `intro-2h` | 6, ascending slice (01,02,03,04,06,08) | 2-hour beginner edition (30m intro / 60m CTF / 30m debrief) |

Add a new format = add a `scenarios/<name>/` dir; never delete challenges.
