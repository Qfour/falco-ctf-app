# scenarios/ — the event scenario + time-budget editions

A **challenge** (`challenges/<NN>-slug>/`) is a reusable unit. The challenges
01→10 together ARE the **unified NimbusBreach scenario** (recon → cred access →
evade → harvest → … → exfil boss). Every event runs this same scenario.

What differs between events is the **edition** — the time budget and how much is
hands-on vs walked through (解説). An edition never changes the scenario or its
order; it just decides which missions participants solve themselves and which
the facilitator demonstrates, always completing the full 01→10 arc.

```
scenarios/<scenario>/
├── scenario.yaml     # id, title, ordered challenge ids (machine-read)
├── playbook-<edition>.md   # facilitator run-of-show for a time budget
└── debrief.md        # post-event walkthrough (all missions, reusable)
```

## Ordering principle

Challenges 01–10 are the canonical storyline. **Scenarios keep that ascending
order — never reorder.** This keeps the narrative aligned with the scoreboard,
which always sorts challenges by id. Editions select *how* missions are run
(hands-on / 解説), not *which* — the full arc is always covered.

## How the scoreboard uses it

The scoreboard bakes `scenarios/` into its image. `SCENARIO_FILE` (chart value
`env.scenarioFile`) restricts scoring + `/api/state` to a scenario's challenges:

```
SCENARIO_FILE=/app/scenarios/nimbusbreach-full/scenario.yaml   # all 10 (= default)
```

Unset = all challenges (same as nimbusbreach-full). Restrict is fail-closed: a
scenario referencing a missing challenge id won't start. (The mechanism stays
available for any future genuinely-shorter subset edition.)

## Scenario + editions

| | challenges | notes |
|---|---|---|
| scenario `nimbusbreach-full` | all 10, ascending (trigger + evade + boss) | the one unified storyline; scoreboard shows all 10 |
| edition `playbook-2h.md` | hands-on 01,02,03,04,06,08 · 解説 05,07,09,10 | **本番リハーサル** (30m intro / 60m hands-on / 30m 解説); completes the full arc in 2h |

Longer editions (本番) just move 解説 missions into hands-on — same scenario,
same order, more time. Add a new edition = add a `playbook-<edition>.md`; never
delete challenges or reorder.
