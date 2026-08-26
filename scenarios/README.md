# scenarios/ — composable, ATT&CK-aligned scenarios (P27)

A **challenge** (`challenges/<NN>-slug>/`) is a reusable unit. `nimbusbreach-full`
(challenges 01→10, recon → cred access → evade → harvest → … → exfil boss) is
the original flagship scenario — a single strong narrative every event has run
so far. As of P27 (REFACTORING.md), `scenarios/` is a **general mechanism**: a
scenario is any subset/order of challenges declared in its `scenario.yaml`, and
new scenarios can mix challenges freely (see `tutorial-intro` for a working
example: `00,01,03` — not an ascending run through all 10). `nimbusbreach-full`
staying ascending-only is that scenario's own narrative choice, not a
constraint the mechanism imposes on future scenarios.

`journey.yaml`'s challenge-local `briefing`/`bridge` were originally authored
assuming the 01→10 order and can reference other missions by number — a
scenario that picks a different subset/order can hit a narrative contradiction
as a result. ADR-0014 (`docs/adr/0014-journey-narrative-scenario-overlay.md`)
fixes this with an optional `narrative.yaml` override (see below); a new
scenario should add one whenever it excludes a mission an included challenge's
briefing references by number.

Within `nimbusbreach-full`, what differs between events is the **edition** —
the time budget and how much is hands-on vs walked through (解説). An edition
never changes that scenario's challenges or order; it just decides which
missions participants solve themselves and which the facilitator demonstrates,
always completing the full 01→10 arc.

```
scenarios/<scenario>/
├── scenario.yaml     # id, title, ordered challenge ids (machine-read)
├── narrative.yaml    # optional (ADR-0014): per-challengeId briefing/bridge
│                     # override, replaces the challenge-local journey.yaml
│                     # text wholesale where it would otherwise reference a
│                     # mission this scenario doesn't include
├── playbook-<edition>.md   # facilitator run-of-show for a time budget
└── debrief.md        # post-event walkthrough (all missions, reusable)
```

## Ordering principle (nimbusbreach-full specifically, not the mechanism)

`nimbusbreach-full`'s 01–10 order is its own canonical storyline and **that
scenario keeps ascending order — never reorder it.** This keeps its narrative
aligned with the scoreboard, which always sorts a scenario's `challenges:` as
declared. Editions of `nimbusbreach-full` select *how* its missions are run
(hands-on / 解説), not *which* — the full 01→10 arc is always covered by every
`nimbusbreach-full` edition. **This principle does not extend to other
scenarios** — `tutorial-intro` already deliberately runs `00,01,03` (skipping
02), and new scenarios are free to pick whatever subset/order fits their own
narrative.

## How the scoreboard uses it

The scoreboard bakes `scenarios/` into its image. `SCENARIO_FILE` (chart value
`env.scenarioFile`) restricts scoring + `/api/state` to a scenario's challenges:

```
SCENARIO_FILE=/app/scenarios/nimbusbreach-full/scenario.yaml   # all 10 (= default)
```

Unset = all challenges (same as nimbusbreach-full). Restrict is fail-closed: a
scenario referencing a missing challenge id won't start.

## How the participant workspace uses it (P27-1)

`charts/ctf-user`'s `deploy-user.sh` has a third challenge-id mode,
`scenario:<name>`, alongside `all` and a single `<NN-slug>`:

```
deploy-user.sh <username> scenario:tutorial-intro
```

This is a **separate consumer of `scenario.yaml` from the scoreboard's
`SCENARIO_FILE` above** — the two are not automatically kept in sync (an
operator picking a `scoreboardScenario` for an event must also deploy
workspaces with the matching `scenario:<name>`). Only the challenges listed in
`<name>/scenario.yaml`'s `challenges:` get their flag planted and their
fixtures/README visible under `/opt/ctf/missions/` in the participant's shell;
challenges outside the list are unreachable regardless of what `all` mode
would have planted (`challenges/gen-values.sh` generates a
`challenges/values-scenario-<name>.yaml` per scenario; run `make gen-values`
after adding/editing a `scenario.yaml`). Before P27-1, the workspace had no
such scoping — every deploy planted/exposed every challenge, so scoring could
be restricted to a scenario while the workspace still leaked every other
challenge's content. `charts/ctf-user/assert-flag-isolation.sh` verifies this
boundary at deploy time (checks 3-1..3-8).

## Scenario + editions

| | challenges | notes |
|---|---|---|
| scenario `nimbusbreach-full` | all 10, ascending (trigger + evade + boss) | the one unified storyline; scoreboard shows all 10 |
| edition `playbook-2h.md` | hands-on 01,02,03,04,06,08 · 解説 05,07,09,10 | **本番リハーサル** (30m intro / 60m hands-on / 30m 解説); completes the full arc in 2h |

Longer editions (本番) just move 解説 missions into hands-on — same scenario,
same order, more time. Add a new edition = add a `playbook-<edition>.md`; never
delete challenges or reorder.
