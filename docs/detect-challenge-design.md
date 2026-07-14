# Detection-authoring challenge (`type: detect`) — design + feasibility spike

**Status:** design + feasibility spike only. Full implementation is a follow-up
after this spike is accepted. **security-lead review is a precondition to any
implementation** (this feature runs *untrusted participant input through Falco*).

**Author:** app-lead. **Branch:** `feat/detect-challenge` (off `fix/journey-flag-input`
= LIVE-deployed superset). **No prod change; no image rebuild/redeploy; no push.**

---

## 0. Concept (CEO)

A new challenge type where the participant is the *defender*: they write the Falco
**`condition:`** that would have caught the evasion from the existing evade missions.
Missions in scope: **03-stealth-read**, **05-silent-search**, **10-final-exfil**.

- Participant submits **only the `condition:` string**. Rule `name` / `output` /
  `priority` and the set of usable `macro`/`list` names are provided by the system
  skeleton (they never author a whole rule file).
- Grading = **capture replay**. The submitted condition is wrapped into a fixed rule
  and Falco replays two pre-recorded captures per mission:
  - **(a)** the *evasion* capture (the attack behaviour) — the condition **must fire**;
  - **(b)** a *benign* capture — the condition **must NOT fire** (zero false positives).
  - `pass = fires_on_evasion > 0 AND fires_on_benign == 0`.
- Fully **live-cluster-independent** — captures are static fixtures, replay needs no
  kernel driver.

This is a distinct type from the existing `trigger` (auto-solve on a live rule fire)
and `evade` (submit flag + clean-window + optional exfil).

---

## 1. New challenge type in the catalog schema

### 1.1 Schema additions (`internal/catalog/catalog.go`)

Add `type: detect` as a third `Type` value and three fields, all `detect`-only:

```yaml
challengeId: 03-stealth-read-detect
type: detect
detect:
  # captures live under challenges/<NN>/detect/ (see §5). Paths are RELATIVE to the
  # challenge dir and resolved by the harness, never absolute / participant-controlled.
  evasionCapture: detect/evasion.scap
  benignCapture:  detect/benign.scap
  # skeleton the participant condition is wrapped into. Only `condition` is theirs.
  ruleName: participant_detect          # fixed; grading greps this rule name
  # allowed macros/lists exposed to the participant condition (allow-list, see §4).
  allowedMacros: [open_read, spawned_process, sensitive_files, private_key_or_password]
```

Catalog validation (mirrors the existing evade/trigger switch in `parseFile`):
- `detect` requires `detect.evasionCapture` and `detect.benignCapture` non-empty;
- capture paths must be **relative, within the challenge dir** (reject `..`, absolute,
  symlink escape) — validated at load time so a bad catalog fails fast at boot;
- `ruleName` defaults to `participant_detect` if unset;
- `detect` challenges have **no `expectedFlag`** (not flag-based) and **no
  `expectedRules`/`forbiddenRules`** (not live-Falco-based) — keep those empty.

### 1.2 Relationship to existing types (projection / solve)

| type | solve trigger | authority |
|---|---|---|
| `trigger` | live Falco rule fires (ingest) → `EvaluateTrigger` | `expectedRules` |
| `evade` | `/submit` flag + clean window (+exfil) → `SubmitEvade` | `expectedFlag` |
| **`detect`** | **`/submit-detect` condition passes replay grade → `SubmitDetect`** | **capture pair** |

- `/api/state` and the journey projection already switch on `ch.Type`; a `detect`
  mission renders like a `trigger` in the map (no flag input) but with a **condition
  textarea** instead of a flag field (§6).
- The three `detect` missions are **new challenge dirs** (e.g. `03-stealth-read-detect`),
  NOT edits to the existing evade dirs — keeps I6 (falco-rule.yaml one-to-one) and the
  existing solve paths untouched. Content-lead owns the dirs; app-lead owns the type.

---

## 2. Scoreboard solve path (Grader integration)

The Grader (`internal/scoreboard/scoring`) stays the **single solve-decision point** and
sole `MarkSolved` caller (conventions I1 authenticity). Add one method mirroring
`SubmitEvade`'s shape:

```go
type DetectStatus int
const (
    DetectUnknownChallenge DetectStatus = iota
    DetectNotDetectType
    DetectInvalidCondition   // falco -V rejected it (compile error) — see §4
    DetectMissedEvasion      // did not fire on the evasion capture
    DetectFalsePositive      // fired on the benign capture
    DetectSolved
)

type DetectOutcome struct {
    Status        DetectStatus
    EvasionFires  int
    BenignFires   int
    Newly         bool
}

// SubmitDetect: gates 1-2 (exists / is detect type) are Grader-owned like SubmitEvade.
// The actual replay is delegated to an injected DetectGrader PORT (see §3) so the
// scoring package never shells out to falco itself (keeps it unit-testable & falco-free).
func (g *Grader) SubmitDetect(user, cid, condition string) (DetectOutcome, error)
```

Key design points:
- **Single judgment point:** `SubmitDetect` calls a new `DetectRunner` port
  (`Grade(ctx, cid, condition) (evasionFires, benignFires int, invalid bool, err error)`).
  The Grader interprets the counts into a `DetectStatus` and, on `DetectSolved`, calls
  the *existing* `g.store.MarkSolved` — so a detect solve is authentically identical to
  every other solve (same table, same idempotency, same `/api/state`).
- **Self-scope / authenticity unchanged:** the `/api/challenges/{cid}/submit-detect`
  handler reuses the exact `/submit` trust model (claimed user, rate-limited on the same
  bucket, audit-logged). No new auth surface.
- **No attacker-supplied time**, no forbidden-window — detect grading is purely a
  function of the (static capture, submitted condition) pair, so it is deterministic and
  replay-stable across scoreboard restarts (I1).
- The **auto-solve sweeper is not involved** (detect has no exfil receipt); the
  submit path is synchronous.

---

## 3. Grading harness — execution body & sandbox (MOST IMPORTANT)

The scoreboard is **distroless and has no Falco** (conventions Dockerfile table). We must
NOT add Falco to the scoreboard image, and we must NOT run untrusted conditions inside the
scoreboard process. The harness is a **separate execution body**.

### 3.1 Chosen model: per-submission Kubernetes Job (validator), driven by a thin runner

```
participant ──POST /submit-detect──▶ scoreboard (Grader.SubmitDetect)
                                          │  DetectRunner port
                                          ▼
                            create a per-submission K8s Job:
                              image = falco-ctf-detect-grader (falco 0.43.1 + captures baked)
                              args  = mission id + condition (via a file, not argv)
                              Job runs: falco -V (validate) then two `engine.kind: replay`
                              passes; writes {evasionFires,benignFires,invalid} to a result
                          ◀── scoreboard reads Job result (status/JSON) ──┘
```

Why a **per-submission Job** over the alternatives:

| option | verdict |
|---|---|
| **sidecar validator svc (long-lived)** | rejected as default: a long-lived process replaying attacker conditions back-to-back is a standing DoS/again-and-again target; harder to bound per-submission. Keep as a possible optimisation later if Job cold-start is too slow. |
| **falco in scoreboard image** | rejected: breaks distroless, puts untrusted exec in the single-writer SQLite process (I1 risk), enlarges the auth-path image. |
| **per-submission Job** | **chosen**: clean blast-radius isolation (one condition = one throwaway pod), trivially resource/time-capped, no persistent attack surface, no state. |

### 3.2 Grader image

New image `falco-ctf-detect-grader` (owned by app-lead, follows the Dockerfile conventions
& digest-pin/I5 rules — built at the same git SHA as the other 6 in a follow-up; this
would extend I5 to **7 images**, a documented convention change, see §7 risk). Contents:
- Falco 0.43.1 (pinned by digest);
- the mission captures baked in (or mounted read-only from a ConfigMap/PVC — see §5);
- a tiny entrypoint that: writes the participant condition into a fixed rule skeleton,
  runs `falco -V` (reject on non-zero), then two `engine.kind: replay` passes, and emits
  `{"evasionFires":N,"benignFires":M,"invalid":bool}` on stdout.

### 3.3 Sandbox / DoS controls (all enforced on the Job, not trusted to the condition)

- **No network:** Job pod gets a deny-all NetworkPolicy (replay is local file I/O only).
- **Non-root, read-only rootfs, drop ALL caps, no privilege escalation** — same
  securityContext posture as scoreboard/auth-policy. Replay needs **no kernel driver**
  (proven in spike §8), so **no privileged/`SYS_*` caps** at all.
- **Resource caps:** small CPU/memory `limits`; `activeDeadlineSeconds` (e.g. 20s) so a
  pathological condition/capture can't run forever; `backoffLimit: 0`.
- **Input hardening:** condition delivered via a **file**, never argv/env interpolation;
  size-capped (e.g. ≤4 KiB) before the Job is even created; `falco -V` is the compile
  gate (spike §8 shows malformed/"injection" conditions fail to compile — Falco's
  condition grammar is a closed expression language with no OS/shell access).
- **Concurrency cap + rate limit:** reuse the `/submit` per-IP limiter, PLUS a global
  cap on in-flight grader Jobs (queue/reject beyond N) so a flood can't spawn unbounded
  pods. This is the main net-new DoS lever and must be in the threat model review.
- **Capture provenance:** captures are operator-produced fixtures (§5), read-only,
  never participant-supplied — the participant only supplies the *condition*.

### 3.4 Cross-repo impact

The scoreboard needs RBAC to create/read Jobs in a dedicated namespace + a NetworkPolicy
for grader pods → **platform-lead** provides the Role/RoleBinding/NetworkPolicy and the
grader image pin in helmfile. `DetectRunner` is an interface in app; the K8s-Job
implementation may live in app (client-go) with platform supplying RBAC. **This crosses
the app/platform boundary → route through VP; do not implement unilaterally.**

---

## 4. Macro/list exposure (limiting the participant's vocabulary)

The rule skeleton is loaded alongside a **curated, minimal** rules file that defines only
the `allowedMacros`/lists the mission needs (from `detect.allowedMacros`). We do **not**
load the full stock Falco ruleset into the grader — that would (a) let a condition
reference arbitrary macros unrelated to the lesson and (b) enlarge the compile surface.
`falco -V` guarantees a condition referencing an undefined macro fails closed
(`LOAD_ERR_COMPILE_CONDITION`, proven in spike §8) → mapped to `DetectInvalidCondition`.

---

## 5. Capture generation & storage

Each mission needs a **pair** of captures, produced once by an operator and committed as
fixtures (single source, reproducible):

- `challenges/<NN>-<slug>-detect/detect/evasion.scap` — the evasion behaviour.
- `challenges/<NN>-<slug>-detect/detect/benign.scap`  — benign look-alike activity.

**Recording procedure (validated in the spike, §8):**
1. Run Falco with `engine.kind: modern_ebpf` + `capture.enabled: true` on a Linux host
   (colima kernel 6.8 + BTF works) with a broad "catch" rule so the relevant window is
   written to a `.scap`.
2. Perform the mission's evasion action (mission 3: `cat /proc/self/root/etc/shadow`);
   separately, perform only benign activity for the benign capture.
3. Trim/keep the chunk containing the behaviour; commit as the fixture.

Storage decision: **commit the `.scap` fixtures in the challenge dir** (single source,
same repo as the grader that consumes them — mirrors the challenges/scoreboard
same-repo rationale) and **bake them into the grader image** at build (or mount via a
ConfigMap/PVC that platform renders). `.scap` are binary blobs (public repo: they must
contain **no real flags/secrets** — the mission-3 evasion reads a *fake* shadow; verify
each capture before commit, add to the flag-guard's awareness). Re-record when the Falco
version bumps (capture format & field semantics can change).

> Open question for content-lead + security-lead: acceptable size of committed `.scap`
> (spike chunks were 300–740 KB each; trimming recommended) and confirming captures leak
> no sensitive host data (they record real host syscalls during recording).

---

## 6. UI (condition submit + result)

- **Journey UI (participant host), self-scope unchanged.** A `detect` mission renders a
  **condition `<textarea>`** + "Grade" button instead of a flag input. `missionDetail`
  gains `type: "detect"` handling; the projection stays hint-free and self-scoped (the
  existing `selfOrAdmin` read gate is untouched).
- On submit → `POST /api/challenges/{cid}/submit-detect` → shows one of: *invalid
  condition (compile error)* / *missed the evasion* / *fired on benign traffic (false
  positive)* / *solved*. Counts (`evasionFires`/`benignFires`) are surfaced as feedback
  ("your rule fired 0× on the attack") — pedagogically valuable, leaks nothing.
- No hint text, no solution reveal — the grader never returns the reference condition.

---

## 7. Invariant / cross-repo impact summary

- **I1 (single writer):** preserved — detect solves go through the same `MarkSolved`; the
  grader Job never writes the scoreboard DB (it only returns counts).
- **I5 (all images same SHA):** **impacted** — adds a **7th image**
  (`falco-ctf-detect-grader`). This is a convention change to the I5 image set and the
  Dockerfile/UID tables → must be ratified (CEO/VP) and reflected in
  `.claude/rules/falco-ctf-app-conventions.md`.
- **I8 (auth prefix-exact):** untouched — no auth-policy change; submit reuses the
  existing claimed-identity model.
- **I10 (no secrets in image/yaml):** captures must be verified secret/flag-free before
  commit (§5).
- **Cross-repo:** platform must supply grader-namespace RBAC (create/get Jobs) +
  deny-all NetworkPolicy + grader image pin. Contract-touching → both-repo PRs.

---

## 8. Feasibility spike — RESULT (mission 3, `/proc/self/root` evasion)

Run locally on colima (Docker 29.2.1, kernel 6.8 + BTF), **prod untouched** (ephemeral
containers/volumes only, all cleaned up). Falco image: `falcosecurity/falco:0.43.1`.

### 8.1 Findings

- **Replay is driverless & config-driven.** In Falco 0.43 the old `-e <capture>` flag is
  **removed**; capture replay is now `engine.kind: replay` + `engine.replay.capture_file`
  (verified against `--config-schema`). Replay needs **no kernel module/eBPF** → the
  grader pod needs **no privilege**.
- **Recording works with `modern_ebpf` + `capture.enabled`.** Kernel 6.8 + BTF on colima
  loaded modern_ebpf and wrote `.scap` chunks (300–740 KB).
- **The evasion behaviour is captured faithfully.** Replaying the evasion `.scap` with a
  catch-all rule showed both `openat fd.name=/proc/self/root/etc/shadow` (the evade path)
  and `openat fd.name=/etc/shadow` (direct read).

### 8.2 The grading model works end-to-end

Wrapping a participant condition into a fixed `participant_detect` rule and counting fires
across the two captures:

| submitted condition | evasion capture fires | benign capture fires | verdict |
|---|---:|---:|---|
| **correct** — `open_read` & `fd.name endswith "/shadow"` | **2** | **0** | **PASS** (detects evasion, 0 FP) |
| **wrong / off-target** — `execve and proc.name=nginx` | 0 | — | FAIL (missed evasion) |
| **too broad** — any `open_read` | 14639 | 9274 | FAIL (false positives) |

→ `pass = (evasionFires > 0) AND (benignFires == 0)` cleanly separates all three cases.

### 8.3 Untrusted-input safety validated

`falco -V <rules>` (validate mode) on a malformed / "injection" condition
(`evt.type = ) OR $(rm -rf /) unclosed ...`) returns **exit 1** with
`LOAD_ERR_COMPILE_CONDITION`; a valid condition returns **exit 0**. Falco's condition
grammar is a **closed expression language** — the shell-injection attempt is merely a
compile error and is **never executed**. This is the primary safety property the harness
relies on (compile-gate before replay).

### 8.4 Commands used (reference)

```sh
# record (privileged, modern_ebpf) — OPERATOR-ONLY, prod not involved
falco -c <falco.yaml: engine.kind=modern_ebpf, capture.enabled=true, capture.mode=all_rules> \
      -r catchall.yaml            # writes /captures/*.scap while the evasion/benign action runs

# validate an untrusted condition (compile gate)
falco -V /rules/participant.yaml  # exit 1 + LOAD_ERR_* on bad input; exit 0 on valid

# grade (driverless replay) — this is what the per-submission Job runs
falco -c <replay.yaml: engine.kind=replay, engine.replay.capture_file=/captures/evasion.scap> \
      -r /rules/participant.yaml --json | grep -c '"rule":"participant_detect"'
# repeat with capture_file=benign.scap
```

**Conclusion: the capture-replay grading method is technically sound.** Replay is
driverless (no privileged grader), the fire/no-fire signal is deterministic and cleanly
thresholded, and untrusted conditions are compile-gated by `falco -V` before any replay.
The remaining work is engineering (the Job harness + RBAC + captures + UI), not a
feasibility risk.

---

## 9. Effort estimate & split (full implementation, post-acceptance)

| area | work | owner | rough size |
|---|---|---|---|
| catalog `type: detect` + validation + tests | schema, path-safety validation | app-lead | S |
| Grader `SubmitDetect` + `DetectRunner` port + tests | single judgment point, fake runner in tests | app-lead | M |
| `/submit-detect` handler + oapi type + rate limit | thin adapter, reuse `/submit` trust model | app-lead | S |
| `falco-ctf-detect-grader` image + entrypoint | falco + skeleton + `-V` gate + 2-pass replay + JSON out | app-lead | M |
| K8s-Job DetectRunner (client-go) | create/watch/read Job, deadline, concurrency cap | app-lead | M–L |
| grader RBAC (Role/RoleBinding) + deny-all NetworkPolicy + image pin | namespace, least-priv Job perms | platform-lead | M |
| capture fixtures (3 missions × 2) + record runbook | evasion + benign scaps, secret-free verify | content-lead + operator | M |
| Journey UI detect textarea + result states | condition input, feedback rendering | app-lead + content-lead | S–M |
| threat model review (untrusted falco exec, DoS, capture provenance) | **blocking gate** | security-lead | — |

Suggested sequencing: catalog+Grader+handler (unit-testable, no k8s) → grader image +
local replay runner → K8s-Job runner + platform RBAC → captures → UI. security-lead
review gates the image + Job + RBAC step.

---

## 10. Unresolved design risks

1. **Untrusted Falco execution (highest).** Even compile-gated + replay-only + no-network
   + resource-capped, we are running attacker-influenced input through a C++ engine.
   Residual risk: a Falco parser/engine CVE. Mitigations: pinned digest, ephemeral pod,
   no network, no privilege, deadline, drop-all caps. **security-lead must sign off.**
2. **DoS via Job flooding.** Per-submission pods are the new amplification vector. Needs a
   hard global in-flight cap + per-IP rate limit + `activeDeadlineSeconds` (net-new lever,
   must be reviewed).
3. **Grader latency vs UX.** Job cold-start + two replay passes may be multi-second. If
   too slow, revisit the (higher-risk) long-lived sidecar — but only with an isolation
   story that matches the per-Job model.
4. **I5 → 7 images.** Convention change requiring ratification; touches Dockerfile/UID
   tables and the image-set contract in both repos.
5. **Capture provenance & size.** `.scap` record real host syscalls during recording —
   must be verified flag/secret-free (public repo, I10) and trimmed. Re-record on Falco
   version bump.
6. **Anti-cheat.** A condition could be gamed to fire on some incidental artifact of the
   evasion capture rather than the intended detection (e.g. keying on a pid/timestamp).
   Benign-capture FP check mitigates the trivial "match everything"; content-lead should
   design captures so the *only* clean discriminator is the intended detection idea.
