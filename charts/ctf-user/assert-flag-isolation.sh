#!/usr/bin/env bash
# ADR-0001 Verification 3 — deploy-time fail-closed assert (F2).
#
# docs/adr/0001-flag-plant-initcontainer-not-challenge-env.md
#
# WHAT this checks (Verification 3, 3-1..3-7), run right after
# `helm upgrade --install ... --wait` against the just-deployed workspace:
#   3-1  the challenge container's own process env never contains CTF_FLAG
#   3-2  neither does PID 1's env (/proc/1/environ)
#   3-3  the challenge container has no ServiceAccount token mounted
#   3-4  the seed volume root (/plant-seed) is not visible from `challenge`
#        (only individual plant-target subPath mounts are — F5); likewise the
#        evidence source root (/opt/ctf/evidence-src, where `plant` alone mounts
#        the ctf-evidence-<cid> Secrets, ADR-0056 D11) is not visible from `challenge`
#   3-5  the planted /etc/shadow contains exactly as many `FALCO{` lines as
#        the missions actually in scope for this deploy declare (03/10)
#   3-6  the planted /root/.ssh/id_rsa exists IF mission 05 is in scope —
#        `test -f` ONLY, never opened/read (see WHY below)
#   3-7  ttyd's own in-cluster `kubectl exec` into `challenge` still works
#        (this is the participant's actual terminal path, not the
#        operator's — a separate RBAC principal from the one running this
#        script)
#   3-8  ADR-0026 V4 (all three modes: scenario / `all` / single mission):
#        /opt/ctf/missions/ holds EXACTLY the expected challenge ids, every
#        one a real directory, and each <id>/ holds nothing but a real
#        `fixtures` directory (fixtures' own contents are never opened).
#        Dot entries are enumerated too. See the 3-8 judgment block below.
#   3-9  ADR-0056 D11 "3-x" item (1) (A5d, V8): inside each evidence mount directory
#        of the scope (the `mountDir` of every investigate challenge, read from the
#        values file helm was given: the plant.mounts entries marked `evidence:
#        true`), as `challenge` sees it: it is a real directory, holds at least one
#        entry, and every entry (dot entries too) is a regular file and not a
#        symlink. Entries are tested with `[ -L ]` / `[ -f ]` only, never opened.
#   3-10 ADR-0056 D11 "3-x" item (2) (A5d, V2): the names of the namespace's
#        Secrets of type Opaque are exactly {ctf-flags} plus ctf-evidence-<cid> for
#        every investigate challenge of the scope (an extra one or a missing one
#        fails). Helm's release records (type helm.sh/release.v1) are counted
#        apart; a Secret of any other type fails. This runs `kubectl get secrets`
#        as the operator, outside the workspace (no process in the Pod).
#        The Secrets of a seat's namespace are a CLOSED set: flags, bundles and
#        Helm's release records only; a Secret of any other type fails the deploy.
#        That is a constraint on the platform (ADR-0056 D11 and D19's P1b-3; the
#        contract table's wording 2 at A4e-4).
#   3-11 ADR-0056 D11 "3-x" item (3) (A5e, V94): for every investigate challenge of
#        the scope, the KEY set of the Secret ctf-evidence-<cid> equals the names the
#        chart was given for it (the <cid>/<name> arguments; an extra key or a
#        missing one fails). Only the keys are read (`kubectl get secret -o
#        go-template` over `.data` printing the key alone): no value, no byte of a
#        bundle, is fetched or printed. Operator-side, like 3-10.
#   D11's "3-x" has four items; this script has (1), (2) and (3). (4) (no bundle
#   content in the Helm release record) is not a deploy-time automatic check
#   (ADR-0056 D11): V50 holds it in CI and V51 measures it at a rehearsal.
#
# The scope's values file is NOT chosen here: it is the 5th argument, the file
# deploy-user.sh gave helm (ADR-0056 A5e; the rule that picks it lives in
# deploy-user.sh only). Its evidence entries must be in the exact form
# challenges/gen-values.sh writes (an `evidence` key in any other form stops the
# assert, fail-closed, as deploy-user.sh's evidence_scope_cids does).
#
# WHAT 3-8 does and does not prove: it is a deploy-moment check of the image
# the Pod actually started from (a tag mix-up, an image older than the
# checkout, a scenario copy that went wrong). It does NOT defend against a
# malicious registry-side replacement (digest pin / signing do that), and
# re-running it AFTER participants have used the workspace is NOT evidence
# about the image: they are root in `challenge` and can change /opt/ctf. Audit
# an image with `scripts/check-image-hygiene.sh <image digest>`, not with this.
#
# WHY builtin-only (this is the load-bearing part — do not "simplify" this
# script by swapping any check below for grep/cat/head/tail/awk/find/cp):
#
#   3-1..3-6 run as a process INSIDE the participant's own workspace
#   (`kubectl exec workspace -c challenge -- sh -c '<payload>'`). The
#   scoreboard ingest filter (internal/scoreboard/ingest/ingest.go:77-99)
#   does NOT look at container name — it only checks (i) the namespace
#   starts with `ctf-`, (ii) the pod name is `workspace`, (iii) the image
#   repo substring matches. `user` is derived from the namespace
#   (ingest.go:112). So any process this script starts inside that Pod is
#   scored as THAT PARTICIPANT'S OWN Falco activity — indistinguishable
#   from something the participant typed themselves.
#
#   grep / cat / head / tail / awk / find / cp are not excluded by the
#   `sensitive_files` macro / `Read sensitive file untrusted` rule's
#   exclusion conditions (challenges/03-stealth-read/rule.yaml) the way
#   `proc.name=sh` doing its OWN builtin read is. Running any of those
#   seven against /etc/shadow (or the other `sensitive_file_names` /
#   /etc/sudoers.d / /etc/pam.d paths) would fire that rule and — because
#   mission 02's expectedRules is exactly `Read sensitive file untrusted`
#   (trigger, NOT attempt-scoped, first-write-wins, permanent) — auto-solve
#   mission 02 for the participant, submit-free, on every single deploy.
#   `cp` looks safe at a glance because of the `cmp_cp_by_passwd` exclusion
#   macro, but that macro's condition is gated on parent process name and
#   does NOT cover a `cp` invoked from this script's own payload (ADR-0001
#   §F3′, "assert 側" — the exact mistake the ADR's rev.2 made and rev.3
#   had to walk back). `find` matters for a *different* rule (`Search
#   Private Keys or Passwords`) if ever pointed at /root/.ssh.
#
#   So every one of 3-1..3-6 is implemented below with shell redirection +
#   builtins only (`read`, `case`, `[ -e/-f ]`, `export -p`, `printf`)
#   inside the string handed to `sh -c`. To keep the self-check below
#   simple, unambiguous, and reviewable as ONE rule with no exceptions to
#   remember, the OUTER (operator-side) half of this script — the part
#   that never runs inside a Falco-monitored Pod at all — avoids the same
#   seven binaries too. One rule for the whole file.
#
#   3-6 is `test -f` ONLY — it never opens the file. The ADR is explicit
#   this is a deliberate least-privilege choice, not (only) a rule-firing
#   concern: the current catalog's mission 05 forbidden rule (`Search
#   Private Keys or Passwords`) is argv-based, not read-based, so reading
#   would likely not trip anything today — but this script must not be the
#   place that finds that out the hard way after a future rule change.
#
# HOW the self-check works (self_check_builtin_only, below): it reads this
# very file line by line (offline, static text — no cluster needed) and,
# for every line that is not a whole-line comment and not a variable
# assignment, looks at the FIRST shell word. If that word is exactly one of
# the seven banned names, it fails closed. This is intentionally NOT
# implemented with a `grep`/`awk` invocation, even though that would be
# harmless here (this scan never touches a Falco-monitored process) —
# doing it this way means the "no external binaries anywhere in this file"
# claim above is not just an intention, it is what the self-check itself
# is made of, and a reviewer never has to ask "does the self-check
# mechanism count?".
#
# Usage:
#   assert-flag-isolation.sh <namespace> <challenges-dir> <challenge-id> \
#       <scenarios-dir> <values-file> [<cid>/<name>...]
#
# All five are required (ADR-0056 A5e: fewer is exit 2, never a default):
# <scenarios-dir> may be the empty string outside scenario mode; <values-file> is
# the values file deploy-user.sh gave helm, or `-` when it gave helm none (a
# single challenge with no values overlay). Each <cid>/<name> is one evidence file
# name the chart was given for <cid> (evidence.challenges.<cid>.names): every
# investigate challenge of <values-file> must have at least one, and none may name
# another challenge (exit 1, before the probe).
#
# <challenge-id> is one of three shapes, matching what was passed to
# deploy-user.sh: the literal string `all` (roster / all-missions deploys —
# the prod default), a single mission id (e.g. `03-stealth-read`), or (P27-1)
# `scenario:<name>` — <scenarios-dir>/<name>/scenario.yaml's `challenges:`
# list then becomes the scope for every check below, instead of every
# challenges/*/plant.sh ("all") or just the one named id (single-mission).
# <scenarios-dir> is REQUIRED (and must contain <name>/scenario.yaml) when
# challenge-id is `scenario:<name>`; ignored otherwise.
#
# This determines how many `FALCO{` lines /etc/shadow is expected to carry,
# whether /root/.ssh/id_rsa is expected to exist at all (3-5 / 3-6, computed
# dynamically from the actual plant.sh headers in <challenges-dir> that are
# in scope for this deploy — never hardcoded to the all-missions "2"), and
# (3-8, P27-1 + ADR-0026 V4) exactly which challenge ids /opt/ctf/missions/
# is expected to contain:
#   - scenario mode: exactly the scenario's own `challenges:` list (the
#     `missions-scope` initContainer copies only those), and
#   - `all` / single-mission mode: every catalog id in <challenges-dir>
#     (a directory holding falco-rule.yaml; id == directory name, ADR-0026
#     解釈 1). A single-mission deploy still gets the image's FULL id set —
#     the chart only narrows scenarios. The id set therefore comes from the
#     OPERATOR'S CHECKOUT, so the checkout and the image's ref must agree
#     (ADR-0026 解釈 3): a checkout that drifts from the image stops the
#     deploy here (fail-closed), by design.
#
# Exit status: 0 if every check passes, non-zero (with violations printed
# to stderr) otherwise. Called from deploy-user.sh with no `||` / `if`
# wrapper around the call, so `set -e` there propagates this script's exit
# status directly (ADR-0001 DoD 4 / Cross-repo 契約: deploy-user.sh's
# non-zero exit is a fail-closed contract the caller must not swallow).
set -euo pipefail

# ---------------------------------------------------------------------------
# Self-check: this file must never invoke the seven banned binaries. Runs
# before anything else, unconditionally, every invocation.
# ---------------------------------------------------------------------------

self_check_builtin_only() {
  local self="${BASH_SOURCE[0]}"
  local line trimmed first violations=0

  while IFS= read -r line || [ -n "${line}" ]
  do
    # Trim leading whitespace (standard bash idiom: strip the longest
    # suffix starting at the first non-space char, then remove that as a
    # prefix from the original line).
    trimmed="${line#"${line%%[![:space:]]*}"}"

    case "${trimmed}" in
      ''|'#'*)
        # Blank or whole-line comment — this is exactly where the header
        # above (and this function's own comments) are allowed to mention
        # the banned names in prose without tripping the check.
        continue
        ;;
    esac

    # First shell word of the (trimmed) line. Disable globbing for the
    # word-split so a literal `*` in e.g. a glob pattern elsewhere in this
    # script doesn't expand against the filesystem.
    set -f
    # shellcheck disable=SC2206  # intentional word-splitting on unquoted var
    local -a words=( ${trimmed} )
    set +f
    first="${words[0]:-}"

    case "${first}" in
      *=*)
        # Variable / array assignment (e.g. `NAME=value`, `NAME=(...)`) —
        # not a command invocation. This is also how this function's own
        # banned-name literals below (inside `case` patterns, which are
        # data, not invocations) are correctly never mis-scanned: a `case`
        # arm like `grep|cat|...)` is a single word with no `=`, but it
        # also never equals any single banned name exactly (see below).
        continue
        ;;
    esac

    case "${first}" in
      grep|cat|head|tail|awk|find|cp)
        printf 'assert-flag-isolation.sh: BUILTIN-ONLY VIOLATION: line uses external binary "%s":\n  %s\n' \
          "${first}" "${line}" >&2
        violations=$((violations + 1))
        ;;
    esac
  done < "${self}"

  if [ "${violations}" -gt 0 ]
  then
    printf 'assert-flag-isolation.sh: self-check failed (%d violation(s)) — refusing to run. See ADR-0001 §F3′.\n' \
      "${violations}" >&2
    return 1
  fi
  return 0
}

if ! self_check_builtin_only
then
  exit 1
fi

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

USAGE_MSG='usage: assert-flag-isolation.sh <namespace> <challenges-dir> <challenge-id> <scenarios-dir> <values-file|-> [<cid>/<name>...]'
# ADR-0056 A5e: all five positional arguments are required. In particular the values
# file is never defaulted: without it, exit 2 (the file is the one helm was given,
# and only deploy-user.sh knows which one that is).
if [ "$#" -lt 5 ]
then
  printf '%s\n  (%d argument(s) given; the 5th, the values file helm was given or -, is required: ADR-0056 A5e)\n' "${USAGE_MSG}" "$#" >&2
  exit 2
fi
NS="${1:?${USAGE_MSG}}"
CHALLENGES_DIR="${2:?${USAGE_MSG}}"
CHALLENGE_ID="${3:?${USAGE_MSG}}"
SCENARIOS_DIR="${4}"
SCOPE_VALUES_ARG="${5}"
shift 5
# the <cid>/<name> arguments (checked against the scope once it is read, below)
EVIDENCE_NAME_ARGS=()
for _a in "$@"
do
  EVIDENCE_NAME_ARGS+=("${_a}")
done

if [ ! -d "${CHALLENGES_DIR}" ]
then
  printf 'assert-flag-isolation.sh: challenges dir not found: %s\n' "${CHALLENGES_DIR}" >&2
  exit 1
fi

# P27-1 (REFACTORING.md): scenario-scope mode. challenge-id "scenario:<name>"
# scopes every check below (3-5/3-6/3-8) to exactly
# <scenarios-dir>/<name>/scenario.yaml's `challenges:` list, instead of
# every challenges/*/plant.sh ("all") or just the one named id
# (single-mission).
SCENARIO_MODE=no
SCENARIO_NAME=""
case "${CHALLENGE_ID}" in
  scenario:*)
    SCENARIO_MODE=yes
    SCENARIO_NAME="${CHALLENGE_ID#scenario:}"
    ;;
esac

SCENARIO_FILE=""
if [ "${SCENARIO_MODE}" = yes ]
then
  if [ -z "${SCENARIOS_DIR}" ]
  then
    printf 'assert-flag-isolation.sh: challenge-id is %s but no <scenarios-dir> (4th arg) was given\n' "${CHALLENGE_ID}" >&2
    exit 1
  fi
  SCENARIO_FILE="${SCENARIOS_DIR}/${SCENARIO_NAME}/scenario.yaml"
  if [ ! -f "${SCENARIO_FILE}" ]
  then
    printf 'assert-flag-isolation.sh: scenario file not found: %s\n' "${SCENARIO_FILE}" >&2
    exit 1
  fi
fi

# collect_scenario_challenge_ids <scenario.yaml> -> populates the global
# SCENARIO_CHALLENGE_IDS array with that file's `challenges:` list, in
# declared order. Builtin-only (see file header — this parses the same
# `challenges:` / `  - <id>` shape challenges/gen-values.sh's
# scenario_challenge_ids() reads with awk, just without awk: case statements
# and parameter-expansion trims only).
SCENARIO_CHALLENGE_IDS=()
collect_scenario_challenge_ids() {
  local f="$1" line trimmed inblock=0 rest
  SCENARIO_CHALLENGE_IDS=()
  [ -f "${f}" ] || return 0
  while IFS= read -r line || [ -n "${line}" ]
  do
    case "${line}" in
      'challenges:'*)
        inblock=1
        continue
        ;;
    esac
    if [ "${inblock}" -eq 1 ]
    then
      case "${line}" in
        '')
          continue
          ;;
        ' '*|$'\t'*)
          trimmed="${line#"${line%%[![:space:]]*}"}"
          case "${trimmed}" in
            '-'*)
              rest="${trimmed#-}"
              rest="${rest#"${rest%%[![:space:]]*}"}"
              case "${rest}" in
                *'#'*) rest="${rest%%#*}" ;;
              esac
              rest="${rest%"${rest##*[![:space:]]}"}"
              [ -n "${rest}" ] && SCENARIO_CHALLENGE_IDS+=("${rest}")
              ;;
          esac
          ;;
        *)
          inblock=0
          ;;
      esac
    fi
  done < "${f}"
}

if [ "${SCENARIO_MODE}" = yes ]
then
  collect_scenario_challenge_ids "${SCENARIO_FILE}"
  if [ "${#SCENARIO_CHALLENGE_IDS[@]}" -eq 0 ]
  then
    printf 'assert-flag-isolation.sh: %s has no challenges: list (or gen-values.sh scenario parsing drifted from this script'"'"'s)\n' "${SCENARIO_FILE}" >&2
    exit 1
  fi
fi

# 3-8 expected id set (ADR-0026 V4). Scenario mode: the scenario's own list.
# `all` / single: every catalog id under <challenges-dir> — a directory that
# holds falco-rule.yaml (so non-challenge dirs such as an untracked decks/
# are not ids). Zero ids is fail-closed: an empty expectation would let an
# empty or wrong missions tree compare equal to "nothing".
EXPECTED_MISSION_IDS=()
if [ "${SCENARIO_MODE}" = yes ]
then
  EXPECTED_MISSION_IDS=("${SCENARIO_CHALLENGE_IDS[@]}")
else
  for d in "${CHALLENGES_DIR}"/*/
  do
    [ -f "${d}falco-rule.yaml" ] || continue
    _id="${d%/}"
    _id="${_id##*/}"
    EXPECTED_MISSION_IDS+=("${_id}")
  done
  if [ "${#EXPECTED_MISSION_IDS[@]}" -eq 0 ]
  then
    printf 'assert-flag-isolation.sh: no catalog id (<dir>/falco-rule.yaml) under %s — cannot judge 3-8\n' "${CHALLENGES_DIR}" >&2
    exit 1
  fi
fi
# The expectation itself is validated before anything is compared: a duplicate
# id would turn "observed == expected" into a one-directional check (count
# equal + expected ⊆ observed lets a missing id hide behind a repeated one),
# and an id outside the probe's character set could never be observed (and
# would reach the diagnostics below raw).
for _i in "${!EXPECTED_MISSION_IDS[@]}"
do
  case "${EXPECTED_MISSION_IDS[_i]}" in
    ''|*[!A-Za-z0-9._-]*)
      printf 'assert-flag-isolation.sh: expected id #%d has a character outside [A-Za-z0-9._-] — refusing (3-8 fail-closed)\n' "${_i}" >&2
      exit 1
      ;;
  esac
  for _j in "${!EXPECTED_MISSION_IDS[@]}"
  do
    if [ "${_j}" -gt "${_i}" ] && [ "${EXPECTED_MISSION_IDS[_j]}" = "${EXPECTED_MISSION_IDS[_i]}" ]
    then
      printf 'assert-flag-isolation.sh: duplicate id "%s" in the expected mission set (%s) — refusing (3-8 fail-closed)\n' \
        "${EXPECTED_MISSION_IDS[_i]}" "${SCENARIO_FILE:-${CHALLENGES_DIR}}" >&2
      exit 1
    fi
  done
done

# ---------------------------------------------------------------------------
# NOTE (flag-guard): diagnostic messages below say "flag-marker line(s)" and never
# spell the literal FALCO + { on a line that also contains a ${...} expansion.
# scripts/check-flags.sh matches FALCO\{[^}]*\} per line, so such a line reads as
# a real flag literal and fails the flag-guard CI job. Reword the message — do NOT
# loosen check-flags.sh, which is deliberately fail-closed.
# Dynamic expectations: how many `FALCO{` lines /etc/shadow should carry,
# and whether /root/.ssh/id_rsa should exist, for the missions actually in
# scope for THIS deploy. Derived from each in-scope plant.sh's own
# `# plant-target:` header line(s) (challenges/gen-values.sh's single
# source of truth) — never hardcoded to the all-missions "2", since a
# single-mission dev/test deploy plants a different subset (e.g.
# `05-silent-search` alone plants only /root/.ssh, zero /etc/shadow lines).
# ---------------------------------------------------------------------------

EXPECTED_SHADOW_FALCO_LINES=0
EXPECTED_SSH_KEY_EXISTS=no

collect_plant_target_expectations() { # $1 = path to a plant.sh
  local f="$1" line trimmed target
  [ -f "${f}" ] || return 0
  while IFS= read -r line || [ -n "${line}" ]
  do
    case "${line}" in
      '# plant-target: '*)
        target="${line#'# plant-target: '}"
        case "${target}" in
          /etc/shadow)
            EXPECTED_SHADOW_FALCO_LINES=$((EXPECTED_SHADOW_FALCO_LINES + 1))
            ;;
          /root/.ssh)
            EXPECTED_SSH_KEY_EXISTS=yes
            ;;
        esac
        ;;
    esac
  done < "${f}"
  # unused, silences shellcheck SC2034 concerns about trimmed in some shells
  trimmed=""
}

if [ "${CHALLENGE_ID}" = "all" ]
then
  for d in "${CHALLENGES_DIR}"/*/
  do
    collect_plant_target_expectations "${d}plant.sh"
  done
elif [ "${SCENARIO_MODE}" = yes ]
then
  for cid in "${SCENARIO_CHALLENGE_IDS[@]}"
  do
    collect_plant_target_expectations "${CHALLENGES_DIR}/${cid}/plant.sh"
  done
else
  collect_plant_target_expectations "${CHALLENGES_DIR}/${CHALLENGE_ID}/plant.sh"
fi

# ---------------------------------------------------------------------------
# 3-9 / 3-10 / 3-11 expectations (ADR-0056 D11 "3-x" items (1)(2)(3), A5d / A5e): the
# investigate challenges of this scope and their evidence mount directories, read
# from the scope's values file (the file deploy-user.sh gives helm; see the
# header). WHY a third reader of that file (after gen-values.sh, which writes it,
# and deploy-user.sh's evidence_scope_cids in charts/ctf-user/evidence-bundle.sh):
# this file is builtin-only (see the header), and that reader is awk. HOW they are
# kept equal: scripts/check-missions-allowlist-assert.sh runs both over
# gen-values.sh's own output, over every committed values-all.yaml /
# values-scenario-*.yaml, and over a table of accepted and refused inputs, and
# fails on any input one of them accepts and the other refuses. This reader is
# stricter in one documented way: it also needs the entry's `- path:` (it sends
# the directory to the probe), which deploy-user.sh does not read.
#   - a non-comment line naming an `evidence` key (any quoting / spacing before
#     the `:`) must be exactly `      evidence: true`;
#   - the very next line must be `      challenge: <NN-slug>`;
#   - the entry must have its own `    - path: <dir>` line before them, and <dir>
#     must be an absolute, clean path of [A-Za-z0-9._-] elements (it is written
#     into the probe's payload below).
# Anything else stops the assert before the probe (exit 1). A duplicate challenge
# or mount directory stops it too.
# ---------------------------------------------------------------------------

EVIDENCE_SCOPE_CIDS=()
EVIDENCE_SCOPE_DIRS=()
# ADR-0056 A5e: the values file is the one given (5th argument), never one chosen here.
SCOPE_VALUES_FILE=""
case "${SCOPE_VALUES_ARG}" in
  -)
    # helm was given no values file: no investigate challenge in this scope
    ;;
  '')
    printf 'assert-flag-isolation.sh: the values file argument is empty (give the file helm was given, or -) — cannot judge 3-9 / 3-10 / 3-11\n' >&2
    exit 2
    ;;
  *)
    if [ ! -f "${SCOPE_VALUES_ARG}" ]
    then
      printf 'assert-flag-isolation.sh: the values file given is not a file: %s — cannot judge 3-9 / 3-10 / 3-11\n' "${SCOPE_VALUES_ARG}" >&2
      exit 1
    fi
    SCOPE_VALUES_FILE="${SCOPE_VALUES_ARG}"
    ;;
esac

evidence_scope_reject() { # $1 = line number, $2 = what is wrong
  printf 'assert-flag-isolation.sh: %s line %s: %s (the evidence entries must be in the form gen-values.sh writes) — cannot judge 3-9 / 3-10\n' \
    "${SCOPE_VALUES_FILE}" "$1" "$2" >&2
  exit 1
}

read_evidence_scope() { # $1 = values file -> EVIDENCE_SCOPE_CIDS / EVIDENCE_SCOPE_DIRS
  local f="$1" line trimmed lineno=0 want=0 item_path="" entry_path="" cid rest x
  local key_re='evidence["'"'"'[:space:]]*:'
  while IFS= read -r line || [ -n "${line}" ]
  do
    lineno=$((lineno + 1))
    if [ "${want}" -eq 1 ]
    then
      want=0
      case "${line}" in
        '      challenge: '*) cid="${line#'      challenge: '}" ;;
        *) evidence_scope_reject "${lineno}" "the line after 'evidence: true' is not '      challenge: <id>'" ;;
      esac
      case "${cid}" in
        [0-9][0-9]-?*) rest="${cid#??-}" ;;
        *) evidence_scope_reject "${lineno}" "the challenge is not of the form NN-slug" ;;
      esac
      case "${rest}" in
        *[!abcdefghijklmnopqrstuvwxyz0123456789-]*) evidence_scope_reject "${lineno}" "the challenge is not of the form NN-slug" ;;
      esac
      for x in ${EVIDENCE_SCOPE_CIDS[@]+"${EVIDENCE_SCOPE_CIDS[@]}"}
      do
        [ "${x}" != "${cid}" ] || evidence_scope_reject "${lineno}" "the challenge ${cid} has a second evidence entry"
      done
      for x in ${EVIDENCE_SCOPE_DIRS[@]+"${EVIDENCE_SCOPE_DIRS[@]}"}
      do
        [ "${x}" != "${entry_path}" ] || evidence_scope_reject "${lineno}" "the mount directory ${entry_path} has a second evidence entry"
      done
      EVIDENCE_SCOPE_CIDS+=("${cid}")
      EVIDENCE_SCOPE_DIRS+=("${entry_path}")
      continue
    fi
    trimmed="${line#"${line%%[![:space:]]*}"}"
    case "${trimmed}" in
      '#'*) continue ;;
    esac
    case "${line}" in
      '    - path: '*) item_path="${line#'    - path: '}" ;;
      '    - '*) item_path="" ;;
    esac
    if [[ "${line}" =~ ${key_re} ]]
    then
      [ "${line}" = '      evidence: true' ] || evidence_scope_reject "${lineno}" "an evidence key that is not '      evidence: true'"
      [ -n "${item_path}" ] || evidence_scope_reject "${lineno}" "an evidence entry without its own '    - path:' line"
      case "${item_path}" in
        /*) ;;
        *) evidence_scope_reject "${lineno}" "the mount directory is not an absolute path" ;;
      esac
      case "${item_path}" in
        *[!A-Za-z0-9._/-]* | */ | *//* | */./* | */. | */../* | */..)
          evidence_scope_reject "${lineno}" "the mount directory is not a clean path of [A-Za-z0-9._-] elements"
          ;;
      esac
      entry_path="${item_path}"
      want=1
    fi
  done < "${f}"
  [ "${want}" -eq 0 ] || evidence_scope_reject "${lineno}" "'evidence: true' is the last line"
}

if [ -n "${SCOPE_VALUES_FILE}" ]
then
  read_evidence_scope "${SCOPE_VALUES_FILE}"
fi

# 3-10: the Opaque Secrets this namespace must hold, exactly
EXPECTED_SECRET_NAMES=(ctf-flags)
for _c in ${EVIDENCE_SCOPE_CIDS[@]+"${EVIDENCE_SCOPE_CIDS[@]}"}
do
  EXPECTED_SECRET_NAMES+=("ctf-evidence-${_c}")
done

# 3-11 expectations (ADR-0056 D11 "3-x" item (3), A5e): the names the chart was
# given, from the <cid>/<name> arguments (deploy-user.sh passes exactly the names it
# gave helm as evidence.challenges.<cid>.names). Each one names a challenge of the
# scope read above and a name of [A-Za-z0-9._-] (a Secret key's character set; B2's
# grammar itself was deploy-user.sh's check before it made the Secret); none is
# given twice; every challenge of the scope has at least one. Anything else stops
# the assert before the probe (exit 1). An argument is never echoed (only its
# position), since it is not held to a character set until here.
evidence_names_reject() { # $1 = what is wrong
  printf 'assert-flag-isolation.sh: the evidence name arguments: %s — cannot judge 3-11\n' "$1" >&2
  exit 1
}
_i=0
for _a in ${EVIDENCE_NAME_ARGS[@]+"${EVIDENCE_NAME_ARGS[@]}"}
do
  _i=$((_i + 1))
  case "${_a}" in
    */*)
      _ac="${_a%%/*}"
      _an="${_a#*/}"
      ;;
    *)
      evidence_names_reject "argument #${_i} after the values file is not <cid>/<name>"
      ;;
  esac
  case "${_an}" in
    '' | *[!A-Za-z0-9._-]*)
      evidence_names_reject "argument #${_i} after the values file has a name outside [A-Za-z0-9._-]"
      ;;
  esac
  _found=0
  for _c in ${EVIDENCE_SCOPE_CIDS[@]+"${EVIDENCE_SCOPE_CIDS[@]}"}
  do
    if [ "${_c}" = "${_ac}" ]
    then
      _found=1
    fi
  done
  [ "${_found}" -eq 1 ] || evidence_names_reject "argument #${_i} after the values file names a challenge that is not an investigate challenge of this scope"
  _j=0
  for _b in ${EVIDENCE_NAME_ARGS[@]+"${EVIDENCE_NAME_ARGS[@]}"}
  do
    _j=$((_j + 1))
    if [ "${_j}" -gt "${_i}" ] && [ "${_b}" = "${_a}" ]
    then
      evidence_names_reject "argument #${_j} after the values file repeats argument #${_i}"
    fi
  done
done
for _c in ${EVIDENCE_SCOPE_CIDS[@]+"${EVIDENCE_SCOPE_CIDS[@]}"}
do
  _found=0
  for _a in ${EVIDENCE_NAME_ARGS[@]+"${EVIDENCE_NAME_ARGS[@]}"}
  do
    case "${_a}" in
      "${_c}/"*) _found=1 ;;
    esac
  done
  [ "${_found}" -eq 1 ] || evidence_names_reject "the investigate challenge ${_c} of this scope has no <cid>/<name> argument"
done

# ---------------------------------------------------------------------------
# The in-workspace probe (3-1..3-6, 3-8, 3-9). Builtin-only — see header. Sent
# verbatim as the `sh -c` payload via `kubectl exec`, after one assignment line
# (EVIDENCE_MOUNT_DIRS, 3-9); runs as a single `sh` process inside the
# `challenge` container, spawns nothing else.
#
# Deliberately observation-only: it reports raw facts (env/proc1/mount/line
# counts), never judges pass/fail itself — all comparison against the
# expectations above happens out here, after the fact, so the payload
# itself stays minimal and auditable.
# ---------------------------------------------------------------------------

read -r -d '' PROBE_PAYLOAD <<'PROBE_EOF' || true
set -eu

PLANT_SEED_ROOT_EXISTS=no
if [ -e /plant-seed ]
then
  PLANT_SEED_ROOT_EXISTS=yes
fi

EVIDENCE_SRC_ROOT_EXISTS=no
if [ -e /opt/ctf/evidence-src ]
then
  EVIDENCE_SRC_ROOT_EXISTS=yes
fi

SA_TOKEN_EXISTS=no
if [ -e /var/run/secrets/kubernetes.io/serviceaccount/token ]
then
  SA_TOKEN_EXISTS=yes
fi

ENV_HAS_CTF_FLAG=no
_exported="$(export -p)"
case "${_exported}" in
  *CTF_FLAG*) ENV_HAS_CTF_FLAG=yes ;;
esac

PROC1_HAS_CTF_FLAG=no
_environ_blob=""
if [ -r /proc/1/environ ]
then
  IFS= read -r _environ_blob < /proc/1/environ || true
fi
case "${_environ_blob}" in
  *CTF_FLAG*) PROC1_HAS_CTF_FLAG=yes ;;
esac

SHADOW_FALCO_LINES=0
if [ -f /etc/shadow ]
then
  while IFS= read -r _sline || [ -n "${_sline}" ]
  do
    case "${_sline}" in
      *'FALCO{'*) SHADOW_FALCO_LINES=$((SHADOW_FALCO_LINES + 1)) ;;
    esac
  done < /etc/shadow
fi

SSH_KEY_EXISTS=no
if [ -f /root/.ssh/id_rsa ]
then
  SSH_KEY_EXISTS=yes
fi

# 3-8 (P27-1 + ADR-0026 V4): enumerate /opt/ctf/missions/ — glob and shell
# builtins only (no external binary: see header). Dot entries are listed too
# (`*` alone skips them): `.[!.]*` and `..?*`. A glob that matches nothing
# stays as its literal pattern, so every candidate is confirmed to exist
# (`-e`, or `-L` for a dangling symlink) before it is counted.
#   MISSIONS_LIST   clean-named entries that are real directories (not symlinks)
#   MISSIONS_BAD    top-level entries that are NOT a real directory (file,
#                   symlink, ...) or whose name has a character outside
#                   [A-Za-z0-9._-] (reported as <bad-name>, never echoed raw:
#                   a name with a newline could otherwise forge a KEY=VALUE
#                   line of this protocol)
#   MISSIONS_SUBBAD "<id>/<entry>" for every entry under <id>/ other than a
#                   real `fixtures` directory, plus "<id>/fixtures:missing"
#                   / "<id>/fixtures:not-a-dir". fixtures' contents are never
#                   opened (V4).
# A challenge id never contains whitespace, so space-joining is a safe wire
# format for the single-line KEY=VALUE contract the rest of this probe uses.
MISSIONS_LIST=""
MISSIONS_BAD=""
MISSIONS_SUBBAD=""
if [ -d /opt/ctf/missions ]
then
  for _mdir in /opt/ctf/missions/* /opt/ctf/missions/.[!.]* /opt/ctf/missions/..?*
  do
    if [ ! -e "${_mdir}" ] && [ ! -L "${_mdir}" ]
    then
      continue
    fi
    _mb="${_mdir##*/}"
    case "${_mb}" in
      *[!A-Za-z0-9._-]*) _mb="<bad-name>" ;;
    esac
    if [ -L "${_mdir}" ] || [ ! -d "${_mdir}" ] || [ "${_mb}" = "<bad-name>" ]
    then
      MISSIONS_BAD="${MISSIONS_BAD:+${MISSIONS_BAD} }${_mb}"
      continue
    fi
    MISSIONS_LIST="${MISSIONS_LIST:+${MISSIONS_LIST} }${_mb}"
    _fx=missing
    for _sub in "${_mdir}"/* "${_mdir}"/.[!.]* "${_mdir}"/..?*
    do
      if [ ! -e "${_sub}" ] && [ ! -L "${_sub}" ]
      then
        continue
      fi
      _sb="${_sub##*/}"
      case "${_sb}" in
        *[!A-Za-z0-9._-]*) _sb="<bad-name>" ;;
      esac
      if [ "${_sb}" = fixtures ]
      then
        if [ -L "${_sub}" ] || [ ! -d "${_sub}" ]
        then
          _fx=not-a-dir
        else
          _fx=ok
        fi
        continue
      fi
      MISSIONS_SUBBAD="${MISSIONS_SUBBAD:+${MISSIONS_SUBBAD} }${_mb}/${_sb}"
    done
    if [ "${_fx}" != ok ]
    then
      MISSIONS_SUBBAD="${MISSIONS_SUBBAD:+${MISSIONS_SUBBAD} }${_mb}/fixtures:${_fx}"
    fi
  done
fi

# 3-9 (ADR-0056 D11 "3-x" item (1), A5d): EVIDENCE_MOUNT_DIRS is set by the one line the
# operator side puts before this payload (the scope's evidence mount directories,
# space-joined, each already held to [A-Za-z0-9._/-]; empty without an
# investigate challenge). Glob and `[ ]` only, nothing is opened: every entry of
# each directory (dot entries too) must be a regular file and not a symlink, and
# the directory must be a real directory with at least one file.
#   EVIDENCE_DIRS_SEEN  how many of the directories were real directories (the
#                       operator side compares it with how many it sent, so a
#                       probe that skipped this loop is not "clean")
#   EVIDENCE_BAD        "<n>:not-a-dir", "<n>:empty", "<n>/<entry>:link" or
#                       "<n>/<entry>:not-a-file" (<n> = the n-th directory sent;
#                       an entry name outside [A-Za-z0-9._-] is <bad-name>)
EVIDENCE_DIRS_SEEN=0
EVIDENCE_BAD=""
_ei=0
for _ed in ${EVIDENCE_MOUNT_DIRS:-}
do
  _ei=$((_ei + 1))
  if [ -L "${_ed}" ] || [ ! -d "${_ed}" ]
  then
    EVIDENCE_BAD="${EVIDENCE_BAD:+${EVIDENCE_BAD} }${_ei}:not-a-dir"
    continue
  fi
  EVIDENCE_DIRS_SEEN=$((EVIDENCE_DIRS_SEEN + 1))
  _en=0
  for _ef in "${_ed}"/* "${_ed}"/.[!.]* "${_ed}"/..?*
  do
    if [ ! -e "${_ef}" ] && [ ! -L "${_ef}" ]
    then
      continue
    fi
    _eb="${_ef##*/}"
    case "${_eb}" in
      *[!A-Za-z0-9._-]*) _eb="<bad-name>" ;;
    esac
    if [ -L "${_ef}" ]
    then
      EVIDENCE_BAD="${EVIDENCE_BAD:+${EVIDENCE_BAD} }${_ei}/${_eb}:link"
    elif [ ! -f "${_ef}" ]
    then
      EVIDENCE_BAD="${EVIDENCE_BAD:+${EVIDENCE_BAD} }${_ei}/${_eb}:not-a-file"
    else
      _en=$((_en + 1))
    fi
  done
  if [ "${_en}" -eq 0 ]
  then
    EVIDENCE_BAD="${EVIDENCE_BAD:+${EVIDENCE_BAD} }${_ei}:empty"
  fi
done

printf 'PLANT_SEED_ROOT_EXISTS=%s\n' "${PLANT_SEED_ROOT_EXISTS}"
printf 'EVIDENCE_SRC_ROOT_EXISTS=%s\n' "${EVIDENCE_SRC_ROOT_EXISTS}"
printf 'SA_TOKEN_EXISTS=%s\n' "${SA_TOKEN_EXISTS}"
printf 'ENV_HAS_CTF_FLAG=%s\n' "${ENV_HAS_CTF_FLAG}"
printf 'PROC1_HAS_CTF_FLAG=%s\n' "${PROC1_HAS_CTF_FLAG}"
printf 'SHADOW_FALCO_LINES=%s\n' "${SHADOW_FALCO_LINES}"
printf 'SSH_KEY_EXISTS=%s\n' "${SSH_KEY_EXISTS}"
printf 'MISSIONS_LIST=%s\n' "${MISSIONS_LIST}"
printf 'MISSIONS_BAD=%s\n' "${MISSIONS_BAD}"
printf 'MISSIONS_SUBBAD=%s\n' "${MISSIONS_SUBBAD}"
printf 'EVIDENCE_DIRS_SEEN=%s\n' "${EVIDENCE_DIRS_SEEN}"
printf 'EVIDENCE_BAD=%s\n' "${EVIDENCE_BAD}"
printf 'PROBE_END=yes\n'
PROBE_EOF

# 3-9: the one line put before the payload. The directories were held to
# [A-Za-z0-9._/-] by read_evidence_scope, so a single quote cannot be among them.
EVIDENCE_MOUNT_DIRS_WIRE="${EVIDENCE_SCOPE_DIRS[*]+${EVIDENCE_SCOPE_DIRS[*]}}"
PROBE_PAYLOAD="EVIDENCE_MOUNT_DIRS='${EVIDENCE_MOUNT_DIRS_WIRE}'"$'\n'"${PROBE_PAYLOAD}"

run_probe() { # prints the probe's stdout, or aborts (set -e) on kubectl failure
  kubectl -n "${NS}" exec workspace -c challenge -- sh -c "${PROBE_PAYLOAD}"
}

OBSERVED="$(run_probe)"

# ---------------------------------------------------------------------------
# 3-7: ttyd's OWN kubectl exec into `challenge` (the participant's actual
# terminal path — a different RBAC principal than the one running this
# script). Not part of the builtin-only payload above: this runs `kubectl`
# itself (not banned) as ttyd, from ttyd's container, once, and only checks
# its exit status.
# ---------------------------------------------------------------------------

TTYD_EXEC_OK=yes
if ! kubectl -n "${NS}" exec workspace -c ttyd -- kubectl exec workspace -c challenge -- true >/dev/null 2>&1
then
  TTYD_EXEC_OK=no
fi

# ---------------------------------------------------------------------------
# 3-10 (ADR-0056 D11 "3-x" item (2), A5d): the namespace's Secrets, listed by the
# operator (`kubectl get`, not an exec: nothing runs in the Pod). One line per
# Secret, name TAB type. A failed listing is a violation, never "no Secret".
# ---------------------------------------------------------------------------

SECRETS_LISTED=yes
SECRETS_LISTING=""
if ! SECRETS_LISTING="$(kubectl -n "${NS}" get secrets -o 'jsonpath={range .items[*]}{.metadata.name}{"\t"}{.type}{"\n"}{end}')"
then
  SECRETS_LISTED=no
fi

# ---------------------------------------------------------------------------
# 3-11 (ADR-0056 D11 "3-x" item (3), A5e): the KEYS of each ctf-evidence-<cid> of
# the scope, read by the operator, one `kubectl get secret` per challenge. The
# go-template ranges over `.data` and prints the key alone: the value is bound to a
# variable that is never printed, so no byte of a bundle leaves the API server's
# answer as anything but a key name. A failed read is recorded per challenge and is
# a violation, never "no key".
# ---------------------------------------------------------------------------

EVIDENCE_KEYS_READ=()   # per EVIDENCE_SCOPE_CIDS entry: yes / no
EVIDENCE_KEYS=()        # per EVIDENCE_SCOPE_CIDS entry: the key names, one per line
for _c in ${EVIDENCE_SCOPE_CIDS[@]+"${EVIDENCE_SCOPE_CIDS[@]}"}
do
  _keys=""
  # shellcheck disable=SC2016  # the $k / $v are the go-template's own variables
  if _keys="$(kubectl -n "${NS}" get secret "ctf-evidence-${_c}" -o 'go-template={{range $k, $v := .data}}{{$k}}{{"\n"}}{{end}}')"
  then
    EVIDENCE_KEYS_READ+=(yes)
  else
    EVIDENCE_KEYS_READ+=(no)
    _keys=""
  fi
  EVIDENCE_KEYS+=("${_keys}")
done

# ---------------------------------------------------------------------------
# Parse OBSERVED (fixed set of KEY=VALUE lines, one per probe field) and
# judge against the expectations computed above.
# ---------------------------------------------------------------------------

OBS_PLANT_SEED_ROOT_EXISTS=""
OBS_EVIDENCE_SRC_ROOT_EXISTS=""
OBS_SA_TOKEN_EXISTS=""
OBS_ENV_HAS_CTF_FLAG=""
OBS_PROC1_HAS_CTF_FLAG=""
OBS_SHADOW_FALCO_LINES=""
OBS_SSH_KEY_EXISTS=""
OBS_MISSIONS_LIST=""
OBS_MISSIONS_BAD=""
OBS_MISSIONS_SUBBAD=""
OBS_EVIDENCE_DIRS_SEEN=""
OBS_EVIDENCE_BAD=""
OBS_PROBE_END=""

while IFS='=' read -r key val
do
  case "${key}" in
    PLANT_SEED_ROOT_EXISTS) OBS_PLANT_SEED_ROOT_EXISTS="${val}" ;;
    EVIDENCE_SRC_ROOT_EXISTS) OBS_EVIDENCE_SRC_ROOT_EXISTS="${val}" ;;
    SA_TOKEN_EXISTS)        OBS_SA_TOKEN_EXISTS="${val}" ;;
    ENV_HAS_CTF_FLAG)       OBS_ENV_HAS_CTF_FLAG="${val}" ;;
    PROC1_HAS_CTF_FLAG)     OBS_PROC1_HAS_CTF_FLAG="${val}" ;;
    SHADOW_FALCO_LINES)     OBS_SHADOW_FALCO_LINES="${val}" ;;
    SSH_KEY_EXISTS)         OBS_SSH_KEY_EXISTS="${val}" ;;
    MISSIONS_LIST)          OBS_MISSIONS_LIST="${val}" ;;
    MISSIONS_BAD)           OBS_MISSIONS_BAD="${val}" ;;
    MISSIONS_SUBBAD)        OBS_MISSIONS_SUBBAD="${val}" ;;
    EVIDENCE_DIRS_SEEN)     OBS_EVIDENCE_DIRS_SEEN="${val}" ;;
    EVIDENCE_BAD)           OBS_EVIDENCE_BAD="${val}" ;;
    PROBE_END)              OBS_PROBE_END="${val}" ;;
  esac
done <<< "${OBSERVED}"

VIOLATIONS=()

# The probe's output is untrusted text (it comes from inside the workspace,
# via a possibly fake `sh`) and is printed to the operator's terminal below.
# Every value must stay inside the probe's own character set; anything else
# (escape sequences, control characters, glob metacharacters) becomes 3-0 and
# the value is replaced by a placeholder so it is never echoed or split.
# MISSIONS_LIST is ids only; BAD / SUBBAD also carry '/', ':' and the
# <bad-name> placeholder.
for _v in OBS_PLANT_SEED_ROOT_EXISTS OBS_EVIDENCE_SRC_ROOT_EXISTS OBS_SA_TOKEN_EXISTS OBS_ENV_HAS_CTF_FLAG OBS_PROC1_HAS_CTF_FLAG \
          OBS_SHADOW_FALCO_LINES OBS_SSH_KEY_EXISTS OBS_MISSIONS_LIST OBS_MISSIONS_BAD OBS_MISSIONS_SUBBAD \
          OBS_EVIDENCE_DIRS_SEEN OBS_EVIDENCE_BAD OBS_PROBE_END
do
  _val="${!_v}"
  _bad=no
  case "${_v}" in
    OBS_MISSIONS_BAD|OBS_MISSIONS_SUBBAD|OBS_EVIDENCE_BAD)
      case "${_val}" in *[!A-Za-z0-9._/:\<\>\ -]*) _bad=yes ;; esac ;;
    *)
      case "${_val}" in *[!A-Za-z0-9._\ -]*) _bad=yes ;; esac ;;
  esac
  if [ "${_bad}" = yes ]
  then
    VIOLATIONS+=("3-0: probe field ${_v#OBS_} has a character outside its allowed set — value discarded")
    printf -v "${_v}" '%s' '<rejected>'
  fi
done

# A truncated probe must not read as "nothing found" (the 3-8 fields default
# to empty above): the last line is a sentinel.
if [ "${OBS_PROBE_END}" != "yes" ]
then
  VIOLATIONS+=("3-0: probe output incomplete (no PROBE_END sentinel) — cannot trust any check below")
fi

if [ "${OBS_ENV_HAS_CTF_FLAG}" != "no" ]
then
  VIOLATIONS+=("3-1: challenge container's own process env contains CTF_FLAG (expected: absent)")
fi

if [ "${OBS_PROC1_HAS_CTF_FLAG}" != "no" ]
then
  VIOLATIONS+=("3-2: /proc/1/environ contains CTF_FLAG (expected: absent)")
fi

if [ "${OBS_SA_TOKEN_EXISTS}" != "no" ]
then
  VIOLATIONS+=("3-3: ServiceAccount token is mounted into challenge (expected: not exist)")
fi

if [ "${OBS_PLANT_SEED_ROOT_EXISTS}" != "no" ]
then
  VIOLATIONS+=("3-4: seed volume root (/plant-seed) is visible from challenge (expected: not exist)")
fi

if [ "${OBS_EVIDENCE_SRC_ROOT_EXISTS}" != "no" ]
then
  VIOLATIONS+=("3-4: the evidence source root (/opt/ctf/evidence-src, the plant initContainer's Secret mounts) is visible from challenge (expected: not exist; ADR-0056 D11)")
fi

if [ "${OBS_SHADOW_FALCO_LINES}" != "${EXPECTED_SHADOW_FALCO_LINES}" ]
then
  VIOLATIONS+=("3-5: /etc/shadow has ${OBS_SHADOW_FALCO_LINES} planted flag-marker line(s), expected ${EXPECTED_SHADOW_FALCO_LINES} for challenge-id=${CHALLENGE_ID}")
fi

if [ "${OBS_SSH_KEY_EXISTS}" != "${EXPECTED_SSH_KEY_EXISTS}" ]
then
  VIOLATIONS+=("3-6: /root/.ssh/id_rsa exists=${OBS_SSH_KEY_EXISTS}, expected exists=${EXPECTED_SSH_KEY_EXISTS} for challenge-id=${CHALLENGE_ID}")
fi

if [ "${TTYD_EXEC_OK}" != "yes" ]
then
  VIOLATIONS+=("3-7: ttyd's own kubectl exec into challenge failed (participant terminal would be broken)")
fi

# 3-8 (P27-1 + ADR-0026 V4), all three modes. Three independent conditions:
#   (a) the observed id set == EXPECTED_MISSION_IDS, both directions: an
#       out-of-scope id (P27-1: its fixtures reachable) or a missing one (a
#       broken missions-scope copy / an image older than the checkout) fails.
#       Zero observed entries fails too (expected is never empty, see above).
#   (b) every top-level entry is a real directory (MISSIONS_BAD empty) —
#       this includes dot entries such as .DS_Store.
#   (c) each <id>/ holds only a real `fixtures` directory (MISSIONS_SUBBAD
#       empty). fixtures' own contents are deliberately not inspected.
# ADR-0026 V4 は「image の allowlist 証跡」を image 自身に問い合わせる:
# build 時の検査 (check-image-hygiene.sh) が通った image でも、tag の取り違え・
# 古い image は deploy の瞬間にしか見えない。防げるのはここまで:
# 悪意ある registry 上の差し替えは digest pin / 署名の役目で、この検査では防げない。
# 参加者が触った後に再実行しても image の証跡にならない (監査は
# `scripts/check-image-hygiene.sh <image digest>` で行う)。
# Split with globbing off: the value is already charset-checked above, but a
# glob character must never expand against the operator's filesystem.
set -f
# shellcheck disable=SC2206  # intentional word-splitting on unquoted var
OBS_MISSIONS_ARR=(${OBS_MISSIONS_LIST})
set +f
MISSIONS_OK=yes
if [ "${#OBS_MISSIONS_ARR[@]}" -ne "${#EXPECTED_MISSION_IDS[@]}" ]
then
  MISSIONS_OK=no
else
  for sid in "${EXPECTED_MISSION_IDS[@]}"
  do
    found=0
    for x in "${OBS_MISSIONS_ARR[@]}"
    do
      if [ "${x}" = "${sid}" ]
      then
        found=1
        break
      fi
    done
    if [ "${found}" -eq 0 ]
    then
      MISSIONS_OK=no
      break
    fi
  done
  # observed ⊆ expected too (expected is duplicate-free, so with equal counts
  # this makes the comparison a true two-way set equality)
  for x in "${OBS_MISSIONS_ARR[@]}"
  do
    found=0
    for sid in "${EXPECTED_MISSION_IDS[@]}"
    do
      if [ "${x}" = "${sid}" ]
      then
        found=1
        break
      fi
    done
    if [ "${found}" -eq 0 ]
    then
      MISSIONS_OK=no
      break
    fi
  done
fi
if [ "${MISSIONS_OK}" != yes ]
then
  VIOLATIONS+=("3-8: /opt/ctf/missions/ contains [${OBS_MISSIONS_LIST}], expected exactly [${EXPECTED_MISSION_IDS[*]}] for challenge-id=${CHALLENGE_ID}")
fi
if [ -n "${OBS_MISSIONS_BAD}" ]
then
  VIOLATIONS+=("3-8: /opt/ctf/missions/ has entries that are not a plain directory: [${OBS_MISSIONS_BAD}]")
fi
if [ -n "${OBS_MISSIONS_SUBBAD}" ]
then
  VIOLATIONS+=("3-8: an <id>/ directory holds something other than a plain fixtures/ directory: [${OBS_MISSIONS_SUBBAD}]")
fi

# 3-9 (ADR-0056 D11 "3-x" item (1), A5d, V8): every evidence mount directory of the scope
# is a real directory of regular files only (no symlink), and the probe judged
# all of them (a probe that saw fewer than it was sent is not clean).
if [ -n "${OBS_EVIDENCE_BAD}" ]
then
  VIOLATIONS+=("3-9: an evidence mount directory is not a real directory of regular files only: [${OBS_EVIDENCE_BAD}] (<n> is the n-th of [${EVIDENCE_MOUNT_DIRS_WIRE}])")
fi
if [ "${OBS_EVIDENCE_DIRS_SEEN}" != "${#EVIDENCE_SCOPE_DIRS[@]}" ]
then
  VIOLATIONS+=("3-9: the probe judged ${OBS_EVIDENCE_DIRS_SEEN:-no} of the ${#EVIDENCE_SCOPE_DIRS[@]} evidence mount director(ies) [${EVIDENCE_MOUNT_DIRS_WIRE}] of this scope")
fi

# 3-10 (ADR-0056 D11 "3-x" item (2), A5d, V2): the Opaque Secrets are exactly
# EXPECTED_SECRET_NAMES (both directions); Helm's release records are counted
# apart; any other type, and a line outside the character sets of a Secret's
# name / type (it is discarded, never echoed), fails. The seat's Secrets are a
# closed set (flags, bundles, Helm's records): a constraint on the platform, for
# the next ADR-0056 addendum and the contract table.
OBS_OPAQUE_SECRETS=()
OBS_OTHER_SECRETS=()
OBS_HELM_RELEASES=0
SECRETS_BAD_LINES=0
if [ "${SECRETS_LISTED}" != yes ]
then
  VIOLATIONS+=("3-10: kubectl get secrets failed in ${NS}, so the Secret names of the namespace could not be judged")
else
  while IFS= read -r _sline || [ -n "${_sline}" ]
  do
    [ -n "${_sline}" ] || continue
    case "${_sline}" in
      *$'\t'*) ;;
      *)
        SECRETS_BAD_LINES=$((SECRETS_BAD_LINES + 1))
        continue
        ;;
    esac
    _sname="${_sline%%$'\t'*}"
    _stype="${_sline#*$'\t'}"
    case "${_sname}" in
      '' | *[!a-z0-9.-]*)
        SECRETS_BAD_LINES=$((SECRETS_BAD_LINES + 1))
        continue
        ;;
    esac
    case "${_stype}" in
      '' | *[!A-Za-z0-9./_-]*)
        SECRETS_BAD_LINES=$((SECRETS_BAD_LINES + 1))
        continue
        ;;
    esac
    case "${_stype}" in
      Opaque) OBS_OPAQUE_SECRETS+=("${_sname}") ;;
      helm.sh/release.v1) OBS_HELM_RELEASES=$((OBS_HELM_RELEASES + 1)) ;;
      *) OBS_OTHER_SECRETS+=("${_sname} (${_stype})") ;;
    esac
  done <<< "${SECRETS_LISTING}"
  if [ "${SECRETS_BAD_LINES}" -gt 0 ]
  then
    VIOLATIONS+=("3-10: ${SECRETS_BAD_LINES} line(s) of the Secret listing are outside the character set of a name TAB a type (discarded)")
  fi
  if [ "${#OBS_OTHER_SECRETS[@]}" -gt 0 ]
  then
    VIOLATIONS+=("3-10: Secret(s) of a type other than Opaque and helm.sh/release.v1 in ${NS}: [${OBS_OTHER_SECRETS[*]}]")
  fi
  SECRETS_OK=yes
  if [ "${#OBS_OPAQUE_SECRETS[@]}" -ne "${#EXPECTED_SECRET_NAMES[@]}" ]
  then
    SECRETS_OK=no
  fi
  for _e in "${EXPECTED_SECRET_NAMES[@]}"
  do
    found=0
    for _o in ${OBS_OPAQUE_SECRETS[@]+"${OBS_OPAQUE_SECRETS[@]}"}
    do
      if [ "${_o}" = "${_e}" ]
      then
        found=1
        break
      fi
    done
    [ "${found}" -eq 1 ] || SECRETS_OK=no
  done
  for _o in ${OBS_OPAQUE_SECRETS[@]+"${OBS_OPAQUE_SECRETS[@]}"}
  do
    found=0
    for _e in "${EXPECTED_SECRET_NAMES[@]}"
    do
      if [ "${_o}" = "${_e}" ]
      then
        found=1
        break
      fi
    done
    [ "${found}" -eq 1 ] || SECRETS_OK=no
  done
  if [ "${SECRETS_OK}" != yes ]
  then
    VIOLATIONS+=("3-10: the Opaque Secrets of ${NS} are [${OBS_OPAQUE_SECRETS[*]+${OBS_OPAQUE_SECRETS[*]}}], expected exactly [${EXPECTED_SECRET_NAMES[*]}] (ctf-flags and ctf-evidence-<cid> of this scope's investigate challenges)")
  fi
fi

# 3-11 (ADR-0056 D11 "3-x" item (3), A5e, V94): for each investigate challenge of
# the scope, the key set of ctf-evidence-<cid> equals the names the chart was given
# for it (both directions). A key outside a Secret key's character set is
# discarded (never echoed) and fails.
_idx=0
for _c in ${EVIDENCE_SCOPE_CIDS[@]+"${EVIDENCE_SCOPE_CIDS[@]}"}
do
  if [ "${EVIDENCE_KEYS_READ[_idx]}" != yes ]
  then
    VIOLATIONS+=("3-11: the keys of the Secret ctf-evidence-${_c} could not be read (kubectl get secret failed)")
    _idx=$((_idx + 1))
    continue
  fi
  _obs=()
  _badkeys=0
  while IFS= read -r _k || [ -n "${_k}" ]
  do
    [ -n "${_k}" ] || continue
    case "${_k}" in
      *[!A-Za-z0-9._-]*)
        _badkeys=$((_badkeys + 1))
        continue
        ;;
    esac
    _obs+=("${_k}")
  done <<< "${EVIDENCE_KEYS[_idx]}"
  _want=()
  for _a in ${EVIDENCE_NAME_ARGS[@]+"${EVIDENCE_NAME_ARGS[@]}"}
  do
    case "${_a}" in
      "${_c}/"*) _want+=("${_a#*/}") ;;
    esac
  done
  KEYS_OK=yes
  if [ "${_badkeys}" -gt 0 ]
  then
    VIOLATIONS+=("3-11: ${_badkeys} key(s) of ctf-evidence-${_c} are outside a Secret key's character set (discarded)")
    KEYS_OK=no
  fi
  if [ "${#_obs[@]}" -ne "${#_want[@]}" ]
  then
    KEYS_OK=no
  fi
  for _w in "${_want[@]}"
  do
    found=0
    for _o in ${_obs[@]+"${_obs[@]}"}
    do
      if [ "${_o}" = "${_w}" ]
      then
        found=1
        break
      fi
    done
    [ "${found}" -eq 1 ] || KEYS_OK=no
  done
  for _o in ${_obs[@]+"${_obs[@]}"}
  do
    found=0
    for _w in "${_want[@]}"
    do
      if [ "${_o}" = "${_w}" ]
      then
        found=1
        break
      fi
    done
    [ "${found}" -eq 1 ] || KEYS_OK=no
  done
  if [ "${KEYS_OK}" != yes ]
  then
    VIOLATIONS+=("3-11: the keys of ctf-evidence-${_c} are [${_obs[*]+${_obs[*]}}], expected exactly the names the chart was given [${_want[*]}]")
  fi
  _idx=$((_idx + 1))
done

if [ "${#VIOLATIONS[@]}" -gt 0 ]
then
  printf 'assert-flag-isolation.sh: FAIL (%d violation(s)) for namespace %s (challenge-id=%s):\n' \
    "${#VIOLATIONS[@]}" "${NS}" "${CHALLENGE_ID}" >&2
  for v in "${VIOLATIONS[@]}"
  do
    printf '  - %s\n' "${v}" >&2
  done
  exit 1
fi

CHECKS_RUN="3-1..3-11"
# 3-9 / 3-10 / 3-11 are ADR-0056 D11 "3-x" items (1)(2)(3) (see the header). The
# evidence scope is printed so that a test can hold it to evidence_scope_cids.
printf 'assert-flag-isolation.sh: OK — %s clean for namespace %s (challenge-id=%s): evidence scope [%s], Opaque Secrets [%s], %d Helm release record(s)\n' \
  "${CHECKS_RUN}" "${NS}" "${CHALLENGE_ID}" "${EVIDENCE_SCOPE_CIDS[*]+${EVIDENCE_SCOPE_CIDS[*]}}" "${EXPECTED_SECRET_NAMES[*]}" "${OBS_HELM_RELEASES}"
