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
#        (only individual plant-target subPath mounts are — F5)
#   3-5  the planted /etc/shadow contains exactly as many `FALCO{` lines as
#        the missions actually in scope for this deploy declare (03/10)
#   3-6  the planted /root/.ssh/id_rsa exists IF mission 05 is in scope —
#        `test -f` ONLY, never opened/read (see WHY below)
#   3-7  ttyd's own in-cluster `kubectl exec` into `challenge` still works
#        (this is the participant's actual terminal path, not the
#        operator's — a separate RBAC principal from the one running this
#        script)
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
#   assert-flag-isolation.sh <namespace> <challenges-dir> <challenge-id>
#
# <challenge-id> is either the literal string `all` (roster / all-missions
# deploys — the prod default) or a single mission id (e.g. `03-stealth-read`)
# matching what was passed to deploy-user.sh. This determines how many
# `FALCO{` lines /etc/shadow is expected to carry and whether
# /root/.ssh/id_rsa is expected to exist at all (3-5 / 3-6 are computed
# dynamically from the actual plant.sh headers in <challenges-dir>, not
# hardcoded to the all-missions "2" — a single-mission dev deploy plants a
# different subset).
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

NS="${1:?usage: assert-flag-isolation.sh <namespace> <challenges-dir> <challenge-id>}"
CHALLENGES_DIR="${2:?usage: assert-flag-isolation.sh <namespace> <challenges-dir> <challenge-id>}"
CHALLENGE_ID="${3:?usage: assert-flag-isolation.sh <namespace> <challenges-dir> <challenge-id>}"

if [ ! -d "${CHALLENGES_DIR}" ]
then
  printf 'assert-flag-isolation.sh: challenges dir not found: %s\n' "${CHALLENGES_DIR}" >&2
  exit 1
fi

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
else
  collect_plant_target_expectations "${CHALLENGES_DIR}/${CHALLENGE_ID}/plant.sh"
fi

# ---------------------------------------------------------------------------
# The in-workspace probe (3-1..3-6). Builtin-only — see header. Sent
# verbatim as the `sh -c` payload via `kubectl exec`; runs as a single `sh`
# process inside the `challenge` container, spawns nothing else.
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

printf 'PLANT_SEED_ROOT_EXISTS=%s\n' "${PLANT_SEED_ROOT_EXISTS}"
printf 'SA_TOKEN_EXISTS=%s\n' "${SA_TOKEN_EXISTS}"
printf 'ENV_HAS_CTF_FLAG=%s\n' "${ENV_HAS_CTF_FLAG}"
printf 'PROC1_HAS_CTF_FLAG=%s\n' "${PROC1_HAS_CTF_FLAG}"
printf 'SHADOW_FALCO_LINES=%s\n' "${SHADOW_FALCO_LINES}"
printf 'SSH_KEY_EXISTS=%s\n' "${SSH_KEY_EXISTS}"
PROBE_EOF

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
# Parse OBSERVED (fixed set of KEY=VALUE lines, one per probe field) and
# judge against the expectations computed above.
# ---------------------------------------------------------------------------

OBS_PLANT_SEED_ROOT_EXISTS=""
OBS_SA_TOKEN_EXISTS=""
OBS_ENV_HAS_CTF_FLAG=""
OBS_PROC1_HAS_CTF_FLAG=""
OBS_SHADOW_FALCO_LINES=""
OBS_SSH_KEY_EXISTS=""

while IFS='=' read -r key val
do
  case "${key}" in
    PLANT_SEED_ROOT_EXISTS) OBS_PLANT_SEED_ROOT_EXISTS="${val}" ;;
    SA_TOKEN_EXISTS)        OBS_SA_TOKEN_EXISTS="${val}" ;;
    ENV_HAS_CTF_FLAG)       OBS_ENV_HAS_CTF_FLAG="${val}" ;;
    PROC1_HAS_CTF_FLAG)     OBS_PROC1_HAS_CTF_FLAG="${val}" ;;
    SHADOW_FALCO_LINES)     OBS_SHADOW_FALCO_LINES="${val}" ;;
    SSH_KEY_EXISTS)         OBS_SSH_KEY_EXISTS="${val}" ;;
  esac
done <<< "${OBSERVED}"

VIOLATIONS=()

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

printf 'assert-flag-isolation.sh: OK — 3-1..3-7 clean for namespace %s (challenge-id=%s)\n' \
  "${NS}" "${CHALLENGE_ID}"
