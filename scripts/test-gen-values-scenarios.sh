#!/usr/bin/env bash
# Self-test of the scenario checks in challenges/gen-values.sh (ADR-0055 V1).
#
# WHY: a check that nothing has ever made red stays green forever. gen-values.sh
# refuses, with exit 1 and a message that names the scenario, (a) a scenario whose
# `id:` is not the name of its directory (or has no `id:`), and (b) a challenge id
# listed twice in one scenario. Each case below copies the real challenges/ and
# scenarios/ into a throwaway directory, adds ONE scenario directory to the copy, and
# runs the copied gen-values.sh (generation mode; it writes only inside the copy):
#
#   controls (the check is not simply red; each must exit 0 and be silent about V1)
#     s-ok         id == directory name, two distinct challenges
#     s-quoted     id == directory name, written "quoted" with a trailing comment
#   violations (each must exit 1, with the message that names the scenario)
#     s-mismatch   `id: s-other` in directory s-mismatch
#     s-noid       no top-level `id:`
#     s-unsafe     an id outside the echo grammar: refused, and its value not printed
#     s-dup        01-initial-recon listed twice (02-credential-files once)
#
# The real scenarios/ tree rides along in every case, so exit 0 in a control also shows
# the shipped scenarios pass; a violation case is red for the one scenario it adds, and
# the message is what proves it is red for that reason. A run that executed fewer cases
# than listed fails (a loop that ran nothing proves nothing).
#
# The Go side of the same rule (an id that is not its directory's name, in
# LoadScenarios) is internal/catalog/scenario_test.go.
#
# Usage: ./scripts/test-gen-values-scenarios.sh   (called by scripts/check-flags.sh;
#        CI flag-guard, make check-flags)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

cp -R "${REPO_ROOT}/challenges" "${tmp}/challenges"
cp -R "${REPO_ROOT}/scenarios" "${tmp}/scenarios"
GEN="${tmp}/challenges/gen-values.sh"

# Two challenges every checkout has (both are in scenarios/nimbusbreach-full).
CID_A="01-initial-recon"
CID_B="02-credential-files"
for c in "${CID_A}" "${CID_B}"; do
  if [ ! -d "${tmp}/challenges/${c}" ]; then
    echo "FAIL: the self-test needs challenges/${c} (rename it here too)" >&2
    exit 1
  fi
done

ran=0
rc=0
out=""

fail() { # <message>: names the case, prints what gen-values.sh said, exits 1
  echo "FAIL: ${1}" >&2
  echo "  gen-values.sh exit=${rc}, output:" >&2
  printf '%s\n' "${out}" | sed 's/^/    /' >&2
  exit 1
}

# run_case <label> <dir> <want exit: 0|1> <scenario.yaml body> [needle...]
# Adds scenarios/<dir>/scenario.yaml to the copy, runs gen-values.sh, removes it again.
# A needle must appear in the output; a needle starting with '!' must NOT appear.
run_case() {
  local label="$1" dir="$2" want="$3" body="$4" needle plain
  shift 4
  mkdir "${tmp}/scenarios/${dir}"
  printf '%s' "${body}" > "${tmp}/scenarios/${dir}/scenario.yaml"
  rc=0
  out="$(bash "${GEN}" 2>&1)" || rc=$?
  rm -rf "${tmp}/scenarios/${dir}"
  rm -f "${tmp}/challenges/values-scenario-${dir}.yaml"
  if [ "${rc}" -ne "${want}" ]; then
    fail "${label}: expected exit ${want}, got ${rc}"
  fi
  for needle in "$@"; do
    case "${needle}" in
      '!'*)
        plain="${needle#!}"
        case "${out}" in
          *"${plain}"*) fail "${label}: the output must not contain: ${plain}" ;;
        esac
        ;;
      *)
        case "${out}" in
          *"${needle}"*) ;;
          *) fail "${label}: the output does not contain: ${needle}" ;;
        esac
        ;;
    esac
  done
  ran=$((ran + 1))
  echo "ok (selftest): ${label} -> exit ${want}"
}

# --- controls -----------------------------------------------------------------
run_case "control: id equals the directory name" s-ok 0 \
  $'id: s-ok\ntitle: Ok\nchallenges:\n  - '"${CID_A}"$'\n  - '"${CID_B}"$'\n' \
  '!ADR-0055 V1 VIOLATION'

run_case "control: a quoted id with a trailing comment equals the directory name" s-quoted 0 \
  $'id: "s-quoted"   # the name of the directory\ntitle: Q\nchallenges:\n  - '"${CID_A}"$'\n' \
  '!ADR-0055 V1 VIOLATION'

# --- violations ---------------------------------------------------------------
run_case "id is not the name of its directory" s-mismatch 1 \
  $'id: s-other\ntitle: M\nchallenges:\n  - '"${CID_A}"$'\n' \
  "ADR-0055 V1 VIOLATION: scenario directory 's-mismatch' declares id 's-other'" \
  "want 's-mismatch'"

run_case "no top-level id" s-noid 1 \
  $'title: N\nchallenges:\n  - '"${CID_A}"$'\n' \
  "ADR-0055 V1 VIOLATION: scenario 's-noid'" \
  "has no top-level 'id:'"

run_case "an id outside the echo grammar is refused and not printed" s-unsafe 1 \
  $'id: \'x;y\'\ntitle: U\nchallenges:\n  - '"${CID_A}"$'\n' \
  "ADR-0055 V1 VIOLATION: scenario directory 's-unsafe'" \
  "not echoed" \
  '!x;y'

run_case "a challenge listed twice in one scenario" s-dup 1 \
  $'id: s-dup\ntitle: D\nchallenges:\n  - '"${CID_A}"$'\n  - '"${CID_B}"$'\n  - '"${CID_A}"$'\n' \
  "ADR-0055 V1 VIOLATION: scenario 's-dup': challenge '${CID_A}' is listed more than once" \
  "!challenge '${CID_B}' is listed more than once"

want_cases=6
if [ "${ran}" -ne "${want_cases}" ]; then
  echo "FAIL: ran ${ran} cases, expected ${want_cases}" >&2
  exit 1
fi
echo "ok: gen-values.sh scenario checks accept the controls and refuse each violation (${ran} cases)"
