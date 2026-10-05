#!/usr/bin/env bash
# Validate a per-event flags file before deploy-user.sh hands it to helm.
#
# This is the planting-side counterpart of the scoreboard's
# catalog.ApplyFlagOverrides (internal/catalog/flags.go). Both sides read the
# same file ({flags: {<challengeId>: FALCO{...}}}) and apply the same rules, so
# an incomplete or un-rotated file is refused on both sides instead of leaving
# a challenge on the repository default.
#
# Usage:
#   validate-flags-file.sh <flags-file> <challenges-dir> <challenge-id> [<scenarios-dir>]
#
# <challenge-id> is what deploy-user.sh was given: `all`, a single `<NN-slug>`,
# or `scenario:<name>` (<scenarios-dir> is then required).
#
# Rules (every violation is reported; any violation => exit 1):
#   - the file has at least one entry under a top-level `flags:` map
#   - no challengeId appears twice
#   - every entry names an evade challenge that exists in <challenges-dir>
#     (challenges/<id>/falco-rule.yaml `type: evade`)
#   - every value matches FALCO{...}
#   - no value equals the repository default for that challenge
#     (falco-rule.yaml `expectedFlag`, or this chart's values.yaml
#     `challenge.flags.<id>`)
#   - every evade challenge IN SCOPE for this deploy has an entry:
#       all              -> every evade challenge in <challenges-dir>
#       scenario:<name>  -> the evade challenges listed in
#                           <scenarios-dir>/<name>/scenario.yaml `challenges:`
#       <NN-slug>        -> that challenge, if it is an evade challenge
#     (the same scoping templates/ctf-flags-secret.yaml uses to decide which
#     flags reach the `plant` initContainer). Entries for evade challenges
#     outside the scope are allowed, so one event file works for every mode.
#
# Output: on success, one `<challengeId><TAB><flag>` line per entry on stdout
# (deploy-user.sh turns these into --set-string args) and nothing else.
# Diagnostics go to stderr and name challenge ids only — a flag value is never
# printed in a message.
#
# Exit status: 0 valid / 1 the file was rejected / 2 usage or unreadable input.
set -euo pipefail

USAGE='usage: validate-flags-file.sh <flags-file> <challenges-dir> <challenge-id> [<scenarios-dir>]'
FLAGS_FILE="${1:?${USAGE}}"
CHALLENGES_DIR="${2:?${USAGE}}"
CHALLENGE_ID="${3:?${USAGE}}"
SCENARIOS_DIR="${4:-}"
CHART_VALUES="$(cd "$(dirname "$0")" && pwd)/values.yaml"

die() { # $1=exit-status $2=message
  printf 'validate-flags-file.sh: %s\n' "$2" >&2
  exit "$1"
}

[[ -f "${FLAGS_FILE}" ]] || die 2 "flags file not found: ${FLAGS_FILE}"
[[ -d "${CHALLENGES_DIR}" ]] || die 2 "challenges dir not found: ${CHALLENGES_DIR}"
[[ -f "${CHART_VALUES}" ]] || die 2 "chart values not found: ${CHART_VALUES}"

FLAG_RE='^FALCO\{[^}]+\}$'

# index_of <needle> <haystack...> -> prints the 0-based index and returns 0,
# or returns 1 if absent. (bash 3.2: no associative arrays.)
index_of() {
  local needle="$1" i=0
  shift
  local item
  for item in "$@"; do
    if [[ "${item}" == "${needle}" ]]; then
      printf '%s\n' "${i}"
      return 0
    fi
    i=$((i + 1))
  done
  return 1
}

# top_level_scalar <file> <key> -> the value of a top-level `key: value` line,
# with surrounding quotes and a trailing ` # comment` removed.
top_level_scalar() {
  awk -v key="$2" '
    index($0, key ":") == 1 {
      v = substr($0, length(key) + 2)
      sub(/[[:space:]]+#.*$/, "", v)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
      gsub(/^["'"'"']|["'"'"']$/, "", v)
      print v
      exit
    }' "$1"
}

# --- evade challenges known to <challenges-dir>, with their repo defaults ---
EVADE_IDS=()
EVADE_DEFAULTS=()
for rule in "${CHALLENGES_DIR}"/*/falco-rule.yaml; do
  [[ -f "${rule}" ]] || continue
  [[ "$(top_level_scalar "${rule}" type)" == "evade" ]] || continue
  cid="$(top_level_scalar "${rule}" challengeId)"
  [[ -n "${cid}" ]] || die 2 "no challengeId in ${rule}"
  EVADE_IDS+=("${cid}")
  EVADE_DEFAULTS+=("$(top_level_scalar "${rule}" expectedFlag)")
done

# --- this chart's own defaults (values.yaml: challenge.flags.<id>) ----------
CHART_IDS=()
CHART_DEFAULTS=()
while IFS=$'\t' read -r cid cval; do
  [[ -z "${cid}" ]] && continue
  CHART_IDS+=("${cid}")
  CHART_DEFAULTS+=("${cval}")
done < <(awk '
  /^[[:space:]]*(#|$)/ { next }
  { match($0, /^ */); indent = RLENGTH }
  indent == 0 { inchallenge = ($0 ~ /^challenge:/); inflags = 0; next }
  inchallenge && indent == 2 { inflags = ($0 ~ /^  flags:/); next }
  inchallenge && inflags && indent == 4 {
    line = substr($0, 5)
    idx = index(line, ":"); k = substr(line, 1, idx - 1); v = substr(line, idx + 1)
    sub(/[[:space:]]+#.*$/, "", v)
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
    gsub(/^["'"'"']|["'"'"']$/, "", v)
    printf "%s\t%s\n", k, v
  }' "${CHART_VALUES}")
# A chart that ships evade challenges always carries their placeholder
# defaults; reading none means this parser no longer matches values.yaml, and
# the "equals the chart default" rule below would silently stop checking.
if [[ ${#EVADE_IDS[@]} -gt 0 && ${#CHART_IDS[@]} -eq 0 ]]; then
  die 2 "could not read challenge.flags defaults from ${CHART_VALUES}"
fi

# --- evade challenges in scope for this deploy ------------------------------
REQUIRED_IDS=()
case "${CHALLENGE_ID}" in
  all)
    REQUIRED_IDS=(${EVADE_IDS[@]+"${EVADE_IDS[@]}"})
    ;;
  scenario:*)
    scenario_name="${CHALLENGE_ID#scenario:}"
    [[ -n "${scenario_name}" ]] || die 2 "scenario name is empty in challenge-id '${CHALLENGE_ID}'"
    [[ -n "${SCENARIOS_DIR}" ]] || die 2 "challenge-id is ${CHALLENGE_ID} but no <scenarios-dir> was given"
    scenario_file="${SCENARIOS_DIR}/${scenario_name}/scenario.yaml"
    [[ -f "${scenario_file}" ]] || die 2 "scenario file not found: ${scenario_file}"
    scenario_count=0
    # Same `challenges:` list parsing as challenges/gen-values.sh's
    # scenario_challenge_ids().
    while IFS= read -r sid; do
      [[ -z "${sid}" ]] && continue
      scenario_count=$((scenario_count + 1))
      if index_of "${sid}" ${EVADE_IDS[@]+"${EVADE_IDS[@]}"} >/dev/null; then
        REQUIRED_IDS+=("${sid}")
      fi
    done < <(awk '
      /^challenges:/ { inblock=1; next }
      inblock && /^[^[:space:]]/ { inblock=0 }
      inblock && /^[[:space:]]*-[[:space:]]*/ {
        line=$0
        sub(/^[[:space:]]*-[[:space:]]*/, "", line)
        sub(/[[:space:]]*#.*$/, "", line)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
        if (line != "") print line
      }' "${scenario_file}")
    [[ "${scenario_count}" -gt 0 ]] || die 2 "${scenario_file} has no challenges: list"
    ;;
  *)
    if index_of "${CHALLENGE_ID}" ${EVADE_IDS[@]+"${EVADE_IDS[@]}"} >/dev/null; then
      REQUIRED_IDS=("${CHALLENGE_ID}")
    fi
    ;;
esac

# --- the flags file itself ---------------------------------------------------
SUPPLIED_IDS=()
SUPPLIED_VALUES=()
while IFS=$'\t' read -r fid fval; do
  [[ -z "${fid}" ]] && continue
  SUPPLIED_IDS+=("${fid}")
  SUPPLIED_VALUES+=("${fval}")
done < <(awk '
  /^flags:/ { inblock=1; next }
  inblock && /^[^[:space:]]/ { inblock=0 }
  inblock && /^[[:space:]]+[^[:space:]#]/ {
    line=$0; sub(/^[[:space:]]+/, "", line)
    idx=index(line, ":"); k=substr(line, 1, idx-1); v=substr(line, idx+1)
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
    gsub(/^["'"'"']|["'"'"']$/, "", v)
    printf "%s\t%s\n", k, v
  }' "${FLAGS_FILE}")

RC=0
violation() {
  printf '  ✗ %s\n' "$1" >&2
  RC=1
}

if [[ ${#SUPPLIED_IDS[@]} -eq 0 ]]; then
  violation "no flags parsed from ${FLAGS_FILE} (expected a top-level 'flags:' map)"
fi

i=0
SEEN_IDS=()
while [[ "${i}" -lt ${#SUPPLIED_IDS[@]} ]]; do
  fid="${SUPPLIED_IDS[${i}]}"
  fval="${SUPPLIED_VALUES[${i}]}"
  i=$((i + 1))

  if index_of "${fid}" ${SEEN_IDS[@]+"${SEEN_IDS[@]}"} >/dev/null; then
    violation "${fid}: listed more than once"
    continue
  fi
  SEEN_IDS+=("${fid}")

  if ! eidx="$(index_of "${fid}" ${EVADE_IDS[@]+"${EVADE_IDS[@]}"})"; then
    violation "${fid}: not an evade challenge in ${CHALLENGES_DIR} (only evade challenges have flags)"
    continue
  fi
  if [[ ! "${fval}" =~ ${FLAG_RE} ]]; then
    violation "${fid}: value must match FALCO{...}"
    continue
  fi
  if [[ "${fval}" == "${EVADE_DEFAULTS[${eidx}]}" ]]; then
    violation "${fid}: value is the same as the repository default; supply a per-event value"
    continue
  fi
  if cidx="$(index_of "${fid}" ${CHART_IDS[@]+"${CHART_IDS[@]}"})"; then
    if [[ "${fval}" == "${CHART_DEFAULTS[${cidx}]}" ]]; then
      violation "${fid}: value is the same as the chart default; supply a per-event value"
      continue
    fi
  fi
done

for rid in ${REQUIRED_IDS[@]+"${REQUIRED_IDS[@]}"}; do
  if ! index_of "${rid}" ${SUPPLIED_IDS[@]+"${SUPPLIED_IDS[@]}"} >/dev/null; then
    violation "${rid}: no flag supplied (evade challenge in scope for '${CHALLENGE_ID}')"
  fi
done

if [[ "${RC}" -ne 0 ]]; then
  printf 'validate-flags-file.sh: %s rejected for challenge-id %s — nothing was deployed\n' "${FLAGS_FILE}" "${CHALLENGE_ID}" >&2
  exit 1
fi

i=0
while [[ "${i}" -lt ${#SUPPLIED_IDS[@]} ]]; do
  printf '%s\t%s\n' "${SUPPLIED_IDS[${i}]}" "${SUPPLIED_VALUES[${i}]}"
  i=$((i + 1))
done
