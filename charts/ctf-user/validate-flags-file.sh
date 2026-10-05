#!/usr/bin/env bash
# Validate a per-event flags file before deploy-user.sh hands it to helm.
#
# This is the planting-side EARLY CHECK for the same file the scoreboard reads
# as FLAGS_FILE ({flags: {<challengeId>: FALCO{...}}}). The scoreboard
# (internal/catalog/flags.go) is the authority on what is scored; this script
# exists so a bad file is refused before anything touches a cluster. Where the
# two disagree, the Go side is right and this script is what gets fixed. The
# shared cases in internal/catalog/testdata/flags-parity are run against both
# (scripts/check-flags-file-validation.sh / flags_test.go).
#
# Usage:
#   validate-flags-file.sh <flags-file> <challenges-dir> <challenge-id> [<scenarios-dir>]
#
# <challenge-id> is what deploy-user.sh was given: `all`, a single `<NN-slug>`,
# or `scenario:<name>` (<scenarios-dir> is then required).
#
# Accepted file shape (deliberately narrower than YAML — anything else is
# "line N: malformed entry"): one top-level `flags:` line, then one entry per
# line, all at the same space indentation:
#     <challengeId>: <value>        value may be wrapped in '...' or "..."
# Blank lines and whole-line `#` comments (indented with spaces only) are
# skipped anywhere. NOTHING else may appear in the file: no other top-level
# key, no inline comments, flow/block/multi-line values, anchors, or `---`
# document markers. Any line — comments included — that contains a control
# character (TAB and CR too), NEL / LS / PS (line breaks to a YAML parser), a
# BOM, or bytes that are not well-formed UTF-8 is refused; other non-ASCII
# text in comments is fine.
#
# Rules (every violation is reported; any violation => exit 1):
#   - every line of the `flags:` block is a well-formed entry
#   - no challengeId appears twice
#   - every entry names an evade challenge that exists in <challenges-dir>
#     (challenges/<id>/falco-rule.yaml `type: evade`)
#   - every value matches FALCO{...} (only A-Za-z0-9_- inside the braces; the only characters that
#     reach helm --set-string and the scoreboard unchanged)
#   - no value equals the repository default of ANY challenge
#     (falco-rule.yaml `expectedFlag`, or this chart's values.yaml
#     `challenge.flags`)
#   - no two entries carry the same value
#   - every evade challenge IN SCOPE for this deploy has an entry:
#       all              -> every evade challenge in <challenges-dir>
#       scenario:<name>  -> the evade challenges listed in
#                           <scenarios-dir>/<name>/scenario.yaml `challenges:`
#       <NN-slug>        -> that challenge, if it is an evade challenge
#     (the same scoping templates/ctf-flags-secret.yaml uses to decide which
#     flags reach the `plant` initContainer). Entries for evade challenges
#     outside the scope are validated too, so one event file works for every
#     mode.
#
# Output: on success, one `<challengeId><TAB><flag>` line on stdout for each
# entry IN SCOPE, and nothing else. Out-of-scope entries are not emitted, so
# they never become helm arguments or part of the release record.
# Diagnostics go to stderr and contain only line numbers and challenge ids
# that passed the id check — never a flag value, and never the text of a line
# that was not understood.
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

FLAG_RE='^FALCO\{[A-Za-z0-9_-]+\}$'

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
# NUL bytes cannot be screened reliably inside awk (some implementations end
# the record at the first NUL), so they are refused up front.
if ! LC_ALL=C tr -d '\000' < "${FLAGS_FILE}" | cmp -s - "${FLAGS_FILE}"; then
  printf '  ✗ %s\n' "the file contains NUL bytes" >&2
  printf 'validate-flags-file.sh: %s rejected for challenge-id %s — nothing was deployed\n' "${FLAGS_FILE}" "${CHALLENGE_ID}" >&2
  exit 1
fi

# The awk below classifies every line of the `flags:` block and prints either
#   P <TAB> <line-no> <TAB> <id> <TAB> <value>     a well-formed entry
#   E <TAB> <line-no>                              anything else
# An E record carries NO text from the file: a line this reader did not
# understand may hold a flag value in an unexpected position.
SUPPLIED_IDS=()
SUPPLIED_VALUES=()
MALFORMED_LINES=()
while IFS=$'\t' read -r kind lineno fid fval; do
  case "${kind}" in
    P)
      SUPPLIED_IDS+=("${fid}")
      SUPPLIED_VALUES+=("${fval}")
      ;;
    E)
      MALFORMED_LINES+=("${lineno}")
      ;;
  esac
done < <(LC_ALL=C awk '
  # LC_ALL=C: every pattern below is about BYTES, so the result does not
  # depend on the awk implementation or the caller locale (checked with BWK
  # awk, mawk, gawk and busybox awk).
  #
  # Screen each line before looking at its shape. A YAML parser treats more
  # than "\n" as a line break (CR, NEL U+0085, LS U+2028, PS U+2029) and
  # refuses control characters and invalid UTF-8 outright, even inside a
  # comment. A line carrying any of those is refused here too, so that a
  # comment this reader skips can never be a line break, an extra entry or a
  # parse error for the scoreboard. Other non-ASCII text (in comments) is
  # fine. In order: C0 controls incl. TAB and CR, DEL; C1 controls incl.
  # NEL; LS / PS; BOM / U+FFFE / U+FFFF; anything that is not well-formed
  # UTF-8.
  /[\001-\037\177]/ || /\302[\200-\237]/ ||
  index($0, "\342\200\250") || index($0, "\342\200\251") ||
  index($0, "\357\273\277") || index($0, "\357\277\276") || index($0, "\357\277\277") ||
  $0 !~ /^([\040-\176]|[\302-\337][\200-\277]|\340[\240-\277][\200-\277]|[\341-\354\356\357][\200-\277][\200-\277]|\355[\200-\237][\200-\277]|\360[\220-\277][\200-\277][\200-\277]|[\361-\363][\200-\277][\200-\277][\200-\277]|\364[\200-\217][\200-\277][\200-\277])*$/ {
    printf "E\t%d\n", NR; next
  }
  # The whole file is: blank lines, whole-line comments, ONE `flags:` line,
  # and entries after it. Every other line — before, inside or after the
  # block, at any indentation — is an E record. Nothing is skipped as
  # "some other key": text this reader does not model could change what a
  # YAML parser takes the flags to be.
  # Blank / comment lines: spaces only before the `#` (never [[:space:]]).
  /^ *(#.*)?$/ { next }
  /^flags:/ {
    rest = substr($0, 7)
    if (seen || rest !~ /^ *(#.*)?$/) { printf "E\t%d\n", NR }
    seen = 1; indent = -1
    next
  }
  !seen { printf "E\t%d\n", NR; next }
  /^ +[A-Za-z0-9._-]+: +[^ ]/ {
    match($0, /^ +/)
    if (indent < 0) indent = RLENGTH
    if (RLENGTH != indent) { printf "E\t%d\n", NR; next }
    line = substr($0, RLENGTH + 1)
    idx = index(line, ":"); k = substr(line, 1, idx - 1); v = substr(line, idx + 1)
    gsub(/^ +| +$/, "", v)
    n = length(v)
    if (n >= 2 && ((substr(v, 1, 1) == "\"" && substr(v, n, 1) == "\"") || (substr(v, 1, 1) == "\047" && substr(v, n, 1) == "\047"))) {
      v = substr(v, 2, n - 2)
    }
    if (v == "") { printf "E\t%d\n", NR; next }
    printf "P\t%d\t%s\t%s\n", NR, k, v
    next
  }
  { printf "E\t%d\n", NR }' "${FLAGS_FILE}")

RC=0
violation() {
  printf '  ✗ %s\n' "$1" >&2
  RC=1
}

for lineno in ${MALFORMED_LINES[@]+"${MALFORMED_LINES[@]}"}; do
  violation "line ${lineno}: malformed entry (the file may hold only one top-level 'flags:' key, '<challengeId>: FALCO{...}' entries under it, blank lines and # comments)"
done

if [[ ${#SUPPLIED_IDS[@]} -eq 0 && ${#MALFORMED_LINES[@]} -eq 0 ]]; then
  violation "no flags found under a top-level 'flags:' key"
fi

i=0
SEEN_IDS=()
SEEN_VALUES=()
SEEN_VALUE_IDS=()
while [[ "${i}" -lt ${#SUPPLIED_IDS[@]} ]]; do
  fid="${SUPPLIED_IDS[${i}]}"
  fval="${SUPPLIED_VALUES[${i}]}"
  i=$((i + 1))

  if index_of "${fid}" ${SEEN_IDS[@]+"${SEEN_IDS[@]}"} >/dev/null; then
    violation "${fid}: listed more than once"
    continue
  fi
  SEEN_IDS+=("${fid}")

  if ! index_of "${fid}" ${EVADE_IDS[@]+"${EVADE_IDS[@]}"} >/dev/null; then
    violation "${fid}: not an evade challenge in ${CHALLENGES_DIR} (only evade challenges have flags)"
    continue
  fi
  if [[ ! "${fval}" =~ ${FLAG_RE} ]]; then
    violation "${fid}: value must match FALCO{...} (only A-Za-z0-9_- inside the braces)"
    continue
  fi
  # A value equal to ANY challenge default (not just this challenge's) is a
  # value that is public in this repository.
  if didx="$(index_of "${fval}" ${EVADE_DEFAULTS[@]+"${EVADE_DEFAULTS[@]}"})"; then
    violation "${fid}: value is the same as a repository default (of ${EVADE_IDS[${didx}]}); supply a per-event value"
    continue
  fi
  if didx="$(index_of "${fval}" ${CHART_DEFAULTS[@]+"${CHART_DEFAULTS[@]}"})"; then
    violation "${fid}: value is the same as a chart default (of ${CHART_IDS[${didx}]}); supply a per-event value"
    continue
  fi
  if didx="$(index_of "${fval}" ${SEEN_VALUES[@]+"${SEEN_VALUES[@]}"})"; then
    violation "${fid}: value is the same as the one for ${SEEN_VALUE_IDS[${didx}]}; every challenge needs its own value"
    continue
  fi
  SEEN_VALUES+=("${fval}")
  SEEN_VALUE_IDS+=("${fid}")
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

# Only in-scope entries leave this script.
i=0
while [[ "${i}" -lt ${#SUPPLIED_IDS[@]} ]]; do
  if index_of "${SUPPLIED_IDS[${i}]}" ${REQUIRED_IDS[@]+"${REQUIRED_IDS[@]}"} >/dev/null; then
    printf '%s\t%s\n' "${SUPPLIED_IDS[${i}]}" "${SUPPLIED_VALUES[${i}]}"
  fi
  i=$((i + 1))
done
