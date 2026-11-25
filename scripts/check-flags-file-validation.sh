#!/usr/bin/env bash
# Tests for the planting-side flags-file validation
# (charts/ctf-user/validate-flags-file.sh, called by deploy-user.sh
# --flags-file). No cluster, no helm, no docker: part B runs deploy-user.sh
# with stub `helm` / `kubectl` on PATH that only record their invocations.
#
#   A. validate-flags-file.sh directly, against this repo's real challenges/
#      and scenarios/ (plus one fixture challenges dir), for every deploy
#      mode: complete file accepted; missing / default-valued / reused /
#      unknown / malformed / duplicate entries rejected; only in-scope
#      entries are emitted.
#   P. the shared cases in internal/catalog/testdata/flags-parity (also run
#      by internal/catalog/flags_test.go against the scoreboard's reader):
#      this side must match the `shell` column of cases.tsv, every accepted
#      input must be read as exactly expected.tsv, and no rejection may print
#      file content.
#   B. deploy-user.sh end to end: a rejected file exits non-zero BEFORE any
#      helm/kubectl call and shows the validator's reason; a complete file
#      reaches `helm upgrade` carrying exactly the in-scope id=value pairs;
#      no --flags-file behaves as before (no validation, no challenge.flags
#      override). A scope of the real tree that holds investigate challenges
#      (ADR-0056 D11: all, scenario ir-nimbus-desk, a single investigate
#      challenge) is an event deploy only with the event's evidence too:
#      --flags-file alone (or with half of the evidence arguments) exits 2 with
#      no helm/kubectl call; with a synthetic event bundle built here it reaches
#      `helm upgrade` by the event path (never the practice one).
#
# Part B's stub helm / kubectl, the runner and the "reached `helm upgrade`" status
# are scripts/lib/deploy-user-harness.sh (app#521: this script held the third copy
# of them), shared with scripts/check-seat-grammar.sh and check-deploy-user-ids.sh.
#
# Every expectation is on an exit status or an exact string/count, never on
# "some output appeared". Flag values here are synthetic FALCO{dev-...}
# strings (public repo; scripts/check-flags.sh allows only that form).
#
# Usage: ./scripts/check-flags-file-validation.sh   (make check-flags; CI flag-guard)
set -euo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
# shellcheck source=lib/casetable.sh
source "${REPO_ROOT}/scripts/lib/casetable.sh"
# shellcheck source=lib/deploy-user-harness.sh
source "${REPO_ROOT}/scripts/lib/deploy-user-harness.sh"
# The digest of an evidence bundle (ADR-0056 D9), for the synthetic event bundles of part B.
# shellcheck source=../charts/ctf-user/evidence-bundle.sh
source "${REPO_ROOT}/charts/ctf-user/evidence-bundle.sh"

VALIDATE="${REPO_ROOT}/charts/ctf-user/validate-flags-file.sh"
DEPLOY="${REPO_ROOT}/charts/ctf-user/deploy-user.sh"
CHALLENGES="${REPO_ROOT}/challenges"
SCENARIOS="${REPO_ROOT}/scenarios"

ct_init "${REPO_ROOT}"

CASES=0

# Synthetic per-event values (distinct from every default).
V03='FALCO{dev-rotated-for-test-03}'
V05='FALCO{dev-rotated-for-test-05}'
V10='FALCO{dev-rotated-for-test-10}'

# Repository default of a real challenge, read from its falco-rule.yaml (not
# hardcoded, so this test follows the repo if a placeholder is renamed).
repo_default() {
  sed -n 's/^expectedFlag:[[:space:]]*//p' "${CHALLENGES}/$1/falco-rule.yaml"
}
D03="$(repo_default 03-stealth-read)"
D10="$(repo_default 10-final-exfil)"
for d in "${D03}" "${D10}"; do
  case "${d}" in
    FALCO\{*\}) ;;
    *) echo "FAIL: could not read a repository default from challenges/*/falco-rule.yaml" >&2; exit 1 ;;
  esac
done

# Investigate challenges (ADR-0056) of the real tree: falco-rule.yaml `type: investigate`
# (the pattern of challenges/gen-values.sh's is_investigate_file). Read here, NOT through
# deploy-user.sh's scope reader (evidence_scope_cids over the generated values), so a
# values file that lost its `evidence: true` marks turns the event cases of part B red
# instead of being followed. An investigate challenge has no flag (it is scored by its
# answers table): validate-flags-file.sh never requires one and refuses an entry for one.
INVESTIGATE_TYPE_RE="^type:[[:space:]]*[\"']?investigate[\"']?[[:space:]]*(#.*)?\$"
IR_SCENARIO='ir-nimbus-desk'
# investigate_among <id>...: the investigate challenges among the ids, one per line, in order
investigate_among() {
  local id
  for id in "$@"; do
    if [[ -f "${CHALLENGES}/${id}/falco-rule.yaml" ]] && grep -qE -- "${INVESTIGATE_TYPE_RE}" "${CHALLENGES}/${id}/falco-rule.yaml"; then
      printf '%s\n' "${id}"
    fi
  done
}
# scenario_challenges <name>: the `challenges:` list of scenarios/<name>/scenario.yaml (the
# same reading as validate-flags-file.sh and gen-values.sh's scenario_challenge_ids)
scenario_challenges() {
  awk '
    /^challenges:/ { inblock=1; next }
    inblock && /^[^[:space:]]/ { inblock=0 }
    inblock && /^[[:space:]]*-[[:space:]]*/ {
      line=$0
      sub(/^[[:space:]]*-[[:space:]]*/, "", line)
      sub(/[[:space:]]*#.*$/, "", line)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
      if (line != "") print line
    }' "${SCENARIOS}/$1/scenario.yaml"
}
ALL_IDS=()
for d in "${CHALLENGES}"/*/; do
  d="${d%/}"
  ALL_IDS+=("${d##*/}")
done
IR_IDS=()
while IFS= read -r id; do
  if [[ -n "${id}" ]]; then IR_IDS+=("${id}"); fi
done < <(scenario_challenges "${IR_SCENARIO}")
ALL_INVESTIGATE="$(investigate_among "${ALL_IDS[@]}")"
IR_INVESTIGATE="$(investigate_among ${IR_IDS[@]+"${IR_IDS[@]}"})"
if [[ -z "${ALL_INVESTIGATE}" || -z "${IR_INVESTIGATE}" ]]; then
  echo "FAIL: no investigate challenge read from challenges/*/falco-rule.yaml (all: [$(printf '%s' "${ALL_INVESTIGATE}" | tr '\n' ' ')], scenario ${IR_SCENARIO}: [$(printf '%s' "${IR_INVESTIGATE}" | tr '\n' ' ')]); the event cases of part B expect the real tree to hold some (ADR-0056)" >&2
  exit 1
fi
FIRST_INVESTIGATE="${ALL_INVESTIGATE%%$'\n'*}"

# leaks_value <file...> -> 0 if any file contains one of the flag values this
# test feeds in (messages must name challenge ids only).
leaks_value() {
  local v
  for v in "${V03}" "${V05}" "${V10}" "${D03}" "${D10}" 'not-a-flag' 'FALCO{dev-fixture-default}' 'dev-rotated' 'FALCO{dev-'; do
    if grep -qF -- "${v}" "$@"; then
      return 0
    fi
  done
  return 1
}

# write_flags <name> <id> <value> [<id> <value> ...] -> path of a flags file
write_flags() {
  local path="${WORK}/$1.yaml"
  shift
  {
    echo "flags:"
    while [[ $# -ge 2 ]]; do
      printf '  %s: %s\n' "$1" "$2"
      shift 2
    done
  } > "${path}"
  printf '%s\n' "${path}"
}

FULL="$(write_flags full 03-stealth-read "${V03}" 05-silent-search "${V05}" 10-final-exfil "${V10}")"
NO05="$(write_flags no05 03-stealth-read "${V03}" 10-final-exfil "${V10}")"
NO10="$(write_flags no10 03-stealth-read "${V03}" 05-silent-search "${V05}")"
ONLY03="$(write_flags only03 03-stealth-read "${V03}")"
ONLY05="$(write_flags only05 05-silent-search "${V05}")"
NO03="$(write_flags no03 05-silent-search "${V05}" 10-final-exfil "${V10}")"
OUTSCOPE_DEFAULT10="$(write_flags outscope-default10 03-stealth-read "${V03}" 10-final-exfil "${D10}")"
OTHERDEFAULT03="$(write_flags otherdefault03 03-stealth-read "${D10}" 05-silent-search "${V05}" 10-final-exfil "${V10}")"
REUSED="$(write_flags reused 03-stealth-read "${V03}" 05-silent-search "${V03}" 10-final-exfil "${V10}")"
COMMA="$(write_flags comma 03-stealth-read 'FALCO{dev-rotated,for-test-03}' 05-silent-search "${V05}" 10-final-exfil "${V10}")"
DEFAULT03="$(write_flags default03 03-stealth-read "${D03}" 05-silent-search "${V05}" 10-final-exfil "${V10}")"
UNKNOWN="$(write_flags unknown 03-stealth-read "${V03}" 05-silent-search "${V05}" 10-final-exfil "${V10}" 99-nope 'FALCO{dev-rotated-for-test-99}')"
TRIGGER="$(write_flags trigger 03-stealth-read "${V03}" 05-silent-search "${V05}" 10-final-exfil "${V10}" 01-initial-recon 'FALCO{dev-rotated-for-test-01}')"
INVESTIGATE_ENTRY="$(write_flags investigate-entry 03-stealth-read "${V03}" 05-silent-search "${V05}" 10-final-exfil "${V10}" "${FIRST_INVESTIGATE}" 'FALCO{dev-rotated-for-test-investigate}')"
MALFORMED="$(write_flags malformed 03-stealth-read not-a-flag 05-silent-search "${V05}" 10-final-exfil "${V10}")"
DUPLICATE="$(write_flags duplicate 03-stealth-read "${V03}" 03-stealth-read "${V03}" 05-silent-search "${V05}" 10-final-exfil "${V10}")"
EMPTY="${WORK}/empty.yaml"
echo "flags: {}" > "${EMPTY}"

# expect_validate <want: accept|reject> <label> <stderr-must-contain or ''> <validator args...>
expect_validate() {
  local want="$1" label="$2" needle="$3"
  shift 3
  CASES=$((CASES + 1))
  local out="${WORK}/out" err="${WORK}/err" status
  set +e
  "${VALIDATE}" "$@" >"${out}" 2>"${err}"
  status=$?
  set -e
  if [[ "${want}" == "accept" ]]; then
    if [[ "${status}" -ne 0 ]]; then
      fail "${label}: expected exit 0, got ${status}: $(tr '\n' ' ' < "${err}")"
      return
    fi
    pass "${label}"
    return
  fi
  if [[ "${status}" -ne 1 ]]; then
    fail "${label}: expected exit 1 (rejected), got ${status}: $(tr '\n' ' ' < "${err}")"
    return
  fi
  if [[ -s "${out}" ]]; then
    fail "${label}: rejected, but still wrote pairs to stdout"
    return
  fi
  if [[ -n "${needle}" ]] && ! grep -qF -- "${needle}" "${err}"; then
    fail "${label}: stderr does not mention '${needle}': $(tr '\n' ' ' < "${err}")"
    return
  fi
  if leaks_value "${err}"; then
    fail "${label}: a flag value was printed in the error output"
    return
  fi
  pass "${label}"
}

echo "==> A. validate-flags-file.sh"
expect_validate accept "all: complete file" '' "${FULL}" "${CHALLENGES}" all
expect_validate reject "all: one evade flag missing" '05-silent-search: no flag supplied' "${NO05}" "${CHALLENGES}" all
expect_validate reject "all: only one of three supplied" '10-final-exfil: no flag supplied' "${ONLY03}" "${CHALLENGES}" all
expect_validate reject "all: value equals the repository default" '03-stealth-read: value is the same as a repository default (of 03-stealth-read)' "${DEFAULT03}" "${CHALLENGES}" all
expect_validate reject "all: value equals ANOTHER challenge's repository default" '03-stealth-read: value is the same as a repository default (of 10-final-exfil)' "${OTHERDEFAULT03}" "${CHALLENGES}" all
expect_validate reject "all: two challenges share one value" '05-silent-search: value is the same as the one for 03-stealth-read' "${REUSED}" "${CHALLENGES}" all
expect_validate reject "all: comma in a value" '03-stealth-read: value must match' "${COMMA}" "${CHALLENGES}" all
expect_validate reject "all: unknown challenge id" '99-nope: not an evade challenge' "${UNKNOWN}" "${CHALLENGES}" all
expect_validate reject "all: entry for a trigger challenge" '01-initial-recon: not an evade challenge' "${TRIGGER}" "${CHALLENGES}" all
expect_validate reject "all: malformed value" '03-stealth-read: value must match' "${MALFORMED}" "${CHALLENGES}" all
expect_validate reject "all: duplicate id" '03-stealth-read: listed more than once' "${DUPLICATE}" "${CHALLENGES}" all
expect_validate reject "all: empty flags map" 'line 1: malformed entry' "${EMPTY}" "${CHALLENGES}" all

expect_validate accept "scenario nimbusbreach-full: complete file (03/05/10)" '' "${FULL}" "${CHALLENGES}" scenario:nimbusbreach-full "${SCENARIOS}"
expect_validate reject "scenario nimbusbreach-full: one evade flag missing" '10-final-exfil: no flag supplied' "${NO10}" "${CHALLENGES}" scenario:nimbusbreach-full "${SCENARIOS}"
expect_validate accept "scenario nimbusbreach-with-tutorial: complete file" '' "${FULL}" "${CHALLENGES}" scenario:nimbusbreach-with-tutorial "${SCENARIOS}"
expect_validate accept "scenario tutorial-intro: only its own evade flag" '' "${ONLY03}" "${CHALLENGES}" scenario:tutorial-intro "${SCENARIOS}"
expect_validate accept "scenario tutorial-intro: full event file reused" '' "${FULL}" "${CHALLENGES}" scenario:tutorial-intro "${SCENARIOS}"
expect_validate reject "scenario tutorial-intro: its evade flag missing" '03-stealth-read: no flag supplied' "${NO03}" "${CHALLENGES}" scenario:tutorial-intro "${SCENARIOS}"
expect_validate reject "scenario tutorial-intro: out-of-scope entry equals default" '10-final-exfil: value is the same as a repository default' "${OUTSCOPE_DEFAULT10}" "${CHALLENGES}" scenario:tutorial-intro "${SCENARIOS}"
# onboarding (ADR-0055 S2b-2) holds no evade challenge: no flag is required, and the full
# event file's entries are out of scope (checked, not applied).
expect_validate accept "scenario onboarding: no evade challenge, nothing required (full event file)" '' "${FULL}" "${CHALLENGES}" scenario:onboarding "${SCENARIOS}"
# ir-nimbus-desk (ADR-0056) holds investigate challenges only: they have no flag, so nothing
# is required here either; an entry for one is refused like any id that is not an evade
# challenge (the flags file has no line for 50-/51-*; their evidence is part B's business).
expect_validate accept "scenario ${IR_SCENARIO}: investigate challenges only, nothing required (full event file)" '' "${FULL}" "${CHALLENGES}" "scenario:${IR_SCENARIO}" "${SCENARIOS}"
expect_validate reject "all: entry for an investigate challenge" "${FIRST_INVESTIGATE}: not an evade challenge" "${INVESTIGATE_ENTRY}" "${CHALLENGES}" all

expect_validate accept "single evade challenge: its own flag only" '' "${ONLY03}" "${CHALLENGES}" 03-stealth-read
expect_validate accept "single evade challenge: full event file reused" '' "${FULL}" "${CHALLENGES}" 03-stealth-read
expect_validate reject "single evade challenge: its flag missing" '03-stealth-read: no flag supplied' "${ONLY05}" "${CHALLENGES}" 03-stealth-read
expect_validate accept "single trigger challenge: full event file, nothing required" '' "${FULL}" "${CHALLENGES}" 01-initial-recon

# Unusable input is exit 2, not a silent pass.
CASES=$((CASES + 1))
set +e
"${VALIDATE}" "${WORK}/does-not-exist.yaml" "${CHALLENGES}" all >/dev/null 2>&1
status=$?
set -e
if [[ "${status}" -eq 2 ]]; then pass "missing flags file: exit 2"; else fail "missing flags file: expected exit 2, got ${status}"; fi

CASES=$((CASES + 1))
set +e
"${VALIDATE}" "${FULL}" "${CHALLENGES}" scenario:no-such-scenario "${SCENARIOS}" >/dev/null 2>&1
status=$?
set -e
if [[ "${status}" -eq 2 ]]; then pass "unknown scenario: exit 2"; else fail "unknown scenario: expected exit 2, got ${status}"; fi

# The chart-default rule on its own: a fixture challenges dir whose repository
# default differs from charts/ctf-user/values.yaml, so only the chart-default
# comparison can reject the chart's value.
FIXTURE="${WORK}/fixture-challenges"
mkdir -p "${FIXTURE}/03-stealth-read"
cat > "${FIXTURE}/03-stealth-read/falco-rule.yaml" <<'YAML'
challengeId: 03-stealth-read
type: evade
expectedFlag: FALCO{dev-fixture-default}
YAML
expect_validate reject "chart default value (fixture catalog)" '03-stealth-read: value is the same as a chart default' "$(write_flags chartdefault 03-stealth-read "${D03}")" "${FIXTURE}" all
expect_validate reject "repository default value (fixture catalog)" '03-stealth-read: value is the same as a repository default' "$(write_flags repodefault 03-stealth-read 'FALCO{dev-fixture-default}')" "${FIXTURE}" all
expect_validate accept "per-event value (fixture catalog)" '' "${ONLY03}" "${FIXTURE}" all

# On success stdout is exactly the IN-SCOPE pairs — nothing else from the
# event file leaves the validator.
# expect_stdout <label> <expected stdout> <validator args...>
expect_stdout() {
  local label="$1" want="$2" got
  shift 2
  CASES=$((CASES + 1))
  if ! got="$("${VALIDATE}" "$@" 2>/dev/null)"; then
    fail "${label}: validator rejected the file"
    return
  fi
  if [[ "${got}" == "${want}" ]]; then pass "${label}"; else fail "${label}: unexpected stdout"; fi
}
expect_stdout "all: stdout is all three pairs" \
  "$(printf '03-stealth-read\t%s\n05-silent-search\t%s\n10-final-exfil\t%s' "${V03}" "${V05}" "${V10}")" \
  "${FULL}" "${CHALLENGES}" all
expect_stdout "scenario tutorial-intro, full event file: stdout is its one pair only" \
  "$(printf '03-stealth-read\t%s' "${V03}")" \
  "${FULL}" "${CHALLENGES}" scenario:tutorial-intro "${SCENARIOS}"
expect_stdout "single evade challenge, full event file: stdout is its one pair only" \
  "$(printf '05-silent-search\t%s' "${V05}")" \
  "${FULL}" "${CHALLENGES}" 05-silent-search
expect_stdout "single trigger challenge, full event file: stdout is empty" "" \
  "${FULL}" "${CHALLENGES}" 01-initial-recon
expect_stdout "scenario onboarding, full event file: stdout is empty" "" \
  "${FULL}" "${CHALLENGES}" scenario:onboarding "${SCENARIOS}"
expect_stdout "scenario ${IR_SCENARIO}, full event file: stdout is empty" "" \
  "${FULL}" "${CHALLENGES}" "scenario:${IR_SCENARIO}" "${SCENARIOS}"

echo "==> P. shared parity cases (internal/catalog/testdata/flags-parity)"
PARITY="${REPO_ROOT}/internal/catalog/testdata/flags-parity"
PARITY_EXPECTED="$(cat "${PARITY}/expected.tsv")"
PARITY_CASES=0
while IFS=$'\t' read -r pfile pgo pshell pnote; do
  case "${pfile}" in ''|'#'*) continue ;; esac
  PARITY_CASES=$((PARITY_CASES + 1))
  CASES=$((CASES + 1))
  label="parity ${pfile} (${pnote}): go=${pgo} shell=${pshell}"
  if [[ "${pgo}" == "reject" && "${pshell}" == "accept" ]]; then
    fail "${label}: the planting-side check must never accept what the scoreboard rejects"
    continue
  fi
  set +e
  "${VALIDATE}" "${PARITY}/${pfile}" "${CHALLENGES}" all >"${WORK}/out" 2>"${WORK}/err"
  status=$?
  set -e
  case "${pshell}:${status}" in
    accept:0)
      if [[ "$(cat "${WORK}/out")" == "${PARITY_EXPECTED}" ]]; then
        pass "${label}"
      else
        fail "${label}: accepted, but read differently from expected.tsv"
      fi
      ;;
    reject:1)
      if grep -qE 'FALCO\{dev-|parity-|dev-decoy' "${WORK}/err" "${WORK}/out"; then
        fail "${label}: rejected, but file content was printed"
      elif grep -qiE 'echo-probe|echo_probe|echo\.probe|a1b2c3d4e5f6a7b8c9d0e1f2|eeeeeeeeeeeeeeeeeeee' "${WORK}/err" "${WORK}/out"; then
        fail "${label}: rejected, but a key outside the challenge-id grammar was echoed (app#437)"
      elif [[ -s "${WORK}/out" ]]; then
        fail "${label}: rejected, but still wrote pairs to stdout"
      else
        pass "${label}"
      fi
      ;;
    *)
      fail "${label}: validator exit ${status}: $(tr '\n' ' ' < "${WORK}/err" | cut -c1-200)"
      ;;
  esac
done < "${PARITY}/cases.tsv"
if [[ "${PARITY_CASES}" -lt 79 ]]; then
  fail "only ${PARITY_CASES} parity case(s) read from ${PARITY}/cases.tsv"
fi

# NUL byte inside a comment: both readers refuse it. Generated here (and in
# flags_test.go) instead of living in the shared testdata, because a tracked
# file containing NUL is "binary" to git grep and scripts/check-flags.sh
# could not scan it.
NULFILE="${WORK}/nul.yaml"
printf 'flags:\n  # a\000b\n  03-stealth-read: %s\n  05-silent-search: %s\n  10-final-exfil: %s\n' "${V03}" "${V05}" "${V10}" > "${NULFILE}"
expect_validate reject "all: NUL byte inside a comment" 'the file contains NUL bytes' "${NULFILE}" "${CHALLENGES}" all

echo "==> B. deploy-user.sh --flags-file (stub helm/kubectl)"
ct_init_stubs

# run_deploy <deploy-user.sh args...> -> sets RUN_STATUS, refreshes CT_CALLS
run_deploy() {
  ct_run "${DEPLOY}" "$@"
}

# expect_deploy_rejected <label> <stderr-must-contain> <deploy-user.sh args...>
expect_deploy_rejected() {
  deploy_rejected '' "$@"
}
# expect_deploy_rejected_exit <exit status> <label> <stderr-must-contain> <deploy-user.sh args...>:
# the same, and the exit status is exactly the one given
expect_deploy_rejected_exit() {
  deploy_rejected "$@"
}
# deploy_rejected <exit status or ''> <label> <stderr-must-contain> <deploy-user.sh args...>
deploy_rejected() {
  local want="$1" label="$2" needle="$3"
  shift 3
  CASES=$((CASES + 1))
  run_deploy "$@"
  if [[ "${RUN_STATUS}" -eq 0 || "${RUN_STATUS}" -eq "${CT_UPGRADE_EXIT}" ]]; then
    fail "${label}: expected a non-zero exit before helm upgrade, got ${RUN_STATUS}"
    return
  fi
  if [[ -n "${want}" && "${RUN_STATUS}" -ne "${want}" ]]; then
    fail "${label}: expected exit ${want}, got ${RUN_STATUS}: $(tr '\n' ' ' < "${CT_RUN_ERR}" | cut -c1-200)"
    return
  fi
  if [[ -s "${CT_CALLS}" ]]; then
    fail "${label}: helm/kubectl was called although the flags file was rejected: $(cut -d' ' -f1-4 "${CT_CALLS}" | tr '\n' ';' | cut -c1-200)"
    return
  fi
  if ! grep -qF -- "${needle}" "${CT_RUN_ERR}"; then
    fail "${label}: stderr does not carry the reason '${needle}'"
    return
  fi
  if leaks_value "${CT_RUN_OUT}" "${CT_RUN_ERR}"; then
    fail "${label}: a flag value was printed in the output"
    return
  fi
  pass "${label} (exit ${RUN_STATUS}, no helm/kubectl call)"
}

# expect_deploy_reaches_helm <label> <expected id=value pairs, one per line, '' for none> <deploy-user.sh args...>
# The `helm upgrade` argv must carry EXACTLY these challenge.flags overrides:
# each expected pair verbatim, and no other challenge.flags argument.
expect_deploy_reaches_helm() {
  local label="$1" want_pairs="$2"
  shift 2
  CASES=$((CASES + 1))
  run_deploy "$@"
  reached_helm_with_flags "${label}" "${want_pairs}" || return 0
  pass "${label} (helm upgrade reached, ${GOT_FLAGS} flag override(s), values verbatim)"
}

# reached_helm_with_flags <label> <expected id=value pairs>: after run_deploy, rc 0 when
# `helm upgrade` was reached carrying exactly these challenge.flags overrides (fail and rc 1
# otherwise). Sets UPGRADE_LINE and GOT_FLAGS.
reached_helm_with_flags() {
  local label="$1" want_pairs="$2" want_flags=0 pair
  UPGRADE_LINE=""
  GOT_FLAGS=0
  if ! ct_check_reached_upgrade "${label}"; then
    fail "${label}: did not reach helm upgrade"
    return 1
  fi
  UPGRADE_LINE="$(ct_upgrade_call)"
  if [[ -z "${UPGRADE_LINE}" ]]; then
    fail "${label}: exit ${CT_UPGRADE_EXIT} but no 'helm upgrade' call was recorded"
    return 1
  fi
  while IFS= read -r pair; do
    [[ -z "${pair}" ]] && continue
    want_flags=$((want_flags + 1))
    case " ${UPGRADE_LINE} " in
      *" --set-string challenge.flags.${pair} "*) ;;
      *)
        fail "${label}: helm upgrade does not carry the expected override for ${pair%%=*}"
        return 1
        ;;
    esac
  done <<< "${want_pairs}"
  # grep exits 1 on "no match" (the expected result when no pair is
  # expected); only the count matters here.
  GOT_FLAGS="$(printf '%s\n' "${UPGRADE_LINE}" | { grep -oE 'challenge\.flags\.[^=]+=' || true; } | wc -l | tr -d ' ')"
  if [[ "${GOT_FLAGS}" -ne "${want_flags}" ]]; then
    fail "${label}: helm upgrade carried ${GOT_FLAGS} challenge.flags override(s), expected ${want_flags}"
    return 1
  fi
  return 0
}

# The event's evidence (ADR-0056 D11) for the scopes of the real tree that hold investigate
# challenges. SYNTHETIC and built here: never the tracked practice bundle
# (<cid>/edition/practice/) passed off as an event's. Placeholders only (public repo).
EVENT_RUN_ID='0123456789abcdef0123456789abcdef'
EVENT_EVIDENCE_NAME='event-bundle.txt'
# make_event_evidence <name> <cids, one per line>: <WORK>/<name>-evidence/<cid>/ holding one
# placeholder file EVENT_EVIDENCE_NAME per cid, and <WORK>/<name>-digests.tsv: the v1 header
# with a run id that is not all zeros (all zeros is the practice edition's), then one
# `user1 TAB cid TAB digest` row per cid, the digest by charts/ctf-user/evidence-bundle.sh
# (which scripts/check-evidence-digest.sh holds to the Go case table). Sets EV_DIR / EV_DIGESTS.
make_event_evidence() {
  local cid digest
  EV_DIR="${WORK}/$1-evidence"
  EV_DIGESTS="${WORK}/$1-digests.tsv"
  rm -rf "${EV_DIR}"
  mkdir -p "${EV_DIR}"
  printf '# falco-ctf evidence-digests v1 run=%s\n' "${EVENT_RUN_ID}" > "${EV_DIGESTS}"
  while IFS= read -r cid; do
    if [[ -z "${cid}" ]]; then continue; fi
    mkdir -p "${EV_DIR}/${cid}"
    printf 'synthetic event evidence of %s (test placeholder)\n' "${cid}" > "${EV_DIR}/${cid}/${EVENT_EVIDENCE_NAME}"
    if ! digest="$(evidence_bundle_digest "${EV_DIR}/${cid}")"; then
      echo "FAIL: could not compute the digest of the synthetic bundle ${cid}" >&2
      exit 1
    fi
    printf 'user1\t%s\t%s\n' "${cid}" "${digest}" >> "${EV_DIGESTS}"
  done <<< "$2"
}

# expect_event_deploy_reaches_helm <label> <expected id=value pairs> <investigate cids, one per
# line> <evidence dir> <deploy-user.sh args...>: reached `helm upgrade` with exactly the pairs,
# by the EVENT path: no practice-edition line on stderr, ctf-evidence-<cid> made from the
# evidence dir's file (one --from-file=<name>=<path>), and helm given exactly the one name
# per cid (evidence.challenges.<cid>.names[0]) and no other evidence value.
expect_event_deploy_reaches_helm() {
  local label="$1" want_pairs="$2" cids="$3" evdir cid want_ev=0 got_ev
  evdir="$(cd "$4" && pwd)"
  shift 4
  CASES=$((CASES + 1))
  run_deploy "$@"
  reached_helm_with_flags "${label}" "${want_pairs}" || return 0
  if grep -qF 'deploying the practice edition' "${CT_RUN_ERR}"; then
    fail "${label}: the practice edition's path was taken although the event's evidence was given"
    return 0
  fi
  while IFS= read -r cid; do
    if [[ -z "${cid}" ]]; then continue; fi
    want_ev=$((want_ev + 1))
    if ! grep -qxF -- "kubectl -n ctf-user1 create secret generic ctf-evidence-${cid} --from-file=${EVENT_EVIDENCE_NAME}=${evdir}/${cid}/${EVENT_EVIDENCE_NAME}" "${CT_CALLS}"; then
      fail "${label}: ctf-evidence-${cid} is not made from the event's bundle: $(grep -F "ctf-evidence-${cid} --from-file" "${CT_CALLS}" | cut -c1-200)"
      return 0
    fi
    case " ${UPGRADE_LINE} " in
      *" --set-string evidence.challenges.${cid}.names[0]=${EVENT_EVIDENCE_NAME} "*) ;;
      *)
        fail "${label}: helm upgrade does not carry the event bundle's name for ${cid}"
        return 0
        ;;
    esac
  done <<< "${cids}"
  got_ev="$(printf '%s\n' "${UPGRADE_LINE}" | { grep -oE 'evidence\.challenges\.[^ ]+=' || true; } | wc -l | tr -d ' ')"
  if [[ "${want_ev}" -lt 1 || "${got_ev}" -ne "${want_ev}" ]]; then
    fail "${label}: helm upgrade carried ${got_ev} evidence value(s), expected ${want_ev} (one name per investigate challenge)"
    return 0
  fi
  pass "${label} (helm upgrade reached by the event path, ${GOT_FLAGS} flag override(s), ${got_ev} evidence name(s))"
}

make_event_evidence all "${ALL_INVESTIGATE}"
ALL_EV_DIR="${EV_DIR}"
ALL_EV_DIGESTS="${EV_DIGESTS}"
make_event_evidence "${IR_SCENARIO}" "${IR_INVESTIGATE}"
IR_EV_DIR="${EV_DIR}"
IR_EV_DIGESTS="${EV_DIGESTS}"
make_event_evidence single "${FIRST_INVESTIGATE}"
ONE_EV_DIR="${EV_DIR}"
ONE_EV_DIGESTS="${EV_DIGESTS}"

P03="03-stealth-read=${V03}"
P05="05-silent-search=${V05}"
P10="10-final-exfil=${V10}"
ALL_PAIRS="$(printf '%s\n%s\n%s' "${P03}" "${P05}" "${P10}")"

expect_deploy_rejected "all: one evade flag missing" '05-silent-search: no flag supplied' --flags-file "${NO05}" user1 all
expect_deploy_rejected "all: value equals the repository default" '03-stealth-read: value is the same as a repository default' --flags-file "${DEFAULT03}" user1 all
expect_deploy_rejected "all: two challenges share one value" 'every challenge needs its own value' --flags-file "${REUSED}" user1 all
expect_deploy_rejected "all: comma in a value" '03-stealth-read: value must match' --flags-file "${COMMA}" user1 all
expect_deploy_rejected "scenario nimbusbreach-full: one evade flag missing" '10-final-exfil: no flag supplied' --flags-file "${NO10}" user1 scenario:nimbusbreach-full
expect_deploy_rejected "scenario tutorial-intro: its evade flag missing" '03-stealth-read: no flag supplied' --flags-file "${NO03}" user1 scenario:tutorial-intro
expect_deploy_rejected "single evade challenge: its flag missing" '03-stealth-read: no flag supplied' --flags-file "${ONLY05}" user1 03-stealth-read
expect_deploy_rejected "flags file does not exist" 'flags file not found' --flags-file "${WORK}/does-not-exist.yaml" user1 all
# ADR-0034 D10: --display-name is removed, not ignored. Both spellings, with a
# complete (otherwise valid) flags file so a rejection can only be the flag
# itself; nothing may reach helm/kubectl.
expect_deploy_rejected "--display-name (separate value) is removed" '--display-name was removed' --display-name 'Alice' --flags-file "${FULL}" user1 all
expect_deploy_rejected "--display-name=value is removed" '--display-name was removed' --display-name=Alice --flags-file "${FULL}" user1 scenario:tutorial-intro
# ADR-0056 D11: a scope of the real tree with investigate challenges (all, scenario
# ir-nimbus-desk, a single investigate challenge) is an event deploy (--flags-file) only with
# BOTH --evidence-dir and --evidence-digests. A complete flags file alone, or with one of the
# two, exits 2 before any helm/kubectl call (and is not the practice edition's path).
expect_deploy_rejected_exit 2 "all: complete file, no evidence arguments (investigate challenges in scope)" 'both are required' --flags-file "${FULL}" user1 all
expect_deploy_rejected_exit 2 "all: complete file and --evidence-dir alone" 'go together' --flags-file "${FULL}" --evidence-dir "${ALL_EV_DIR}" user1 all
expect_deploy_rejected_exit 2 "scenario ${IR_SCENARIO}: flags file, no evidence arguments" 'both are required' --flags-file "${FULL}" user1 "scenario:${IR_SCENARIO}"
expect_deploy_rejected_exit 2 "single investigate challenge: flags file, no evidence arguments" 'both are required' --flags-file "${FULL}" user1 "${FIRST_INVESTIGATE}"

expect_event_deploy_reaches_helm "all: complete file and the event's evidence" "${ALL_PAIRS}" "${ALL_INVESTIGATE}" "${ALL_EV_DIR}" \
  --flags-file "${FULL}" --evidence-dir "${ALL_EV_DIR}" --evidence-digests "${ALL_EV_DIGESTS}" user1 all
expect_event_deploy_reaches_helm "scenario ${IR_SCENARIO}: flags file and the event's evidence (no evade flag in scope)" "" "${IR_INVESTIGATE}" "${IR_EV_DIR}" \
  --flags-file "${FULL}" --evidence-dir "${IR_EV_DIR}" --evidence-digests "${IR_EV_DIGESTS}" user1 "scenario:${IR_SCENARIO}"
expect_event_deploy_reaches_helm "single investigate challenge: flags file and its event evidence (no flag)" "" "${FIRST_INVESTIGATE}" "${ONE_EV_DIR}" \
  --flags-file "${FULL}" --evidence-dir "${ONE_EV_DIR}" --evidence-digests "${ONE_EV_DIGESTS}" user1 "${FIRST_INVESTIGATE}"
expect_deploy_reaches_helm "scenario nimbusbreach-full: complete file" "${ALL_PAIRS}" --flags-file "${FULL}" user1 scenario:nimbusbreach-full
expect_deploy_reaches_helm "scenario tutorial-intro: only its own flag" "${P03}" --flags-file "${ONLY03}" user1 scenario:tutorial-intro
expect_deploy_reaches_helm "scenario tutorial-intro, full event file: only its own flag reaches helm" "${P03}" --flags-file "${FULL}" user1 scenario:tutorial-intro
expect_deploy_reaches_helm "single evade challenge: its own flag" "${P03}" --flags-file "${ONLY03}" user1 03-stealth-read
expect_deploy_reaches_helm "single evade challenge, full event file: only its own flag reaches helm" "${P05}" --flags-file "${FULL}" user1 05-silent-search
expect_deploy_reaches_helm "single trigger challenge, full event file: no flag reaches helm" "" --flags-file "${FULL}" user1 01-initial-recon
# (all with no argument at all is the local default: the investigate challenges in it take
# the practice edition's path, ADR-0056 D11 amendment 9; scripts/check-deploy-user-evidence.sh
# holds that path. Only the absence of a flag override is held here.)
expect_deploy_reaches_helm "no --flags-file (local dev): unchanged, no override" "" user1 all
expect_deploy_reaches_helm "no --flags-file, scenario mode: unchanged, no override" "" user1 scenario:nimbusbreach-full

echo "==> ${CASES} case(s) run"
# A run that executed no cases proves nothing.
if [[ "${CASES}" -lt 142 ]]; then
  echo "FAIL: only ${CASES} case(s) ran — the test list was truncated" >&2
  RC=1
fi
if [[ "${RC}" -ne 0 ]]; then
  echo "FAIL: flags-file validation tests failed" >&2
  exit 1
fi
echo "ok: flags-file validation behaves fail-closed"
