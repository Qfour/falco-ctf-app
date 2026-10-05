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
#      override).
#
# Every expectation is on an exit status or an exact string/count, never on
# "some output appeared". Flag values here are synthetic FALCO{dev-...}
# strings (public repo; scripts/check-flags.sh allows only that form).
#
# Usage: ./scripts/check-flags-file-validation.sh   (make check-flags; CI flag-guard)
set -euo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"

VALIDATE="${REPO_ROOT}/charts/ctf-user/validate-flags-file.sh"
DEPLOY="${REPO_ROOT}/charts/ctf-user/deploy-user.sh"
CHALLENGES="${REPO_ROOT}/challenges"
SCENARIOS="${REPO_ROOT}/scenarios"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

RC=0
CASES=0
fail() { echo "  FAIL: $1" >&2; RC=1; }
pass() { echo "  ok:   $1"; }

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
      if grep -qE 'FALCO\{dev-|parity-' "${WORK}/err" "${WORK}/out"; then
        fail "${label}: rejected, but file content was printed"
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
if [[ "${PARITY_CASES}" -lt 40 ]]; then
  fail "only ${PARITY_CASES} parity case(s) read from ${PARITY}/cases.tsv"
fi

echo "==> B. deploy-user.sh --flags-file (stub helm/kubectl)"
STUB_BIN="${WORK}/bin"
CALLS="${WORK}/calls.log"
mkdir -p "${STUB_BIN}"
# helm stub: `status` -> 1 (no stray release); `upgrade` -> record argv, exit
# 97 so deploy-user.sh (set -e) stops right there with a recognisable status.
cat > "${STUB_BIN}/helm" <<'STUB'
#!/usr/bin/env bash
printf 'helm' >> "${CALLS_LOG}"
printf ' %s' "$@" >> "${CALLS_LOG}"
printf '\n' >> "${CALLS_LOG}"
for a in "$@"; do
  case "${a}" in
    status) exit 1 ;;
    upgrade) exit 97 ;;
  esac
done
exit 0
STUB
cat > "${STUB_BIN}/kubectl" <<'STUB'
#!/usr/bin/env bash
printf 'kubectl' >> "${CALLS_LOG}"
printf ' %s' "$@" >> "${CALLS_LOG}"
printf '\n' >> "${CALLS_LOG}"
cat >/dev/null 2>&1 < /dev/stdin || true
exit 0
STUB
chmod +x "${STUB_BIN}/helm" "${STUB_BIN}/kubectl"

# run_deploy <deploy-user.sh args...> -> sets DEPLOY_STATUS, refreshes CALLS
run_deploy() {
  : > "${CALLS}"
  set +e
  PATH="${STUB_BIN}:${PATH}" CALLS_LOG="${CALLS}" \
    "${DEPLOY}" "$@" >"${WORK}/deploy.out" 2>"${WORK}/deploy.err" </dev/null
  DEPLOY_STATUS=$?
  set -e
}

# expect_deploy_rejected <label> <stderr-must-contain> <deploy-user.sh args...>
expect_deploy_rejected() {
  local label="$1" needle="$2"
  shift 2
  CASES=$((CASES + 1))
  run_deploy "$@"
  if [[ "${DEPLOY_STATUS}" -eq 0 || "${DEPLOY_STATUS}" -eq 97 ]]; then
    fail "${label}: expected a non-zero exit before helm upgrade, got ${DEPLOY_STATUS}"
    return
  fi
  if [[ -s "${CALLS}" ]]; then
    fail "${label}: helm/kubectl was called although the flags file was rejected: $(cut -d' ' -f1-4 "${CALLS}" | tr '\n' ';' | cut -c1-200)"
    return
  fi
  if ! grep -qF -- "${needle}" "${WORK}/deploy.err"; then
    fail "${label}: stderr does not carry the reason '${needle}'"
    return
  fi
  if leaks_value "${WORK}/deploy.out" "${WORK}/deploy.err"; then
    fail "${label}: a flag value was printed in the output"
    return
  fi
  pass "${label} (exit ${DEPLOY_STATUS}, no helm/kubectl call)"
}

# expect_deploy_reaches_helm <label> <expected id=value pairs, one per line, '' for none> <deploy-user.sh args...>
# The `helm upgrade` argv must carry EXACTLY these challenge.flags overrides:
# each expected pair verbatim, and no other challenge.flags argument.
expect_deploy_reaches_helm() {
  local label="$1" want_pairs="$2"
  shift 2
  CASES=$((CASES + 1))
  run_deploy "$@"
  if [[ "${DEPLOY_STATUS}" -ne 97 ]]; then
    fail "${label}: expected to reach helm upgrade (stub exit 97), got ${DEPLOY_STATUS}: $(tr '\n' ' ' < "${WORK}/deploy.err" | cut -c1-300)"
    return
  fi
  local upgrade_line got_flags want_flags=0 pair
  upgrade_line="$(grep -E '^helm upgrade ' "${CALLS}" || true)"
  if [[ -z "${upgrade_line}" ]]; then
    fail "${label}: exit 97 but no 'helm upgrade' call was recorded"
    return
  fi
  while IFS= read -r pair; do
    [[ -z "${pair}" ]] && continue
    want_flags=$((want_flags + 1))
    case " ${upgrade_line} " in
      *" --set-string challenge.flags.${pair} "*) ;;
      *)
        fail "${label}: helm upgrade does not carry the expected override for ${pair%%=*}"
        return
        ;;
    esac
  done <<< "${want_pairs}"
  # grep exits 1 on "no match" (the expected result when no pair is
  # expected); only the count matters here.
  got_flags="$(printf '%s\n' "${upgrade_line}" | { grep -oE 'challenge\.flags\.[^=]+=' || true; } | wc -l | tr -d ' ')"
  if [[ "${got_flags}" -ne "${want_flags}" ]]; then
    fail "${label}: helm upgrade carried ${got_flags} challenge.flags override(s), expected ${want_flags}"
    return
  fi
  pass "${label} (helm upgrade reached, ${got_flags} flag override(s), values verbatim)"
}

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

expect_deploy_reaches_helm "all: complete file" "${ALL_PAIRS}" --flags-file "${FULL}" user1 all
expect_deploy_reaches_helm "scenario nimbusbreach-full: complete file" "${ALL_PAIRS}" --flags-file "${FULL}" user1 scenario:nimbusbreach-full
expect_deploy_reaches_helm "scenario tutorial-intro: only its own flag" "${P03}" --flags-file "${ONLY03}" user1 scenario:tutorial-intro
expect_deploy_reaches_helm "scenario tutorial-intro, full event file: only its own flag reaches helm" "${P03}" --flags-file "${FULL}" user1 scenario:tutorial-intro
expect_deploy_reaches_helm "single evade challenge: its own flag" "${P03}" --flags-file "${ONLY03}" user1 03-stealth-read
expect_deploy_reaches_helm "single evade challenge, full event file: only its own flag reaches helm" "${P05}" --flags-file "${FULL}" user1 05-silent-search
expect_deploy_reaches_helm "single trigger challenge, full event file: no flag reaches helm" "" --flags-file "${FULL}" user1 01-initial-recon
expect_deploy_reaches_helm "no --flags-file (local dev): unchanged, no override" "" user1 all
expect_deploy_reaches_helm "no --flags-file, scenario mode: unchanged, no override" "" user1 scenario:nimbusbreach-full

echo "==> ${CASES} case(s) run"
# A run that executed no cases proves nothing.
if [[ "${CASES}" -lt 90 ]]; then
  echo "FAIL: only ${CASES} case(s) ran — the test list was truncated" >&2
  RC=1
fi
if [[ "${RC}" -ne 0 ]]; then
  echo "FAIL: flags-file validation tests failed" >&2
  exit 1
fi
echo "ok: flags-file validation behaves fail-closed"
