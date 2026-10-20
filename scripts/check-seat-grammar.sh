#!/usr/bin/env bash
# The shell copy of the seat grammar (app#480, ADR-0034 D2): runs every row of
# internal/identity/testdata/seat-cases.tsv through charts/ctf-user/deploy-user.sh
# and checks the verdict. No cluster, no helm, no docker: stub `helm` / `kubectl`
# on PATH only record their invocations.
#
#   accept row -> deploy-user.sh gets as far as `helm upgrade` (the stub exits 97
#                 there) carrying `--set username=<seat>` verbatim.
#   reject row -> exit 2 with the reason on stderr and NOT ONE helm / kubectl
#                 call (an empty seat is the usage error, exit 1, same rule).
#                 The seat is never echoed raw: a bidi control in the row must
#                 not reach the terminal.
#
# The Go side reads the same table (internal/identity/seat_cases_test.go, which
# also pins the text of SEAT_PATTERN to identity.SeatPattern). Platform's roster
# tooling reads it in its paired PR.
#
# Self-test: the same table is run against copies of deploy-user.sh whose
# SEAT_PATTERN is broken three ways (accepts anything / one character too wide /
# one character too narrow); each must produce failures, or this check proves
# nothing and fails.
#
# Every expectation is an exit status or an exact string, never "some output
# appeared". Usage: ./scripts/check-seat-grammar.sh   (make check-flags; CI flag-guard)
set -euo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
TABLE="${REPO_ROOT}/internal/identity/testdata/seat-cases.tsv"
DEPLOY="${REPO_ROOT}/charts/ctf-user/deploy-user.sh"
CHALLENGES="${REPO_ROOT}/challenges"
MIN_ROWS=40

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

RC=0
fail() { echo "  FAIL: $1" >&2; RC=1; }
pass() { echo "  ok:   $1"; }

[[ -f "${TABLE}" ]] || { echo "FAIL: ${TABLE} not found" >&2; exit 1; }

BIDI="$(printf '\342\200\256')"   # U+202E, built at run time: this file stays ASCII
UUML="$(printf '\303\274')"       # U+00FC
IUML="$(printf '\303\257')"       # U+00EF
LF=$'\n'

# decode <placeholdered input> -> DECODED, the string the row stands for (the
# placeholders are listed in the table's header; the Go reader decodes the same
# set). A variable, not stdout: $(...) would strip a trailing newline, and the
# row `user1{LF}` is exactly that case.
decode() {
  DECODED="$1"
  DECODED="${DECODED//\{LF\}/${LF}}"
  DECODED="${DECODED//\{U+202E\}/${BIDI}}"
  DECODED="${DECODED//\{U+00FC\}/${UUML}}"
  DECODED="${DECODED//\{U+00EF\}/${IUML}}"
}

# --- stub helm / kubectl ----------------------------------------------------
STUB_BIN="${WORK}/bin"
CALLS="${WORK}/calls.log"
mkdir -p "${STUB_BIN}"
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

# run_deploy <deploy script> <username> -> sets DEPLOY_STATUS
run_deploy() {
  : > "${CALLS}"
  set +e
  PATH="${STUB_BIN}:${PATH}" CALLS_LOG="${CALLS}" \
    "$1" --challenges-dir "${CHALLENGES}" -- "$2" all \
    >"${WORK}/deploy.out" 2>"${WORK}/deploy.err" </dev/null
  DEPLOY_STATUS=$?
  set -e
}

# check_row <deploy script> <line no> <verdict> <username> -> 0 if the script
# behaves as the row says, else prints why on stderr and returns 1.
check_row() {
  local script="$1" lineno="$2" verdict="$3" user="$4"
  run_deploy "${script}" "${user}"
  if [[ "${verdict}" == accept ]]; then
    if [[ "${DEPLOY_STATUS}" -ne 97 ]]; then
      echo "    seat-cases.tsv:${lineno}: accept, but exit ${DEPLOY_STATUS} (want 97 = reached helm upgrade): $(tr '\n' ' ' < "${WORK}/deploy.err" | cut -c1-200)" >&2
      return 1
    fi
    if ! grep -E '^helm upgrade ' "${CALLS}" | grep -qF -- " --set username=${user} "; then
      echo "    seat-cases.tsv:${lineno}: accept, but helm upgrade did not carry --set username=<seat> verbatim" >&2
      return 1
    fi
    return 0
  fi
  local want=2
  [[ -z "${user}" ]] && want=1
  if [[ "${DEPLOY_STATUS}" -ne "${want}" ]]; then
    echo "    seat-cases.tsv:${lineno}: reject, but exit ${DEPLOY_STATUS} (want ${want})" >&2
    return 1
  fi
  if [[ -s "${CALLS}" ]]; then
    echo "    seat-cases.tsv:${lineno}: reject, but helm/kubectl was called: $(cut -d' ' -f1-3 "${CALLS}" | tr '\n' ';' | cut -c1-160)" >&2
    return 1
  fi
  if [[ -n "${user}" ]] && ! grep -qF 'invalid username' "${WORK}/deploy.err"; then
    echo "    seat-cases.tsv:${lineno}: reject, but stderr does not carry the reason" >&2
    return 1
  fi
  if grep -qF -- "${BIDI}" "${WORK}/deploy.err" "${WORK}/deploy.out"; then
    echo "    seat-cases.tsv:${lineno}: a raw bidi control reached the output" >&2
    return 1
  fi
  return 0
}

# run_table <deploy script> -> sets ROWS, ACCEPTED, REJECTED, BAD (rows that disagree)
run_table() {
  local script="$1" line lineno=0 input verdict user
  ROWS=0 ACCEPTED=0 REJECTED=0 BAD=0
  while IFS= read -r line || [[ -n "${line}" ]]; do
    lineno=$((lineno + 1))
    case "${line}" in ''|'#'*) continue ;; esac
    # First tab only (an empty input makes the line start with a tab).
    if [[ "${line}" != *$'\t'* ]]; then
      echo "    seat-cases.tsv:${lineno}: no tab" >&2; BAD=$((BAD + 1)); continue
    fi
    input="${line%%$'\t'*}"
    verdict="${line#*$'\t'}"
    case "${verdict}" in
      accept) ACCEPTED=$((ACCEPTED + 1)) ;;
      reject) REJECTED=$((REJECTED + 1)) ;;
      *) echo "    seat-cases.tsv:${lineno}: verdict must be accept|reject" >&2; BAD=$((BAD + 1)); continue ;;
    esac
    ROWS=$((ROWS + 1))
    decode "${input}"
    user="${DECODED}"
    check_row "${script}" "${lineno}" "${verdict}" "${user}" || BAD=$((BAD + 1))
  done < "${TABLE}"
}

echo "==> deploy-user.sh against the shared seat-case table"
run_table "${DEPLOY}"
if [[ "${ROWS}" -lt "${MIN_ROWS}" || "${ACCEPTED}" -lt 10 || "${REJECTED}" -lt 20 ]]; then
  fail "the table was misread or truncated: ${ROWS} rows (${ACCEPTED} accept / ${REJECTED} reject)"
elif [[ "${BAD}" -ne 0 ]]; then
  fail "${BAD} of ${ROWS} rows disagree with deploy-user.sh"
else
  pass "all ${ROWS} rows (${ACCEPTED} accept / ${REJECTED} reject) behave as the table says"
fi

echo "==> self-test: a broken SEAT_PATTERN must be caught"
mutate() { # <label> <replacement pattern>
  local dir="${WORK}/mut-$1/charts/ctf-user"
  mkdir -p "${dir}"
  cp "${REPO_ROOT}"/charts/ctf-user/*.sh "${dir}/"
  if ! grep -qE "^SEAT_PATTERN='" "${dir}/deploy-user.sh"; then
    fail "self-test $1: deploy-user.sh has no SEAT_PATTERN line to mutate"
    return
  fi
  # Rewrite the one definition line (no sed -i: BSD and GNU differ).
  while IFS= read -r l; do
    case "${l}" in
      "SEAT_PATTERN='"*) printf "SEAT_PATTERN='%s'\n" "$2" ;;
      *) printf '%s\n' "${l}" ;;
    esac
  done < "${dir}/deploy-user.sh" > "${dir}/deploy-user.sh.new"
  mv "${dir}/deploy-user.sh.new" "${dir}/deploy-user.sh"
  chmod +x "${dir}/deploy-user.sh"
  run_table "${dir}/deploy-user.sh" 2>"${WORK}/mut-$1.err"
  if [[ "${BAD}" -eq 0 ]]; then
    fail "self-test $1: the table did not notice SEAT_PATTERN='$2'"
  else
    pass "self-test $1: ${BAD} row(s) disagree with SEAT_PATTERN='$2'"
  fi
}
mutate any '^.*$'
mutate wide '^[a-z0-9][a-z0-9-]{0,63}$'
mutate narrow '^[a-z0-9][a-z0-9-]{0,61}$'

if [[ "${RC}" -ne 0 ]]; then
  echo "seat grammar check FAILED" >&2
  exit 1
fi
echo "seat grammar check passed"
