#!/usr/bin/env bash
# The shell copies of the challenge id grammar and the scenario name grammar
# (app#494): runs every row of
#   internal/catalog/challengeid/testdata/challenge-id-cases.tsv  (<NN-slug>)
#   internal/catalog/testdata/scenario-name-cases.tsv             (scenario:<name>)
# through charts/ctf-user/deploy-user.sh and checks the verdict. No cluster, no
# helm, no docker: stub `helm` / `kubectl` on PATH only record their invocations.
#
#   accept row -> deploy-user.sh gets as far as `helm upgrade` (the stub exits 97
#                 there; the challenge dir / the scenario dir + values file the
#                 script wants are created empty for the row, in a scratch tree).
#                 The recorded call is compared EXACTLY: the id reaches the chart as
#                 `--set-string challengeId=<id>` (or `scenario:<name>`) verbatim,
#                 --set-string and not --set, so helm's own typing and its `,` / `=`
#                 syntax never see it.
#   reject row -> exit 2 with `invalid challenge id` / `invalid scenario name` on
#                 stderr and NOT ONE helm / kubectl call (an empty challenge id is
#                 the usage error, exit 1). The value is never echoed raw: a bidi
#                 control in the row must not reach the terminal.
#
# The Go side reads the same tables (internal/catalog/challengeid/shell_cases_test.go,
# internal/catalog/scenario_name_test.go), which also pin the text of
# CHALLENGE_ID_PATTERN to challengeid.Pattern and of SCENARIO_PATTERN to the table's
# header. Also: a rejected id is stopped before kubectl on the --egress-lockdown path
# (which runs a kubectl before anything else), not only on the plain one.
#
# Self-test: the tables are run against copies of deploy-user.sh whose patterns are
# broken (accepts anything / one character too wide / too narrow / a trailing hyphen
# or an end anchor missing / the old charset `[A-Za-z0-9._-]` that let `.` and `..`
# through) and whose `--set-string challengeId=` is `--set`; each must fail the table
# row the break is about, or this check proves nothing and fails. A row with a
# placeholder the reader does not know makes the reader fail (the closed set).
#
# Every expectation is an exit status or an exact string, never "some output
# appeared". Usage: ./scripts/check-deploy-user-ids.sh   (make check-flags; CI flag-guard)
set -euo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
CID_TABLE="${REPO_ROOT}/internal/catalog/challengeid/testdata/challenge-id-cases.tsv"
SCN_TABLE="${REPO_ROOT}/internal/catalog/testdata/scenario-name-cases.tsv"
DEPLOY="${REPO_ROOT}/charts/ctf-user/deploy-user.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

RC=0
fail() { echo "  FAIL: $1" >&2; RC=1; }
pass() { echo "  ok:   $1"; }

for f in "${CID_TABLE}" "${SCN_TABLE}" "${DEPLOY}"; do
  [[ -f "${f}" ]] || { echo "FAIL: ${f} not found" >&2; exit 1; }
done

BIDI="$(printf '\342\200\256')"   # U+202E, built at run time: this file stays ASCII
UUML="$(printf '\303\274')"       # U+00FC
IUML="$(printf '\303\257')"       # U+00EF
LF=$'\n'

# decode <placeholdered input> -> DECODED (the placeholders are the tables' closed
# set; the Go reader, internal/casetable, decodes the same). A variable, not stdout:
# $(...) would strip a trailing newline, and `01-a{LF}` is exactly that case.
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
# One printf per call = one write(2) of one whole line.
cat > "${STUB_BIN}/helm" <<'STUB'
#!/usr/bin/env bash
printf 'helm %s\n' "$*" >> "${CALLS_LOG}"
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
printf 'kubectl %s\n' "$*" >> "${CALLS_LOG}"
case " $* " in
  *" get svc kubernetes "*) printf '10.96.0.1'; exit 0 ;;
esac
cat >/dev/null 2>&1 < /dev/stdin || true
exit 0
STUB
chmod +x "${STUB_BIN}/helm" "${STUB_BIN}/kubectl"

# run_deploy <deploy script> <challenge-id argument as given> <make dirs: 1|0> [extra flags...]
# -> sets DEPLOY_STATUS. With <make dirs> = 1 a scratch challenges dir and scenarios
# dir are made to hold what the script looks for after the grammar check (the
# challenge directory, or scenario.yaml + values-scenario-<name>.yaml), so an accept
# row reaches `helm upgrade`; a reject row gets none, and must stop on the grammar.
run_deploy() {
  local script="$1" arg="$2" mk="$3" cdir sdir name
  shift 3
  cdir="${WORK}/challenges"; sdir="${WORK}/scenarios"
  rm -rf "${cdir}" "${sdir}"; mkdir -p "${cdir}" "${sdir}"
  if [[ "${mk}" -eq 1 ]]; then
    case "${arg}" in
      all) : > "${cdir}/values-all.yaml" ;;
      scenario:*)
        name="${arg#scenario:}"
        mkdir -p "${sdir}/${name}"; : > "${sdir}/${name}/scenario.yaml"
        : > "${cdir}/values-scenario-${name}.yaml" ;;
      *) mkdir -p "${cdir}/${arg}" ;;
    esac
  fi
  : > "${CALLS}"
  set +e
  PATH="${STUB_BIN}:${PATH}" CALLS_LOG="${CALLS}" \
    "${script}" --challenges-dir "${cdir}" --scenarios-dir "${sdir}" ${1+"$@"} -- user1 "${arg}" \
    >"${WORK}/deploy.out" 2>"${WORK}/deploy.err" </dev/null
  DEPLOY_STATUS=$?
  set -e
}

# check_row <table label> <deploy script> <line no> <verdict> <argument> <message> [extra flags...]
# -> 0 if the script behaves as the row says, else prints why on stderr and returns 1.
# <message> is the stderr marker of a rejection (`invalid challenge id` / `invalid scenario name`).
check_row() {
  local label="$1" script="$2" lineno="$3" verdict="$4" arg="$5" msg="$6"
  shift 6
  if [[ "${verdict}" == accept ]]; then
    run_deploy "${script}" "${arg}" 1 ${1+"$@"}
    if [[ "${DEPLOY_STATUS}" -ne 97 ]]; then
      echo "    ${label}:${lineno}: accept, but exit ${DEPLOY_STATUS} (want 97 = reached helm upgrade): $(tr '\n' ' ' < "${WORK}/deploy.err" | cut -c1-200)" >&2
      return 1
    fi
    # Exact: token ` --set-string challengeId=<arg> ` (the call is `$*`, so a value
    # with a space or a newline cannot be an accept row: none is one).
    if ! grep -E '^helm upgrade ' "${CALLS}" | grep -qF -- " --set-string challengeId=${arg} "; then
      echo "    ${label}:${lineno}: accept, but helm upgrade did not carry --set-string challengeId=<id> verbatim: $(grep -E '^helm upgrade ' "${CALLS}" | cut -c1-200)" >&2
      return 1
    fi
    return 0
  fi
  run_deploy "${script}" "${arg}" 0 ${1+"$@"}
  local want=2
  [[ -z "${arg}" ]] && want=1
  if [[ "${DEPLOY_STATUS}" -ne "${want}" ]]; then
    echo "    ${label}:${lineno}: reject, but exit ${DEPLOY_STATUS} (want ${want})" >&2
    return 1
  fi
  if [[ -s "${CALLS}" ]]; then
    echo "    ${label}:${lineno}: reject, but helm/kubectl was called: $(cut -d' ' -f1-3 "${CALLS}" | tr '\n' ';' | cut -c1-160)" >&2
    return 1
  fi
  if [[ -n "${arg}" ]] && ! grep -qF "${msg}" "${WORK}/deploy.err"; then
    echo "    ${label}:${lineno}: reject, but stderr does not carry '${msg}'" >&2
    return 1
  fi
  if grep -qF -- "${BIDI}" "${WORK}/deploy.err" "${WORK}/deploy.out"; then
    echo "    ${label}:${lineno}: a raw bidi control reached the output" >&2
    return 1
  fi
  return 0
}

# run_table <kind: cid|scn> <deploy script> [table] -> sets ROWS, ACCEPTED, REJECTED,
# BAD (rows that disagree) and BAD_LINES (" n n ": their line numbers in the table).
run_table() {
  local kind="$1" script="$2" table line lineno=0 input verdict arg label msg prefix=""
  if [[ "${kind}" == cid ]]; then
    table="${3:-${CID_TABLE}}"; msg="invalid challenge id"
  else
    table="${3:-${SCN_TABLE}}"; msg="invalid scenario name"; prefix="scenario:"
  fi
  label="$(basename "${table}")"
  ROWS=0 ACCEPTED=0 REJECTED=0 BAD=0 BAD_LINES=" "
  while IFS= read -r line || [[ -n "${line}" ]]; do
    lineno=$((lineno + 1))
    case "${line}" in ''|'#'*) continue ;; esac
    # First tab only (an empty input makes the line start with a tab).
    if [[ "${line}" != *$'\t'* ]]; then
      echo "    ${label}:${lineno}: no tab" >&2; BAD=$((BAD + 1)); BAD_LINES="${BAD_LINES}${lineno} "; continue
    fi
    input="${line%%$'\t'*}"
    verdict="${line#*$'\t'}"
    case "${verdict}" in
      accept) ACCEPTED=$((ACCEPTED + 1)) ;;
      reject) REJECTED=$((REJECTED + 1)) ;;
      *) echo "    ${label}:${lineno}: verdict must be accept|reject" >&2; BAD=$((BAD + 1)); BAD_LINES="${BAD_LINES}${lineno} "; continue ;;
    esac
    ROWS=$((ROWS + 1))
    decode "${input}"
    arg="${DECODED}"
    # The placeholder set is closed: a brace left after decoding is an unknown
    # placeholder, an error of this reader, not a verdict.
    case "${arg}" in
      *'{'*|*'}'*)
        echo "    ${label}:${lineno}: a brace is left after decoding: an unknown placeholder" >&2
        BAD=$((BAD + 1)); BAD_LINES="${BAD_LINES}${lineno} "; continue ;;
    esac
    check_row "${label}" "${script}" "${lineno}" "${verdict}" "${prefix}${arg}" "${msg}" \
      || { BAD=$((BAD + 1)); BAD_LINES="${BAD_LINES}${lineno} "; }
  done < "${table}"
}

# expect_table <kind> <label> <min rows> <min accept> <min reject>
expect_table() {
  run_table "$1" "${DEPLOY}"
  if [[ "${ROWS}" -lt "$3" || "${ACCEPTED}" -lt "$4" || "${REJECTED}" -lt "$5" ]]; then
    fail "$2: the table was misread or truncated: ${ROWS} rows (${ACCEPTED} accept / ${REJECTED} reject)"
  elif [[ "${BAD}" -ne 0 ]]; then
    fail "$2: ${BAD} of ${ROWS} rows disagree with deploy-user.sh"
  else
    pass "$2: all ${ROWS} rows (${ACCEPTED} accept / ${REJECTED} reject) behave as the table says"
  fi
}

echo "==> deploy-user.sh against the shared challenge-id and scenario-name case tables"
expect_table cid "challenge-id-cases.tsv" 50 10 40
expect_table scn "scenario-name-cases.tsv" 40 10 25

echo "==> the fixed word is not an id: 'all' still reaches helm upgrade"
if check_row all-mode "${DEPLOY}" 0 accept all "invalid challenge id"; then
  pass "'all' reaches helm upgrade with --set-string challengeId=all"
else
  fail "'all' did not reach helm upgrade as expected"
fi

echo "==> the check comes before kubectl on the --egress-lockdown path too"
LOCKDOWN=(--egress-lockdown --api-server-cidr 10.0.0.1/32)
# An accepted id reaches helm upgrade with the flags (so the stub setup works and a
# reject below is not an artefact of a broken lockdown path) ...
if check_row lockdown "${DEPLOY}" 0 accept 01-initial-recon "invalid challenge id" "${LOCKDOWN[@]}" && grep -qF 'kubectl get svc kubernetes' "${CALLS}"; then
  pass "01-initial-recon with --egress-lockdown reaches helm upgrade (the ClusterIP lookup ran)"
else
  fail "01-initial-recon with --egress-lockdown did not reach helm upgrade as expected"
fi
# ... and a rejected one stops before the ClusterIP lookup: not one call.
for u in '01-a,b=c' '..' '01-A'; do
  if check_row lockdown "${DEPLOY}" 0 reject "${u}" "invalid challenge id" "${LOCKDOWN[@]}"; then
    pass "'${u}' with --egress-lockdown: exit 2, no kubectl / helm call"
  else
    fail "'${u}' with --egress-lockdown was not stopped before kubectl"
  fi
done
for u in 'scenario:a,b=c' 'scenario:..' 'scenario:'; do
  if check_row lockdown "${DEPLOY}" 0 reject "${u}" "invalid scenario name" "${LOCKDOWN[@]}"; then
    pass "'${u}' with --egress-lockdown: exit 2, no kubectl / helm call"
  else
    fail "'${u}' with --egress-lockdown was not stopped before kubectl"
  fi
done

echo "==> self-test: a broken pattern, or --set instead of --set-string, must be caught, on the row that breaks"
# line_of <table> <awk condition on $1 (input) and $2 (verdict)> -> the table line number
line_of() {
  local n
  n="$(awk -F'\t' "$2 { print NR; exit }" "$1")"
  [[ -n "${n}" ]] || { echo "FAIL: no row of $1 matches $2" >&2; exit 1; }
  printf '%s' "${n}"
}
# mutate_line <kind> <label> <line prefix> <replacement line> <expected failing line>:
# a copy of deploy-user.sh whose ONE line starting with <line prefix> is replaced, run
# against the <kind> table; the row at <expected failing line> must disagree.
mutate_line() {
  local kind="$1" label="$2" prefix="$3" repl="$4" want="$5" dir="${WORK}/mut-$2/charts/ctf-user" l n=0
  mkdir -p "${dir}"
  cp "${REPO_ROOT}"/charts/ctf-user/*.sh "${dir}/"
  # Rewrite the one definition line (no sed -i: BSD and GNU differ).
  while IFS= read -r l; do
    case "${l}" in
      "${prefix}"*) printf '%s\n' "${repl}"; n=$((n + 1)) ;;
      *) printf '%s\n' "${l}" ;;
    esac
  done < "${dir}/deploy-user.sh" > "${dir}/deploy-user.sh.new"
  if [[ "${n}" -ne 1 ]]; then
    fail "self-test ${label}: deploy-user.sh has ${n} lines starting with '${prefix}' (want exactly 1 to mutate)"
    return
  fi
  mv "${dir}/deploy-user.sh.new" "${dir}/deploy-user.sh"
  chmod +x "${dir}/deploy-user.sh"
  run_table "${kind}" "${dir}/deploy-user.sh" 2>"${WORK}/mut-${label}.err"
  case "${BAD_LINES}" in
    *" ${want} "*) pass "self-test ${label}: '${repl}' fails table line ${want} (${BAD} row(s) in all): $(grep -F ":${want}:" "${WORK}/mut-${label}.err" | head -n 1 | sed 's/^ *//' | cut -c1-150)" ;;
    *) fail "self-test ${label}: '${repl}' did not fail table line ${want} (failing lines:${BAD_LINES})" ;;
  esac
}
cid_mutate() { mutate_line cid "cid-$1" "CHALLENGE_ID_PATTERN='" "CHALLENGE_ID_PATTERN='$2'" "$3"; }
scn_mutate() { mutate_line scn "scn-$1" "SCENARIO_PATTERN='" "SCENARIO_PATTERN='$2'" "$3"; }

cid_mutate any '^.*$' "$(line_of "${CID_TABLE}" '$1 == "01-a,b=c"')"
cid_mutate old-charset '^[0-9]{2}-[A-Za-z0-9._-]{1,60}$' "$(line_of "${CID_TABLE}" '$1 == "01-.."')"
cid_mutate wide '^[0-9]{2}-[a-z0-9-]{1,61}$' "$(line_of "${CID_TABLE}" 'length($1) == 64 && $2 == "reject"')"
cid_mutate narrow '^[0-9]{2}-[a-z0-9-]{1,59}$' "$(line_of "${CID_TABLE}" 'length($1) == 63 && $2 == "accept"')"
cid_mutate empty-slug '^[0-9]{2}-[a-z0-9-]{0,60}$' "$(line_of "${CID_TABLE}" '$1 == "12-"')"
cid_mutate one-digit '^[0-9]{1,2}-[a-z0-9-]{1,60}$' "$(line_of "${CID_TABLE}" '$1 == "1-a"')"
cid_mutate no-dollar '^[0-9]{2}-[a-z0-9-]{1,60}' "$(line_of "${CID_TABLE}" '$1 == "01-a{LF}"')"
cid_mutate no-caret '[0-9]{2}-[a-z0-9-]{1,60}$' "$(line_of "${CID_TABLE}" '$1 == "../01-a"')"
scn_mutate any '^.*$' "$(line_of "${SCN_TABLE}" '$1 == "a,b=c"')"
scn_mutate old-charset '^[A-Za-z0-9._-]+$' "$(line_of "${SCN_TABLE}" '$1 == ".."')"
scn_mutate slash '^[a-z0-9/-]+$' "$(line_of "${SCN_TABLE}" '$1 == "a/b"')"
scn_mutate wide '^[a-z0-9]([a-z0-9-]{0,53}[a-z0-9])?$' "$(line_of "${SCN_TABLE}" 'length($1) == 55 && $2 == "reject"')"
scn_mutate narrow '^[a-z0-9]([a-z0-9-]{0,51}[a-z0-9])?$' "$(line_of "${SCN_TABLE}" 'length($1) == 54 && $2 == "accept"')"
scn_mutate trailing-dash '^[a-z0-9][a-z0-9-]{0,53}$' "$(line_of "${SCN_TABLE}" '$1 == "a-"')"
scn_mutate empty '^[a-z0-9-]*$' "$(line_of "${SCN_TABLE}" '$1 == "" && $2 == "reject"')"
scn_mutate no-dollar '^[a-z0-9]([a-z0-9-]{0,52}[a-z0-9])?' "$(line_of "${SCN_TABLE}" '$1 == "a{LF}"')"
scn_mutate no-caret '[a-z0-9]([a-z0-9-]{0,52}[a-z0-9])?$' "$(line_of "${SCN_TABLE}" '$1 == "-a"')"
# --set-string -> --set: helm would type the value and read `,` / `=` in it.
mutate_line cid set-not-set-string '  --set-string "challengeId=' '  --set "challengeId=${CHALLENGE_ID}" \' "$(line_of "${CID_TABLE}" '$1 == "00-tutorial"')"

echo "==> self-test: an unknown placeholder makes the reader fail"
BADTABLE="${WORK}/unknown-placeholder.tsv"
printf '01-a\taccept\n01-a{U+2028}\treject\n01-a{LF\treject\n' > "${BADTABLE}"
run_table cid "${DEPLOY}" "${BADTABLE}" 2>"${WORK}/unknown.err"
if [[ "${BAD_LINES}" == " 2 3 " ]]; then
  pass "rows with an unknown / unclosed placeholder fail the reader (lines 2 and 3), the plain row does not"
else
  fail "an unknown placeholder did not fail the reader exactly on lines 2 and 3 (failing lines:${BAD_LINES})"
fi

if [[ "${RC}" -ne 0 ]]; then
  echo "deploy-user.sh id grammar check FAILED" >&2
  exit 1
fi
echo "deploy-user.sh id grammar check passed"
