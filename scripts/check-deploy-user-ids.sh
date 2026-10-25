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
# app#510 adds the four other operator inputs, each with its own case table in
# internal/catalog/testdata/ (dns-suffix-cases.tsv, image-registry-cases.tsv,
# image-tag-cases.tsv, api-server-cidr-cases.tsv; the section at the end of this file):
# `--dns-suffix <input>`, the env FALCO_CTF_REGISTRY=<input>, FALCO_CTF_IMAGE_TAG=<input>
# and `--egress-lockdown --api-server-cidr <input>`. An accept row reaches `helm upgrade`
# with every value that came from the input as `--set-string <key>=<value>` (exact tokens),
# and with NO ` --set ` token in the call but the one boolean the script writes itself
# (networkPolicy.egress.enabled=true); a reject row is exit 2, `invalid <name>` on stderr,
# not one helm / kubectl call. Its self-test breaks each pattern, the length bound and
# each check, and turns each --set-string back into --set.
#
# Every expectation is an exit status or an exact string, never "some output
# appeared". Usage: ./scripts/check-deploy-user-ids.sh   (make check-flags; CI flag-guard)
set -euo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
CID_TABLE="${REPO_ROOT}/internal/catalog/challengeid/testdata/challenge-id-cases.tsv"
SCN_TABLE="${REPO_ROOT}/internal/catalog/testdata/scenario-name-cases.tsv"
DEPLOY="${REPO_ROOT}/charts/ctf-user/deploy-user.sh"
DNS_TABLE="${REPO_ROOT}/internal/catalog/testdata/dns-suffix-cases.tsv"
REG_TABLE="${REPO_ROOT}/internal/catalog/testdata/image-registry-cases.tsv"
TAG_TABLE="${REPO_ROOT}/internal/catalog/testdata/image-tag-cases.tsv"
CIDR_TABLE="${REPO_ROOT}/internal/catalog/testdata/api-server-cidr-cases.tsv"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# The real FALCO_CTF_* of the operator running this check must not reach any row (before
# run_deploy is defined, so no run of deploy-user.sh below can see them).
unset FALCO_CTF_REGISTRY FALCO_CTF_IMAGE_TAG

RC=0
fail() { echo "  FAIL: $1" >&2; RC=1; }
pass() { echo "  ok:   $1"; }

for f in "${CID_TABLE}" "${SCN_TABLE}" "${DEPLOY}" "${DNS_TABLE}" "${REG_TABLE}" "${TAG_TABLE}" "${CIDR_TABLE}"; do
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

# ============================================================================
# app#510: the other operator inputs (--dns-suffix, FALCO_CTF_REGISTRY,
# FALCO_CTF_IMAGE_TAG, --api-server-cidr). New functions only: they reuse decode,
# run_deploy and the stubs above and change none of them.
# ============================================================================
# The one ` --set ` token a helm call may carry: a boolean the script writes itself.
OP_ALLOWED_SET=' --set networkPolicy.egress.enabled=true'

# op_conf <dns|reg|tag|cidr> -> OP_TABLE, OP_MSG (the stderr marker of a rejection).
op_conf() {
  case "$1" in
    dns)  OP_TABLE="${DNS_TABLE}";  OP_MSG="invalid --dns-suffix" ;;
    reg)  OP_TABLE="${REG_TABLE}";  OP_MSG="invalid FALCO_CTF_REGISTRY" ;;
    tag)  OP_TABLE="${TAG_TABLE}";  OP_MSG="invalid FALCO_CTF_IMAGE_TAG" ;;
    cidr) OP_TABLE="${CIDR_TABLE}"; OP_MSG="invalid --api-server-cidr" ;;
    *) echo "FAIL: op_conf: unknown kind $1" >&2; exit 1 ;;
  esac
}

# op_run <script> <kind> <value> -> DEPLOY_STATUS. The value goes in the way the real
# caller passes it: a flag (dns, cidr) or the environment (reg, tag), next to a valid
# challenge id whose directory exists, so a reject can only be the grammar.
op_run() {
  local script="$1" kind="$2" value="$3"
  case "${kind}" in
    dns)  run_deploy "${script}" 00-tutorial 1 --dns-suffix "${value}" ;;
    cidr) run_deploy "${script}" 00-tutorial 1 --egress-lockdown --api-server-cidr "${value}" ;;
    reg)  FALCO_CTF_REGISTRY="${value}" run_deploy "${script}" 00-tutorial 1 ;;
    tag)  FALCO_CTF_IMAGE_TAG="${value}" run_deploy "${script}" 00-tutorial 1 ;;
  esac
}

# op_expected_tokens <kind> <value> -> the exact ` --set-string key=value ` tokens an
# accepted value must produce, one per line.
op_expected_tokens() {
  local kind="$1" v="$2"
  case "${kind}" in
    dns)  printf ' --set-string dnsSuffix=%s \n' "${v}" ;;
    cidr) printf ' --set-string networkPolicy.egress.apiServerCidr=%s \n' "${v}" ;;
    reg)  printf ' --set-string ttyd.image.repository=%s/ttyd \n --set-string ttyd.proxy.image.repository=%s/ttyd-proxy \n --set-string challenge.image.repository=%s/challenge \n' "${v}" "${v}" "${v}" ;;
    tag)  printf ' --set-string ttyd.image.tag=%s \n --set-string ttyd.proxy.image.tag=%s \n --set-string challenge.image.tag=%s \n' "${v}" "${v}" "${v}" ;;
  esac
}

# op_check_row <label> <script> <line no> <kind> <verdict> <value> -> 0 if deploy-user.sh
# behaves as the row says, else the reason on stderr and 1.
op_check_row() {
  local label="$1" script="$2" lineno="$3" kind="$4" verdict="$5" value="$6" tok call stray
  op_conf "${kind}"
  op_run "${script}" "${kind}" "${value}"
  if [[ "${verdict}" == accept ]]; then
    if [[ "${DEPLOY_STATUS}" -ne 97 ]]; then
      echo "    ${label}:${lineno}: accept, but exit ${DEPLOY_STATUS} (want 97 = reached helm upgrade): $(tr '\n' ' ' < "${WORK}/deploy.err" | cut -c1-200)" >&2
      return 1
    fi
    call="$(grep -E '^helm upgrade ' "${CALLS}" || true) "
    while IFS= read -r tok; do
      [[ -n "${tok}" ]] || continue
      case "${call}" in
        *"${tok}"*) ;;
        *) echo "    ${label}:${lineno}: accept, but helm upgrade lacks the token '${tok}': $(printf '%s' "${call}" | cut -c1-240)" >&2; return 1 ;;
      esac
    done < <(op_expected_tokens "${kind}" "${value}")
    # Not one ` --set ` (typed, `,` / `=` parsed) besides the boolean the script writes.
    stray="$(printf '%s' "${call}" | grep -oE ' --set [^ ]*' | grep -vxF "${OP_ALLOWED_SET}" || true)"
    if [[ -n "${stray}" ]]; then
      echo "    ${label}:${lineno}: accept, but helm upgrade carries a bare --set:$(printf '%s' "${stray}" | tr '\n' ';')" >&2
      return 1
    fi
    return 0
  fi
  # (No table has an empty row: an empty flag value is the flag parser's usage error and an
  # empty env value means "not set"; neither is a verdict of the grammar.)
  if [[ "${DEPLOY_STATUS}" -ne 2 ]]; then
    echo "    ${label}:${lineno}: reject, but exit ${DEPLOY_STATUS} (want 2)" >&2
    return 1
  fi
  if [[ -s "${CALLS}" ]]; then
    echo "    ${label}:${lineno}: reject, but helm/kubectl was called: $(cut -d' ' -f1-3 "${CALLS}" | tr '\n' ';' | cut -c1-160)" >&2
    return 1
  fi
  if ! grep -qF "${OP_MSG}" "${WORK}/deploy.err"; then
    echo "    ${label}:${lineno}: reject, but stderr does not carry '${OP_MSG}'" >&2
    return 1
  fi
  if grep -qF -- "${BIDI}" "${WORK}/deploy.err" "${WORK}/deploy.out"; then
    echo "    ${label}:${lineno}: a raw bidi control reached the output" >&2
    return 1
  fi
  return 0
}

# op_run_table <kind> <script> -> ROWS, ACCEPTED, REJECTED, BAD, BAD_LINES (as run_table).
op_run_table() {
  local kind="$1" script="$2" line lineno=0 input verdict label
  op_conf "${kind}"
  label="$(basename "${OP_TABLE}")"
  ROWS=0 ACCEPTED=0 REJECTED=0 BAD=0 BAD_LINES=" "
  while IFS= read -r line || [[ -n "${line}" ]]; do
    lineno=$((lineno + 1))
    case "${line}" in ''|'#'*) continue ;; esac
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
    case "${DECODED}" in
      *'{'*|*'}'*)
        echo "    ${label}:${lineno}: a brace is left after decoding: an unknown placeholder" >&2
        BAD=$((BAD + 1)); BAD_LINES="${BAD_LINES}${lineno} "; continue ;;
    esac
    op_check_row "${label}" "${script}" "${lineno}" "${kind}" "${verdict}" "${DECODED}" \
      || { BAD=$((BAD + 1)); BAD_LINES="${BAD_LINES}${lineno} "; }
  done < "${OP_TABLE}"
}

op_expect_table() {
  local kind="$1" label="$2"
  op_run_table "${kind}" "${DEPLOY}"
  if [[ "${ROWS}" -lt "$3" || "${ACCEPTED}" -lt "$4" || "${REJECTED}" -lt "$5" ]]; then
    fail "${label}: the table was misread or truncated: ${ROWS} rows (${ACCEPTED} accept / ${REJECTED} reject)"
  elif [[ "${BAD}" -ne 0 ]]; then
    fail "${label}: ${BAD} of ${ROWS} rows disagree with deploy-user.sh"
  else
    pass "${label}: all ${ROWS} rows (${ACCEPTED} accept / ${REJECTED} reject) behave as the table says"
  fi
}

echo "==> deploy-user.sh against the operator-input case tables (app#510)"
op_expect_table dns  "dns-suffix-cases.tsv"      50 15 30
op_expect_table reg  "image-registry-cases.tsv"  80 14 60
op_expect_table tag  "image-tag-cases.tsv"       50 15 25
op_expect_table cidr "api-server-cidr-cases.tsv" 65 15 45

echo "==> a bad --api-server-cidr is refused without --egress-lockdown too (a set value is never ignored quietly)"
for u in '10.0.0.1/33' 'a,b=c' '10.0.0.1/32,10.0.0.2/32'; do
  run_deploy "${DEPLOY}" 00-tutorial 1 --api-server-cidr "${u}"
  if [[ "${DEPLOY_STATUS}" -eq 2 && ! -s "${CALLS}" ]] && grep -qF 'invalid --api-server-cidr' "${WORK}/deploy.err"; then
    pass "'${u}' without --egress-lockdown: exit 2, no kubectl / helm call"
  else
    fail "'${u}' without --egress-lockdown was not refused before kubectl (exit ${DEPLOY_STATUS})"
  fi
done

echo "==> all four good together: the helm call carries every value as --set-string and no other --set"
op_all_good() {
  FALCO_CTF_REGISTRY='000000000000.dkr.ecr.us-east-1.amazonaws.com/falco-ctf' FALCO_CTF_IMAGE_TAG='0123456789abcdef0123456789abcdef01234567' \
    run_deploy "${DEPLOY}" 00-tutorial 1 --dns-suffix ctf.192.168.64.2.nip.io --egress-lockdown --api-server-cidr 10.100.0.1/32
  local c k
  [[ "${DEPLOY_STATUS}" -eq 97 ]] || { echo "    exit ${DEPLOY_STATUS}, want 97" >&2; return 1; }
  c="$(grep -E '^helm upgrade ' "${CALLS}" || true) "
  for k in ' --set-string dnsSuffix=ctf.192.168.64.2.nip.io ' \
           ' --set-string networkPolicy.egress.apiServerCidr=10.100.0.1/32 ' \
           ' --set-string ttyd.image.repository=000000000000.dkr.ecr.us-east-1.amazonaws.com/falco-ctf/ttyd ' \
           ' --set-string ttyd.proxy.image.tag=0123456789abcdef0123456789abcdef01234567 ' \
           ' --set-string username=user1 ' ' --set-string challengeId=00-tutorial '; do
    case "${c}" in *"${k}"*) ;; *) echo "    helm upgrade lacks '${k}'" >&2; return 1 ;; esac
  done
  [[ -z "$(printf '%s' "${c}" | grep -oE ' --set [^ ]*' | grep -vxF "${OP_ALLOWED_SET}" || true)" ]] || { echo "    a bare --set is in the call" >&2; return 1; }
}
if op_all_good; then pass "four good values together: every one is --set-string, the only --set is networkPolicy.egress.enabled=true"; else fail "four good values together did not produce the expected helm call"; fi

echo "==> self-test (app#510): a broken pattern, a removed check, or --set instead of --set-string, must be caught on the row that breaks it"
# op_line_of <table> <awk condition> -> line number (the awk of line_of, kept as is).
# op_mutate <kind> <label> <line prefix> <replacement line> <failing line> <control: accept|reject>:
# a copy of deploy-user.sh whose ONE line starting with <line prefix> is replaced. The row at
# <failing line> must disagree, and the control row (the first accept / reject row of the
# table) must still agree: a copy that is broken everywhere would fail the first for the
# wrong reason and prove nothing.
op_mutate() {
  local kind="$1" label="$2" prefix="$3" repl="$4" want="$5" control="$6" dir="${WORK}/opmut-$2/charts/ctf-user" l n=0 cl cv ctl
  if [[ ! "${want}" =~ ^[0-9]+$ ]]; then
    fail "self-test ${label}: no table row matches the condition for the row it is about"
    return
  fi
  mkdir -p "${dir}"
  cp "${REPO_ROOT}"/charts/ctf-user/*.sh "${dir}/"
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
  op_conf "${kind}"
  op_row_at() { # <line no> -> prints "<input decoded>"; sets OP_VERDICT
    local raw
    raw="$(sed -n "$1p" "${OP_TABLE}")"
    OP_VERDICT="${raw#*$'\t'}"
    decode "${raw%%$'\t'*}"
  }
  op_row_at "${want}"
  if op_check_row "${label}" "${dir}/deploy-user.sh" "${want}" "${kind}" "${OP_VERDICT}" "${DECODED}" 2>"${WORK}/opmut-${label}.err"; then
    fail "self-test ${label}: '${repl}' did not fail table line ${want}"
    return
  fi
  cl="$(awk -F'\t' -v v="${control}" '!/^#/ && NF >= 2 && $2 == v { print NR; exit }' "${OP_TABLE}")"
  op_row_at "${cl}"; cv="${DECODED}"; ctl="${OP_VERDICT}"
  if ! op_check_row "${label}" "${dir}/deploy-user.sh" "${cl}" "${kind}" "${ctl}" "${cv}" 2>"${WORK}/opmut-${label}-control.err"; then
    fail "self-test ${label}: the mutated copy also fails its control row (line ${cl}): it is broken everywhere, not on the row that matters"
    return
  fi
  pass "self-test ${label}: '$(printf '%s' "${repl}" | cut -c1-90)' fails table line ${want}: $(sed 's/^ *//' "${WORK}/opmut-${label}.err" | head -n 1 | cut -c1-140)"
}
# op_line <kind> <awk condition on $1 (input) and $2 (verdict)> -> the line number of the first
# matching row (empty if none: op_mutate then fails the self-test; no exit inside $(...)).
op_line() {
  op_conf "$1"
  awk -F'\t' "$2 { print NR; exit }" "${OP_TABLE}"
}
# <kind>_mutate <name> <broken pattern> <failing line> [control: accept (default) | reject]:
# a narrowing break rejects a good row, so its control is a reject row.
dns_mutate() { op_mutate dns "dns-$1" "DNS_SUFFIX_PATTERN='" "DNS_SUFFIX_PATTERN='$2'" "$3" "${4:-accept}"; }
reg_mutate() { op_mutate reg "reg-$1" "REGISTRY_PATTERN='" "REGISTRY_PATTERN='$2'" "$3" "${4:-accept}"; }
tag_mutate() { op_mutate tag "tag-$1" "IMAGE_TAG_PATTERN='" "IMAGE_TAG_PATTERN='$2'" "$3" "${4:-accept}"; }
cidr_mutate() { op_mutate cidr "cidr-$1" "API_SERVER_CIDR_PATTERN='" "API_SERVER_CIDR_PATTERN='$2'" "$3" "${4:-accept}"; }

DNS_LABEL='[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?'
dns_mutate any '^.*$' "$(op_line dns '$1 == "a,b=c"')"
dns_mutate no-dollar "^${DNS_LABEL}(\\.${DNS_LABEL})*" "$(op_line dns '$1 == "a.com{LF}"')"
dns_mutate no-caret "${DNS_LABEL}(\\.${DNS_LABEL})*\$" "$(op_line dns '$1 == "{LF}a.com"')"
dns_mutate upper "^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\$" "$(op_line dns '$1 == "A.com"')"
dns_mutate leading-hyphen "^[a-z0-9-]([a-z0-9-]{0,61}[a-z0-9])?(\\.${DNS_LABEL})*\$" "$(op_line dns '$1 == "-a.com"')"
dns_mutate trailing-dot "^${DNS_LABEL}(\\.${DNS_LABEL})*\\.?\$" "$(op_line dns '$1 == "example.com."')"
dns_mutate underscore "^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*\$" "$(op_line dns '$1 == "a_b.com"')"
dns_mutate label-wide "^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)*\$" "$(op_line dns 'length($1) == 64 && $2 == "reject"')"
dns_mutate label-narrow "^[a-z0-9]([a-z0-9-]{0,60}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,60}[a-z0-9])?)*\$" "$(op_line dns 'length($1) == 63 && $2 == "accept"')"
dns_mutate empty-label "^${DNS_LABEL}(\\.+${DNS_LABEL})*\$" "$(op_line dns '$1 == "a..b"')"
op_mutate dns dns-len-wide "DNS_SUFFIX_MAX_LEN='" "DNS_SUFFIX_MAX_LEN='254'" "$(op_line dns 'length($1) == 254 && $2 == "reject"')" accept
op_mutate dns dns-len-narrow "DNS_SUFFIX_MAX_LEN='" "DNS_SUFFIX_MAX_LEN='252'" "$(op_line dns 'length($1) == 253 && $2 == "accept"')" accept
op_mutate dns dns-check-removed '[[ -z "${DNS_SUFFIX}" ]] || check_operator_input' ':' "$(op_line dns '$1 == "a,b=c"')" accept

# The registry pattern, in pieces, so each break changes one thing. REG_TAIL is the ingest
# filter's part (the last component is falco-ctf); the other three are the shape.
REG_HOST='[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*'
REG_PORT='(:[0-9]{1,5})?'
REG_PATH='(/[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*)*'
REG_TAIL='/falco-ctf'
reg_mutate any '^.*$' "$(op_line reg '$1 == "a,b=c/falco-ctf"')"
reg_mutate no-dollar "^${REG_HOST}${REG_PORT}${REG_PATH}${REG_TAIL}" "$(op_line reg '$1 == "a.com/falco-ctf{LF}"')"
reg_mutate no-caret "${REG_HOST}${REG_PORT}${REG_PATH}${REG_TAIL}\$" "$(op_line reg '$1 == "{LF}a.com/falco-ctf"')"
reg_mutate old-charset '^[a-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)*/falco-ctf$' "$(op_line reg '$1 == "../falco-ctf"')"
reg_mutate dotdot-path "^${REG_HOST}${REG_PORT}(/[a-z0-9.]+((\\.|_|__|-+)[a-z0-9]+)*)*${REG_TAIL}\$" "$(op_line reg '$1 == "a.com/../falco-ctf"')"
reg_mutate trailing-slash "^${REG_HOST}${REG_PORT}${REG_PATH}${REG_TAIL}/?\$" "$(op_line reg '$1 == "a.com/falco-ctf/"')"
reg_mutate port-wide "^${REG_HOST}(:[0-9]+)?${REG_PATH}${REG_TAIL}\$" "$(op_line reg '$1 == "a.com:123456/falco-ctf"')"
reg_mutate colon-in-path "^${REG_HOST}${REG_PORT}(/[a-z0-9]+((\\.|_|__|-+|:)[a-z0-9]+)*)*${REG_TAIL}\$" "$(op_line reg '$1 == "a.com/x:tag/falco-ctf"')"
reg_mutate upper "^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*${REG_PORT}${REG_PATH}${REG_TAIL}\$" "$(op_line reg '$1 == "A.com/falco-ctf"')"
reg_mutate host-underscore "^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*${REG_PORT}${REG_PATH}${REG_TAIL}\$" "$(op_line reg '$1 == "a_b/falco-ctf"')"
# The ingest filter's part: without the `/falco-ctf` tail a registry the scoreboard would
# silently drop (every event of the workspace) is accepted.
reg_mutate no-ingest-tail "^${REG_HOST}${REG_PORT}${REG_PATH}\$" "$(op_line reg '$1 == "registry.local"')"
op_mutate reg reg-check-removed '[[ -z "${FALCO_CTF_REGISTRY:-}" ]] || check_operator_input' ':' "$(op_line reg '$1 == "a,b=c/falco-ctf"')" accept

tag_mutate any '^.*$' "$(op_line tag '$1 == "a,b=c"')"
tag_mutate no-dollar '^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}' "$(op_line tag '$1 == "a{LF}"')"
tag_mutate no-caret '[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$' "$(op_line tag '$1 == "{LF}a"')"
tag_mutate wide '^[A-Za-z0-9_][A-Za-z0-9._-]{0,128}$' "$(op_line tag 'length($1) == 129 && $2 == "reject"')"
tag_mutate narrow '^[A-Za-z0-9_][A-Za-z0-9._-]{0,126}$' "$(op_line tag 'length($1) == 128 && $2 == "accept"')"
tag_mutate leading-dot '^[A-Za-z0-9_.][A-Za-z0-9._-]{0,127}$' "$(op_line tag '$1 == ".a"')"
tag_mutate leading-hyphen '^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$' "$(op_line tag '$1 == "-a"')"
tag_mutate colon '^[A-Za-z0-9_][A-Za-z0-9._:-]{0,127}$' "$(op_line tag '$1 == "sha256:0123"')"
tag_mutate slash '^[A-Za-z0-9_][A-Za-z0-9._/-]{0,127}$' "$(op_line tag '$1 == "a/b"')"
op_mutate tag tag-check-removed '[[ -z "${FALCO_CTF_IMAGE_TAG:-}" ]] || check_operator_input' ':' "$(op_line tag '$1 == "a,b=c"')" accept

cidr_mutate any '^.*$' "$(op_line cidr '$1 == "10.0.0.1/32,10.0.0.2/32"')"
cidr_mutate no-dollar '^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])/(3[0-2]|[12]?[0-9])' "$(op_line cidr '$1 == "10.0.0.1/32{LF}"')"
cidr_mutate no-caret '((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])/(3[0-2]|[12]?[0-9])$' "$(op_line cidr '$1 == "{LF}10.0.0.1/32"')"
cidr_mutate octet-999 '^(([0-9]{1,3})\.){3}([0-9]{1,3})/(3[0-2]|[12]?[0-9])$' "$(op_line cidr '$1 == "256.0.0.1/32"')"
cidr_mutate prefix-wide '^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])/(3[0-9]|[12]?[0-9])$' "$(op_line cidr '$1 == "10.0.0.1/33"')"
cidr_mutate prefix-narrow '^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])/(3[0-1]|[12]?[0-9])$' "$(op_line cidr '$1 == "255.255.255.255/32"')" reject
cidr_mutate leading-zero '^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|0?[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|0?[1-9]?[0-9])/(3[0-2]|[12]?[0-9])$' "$(op_line cidr '$1 == "010.0.0.1/32"')"
cidr_mutate no-prefix '^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(/(3[0-2]|[12]?[0-9]))?$' "$(op_line cidr '$1 == "10.0.0.1"')"
cidr_mutate three-octets '^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){2,3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])/(3[0-2]|[12]?[0-9])$' "$(op_line cidr '$1 == "10.0.0/24"')"
op_mutate cidr cidr-check-removed '[[ -z "${API_SERVER_CIDR}" ]] || check_operator_input' ':' "$(op_line cidr '$1 == "10.0.0.1/32,10.0.0.2/32"')" accept

# --set-string -> --set: helm would type the value (`null` deletes the key) and read `,` / `=` in it.
op_mutate dns dns-set-not-set-string '  DNS_SUFFIX_ARGS+=(' '  DNS_SUFFIX_ARGS+=(--set "dnsSuffix=${DNS_SUFFIX}")' "$(op_line dns '$1 == "null"')" reject
op_mutate cidr cidr-set-not-set-string '  EGRESS_ARGS+=(--set-string "networkPolicy.egress.apiServerCidr=' '  EGRESS_ARGS+=(--set "networkPolicy.egress.apiServerCidr=${API_SERVER_CIDR}")' "$(op_line cidr '$1 == "10.100.0.1/32"')" reject
op_mutate reg reg-set-not-set-string-ttyd '  IMAGE_ARGS+=(--set-string "ttyd.image.repository=' '  IMAGE_ARGS+=(--set "ttyd.image.repository=${FALCO_CTF_REGISTRY}/ttyd")' "$(op_line reg '$1 == "docker.io/falco-ctf"')" reject
op_mutate reg reg-set-not-set-string-proxy '  IMAGE_ARGS+=(--set-string "ttyd.proxy.image.repository=' '  IMAGE_ARGS+=(--set "ttyd.proxy.image.repository=${FALCO_CTF_REGISTRY}/ttyd-proxy")' "$(op_line reg '$1 == "docker.io/falco-ctf"')" reject
op_mutate reg reg-set-not-set-string-challenge '  IMAGE_ARGS+=(--set-string "challenge.image.repository=' '  IMAGE_ARGS+=(--set "challenge.image.repository=${FALCO_CTF_REGISTRY}/challenge")' "$(op_line reg '$1 == "docker.io/falco-ctf"')" reject
op_mutate tag tag-set-not-set-string-ttyd '  IMAGE_ARGS+=(--set-string "ttyd.image.tag=' '  IMAGE_ARGS+=(--set "ttyd.image.tag=${FALCO_CTF_IMAGE_TAG}")' "$(op_line tag '$1 == "null"')" reject
op_mutate tag tag-set-not-set-string-proxy '  IMAGE_ARGS+=(--set-string "ttyd.proxy.image.tag=' '  IMAGE_ARGS+=(--set "ttyd.proxy.image.tag=${FALCO_CTF_IMAGE_TAG}")' "$(op_line tag '$1 == "null"')" reject
op_mutate tag tag-set-not-set-string-challenge '  IMAGE_ARGS+=(--set-string "challenge.image.tag=' '  IMAGE_ARGS+=(--set "challenge.image.tag=${FALCO_CTF_IMAGE_TAG}")' "$(op_line tag '$1 == "null"')" reject

if [[ "${RC}" -ne 0 ]]; then
  echo "deploy-user.sh id grammar check FAILED" >&2
  exit 1
fi
echo "deploy-user.sh id grammar check passed"
