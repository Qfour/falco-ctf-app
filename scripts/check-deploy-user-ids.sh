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
# row the break is about, parse (bash -n) and leave its control rows as they were
# (app#522), or this check proves nothing and fails. A row with a
# placeholder the reader does not know makes the reader fail (the closed set:
# scripts/test-casetable-lib.sh).
#
# The table reader (placeholder decode, table walk, mutate_line) is
# scripts/lib/casetable.sh and the stub helm / kubectl harness is
# scripts/lib/deploy-user-harness.sh, both shared with scripts/check-seat-grammar.sh
# (app#509); what stays here is this grammar's check_row, its scratch tree and its
# mutations.
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
# each check, and turns each --set-string back into --set (each mutant runs its own row and
# its control rows only: ct_run_mutant_rows).
#
# app#520 (ADR-0044) adds `--frame-ancestors` and `--app-host` (the last section): the
# frame-ancestors table (internal/ttydproxy/testdata/frame-ancestors-cases.tsv) goes through
# `--frame-ancestors <input>`, the dns-suffix table (the same grammar) through
# `--app-host <input>`, each with the same exact-token and no-bare-`--set` verdicts, and a
# table of (frame-ancestors, app-host) pairs holds D3: not 'none' means exactly
# https://<app-host>, else exit 2 `ADR-0044 D3`, before any kubectl / helm call. Its
# self-test breaks the pattern (anchors, http, 'self', a wildcard, a port, a path, case, a bare
# none, several sources, a `,`), both bounds, each check, each --set-string and the pairing.
#
# Every expectation is an exit status or an exact string, never "some output
# appeared". Usage: ./scripts/check-deploy-user-ids.sh   (make check-flags; CI flag-guard)
set -euo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
# shellcheck source=lib/casetable.sh
source "${REPO_ROOT}/scripts/lib/casetable.sh"
# shellcheck source=lib/deploy-user-harness.sh
source "${REPO_ROOT}/scripts/lib/deploy-user-harness.sh"
CID_TABLE="${REPO_ROOT}/internal/catalog/challengeid/testdata/challenge-id-cases.tsv"
SCN_TABLE="${REPO_ROOT}/internal/catalog/testdata/scenario-name-cases.tsv"
DNS_TABLE="${REPO_ROOT}/internal/catalog/testdata/dns-suffix-cases.tsv"
REG_TABLE="${REPO_ROOT}/internal/catalog/testdata/image-registry-cases.tsv"
TAG_TABLE="${REPO_ROOT}/internal/catalog/testdata/image-tag-cases.tsv"
CIDR_TABLE="${REPO_ROOT}/internal/catalog/testdata/api-server-cidr-cases.tsv"
FA_TABLE="${REPO_ROOT}/internal/ttydproxy/testdata/frame-ancestors-cases.tsv"
DEPLOY="${REPO_ROOT}/charts/ctf-user/deploy-user.sh"
DEPLOY_REL="charts/ctf-user/deploy-user.sh"

ct_init "${REPO_ROOT}"
ct_init_stubs
# The real FALCO_CTF_* of the operator running this check must not reach any row (before
# run_deploy is defined, so no run of deploy-user.sh below can see them).
unset FALCO_CTF_REGISTRY FALCO_CTF_IMAGE_TAG

for f in "${CID_TABLE}" "${SCN_TABLE}" "${DEPLOY}" "${DNS_TABLE}" "${REG_TABLE}" "${TAG_TABLE}" "${CIDR_TABLE}" "${FA_TABLE}"; do
  [[ -f "${f}" ]] || { echo "FAIL: ${f} not found" >&2; exit 1; }
done

# run_deploy <deploy script> <challenge-id argument as given> <make dirs: 1|0> [extra flags...]
# -> sets RUN_STATUS. With <make dirs> = 1 a scratch challenges dir and scenarios
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
  ct_run "${script}" --challenges-dir "${cdir}" --scenarios-dir "${sdir}" ${1+"$@"} -- user1 "${arg}"
}

# check_arg <label> <line no> <verdict> <argument as given> <message> <deploy script> [extra flags...]
# -> 0 if the script behaves as the row says, else prints why on stderr and returns 1.
# <message> is the stderr marker of a rejection (`invalid challenge id` / `invalid scenario name`).
check_arg() {
  local label="$1" lineno="$2" verdict="$3" arg="$4" msg="$5" script="$6" call
  shift 6
  if [[ "${verdict}" == accept ]]; then
    run_deploy "${script}" "${arg}" 1 ${1+"$@"}
    ct_check_reached_upgrade "${label}:${lineno}" || return 1
    # Exact: token ` --set-string challengeId=<arg> ` (the call is `$*`, so a value
    # with a space or a newline cannot be an accept row: none is one).
    call="$(ct_upgrade_call)"
    if ! grep -qF -- " --set-string challengeId=${arg} " <<< "${call}"; then
      echo "    ${label}:${lineno}: accept, but helm upgrade did not carry --set-string challengeId=<id> verbatim: ${call:0:200}" >&2
      return 1
    fi
    return 0
  fi
  run_deploy "${script}" "${arg}" 0 ${1+"$@"}
  ct_check_reject "${label}:${lineno}" "${arg}" "${msg}"
}

# The ct_run_table row functions: the table's input is the id (cid) or the name
# AFTER `scenario:` (scn).
cid_row() { local l="$1" n="$2" v="$3" a="$4"; shift 4; check_arg "${l}" "${n}" "${v}" "${a}" "invalid challenge id" "$@"; }
scn_row() { local l="$1" n="$2" v="$3" a="$4"; shift 4; check_arg "${l}" "${n}" "${v}" "scenario:${a}" "invalid scenario name" "$@"; }

echo "==> deploy-user.sh against the shared challenge-id and scenario-name case tables"
ct_expect_table "challenge-id-cases.tsv" 50 10 40 "${CID_TABLE}" cid_row "${DEPLOY}"
ct_expect_table "scenario-name-cases.tsv" 40 10 25 "${SCN_TABLE}" scn_row "${DEPLOY}"

echo "==> the fixed word is not an id: 'all' still reaches helm upgrade"
if check_arg all-mode 0 accept all "invalid challenge id" "${DEPLOY}"; then
  pass "'all' reaches helm upgrade with --set-string challengeId=all"
else
  fail "'all' did not reach helm upgrade as expected"
fi

echo "==> the check comes before kubectl on the --egress-lockdown path too"
LOCKDOWN=(--egress-lockdown --api-server-cidr 10.0.0.1/32)
# An accepted id reaches helm upgrade with the flags (so the stub setup works and a
# reject below is not an artefact of a broken lockdown path) ...
if check_arg lockdown 0 accept 01-initial-recon "invalid challenge id" "${DEPLOY}" "${LOCKDOWN[@]}" && grep -qF 'kubectl get svc kubernetes' "${CT_CALLS}"; then
  pass "01-initial-recon with --egress-lockdown reaches helm upgrade (the ClusterIP lookup ran)"
else
  fail "01-initial-recon with --egress-lockdown did not reach helm upgrade as expected"
fi
# ... and a rejected one stops before the ClusterIP lookup: not one call.
for u in '01-a,b=c' '..' '01-A'; do
  if check_arg lockdown 0 reject "${u}" "invalid challenge id" "${DEPLOY}" "${LOCKDOWN[@]}"; then
    pass "'${u}' with --egress-lockdown: exit 2, no kubectl / helm call"
  else
    fail "'${u}' with --egress-lockdown was not stopped before kubectl"
  fi
done
for u in 'scenario:a,b=c' 'scenario:..' 'scenario:'; do
  if check_arg lockdown 0 reject "${u}" "invalid scenario name" "${DEPLOY}" "${LOCKDOWN[@]}"; then
    pass "'${u}' with --egress-lockdown: exit 2, no kubectl / helm call"
  else
    fail "'${u}' with --egress-lockdown was not stopped before kubectl"
  fi
done

echo "==> self-test: a broken pattern, or --set instead of --set-string, must be caught, on the row that breaks"
run_cid_mutant() { ct_run_table "${CID_TABLE}" cid_row "$1"; }
run_scn_mutant() { ct_run_table "${SCN_TABLE}" scn_row "$1"; }
# <cid|scn> <awk condition on $1 (input) and $2 (verdict)> -> the table line number
line_of() {
  if [[ "$1" == cid ]]; then ct_line_of "${CID_TABLE}" "$2" || true; else ct_line_of "${SCN_TABLE}" "$2" || true; fi
}
# <cid|scn>_mutate <name> <broken pattern> <failing line> [ct_mutate_line options...]
cid_mutate() {
  local name="$1" pat="$2" want="$3"
  shift 3
  ct_mutate_line ${1+"$@"} "cid-${name}" "${DEPLOY_REL}" "CHALLENGE_ID_PATTERN='" "CHALLENGE_ID_PATTERN='${pat}'" "${want}" run_cid_mutant
}
scn_mutate() {
  local name="$1" pat="$2" want="$3"
  shift 3
  ct_mutate_line ${1+"$@"} "scn-${name}" "${DEPLOY_REL}" "SCENARIO_PATTERN='" "SCENARIO_PATTERN='${pat}'" "${want}" run_scn_mutant
}

# A break that flips every reject row by design (accepts anything, a check removed) is held by
# an accept row only; one that flips many reject rows names a reject row it must leave alone;
# one that flips every accept row (--set) names a reject row and the reason (--must).
cid_mutate any '^.*$' "$(line_of cid '$1 == "01-a,b=c"')" --control accept
cid_mutate old-charset '^[0-9]{2}-[A-Za-z0-9._-]{1,60}$' "$(line_of cid '$1 == "01-.."')"
cid_mutate wide '^[0-9]{2}-[a-z0-9-]{1,61}$' "$(line_of cid 'length($1) == 64 && $2 == "reject"')"
cid_mutate narrow '^[0-9]{2}-[a-z0-9-]{1,59}$' "$(line_of cid 'length($1) == 63 && $2 == "accept"')"
cid_mutate empty-slug '^[0-9]{2}-[a-z0-9-]{0,60}$' "$(line_of cid '$1 == "12-"')"
cid_mutate one-digit '^[0-9]{1,2}-[a-z0-9-]{1,60}$' "$(line_of cid '$1 == "1-a"')"
cid_mutate no-dollar '^[0-9]{2}-[a-z0-9-]{1,60}' "$(line_of cid '$1 == "01-a{LF}"')"
cid_mutate no-caret '[0-9]{2}-[a-z0-9-]{1,60}$' "$(line_of cid '$1 == "../01-a"')"
scn_mutate any '^.*$' "$(line_of scn '$1 == "a,b=c"')" --control accept
scn_mutate old-charset '^[A-Za-z0-9._-]+$' "$(line_of scn '$1 == ".."')" --control accept --control "$(line_of scn '$1 == "a/b"')"
scn_mutate slash '^[a-z0-9/-]+$' "$(line_of scn '$1 == "a/b"')" --control accept --control "$(line_of scn '$1 == ".."')"
scn_mutate wide '^[a-z0-9]([a-z0-9-]{0,53}[a-z0-9])?$' "$(line_of scn 'length($1) == 55 && $2 == "reject"')"
scn_mutate narrow '^[a-z0-9]([a-z0-9-]{0,51}[a-z0-9])?$' "$(line_of scn 'length($1) == 54 && $2 == "accept"')"
scn_mutate trailing-dash '^[a-z0-9][a-z0-9-]{0,53}$' "$(line_of scn '$1 == "a-"')"
scn_mutate empty '^[a-z0-9-]*$' "$(line_of scn '$1 == "" && $2 == "reject"')" --control accept --control "$(line_of scn '$1 == ".."')"
scn_mutate no-dollar '^[a-z0-9]([a-z0-9-]{0,52}[a-z0-9])?' "$(line_of scn '$1 == "a{LF}"')"
scn_mutate no-caret '[a-z0-9]([a-z0-9-]{0,52}[a-z0-9])?$' "$(line_of scn '$1 == "-a"')"
# --set-string -> --set: helm would type the value and read `,` / `=` in it.
ct_mutate_line --control reject --must 'did not carry --set-string challengeId=<id> verbatim' \
  cid-set-not-set-string "${DEPLOY_REL}" '  --set-string "challengeId=' '  --set "challengeId=${CHALLENGE_ID}" \' "$(line_of cid '$1 == "00-tutorial"')" run_cid_mutant

# ============================================================================
# app#510: the other operator inputs (--dns-suffix, FALCO_CTF_REGISTRY,
# FALCO_CTF_IMAGE_TAG, --api-server-cidr). They stand on the same two layers as the
# grammars above (ct_run_table / ct_expect_table / ct_mutate_line, run_deploy and the stubs).
# ============================================================================
# The one ` --set ` token a helm call may carry: a boolean the script writes itself.
OP_ALLOWED_SET=' --set networkPolicy.egress.enabled=true'

# op_conf <dns|reg|tag|cidr|fa|host> -> OP_TABLE, OP_MSG (the stderr marker of a rejection).
op_conf() {
  case "$1" in
    dns)  OP_TABLE="${DNS_TABLE}";  OP_MSG="invalid --dns-suffix" ;;
    reg)  OP_TABLE="${REG_TABLE}";  OP_MSG="invalid FALCO_CTF_REGISTRY" ;;
    tag)  OP_TABLE="${TAG_TABLE}";  OP_MSG="invalid FALCO_CTF_IMAGE_TAG" ;;
    cidr) OP_TABLE="${CIDR_TABLE}"; OP_MSG="invalid --api-server-cidr" ;;
    fa)   OP_TABLE="${FA_TABLE}";   OP_MSG="invalid --frame-ancestors" ;;
    host) OP_TABLE="${DNS_TABLE}";  OP_MSG="invalid --app-host" ;;
    *) echo "FAIL: op_conf: unknown kind $1" >&2; exit 1 ;;
  esac
}

# op_run <script> <kind> <value> -> RUN_STATUS. The value goes in the way the real
# caller passes it: a flag (dns, cidr) or the environment (reg, tag), next to a valid
# challenge id whose directory exists, so a reject can only be the grammar.
op_run() {
  local script="$1" kind="$2" value="$3"
  case "${kind}" in
    dns)  run_deploy "${script}" 00-tutorial 1 --dns-suffix "${value}" ;;
    cidr) run_deploy "${script}" 00-tutorial 1 --egress-lockdown --api-server-cidr "${value}" ;;
    reg)  FALCO_CTF_REGISTRY="${value}" run_deploy "${script}" 00-tutorial 1 ;;
    tag)  FALCO_CTF_IMAGE_TAG="${value}" run_deploy "${script}" 00-tutorial 1 ;;
    fa)   run_deploy "${script}" 00-tutorial 1 --frame-ancestors "${value}" ;;
    host) run_deploy "${script}" 00-tutorial 1 --app-host "${value}" ;;
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
    fa)   printf ' --set-string ttyd.frameAncestors=%s \n' "${v}" ;;
    host) printf ' --set-string auth.appHost=%s \n' "${v}" ;;
  esac
}

# op_row <label> <line no> <verdict> <value> <kind> <script> (the ct_run_table row function)
# -> 0 if deploy-user.sh behaves as the row says, else the reason on stderr and 1.
op_row() {
  local label="$1" lineno="$2" verdict="$3" value="$4" kind="$5" script="$6" tok call stray
  op_conf "${kind}"
  # No table has an empty row: an empty flag value is the flag parser's usage error and an
  # empty env value means "not set"; neither is a verdict of the grammar.
  if [[ -z "${value}" ]]; then
    echo "    ${label}:${lineno}: an empty value is not a verdict of this grammar" >&2
    return 1
  fi
  op_run "${script}" "${kind}" "${value}"
  if [[ "${verdict}" == accept ]]; then
    ct_check_reached_upgrade "${label}:${lineno}" || return 1
    call="$(grep -E '^helm upgrade ' "${CT_CALLS}" || true) "
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
  # Always a non-empty value here, so exit 2 (never the empty-argument usage error).
  ct_check_reject "${label}:${lineno}" "${value}" "${OP_MSG}"
}

echo "==> deploy-user.sh against the operator-input case tables (app#510)"
ct_expect_table "dns-suffix-cases.tsv" 50 15 30 "${DNS_TABLE}" op_row dns "${DEPLOY}"
ct_expect_table "image-registry-cases.tsv" 80 14 60 "${REG_TABLE}" op_row reg "${DEPLOY}"
ct_expect_table "image-tag-cases.tsv" 50 15 25 "${TAG_TABLE}" op_row tag "${DEPLOY}"
ct_expect_table "api-server-cidr-cases.tsv" 65 15 45 "${CIDR_TABLE}" op_row cidr "${DEPLOY}"

echo "==> a bad --api-server-cidr is refused without --egress-lockdown too (a set value is never ignored quietly)"
for u in '10.0.0.1/33' 'a,b=c' '10.0.0.1/32,10.0.0.2/32'; do
  run_deploy "${DEPLOY}" 00-tutorial 1 --api-server-cidr "${u}"
  if [[ "${RUN_STATUS}" -eq 2 && ! -s "${CT_CALLS}" ]] && grep -qF 'invalid --api-server-cidr' "${CT_RUN_ERR}"; then
    pass "'${u}' without --egress-lockdown: exit 2, no kubectl / helm call"
  else
    fail "'${u}' without --egress-lockdown was not refused before kubectl (exit ${RUN_STATUS})"
  fi
done

echo "==> all four good together: the helm call carries every value as --set-string and no other --set"
op_all_good() {
  FALCO_CTF_REGISTRY='000000000000.dkr.ecr.us-east-1.amazonaws.com/falco-ctf' FALCO_CTF_IMAGE_TAG='0123456789abcdef0123456789abcdef01234567' \
    run_deploy "${DEPLOY}" 00-tutorial 1 --dns-suffix ctf.192.168.64.2.nip.io --egress-lockdown --api-server-cidr 10.100.0.1/32
  local c k
  [[ "${RUN_STATUS}" -eq 97 ]] || { echo "    exit ${RUN_STATUS}, want 97" >&2; return 1; }
  c="$(grep -E '^helm upgrade ' "${CT_CALLS}" || true) "
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
# op_mutate <kind> <label> <line prefix> <replacement line> <failing line> [ct_mutate_line options...]:
# ct_mutate_line on deploy-user.sh. The runner walks only the row at <failing line> and the
# control rows (ct_run_mutant_rows: 53 mutants, not 53 whole tables); ct_mutate_line judges
# them (the failing row disagrees, every control row still agrees).
op_mutate() {
  local kind="$1" label="$2" prefix="$3" repl="$4" want="$5"
  shift 5
  OP_KIND="${kind}"
  ct_mutate_line ${1+"$@"} "${label}" "${DEPLOY_REL}" "${prefix}" "${repl}" "${want}" op_mutant_runner
}
op_mutant_runner() { # <mutant script>
  op_conf "${OP_KIND}"
  ct_run_mutant_rows "${OP_TABLE}" op_row "${OP_KIND}" "$1"
}
# op_line <kind> <awk condition on $1 (input) and $2 (verdict)> -> the line number of the first
# matching row (empty if none: op_mutate then fails the self-test; no exit inside $(...)).
op_line() {
  op_conf "$1"
  awk -F'\t' "$2 { print NR; exit }" "${OP_TABLE}"
}
# op_set_mutate <kind> <label> <line prefix> <replacement line> <failing line> <key>: the
# `--set-string <key>=` of the line turned back into --set. Every accept row loses that token,
# so the control is a reject row and the failing row must be red for that token.
op_set_mutate() { op_mutate "$1" "$2" "$3" "$4" "$5" --control reject --must "lacks the token ' --set-string $6="; }
# <kind>_mutate <name> <broken pattern> <failing line> [ct_mutate_line options...]
dns_mutate() { local n="$1" p="$2" w="$3"; shift 3; op_mutate dns "dns-${n}" "DNS_SUFFIX_PATTERN='" "DNS_SUFFIX_PATTERN='${p}'" "${w}" ${1+"$@"}; }
reg_mutate() { local n="$1" p="$2" w="$3"; shift 3; op_mutate reg "reg-${n}" "REGISTRY_PATTERN='" "REGISTRY_PATTERN='${p}'" "${w}" ${1+"$@"}; }
tag_mutate() { local n="$1" p="$2" w="$3"; shift 3; op_mutate tag "tag-${n}" "IMAGE_TAG_PATTERN='" "IMAGE_TAG_PATTERN='${p}'" "${w}" ${1+"$@"}; }
cidr_mutate() { local n="$1" p="$2" w="$3"; shift 3; op_mutate cidr "cidr-${n}" "API_SERVER_CIDR_PATTERN='" "API_SERVER_CIDR_PATTERN='${p}'" "${w}" ${1+"$@"}; }

DNS_LABEL='[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?'
dns_mutate any '^.*$' "$(op_line dns '$1 == "a,b=c"')" --control accept
dns_mutate no-dollar "^${DNS_LABEL}(\\.${DNS_LABEL})*" "$(op_line dns '$1 == "a.com{LF}"')" --control accept --control "$(op_line dns '$1 == "{LF}a.com"')"
dns_mutate no-caret "${DNS_LABEL}(\\.${DNS_LABEL})*\$" "$(op_line dns '$1 == "{LF}a.com"')" --control accept --control "$(op_line dns '$1 == "a.com{LF}"')"
dns_mutate upper "^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\$" "$(op_line dns '$1 == "A.com"')"
dns_mutate leading-hyphen "^[a-z0-9-]([a-z0-9-]{0,61}[a-z0-9])?(\\.${DNS_LABEL})*\$" "$(op_line dns '$1 == "-a.com"')"
dns_mutate trailing-dot "^${DNS_LABEL}(\\.${DNS_LABEL})*\\.?\$" "$(op_line dns '$1 == "example.com."')"
dns_mutate underscore "^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*\$" "$(op_line dns '$1 == "a_b.com"')"
dns_mutate label-wide "^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)*\$" "$(op_line dns 'length($1) == 64 && $2 == "reject"')" \
  --control accept --control "$(op_line dns 'length($1) == 254 && $2 == "reject"')"
dns_mutate label-narrow "^[a-z0-9]([a-z0-9-]{0,60}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,60}[a-z0-9])?)*\$" "$(op_line dns 'length($1) == 63 && $2 == "accept"')"
dns_mutate empty-label "^${DNS_LABEL}(\\.+${DNS_LABEL})*\$" "$(op_line dns '$1 == "a..b"')"
op_mutate dns dns-len-wide "DNS_SUFFIX_MAX_LEN='" "DNS_SUFFIX_MAX_LEN='254'" "$(op_line dns 'length($1) == 254 && $2 == "reject"')"
op_mutate dns dns-len-narrow "DNS_SUFFIX_MAX_LEN='" "DNS_SUFFIX_MAX_LEN='252'" "$(op_line dns 'length($1) == 253 && $2 == "accept"')"
op_mutate dns dns-check-removed '[[ -z "${DNS_SUFFIX}" ]] || check_operator_input' ':' "$(op_line dns '$1 == "a,b=c"')" --control accept

# The registry pattern, in pieces, so each break changes one thing. REG_TAIL is the ingest
# filter's part (the last component is falco-ctf); the other three are the shape.
REG_HOST='[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*'
REG_PORT='(:[0-9]{1,5})?'
REG_PATH='(/[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*)*'
REG_TAIL='/falco-ctf'
reg_mutate any '^.*$' "$(op_line reg '$1 == "a,b=c/falco-ctf"')" --control accept
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
reg_mutate no-ingest-tail "^${REG_HOST}${REG_PORT}${REG_PATH}\$" "$(op_line reg '$1 == "registry.local"')" \
  --control accept --control "$(op_line reg '$1 == "a.com/../falco-ctf"')"
op_mutate reg reg-check-removed '[[ -z "${FALCO_CTF_REGISTRY:-}" ]] || check_operator_input' ':' "$(op_line reg '$1 == "a,b=c/falco-ctf"')" --control accept

tag_mutate any '^.*$' "$(op_line tag '$1 == "a,b=c"')" --control accept
tag_mutate no-dollar '^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}' "$(op_line tag '$1 == "a{LF}"')" --control accept --control "$(op_line tag '$1 == "{LF}a"')"
tag_mutate no-caret '[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$' "$(op_line tag '$1 == "{LF}a"')" --control accept --control "$(op_line tag '$1 == "a{LF}"')"
tag_mutate wide '^[A-Za-z0-9_][A-Za-z0-9._-]{0,128}$' "$(op_line tag 'length($1) == 129 && $2 == "reject"')" --control accept --control "$(op_line tag '$1 == ".a"')"
tag_mutate narrow '^[A-Za-z0-9_][A-Za-z0-9._-]{0,126}$' "$(op_line tag 'length($1) == 128 && $2 == "accept"')"
tag_mutate leading-dot '^[A-Za-z0-9_.][A-Za-z0-9._-]{0,127}$' "$(op_line tag '$1 == ".a"')"
tag_mutate leading-hyphen '^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$' "$(op_line tag '$1 == "-a"')"
tag_mutate colon '^[A-Za-z0-9_][A-Za-z0-9._:-]{0,127}$' "$(op_line tag '$1 == "sha256:0123"')"
tag_mutate slash '^[A-Za-z0-9_][A-Za-z0-9._/-]{0,127}$' "$(op_line tag '$1 == "a/b"')"
op_mutate tag tag-check-removed '[[ -z "${FALCO_CTF_IMAGE_TAG:-}" ]] || check_operator_input' ':' "$(op_line tag '$1 == "a,b=c"')" --control accept

cidr_mutate any '^.*$' "$(op_line cidr '$1 == "10.0.0.1/32,10.0.0.2/32"')" --control accept
cidr_mutate no-dollar '^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])/(3[0-2]|[12]?[0-9])' "$(op_line cidr '$1 == "10.0.0.1/32{LF}"')"
cidr_mutate no-caret '((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])/(3[0-2]|[12]?[0-9])$' "$(op_line cidr '$1 == "{LF}10.0.0.1/32"')" \
  --control accept --control "$(op_line cidr '$1 == "10.0.0.1/32{LF}"')"
cidr_mutate octet-999 '^(([0-9]{1,3})\.){3}([0-9]{1,3})/(3[0-2]|[12]?[0-9])$' "$(op_line cidr '$1 == "256.0.0.1/32"')" --control accept --control "$(op_line cidr '$1 == "10.0.0.1/33"')"
cidr_mutate prefix-wide '^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])/(3[0-9]|[12]?[0-9])$' "$(op_line cidr '$1 == "10.0.0.1/33"')"
cidr_mutate prefix-narrow '^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])/(3[0-1]|[12]?[0-9])$' "$(op_line cidr '$1 == "255.255.255.255/32"')" \
  --control "$(op_line cidr '$1 == "199.199.199.199/31"')" --control reject
cidr_mutate leading-zero '^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|0?[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|0?[1-9]?[0-9])/(3[0-2]|[12]?[0-9])$' "$(op_line cidr '$1 == "010.0.0.1/32"')"
cidr_mutate no-prefix '^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(/(3[0-2]|[12]?[0-9]))?$' "$(op_line cidr '$1 == "10.0.0.1"')"
cidr_mutate three-octets '^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){2,3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])/(3[0-2]|[12]?[0-9])$' "$(op_line cidr '$1 == "10.0.0/24"')"
op_mutate cidr cidr-check-removed '[[ -z "${API_SERVER_CIDR}" ]] || check_operator_input' ':' "$(op_line cidr '$1 == "10.0.0.1/32,10.0.0.2/32"')" --control accept

# --set-string -> --set: helm would type the value (`null` deletes the key) and read `,` / `=` in it.
op_set_mutate dns dns-set-not-set-string '  DNS_SUFFIX_ARGS+=(' '  DNS_SUFFIX_ARGS+=(--set "dnsSuffix=${DNS_SUFFIX}")' "$(op_line dns '$1 == "null"')" dnsSuffix
op_set_mutate cidr cidr-set-not-set-string '  EGRESS_ARGS+=(--set-string "networkPolicy.egress.apiServerCidr=' '  EGRESS_ARGS+=(--set "networkPolicy.egress.apiServerCidr=${API_SERVER_CIDR}")' "$(op_line cidr '$1 == "10.100.0.1/32"')" networkPolicy.egress.apiServerCidr
op_set_mutate reg reg-set-not-set-string-ttyd '  IMAGE_ARGS+=(--set-string "ttyd.image.repository=' '  IMAGE_ARGS+=(--set "ttyd.image.repository=${FALCO_CTF_REGISTRY}/ttyd")' "$(op_line reg '$1 == "docker.io/falco-ctf"')" ttyd.image.repository
op_set_mutate reg reg-set-not-set-string-proxy '  IMAGE_ARGS+=(--set-string "ttyd.proxy.image.repository=' '  IMAGE_ARGS+=(--set "ttyd.proxy.image.repository=${FALCO_CTF_REGISTRY}/ttyd-proxy")' "$(op_line reg '$1 == "docker.io/falco-ctf"')" ttyd.proxy.image.repository
op_set_mutate reg reg-set-not-set-string-challenge '  IMAGE_ARGS+=(--set-string "challenge.image.repository=' '  IMAGE_ARGS+=(--set "challenge.image.repository=${FALCO_CTF_REGISTRY}/challenge")' "$(op_line reg '$1 == "docker.io/falco-ctf"')" challenge.image.repository
op_set_mutate tag tag-set-not-set-string-ttyd '  IMAGE_ARGS+=(--set-string "ttyd.image.tag=' '  IMAGE_ARGS+=(--set "ttyd.image.tag=${FALCO_CTF_IMAGE_TAG}")' "$(op_line tag '$1 == "null"')" ttyd.image.tag
op_set_mutate tag tag-set-not-set-string-proxy '  IMAGE_ARGS+=(--set-string "ttyd.proxy.image.tag=' '  IMAGE_ARGS+=(--set "ttyd.proxy.image.tag=${FALCO_CTF_IMAGE_TAG}")' "$(op_line tag '$1 == "null"')" ttyd.proxy.image.tag
op_set_mutate tag tag-set-not-set-string-challenge '  IMAGE_ARGS+=(--set-string "challenge.image.tag=' '  IMAGE_ARGS+=(--set "challenge.image.tag=${FALCO_CTF_IMAGE_TAG}")' "$(op_line tag '$1 == "null"')" challenge.image.tag


# ============================================================================
# app#520 (ADR-0044): --frame-ancestors and --app-host. The same two layers as above (the
# op_* functions take two more kinds: fa = the frame-ancestors table through --frame-ancestors,
# host = the dns-suffix table through --app-host, the same grammar) plus the pairing rule D3.
# ============================================================================
echo "==> deploy-user.sh against the frame-ancestors table (--frame-ancestors) and the dns-suffix table (--app-host) (app#520)"
ct_expect_table "frame-ancestors-cases.tsv" 70 10 50 "${FA_TABLE}" op_row fa "${DEPLOY}"
ct_expect_table "dns-suffix-cases.tsv as --app-host" 50 15 30 "${DNS_TABLE}" op_row host "${DEPLOY}"

# D3, as a table of its own (a pair is two inputs, so it is not a row of either grammar's
# table): `<frame-ancestors> <app-host>` (neither holds a space) and the verdict. Both are
# valid on their own in every row; only the pairing decides.
PAIR_TABLE="${WORK}/frame-ancestors-app-host-pairs.tsv"
{
  echo "# pattern: n/a (pairs of --frame-ancestors and --app-host; ADR-0044 D3)"
  printf '%s\t%s\n' \
    "https://app.x.example app.x.example" accept \
    "'none' app.x.example" accept \
    "'none' a.b" accept \
    "https://a a" accept \
    "https://localhost localhost" accept \
    "https://other.x.example app.x.example" reject \
    "https://app.x.example other.x.example" reject \
    "https://app.x.example x.example" reject \
    "https://x.example app.x.example" reject \
    "https://sub.app.x.example app.x.example" reject \
    "https://app.x.example.y app.x.example" reject \
    "https://app.x.example app.x.example.y" reject \
    "https://localhost 1.2.3.4" reject
} > "${PAIR_TABLE}"

# pair_row <label> <line no> <verdict> <"<frame-ancestors> <app-host>"> <script> (a ct_run_table row function)
pair_row() {
  local label="$1" lineno="$2" verdict="$3" pair="$4" script="$5" fa host call tok
  fa="${pair%% *}"; host="${pair#* }"
  run_deploy "${script}" 00-tutorial 1 --frame-ancestors "${fa}" --app-host "${host}"
  if [[ "${verdict}" == accept ]]; then
    ct_check_reached_upgrade "${label}:${lineno}" || return 1
    call="$(grep -E '^helm upgrade ' "${CT_CALLS}" || true) "
    for tok in " --set-string ttyd.frameAncestors=${fa} " " --set-string auth.appHost=${host} "; do
      case "${call}" in
        *"${tok}"*) ;;
        *) echo "    ${label}:${lineno}: accept, but helm upgrade lacks the token '${tok}': $(printf '%s' "${call}" | cut -c1-240)" >&2; return 1 ;;
      esac
    done
    return 0
  fi
  ct_check_reject "${label}:${lineno}" "${fa}" "ADR-0044 D3"
}
echo "==> D3: given both, a frame-ancestors other than 'none' must be exactly https://<app-host>"
ct_expect_table "frame-ancestors / app-host pairs" 13 5 8 "${PAIR_TABLE}" pair_row "${DEPLOY}"

echo "==> D3 is checked before kubectl on the --egress-lockdown path too, and one flag alone is only held to its own grammar"
run_deploy "${DEPLOY}" 00-tutorial 1 --egress-lockdown --api-server-cidr 10.0.0.1/32 --frame-ancestors https://other.x.example --app-host app.x.example
if [[ "${RUN_STATUS}" -eq 2 && ! -s "${CT_CALLS}" ]] && grep -qF 'ADR-0044 D3' "${CT_RUN_ERR}"; then
  pass "a mismatched pair with --egress-lockdown: exit 2, no kubectl / helm call"
else
  fail "a mismatched pair with --egress-lockdown was not stopped before kubectl (exit ${RUN_STATUS})"
fi
run_deploy "${DEPLOY}" 00-tutorial 1 --frame-ancestors https://other.x.example
if [[ "${RUN_STATUS}" -eq 97 ]]; then pass "--frame-ancestors alone (not 'none') is held to its own grammar only"; else fail "--frame-ancestors alone was refused (exit ${RUN_STATUS})"; fi
run_deploy "${DEPLOY}" 00-tutorial 1 --app-host app.x.example
if [[ "${RUN_STATUS}" -eq 97 ]]; then pass "--app-host alone is held to its own grammar only"; else fail "--app-host alone was refused (exit ${RUN_STATUS})"; fi

echo "==> self-test (app#520): a broken pattern, bound, check, --set-string or pairing must be caught on the row that breaks it"
FA_NONE="'none'"
FA_HOST='[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*'
FA_NONE_COND="\$1 == \"${FA_NONE}\""
# fa_mutate <name> <broken pattern> <failing line> [ct_mutate_line options...]. The literal is
# double quoted (it holds a single quote), so the mutant line is too.
fa_mutate() { local n="$1" p="$2" w="$3"; shift 3; op_mutate fa "fa-${n}" 'FRAME_ANCESTORS_PATTERN="' "FRAME_ANCESTORS_PATTERN=\"${p}\"" "${w}" ${1+"$@"}; }
FA_ACC=(--control accept --control "$(op_line fa '$1 == "*"')")
fa_mutate any '^.*$' "$(op_line fa '$1 == "*"')" --control accept
fa_mutate no-dollar "^(${FA_NONE}|https://${FA_HOST})" "$(op_line fa '$1 == "https://a.example{LF}"')" "${FA_ACC[@]}"
fa_mutate no-caret "(${FA_NONE}|https://${FA_HOST})\$" "$(op_line fa '$1 == "{LF}https://a.example"')" "${FA_ACC[@]}"
fa_mutate http "^(${FA_NONE}|https?://${FA_HOST})\$" "$(op_line fa '$1 == "http://app.x.example"')" "${FA_ACC[@]}"
fa_mutate scheme-alone "^(${FA_NONE}|https:(//${FA_HOST})?)\$" "$(op_line fa '$1 == "https:"')" "${FA_ACC[@]}"
fa_mutate self "^(${FA_NONE}|'self'|https://${FA_HOST})\$" "$(op_line fa '$1 == "'"'self'"'"')" "${FA_ACC[@]}"
fa_mutate wildcard "^(${FA_NONE}|https://[a-z0-9*]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9*]([a-z0-9-]{0,61}[a-z0-9])?)*)\$" "$(op_line fa '$1 == "https://*.x.example"')" "${FA_ACC[@]}"
fa_mutate wildcard-alone "^(${FA_NONE}|\\*|https://${FA_HOST})\$" "$(op_line fa '$1 == "*"')" --control accept --control "$(op_line fa '$1 == "https://*.x.example"')"
fa_mutate port "^(${FA_NONE}|https://${FA_HOST}(:[0-9]+)?)\$" "$(op_line fa '$1 == "https://app.x.example:8443"')" "${FA_ACC[@]}"
fa_mutate path "^(${FA_NONE}|https://${FA_HOST}/?)\$" "$(op_line fa '$1 == "https://app.x.example/"')" "${FA_ACC[@]}"
fa_mutate userinfo "^(${FA_NONE}|https://([a-z0-9]+@)?${FA_HOST})\$" "$(op_line fa '$1 == "https://u@a.example"')" "${FA_ACC[@]}"
fa_mutate upper "^(${FA_NONE}|https://[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*)\$" "$(op_line fa '$1 == "https://APP.x.example"')" "${FA_ACC[@]}"
fa_mutate none-upper "^('[nN][oO][nN][eE]'|https://${FA_HOST})\$" "$(op_line fa '$1 == "'"'NONE'"'"')" "${FA_ACC[@]}"
fa_mutate none-bare "^(${FA_NONE}|none|https://${FA_HOST})\$" "$(op_line fa '$1 == "none"')" "${FA_ACC[@]}"
fa_mutate two-sources "^(${FA_NONE}|https://${FA_HOST}( https://${FA_HOST})*)\$" "$(op_line fa '$1 == "https://a.example https://b.example"')" "${FA_ACC[@]}"
fa_mutate comma "^(${FA_NONE}|https://${FA_HOST}(,.*)?)\$" "$(op_line fa '$1 == "https://a.example,ttyd.x=y"')" "${FA_ACC[@]}"
fa_mutate semicolon "^(${FA_NONE}|https://${FA_HOST}(;.*)?)\$" "$(op_line fa '$1 == "https://a.example;script-src *"')" "${FA_ACC[@]}"
fa_mutate label-wide "^(${FA_NONE}|https://[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)*)\$" "$(op_line fa 'length($1) == 72 && $2 == "reject"')" "${FA_ACC[@]}"
fa_mutate label-narrow "^(${FA_NONE}|https://[a-z0-9]([a-z0-9-]{0,60}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,60}[a-z0-9])?)*)\$" "$(op_line fa 'length($1) == 71 && $2 == "accept"')"
fa_mutate trailing-dot "^(${FA_NONE}|https://${FA_HOST}\\.?)\$" "$(op_line fa '$1 == "https://a.example."')" "${FA_ACC[@]}"
op_mutate fa fa-len-wide 'FRAME_ANCESTORS_MAX_LEN=' "FRAME_ANCESTORS_MAX_LEN='262'" "$(op_line fa 'length($1) == 262 && $2 == "reject"')"
op_mutate fa fa-len-narrow 'FRAME_ANCESTORS_MAX_LEN=' "FRAME_ANCESTORS_MAX_LEN='260'" "$(op_line fa 'length($1) == 261 && $2 == "accept"')"
op_mutate fa fa-check-removed '[[ -z "${FRAME_ANCESTORS}" ]] || check_operator_input' ':' "$(op_line fa '$1 == "*"')" --control accept
op_mutate fa fa-len-removed '[[ -z "${FRAME_ANCESTORS}" ]] || check_operator_input' \
  '[[ -z "${FRAME_ANCESTORS}" ]] || check_operator_input "--frame-ancestors" "${FRAME_ANCESTORS}" "${FRAME_ANCESTORS_PATTERN}"' "$(op_line fa 'length($1) == 262 && $2 == "reject"')"

# --app-host reads the --dns-suffix literals (no new one): a check of its own that is wider, has no bound, or is gone is caught on the dns table's rows.
op_mutate host host-check-removed '[[ -z "${APP_HOST}" ]] || check_operator_input' ':' "$(op_line host '$1 == "a,b=c"')" --control accept
op_mutate host host-pattern-wide '[[ -z "${APP_HOST}" ]] || check_operator_input' \
  '[[ -z "${APP_HOST}" ]] || check_operator_input "--app-host" "${APP_HOST}" '"'^.*\$'"' "${DNS_SUFFIX_MAX_LEN}"' "$(op_line host '$1 == "a,b=c"')" --control accept
op_mutate host host-len-removed '[[ -z "${APP_HOST}" ]] || check_operator_input' \
  '[[ -z "${APP_HOST}" ]] || check_operator_input "--app-host" "${APP_HOST}" "${DNS_SUFFIX_PATTERN}"' "$(op_line host 'length($1) == 254 && $2 == "reject"')"
op_mutate host host-scheme-allowed '[[ -z "${APP_HOST}" ]] || check_operator_input' \
  '[[ -z "${APP_HOST}" ]] || check_operator_input "--app-host" "${APP_HOST}" '"'^(https?://)?[a-z0-9.-]+\$'"' "${DNS_SUFFIX_MAX_LEN}"' "$(op_line host '$1 == "http://a.com"')" --control accept

# --set-string -> --set: helm would type the value and read `,` / `=` in it.
op_set_mutate fa fa-set-not-set-string '  FRAME_ANCESTORS_ARGS+=(' '  FRAME_ANCESTORS_ARGS+=(--set "ttyd.frameAncestors=${FRAME_ANCESTORS}")' "$(op_line fa "${FA_NONE_COND}")" ttyd.frameAncestors
op_set_mutate host host-set-not-set-string '  APP_HOST_ARGS+=(' '  APP_HOST_ARGS+=(--set "auth.appHost=${APP_HOST}")' "$(op_line host '$1 == "null"')" auth.appHost

# D3, on the pairs: no check, no exemption of 'none' wanted, the exemption too wide, a prefix compare, or a compare that
# needs only one of the two (each is caught on the pair that breaks it).
pair_line() { ct_line_of "${PAIR_TABLE}" "$1" || true; }
pair_runner() { ct_run_mutant_rows "${PAIR_TABLE}" pair_row "$1"; }
pair_mutate() { local n="$1" repl="$2" w="$3"; shift 3; ct_mutate_line ${1+"$@"} "d3-${n}" "${DEPLOY_REL}" 'if [[ -n "${APP_HOST}" && -n "${FRAME_ANCESTORS}" &&' "${repl}" "${w}" pair_runner; }
pair_mutate removed 'if false; then' "$(pair_line '$1 == "https://other.x.example app.x.example"')" --control accept
pair_mutate none-not-exempt 'if [[ -n "${APP_HOST}" && -n "${FRAME_ANCESTORS}" && "${FRAME_ANCESTORS}" != "https://${APP_HOST}" ]]; then' "$(pair_line '$1 == "'"'none'"' app.x.example"')" --control accept --control reject
pair_mutate everything-exempt 'if [[ -n "${APP_HOST}" && -n "${FRAME_ANCESTORS}" && "${FRAME_ANCESTORS}" != "'"'none'"'" && "${FRAME_ANCESTORS}" != "https://${APP_HOST}" && 0 -eq 1 ]]; then' "$(pair_line '$1 == "https://other.x.example app.x.example"')" --control accept
pair_mutate prefix-compare 'if [[ -n "${APP_HOST}" && -n "${FRAME_ANCESTORS}" && "${FRAME_ANCESTORS}" != "'"'none'"'" && "${FRAME_ANCESTORS}" != "https://${APP_HOST}"* ]]; then' "$(pair_line '$1 == "https://app.x.example.y app.x.example"')" --control accept --control reject
pair_mutate host-only 'if [[ -n "${APP_HOST}" && -n "${FRAME_ANCESTORS}" && "${FRAME_ANCESTORS}" != "'"'none'"'" && "${FRAME_ANCESTORS}" != *"${APP_HOST}" ]]; then' "$(pair_line '$1 == "https://sub.app.x.example app.x.example"')" --control accept --control reject

ct_finish "deploy-user.sh id grammar check"
