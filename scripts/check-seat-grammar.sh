#!/usr/bin/env bash
# The shell copy of the seat grammar (app#480, ADR-0034 D2): runs every row of
# internal/identity/testdata/seat-cases.tsv through charts/ctf-user/deploy-user.sh
# and checks the verdict. No cluster, no helm, no docker: stub `helm` / `kubectl`
# on PATH only record their invocations.
#
#   accept row -> deploy-user.sh gets as far as `helm upgrade` (the stub exits 97
#                 there). The recorded calls are compared EXACTLY: the release
#                 name is the seat (`helm upgrade --install <seat> ...`), the
#                 release namespace is `ctf-<seat>` (one `-n ctf-<seat>`), the
#                 namespace the script creates is `ctf-<seat>`, and the chart gets
#                 `--set-string username=<seat>` verbatim. This is where the
#                 derivation of the release name and the namespace from the seat
#                 is held (ADR-0042 D3 / V2); seat_render_test.go (V4) renders the
#                 chart with the same names and relies on this check for them.
#   reject row -> exit 2 with the reason on stderr and NOT ONE helm / kubectl
#                 call (an empty seat is the usage error, exit 1, same rule).
#                 The seat is never echoed raw: a bidi control in the row must
#                 not reach the terminal.
#
# The Go side reads the same table (internal/identity/seat_cases_test.go, which
# also pins the text of SEAT_PATTERN to identity.SeatPattern). Platform's roster
# tooling reads it in its paired PR.
#
# Also: a rejected seat is stopped before kubectl on the --egress-lockdown path
# (which runs a kubectl before anything else), not only on the plain one.
#
# Self-test: the same table is run against copies of deploy-user.sh whose
# SEAT_PATTERN is broken six ways (accepts anything / one character too wide /
# one too narrow / a trailing hyphen allowed / no end anchor / no start anchor),
# and the derivation of the release name / namespace from the seat two ways (a
# prefix on RELEASE / another namespace); each must fail the table row that the
# break is about, or this check proves nothing and fails. A row with a
# placeholder the reader does not know makes the reader fail (the table's closed
# placeholder set: scripts/test-casetable-lib.sh).
#
# The table reader (placeholder decode, table walk, mutate_line) is
# scripts/lib/casetable.sh and the stub helm / kubectl harness is
# scripts/lib/deploy-user-harness.sh, both shared with scripts/check-deploy-user-ids.sh
# (app#509); what stays here is this grammar's check_row and its mutations.
#
# Every expectation is an exit status or an exact string, never "some output
# appeared". Usage: ./scripts/check-seat-grammar.sh   (make check-flags; CI flag-guard)
set -euo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
# shellcheck source=lib/casetable.sh
source "${REPO_ROOT}/scripts/lib/casetable.sh"
# shellcheck source=lib/deploy-user-harness.sh
source "${REPO_ROOT}/scripts/lib/deploy-user-harness.sh"
TABLE="${REPO_ROOT}/internal/identity/testdata/seat-cases.tsv"
DEPLOY="${REPO_ROOT}/charts/ctf-user/deploy-user.sh"
DEPLOY_REL="charts/ctf-user/deploy-user.sh"
CHALLENGES="${REPO_ROOT}/challenges"
MIN_ROWS=40

ct_init "${REPO_ROOT}"
ct_init_stubs

[[ -f "${TABLE}" ]] || { echo "FAIL: ${TABLE} not found" >&2; exit 1; }

# run_deploy <deploy script> <username> [extra deploy-user.sh flags...] -> sets RUN_STATUS
run_deploy() {
  local script="$1" user="$2"
  shift 2
  ct_run "${script}" --challenges-dir "${CHALLENGES}" ${1+"$@"} -- "${user}" all
}

# check_accept_calls <where> <seat> -> 0 if the recorded helm / kubectl calls
# derive every name from the seat the way ADR-0042 D3 says, else prints why. The
# comparison is exact (token by token), not "the seat appears somewhere": a
# release name with a prefix, or another namespace, must not pass.
check_accept_calls() {
  local where="$1" user="$2" line tok n_flags=0 i
  local -a toks
  line="$(ct_upgrade_call)"
  if [[ -z "${line}" ]]; then
    echo "    ${where}: accept, but no helm upgrade call was recorded" >&2
    return 1
  fi
  read -r -a toks <<< "${line}"
  # `helm upgrade --install <release> <chart> -n <namespace> ...` (deploy-user.sh's own form)
  if [[ "${toks[0]}" != helm || "${toks[1]}" != upgrade || "${toks[2]}" != --install || "${toks[3]:-}" != "${user}" ]]; then
    echo "    ${where}: accept, but the release is not the seat: want 'helm upgrade --install ${user} ', got '${toks[*]:0:4}'" >&2
    return 1
  fi
  for ((i = 4; i < ${#toks[@]}; i++)); do
    tok="${toks[i]}"
    if [[ "${tok}" == -n || "${tok}" == --namespace ]]; then
      n_flags=$((n_flags + 1))
      if [[ "${toks[i + 1]:-}" != "ctf-${user}" ]]; then
        echo "    ${where}: accept, but the release namespace is not ctf-<seat>: want '${tok} ctf-${user}', got '${tok} ${toks[i + 1]:-}'" >&2
        return 1
      fi
    fi
  done
  if [[ "${n_flags}" -ne 1 ]]; then
    echo "    ${where}: accept, but helm upgrade carries ${n_flags} namespace flags (want exactly one, -n ctf-<seat>)" >&2
    return 1
  fi
  if ! grep -qxF "kubectl create namespace ctf-${user} --dry-run=client -o yaml" "${CT_CALLS}"; then
    echo "    ${where}: accept, but the namespace the script creates is not exactly ctf-<seat>: $(grep -F 'kubectl create namespace' "${CT_CALLS}" | head -n 1 | cut -c1-120)" >&2
    return 1
  fi
  if ! grep -E '^helm upgrade ' "${CT_CALLS}" | grep -qF -- " --set-string username=${user} "; then
    echo "    ${where}: accept, but helm upgrade did not carry --set-string username=<seat> verbatim" >&2
    return 1
  fi
  return 0
}

# check_row <label> <line no> <verdict> <username> <deploy script> [extra flags...]
# (the ct_run_table row function) -> 0 if the script behaves as the row says, else
# prints why on stderr and returns 1.
check_row() {
  local label="$1" lineno="$2" verdict="$3" user="$4" script="$5"
  shift 5
  run_deploy "${script}" "${user}" ${1+"$@"}
  if [[ "${verdict}" == accept ]]; then
    ct_check_reached_upgrade "${label}:${lineno}" || return 1
    check_accept_calls "${label}:${lineno}" "${user}" || return 1
    return 0
  fi
  ct_check_reject "${label}:${lineno}" "${user}" 'invalid username'
}

echo "==> deploy-user.sh against the shared seat-case table"
ct_expect_table "seat-cases.tsv" "${MIN_ROWS}" 10 20 "${TABLE}" check_row "${DEPLOY}"

echo "==> the check comes before kubectl on the --egress-lockdown path too"
LOCKDOWN=(--egress-lockdown --api-server-cidr 10.0.0.1/32)
# An accepted seat reaches helm upgrade with the flags (so the stub setup works
# and a reject below is not an artefact of a broken lockdown path) ...
if check_row seat-cases.tsv 0 accept user1 "${DEPLOY}" "${LOCKDOWN[@]}" && grep -qF 'kubectl get svc kubernetes' "${CT_CALLS}"; then
  pass "user1 with --egress-lockdown reaches helm upgrade (the ClusterIP lookup ran)"
else
  fail "user1 with --egress-lockdown did not reach helm upgrade as expected"
fi
# ... and a rejected one stops before the ClusterIP lookup: not one call.
for u in 'user1,username=x' 'User1' 'a=b'; do
  if check_row seat-cases.tsv 0 reject "${u}" "${DEPLOY}" "${LOCKDOWN[@]}"; then
    pass "'${u}' with --egress-lockdown: exit 2, no kubectl / helm call"
  else
    fail "'${u}' with --egress-lockdown was not stopped before kubectl"
  fi
done

echo "==> self-test: a broken SEAT_PATTERN must be caught, on the row that breaks"
run_mutant() { ct_run_table "${TABLE}" check_row "$1"; }
line_of() { ct_line_of "${TABLE}" "$1" || true; }
mutate_line() { ct_mutate_line "$1" "${DEPLOY_REL}" "$2" "$3" "$4" run_mutant; }
mutate() { # <label> <replacement pattern> <expected failing line>
  mutate_line "$1" "SEAT_PATTERN='" "SEAT_PATTERN='$2'" "$3"
}
mutate any '^.*$' "$(line_of '$1 == "user1,username=x"')"
mutate wide '^[a-z0-9]([a-z0-9-]{0,52}[a-z0-9])?$' "$(line_of 'length($1) == 54 && $2 == "reject"')"
mutate narrow '^[a-z0-9]([a-z0-9-]{0,50}[a-z0-9])?$' "$(line_of 'length($1) == 53 && $2 == "accept"')"
mutate trailing-dash '^[a-z0-9][a-z0-9-]{0,52}$' "$(line_of '$1 == "a-"')"
mutate no-dollar '^[a-z0-9]([a-z0-9-]{0,51}[a-z0-9])?' "$(line_of '$1 == "user1{LF}"')"
mutate no-caret '[a-z0-9]([a-z0-9-]{0,51}[a-z0-9])?$' "$(line_of '$1 == "-user1"')"
# The derivation of the release name and the namespace from the seat (deploy-user.sh
# RELEASE= / NS=) is held by the accept rows' exact comparison of the recorded calls.
mutate_line release-prefix 'RELEASE="' 'RELEASE="x-${USERNAME}"' "$(line_of '$1 == "user1" && $2 == "accept"')"
mutate_line namespace-changed 'NS="' 'NS="ctfx-${USERNAME}"' "$(line_of '$1 == "user1" && $2 == "accept"')"

ct_finish "seat grammar check"
