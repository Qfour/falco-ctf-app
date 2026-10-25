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
# placeholder set).
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
# One printf per call = one write(2) of one whole line: `kubectl create ... | kubectl
# apply` runs two stubs at once, and a line written in pieces could interleave.
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

# run_deploy <deploy script> <username> [extra deploy-user.sh flags...] -> sets DEPLOY_STATUS
run_deploy() {
  local script="$1" user="$2"
  shift 2
  : > "${CALLS}"
  set +e
  PATH="${STUB_BIN}:${PATH}" CALLS_LOG="${CALLS}" \
    "${script}" --challenges-dir "${CHALLENGES}" ${1+"$@"} -- "${user}" all \
    >"${WORK}/deploy.out" 2>"${WORK}/deploy.err" </dev/null
  DEPLOY_STATUS=$?
  set -e
}

# check_accept_calls <line no> <seat> -> 0 if the recorded helm / kubectl calls
# derive every name from the seat the way ADR-0042 D3 says, else prints why. The
# comparison is exact (token by token), not "the seat appears somewhere": a
# release name with a prefix, or another namespace, must not pass.
check_accept_calls() {
  local lineno="$1" user="$2" line tok n_flags=0 i
  local -a toks
  line="$(grep -E '^helm upgrade ' "${CALLS}" | head -n 1 || true)"
  if [[ -z "${line}" ]]; then
    echo "    seat-cases.tsv:${lineno}: accept, but no helm upgrade call was recorded" >&2
    return 1
  fi
  read -r -a toks <<< "${line}"
  # `helm upgrade --install <release> <chart> -n <namespace> ...` (deploy-user.sh's own form)
  if [[ "${toks[0]}" != helm || "${toks[1]}" != upgrade || "${toks[2]}" != --install || "${toks[3]:-}" != "${user}" ]]; then
    echo "    seat-cases.tsv:${lineno}: accept, but the release is not the seat: want 'helm upgrade --install ${user} ', got '${toks[*]:0:4}'" >&2
    return 1
  fi
  for ((i = 4; i < ${#toks[@]}; i++)); do
    tok="${toks[i]}"
    if [[ "${tok}" == -n || "${tok}" == --namespace ]]; then
      n_flags=$((n_flags + 1))
      if [[ "${toks[i + 1]:-}" != "ctf-${user}" ]]; then
        echo "    seat-cases.tsv:${lineno}: accept, but the release namespace is not ctf-<seat>: want '${tok} ctf-${user}', got '${tok} ${toks[i + 1]:-}'" >&2
        return 1
      fi
    fi
  done
  if [[ "${n_flags}" -ne 1 ]]; then
    echo "    seat-cases.tsv:${lineno}: accept, but helm upgrade carries ${n_flags} namespace flags (want exactly one, -n ctf-<seat>)" >&2
    return 1
  fi
  if ! grep -qxF "kubectl create namespace ctf-${user} --dry-run=client -o yaml" "${CALLS}"; then
    echo "    seat-cases.tsv:${lineno}: accept, but the namespace the script creates is not exactly ctf-<seat>: $(grep -F 'kubectl create namespace' "${CALLS}" | head -n 1 | cut -c1-120)" >&2
    return 1
  fi
  if ! grep -E '^helm upgrade ' "${CALLS}" | grep -qF -- " --set-string username=${user} "; then
    echo "    seat-cases.tsv:${lineno}: accept, but helm upgrade did not carry --set-string username=<seat> verbatim" >&2
    return 1
  fi
  return 0
}

# check_row <deploy script> <line no> <verdict> <username> [extra flags...] -> 0
# if the script behaves as the row says, else prints why on stderr and returns 1.
check_row() {
  local script="$1" lineno="$2" verdict="$3" user="$4"
  shift 4
  run_deploy "${script}" "${user}" ${1+"$@"}
  if [[ "${verdict}" == accept ]]; then
    if [[ "${DEPLOY_STATUS}" -ne 97 ]]; then
      echo "    seat-cases.tsv:${lineno}: accept, but exit ${DEPLOY_STATUS} (want 97 = reached helm upgrade): $(tr '\n' ' ' < "${WORK}/deploy.err" | cut -c1-200)" >&2
      return 1
    fi
    check_accept_calls "${lineno}" "${user}" || return 1
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

# run_table <deploy script> [table] -> sets ROWS, ACCEPTED, REJECTED, BAD (rows
# that disagree) and BAD_LINES (" n n " : their line numbers in the table).
run_table() {
  local script="$1" table="${2:-${TABLE}}" line lineno=0 input verdict user
  ROWS=0 ACCEPTED=0 REJECTED=0 BAD=0 BAD_LINES=" "
  while IFS= read -r line || [[ -n "${line}" ]]; do
    lineno=$((lineno + 1))
    case "${line}" in ''|'#'*) continue ;; esac
    # First tab only (an empty input makes the line start with a tab).
    if [[ "${line}" != *$'\t'* ]]; then
      echo "    seat-cases.tsv:${lineno}: no tab" >&2; BAD=$((BAD + 1)); BAD_LINES="${BAD_LINES}${lineno} "; continue
    fi
    input="${line%%$'\t'*}"
    verdict="${line#*$'\t'}"
    case "${verdict}" in
      accept) ACCEPTED=$((ACCEPTED + 1)) ;;
      reject) REJECTED=$((REJECTED + 1)) ;;
      *) echo "    seat-cases.tsv:${lineno}: verdict must be accept|reject" >&2; BAD=$((BAD + 1)); BAD_LINES="${BAD_LINES}${lineno} "; continue ;;
    esac
    ROWS=$((ROWS + 1))
    decode "${input}"
    user="${DECODED}"
    # The placeholder set is closed (the table's header): a brace left after
    # decoding is an unknown placeholder, an error of this reader, not a verdict.
    case "${user}" in
      *'{'*|*'}'*)
        echo "    seat-cases.tsv:${lineno}: a brace is left after decoding: an unknown placeholder" >&2
        BAD=$((BAD + 1)); BAD_LINES="${BAD_LINES}${lineno} "; continue ;;
    esac
    check_row "${script}" "${lineno}" "${verdict}" "${user}" || { BAD=$((BAD + 1)); BAD_LINES="${BAD_LINES}${lineno} "; }
  done < "${table}"
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

echo "==> the check comes before kubectl on the --egress-lockdown path too"
LOCKDOWN=(--egress-lockdown --api-server-cidr 10.0.0.1/32)
# An accepted seat reaches helm upgrade with the flags (so the stub setup works
# and a reject below is not an artefact of a broken lockdown path) ...
if check_row "${DEPLOY}" 0 accept user1 "${LOCKDOWN[@]}" && grep -qF 'kubectl get svc kubernetes' "${CALLS}"; then
  pass "user1 with --egress-lockdown reaches helm upgrade (the ClusterIP lookup ran)"
else
  fail "user1 with --egress-lockdown did not reach helm upgrade as expected"
fi
# ... and a rejected one stops before the ClusterIP lookup: not one call.
for u in 'user1,username=x' 'User1' 'a=b'; do
  if check_row "${DEPLOY}" 0 reject "${u}" "${LOCKDOWN[@]}"; then
    pass "'${u}' with --egress-lockdown: exit 2, no kubectl / helm call"
  else
    fail "'${u}' with --egress-lockdown was not stopped before kubectl"
  fi
done

echo "==> self-test: a broken SEAT_PATTERN must be caught, on the row that breaks"
# line_of <awk condition on $1 (input) and $2 (verdict)> -> the table line number
line_of() {
  local n
  n="$(awk -F'\t' "$1 { print NR; exit }" "${TABLE}")"
  [[ -n "${n}" ]] || { echo "FAIL: no table row matches $1" >&2; exit 1; }
  printf '%s' "${n}"
}
# mutate_line <label> <line prefix> <replacement line> <expected failing line>:
# a copy of deploy-user.sh whose ONE line starting with <line prefix> is replaced,
# run against the table; the row at <expected failing line> must disagree.
mutate_line() {
  local dir="${WORK}/mut-$1/charts/ctf-user" l n=0
  mkdir -p "${dir}"
  cp "${REPO_ROOT}"/charts/ctf-user/*.sh "${dir}/"
  # Rewrite the one definition line (no sed -i: BSD and GNU differ).
  while IFS= read -r l; do
    case "${l}" in
      "$2"*) printf '%s\n' "$3"; n=$((n + 1)) ;;
      *) printf '%s\n' "${l}" ;;
    esac
  done < "${dir}/deploy-user.sh" > "${dir}/deploy-user.sh.new"
  if [[ "${n}" -ne 1 ]]; then
    fail "self-test $1: deploy-user.sh has ${n} lines starting with '$2' (want exactly 1 to mutate)"
    return
  fi
  mv "${dir}/deploy-user.sh.new" "${dir}/deploy-user.sh"
  chmod +x "${dir}/deploy-user.sh"
  run_table "${dir}/deploy-user.sh" 2>"${WORK}/mut-$1.err"
  case "${BAD_LINES}" in
    *" $4 "*) pass "self-test $1: '$3' fails table line $4 (${BAD} row(s) in all): $(grep -F "seat-cases.tsv:$4:" "${WORK}/mut-$1.err" | head -n 1 | sed 's/^ *//' | cut -c1-150)" ;;
    *) fail "self-test $1: '$3' did not fail table line $4 (failing lines:${BAD_LINES})" ;;
  esac
}
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

echo "==> self-test: an unknown placeholder makes the reader fail"
BADTABLE="${WORK}/unknown-placeholder.tsv"
printf 'user1\taccept\nuser{U+2028}1\treject\nuser1{LF\treject\n' > "${BADTABLE}"
run_table "${DEPLOY}" "${BADTABLE}" 2>"${WORK}/unknown.err"
if [[ "${BAD_LINES}" == " 2 3 " ]]; then
  pass "rows with an unknown / unclosed placeholder fail the reader (lines 2 and 3), the plain row does not"
else
  fail "an unknown placeholder did not fail the reader exactly on lines 2 and 3 (failing lines:${BAD_LINES})"
fi

if [[ "${RC}" -ne 0 ]]; then
  echo "seat grammar check FAILED" >&2
  exit 1
fi
echo "seat grammar check passed"
