#!/usr/bin/env bash
# Self-test for ADR-0026 V4 — the deploy-time missions allowlist assert
# (check 3-8 in charts/ctf-user/assert-flag-isolation.sh, called by
# deploy-user.sh right after `helm upgrade --wait`). No cluster, no docker:
# a stub `kubectl` on PATH runs the REAL in-workspace probe payload (the
# `sh -c` string the assert sends) against a fake filesystem root, by
# rewriting the probe's absolute paths into that root. So what is tested is
# the shipped probe and the shipped judgment, not a copy of them.
#
# Cases (every expectation is an exit status plus an exact diagnostic string
# naming the offending path, never "some output appeared"):
#   good image                      -> exit 0 (all / single / scenario)
#   fixtures' CONTENTS are not opened -> a README.md inside fixtures/ is fine
#   extra file in <id>/             -> exit != 0   (README.md, .dotfile, name with a space)
#   extra / missing id              -> exit != 0   (both directions)
#   file / symlink / dot entry at the top level -> exit != 0
#   fixtures missing / a symlink    -> exit != 0
#   empty or absent missions dir    -> exit != 0   (0 entries never passes)
#   forged-protocol file name       -> exit != 0   (a name carrying a newline + KEY=VALUE)
#   kubectl exec failure            -> exit != 0   (a failing probe is not "clean")
#   truncated probe output          -> exit != 0   (3-0: no PROBE_END sentinel)
#   no catalog id in the checkout   -> exit != 0   (an empty expectation never matches)
#   scenario mode                   -> exactly the scenario's ids; one extra id fails
#   3-9 / 3-10 (ADR-0056 D11 "3-x", A5d; V8, V2): over values that
#   challenges/gen-values.sh itself generates for two investigate challenges, a
#   clean root and the expected Secrets pass in all / scenario / single mode, and
#   the evidence scope the assert reads is the one deploy-user.sh's
#   evidence_scope_cids reads; a symlink (also a dot one or a dangling one), a
#   directory, an empty or missing mount directory, a probe that judged fewer
#   directories than it was sent, a Secret too many or too few (either family),
#   a Secret of another type, an unreadable listing, a failed `kubectl get`, a
#   missing values file and an evidence entry not in gen-values.sh's form each
#   exit != 0 with their own diagnostic
#
# The stub kubectl answers `get secrets` with FAKE_SECRETS (name TAB type lines;
# default: ctf-flags and one Helm release record) or fails with FAKE_SECRETS_FAIL=1.
#
# Usage: ./scripts/check-missions-allowlist-assert.sh   (make check-flags; CI flag-guard)
set -euo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
ASSERT="${REPO_ROOT}/charts/ctf-user/assert-flag-isolation.sh"
# deploy-user.sh's reader of a values file's investigate scope: the 3-9 / 3-10 cases hold
# the assert's own (builtin-only) reader to it
# shellcheck source=charts/ctf-user/evidence-bundle.sh
source "${REPO_ROOT}/charts/ctf-user/evidence-bundle.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

RC=0
CASES=0
fail() { echo "  FAIL: $1" >&2; RC=1; }
pass() { echo "  ok:   $1"; }

# --- stub kubectl -----------------------------------------------------------
# `exec ... -c ttyd ...`      -> exit 0 (or 1 when FAKE_TTYD_FAIL=1)
# `exec ... -c challenge -- sh -c <payload>` -> run the payload with the probe's
# absolute paths rewritten into $FAKE_ROOT. FAKE_KUBECTL_FAIL=1 makes it fail.
mkdir -p "${WORK}/bin"
cat >"${WORK}/bin/kubectl" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
[[ "${FAKE_KUBECTL_FAIL:-0}" != 1 ]] || { echo "stub kubectl: forced failure" >&2; exit 1; }
# `-n <ns> get secrets -o jsonpath=...` (3-10): name TAB type, one Secret per line
if [[ "${3:-}" == get ]]; then
  [[ "${4:-}" == secrets ]] || { echo "stub kubectl: unexpected get '${4:-}'" >&2; exit 2; }
  [[ "${FAKE_SECRETS_FAIL:-0}" != 1 ]] || { echo "stub kubectl: forced get failure" >&2; exit 1; }
  if [[ -n "${FAKE_SECRETS+x}" ]]; then
    printf '%s\n' "${FAKE_SECRETS}"
  else
    printf 'ctf-flags\tOpaque\nsh.helm.release.v1.user1.v1\thelm.sh/release.v1\n'
  fi
  exit 0
fi
container=""
prev=""
for a in "$@"; do
  if [[ "${prev}" == "-c" && -z "${container}" ]]; then container="${a}"; fi
  prev="${a}"
done
case "${container}" in
  ttyd) [[ "${FAKE_TTYD_FAIL:-0}" != 1 ]]; exit ;;
  challenge) ;;
  *) echo "stub kubectl: unexpected container '${container}'" >&2; exit 2 ;;
esac
payload="${!#}"
# FAKE_TRUNCATE=1: the probe "forgets" its last line (a cut-off exec stream).
if [[ "${FAKE_TRUNCATE:-0}" == 1 ]]; then
  needle="printf 'PROBE_END=yes\\n'"
  [[ "${payload}" == *"${needle}"* ]] || { echo "stub kubectl: sentinel line not found in payload" >&2; exit 2; }
  payload="${payload//"${needle}"/true}"
fi
payload="${payload//\/opt\/ctf\/missions/${FAKE_ROOT}/opt/ctf/missions}"
payload="${payload//\/etc\/shadow/${FAKE_ROOT}/etc/shadow}"
payload="${payload//\/root\/.ssh/${FAKE_ROOT}/root/.ssh}"
payload="${payload//\/var\/run\/secrets/${FAKE_ROOT}/var/run/secrets}"
payload="${payload//\/proc\/1\/environ/${FAKE_ROOT}/proc1-environ}"
payload="${payload//\/plant-seed/${FAKE_ROOT}/plant-seed}"
payload="${payload//\/opt\/ctf\/evidence-src/${FAKE_ROOT}/opt/ctf/evidence-src}"
# the evidence mount directories of the fixtures (3-9), sent on the payload's first line
payload="${payload//\/opt\/fx/${FAKE_ROOT}/opt/fx}"
if [[ -n "${FAKE_EXTRA_LINES:-}" ]]; then
  sh -c "${payload}"
  printf '%s\n' "${FAKE_EXTRA_LINES}"
  exit
fi
exec sh -c "${payload}"
STUB
chmod +x "${WORK}/bin/kubectl"

# --- fixture builders -------------------------------------------------------
# Synthetic checkout: three challenges + a non-challenge dir (decks/, no
# falco-rule.yaml: must NOT become an expected id). No plant.sh anywhere, so
# the assert expects 0 planted shadow lines and no ssh key.
CH="${WORK}/challenges"
mkdir -p "${CH}/decks"
for id in 01-alpha 02-beta 03-gamma; do
  mkdir -p "${CH}/${id}"
  printf 'challengeId: %s\n' "${id}" >"${CH}/${id}/falco-rule.yaml"
done
SC="${WORK}/scenarios"
mkdir -p "${SC}/two"
printf 'name: two\nchallenges:\n  - 01-alpha\n  - 02-beta\n' >"${SC}/two/scenario.yaml"
# The values file of the scope (3-9 / 3-10 read its evidence entries; deploy-user.sh gives
# it to helm). No investigate challenge here, so the only Secret expected is ctf-flags.
NOEV_VALUES=$'plant:\n  seedScript: [sh, -c, "true"]\n  mounts: []\n'
printf '%s' "${NOEV_VALUES}" >"${CH}/values-all.yaml"
printf '%s' "${NOEV_VALUES}" >"${CH}/values-scenario-two.yaml"

# newroot <name> [ids...] -> $WORK/<name>, a good fake image root holding ids
newroot() {
  local root="${WORK}/$1"
  shift
  rm -rf "${root}"
  mkdir -p "${root}/opt/ctf/missions" "${root}/etc" "${root}/root"
  : >"${root}/etc/shadow"
  local id
  for id in "$@"; do
    mkdir -p "${root}/opt/ctf/missions/${id}/fixtures"
    printf 'x\n' >"${root}/opt/ctf/missions/${id}/fixtures/welcome.txt"
  done
  printf '%s' "${root}"
}

# expect <accept|reject> <label> <needle> <root> <challenges-dir> <challenge-id> [scenarios-dir]
expect() {
  local verdict="$1" label="$2" needle="$3" root="$4" chdir="$5" cid="$6" scdir="${7:-}"
  local out="${WORK}/out.$$" rc
  CASES=$((CASES + 1))
  set +e
  PATH="${WORK}/bin:${PATH}" FAKE_ROOT="${root}" \
    "${ASSERT}" ns-test "${chdir}" "${cid}" ${scdir:+"${scdir}"} >"${out}" 2>&1
  rc=$?
  set -e
  if [[ "${verdict}" == accept ]]; then
    if [[ "${rc}" -ne 0 ]]; then
      fail "${label}: expected exit 0, got ${rc}: $(tr '\n' ' ' <"${out}")"
    elif ! grep -qF 'OK — 3-1..3-8 clean' "${out}"; then
      fail "${label}: exit 0 but no '3-1..3-8 clean' line: $(tr '\n' ' ' <"${out}")"
    else
      pass "${label}"
    fi
    return
  fi
  if [[ "${rc}" -eq 0 ]]; then
    fail "${label}: expected non-zero exit, got 0 (violation not caught): $(tr '\n' ' ' <"${out}")"
  elif [[ -n "${needle}" ]] && ! grep -qF -- "${needle}" "${out}"; then
    fail "${label}: exit ${rc} but diagnostic lacks '${needle}': $(tr '\n' ' ' <"${out}")"
  else
    pass "${label}"
  fi
}

M() { printf '%s/opt/ctf/missions' "$1"; }

echo "==> 3-8 (ADR-0026 V4): all / single mode"
r="$(newroot good 01-alpha 02-beta 03-gamma)"
expect accept "all: exact id set, fixtures only" '' "$r" "${CH}" all
expect accept "single mission: the image still holds the FULL id set" '' "$r" "${CH}" 02-beta

r="$(newroot fixtures-inner 01-alpha 02-beta 03-gamma)"
mkdir -p "$(M "$r")/01-alpha/fixtures/deep"
: >"$(M "$r")/01-alpha/fixtures/deep/README.md"
expect accept "all: anything INSIDE fixtures/ is not opened (V4: contents are V1/V5's job)" '' "$r" "${CH}" all

r="$(newroot extra-readme 01-alpha 02-beta 03-gamma)"
: >"$(M "$r")/02-beta/README.md"
expect reject "all: README.md beside fixtures/" '02-beta/README.md' "$r" "${CH}" all

r="$(newroot extra-journey 01-alpha 02-beta 03-gamma)"
: >"$(M "$r")/03-gamma/journey.yaml"
expect reject "all: journey.yaml beside fixtures/" '03-gamma/journey.yaml' "$r" "${CH}" all

r="$(newroot extra-dot-in-id 01-alpha 02-beta 03-gamma)"
: >"$(M "$r")/01-alpha/.hidden"
expect reject "all: dot file inside <id>/" '01-alpha/.hidden' "$r" "${CH}" all

r="$(newroot extra-dotdot-in-id 01-alpha 02-beta 03-gamma)"
: >"$(M "$r")/01-alpha/..hidden"
expect reject "all: ..dot file inside <id>/ (the second dot glob)" '01-alpha/..hidden' "$r" "${CH}" all

r="$(newroot extra-space 01-alpha 02-beta 03-gamma)"
: >"$(M "$r")/01-alpha/a b"
expect reject "all: file name with a space inside <id>/" '01-alpha/<bad-name>' "$r" "${CH}" all

r="$(newroot missing-id 01-alpha 03-gamma)"
expect reject "all: an id of the checkout is missing from the image" 'expected exactly [01-alpha 02-beta 03-gamma]' "$r" "${CH}" all

r="$(newroot extra-id 01-alpha 02-beta 03-gamma 99-extra)"
expect reject "all: an id the checkout does not know" 'contains [01-alpha 02-beta 03-gamma 99-extra]' "$r" "${CH}" all

r="$(newroot top-file 01-alpha 02-beta 03-gamma)"
: >"$(M "$r")/README.md"
expect reject "all: a file at the top level" 'not a plain directory: [README.md]' "$r" "${CH}" all

r="$(newroot top-dsstore 01-alpha 02-beta 03-gamma)"
: >"$(M "$r")/.DS_Store"
expect reject "all: .DS_Store at the top level (dot entry)" 'not a plain directory: [.DS_Store]' "$r" "${CH}" all

r="$(newroot top-dotdir 01-alpha 02-beta 03-gamma)"
mkdir -p "$(M "$r")/.git/fixtures"
expect reject "all: a dot DIRECTORY at the top level is an unexpected id" 'contains [01-alpha 02-beta 03-gamma .git]' "$r" "${CH}" all

r="$(newroot top-symlink 01-alpha 02-beta 03-gamma)"
rm -rf "$(M "$r")/03-gamma"
ln -s 01-alpha "$(M "$r")/03-gamma"
expect reject "all: an id that is a symlink to a directory" 'not a plain directory: [03-gamma]' "$r" "${CH}" all

r="$(newroot top-dangling 01-alpha 02-beta 03-gamma)"
ln -s /nonexistent "$(M "$r")/dangling"
expect reject "all: a dangling symlink at the top level" 'not a plain directory: [dangling]' "$r" "${CH}" all

r="$(newroot fixtures-missing 01-alpha 02-beta 03-gamma)"
rm -rf "$(M "$r")/02-beta/fixtures"
expect reject "all: an id without fixtures/" '02-beta/fixtures:missing' "$r" "${CH}" all

r="$(newroot fixtures-symlink 01-alpha 02-beta 03-gamma)"
rm -rf "$(M "$r")/02-beta/fixtures"
ln -s ../01-alpha/fixtures "$(M "$r")/02-beta/fixtures"
expect reject "all: fixtures is a symlink" '02-beta/fixtures:not-a-dir' "$r" "${CH}" all

r="$(newroot fixtures-file 01-alpha 02-beta 03-gamma)"
rm -rf "$(M "$r")/02-beta/fixtures"
: >"$(M "$r")/02-beta/fixtures"
expect reject "all: fixtures is a regular file" '02-beta/fixtures:not-a-dir' "$r" "${CH}" all

r="$(newroot empty-missions)"
expect reject "all: /opt/ctf/missions/ is empty (0 entries never passes)" 'contains []' "$r" "${CH}" all

r="$(newroot no-missions)"
rmdir "$(M "$r")"
expect reject "all: /opt/ctf/missions/ does not exist" 'contains []' "$r" "${CH}" all

# A name that carries a newline + a forged protocol line must neither splice
# into the probe's output nor clear MISSIONS_BAD.
r="$(newroot forged-name 01-alpha 02-beta 03-gamma)"
: >"$(M "$r")/$(printf 'z\nMISSIONS_BAD=')"
expect reject "all: top-level file name forging a 'MISSIONS_BAD=' line" 'not a plain directory: [<bad-name>]' "$r" "${CH}" all

r="$(newroot forged-name-in-id 01-alpha 02-beta 03-gamma)"
: >"$(M "$r")/01-alpha/$(printf 'z\nMISSIONS_SUBBAD=')"
expect reject "all: in-id file name forging a 'MISSIONS_SUBBAD=' line" '01-alpha/<bad-name>' "$r" "${CH}" all

r="$(newroot forged-list 01-alpha 03-gamma)"
: >"$(M "$r")/$(printf 'q\nMISSIONS_LIST=01-alpha 02-beta 03-gamma')"
expect reject "all: file name forging the id list of a missing id" 'not a plain directory: [<bad-name>]' "$r" "${CH}" all

# A probe that does not complete must not read as clean.
r="$(newroot good-kubectl-fail 01-alpha 02-beta 03-gamma)"
CASES=$((CASES + 1))
set +e
PATH="${WORK}/bin:${PATH}" FAKE_ROOT="$r" FAKE_KUBECTL_FAIL=1 "${ASSERT}" ns-test "${CH}" all >"${WORK}/out.$$" 2>&1
rc=$?
set -e
if [[ "${rc}" -ne 0 ]]; then pass "all: kubectl exec failure -> exit ${rc}"; else fail "all: kubectl exec failure exited 0"; fi

# A truncated probe (no PROBE_END sentinel) must not read as clean.
r="$(newroot good-truncated 01-alpha 02-beta 03-gamma)"
CASES=$((CASES + 1))
set +e
PATH="${WORK}/bin:${PATH}" FAKE_ROOT="$r" FAKE_TRUNCATE=1 "${ASSERT}" ns-test "${CH}" all >"${WORK}/out.$$" 2>&1
rc=$?
set -e
if [[ "${rc}" -ne 0 ]] && grep -qF '3-0: probe output incomplete' "${WORK}/out.$$"; then
  pass "all: truncated probe (no sentinel) -> exit ${rc}"
else
  fail "all: truncated probe was not rejected with 3-0 (rc=${rc}): $(tr '\n' ' ' <"${WORK}/out.$$")"
fi

# A checkout with no catalog id cannot be compared against anything.
mkdir -p "${WORK}/empty-challenges/decks"
r="$(newroot empty-checkout)"
expect reject "all: no catalog id in the checkout" 'no catalog id' "$r" "${WORK}/empty-challenges" all

# The id set comes from the checkout: a real-catalog run (falco-rule.yaml only,
# no plant.sh so no planted-file expectations) over a root holding exactly the
# real ids passes, and drops one id -> fails.
mkdir -p "${WORK}/real-challenges"
printf '%s' "${NOEV_VALUES}" >"${WORK}/real-challenges/values-all.yaml"
real_ids=()
for d in "${REPO_ROOT}"/challenges/*/; do
  [[ -f "${d}falco-rule.yaml" ]] || continue
  id="$(basename "${d}")"
  real_ids+=("${id}")
  mkdir -p "${WORK}/real-challenges/${id}"
  cp "${d}falco-rule.yaml" "${WORK}/real-challenges/${id}/falco-rule.yaml"
done
if [[ "${#real_ids[@]}" -lt 1 ]]; then
  fail "real catalog: no challenges/*/falco-rule.yaml found (extraction returned nothing)"
else
  r="$(newroot real "${real_ids[@]}")"
  expect accept "real catalog (${#real_ids[@]} ids): exact set" '' "$r" "${WORK}/real-challenges" all
  r="$(newroot real-short "${real_ids[@]:1}")"
  expect reject "real catalog: first id missing" "expected exactly [${real_ids[*]}]" "$r" "${WORK}/real-challenges" all
fi

echo "==> 3-4 (ADR-0056 D11, A5c): the evidence source root is not visible from challenge"
r="$(newroot evidence-src-visible 01-alpha 02-beta 03-gamma)"
mkdir -p "${r}/opt/ctf/evidence-src/01-alpha"
expect reject "all: /opt/ctf/evidence-src exists in challenge" '3-4: the evidence source root' "$r" "${CH}" all
r="$(newroot evidence-src-file 01-alpha 02-beta 03-gamma)"
: >"${r}/opt/ctf/evidence-src"
expect reject "all: /opt/ctf/evidence-src is a plain file in challenge (still visible)" '3-4: the evidence source root' "$r" "${CH}" all

echo "==> 3-8 (ADR-0026 V4): scenario mode"
r="$(newroot sc-good 01-alpha 02-beta)"
expect accept "scenario:two: exactly the scenario's ids" '' "$r" "${CH}" scenario:two "${SC}"

r="$(newroot sc-full 01-alpha 02-beta 03-gamma)"
expect reject "scenario:two: an out-of-scenario id is reachable" 'expected exactly [01-alpha 02-beta]' "$r" "${CH}" scenario:two "${SC}"

r="$(newroot sc-extra 01-alpha 02-beta)"
: >"$(M "$r")/01-alpha/README.md"
expect reject "scenario:two: README.md beside fixtures/" '01-alpha/README.md' "$r" "${CH}" scenario:two "${SC}"

r="$(newroot sc-short 01-alpha)"
expect reject "scenario:two: a scenario id is missing" 'expected exactly [01-alpha 02-beta]' "$r" "${CH}" scenario:two "${SC}"

echo "==> 3-8 hardening: duplicate ids, probe charset"
# Duplicate id in the scenario's list: refused before comparing anything (a
# duplicate would let a missing id hide behind a repeated one).
mkdir -p "${SC}/dup"
printf 'name: dup\nchallenges:\n  - 01-alpha\n  - 01-alpha\n  - 02-beta\n' >"${SC}/dup/scenario.yaml"
r="$(newroot dup-img 01-alpha 02-beta)"
expect reject "scenario: duplicate id in challenges: is refused" 'duplicate id "01-alpha"' "$r" "${CH}" scenario:dup "${SC}"
r="$(newroot dup-img-3 01-alpha 03-gamma)"
expect reject "scenario: duplicate id is refused even when the image lacks 02-beta" 'duplicate id' "$r" "${CH}" scenario:dup "${SC}"

# An expected id outside the probe's character set is refused.
mkdir -p "${SC}/oddid"
printf 'name: oddid\nchallenges:\n  - 01-alpha\n  - 02-b*ta\n' >"${SC}/oddid/scenario.yaml"
r="$(newroot odd-img 01-alpha 02-beta)"
expect reject "scenario: id with a glob character is refused" 'character outside [A-Za-z0-9._-]' "$r" "${CH}" scenario:oddid "${SC}"

# A fake `sh` (or tampered probe) that prints values outside the character set:
# glob characters / escape sequences must become 3-0 and never be echoed.
# FAKE_EXTRA_LINES is appended to the probe's stdout by the stub.
r="$(newroot esc 01-alpha 02-beta 03-gamma)"
CASES=$((CASES + 1))
set +e
PATH="${WORK}/bin:${PATH}" FAKE_ROOT="$r" FAKE_EXTRA_LINES="$(printf 'MISSIONS_LIST=*\nMISSIONS_BAD=\033]0;pwned\007')" \
  "${ASSERT}" ns-test "${CH}" all >"${WORK}/out.$$" 2>&1
rc=$?
set -e
if [[ "${rc}" -ne 0 ]] && grep -qF '3-0: probe field MISSIONS_LIST' "${WORK}/out.$$" \
  && grep -qF '3-0: probe field MISSIONS_BAD' "${WORK}/out.$$" && ! grep -q "$(printf '\033')" "${WORK}/out.$$"; then
  pass "all: out-of-charset probe values -> 3-0, no escape byte reaches the output"
else
  fail "all: out-of-charset probe values not handled (rc=${rc}): $(tr '\n' ' ' <"${WORK}/out.$$" | cat -v)"
fi

echo "==> 3-9 / 3-10 (ADR-0056 D11 \"3-x\", A5d): evidence mount directories (V8) and the Secret names (V2)"
# The values come from challenges/gen-values.sh itself (--emit-evidence-fixture: two
# investigate challenges, 40-ev and 41-ev, each with its own mount directory under /opt/fx,
# the prefix the stub rewrites), so the form the assert reads is the generator's.
EVFX="${WORK}/evfx"
EVCH="${WORK}/ev-challenges"
EVSC="${WORK}/ev-scenarios"
mkdir -p "${EVFX}" "${EVCH}" "${EVSC}/one"
EVFX_OK=1
if ! "${REPO_ROOT}/challenges/gen-values.sh" --emit-evidence-fixture "${EVFX}" >/dev/null 2>&1; then
  fail "gen-values.sh --emit-evidence-fixture failed: no generated values for the 3-9 / 3-10 cases"
  EVFX_OK=0
fi
EV_DIR_A=""
EV_DIR_B=""
if [[ "${EVFX_OK}" -eq 1 ]]; then
  while IFS=$'\t' read -r ev_dir ev_cid; do
    case "${ev_cid}" in
      40-ev) EV_DIR_A="${ev_dir}" ;;
      41-ev) EV_DIR_B="${ev_dir}" ;;
    esac
  done <"${EVFX}/map"
  case "${EV_DIR_A}:${EV_DIR_B}" in
    /opt/fx/?*:/opt/fx/?*) ;;
    *)
      fail "the generated fixture's mount directories are [${EV_DIR_A}] [${EV_DIR_B}], not two directories under /opt/fx (the stub rewrites that prefix only)"
      EVFX_OK=0
      ;;
  esac
fi

# ev_values <path> <cid> ...: a values file in gen-values.sh's form (render_plant_block)
ev_values() {
  printf 'plant:\n  seedScript:\n    - sh\n    - -c\n    - |\n      set -eu\n  mounts:\n'
  while [[ "$#" -ge 2 ]]; do
    printf '    - path: %s\n      readOnly: true\n      evidence: true\n      challenge: %s\n' "$1" "$2"
    shift 2
  done
}
# evroot <name> [ids...]: newroot, plus the two evidence mount directories with one file each
evroot() {
  local r
  r="$(newroot "$@")"
  mkdir -p "${r}${EV_DIR_A}" "${r}${EV_DIR_B}"
  printf 'x\n' >"${r}${EV_DIR_A}/a.log"
  printf 'x\n' >"${r}${EV_DIR_B}/b.txt"
  printf '%s' "${r}"
}
# expect_ev <verdict> <label> <needle> <secrets listing> <root> <challenges-dir> <challenge-id> [scenarios-dir]
expect_ev() {
  export FAKE_SECRETS="$4"
  expect "$1" "$2" "$3" "${@:5}"
  unset FAKE_SECRETS
}
# ev_tree <dir> <values text>: a checkout holding 01-alpha, 40-ev and 41-ev, with <values text>
# as its values-all.yaml
ev_tree() {
  local id
  mkdir -p "$1"
  for id in 01-alpha 40-ev 41-ev; do
    mkdir -p "$1/${id}"
    printf 'challengeId: %s\n' "${id}" >"$1/${id}/falco-rule.yaml"
  done
  printf '%s' "$2" >"$1/values-all.yaml"
}

if [[ "${EVFX_OK}" -eq 1 ]]; then
  ev_tree "${EVCH}" "$(cat "${EVFX}/values.yaml")"$'\n'
  printf 'name: one\nchallenges:\n  - 01-alpha\n  - 40-ev\n' >"${EVSC}/one/scenario.yaml"
  ev_values "${EV_DIR_A}" 40-ev >"${EVCH}/values-scenario-one.yaml"
  ev_values "${EV_DIR_A}" 40-ev >"${EVCH}/40-ev/values.yaml"
  TAB=$'\t'
  LF=$'\n'
  SEC_HELM="sh.helm.release.v1.user1.v1${TAB}helm.sh/release.v1${LF}sh.helm.release.v1.user1.v2${TAB}helm.sh/release.v1"
  SEC_ALL="ctf-flags${TAB}Opaque${LF}ctf-evidence-40-ev${TAB}Opaque${LF}ctf-evidence-41-ev${TAB}Opaque${LF}${SEC_HELM}"
  SEC_A="ctf-flags${TAB}Opaque${LF}ctf-evidence-40-ev${TAB}Opaque${LF}${SEC_HELM}"
  EV_IDS=(01-alpha 40-ev 41-ev)

  r="$(evroot ev-good "${EV_IDS[@]}")"
  expect_ev accept "all: the evidence mounts hold regular files only, the Secrets are exactly the scope's" '' "${SEC_ALL}" "$r" "${EVCH}" all
  # the scope the assert read is the one deploy-user.sh's reader reads (parity of the two readers)
  CASES=$((CASES + 1))
  if ! scope_out="$(evidence_scope_cids "${EVCH}/values-all.yaml")"; then
    fail "evidence_scope_cids refused gen-values.sh's own output"
  elif [[ "${scope_out}" != "40-ev${LF}41-ev" ]]; then
    fail "evidence_scope_cids read [${scope_out//${LF}/ }], want [40-ev 41-ev]"
  elif ! grep -qF "evidence scope [${scope_out//${LF}/ }], Opaque Secrets [ctf-flags ctf-evidence-40-ev ctf-evidence-41-ev], 2 Helm release record(s)" "${WORK}/out.$$"; then
    fail "the assert's evidence scope is not evidence_scope_cids' [${scope_out//${LF}/ }]: $(tr '\n' ' ' <"${WORK}/out.$$")"
  else
    pass "all: the assert reads the scope evidence_scope_cids reads ([${scope_out//${LF}/ }]); Helm's records are counted apart"
  fi

  r="$(evroot ev-sc 01-alpha 40-ev)"
  expect_ev accept "scenario:one: its one investigate challenge" '' "${SEC_A}" "$r" "${EVCH}" scenario:one "${EVSC}"
  r="$(evroot ev-single "${EV_IDS[@]}")"
  expect_ev accept "single mission 40-ev: its own values file" '' "${SEC_A}" "$r" "${EVCH}" 40-ev

  # V8: anything but a regular file in a mount directory
  r="$(evroot ev-link "${EV_IDS[@]}")"
  ln -s a.log "${r}${EV_DIR_A}/link.log"
  expect_ev reject "all: a symlink in an evidence mount directory (V8)" '3-9: an evidence mount directory is not a real directory of regular files only: [1/link.log:link]' "${SEC_ALL}" "$r" "${EVCH}" all
  r="$(evroot ev-dotlink "${EV_IDS[@]}")"
  ln -s a.log "${r}${EV_DIR_A}/.hidden"
  expect_ev reject "all: a dot symlink in an evidence mount directory" '1/.hidden:link' "${SEC_ALL}" "$r" "${EVCH}" all
  r="$(evroot ev-dangling "${EV_IDS[@]}")"
  ln -s /nonexistent "${r}${EV_DIR_B}/gone.log"
  expect_ev reject "all: a dangling symlink in an evidence mount directory" '2/gone.log:link' "${SEC_ALL}" "$r" "${EVCH}" all
  r="$(evroot ev-subdir "${EV_IDS[@]}")"
  mkdir -p "${r}${EV_DIR_B}/sub"
  expect_ev reject "all: a directory in an evidence mount directory" '2/sub:not-a-file' "${SEC_ALL}" "$r" "${EVCH}" all
  r="$(evroot ev-dirlink "${EV_IDS[@]}")"
  rm -rf "${r}${EV_DIR_B}"
  ln -s "${r}${EV_DIR_A}" "${r}${EV_DIR_B}"
  expect_ev reject "all: the mount directory itself is a symlink" '2:not-a-dir' "${SEC_ALL}" "$r" "${EVCH}" all
  r="$(evroot ev-missing "${EV_IDS[@]}")"
  rm -rf "${r}${EV_DIR_A}"
  expect_ev reject "all: an evidence mount directory is missing" '1:not-a-dir' "${SEC_ALL}" "$r" "${EVCH}" all
  r="$(evroot ev-empty "${EV_IDS[@]}")"
  rm -f "${r}${EV_DIR_A}/a.log"
  expect_ev reject "all: an evidence mount directory is empty" '1:empty' "${SEC_ALL}" "$r" "${EVCH}" all
  # the sentinel: a probe that judged fewer directories than it was sent is not clean
  r="$(evroot ev-skipped "${EV_IDS[@]}")"
  export FAKE_EXTRA_LINES='EVIDENCE_DIRS_SEEN=0'
  expect_ev reject "all: a probe that judged none of the evidence mount directories" '3-9: the probe judged 0 of the 2' "${SEC_ALL}" "$r" "${EVCH}" all
  unset FAKE_EXTRA_LINES

  # V2: the Opaque Secrets are exactly {ctf-flags} + ctf-evidence-<cid> of the scope
  r="$(evroot ev-secrets "${EV_IDS[@]}")"
  expect_ev reject "all: an extra ctf-evidence-* Secret (V2)" '3-10: the Opaque Secrets of ns-test are' "${SEC_ALL}${LF}ctf-evidence-99-zz${TAB}Opaque" "$r" "${EVCH}" all
  expect_ev reject "all: an extra Opaque Secret of another name" '3-10: the Opaque Secrets of ns-test are' "${SEC_ALL}${LF}stash${TAB}Opaque" "$r" "${EVCH}" all
  expect_ev reject "all: a missing ctf-evidence-* Secret (V2)" '3-10: the Opaque Secrets of ns-test are' "${SEC_A}" "$r" "${EVCH}" all
  expect_ev reject "all: ctf-flags missing" '3-10: the Opaque Secrets of ns-test are' "ctf-evidence-40-ev${TAB}Opaque${LF}ctf-evidence-41-ev${TAB}Opaque" "$r" "${EVCH}" all
  expect_ev reject "all: no Secret at all" '3-10: the Opaque Secrets of ns-test are' '' "$r" "${EVCH}" all
  expect_ev reject "all: a Secret of another type" '3-10: Secret(s) of a type other than Opaque' "${SEC_ALL}${LF}stash${TAB}kubernetes.io/basic-auth" "$r" "${EVCH}" all
  expect_ev reject "all: a listing line outside the character set" '3-10: 1 line(s) of the Secret listing are outside' "${SEC_ALL}${LF}BAD NAME${TAB}Opaque" "$r" "${EVCH}" all
  r="$(newroot ev-stale 01-alpha 02-beta 03-gamma)"
  expect_ev reject "all, no investigate challenge: an earlier deploy's ctf-evidence-* Secret stayed" '3-10: the Opaque Secrets of ns-test are' "ctf-flags${TAB}Opaque${LF}ctf-evidence-40-ev${TAB}Opaque" "$r" "${CH}" all
  r="$(evroot ev-getfail "${EV_IDS[@]}")"
  export FAKE_SECRETS_FAIL=1
  expect_ev reject "all: kubectl get secrets fails" '3-10: kubectl get secrets failed' "${SEC_ALL}" "$r" "${EVCH}" all
  unset FAKE_SECRETS_FAIL

  # the scope's values file: required in all / scenario mode, and only gen-values.sh's form
  r="$(evroot ev-values "${EV_IDS[@]}")"
  ev_tree "${WORK}/ev-novalues" ''
  rm -f "${WORK}/ev-novalues/values-all.yaml"
  expect_ev reject "all: the values file of the scope is missing" 'the values file of this scope is missing' "${SEC_ALL}" "$r" "${WORK}/ev-novalues" all
  mkdir -p "${EVSC}/nov"
  printf 'name: nov\nchallenges:\n  - 01-alpha\n' >"${EVSC}/nov/scenario.yaml"
  expect_ev reject "scenario:nov: its values file is missing" 'the values file of this scope is missing' "${SEC_ALL}" "$r" "${EVCH}" scenario:nov "${EVSC}"
  ev_tree "${WORK}/ev-quoted" "$(ev_values "${EV_DIR_A}" 40-ev | sed 's/evidence: true/evidence: "true"/')"$'\n'
  expect_ev reject "all: an evidence entry not in gen-values.sh's form" 'an evidence key that is not' "${SEC_ALL}" "$r" "${WORK}/ev-quoted" all
  ev_tree "${WORK}/ev-nochallenge" "$(ev_values "${EV_DIR_A}" 40-ev "${EV_DIR_B}" 41-ev | sed '/challenge: 40-ev/d')"$'\n'
  expect_ev reject "all: an evidence entry with no challenge line" 'the line after' "${SEC_ALL}" "$r" "${WORK}/ev-nochallenge" all
  ev_tree "${WORK}/ev-dup" "$(ev_values "${EV_DIR_A}" 40-ev "${EV_DIR_B}" 40-ev)"$'\n'
  expect_ev reject "all: one challenge with two evidence entries" 'has a second evidence entry' "${SEC_ALL}" "$r" "${WORK}/ev-dup" all
  ev_tree "${WORK}/ev-badpath" "$(ev_values "/opt/fx/a'b" 40-ev)"$'\n'
  expect_ev reject "all: a mount directory with a quote" 'is not a clean path' "${SEC_ALL}" "$r" "${WORK}/ev-badpath" all
fi

echo
if [[ "${CASES}" -lt 20 ]]; then
  echo "FAIL: only ${CASES} cases ran (expected >= 20) — the harness is not exercising the assert" >&2
  RC=1
fi
if [[ "${RC}" -eq 0 ]]; then
  echo "OK: ${CASES} cases — the deploy-time missions allowlist (3-8) accepts a clean image and rejects each violation."
else
  echo "FAIL: see FAIL lines above." >&2
fi
exit "${RC}"
