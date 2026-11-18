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
#   3-9 / 3-10 (ADR-0056 D11 "3-x" items (1)(2), A5d; V8, V2; item (3) = 3-11 is
#   the A5e block below): over values that
#   challenges/gen-values.sh itself generates for two investigate challenges, a
#   clean root and the expected Secrets pass in all / scenario / single mode, and
#   the evidence scope the assert reads is the one deploy-user.sh's
#   evidence_scope_cids reads; a symlink (also a dot one or a dangling one), a
#   directory, an empty or missing mount directory, a probe that judged fewer
#   directories than it was sent, a Secret too many or too few (either family),
#   a Secret of another type, an unreadable listing, a failed `kubectl get`, a
#   missing values file and an evidence entry not in gen-values.sh's form each
#   exit != 0 with their own diagnostic
#   A5e (ADR-0056 V94 / V95, 3-x item (3) = 3-11): the assert reads the values file
#   it is GIVEN (two candidates in one checkout: the given one is used; no 5th
#   argument or an empty one: exit 2); the keys of each ctf-evidence-<cid> equal the
#   <cid>/<name> arguments (one key more / fewer / different / unreadable / outside
#   the key character set: red); the name arguments themselves are checked; an image
#   pull Secret (kubernetes.io/dockerconfigjson) is outside the closed set (3-10);
#   two mutants of the assert (3-11 off, the values file optional) let a case through;
#   deploy-user.sh's call gives the values file it gave helm (static: its stub harness
#   stops at helm upgrade)
#
# Every call gives the assert all five arguments: the values file is the one
# deploy-user.sh would give helm for the mode (values_for), unless a case sets
# ASSERT_VALUES; the <cid>/<name> arguments and the keys the stub serves follow from it.
#
# The stub kubectl answers `get secrets` with FAKE_SECRETS (name TAB type lines;
# default: ctf-flags and one Helm release record) or fails with FAKE_SECRETS_FAIL=1, and
# `get secret <name>` (3-11, the keys-only go-template and nothing else) with the keys
# FAKE_EVIDENCE_KEYS lists for <name>.
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
# `-n <ns> get secret <name> -o go-template=...` (3-11): the KEYS of one Secret. The
# template must be exactly the keys-only one (the stub refuses any other, so a change
# that would fetch a value is red here); the keys come from FAKE_EVIDENCE_KEYS
# ("<secret> TAB <key>" lines); a Secret it does not list is NotFound (exit 1);
# FAKE_EVIDENCE_KEYS_FAIL=1 fails every such read.
if [[ "${3:-}" == get && "${4:-}" == secret ]]; then
  want_tpl='go-template={{range $k, $v := .data}}{{$k}}{{"\n"}}{{end}}'
  [[ "${6:-}" == -o && "${7:-}" == "${want_tpl}" && "$#" -eq 7 ]] || { echo "stub kubectl: get secret is not the keys-only go-template read: $*" >&2; exit 2; }
  [[ "${FAKE_EVIDENCE_KEYS_FAIL:-0}" != 1 ]] || { echo "stub kubectl: forced get secret failure" >&2; exit 1; }
  found=0
  while IFS=$'\t' read -r sname skey; do
    if [[ -n "${sname}" && "${sname}" == "${5}" ]]; then
      found=1
      printf '%s\n' "${skey}"
    fi
  done <<<"${FAKE_EVIDENCE_KEYS:-}"
  [[ "${found}" -eq 1 ]] || { echo "Error from server (NotFound): secrets \"${5}\" not found" >&2; exit 1; }
  exit 0
fi
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
# the evidence mount directories (3-9) are the payload's first line,
# EVIDENCE_MOUNT_DIRS='<dir> <dir>...': each one is moved under $FAKE_ROOT, whatever it is
first="${payload%%$'\n'*}"
case "${first}" in
  "EVIDENCE_MOUNT_DIRS='"*"'")
    dirs="${first#EVIDENCE_MOUNT_DIRS=\'}"
    dirs="${dirs%\'}"
    moved=""
    for d in ${dirs}; do moved="${moved:+${moved} }${FAKE_ROOT}${d}"; done
    payload="EVIDENCE_MOUNT_DIRS='${moved}'"$'\n'"${payload#*$'\n'}"
    ;;
  *) echo "stub kubectl: the payload does not start with the EVIDENCE_MOUNT_DIRS line" >&2; exit 2 ;;
esac
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

# The values file a case gives the assert (ADR-0056 A5e: the assert is given the file,
# it never chooses one). By default the one deploy-user.sh would give helm for the mode
# (values_for, the test's own statement of deploy-user.sh's choice); ASSERT_VALUES set
# and non-empty overrides it for one case. ASSERT_NAMES: the <cid>/<name> arguments.
# values_for only picks the fixtures' file; that deploy-user.sh really gives the assert
# helm's file is held by scripts/check-deploy-user-evidence.sh (A5e, the behaviour case).
ASSERT_VALUES=""
ASSERT_NAMES=()
values_for() { # <challenges-dir> <challenge-id> -> the values file path, or -
  case "$2" in
    all) printf '%s' "$1/values-all.yaml" ;;
    scenario:*) printf '%s' "$1/values-scenario-${2#scenario:}.yaml" ;;
    *) if [[ -f "$1/$2/values.yaml" ]]; then printf '%s' "$1/$2/values.yaml"; else printf '%s' -; fi ;;
  esac
}

# expect <accept|reject> <label> <needle> <root> <challenges-dir> <challenge-id> [scenarios-dir]
expect() {
  local verdict="$1" label="$2" needle="$3" root="$4" chdir="$5" cid="$6" scdir="${7:-}"
  local out="${WORK}/out.$$" rc vf
  vf="${ASSERT_VALUES:-$(values_for "${chdir}" "${cid}")}"
  CASES=$((CASES + 1))
  set +e
  PATH="${WORK}/bin:${PATH}" FAKE_ROOT="${root}" \
    "${ASSERT}" ns-test "${chdir}" "${cid}" "${scdir}" "${vf}" ${ASSERT_NAMES[@]+"${ASSERT_NAMES[@]}"} >"${out}" 2>&1
  rc=$?
  set -e
  if [[ "${verdict}" == accept ]]; then
    if [[ "${rc}" -ne 0 ]]; then
      fail "${label}: expected exit 0, got ${rc}: $(tr '\n' ' ' <"${out}")"
    elif ! grep -qF 'OK — 3-1..3-11 clean' "${out}"; then
      fail "${label}: exit 0 but no '3-1..3-11 clean' line: $(tr '\n' ' ' <"${out}")"
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
PATH="${WORK}/bin:${PATH}" FAKE_ROOT="$r" FAKE_KUBECTL_FAIL=1 "${ASSERT}" ns-test "${CH}" all '' "${CH}/values-all.yaml" >"${WORK}/out.$$" 2>&1
rc=$?
set -e
if [[ "${rc}" -ne 0 ]]; then pass "all: kubectl exec failure -> exit ${rc}"; else fail "all: kubectl exec failure exited 0"; fi

# A truncated probe (no PROBE_END sentinel) must not read as clean.
r="$(newroot good-truncated 01-alpha 02-beta 03-gamma)"
CASES=$((CASES + 1))
set +e
PATH="${WORK}/bin:${PATH}" FAKE_ROOT="$r" FAKE_TRUNCATE=1 "${ASSERT}" ns-test "${CH}" all '' "${CH}/values-all.yaml" >"${WORK}/out.$$" 2>&1
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
  "${ASSERT}" ns-test "${CH}" all '' "${CH}/values-all.yaml" >"${WORK}/out.$$" 2>&1
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
# ev_name <cid>: the one bundle file name the fixtures give a challenge (the file evroot
# puts in its mount directory)
ev_name() {
  case "$1" in
    40-ev) printf 'a.log' ;;
    41-ev) printf 'b.txt' ;;
    *) printf 'x.log' ;;
  esac
}
# expect_ev <verdict> <label> <needle> <secrets listing> <root> <challenges-dir> <challenge-id> [scenarios-dir]
# The <cid>/<name> arguments (as deploy-user.sh passes them) and the keys the stub serves
# for each ctf-evidence-<cid> follow from the investigate challenges of the values file
# the case gives the assert: one name per challenge (ev_name), its Secret holding exactly
# that key. EV_NAMES_OVERRIDE (set, an array spec "a b ...") and EV_KEYS_OVERRIDE (set)
# replace them for one case.
expect_ev() {
  local vf cids c
  vf="${ASSERT_VALUES:-$(values_for "$6" "$7")}"
  ASSERT_NAMES=()
  local keys=""
  if [[ "${vf}" != - ]] && cids="$(evidence_scope_cids "${vf}" 2>/dev/null)"; then
    for c in ${cids}; do
      ASSERT_NAMES+=("${c}/$(ev_name "${c}")")
      keys="${keys}ctf-evidence-${c}${TAB}$(ev_name "${c}")${LF}"
    done
  fi
  if [[ -n "${EV_NAMES_OVERRIDE+x}" ]]; then
    # shellcheck disable=SC2206  # the override is a space-joined list on purpose
    ASSERT_NAMES=(${EV_NAMES_OVERRIDE})
  fi
  if [[ -n "${EV_KEYS_OVERRIDE+x}" ]]; then keys="${EV_KEYS_OVERRIDE}"; fi
  export FAKE_SECRETS="$4"
  export FAKE_EVIDENCE_KEYS="${keys}"
  expect "$1" "$2" "$3" "${@:5}"
  unset FAKE_SECRETS FAKE_EVIDENCE_KEYS
  ASSERT_NAMES=()
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

  # the scope's values file: the one given must exist (A5e: a path that is not a file is
  # refused, never replaced by another), and only gen-values.sh's form
  r="$(evroot ev-values "${EV_IDS[@]}")"
  ev_tree "${WORK}/ev-novalues" ''
  rm -f "${WORK}/ev-novalues/values-all.yaml"
  expect_ev reject "all: the values file given does not exist" 'the values file given is not a file' "${SEC_ALL}" "$r" "${WORK}/ev-novalues" all
  mkdir -p "${EVSC}/nov"
  printf 'name: nov\nchallenges:\n  - 01-alpha\n' >"${EVSC}/nov/scenario.yaml"
  expect_ev reject "scenario:nov: the values file given does not exist" 'the values file given is not a file' "${SEC_ALL}" "$r" "${EVCH}" scenario:nov "${EVSC}"
  ev_tree "${WORK}/ev-quoted" "$(ev_values "${EV_DIR_A}" 40-ev | sed 's/evidence: true/evidence: "true"/')"$'\n'
  expect_ev reject "all: an evidence entry not in gen-values.sh's form" 'an evidence key that is not' "${SEC_ALL}" "$r" "${WORK}/ev-quoted" all
  ev_tree "${WORK}/ev-nochallenge" "$(ev_values "${EV_DIR_A}" 40-ev "${EV_DIR_B}" 41-ev | sed '/challenge: 40-ev/d')"$'\n'
  expect_ev reject "all: an evidence entry with no challenge line" 'the line after' "${SEC_ALL}" "$r" "${WORK}/ev-nochallenge" all
  ev_tree "${WORK}/ev-dup" "$(ev_values "${EV_DIR_A}" 40-ev "${EV_DIR_B}" 40-ev)"$'\n'
  expect_ev reject "all: one challenge with two evidence entries" 'has a second evidence entry' "${SEC_ALL}" "$r" "${WORK}/ev-dup" all
  ev_tree "${WORK}/ev-badpath" "$(ev_values "/opt/fx/a'b" 40-ev)"$'\n'
  expect_ev reject "all: a mount directory with a quote" 'is not a clean path' "${SEC_ALL}" "$r" "${WORK}/ev-badpath" all

  echo "==> A5e (ADR-0056 V94 / V95): the values file is given, 3-11 (the keys of each ctf-evidence-<cid>)"
  # V94: two candidate values files in one checkout (values-all.yaml: 40-ev and 41-ev;
  # 40-ev/values.yaml: 40-ev alone). In `all` mode the assert uses the one it is GIVEN.
  r="$(evroot a5e-given "${EV_IDS[@]}")"
  ASSERT_VALUES="${EVCH}/40-ev/values.yaml"
  expect_ev accept "V94: all mode given 40-ev/values.yaml reads that file (scope 40-ev)" '' "${SEC_A}" "$r" "${EVCH}" all
  CASES=$((CASES + 1))
  if grep -qF 'evidence scope [40-ev], Opaque Secrets [ctf-flags ctf-evidence-40-ev]' "${WORK}/out.$$"; then
    pass "V94: the scope read is the given file's ([40-ev]), not values-all.yaml's"
  else
    fail "V94: the assert did not read the given file: $(tr '\n' ' ' <"${WORK}/out.$$")"
  fi
  # the same Secrets against the other candidate: its scope wants ctf-evidence-41-ev too
  ASSERT_VALUES="${EVCH}/values-all.yaml"
  expect_ev reject "V94: the same deploy given values-all.yaml wants that file's scope" '3-10: the Opaque Secrets of ns-test are' "${SEC_A}" "$r" "${EVCH}" all
  ASSERT_VALUES=""
  # `-` = helm was given no values file: no investigate challenge, so only ctf-flags
  ASSERT_VALUES=-
  expect_ev accept "V94: - (no values file) in single mode, only ctf-flags" '' "ctf-flags${TAB}Opaque${LF}${SEC_HELM}" "$r" "${EVCH}" 01-alpha
  ASSERT_VALUES=""
  # `-` where deploy-user.sh always gives helm a file (all, scenario): exit 2
  ASSERT_VALUES=-
  expect_ev reject "V94: - in all mode (deploy-user.sh always gives values-all.yaml there)" 'challenge-id all is always deployed with a values file, but - (none) was given' "ctf-flags${TAB}Opaque" "$r" "${EVCH}" all
  expect_ev reject "V94: - in scenario mode" 'challenge-id scenario:one is always deployed with a values file, but - (none) was given' "ctf-flags${TAB}Opaque" "$r" "${EVCH}" scenario:one "${EVSC}"
  ASSERT_VALUES=""
  # no 5th argument: exit 2, nothing defaulted. One command line (a checkout with no
  # investigate challenge, so a defaulted values-all.yaml WOULD pass), run here against
  # the assert and below against the mutant that defaults the file.
  NOARG_ROOT="$(newroot v94-noarg 01-alpha 02-beta 03-gamma)"
  v94_noarg() { # <assert> -> exit status of the no-5th-argument run; output in out.$$
    local rc
    set +e
    PATH="${WORK}/bin:${PATH}" FAKE_ROOT="${NOARG_ROOT}" "$1" ns-test "${CH}" all '' >"${WORK}/out.$$" 2>&1
    rc=$?
    set -e
    return "${rc}"
  }
  CASES=$((CASES + 1))
  rc=0
  v94_noarg "${ASSERT}" || rc=$?
  if [[ "${rc}" -eq 2 ]] && grep -qF 'the 5th, the values file helm was given or -, is required' "${WORK}/out.$$"; then
    pass "V94: without the values file argument -> exit 2 (no default)"
  else
    fail "V94: without the values file argument: rc=${rc}: $(tr '\n' ' ' <"${WORK}/out.$$")"
  fi
  CASES=$((CASES + 1))
  set +e
  PATH="${WORK}/bin:${PATH}" FAKE_ROOT="$r" "${ASSERT}" ns-test "${EVCH}" all '' '' >"${WORK}/out.$$" 2>&1
  rc=$?
  set -e
  if [[ "${rc}" -eq 2 ]] && grep -qF 'the values file argument is empty' "${WORK}/out.$$"; then
    pass "V94: an empty values file argument -> exit 2"
  else
    fail "V94: an empty values file argument: rc=${rc}: $(tr '\n' ' ' <"${WORK}/out.$$")"
  fi

  # V94: the key set of ctf-evidence-<cid> against the names (one more, one fewer: red)
  r="$(evroot a5e-keys "${EV_IDS[@]}")"
  EV_KEYS_OVERRIDE="ctf-evidence-40-ev${TAB}a.log${LF}ctf-evidence-41-ev${TAB}b.txt${LF}ctf-evidence-41-ev${TAB}extra.txt"
  expect_ev reject "V94: ctf-evidence-41-ev has one key more than its names" '3-11: the keys of ctf-evidence-41-ev are [b.txt extra.txt], expected exactly the names the chart was given [b.txt]' "${SEC_ALL}" "$r" "${EVCH}" all
  EV_KEYS_OVERRIDE="ctf-evidence-40-ev${TAB}a.log${LF}ctf-evidence-41-ev${TAB}b.txt"
  EV_NAMES_OVERRIDE="40-ev/a.log 41-ev/b.txt 41-ev/c.txt"
  expect_ev reject "V94: ctf-evidence-41-ev has one key fewer than its names" '3-11: the keys of ctf-evidence-41-ev are [b.txt], expected exactly the names the chart was given [b.txt c.txt]' "${SEC_ALL}" "$r" "${EVCH}" all
  EV_KEYS_OVERRIDE="ctf-evidence-40-ev${TAB}a.log${LF}ctf-evidence-41-ev${TAB}b.txt${LF}ctf-evidence-41-ev${TAB}d.txt"
  expect_ev reject "V94: a key that is not a name of the chart (same count)" '3-11: the keys of ctf-evidence-41-ev are [b.txt d.txt], expected exactly the names the chart was given [b.txt c.txt]' "${SEC_ALL}" "$r" "${EVCH}" all
  unset EV_NAMES_OVERRIDE
  EV_KEYS_OVERRIDE="ctf-evidence-40-ev${TAB}a.log${LF}ctf-evidence-41-ev${TAB}"
  expect_ev reject "V94: ctf-evidence-41-ev holds no key" '3-11: the keys of ctf-evidence-41-ev are [], expected exactly the names the chart was given [b.txt]' "${SEC_ALL}" "$r" "${EVCH}" all
  EV_KEYS_OVERRIDE="ctf-evidence-40-ev${TAB}a.log${LF}ctf-evidence-41-ev${TAB}b.txt${LF}ctf-evidence-41-ev${TAB}bad key"
  expect_ev reject "V94: a key outside a Secret key's character set" '3-11: 1 key(s) of ctf-evidence-41-ev are outside' "${SEC_ALL}" "$r" "${EVCH}" all
  EV_KEYS_OVERRIDE="ctf-evidence-40-ev${TAB}a.log"
  expect_ev reject "V94: the keys of one Secret cannot be read (NotFound)" '3-11: the keys of the Secret ctf-evidence-41-ev could not be read' "${SEC_ALL}" "$r" "${EVCH}" all
  unset EV_KEYS_OVERRIDE
  export FAKE_EVIDENCE_KEYS_FAIL=1
  expect_ev reject "V94: kubectl get secret fails" '3-11: the keys of the Secret ctf-evidence-40-ev could not be read' "${SEC_ALL}" "$r" "${EVCH}" all
  unset FAKE_EVIDENCE_KEYS_FAIL
  # the <cid>/<name> arguments themselves
  EV_NAMES_OVERRIDE="40-ev/a.log"
  expect_ev reject "V94: an investigate challenge of the scope with no name argument" 'the investigate challenge 41-ev of this scope has no <cid>/<name> argument' "${SEC_ALL}" "$r" "${EVCH}" all
  EV_NAMES_OVERRIDE="40-ev/a.log 41-ev/b.txt 99-zz/x.log"
  expect_ev reject "V94: a name argument for a challenge outside the scope" 'names a challenge that is not an investigate challenge of this scope' "${SEC_ALL}" "$r" "${EVCH}" all
  EV_NAMES_OVERRIDE="40-ev/a.log 41-ev/b.txt 41-ev/b.txt"
  expect_ev reject "V94: a name argument given twice" 'repeats argument' "${SEC_ALL}" "$r" "${EVCH}" all
  EV_NAMES_OVERRIDE="40-ev/a.log 41-ev"
  expect_ev reject "V94: a name argument without a /" 'is not <cid>/<name>' "${SEC_ALL}" "$r" "${EVCH}" all
  EV_NAMES_OVERRIDE="40-ev/a.log 41-ev/b,txt"
  expect_ev reject "V94: a name argument outside the key character set" 'has a name outside [A-Za-z0-9._-]' "${SEC_ALL}" "$r" "${EVCH}" all
  unset EV_NAMES_OVERRIDE
  ASSERT_VALUES=-
  EV_NAMES_OVERRIDE="40-ev/a.log"
  expect_ev reject "V94: a name argument with - (no values file, no scope)" 'names a challenge that is not an investigate challenge of this scope' "ctf-flags${TAB}Opaque" "$r" "${EVCH}" 01-alpha
  unset EV_NAMES_OVERRIDE
  ASSERT_VALUES=""

  # V95 (3-10), the case #663's tests did not have: an image pull Secret is outside the
  # closed set (the others are above: an Opaque of another name, a missing
  # ctf-evidence-<cid>, Helm's records counted apart in every accept case)
  r="$(evroot a5e-pull "${EV_IDS[@]}")"
  expect_ev reject "V95: a kubernetes.io/dockerconfigjson Secret in the seat's namespace" '3-10: Secret(s) of a type other than Opaque and helm.sh/release.v1 in ns-test: [regcred (kubernetes.io/dockerconfigjson)]' "${SEC_ALL}${LF}regcred${TAB}kubernetes.io/dockerconfigjson" "$r" "${EVCH}" all

  # mutants: a copy of the assert with the 3-11 judgment switched off, and one that lets
  # the values file argument be left out, must each let a case above through (so those
  # cases are what stops such a change)
  MUT="${WORK}/mutant"
  mkdir -p "${MUT}"
  # mutate <label> <old> <new> [<old> <new>...]: ${MUT}/assert-flag-isolation.sh, each old
  # text replaced, each found exactly once in the real assert; rc 1 (after a fail) if not
  mutate() {
    local label="$1" src old new rest
    shift
    src="$(cat "${ASSERT}")"
    while [[ "$#" -ge 2 ]]; do
      old="$1"
      new="$2"
      shift 2
      rest="${src#*"${old}"}"
      if [[ "${rest}" == "${src}" || "${rest}" == *"${old}"* ]]; then
        fail "mutant ${label}: the text to replace is not in the assert exactly once (the assert changed: update the mutant): ${old}"
        return 1
      fi
      src="${src%%"${old}"*}${new}${rest}"
    done
    printf '%s\n' "${src}" >"${MUT}/assert-flag-isolation.sh"
    chmod +x "${MUT}/assert-flag-isolation.sh"
  }
  REAL_ASSERT="${ASSERT}"
  if mutate "3-11 off" '  if [ "${KEYS_OK}" != yes ]' '  if false'; then
    ASSERT="${MUT}/assert-flag-isolation.sh"
    EV_KEYS_OVERRIDE="ctf-evidence-40-ev${TAB}a.log${LF}ctf-evidence-41-ev${TAB}b.txt${LF}ctf-evidence-41-ev${TAB}extra.txt"
    expect_ev accept "mutant (3-11 off): the one-key-more case passes on it, so that case is what goes red" '' "${SEC_ALL}" "$r" "${EVCH}" all
    unset EV_KEYS_OVERRIDE
    ASSERT="${REAL_ASSERT}"
  fi
  # the mutant reads a default file when the 5th is left out (the rule A5e removed)
  if mutate "values file optional" 'if [ "$#" -lt 5 ]' 'if [ "$#" -lt 4 ]' 'SCOPE_VALUES_ARG="${5}"' 'SCOPE_VALUES_ARG="${5:-${CHALLENGES_DIR}/values-all.yaml}"' 'shift 5' 'shift "$#"'; then
    CASES=$((CASES + 1))
    rc=0
    v94_noarg "${MUT}/assert-flag-isolation.sh" || rc=$?
    if [[ "${rc}" -eq 0 ]]; then
      pass "mutant (values file optional): the no-argument run passes on it, so the V94 no-argument case is what goes red"
    else
      fail "mutant (values file optional): the no-argument run still fails (rc=${rc}), so the V94 case does not tell it apart: $(tr '\n' ' ' <"${WORK}/out.$$")"
    fi
  fi
fi

echo "==> A5e (V94): deploy-user.sh gives the assert the values file it gave helm (static)"
# The stub harness of deploy-user.sh stops at `helm upgrade` (exit 97), so the call is held
# by its text: the file helm is given (-f, VALUES_ARGS[1]) is SCOPE_VALUES_FILE, helm gets
# VALUES_ARGS, and the assert gets SCOPE_VALUES_FILE (- when none) and the names.
DU="${REPO_ROOT}/charts/ctf-user/deploy-user.sh"
for want_line in \
  '  SCOPE_VALUES_FILE="${VALUES_ARGS[1]}"' \
  '  ${VALUES_ARGS:+"${VALUES_ARGS[@]}"} \' \
  '    ASSERT_NAME_ARGS+=("${cid}/${name}")' \
  '"${CHART_DIR}/assert-flag-isolation.sh" "${NS}" "${CHALLENGES_DIR}" "${CHALLENGE_ID}" "${SCENARIOS_DIR}" "${SCOPE_VALUES_FILE:--}" ${ASSERT_NAME_ARGS[@]+"${ASSERT_NAME_ARGS[@]}"}'
do
  CASES=$((CASES + 1))
  n="$(grep -cxF -- "${want_line}" "${DU}" || true)"
  if [[ "${n}" == 1 ]]; then
    pass "deploy-user.sh has the line once: ${want_line}"
  else
    fail "deploy-user.sh has the line ${n:-0} times, want once: ${want_line}"
  fi
done
CASES=$((CASES + 1))
n="$(grep -c 'assert-flag-isolation.sh"' "${DU}" || true)"
if [[ "${n}" == 1 ]]; then
  pass "deploy-user.sh calls the assert once"
else
  fail "deploy-user.sh calls the assert ${n:-0} times, want once (every call must give the values file)"
fi

echo "==> the assert's reader of the values file vs deploy-user.sh's (evidence_scope_cids): parity"
# The assert keeps a builtin-only reader of the scope's values file (read_evidence_scope)
# beside deploy-user.sh's evidence_scope_cids (awk). Every input below goes to both: no
# input may be accepted by one and refused by the other, and an accepted one must give
# the same challenges. deploy-user.sh's reading is evidence_scope_cids plus its refusal of
# a challenge listed twice (deploy-user.sh: "is listed twice in the values of this
# scope"). The one documented difference (the assert also needs the entry's `- path:`,
# which it sends to the probe) is pinned at the end, as such.
TAB=$'\t'
LF=$'\n'
# deploy_scope_verdict <values file> -> "accept [<cids>]" or "reject"
deploy_scope_verdict() {
  local out
  if ! out="$(evidence_scope_cids "$1")"; then
    echo reject
    return 0
  fi
  if [[ -n "${out}" && -n "$(printf '%s\n' "${out}" | LC_ALL=C sort | uniq -d)" ]]; then
    echo reject
    return 0
  fi
  printf 'accept [%s]\n' "${out//${LF}/ }"
}
# secrets_for <"accept [<cids>]">: the listing the assert must see for those challenges
secrets_for() {
  local cids="${1#accept [}" c s="ctf-flags${TAB}Opaque"
  cids="${cids%]}"
  for c in ${cids}; do s="${s}${LF}ctf-evidence-${c}${TAB}Opaque"; done
  printf '%s' "${s}"
}
# assert_scope_verdict <checkout> <challenge-id> <scenarios-dir or ''> <root> <secrets> <values file>
#   -> "accept [<cids>]" (exit 0), "reject" (the reader refused: its own message, "the
#      evidence entries must be in the form gen-values.sh writes ... 3-9 / 3-10 / 3-11"),
#      or "error: ..." (anything else: the case is broken, not a verdict)
#   The values file is given (A5e). The <cid>/<name> arguments and the keys the stub
#   serves are one name per challenge evidence_scope_cids reads (k.log): the table is
#   about the readers, and 3-11 must not be what refuses an input.
assert_scope_verdict() {
  local out="${WORK}/parity.out" rc line cids c keys=""
  local -a names=()
  if cids="$(evidence_scope_cids "$6" 2>/dev/null)"; then
    for c in ${cids}; do
      names+=("${c}/k.log")
      keys="${keys}ctf-evidence-${c}${TAB}k.log${LF}"
    done
  fi
  set +e
  PATH="${WORK}/bin:${PATH}" FAKE_ROOT="$4" FAKE_SECRETS="$5" FAKE_EVIDENCE_KEYS="${keys}" \
    "${ASSERT}" ns-test "$1" "$2" "$3" "$6" ${names[@]+"${names[@]}"} >"${out}" 2>&1
  rc=$?
  set -e
  if [[ "${rc}" -eq 0 ]]; then
    line="$(grep -F 'evidence scope [' "${out}" || true)"
    line="${line#*evidence scope [}"
    printf 'accept [%s]\n' "${line%%]*}"
  elif grep -qF '(the evidence entries must be in the form gen-values.sh writes) — cannot judge 3-9 / 3-10 / 3-11' "${out}"; then
    echo reject
  else
    printf 'error: exit %s: %s\n' "${rc}" "$(tr '\n' ' ' <"${out}" | cut -c1-300)"
  fi
}
# a checkout (01-alpha, 40-ev, 41-ev) and a root whose two mount directories hold a file
PCH="${WORK}/parity-challenges"
for id in 01-alpha 40-ev 41-ev; do
  mkdir -p "${PCH}/${id}"
  printf 'challengeId: %s\n' "${id}" >"${PCH}/${id}/falco-rule.yaml"
done
PROOT="$(newroot parity-root 01-alpha 40-ev 41-ev)"
mkdir -p "${PROOT}/opt/fx/p40" "${PROOT}/opt/fx/p41"
printf 'x\n' >"${PROOT}/opt/fx/p40/a.log"
printf 'x\n' >"${PROOT}/opt/fx/p41/b.log"
# parity_case <label> <line>...: both readers agree on the file of these lines
parity_case() {
  local label="$1" d a
  shift
  printf '%s\n' "$@" >"${PCH}/values-all.yaml"
  d="$(deploy_scope_verdict "${PCH}/values-all.yaml")"
  a="$(assert_scope_verdict "${PCH}" all '' "${PROOT}" "$(secrets_for "${d}")" "${PCH}/values-all.yaml")"
  CASES=$((CASES + 1))
  if [[ "${a}" == "${d}" ]]; then
    pass "parity: ${label} (both: ${d})"
  else
    fail "parity: ${label}: deploy-user.sh's reader says '${d}', the assert's says '${a}'"
  fi
}
P40='    - path: /opt/fx/p40'
P41='    - path: /opt/fx/p41'
RO='      readOnly: true'
EVT='      evidence: true'
C40='      challenge: 40-ev'
C41='      challenge: 41-ev'
HEAD_LINES=(plant: '  mounts:')
parity_case "one entry" "${HEAD_LINES[@]}" "${P40}" "${RO}" "${EVT}" "${C40}"
parity_case "two entries" "${HEAD_LINES[@]}" "${P40}" "${RO}" "${EVT}" "${C40}" "${P41}" "${RO}" "${EVT}" "${C41}"
parity_case "no evidence entry" "${HEAD_LINES[@]}" "${P40}" "${RO}"
parity_case "an empty file" ''
parity_case "a commented-out key" "${HEAD_LINES[@]}" "${P40}" "${RO}" '      # evidence: true' '# evidence: true'
parity_case "the seed script's own words (a comment, a path)" 'plant:' '  seedScript:' '    - |' '      # evidence bundle (ADR-0056 D11): x' '      cp "/opt/ctf/evidence-src/40-ev/a" "x"' '  mounts: []'
parity_case "evidence: true and then another key" "${HEAD_LINES[@]}" "${P40}" "${EVT}" '      path: /x'
parity_case "evidence: true at the end of the file" "${HEAD_LINES[@]}" "${P40}" "${EVT}"
parity_case "evidence at 4 spaces" "${HEAD_LINES[@]}" "${P40}" '    evidence: true' '    challenge: 40-ev'
parity_case "evidence at 8 spaces" "${HEAD_LINES[@]}" "${P40}" '        evidence: true' '        challenge: 40-ev'
parity_case "evidence: \"true\"" "${HEAD_LINES[@]}" "${P40}" '      evidence: "true"' "${C40}"
parity_case "evidence: true with a comment" "${HEAD_LINES[@]}" "${P40}" '      evidence: true # c' "${C40}"
parity_case "evidence: True" "${HEAD_LINES[@]}" "${P40}" '      evidence: True' "${C40}"
parity_case "evidence: false" "${HEAD_LINES[@]}" "${P40}" '      evidence: false' "${C40}"
parity_case "a quoted key" "${HEAD_LINES[@]}" "${P40}" '      "evidence": true' "${C40}"
parity_case "the key in a flow mapping" "${HEAD_LINES[@]}" '    - {path: /opt/fx/p40, evidence: true, challenge: 40-ev}'
parity_case "a top-level evidence key (the chart's values shape)" 'evidence:' '  challenges: {}'
parity_case "a comment between the two lines" "${HEAD_LINES[@]}" "${P40}" "${EVT}" '      # c' "${C40}"
parity_case "two evidence lines in a row" "${HEAD_LINES[@]}" "${P40}" "${EVT}" "${EVT}" "${C40}"
parity_case "challenge: with an underscore" "${HEAD_LINES[@]}" "${P40}" "${EVT}" '      challenge: 40_ev'
parity_case "challenge: with a capital" "${HEAD_LINES[@]}" "${P40}" "${EVT}" '      challenge: 40-EV'
parity_case "challenge: without the two digits" "${HEAD_LINES[@]}" "${P40}" "${EVT}" '      challenge: 4-ev'
parity_case "one challenge with two evidence entries" "${HEAD_LINES[@]}" "${P40}" "${EVT}" "${C40}" "${P41}" "${EVT}" "${C40}"

# The documented difference, pinned: an entry the assert cannot send to the probe (no
# `- path:` of its own, or a path outside [A-Za-z0-9._/-]) is refused by the assert and
# read by evidence_scope_cids (deploy-user.sh does not read the path; the chart's `fail`
# refuses such a path at render, so such a file does not deploy either way).
parity_stricter() {
  local label="$1" d a
  shift
  printf '%s\n' "$@" >"${PCH}/values-all.yaml"
  d="$(deploy_scope_verdict "${PCH}/values-all.yaml")"
  a="$(assert_scope_verdict "${PCH}" all '' "${PROOT}" "$(secrets_for "${d}")" "${PCH}/values-all.yaml")"
  CASES=$((CASES + 1))
  if [[ "${d}" == accept* && "${a}" == reject ]]; then
    pass "parity, the documented difference: ${label} (deploy-user.sh's reader: ${d}; the assert: reject)"
  else
    fail "parity, the documented difference: ${label}: deploy-user.sh's reader says '${d}', the assert's says '${a}' (want accept / reject)"
  fi
}
parity_stricter "an evidence entry without its own '- path:'" "${HEAD_LINES[@]}" "${EVT}" "${C40}"
parity_stricter "a mount directory with a quote" "${HEAD_LINES[@]}" "    - path: /opt/fx/a'b" "${EVT}" "${C40}"

# The committed values files: both readers read the same scope from values-all.yaml and
# from every values-scenario-*.yaml (no investigate challenge in the repo yet, so today
# that scope is empty, and that is held too).
RCH="${WORK}/parity-real"
mkdir -p "${RCH}"
prl_ids=()
for d in "${REPO_ROOT}"/challenges/*/; do
  [[ -f "${d}falco-rule.yaml" ]] || continue
  id="$(basename "${d}")"
  prl_ids+=("${id}")
  mkdir -p "${RCH}/${id}"
  cp "${d}falco-rule.yaml" "${RCH}/${id}/falco-rule.yaml"
done
if ! prl_dirs="$("${REPO_ROOT}/challenges/gen-values.sh" --list-evidence-mount-dirs)"; then
  fail "gen-values.sh --list-evidence-mount-dirs failed over the real tree"
  prl_dirs=""
fi
# real_root <name> <ids...>: a root holding those ids and every real evidence mount directory
real_root() {
  local r md
  r="$(newroot "$@")"
  while IFS= read -r md; do
    [[ -n "${md}" ]] || continue
    mkdir -p "${r}${md}"
    printf 'x\n' >"${r}${md}/placeholder.txt"
  done <<<"${prl_dirs}"
  printf '%s' "${r}"
}
# parity_real <label> <values file> <challenge-id> <scenarios-dir or ''> <ids...>
parity_real() {
  local label="$1" vf="$2" cid="$3" scd="$4" d a r
  shift 4
  d="$(deploy_scope_verdict "${vf}")"
  r="$(real_root "parity-real-root" "$@")"
  a="$(assert_scope_verdict "${RCH}" "${cid}" "${scd}" "${r}" "$(secrets_for "${d}")" "${vf}")"
  CASES=$((CASES + 1))
  if [[ "${a}" != "${d}" ]]; then
    fail "parity, committed ${label}: deploy-user.sh's reader says '${d}', the assert's says '${a}'"
  elif [[ -z "${prl_dirs}" && "${d}" != 'accept []' ]]; then
    fail "parity, committed ${label}: the repo has no investigate challenge, but the scope read is '${d}' (want an empty one)"
  else
    pass "parity, committed ${label}: both read ${d}"
  fi
}
if [[ "${#prl_ids[@]}" -lt 1 ]]; then
  fail "parity, committed values: no challenges/*/falco-rule.yaml found"
else
  cp "${REPO_ROOT}/challenges/values-all.yaml" "${RCH}/values-all.yaml"
  parity_real "values-all.yaml" "${RCH}/values-all.yaml" all '' "${prl_ids[@]}"
  prl_n=0
  for sv in "${REPO_ROOT}"/challenges/values-scenario-*.yaml; do
    [[ -f "${sv}" ]] || continue
    sname="${sv##*/values-scenario-}"
    sname="${sname%.yaml}"
    [[ -f "${REPO_ROOT}/scenarios/${sname}/scenario.yaml" ]] || { fail "parity, committed ${sv##*/}: no scenarios/${sname}/scenario.yaml"; continue; }
    cp "${sv}" "${RCH}/${sv##*/}"
    sids=()
    while IFS= read -r x; do
      [[ -n "${x}" ]] && sids+=("${x}")
    done < <(awk '
      /^challenges:/ { inblock=1; next }
      inblock && /^[^[:space:]]/ { inblock=0 }
      inblock && /^[[:space:]]*-[[:space:]]*/ {
        line=$0
        sub(/^[[:space:]]*-[[:space:]]*/, "", line)
        sub(/[[:space:]]*#.*$/, "", line)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
        if (line != "") print line
      }
    ' "${REPO_ROOT}/scenarios/${sname}/scenario.yaml")
    parity_real "${sv##*/}" "${RCH}/${sv##*/}" "scenario:${sname}" "${REPO_ROOT}/scenarios" "${sids[@]}"
    prl_n=$((prl_n + 1))
  done
  if [[ "${prl_n}" -lt 1 ]]; then
    fail "parity, committed values: no challenges/values-scenario-*.yaml was compared"
  fi
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
