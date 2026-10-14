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
#
# Usage: ./scripts/check-missions-allowlist-assert.sh   (make check-flags; CI flag-guard)
set -euo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
ASSERT="${REPO_ROOT}/charts/ctf-user/assert-flag-isolation.sh"

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
