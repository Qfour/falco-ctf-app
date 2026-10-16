#!/usr/bin/env bash
# Proves scripts/check-emails.sh can actually fail (ADR-0034 V17). A scan that
# is `|| true`-shaped passes on a repo full of real addresses; this builds a
# scratch git repo, plants violating and clean files, and asserts the exit
# status of each. Offending addresses are assembled at run time so this file
# itself carries no non-reserved address for the scan to find.
#
# Usage: ./scripts/check-emails-selftest.sh   (make check-flags; CI flag-guard)
set -euo pipefail
cd "$(dirname "$0")/.."
SCAN="$(pwd)/scripts/check-emails.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PUBLIC_DOMAIN="gmail"
PUBLIC_TLD="com"
bad_addr="someone@${PUBLIC_DOMAIN}.${PUBLIC_TLD}"
NOREPLY_DOMAIN="anthropic.com"

rc=0
cases=0
fail() { echo "  FAIL: $1" >&2; rc=1; }
ok() { echo "  ok:   $1"; }

# expect <name> <want-exit> <file-content>
expect() {
  local name="$1" want="$2" content="$3" got
  cases=$((cases + 1))
  local repo="$WORK/case-$cases"
  mkdir -p "$repo"
  git -C "$repo" init -q
  printf '%s\n' "$content" >"$repo/file.txt"
  git -C "$repo" add file.txt
  set +e
  CHECK_EMAILS_ROOT="$repo" "$SCAN" >/dev/null 2>&1
  got=$?
  set -e
  if [ "$got" -eq "$want" ]; then ok "$name (exit $got)"; else fail "$name: exit $got, want $want"; fi
}

expect "a real-looking address fails" 1 "contact: ${bad_addr}"
upper_addr="$(printf '%s' "$bad_addr" | tr '[:lower:]' '[:upper:]')"
expect "an upper-case public domain fails" 1 "contact: ${upper_addr}"
LOOKALIKE_LABEL="evil-local"
lookalike="user@ctf.${LOOKALIKE_LABEL}.${PUBLIC_TLD}"
expect "a lookalike of a reserved label fails (evil-local)" 1 "x: ${lookalike}"
RESERVED_WORD="local"
suffixed="user@ctf.${RESERVED_WORD}-${LOOKALIKE_LABEL}"
expect "a reserved word followed by more label characters fails" 1 "x: ${suffixed}"
expect "reserved .local passes" 0 "user@ctf.local"
expect "reserved .example passes" 0 "someone@partner.example"
expect "reserved .invalid passes" 0 "bot@x.invalid"
expect "reserved .test passes" 0 "bot@x.test"
expect "upper-case reserved label passes" 0 "USER@CTF.LOCAL"
expect "the pinned no-reply trailer passes" 0 "Co-Authored-By: Claude <noreply@${NOREPLY_DOMAIN}>"
expect "a different no-reply on the same domain fails" 1 "Co-Authored-By: Claude <other@${NOREPLY_DOMAIN}>"
expect "version pins are not addresses" 0 "go install example.org/tool/cmd/tool@v1.2.3 and mod@v1.7.12 and image@sha256:abcdef"
expect "no addresses at all passes" 0 "nothing here"
expect "a violation among clean lines still fails" 1 "$(printf 'a@b.local\n%s\nc@d.example' "$bad_addr")"

# A scan that cannot run is NOT clean: point it at a directory that is not a repo.
cases=$((cases + 1))
set +e
CHECK_EMAILS_ROOT="$WORK" "$SCAN" >/dev/null 2>&1
got=$?
set -e
if [ "$got" -ne 0 ]; then ok "a non-repo root does not pass (exit $got)"; else fail "a non-repo root passed"; fi

if [ "$rc" -ne 0 ]; then
  echo "FAIL: check-emails.sh self-test ($cases cases)" >&2
  exit 1
fi
echo "ok: check-emails.sh self-test passed ($cases cases)"
