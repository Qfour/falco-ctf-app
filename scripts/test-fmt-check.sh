#!/bin/sh
# Self-test of scripts/fmt-check.sh (ADR-0056 stage F-fmt, V88).
#
# WHY: a gofmt gate that accepts everything stays green forever. Each case builds a
# throwaway directory and runs the real script on it:
#   (a) one formatted Go file                       -> exit 0
#   (b) (a) plus one unformatted file               -> exit 1, output names that file
#   (c) (a) plus a file with a syntax error         -> exit 1 (gofmt fails, the list is empty)
#   (d) gofmt not on PATH                           -> exit 2
# A failed case is named and the test exits 1. gofmt must be on PATH to run it;
# without it the test exits 2 (it proves nothing).
#
# Usage: scripts/test-fmt-check.sh
set -eu

if ! command -v gofmt >/dev/null 2>&1; then
  echo "FAIL: gofmt is not on PATH; the self-test proves nothing without it" >&2
  exit 2
fi

here="$(dirname "$0")"
sh_bin="$(command -v sh)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mkdir "$tmp/ok" "$tmp/unformatted" "$tmp/syntax" "$tmp/nogofmt" "$tmp/empty-path"
# Tabs matter: gofmt indents with a tab.
printf 'package a\n\nfunc F() int {\n\treturn 1\n}\n' > "$tmp/ok/good.go"
printf 'package a\n\nfunc F() int {\n\treturn 1\n}\n' > "$tmp/unformatted/good.go"
printf 'package a\nfunc G()   int {\nreturn 2\n}\n' > "$tmp/unformatted/badfmt.go"
printf 'package a\n\nfunc F() int {\n\treturn 1\n}\n' > "$tmp/syntax/good.go"
printf 'package a\n\nfunc (\n' > "$tmp/syntax/broken.go"
printf 'package a\n\nfunc F() int {\n\treturn 1\n}\n' > "$tmp/nogofmt/good.go"

# run_case <dir> [path-override]: sets rc and out; never exits on the script's own status.
run_case() {
  rc=0
  if [ "$#" -ge 2 ]; then
    out="$(PATH="$2" "$sh_bin" "$here/fmt-check.sh" "$1" 2>&1)" || rc=$?
  else
    out="$("$sh_bin" "$here/fmt-check.sh" "$1" 2>&1)" || rc=$?
  fi
}

fail() {
  echo "FAIL: self-test case $1: $2" >&2
  echo "  exit=$rc output:" >&2
  printf '%s\n' "$out" | sed 's/^/    /' >&2
  exit 1
}

run_case "$tmp/ok"
[ "$rc" -eq 0 ] || fail "(a) a formatted tree" "expected exit 0"
echo "ok (selftest): (a) a formatted tree -> exit 0"

run_case "$tmp/unformatted"
[ "$rc" -eq 1 ] || fail "(b) an unformatted file" "expected exit 1"
case "$out" in
  *badfmt.go*) ;;
  *) fail "(b) an unformatted file" "the output does not name badfmt.go" ;;
esac
case "$out" in
  *good.go*) fail "(b) an unformatted file" "the output names the formatted file good.go" ;;
esac
echo "ok (selftest): (b) an unformatted file -> exit 1, names badfmt.go"

run_case "$tmp/syntax"
[ "$rc" -eq 1 ] || fail "(c) a syntax error" "expected exit 1"
echo "ok (selftest): (c) a syntax error -> exit 1"

run_case "$tmp/nogofmt" "$tmp/empty-path"
[ "$rc" -eq 2 ] || fail "(d) gofmt not on PATH" "expected exit 2"
echo "ok (selftest): (d) gofmt not on PATH -> exit 2"

echo "ok: fmt-check selftest passed (formatted accepted; unformatted, syntax error and missing gofmt rejected)"
