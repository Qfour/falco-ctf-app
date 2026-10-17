#!/bin/sh
# check-test-only-vuln.sh — govulncheck over the test-only modules themselves
# (ADR-0035 D4 (b) / V5).
#
# Why this exists next to `govulncheck -test ./...`: `-test` does not see an
# import that lives in an in-package test file (`package view`, as
# internal/scoreboard/view/portal_nameproblem_test.go is, which imports goja); it
# sees only external test packages (`package view_test`). Measured on
# govulncheck v1.1.4 and v1.9.0 with a module whose only use of a vulnerable
# x/text is in `a_test.go` (`package t`): `-test` reports nothing and does not
# list x/text among the modules it scanned; the same import in `package t_test`
# is reported. So `-test` alone would say "No vulnerabilities found" for goja and
# its dependencies without having looked at them.
#
# So this script hands govulncheck the test-only packages as the roots. The set
# comes from the one list (internal/apispec/testdata/test-only-deps.txt, ADR-0035
# D4 (a)) and the toolchain: every package of `go list -test -tags e2e -deps ./...`
# that an entry of the list matches. Library roots make their exported API the
# entry points, so the scan is as conservative as it can be for code that only
# tests run. It then checks that every external module of the list is among the
# modules govulncheck says it scanned — a scan that did not look at goja fails.
#
#   scripts/check-test-only-vuln.sh        (run from anywhere; needs go and govulncheck on PATH)
#
# Exit: 0 scanned every listed module, no vulnerability; 1 the setup is wrong or
# a listed module was not scanned; 3 (govulncheck's own) vulnerabilities found.
set -eu
cd "$(dirname "$0")/.."

list=internal/apispec/testdata/test-only-deps.txt
[ -f "$list" ] || { echo "check-test-only-vuln: $list not found" >&2; exit 1; }
command -v govulncheck >/dev/null 2>&1 || { echo "check-test-only-vuln: govulncheck is not on PATH" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The list: drop comments, blanks and a trailing slash.
sed -e 's/#.*//' -e 's/[[:space:]]//g' -e 's:/*$::' "$list" | awk 'NF' > "$work/entries"
[ -s "$work/entries" ] || { echo "check-test-only-vuln: $list has no entry" >&2; exit 1; }

own="$(go list -m)"
# External modules only: the module's own internal/e2e is covered by its import
# path in the roots, not by a "scanned module" line of its own.
grep -v "^$own" "$work/entries" > "$work/external" || true
[ -s "$work/external" ] || { echo "check-test-only-vuln: $list names no external module" >&2; exit 1; }

# Every package the tests (and the e2e-tagged harness) reach that an external
# entry matches. `go list -test` also prints the test variants of the module's own
# packages ("pkg [pkg.test]"); those contain a space, and are the module's own.
go list -test -tags e2e -deps -f '{{.ImportPath}}' ./... > "$work/all"
awk 'NR == FNR { entry[$0] = 1; next }
     index($0, " ") { next }
     { for (e in entry) if ($0 == e || index($0, e "/") == 1) { print $0; break } }' \
  "$work/external" "$work/all" | sort -u > "$work/roots"
[ -s "$work/roots" ] || { echo "check-test-only-vuln: no package matches the list — the roots are empty, and scanning nothing proves nothing" >&2; exit 1; }
echo "check-test-only-vuln: $(wc -l < "$work/roots" | tr -d ' ') test-only packages from $(wc -l < "$work/external" | tr -d ' ') external list entries"

set --
while IFS= read -r pkg; do
  set -- "$@" "$pkg"
done < "$work/roots"

# -show verbose prints the modules govulncheck scanned. The exit status is read
# on its own line: a pipeline would report the last command's.
set +e
govulncheck -tags e2e -show verbose "$@" > "$work/out" 2>&1
rc=$?
set -e
cat "$work/out"

sed -n '/^Govulncheck scanned the following/,$p' "$work/out" > "$work/scanned"
[ -s "$work/scanned" ] || { echo "check-test-only-vuln: govulncheck printed no list of scanned modules (exit $rc)" >&2; exit 1; }
missing=0
while IFS= read -r mod; do
  if ! grep -q "^  ${mod}[/@]" "$work/scanned"; then
    echo "check-test-only-vuln: $mod is on the list but govulncheck did not scan it" >&2
    missing=1
  fi
done < "$work/external"
[ "$missing" -eq 0 ] || exit 1
[ "$rc" -eq 0 ] || { echo "check-test-only-vuln: govulncheck exited $rc" >&2; exit "$rc"; }
echo "check-test-only-vuln: every listed test-only module was scanned: $(tr '\n' ' ' < "$work/external")"
