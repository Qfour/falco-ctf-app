#!/usr/bin/env bash
# check-e2e-image-scope.sh — the browser E2E images (Dockerfile.e2e: `make e2e`'s
# run stage and `make e2e-serve`) are never pushed, so they must not be in
# ci.yaml's build matrix, which builds, scans and publishes the I5 images
# (ADR-0031 D1 (b); review-5x T3 R1#3).
#
# The other halves are Go tests in `make test` (internal/apispec/
# e2e_boundary_test.go): the Makefile's IMAGES and Dockerfile.e2e's
# `RUN --network=none`. This one is shell because .github/ is not in the Docker
# build context `make test` runs in; the required flag-guard job runs it.
#
#   scripts/check-e2e-image-scope.sh [CI_YAML]   CI_YAML defaults to .github/workflows/ci.yaml
#   scripts/check-e2e-image-scope.sh --selftest  planted fixtures must fail, a clean one pass
#
# Exit: 0 clean, 1 an e2e image in the matrix, 2 the matrix could not be found
# (fail-closed: a check that looked at nothing is not a pass).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

check() {
  [ -f "$1" ] || { echo "check-e2e-image-scope: $1 not found" >&2; return 2; }
  awk '
    /^  build:[[:space:]]*$/ { inb = 1; next }
    inb && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { inb = 0 }
    inb && /^[[:space:]]*-[[:space:]]+name:/ {
      n++; v = $0; sub(/^[[:space:]]*-[[:space:]]+name:[[:space:]]*/, "", v)
      if (v ~ /e2e/) { print "FAIL: the build matrix has the image " v; bad++ }
    }
    inb && /^[[:space:]]*dockerfile:/ {
      v = $0; sub(/^[[:space:]]*dockerfile:[[:space:]]*/, "", v)
      if (v ~ /e2e/) { print "FAIL: the build matrix builds " v; bad++ }
    }
    END {
      if (n == 0) { print "FAIL: no image found in the build job matrix (the check would look at nothing)"; exit 2 }
      if (bad) exit 1
      print "ok: " n " images in the build matrix, none of them an e2e image"
    }' "$1"
}

if [ "${1:-}" != "--selftest" ]; then
  check "${1:-.github/workflows/ci.yaml}"
  exit $?
fi

tmp="$(mktemp -d)" || exit 2
trap 'rm -rf "$tmp"' EXIT
good='jobs:
  test:
    uses: x
  build:
    strategy:
      matrix:
        include:
          - name: scoreboard
            dockerfile: scoreboard/Dockerfile
  release:
    steps:
      - name: an e2e word outside the build job is fine'
printf '%s\n' "$good" >"$tmp/good.yaml"
# An extra matrix entry, inserted before the next job (awk: portable newlines).
printf '%s\n' "$good" | awk '/^  release:/ { print "          - name: e2e-serve"; print "            dockerfile: images/x/Dockerfile" } { print }' >"$tmp/name.yaml"
printf '%s\n' "$good" | sed 's|dockerfile: scoreboard/Dockerfile|dockerfile: Dockerfile.e2e|' >"$tmp/file.yaml"
printf '%s\n' "$good" | sed 's|^  build:|  build-x:|' >"$tmp/nobuild.yaml"
printf 'jobs:\n  build:\n    runs-on: x\n' >"$tmp/empty.yaml"

status=0
expect() { # expect <want-exit> <file> <what>
  out="$(check "$2" 2>&1)"; rc=$?
  if [ "$rc" -eq "$1" ]; then
    echo "selftest ok: $3 -> exit $rc"
  else
    echo "selftest FAIL: $3 -> exit $rc, want $1"; printf '%s\n' "$out" | sed 's/^/  /'
    status=1
  fi
}
expect 0 "$tmp/good.yaml" "a matrix without an e2e image"
expect 1 "$tmp/name.yaml" "an e2e-serve entry in the matrix"
expect 1 "$tmp/file.yaml" "Dockerfile.e2e built under another name"
expect 2 "$tmp/nobuild.yaml" "no build job"
expect 2 "$tmp/empty.yaml" "a build job with no image"
expect 2 "$tmp/missing.yaml" "a missing file"
exit "$status"
