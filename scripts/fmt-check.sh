#!/bin/sh
# Every Go file under a directory is gofmt-formatted (ADR-0056 stage F-fmt, V88).
#
# WHY: the required `test` job only builds Dockerfile.test, so a check that is not
# a RUN there is not required. This script is the one place the check lives;
# Dockerfile.test runs it (the alpine image has POSIX sh and gofmt, not make) and
# `make fmt-check` runs it on a host that has gofmt.
#
# HOW: `gofmt -l <dir>` lists the files whose formatting differs. Judged by exit
# status first and by the list second.
#
# FAILS (exit 1) when
#   - gofmt itself exits non-zero (a syntax error, an unreadable path): the list
#     can be empty then, and an empty list must not read as "formatted", or
#   - the list is not empty: every file is printed, one per line.
# Exit 2 when gofmt is not on PATH, or the usage is wrong. Nothing passes silently.
#
# scripts/test-fmt-check.sh is the self-test (a formatted tree passes; an
# unformatted file and a syntax error each fail; no gofmt exits 2).
#
# Usage: scripts/fmt-check.sh [dir]   (default: .)
set -eu

if [ "$#" -gt 1 ]; then
  echo "usage: $0 [dir]" >&2
  exit 2
fi
dir="${1:-.}"

if ! command -v gofmt >/dev/null 2>&1; then
  echo "fmt-check: gofmt is not on PATH; nothing was checked" >&2
  exit 2
fi

# gofmt's own stderr (the syntax error and its position) is left to show.
if ! unformatted="$(gofmt -l -- "$dir")"; then
  echo "FAIL: gofmt exited non-zero on $dir (see its message above); the formatting was not judged"
  exit 1
fi

if [ -n "$unformatted" ]; then
  echo "FAIL: not gofmt-formatted (run gofmt -w on them):"
  printf '%s\n' "$unformatted" | sed 's/^/  /'
  exit 1
fi

echo "ok: every Go file under $dir is gofmt-formatted"
