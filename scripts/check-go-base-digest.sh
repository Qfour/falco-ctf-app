#!/usr/bin/env bash
# check-go-base-digest.sh — every `golang:<tag>@sha256:<digest>` in a Dockerfile or
# a workflow must be the SAME string (app#499 / #500, review-5x 64 R4#3 = R1#2).
#
# WHY: the Go builder is written 13 times (10 Dockerfiles + 3 `container.image` in
# checks.yaml). When one copy lags, `make test`/`build` use Go N while the
# `go-vulncheck` job scans with Go N-1 (or the reverse), and a fixed stdlib
# advisory stays red or, worse, stays green on the wrong toolchain (app#78/#87/#88).
# The hand-kept list of copies in the conventions rule is the thing that went
# stale; this derives the set instead.
#
# The set is derived, not listed: `git ls-files '*Dockerfile*'` and
# `.github/workflows/*.y*ml`. The planted-defect fixtures under scripts/testdata/
# are `.txt`, so those globs do not reach them and nothing needs excluding.
#
#   scripts/check-go-base-digest.sh             check the tracked files
#   scripts/check-go-base-digest.sh --selftest  planted defects must fail, the real tree pass
#
# Exit: 0 exactly one distinct value, 1 two or more values / a golang image with no
# digest, 2 nothing found (fail-closed: a check that looked at nothing is not a pass).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

# Prints "<path><TAB><ref>" per `golang:...@sha256:<64 hex>` in the given files, and
# "<path><TAB>NODIGEST:<line>" for a FROM / image: line that names golang without one.
collect() {
  local f
  for f in "$@"; do
    [ -f "$f" ] || { echo "check-go-base-digest: $f not found" >&2; return 2; }
    # `|| true`: grep exits 1 on "no match", which is a normal answer here (the
    # verdict decides what an empty result means), and pipefail would carry it out.
    { grep -oE 'golang:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}' "$f" || true; } | sed "s|^|$f	|"
    { grep -E '^[[:space:]]*(FROM|image:)[[:space:]].*golang:' "$f" \
      | grep -vE 'golang:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}' || true; } \
      | sed "s|^[[:space:]]*|$f	NODIGEST:|"
  done
  return 0
}

# Reads collect's lines on stdin and decides.
verdict() {
  local lines n distinct
  lines="$(cat)"
  if [ -z "$lines" ]; then
    echo "FAIL: no golang:<tag>@sha256:<digest> found (a check that looked at nothing is not a pass)"
    return 2
  fi
  if printf '%s\n' "$lines" | cut -f2 | grep -q '^NODIGEST:'; then
    echo "FAIL: a golang image without a digest pin:"
    printf '%s\n' "$lines" | grep "$(printf '\tNODIGEST:')" | sed 's/^/  /'
    return 1
  fi
  n="$(printf '%s\n' "$lines" | wc -l | tr -d ' ')"
  distinct="$(printf '%s\n' "$lines" | cut -f2 | sort -u)"
  if [ "$(printf '%s\n' "$distinct" | wc -l | tr -d ' ')" -ne 1 ]; then
    echo "FAIL: $n golang base references carry more than one value:"
    printf '%s\n' "$distinct" | while IFS= read -r v; do
      echo "  $v"
      printf '%s\n' "$lines" | awk -F'\t' -v v="$v" '$2 == v { print "      " $1 }'
    done
    return 1
  fi
  echo "ok: $n golang base references (Dockerfiles + workflows) all pin $distinct"
}

tracked() {
  { git ls-files '*Dockerfile*'; git ls-files '.github/workflows/*.y*ml'; } | sort -u
}

if [ "${1:-}" = "--selftest" ]; then
  tmp="$(mktemp -d)" || exit 2
  trap 'rm -rf "$tmp"' EXIT
  D=sha256:27f2d3b83cfc5803c8078f8e730af0f7c431bf067afaec8f60a36fb763187cba
  OLD=sha256:3082400e369fa24d5fc60bca20edab3f6d604e0c5a690ec66b295eff4dd87ade
  files=()
  while IFS= read -r f; do files+=("$f"); done < <(tracked)
  [ "${#files[@]}" -gt 0 ] || { echo "FAIL: selftest: no tracked Dockerfile or workflow"; exit 1; }
  # The real tree must pass, otherwise "a planted defect fails" proves nothing.
  collect "${files[@]}" | verdict >/dev/null || { echo "FAIL: selftest: the real tree does not pass"; exit 1; }
  real="$(collect "${files[@]}" | head -n 1 | cut -f2)"
  n=0
  # No pipe into verdict here: a pipeline runs it in a subshell, where `n=` is lost and
  # an `exit 1` would not stop the selftest.
  plant() { # name, wanted exit, extra file(s) added to the real tree's files
    local name="$1" want="$2" rc; shift 2
    n=$((n + 1))
    if [ "$want" = 2 ]; then collect "$@" >"$tmp/lines"; else collect "${files[@]}" "$@" >"$tmp/lines"; fi
    verdict <"$tmp/lines" >"$tmp/out" 2>&1; rc=$?
    if [ "$rc" -ne "$want" ]; then
      echo "FAIL: selftest: '$name' exited $rc, wanted $want"; cat "$tmp/out"; exit 1
    fi
    sed "s/^/  planted ($name): /" "$tmp/out" | head -n 1
  }
  # 1. one copy lags: the real tree plus a Dockerfile whose digest is the old one
  printf 'FROM %s AS build\n' "${real%%@*}@$OLD" > "$tmp/Dockerfile.lag"
  plant "one Dockerfile keeps the old digest" 1 "$tmp/Dockerfile.lag"
  # 2. one workflow copy lags
  printf '    container:\n      image: %s\n' "${real%%@*}@$OLD" > "$tmp/lag.yaml"
  plant "one workflow container.image keeps the old digest" 1 "$tmp/lag.yaml"
  # 3. same digest, different tag (the whole ref is compared, not just the digest)
  printf 'FROM golang:1.26.9-alpine@%s AS build\n' "$D" > "$tmp/Dockerfile.tag"
  plant "same digest under another tag" 1 "$tmp/Dockerfile.tag"
  # 4. a golang FROM with no digest
  printf 'FROM golang:1.26-alpine AS build\n' > "$tmp/Dockerfile.nodigest"
  plant "golang FROM without a digest" 1 "$tmp/Dockerfile.nodigest"
  # 5. one digest character changed (still 64 hex)
  printf 'FROM %s AS build\n' "${real%%@*}@sha256:0${D#sha256:?}" > "$tmp/Dockerfile.digit"
  plant "one digest character changed" 1 "$tmp/Dockerfile.digit"
  # 6. nothing found (collect on the empty file only)
  : > "$tmp/Dockerfile.empty"
  plant "no golang reference at all" 2 "$tmp/Dockerfile.empty"
  # 7. the clean case passes (so 'rejects' is not 'rejects everything')
  printf 'FROM %s AS build\n' "$real" > "$tmp/Dockerfile.same"
  collect "${files[@]}" "$tmp/Dockerfile.same" >"$tmp/lines"
  verdict <"$tmp/lines" >/dev/null \
    || { echo "FAIL: selftest: a clean extra copy was rejected"; exit 1; }
  echo "ok: selftest — $n planted defects rejected, the real tree and a clean extra copy pass"
  exit 0
fi

files=()
while IFS= read -r f; do files+=("$f"); done < <(tracked)
[ "${#files[@]}" -gt 0 ] || { echo "FAIL: no tracked Dockerfile or workflow"; exit 2; }
collect "${files[@]}" | verdict
