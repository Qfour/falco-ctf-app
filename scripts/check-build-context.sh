#!/usr/bin/env bash
# The repo-root Docker build context must hold EVERY git-tracked file (app#501).
#
# WHY: `make test` (the required check `test`) runs Dockerfile.test with the repo
# root as the context, and .dockerignore decides which files get in. A tracked file
# the context drops is a file no test inside that build can read: internal/sourcehygiene
# (raw bidi controls), the contract-table readers, the ingress parity test. Before
# this check, `.github` and `.claude` were out of the context and the bidi scan
# silently did not cover workflows or agent files. A test that walks the context
# cannot see what the context lacks; this script is the one place that compares the
# context with `git ls-files`.
#
# HOW: the context is evaluated by Docker itself (BuildKit applies .dockerignore,
# including its `!` re-includes and `**/` patterns): a scratch Dockerfile
# (`FROM scratch` + `COPY . /ctx`) is built with the repo root as the context and
# `-o type=tar`, and the tar's file list is compared with `git ls-files` (minus files
# deleted in the work tree). Needs docker (CI ubuntu-latest has it; locally set
# DOCKER_CONTEXT as `make test` does).
#
# FAILS when
#   - a tracked file is not in the context (every one is listed, up to 30), or
#   - no tracked file is in the context at all (a context of nothing proves nothing).
# A file in the context that is not tracked is only reported (a local scratch file).
#
# --selftest builds the context again with a copy of .dockerignore that (a) also
# excludes go.mod, (b) excludes everything; each must FAIL, and the real one must
# pass, or this check proves nothing. The copy is handed to Docker as
# `<scratch Dockerfile>.dockerignore`, which BuildKit prefers over the root file.
#
# Usage: scripts/check-build-context.sh [--selftest]
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

selftest=0
case "${1:-}" in
  "") ;;
  --selftest) selftest=1 ;;
  *) echo "usage: $0 [--selftest]" >&2; exit 2 ;;
esac
command -v docker >/dev/null || { echo "FAIL: docker is needed to evaluate the build context" >&2; exit 2; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
dockerfile="$tmp/ctx.Dockerfile"
printf 'FROM scratch\nCOPY . /ctx\n' > "$dockerfile"

# context_files [dockerignore-copy]: prints the context's files, sorted (C locale).
context_files() {
  rm -f "$dockerfile.dockerignore"
  if [ -n "${1:-}" ]; then cp "$1" "$dockerfile.dockerignore"; fi
  if ! docker build --progress=plain -f "$dockerfile" -o "type=tar,dest=$tmp/ctx.tar" . > "$tmp/build.log" 2>&1; then
    cat "$tmp/build.log" >&2
    echo "FAIL: docker build of the scratch context failed" >&2
    return 1
  fi
  tar -tf "$tmp/ctx.tar" | awk '!/\/$/ { sub(/^ctx\//, ""); print }' | LC_ALL=C sort
}

# tracked: git ls-files minus the files deleted in the work tree, sorted (C locale).
git -c core.quotepath=off ls-files | LC_ALL=C sort > "$tmp/ls-files.txt"
git -c core.quotepath=off ls-files --deleted | LC_ALL=C sort > "$tmp/deleted.txt"
LC_ALL=C comm -23 "$tmp/ls-files.txt" "$tmp/deleted.txt" > "$tmp/tracked.txt"
[ -s "$tmp/tracked.txt" ] || { echo "FAIL: git ls-files listed nothing" >&2; exit 1; }

# compare <label> <context-list>: prints the verdict; returns 1 on FAIL.
compare() {
  local label="$1" ctx="$2" nmissing ncommon
  LC_ALL=C comm -23 "$tmp/tracked.txt" "$ctx" > "$tmp/missing.txt"
  LC_ALL=C comm -12 "$tmp/tracked.txt" "$ctx" > "$tmp/common.txt"
  nmissing="$(wc -l < "$tmp/missing.txt" | tr -d ' ')"
  ncommon="$(wc -l < "$tmp/common.txt" | tr -d ' ')"
  if [ "$ncommon" -eq 0 ]; then
    echo "FAIL ($label): no tracked file is in the build context"
    return 1
  fi
  if [ "$nmissing" -gt 0 ]; then
    echo "FAIL ($label): $nmissing tracked file(s) are not in the build context (.dockerignore drops them):"
    head -n 30 "$tmp/missing.txt" | sed 's/^/  /'
    return 1
  fi
  echo "ok ($label): the build context holds all $ncommon tracked files"
}

context_files > "$tmp/ctx-real.txt"
compare "real .dockerignore" "$tmp/ctx-real.txt"
extra="$(LC_ALL=C comm -13 "$tmp/tracked.txt" "$tmp/ctx-real.txt" | wc -l | tr -d ' ')"
[ "$extra" -eq 0 ] || echo "note: $extra file(s) in the context are not tracked (local files; the context is a clean checkout in CI)"

if [ "$selftest" -eq 1 ]; then
  # A tracked file excluded by an extra line must fail, and the message must name it.
  { cat .dockerignore; echo; echo 'go.mod'; } > "$tmp/di-drop"
  context_files "$tmp/di-drop" > "$tmp/ctx-drop.txt"
  if out="$(compare "selftest: go.mod excluded" "$tmp/ctx-drop.txt")"; then
    echo "FAIL: selftest: a .dockerignore that drops go.mod was ACCEPTED" >&2; exit 1
  fi
  case "$out" in *"  go.mod"*) ;; *) echo "FAIL: selftest: the failure does not name go.mod: $out" >&2; exit 1 ;; esac
  echo "ok (selftest): $(printf '%s' "$out" | head -n 1)"
  # A context of nothing must fail.
  printf '*\n' > "$tmp/di-all"
  context_files "$tmp/di-all" > "$tmp/ctx-all.txt"
  if out="$(compare "selftest: everything excluded" "$tmp/ctx-all.txt")"; then
    echo "FAIL: selftest: an empty context was ACCEPTED" >&2; exit 1
  fi
  echo "ok (selftest): $out"
  echo "ok: check-build-context selftest passed (2 broken .dockerignore copies rejected, the real one accepted)"
fi
