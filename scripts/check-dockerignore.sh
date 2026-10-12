#!/usr/bin/env bash
# app#322 (ADR-0031 H1 (h)): fail-closed guard that .dockerignore keeps
# excluding decrypted / credential files from every `docker build` context.
#
# WHY: this is a PUBLIC repo whose Dockerfile.* / images/*/Dockerfile use the
# repo root as build context. A sops-decrypted file (`*.dec.yaml`), a
# kubeconfig, or a local `*.secret.*` copy left in the working tree is sent to
# the Docker daemon unless .dockerignore excludes it. Nothing else notices a
# line being deleted from .dockerignore, so this makes it mechanical.
# The older secrets block (*.db / .env / *.pem / *.key / *.cert) is held to the
# same `**/` form: a bare `.env` or `*.key` only matches at the context root.
#
# CHECKS (all must pass, exit 0; otherwise exit 1):
#   1. Each REQUIRED pattern is present as an exact, non-comment line.
#      The `**/` form is required: a bare `*.dec.yaml` only matches at the
#      context root (.dockerignore, unlike .gitignore, has no implicit any-depth
#      matching), so it would miss `scripts/x.dec.yaml`.
#   2. No later `!` (re-include) line mentions one of the patterns' stems — a
#      negation placed after the exclusion would silently undo it.
#   3. No git-tracked file matches any of the patterns. A tracked match would
#      mean the exclusion drops a file some build needs (or the guard's premise
#      "these are never committed" is already false).
#
# --selftest runs the checks against deliberately broken copies and fails
# unless each one is rejected (and the real file still passes). CI runs both.
#
# Usage: scripts/check-dockerignore.sh [--file PATH] [--selftest]
#   --file PATH  check PATH instead of ./.dockerignore (used by --selftest)
#   (no git-tracked-file check when --file is given: that check is about the
#    real repo, not a fixture.)
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

REQUIRED=(
  '**/*.dec.yaml'
  '**/*.dec.json'
  '**/kubeconfig*'
  '**/*.secret.*'
  '**/*.db'
  '**/.env'
  '**/*.pem'
  '**/*.key'
  '**/*.cert'
)

file=.dockerignore
check_tracked=1
selftest=0
while [ $# -gt 0 ]; do
  case "$1" in
    --file) [ $# -ge 2 ] || { echo "error: --file needs a path" >&2; exit 2; }
            file="$2"; check_tracked=0; shift 2 ;;
    --selftest) selftest=1; shift ;;
    *) echo "usage: $0 [--file PATH] [--selftest]" >&2; exit 2 ;;
  esac
done

check_file() {
  local f="$1" p rc=0
  [ -s "$f" ] || { echo "FAIL: $f is missing or empty"; return 1; }
  for p in "${REQUIRED[@]}"; do
    # -x: whole line, -F: literal (the patterns contain * which is a regex char).
    # A commented-out copy ("# **/kubeconfig*") is not a whole-line match.
    if ! grep -qxF -- "$p" "$f"; then
      echo "FAIL: $f lacks the exclusion line: $p"
      rc=1
    fi
  done
  # Check 2: any re-include (`!...`) that targets these stems.
  if grep -nE '^[[:space:]]*!.*(\.dec\.|kubeconfig|\.secret\.|\.db|\.env|\.pem|\.key|\.cert)' "$f"; then
    echo "FAIL: $f re-includes (!) a path matching a decrypted/credential pattern"
    rc=1
  fi
  return "$rc"
}

# Reads paths on stdin; prints a FAIL line per path whose basename matches one
# of the REQUIRED patterns (the patterns are `**/<basename-glob>`, so the glob is
# the pattern minus its `**/` prefix — one source of truth, no second list).
# Returns 1 if any path matched.
tracked_matches() {
  local f b p g rc=0
  while IFS= read -r f; do
    b="${f##*/}"
    for p in "${REQUIRED[@]}"; do
      g="${p#\*\*/}"
      # shellcheck disable=SC2053  # $g is intentionally a glob
      if [[ "$b" == $g ]]; then
        echo "FAIL: tracked file matches .dockerignore pattern $p: $f"
        rc=1
        break
      fi
    done
  done
  return "$rc"
}

check_tracked_files() {
  git ls-files | tracked_matches
}

if [ "$selftest" -eq 1 ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  real=.dockerignore
  [ -s "$real" ] || { echo "FAIL: selftest needs the real $real"; exit 1; }
  # The real file must pass, otherwise "broken input fails" proves nothing.
  check_file "$real" >/dev/null || { echo "FAIL: selftest: real $real does not pass"; exit 1; }
  n=0
  expect_reject() { # name, file
    n=$((n + 1))
    if check_file "$2" >/dev/null 2>&1; then
      echo "FAIL: selftest: guard ACCEPTED a broken .dockerignore ($1)"
      exit 1
    fi
  }
  : > "$tmp/empty";                                expect_reject "empty file" "$tmp/empty"
  for p in "${REQUIRED[@]}"; do
    grep -vxF -- "$p" "$real" > "$tmp/drop" || true
    expect_reject "line removed: $p" "$tmp/drop"
    sed "s|^$(printf '%s' "$p" | sed 's/[][\.*^$/|]/\\&/g')\$|# $p|" "$real" > "$tmp/comment"
    expect_reject "line commented out: $p" "$tmp/comment"
  done
  # Bare (root-only) form of each pattern: the `**/` stripped. Must be rejected
  # — a bare `*.key` / `.env` is exactly the gap app#322 closes.
  for p in "${REQUIRED[@]}"; do
    esc="$(printf '%s' "$p" | sed 's/[][\.*^$/|]/\\&/g')"
    sed "s|^${esc}\$|${p#\*\*/}|" "$real" > "$tmp/rootonly"
    expect_reject "root-only form: ${p#\*\*/}" "$tmp/rootonly"
  done
  { cat "$real"; echo '!foo.dec.yaml'; } > "$tmp/negated"
  expect_reject "re-include after exclusion" "$tmp/negated"
  # Tracked-file check: a path list containing a match must be rejected, one
  # without must pass (otherwise "rejects" could just mean "rejects everything").
  expect_tracked_reject() { # path
    n=$((n + 1))
    if printf '%s\n' "$1" | tracked_matches >/dev/null 2>&1; then
      echo "FAIL: selftest: tracked-file check ACCEPTED $1"
      exit 1
    fi
  }
  for t in a.db sub/dir/x.db .env sub/.env deploy/x.pem k/y.key z.cert \
           sub/prod.dec.yaml sub/kubeconfig-prod x/flags.secret.yaml; do
    expect_tracked_reject "$t"
  done
  printf '%s\n' main.go charts/scoreboard/values.yaml .env.example docs/key.md \
    | tracked_matches >/dev/null \
    || { echo "FAIL: selftest: tracked-file check rejected innocent paths"; exit 1; }
  echo "ok: selftest — guard rejected all $n broken variants (.dockerignore + tracked-file check)"
  exit 0
fi

check_file "$file"
if [ "$check_tracked" -eq 1 ]; then
  check_tracked_files
fi
echo "ok: $file excludes ${#REQUIRED[@]} decrypted/credential patterns (all in **/ form); no tracked file matches"
