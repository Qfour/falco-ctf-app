#!/usr/bin/env bash
# app#322 (ADR-0031 H1 (h)): fail-closed guard that .dockerignore keeps
# excluding decrypted / credential files from the repo-root `docker build`
# context.
#
# WHY: this is a PUBLIC repo whose build contexts are mostly the repo root
# (scoreboard/auth-policy/collector, images/{ttyd-proxy,challenge,docs} and
# every Dockerfile.*; see the Makefile). Two images are the exception:
# images/ttyd and images/detect-grader use their OWN directory as context, so
# the root .dockerignore does not apply to them (they hold only a handful of
# tracked files and COPY two or three by name; an allowlist-form .dockerignore
# there is deliberately NOT added, and check 4 forbids any other .dockerignore
# so the root one stays the single source of truth). A sops-decrypted file (`*.dec.yaml`), a
# kubeconfig, or a local `*.secret.*` copy left in the working tree is sent to
# the Docker daemon unless .dockerignore excludes it. Nothing else notices a
# line being deleted from .dockerignore, so this makes it mechanical.
# The older secrets block (*.db / .env / .env.* / *.pem / *.key / *.cert /
# *.crt) is held to the same `**/` form: a bare `.env` or `*.key` only matches at the context root.
#
# CHECKS (all must pass, exit 0; otherwise exit 1):
#   1. Each REQUIRED pattern is present as an exact, non-comment line.
#      The `**/` form is required: a bare `*.dec.yaml` only matches at the
#      context root (.dockerignore, unlike .gitignore, has no implicit any-depth
#      matching), so it would miss `scripts/x.dec.yaml`.
#   2. NO `!` (re-include) line appears after the first REQUIRED line, whatever
#      it says. Docker's last matching line wins, and a `!` also applies when
#      it matches a PARENT directory (moby/patternmatcher MatchesOrParentMatches),
#      so `!**`, `!**/*.yaml` or `!charts/ctf-user/` placed after the secrets
#      block silently brings a `*.dec.yaml` back into the context. Matching on
#      the `!` line's text cannot catch that; position can. Legitimate
#      re-includes (`!charts/<name>/`) belong ABOVE the secrets block.
#   3. No git-tracked file matches any of the patterns. A tracked match would
#      mean the exclusion drops a file some build needs (or the guard's premise
#      "these are never committed" is already false).
#   4. No tracked `.dockerignore` / `<name>.dockerignore` other than the root
#      `.dockerignore`. BuildKit prefers `<Dockerfile>.dockerignore` over the
#      root file and a context-local `.dockerignore` replaces it for images
#      built from a subdirectory, so any extra one can drop these exclusions
#      without touching the root file.
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
  '**/.env.*'
  '**/*.pem'
  '**/*.key'
  '**/*.cert'
  '**/*.crt'
  'challenges/decks/'
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
  # Check 2: positional. First REQUIRED line number, then any `!` line after it.
  local first="" ln
  for p in "${REQUIRED[@]}"; do
    ln="$(grep -nxF -- "$p" "$f" | head -n 1 | cut -d: -f1 || true)"
    [ -n "$ln" ] || continue
    if [ -z "$first" ] || [ "$ln" -lt "$first" ]; then first="$ln"; fi
  done
  if [ -n "$first" ]; then
    if awk -v first="$first" 'NR > first && /^[[:space:]]*!/ { print NR ": " $0; bad = 1 } END { exit bad ? 0 : 1 }' "$f"; then
      echo "FAIL: $f has a ! (re-include) line after the first exclusion (line $first): last match wins, it can undo the block"
      rc=1
    fi
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
      case "$p" in
        */) # root-anchored directory pattern: match by path prefix
          if [[ "$f" == "$p"* ]]; then
            echo "FAIL: tracked file matches .dockerignore pattern $p: $f"
            rc=1
            break
          fi
          continue ;;
      esac
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
  local rc=0
  git ls-files | tracked_matches || rc=1
  git ls-files | extra_dockerignores || rc=1
  return "$rc"
}

# Reads paths on stdin; prints a FAIL line per path that is a .dockerignore
# other than the root one (check 4). Returns 1 if any.
extra_dockerignores() {
  local f rc=0
  while IFS= read -r f; do
    # shellcheck disable=SC2053
    if [[ "${f##*/}" == *.dockerignore && "$f" != .dockerignore ]]; then
      echo "FAIL: tracked $f would override/replace the root .dockerignore"
      rc=1
    fi
  done
  return "$rc"
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
    case "$p" in '**/'*) ;; *) continue ;; esac   # root-anchored by design
    esc="$(printf '%s' "$p" | sed 's/[][\.*^$/|]/\\&/g')"
    sed "s|^${esc}\$|${p#\*\*/}|" "$real" > "$tmp/rootonly"
    expect_reject "root-only form: ${p#\*\*/}" "$tmp/rootonly"
  done
  # Check 2 is positional: ANY `!` after the first exclusion must fail, however
  # innocent it looks (the 4 below were all accepted by the old text-based check
  # while undoing the block: last match wins, `!` also matches parent dirs).
  { cat "$real"; echo '!foo.dec.yaml'; } > "$tmp/negated"
  expect_reject "re-include after exclusion" "$tmp/negated"
  for neg in '!charts/ctf-user/' '!**/*.yaml' '!**' '!charts/scoreboard/'; do
    { cat "$real"; echo "$neg"; } > "$tmp/neg-tail"
    expect_reject "trailing re-include: $neg" "$tmp/neg-tail"
  done
  # The real `!charts/scoreboard/` moved from the charts block to the file end.
  { grep -vxF '!charts/scoreboard/' "$real"; echo '!charts/scoreboard/'; } > "$tmp/neg-moved"
  expect_reject "!charts/scoreboard/ moved below the secrets block" "$tmp/neg-moved"
  # Tracked-file check: a path list containing a match must be rejected, one
  # without must pass (otherwise "rejects" could just mean "rejects everything").
  expect_tracked_reject() { # path
    n=$((n + 1))
    if printf '%s\n' "$1" | tracked_matches >/dev/null 2>&1; then
      echo "FAIL: selftest: tracked-file check ACCEPTED $1"
      exit 1
    fi
  }
  for t in a.db sub/dir/x.db .env sub/.env .env.prod sub/.env.local \
           deploy/x.pem k/y.key z.cert ca/root.crt \
           challenges/decks/event.md sub/prod.dec.yaml sub/kubeconfig-prod x/flags.secret.yaml; do
    expect_tracked_reject "$t"
  done
  # Check 4: any tracked .dockerignore other than the root one.
  expect_extra_reject() { # path
    n=$((n + 1))
    if printf '%s\n' "$1" | extra_dockerignores >/dev/null 2>&1; then
      echo "FAIL: selftest: extra-.dockerignore check ACCEPTED $1"
      exit 1
    fi
  }
  for t in images/ttyd/.dockerignore images/detect-grader/.dockerignore \
           scoreboard/Dockerfile.dockerignore Dockerfile.test.dockerignore; do
    expect_extra_reject "$t"
  done
  printf '%s\n' .dockerignore docs/dockerignore.md \
    | extra_dockerignores >/dev/null \
    || { echo "FAIL: selftest: extra-.dockerignore check rejected innocent paths"; exit 1; }
  printf '%s\n' main.go charts/scoreboard/values.yaml challenges/01-x/brief.md docs/decks.md docs/env.md docs/key.md \
    | tracked_matches >/dev/null \
    || { echo "FAIL: selftest: tracked-file check rejected innocent paths"; exit 1; }
  echo "ok: selftest — guard rejected all $n broken variants (.dockerignore + tracked-file/extra-.dockerignore checks)"
  exit 0
fi

check_file "$file"
if [ "$check_tracked" -eq 1 ]; then
  check_tracked_files
fi
echo "ok: $file excludes ${#REQUIRED[@]} decrypted/credential patterns (all in **/ form); no tracked file matches"
