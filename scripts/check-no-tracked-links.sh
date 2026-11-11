#!/usr/bin/env bash
# The tracked tree holds no symlink and no submodule (ADR-0054 D2, V1 (g)).
#
# WHY: platform's release (scripts/release-images.sh) sends each image's build
# context to the docker daemon, and `make build` gives context `.` (the whole tracked
# tree) to six of the eight images. A tracked symlink (git mode 120000) or submodule
# (160000) inside a context can make that context carry content from outside the
# clone, or content nobody reviewed in this repo. platform judges the same thing
# from `git ls-tree -r <commit> -- <context>`; this script judges it from the index,
# on the CI host, where both a symlink and a gitlink are visible. A Go test cannot:
# the test build context has no `.git` (so no submodule shows) and how BuildKit
# copies a symlink into it depends on the BuildKit version.
#
# HOW: `git ls-files -s` of the repository this script is run in; every entry whose
# mode is 120000 or 160000 is a problem. Judged by exit status, never by output.
#
# FAILS when
#   - an entry is mode 120000 (symlink) or 160000 (gitlink / submodule): every one is
#     listed with its path, up to 30, or
#   - `git ls-files` fails (not a git work tree, ...), or
#   - it lists nothing (an empty index proves nothing; it is never a pass).
#
# --selftest builds throwaway repositories under a temporary directory: a clean one
# (one regular file) must PASS; one with a symlink added, one with a gitlink added
# (`git update-index --add --cacheinfo 160000,<sha>,sub`) and one with an empty index
# must each FAIL and the message must name the entry; a directory that is not a git
# work tree must FAIL. Without that the check could be accepting everything.
#
# Usage: scripts/check-no-tracked-links.sh [--selftest]
set -euo pipefail

selftest=0
case "${1:-}" in
  "") ;;
  --selftest) selftest=1 ;;
  *) echo "usage: $0 [--selftest]" >&2; exit 2 ;;
esac

# check_tree <dir>: prints the verdict; returns 1 on FAIL.
check_tree() {
  local dir="$1" entries total bad nbad
  if ! entries="$(git -c core.quotepath=off -C "$dir" ls-files -s 2>&1)"; then
    echo "FAIL: git ls-files -s failed in $dir (is it a git work tree?): $entries"
    return 1
  fi
  if [ -z "$entries" ]; then
    echo "FAIL: git ls-files -s listed nothing in $dir (an empty index is not a pass)"
    return 1
  fi
  total="$(printf '%s\n' "$entries" | awk 'END { print NR }')"
  # <mode> <sha> <stage><TAB><path>: the mode is the first 6 characters.
  bad="$(printf '%s\n' "$entries" | awk '{ m = substr($0, 1, 6); if (m == "120000" || m == "160000") print m " " substr($0, index($0, "\t") + 1) }')"
  if [ -n "$bad" ]; then
    nbad="$(printf '%s\n' "$bad" | awk 'END { print NR }')"
    echo "FAIL: $nbad tracked symlink (120000) / submodule (160000) entr(y/ies) of $total (ADR-0054 D2):"
    printf '%s\n' "$bad" | awk 'NR <= 30 { print "  " $0 }'
    return 1
  fi
  echo "ok: no tracked symlink (120000) or submodule (160000) among $total entries"
}

if [ "$selftest" -eq 0 ]; then
  top="$(git rev-parse --show-toplevel)"
  if ! out="$(check_tree "$top")"; then
    echo "$out"
    exit 1
  fi
  echo "$out"
  exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# newrepo <name>: an empty repository at $tmp/<name>.
newrepo() {
  mkdir "$tmp/$1"
  git -C "$tmp/$1" init -q
}
# newrepo_with_file <name>: ... holding one tracked regular file.
newrepo_with_file() {
  newrepo "$1"
  printf 'x\n' > "$tmp/$1/file.txt"
  git -C "$tmp/$1" add file.txt
}
# must_fail <label> <dir> <needle>: check_tree must FAIL and its message must hold needle.
must_fail() {
  local out
  if out="$(check_tree "$2")"; then
    echo "FAIL: selftest: $1 was ACCEPTED: $out" >&2
    exit 1
  fi
  case "$out" in
    *"$3"*) ;;
    *) echo "FAIL: selftest: $1 failed without naming '$3': $out" >&2; exit 1 ;;
  esac
  echo "ok (selftest): $1 -> $(printf '%s' "$out" | head -n 1)"
}

# a clean repository passes
newrepo_with_file clean
if ! out="$(check_tree "$tmp/clean")"; then
  echo "FAIL: selftest: a clean repository was REJECTED: $out" >&2
  exit 1
fi
echo "ok (selftest): a clean repository -> $out"

# a symlink fails and is named
newrepo_with_file symlink
ln -s file.txt "$tmp/symlink/lnk"
git -C "$tmp/symlink" add lnk
must_fail "a tracked symlink" "$tmp/symlink" "120000 lnk"

# a gitlink (submodule) fails and is named; the sha is any 40 hex digits
newrepo_with_file gitlink
git -C "$tmp/gitlink" update-index --add --cacheinfo 160000,0123456789abcdef0123456789abcdef01234567,sub
must_fail "a tracked submodule" "$tmp/gitlink" "160000 sub"

# an empty index fails (zero entries is not a pass)
newrepo empty
must_fail "an empty index" "$tmp/empty" "listed nothing"

# a directory that is not a git work tree fails; git must not find a repository above it
mkdir "$tmp/notrepo"
GIT_CEILING_DIRECTORIES="$tmp" must_fail "a directory that is not a git work tree" "$tmp/notrepo" "git ls-files -s failed"

echo "ok: check-no-tracked-links selftest passed (symlink, submodule, empty index and non-repo rejected, a clean repo accepted)"
