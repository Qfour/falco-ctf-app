#!/usr/bin/env bash
# Public-repo guard of ADR-0056 V84 (D20, A4e-3b): no tracked file carries the output of an
# EVENT's `scoreboard edition render` or `edition check`. Those outputs are the event's answers,
# its bundle digests and the record of its render, and each starts with a version header (the
# Go definitions: internal/edition/table.go headerPrefix, digests.go digestsHeaderPrefix,
# renderrecord.go renderRecordHeader). A line of a tracked file that BEGINS with one of them is
# refused, except:
#   - the practice edition's answers table and digests file, whose header carries the practice
#     run id (32 zeros) and nothing after it: `edition render --practice` writes them into
#     challenges/<cid>/edition/practice/, and they are public by design (ADR-0056 D8);
#   - ALLOWED_PATHS: tracked test fixtures that hold an event's header on purpose, named one by
#     one (today: the golden of WriteDigests). An entry that is no longer tracked fails, so the
#     list cannot keep a hole open for a file that is gone.
# The render record has no practice form: every tracked one is refused. A header in the middle
# of a line (a document, a quoted string of a Go test) is not the start of a file and is not
# refused. A header line with anything after the practice run id (a carriage return, for one) is
# not the practice form and is refused (fail-closed). Every tracked file is read, a binary one
# as text (-a), and only tracked files: an untracked render output is not in the repository yet.
#
# The four constants below are held to the Go definitions by
# internal/edition/flagguard_headers_test.go (a change of one side is red).
#
# Usage: ./scripts/check-edition-headers.sh             scan the tracked files of the work tree
#        ./scripts/check-edition-headers.sh --selftest  the scan can fail (scratch repositories)
#   CHECK_EDITION_HEADERS_ROOT=<dir>  scan that git work tree instead (the selftest uses it)
# Exit: 0 clean, 1 violation(s), 2 the scan itself failed or was misused (fail-closed: a broken
# `git grep` is not "no header found").
# Run by scripts/check-flags.sh (make check-flags; CI flag-guard), both modes.
set -euo pipefail

ANSWERS_PREFIX='# falco-ctf answers v1 run='
DIGESTS_PREFIX='# falco-ctf evidence-digests v1 run='
RECORD_HEADER='# falco-ctf render-record v1'
PRACTICE_RUN_ID='00000000000000000000000000000000'
ALLOWED_PATHS=(
  'internal/edition/testdata/digests-golden/digests.tsv'
)

# literal_ok: the header constants are spliced into an extended regular expression, so they may
# only hold characters that stand for themselves there.
literal_ok() {
  case "$1" in
    '' | *[!a-z0-9\ \#=-]*) return 1 ;;
  esac
  return 0
}

# scan <root>: the check of the header on the tracked files of the git work tree at <root>.
scan() {
  local root="$1" v p rc grc found errf
  for v in "$ANSWERS_PREFIX" "$DIGESTS_PREFIX" "$RECORD_HEADER"; do
    if ! literal_ok "$v"; then
      echo "FAIL: a header constant holds a character a regular expression would not take literally" >&2
      return 2
    fi
  done
  case "$PRACTICE_RUN_ID" in
    '' | *[!0]*)
      echo "FAIL: the practice run id must be zeros only" >&2
      return 2
      ;;
  esac
  if ! git -C "$root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "FAIL: $root is not a git work tree; the scan did not run" >&2
    return 2
  fi

  rc=0
  local excludes=()
  for p in "${ALLOWED_PATHS[@]}"; do
    excludes+=(":(exclude)$p")
    if ! git -C "$root" ls-files --error-unmatch -- "$p" >/dev/null 2>&1; then
      echo "FAIL: ALLOWED_PATHS names $p, which is not a tracked file: remove the entry" >&2
      rc=1
    fi
  done

  echo "==> scanning tracked files for the header of an event's render output (ADR-0056 V84)"
  if ! errf="$(mktemp)"; then
    echo "FAIL: no temporary file for the scan's errors; the scan did not run" >&2
    return 2
  fi
  # git grep: 0 = matches, 1 = none, >1 = error. Only 1 means "clean".
  set +e
  found="$(git -C "$root" grep -n -a -E \
    -e "^${RECORD_HEADER}" \
    --or '(' -e "^${ANSWERS_PREFIX}" --and --not -e "^${ANSWERS_PREFIX}${PRACTICE_RUN_ID}\$" ')' \
    --or '(' -e "^${DIGESTS_PREFIX}" --and --not -e "^${DIGESTS_PREFIX}${PRACTICE_RUN_ID}\$" ')' \
    -- . "${excludes[@]}" 2>"$errf")"
  grc=$?
  set -e
  if [ "$grc" -gt 1 ]; then
    echo "FAIL: git grep failed (exit $grc); the scan did not run, which is not clean:" >&2
    sed 's/^/  /' "$errf" >&2
    rm -f "$errf"
    return 2
  fi
  rm -f "$errf"
  if [ "$grc" -eq 0 ]; then
    echo "FAIL: a tracked file holds the header of an event's answers table, digests file or render record:" >&2
    printf '%s\n' "$found" | cut -c1-200 | sed 's/^/  /' >&2
    echo "  -> an event's render output is the operator's, never the public repository's (ADR-0056 D20, V84): remove it from git." >&2
    echo "     A practice edition carries the practice run id (32 zeros); a test fixture that needs an event header is named in ALLOWED_PATHS." >&2
    rc=1
  fi
  if [ "$rc" -eq 0 ]; then
    echo "  ok: no tracked file holds an event's render output header"
  fi
  return "$rc"
}

# ---- the selftest: scratch repositories with one planted file each ----

SELFTEST_FAILED=0
SELFTEST_CASES=0
SELFTEST_WORK=""

# st_repo <name> [nobase]: a new scratch repository; unless nobase, it holds the allowed fixture.
st_repo() {
  local repo="$SELFTEST_WORK/$1"
  mkdir -p "$repo"
  git -C "$repo" init -q
  if [ "${2:-}" != nobase ]; then
    st_put "$repo" "${ALLOWED_PATHS[0]}" "$(printf '%s%s\nseat-a\t01-demo\t%s' "$DIGESTS_PREFIX" "$ST_EVENT_RUN" "$ST_DIGEST")"
  fi
  printf '%s\n' "$repo"
}

# st_put <repo> <path> <content>: write the file (content and a final newline) and track it.
st_put() {
  mkdir -p "$(dirname "$1/$2")"
  printf '%s\n' "$3" >"$1/$2"
  git -C "$1" add -- "$2"
}

# st_expect <name> <want-exit> <repo>: the scan of the repository exits with want.
st_expect() {
  local got
  SELFTEST_CASES=$((SELFTEST_CASES + 1))
  set +e
  CHECK_EDITION_HEADERS_ROOT="$3" bash "$SELF" >/dev/null 2>&1
  got=$?
  set -e
  if [ "$got" -eq "$2" ]; then
    echo "  ok:   $1 (exit $got)"
  else
    echo "  FAIL: $1: exit $got, want $2" >&2
    SELFTEST_FAILED=1
  fi
}

selftest() {
  local r
  SELFTEST_WORK="$(mktemp -d)"
  trap 'rm -rf "$SELFTEST_WORK"' EXIT
  ST_EVENT_RUN='fedcba9876543210fedcba9876543210'
  ST_DIGEST="$(printf '%064d' 1)"
  local row
  row="$(printf '*\t01-demo\tq1\tplaceholder')"
  echo "==> check-edition-headers.sh self-test"

  r="$(st_repo event-answers)"
  st_put "$r" out/answers.tsv "$(printf '%s%s\n%s' "$ANSWERS_PREFIX" "$ST_EVENT_RUN" "$row")"
  st_expect "a tracked event answers table fails" 1 "$r"

  r="$(st_repo event-digests)"
  st_put "$r" out/digests.tsv "$(printf '%s%s\nseat-a\t01-demo\t%s' "$DIGESTS_PREFIX" "$ST_EVENT_RUN" "$ST_DIGEST")"
  st_expect "a tracked event digests file fails" 1 "$r"

  r="$(st_repo render-record)"
  st_put "$r" out/render-record.tsv "$(printf '%s\nrun-id\t%s' "$RECORD_HEADER" "$ST_EVENT_RUN")"
  st_expect "a tracked render record fails" 1 "$r"

  r="$(st_repo render-record-crlf)"
  st_put "$r" out/render-record.tsv "$(printf '%s\r\nrun-id\t%s\r' "$RECORD_HEADER" "$ST_EVENT_RUN")"
  st_expect "a tracked render record with CRLF line ends fails" 1 "$r"

  r="$(st_repo later-line)"
  st_put "$r" notes.txt "$(printf 'an introduction\n%s%s' "$DIGESTS_PREFIX" "$ST_EVENT_RUN")"
  st_expect "an event header on a later line of a file fails" 1 "$r"

  # (a NUL byte cannot be held in a shell variable, so the file is written directly)
  r="$(st_repo binary)"
  printf 'x\000y\n%s%s\n' "$ANSWERS_PREFIX" "$ST_EVENT_RUN" >"$r/blob.bin"
  git -C "$r" add -- blob.bin
  st_expect "an event header in a file git takes for binary (a NUL byte) fails" 1 "$r"

  r="$(st_repo allowed-elsewhere)"
  st_put "$r" internal/edition/testdata/other/digests.tsv "$(cat "$r/${ALLOWED_PATHS[0]}")"
  st_expect "the allowed fixture's content at another path fails" 1 "$r"

  r="$(st_repo stale nobase)"
  st_put "$r" README.md "nothing here"
  st_expect "an allowed entry that is not tracked fails" 1 "$r"

  r="$(st_repo practice)"
  st_put "$r" challenges/01-demo/edition/practice/answers.tsv "$(printf '%s%s\n%s' "$ANSWERS_PREFIX" "$PRACTICE_RUN_ID" "$row")"
  st_put "$r" challenges/01-demo/edition/practice/digests.tsv "$(printf '%s%s\n*\t01-demo\t%s' "$DIGESTS_PREFIX" "$PRACTICE_RUN_ID" "$ST_DIGEST")"
  st_expect "the practice edition (the practice run id) passes" 0 "$r"

  r="$(st_repo practice-crlf)"
  st_put "$r" challenges/01-demo/edition/practice/answers.tsv "$(printf '%s%s\r\n%s' "$ANSWERS_PREFIX" "$PRACTICE_RUN_ID" "$row")"
  st_expect "a practice header with something after the run id fails" 1 "$r"

  r="$(st_repo mid-line)"
  st_put "$r" docs/x.md "$(printf 'the header is `%s%s` and `%s`' "$ANSWERS_PREFIX" "$ST_EVENT_RUN" "$RECORD_HEADER")"
  st_expect "a header in the middle of a line (a document) passes" 0 "$r"

  r="$(st_repo untracked)"
  printf '%s%s\n' "$ANSWERS_PREFIX" "$ST_EVENT_RUN" >"$r/answers.tsv"
  st_expect "an untracked event file passes (only tracked files are the repository's)" 0 "$r"

  r="$(st_repo clean)"
  st_put "$r" README.md "nothing here"
  st_expect "a tree with no header but the allowed fixture passes (the scan still runs)" 0 "$r"

  # A scan that cannot run is NOT clean: point it at a directory that is not a repository.
  mkdir -p "$SELFTEST_WORK/not-a-repo"
  st_expect "a root that is not a git work tree does not pass" 2 "$SELFTEST_WORK/not-a-repo"

  if [ "$SELFTEST_FAILED" -ne 0 ]; then
    echo "FAIL: check-edition-headers.sh self-test ($SELFTEST_CASES cases)" >&2
    return 1
  fi
  echo "  ok: check-edition-headers.sh self-test passed ($SELFTEST_CASES cases)"
  return 0
}

SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"

case "${1:-}" in
  --selftest)
    if [ -n "${CHECK_EDITION_HEADERS_ROOT:-}" ]; then
      echo "usage: --selftest makes its own repositories; CHECK_EDITION_HEADERS_ROOT is not taken with it" >&2
      exit 2
    fi
    if selftest; then
      exit 0
    fi
    exit 1
    ;;
  '') ;;
  *)
    echo "usage: $0 [--selftest]" >&2
    exit 2
    ;;
esac

if [ -n "${CHECK_EDITION_HEADERS_ROOT:-}" ]; then
  root="$CHECK_EDITION_HEADERS_ROOT"
elif ! root="$(git rev-parse --show-toplevel 2>/dev/null)"; then
  echo "FAIL: not inside a git work tree; the scan did not run" >&2
  exit 2
fi
if scan "$root"; then
  exit 0
else
  exit $?
fi
