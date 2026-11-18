#!/usr/bin/env bash
# Public-repo guard of ADR-0056 V84 (D20, A4e-3b) and V93 (A4e-3c, the second check below).
# V84: no tracked file carries one of the THREE
# version headers of an EVENT's `scoreboard edition render` / `edition check` output: the header
# of the event's answers table, of its bundle digests file and of its render record (the Go
# definitions: internal/edition/table.go headerPrefix, digests.go digestsHeaderPrefix,
# renderrecord.go renderRecordHeader). A line of a tracked file that BEGINS with one of them is
# refused, except:
#   - the practice edition's answers table and digests file, whose header carries the practice
#     run id (32 zeros) and nothing after it: `edition render --practice` writes them into
#     challenges/<cid>/edition/practice/, and they are public by design (ADR-0056 D8);
#   - ALLOWED_PATHS: tracked test fixtures that hold an event's header on purpose, named one by
#     one (today: the golden of WriteDigests). Each entry must be exactly the path of ONE tracked
#     regular file (the line of `git ls-files -s` for it, compared as a whole: a directory, a
#     glob, a link or a path that is not tracked fails), and is excluded as a literal pathspec
#     (`:(exclude,literal)`), so an entry can never take a tree out of the scan.
# The render record has no practice form: every tracked one is refused. A header in the middle
# of a line (a document, a quoted string of a Go test) is not the start of a file and is not
# refused. A header line with anything after the practice run id (a carriage return, for one) is
# not the practice form and is refused (fail-closed). Every tracked file is read, a binary one
# as text (-a), and only tracked files: an untracked render output is not in the repository yet.
#
# The second check (ADR-0056 V93, A4e-3c): the bundles of an event's render
# (`--out`/evidence/<seat>/<cid>/<file>) are plain files with no header, so the check above does
# not see a commit of those files alone, and one bundle is a leak of answers. So no tracked PATH
# may hold, at any depth, the segments `evidence/<seat>/<cid>/` followed by one segment or more
# (a nested <file> too). Each of the three is matched as a WHOLE segment: `evidence` is the
# event's evidence directory name (EVIDENCE_DIR), <seat> is in the seat grammar of ADR-0042
# (SEAT_PATTERN) and <cid> in the challenge id grammar (CHALLENGE_ID_PATTERN); `myevidence/...`,
# or a segment of which only a part has the shape of a seat, is not a match. The practice
# edition's flat bundle (challenges/<cid>/edition/practice/evidence/<file>) has no seat
# directory and does not match; a seat-shaped nesting under it does, and is refused. Any other
# nesting there is an error of the practice layout, which internal/edition (practicelayout.go,
# V11, V81) refuses: this script keeps no second definition of that layout. A tracked path that
# must have the shape (a test fixture) is named in EVIDENCE_ALLOWED_PATHS, one tracked regular
# file an entry, as for ALLOWED_PATHS (today: none). Not covered: a bundle committed under a
# renamed evidence directory, or the seat directory alone; `edition render` refuses an --out in
# a git worktree or in the challenges tree (D20), and the platform checks the host side of the
# mount (ADR-0056 V83).
#
# The four header constants and the list ALLOWED_PATHS below are held to the Go definitions (and
# the list to its one entry) by internal/edition/flagguard_headers_internal_test.go, which also
# holds scripts/check-flags.sh to running both modes of this script. The three parts of the path
# rule, the way scan_evidence joins them and the empty EVIDENCE_ALLOWED_PATHS are held by
# internal/edition/flagguard_evidence_internal_test.go.
#
# Usage: bash scripts/check-edition-headers.sh             scan the tracked files of the work tree
#        bash scripts/check-edition-headers.sh --selftest  the scan can fail (scratch repositories)
#   CHECK_EDITION_HEADERS_ROOT=<dir>  scan that git work tree instead (the selftest uses it)
# (The file's mode is 0644: it is run through bash.)
# Exit: 0 clean, 1 violation(s), 2 the scan itself failed or was misused (fail-closed: a broken
# `git grep` or `git ls-files` is not "nothing found"). Both checks run on every scan; the exit
# is the larger of their two.
# Run by scripts/check-flags.sh (make check-flags; CI flag-guard), both modes.
set -euo pipefail

ANSWERS_PREFIX='# falco-ctf answers v1 run='
DIGESTS_PREFIX='# falco-ctf evidence-digests v1 run='
RECORD_HEADER='# falco-ctf render-record v1'
PRACTICE_RUN_ID='00000000000000000000000000000000'
ALLOWED_PATHS=(
  'internal/edition/testdata/digests-golden/digests.tsv'
)

# The three parts of the path rule of V93, byte for byte the Go definitions: EventEvidenceDirName
# (internal/edition/practicelayout.go), identity.SeatPattern (internal/identity/seat.go, the
# grammar of ADR-0042) and challengeid.Pattern (internal/catalog/challengeid). The two Go
# patterns are POSIX EREs as they stand, with the same language: they use only bracket
# expressions of ASCII ranges with a last literal `-`, a bounded repetition {m,n}, a group and
# `?`, which mean the same in an ERE and in Go's syntax, and scan_evidence matches under
# LC_ALL=C, where a range is a range of bytes. So no translation is kept here: the copy is the
# definition's text, and grammar_body only takes the anchors off to put the body between `/`.
EVIDENCE_DIR='evidence'
SEAT_PATTERN='^[a-z0-9]([a-z0-9-]{0,51}[a-z0-9])?$'
CHALLENGE_ID_PATTERN='^[0-9]{2}-[a-z0-9-]{1,60}$'
EVIDENCE_ALLOWED_PATHS=(
)

# literal_ok: the header constants are spliced into an extended regular expression, so they may
# only hold characters that stand for themselves there.
literal_ok() {
  case "$1" in
    '' | *[!a-z0-9\ \#=-]*) return 1 ;;
  esac
  return 0
}

# allowed_entry_ok <root> <entry>: the entry of ALLOWED_PATHS is a plain relative path (letters,
# digits, `.`, `_`, `-` and `/`: no glob character, no `..`) and `git ls-files -s` of it, as a
# literal pathspec, is exactly one line: a regular file (mode 100644 or 100755) at that very path.
# A directory gives the lines of the files under it, a link mode 120000, a path that is not
# tracked nothing: each fails. It prints why it fails.
allowed_entry_ok() {
  local root="$1" p="$2" listed tab
  tab="$(printf '\t')"
  case "$p" in
    '' | /* | *..* | *[!A-Za-z0-9._/-]*)
      echo "FAIL: ALLOWED_PATHS has the entry '$p', which is not a plain relative path of one file (no glob, no ..)" >&2
      return 1
      ;;
  esac
  if ! listed="$(git -C "$root" ls-files -s -- ":(literal)$p" 2>/dev/null)"; then
    echo "FAIL: git ls-files failed for the ALLOWED_PATHS entry $p" >&2
    return 1
  fi
  case "$listed" in
    *"$tab"*"$tab"* | *$'\n'*)
      echo "FAIL: ALLOWED_PATHS names $p, which is not one tracked file (a directory?): name the file itself" >&2
      return 1
      ;;
    "100644 "*" 0$tab$p" | "100755 "*" 0$tab$p")
      return 0
      ;;
  esac
  echo "FAIL: ALLOWED_PATHS names $p, which is not a tracked regular file at that path: remove or correct the entry" >&2
  return 1
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
    if allowed_entry_ok "$root" "$p"; then
      excludes+=(":(exclude,literal)$p")
    else
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
    -- . ${excludes[@]+"${excludes[@]}"} 2>"$errf")"
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

# grammar_body <pattern>: the pattern without its one leading `^` and one trailing `$`, printed,
# so that it can stand between two `/` of the path rule. It fails (prints nothing) when the
# pattern is not anchored at both ends, or its body is empty or holds `^`, `$`, `/`, `.` or a
# backslash: an anchor, a negated class or a `.` there could match a `/` or the edge of the path
# and stop the body from being one whole segment, and a backslash is not taken alike by every
# ERE. (A top-level `|` cannot leak: scan_evidence puts each body in a group.)
grammar_body() {
  local p="$1" b
  case "$p" in
    '^'*'$') ;;
    *) return 1 ;;
  esac
  b="${p#^}"
  b="${b%\$}"
  case "$b" in
    '' | *'^'* | *'$'* | *'/'* | *'.'* | *'\'*) return 1 ;;
  esac
  printf '%s\n' "$b"
}

# evidence_hits <ere> <list>: prints (shell-quoted, one a line) each path of the NUL-separated
# list whose form "/<path>" the ERE matches, and returns 0 when it printed one, 1 when none
# matched, 2 when the ERE is broken: it must take its own example and refuse two near misses
# first, and a match that is neither a hit nor a miss ([[ =~ ]] exit 2) is not a miss. The caller
# runs it in a subshell with LC_ALL=C, so that a bracket range is a range of bytes and no byte of
# a path is an invalid character.
evidence_hits() {
  local re="$1" list="$2" p m hit=1
  if ! [[ "/${EVIDENCE_DIR}/user1/01-demo/f" =~ $re ]]; then
    return 2
  fi
  if [[ "/${EVIDENCE_DIR}/user1/01-demo" =~ $re ]] || [[ "/x${EVIDENCE_DIR}/user1/01-demo/f" =~ $re ]]; then
    return 2
  fi
  while IFS= read -r -d '' p || [ -n "$p" ]; do
    m=0
    # shellcheck disable=SC2319  # the status of [[ =~ ]] itself is wanted: 1 = no match, 2 = a broken ERE
    [[ "/$p" =~ $re ]] || m=$?
    case "$m" in
      0)
        printf '%q\n' "$p"
        hit=0
        ;;
      1) ;;
      *) return 2 ;;
    esac
  done <"$list"
  return "$hit"
}

# scan_evidence <root> [allowed...]: the check of V93 on the tracked paths of the git work tree
# at <root>. Each allowed entry is held to allowed_entry_ok (one tracked regular file at that
# very path) and excluded as a literal pathspec. The main scan passes EVIDENCE_ALLOWED_PATHS.
# A tracked path, here, is a line of `git ls-files -z`: read up to each NUL, so a path with a
# space or a newline is one path.
scan_evidence() {
  local root="$1" p rc=0 hrc listf errf found seat_body cid_body evidence_ere
  shift
  case "$EVIDENCE_DIR" in
    '' | *[!a-z0-9_-]*)
      echo "FAIL: EVIDENCE_DIR holds a character a regular expression would not take literally" >&2
      return 2
      ;;
  esac
  if ! seat_body="$(grammar_body "$SEAT_PATTERN")" || ! cid_body="$(grammar_body "$CHALLENGE_ID_PATTERN")"; then
    echo "FAIL: SEAT_PATTERN or CHALLENGE_ID_PATTERN is not an anchored pattern whose body can stand for one segment" >&2
    return 2
  fi
  # `evidence`, a seat and a challenge id, each a whole segment (the path is matched as
  # "/<path>", so the first `/` is the start of a segment), then one more segment.
  evidence_ere="/${EVIDENCE_DIR}/(${seat_body})/(${cid_body})/[^/]"
  if ! git -C "$root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "FAIL: $root is not a git work tree; the evidence scan did not run" >&2
    return 2
  fi

  local excludes=()
  for p in ${1+"$@"}; do
    if allowed_entry_ok "$root" "$p"; then
      excludes+=(":(exclude,literal)$p")
    else
      rc=1
    fi
  done

  echo "==> scanning tracked paths for the layout of an event's evidence bundles (ADR-0056 V93)"
  if ! listf="$(mktemp)"; then
    echo "FAIL: no temporary file for the list of tracked paths; the scan did not run" >&2
    return 2
  fi
  if ! errf="$(mktemp)"; then
    rm -f "$listf"
    echo "FAIL: no temporary file for the scan's errors; the scan did not run" >&2
    return 2
  fi
  if ! git -C "$root" ls-files -z -- . ${excludes[@]+"${excludes[@]}"} >"$listf" 2>"$errf"; then
    echo "FAIL: git ls-files failed; the scan did not run, which is not clean:" >&2
    sed 's/^/  /' "$errf" >&2
    rm -f "$listf" "$errf"
    return 2
  fi
  set +e
  found="$(
    export LC_ALL=C
    evidence_hits "$evidence_ere" "$listf"
  )"
  hrc=$?
  set -e
  rm -f "$listf" "$errf"
  case "$hrc" in
    0)
      echo "FAIL: a tracked path has the layout of an event's evidence bundle (evidence/<seat>/<cid>/<file>):" >&2
      printf '%s\n' "$found" | cut -c1-200 | sed 's/^/  /' >&2
      echo "  -> one bundle is a seat's answers: an event's render output is the operator's, never the public repository's (ADR-0056 D20, V93): remove it from git." >&2
      echo "     A practice bundle is flat (edition/practice/evidence/<file>); a test fixture that needs the shape is named in EVIDENCE_ALLOWED_PATHS." >&2
      rc=1
      ;;
    1) ;;
    *)
      echo "FAIL: the path rule did not match as it must (exit $hrc); the scan did not run, which is not clean" >&2
      return 2
      ;;
  esac
  if [ "$rc" -eq 0 ]; then
    echo "  ok: no tracked path has the layout of an event's evidence bundle"
  fi
  return "$rc"
}

# ---- the selftest: scratch repositories with one planted file each ----
#
# The selftest runs as the condition of an `if`, where errexit does not stop anything, so every
# step that makes a case checks its own exit status: a scratch repository or a file that could
# not be made ends the selftest with exit 2 (st_die), and never lets a case that wants exit 0
# pass without having tried anything.

SELFTEST_FAILED=0
SELFTEST_CASES=0
SELFTEST_WORK=""

# st_die <what>: the selftest could not set a case up: exit 2 (from a command substitution, the
# caller sees the status and dies in turn).
st_die() {
  echo "FAIL: check-edition-headers.sh self-test: could not set up: $1" >&2
  exit 2
}

# st_repo <name> [nobase]: a new scratch repository; unless nobase, it holds the allowed fixture.
st_repo() {
  local repo="$SELFTEST_WORK/$1"
  mkdir -p "$repo" || st_die "the directory $1"
  git -C "$repo" init -q || st_die "git init of $1"
  if [ "${2:-}" != nobase ]; then
    st_put "$repo" "${ALLOWED_PATHS[0]}" "$(printf '%s%s\nseat-a\t01-demo\t%s' "$DIGESTS_PREFIX" "$ST_EVENT_RUN" "$ST_DIGEST")"
  fi
  printf '%s\n' "$repo"
}

# st_put <repo> <path> <content>: write the file (content and a final newline) and track it.
st_put() {
  mkdir -p "$(dirname "$1/$2")" || st_die "the directory of $2"
  printf '%s\n' "$3" >"$1/$2" || st_die "the file $2"
  git -C "$1" add -- "$2" || st_die "git add of $2"
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

# st_entry <name> <want: 0 or 1> <repo> <entry>: allowed_entry_ok of the entry in the repository.
st_entry() {
  local got=0
  SELFTEST_CASES=$((SELFTEST_CASES + 1))
  allowed_entry_ok "$3" "$4" >/dev/null 2>&1 || got=1
  if [ "$got" -eq "$2" ]; then
    echo "  ok:   $1 (status $got)"
  else
    echo "  FAIL: $1: status $got, want $2" >&2
    SELFTEST_FAILED=1
  fi
}

# st_call <name> <want-exit> <command...>: the command (a function of this script) exits with
# want. It runs in a subshell, so a constant it changes does not reach the next case.
st_call() {
  local name="$1" want="$2" got
  shift 2
  SELFTEST_CASES=$((SELFTEST_CASES + 1))
  set +e
  ("$@") >/dev/null 2>&1
  got=$?
  set -e
  if [ "$got" -eq "$want" ]; then
    echo "  ok:   $name (exit $got)"
  else
    echo "  FAIL: $name: exit $got, want $want" >&2
    SELFTEST_FAILED=1
  fi
}

# Copies of the path rule with one part broken: each must stop the scan (exit 2), not run it.
st_unanchored_seat() {
  SEAT_PATTERN='[a-z0-9]+'
  scan_evidence "$1"
}
st_dot_challenge_id() {
  CHALLENGE_ID_PATTERN='^[0-9]{2}-.+$'
  scan_evidence "$1"
}
st_unbalanced_seat() {
  SEAT_PATTERN='^[a-z0-9]([a-z0-9-]{0,51}[a-z0-9]?$'
  scan_evidence "$1"
}

# st_evidence <name> <want-exit> <path>...: a scratch repository (with the allowed fixture of
# V84, so that only the evidence check can fail) that tracks a file at each path; the scan of
# the whole script exits with want.
st_evidence() {
  local name="$1" want="$2" r p
  shift 2
  r="$(st_repo "ev-$SELFTEST_CASES")" || st_die "$name"
  for p in "$@"; do
    st_put "$r" "$p" "a placeholder bundle file"
  done
  st_expect "$name" "$want" "$r"
}

selftest() {
  local r row seat53 seat54 slug60 slug61
  if ! SELFTEST_WORK="$(mktemp -d)" || [ -z "$SELFTEST_WORK" ] || [ ! -d "$SELFTEST_WORK" ]; then
    echo "FAIL: check-edition-headers.sh self-test: no scratch directory (mktemp -d)" >&2
    exit 2
  fi
  trap 'rm -rf "$SELFTEST_WORK"' EXIT
  ST_EVENT_RUN='fedcba9876543210fedcba9876543210'
  ST_DIGEST="$(printf '%064d' 1)"
  row="$(printf '*\t01-demo\tq1\tplaceholder')"
  echo "==> check-edition-headers.sh self-test"

  r="$(st_repo event-answers)" || st_die event-answers
  st_put "$r" out/answers.tsv "$(printf '%s%s\n%s' "$ANSWERS_PREFIX" "$ST_EVENT_RUN" "$row")"
  st_expect "a tracked event answers table fails" 1 "$r"

  r="$(st_repo event-digests)" || st_die event-digests
  st_put "$r" out/digests.tsv "$(printf '%s%s\nseat-a\t01-demo\t%s' "$DIGESTS_PREFIX" "$ST_EVENT_RUN" "$ST_DIGEST")"
  st_expect "a tracked event digests file fails" 1 "$r"

  r="$(st_repo render-record)" || st_die render-record
  st_put "$r" out/render-record.tsv "$(printf '%s\nrun-id\t%s' "$RECORD_HEADER" "$ST_EVENT_RUN")"
  st_expect "a tracked render record fails" 1 "$r"

  r="$(st_repo render-record-crlf)" || st_die render-record-crlf
  st_put "$r" out/render-record.tsv "$(printf '%s\r\nrun-id\t%s\r' "$RECORD_HEADER" "$ST_EVENT_RUN")"
  st_expect "a tracked render record with CRLF line ends fails" 1 "$r"

  r="$(st_repo later-line)" || st_die later-line
  st_put "$r" notes.txt "$(printf 'an introduction\n%s%s' "$DIGESTS_PREFIX" "$ST_EVENT_RUN")"
  st_expect "an event header on a later line of a file fails" 1 "$r"

  # (a NUL byte cannot be held in a shell variable, so the file is written directly)
  r="$(st_repo binary)" || st_die binary
  printf 'x\000y\n%s%s\n' "$ANSWERS_PREFIX" "$ST_EVENT_RUN" >"$r/blob.bin" || st_die "the file blob.bin"
  git -C "$r" add -- blob.bin || st_die "git add of blob.bin"
  st_expect "an event header in a file git takes for binary (a NUL byte) fails" 1 "$r"

  r="$(st_repo allowed-elsewhere)" || st_die allowed-elsewhere
  st_put "$r" internal/edition/testdata/other/digests.tsv "$(cat "$r/${ALLOWED_PATHS[0]}")"
  st_expect "the allowed fixture's content at another path fails" 1 "$r"

  r="$(st_repo stale nobase)" || st_die stale
  st_put "$r" README.md "nothing here"
  st_expect "an allowed entry that is not tracked fails" 1 "$r"

  r="$(st_repo practice)" || st_die practice
  st_put "$r" challenges/01-demo/edition/practice/answers.tsv "$(printf '%s%s\n%s' "$ANSWERS_PREFIX" "$PRACTICE_RUN_ID" "$row")"
  st_put "$r" challenges/01-demo/edition/practice/digests.tsv "$(printf '%s%s\n*\t01-demo\t%s' "$DIGESTS_PREFIX" "$PRACTICE_RUN_ID" "$ST_DIGEST")"
  st_expect "the practice edition (the practice run id) passes" 0 "$r"

  r="$(st_repo practice-crlf)" || st_die practice-crlf
  st_put "$r" challenges/01-demo/edition/practice/answers.tsv "$(printf '%s%s\r\n%s' "$ANSWERS_PREFIX" "$PRACTICE_RUN_ID" "$row")"
  st_expect "a practice header with something after the run id fails" 1 "$r"

  r="$(st_repo mid-line)" || st_die mid-line
  st_put "$r" docs/x.md "$(printf 'the header is `%s%s` and `%s`' "$ANSWERS_PREFIX" "$ST_EVENT_RUN" "$RECORD_HEADER")"
  st_expect "a header in the middle of a line (a document) passes" 0 "$r"

  r="$(st_repo untracked)" || st_die untracked
  printf '%s%s\n' "$ANSWERS_PREFIX" "$ST_EVENT_RUN" >"$r/answers.tsv" || st_die "the file answers.tsv"
  st_expect "an untracked event file passes (only tracked files are the repository's)" 0 "$r"

  r="$(st_repo clean)" || st_die clean
  st_put "$r" README.md "nothing here"
  st_expect "a tree with no header but the allowed fixture passes (the scan still runs)" 0 "$r"

  # The entries of ALLOWED_PATHS: exactly one tracked regular file, nothing wider.
  r="$(st_repo entries)" || st_die entries
  st_put "$r" internal/edition/testdata/digests-golden/other.tsv "a second file beside the fixture"
  ln -s digests.tsv "$r/internal/edition/testdata/digests-golden/link.tsv" || st_die "the link link.tsv"
  git -C "$r" add -- internal/edition/testdata/digests-golden/link.tsv || st_die "git add of link.tsv"
  st_entry "an entry that is the path of the tracked file is taken" 0 "$r" "${ALLOWED_PATHS[0]}"
  st_entry "an entry that is a directory is refused" 1 "$r" internal/edition/testdata/digests-golden
  st_entry "an entry that is a directory with a final slash is refused" 1 "$r" internal/edition/testdata/digests-golden/
  st_entry "an entry with a glob character is refused" 1 "$r" 'internal/edition/testdata/*/digests.tsv'
  st_entry "an entry of one glob character is refused" 1 "$r" '*'
  st_entry "an entry with .. is refused" 1 "$r" internal/edition/testdata/../testdata/digests-golden/digests.tsv
  st_entry "an entry that is a tracked link is refused" 1 "$r" internal/edition/testdata/digests-golden/link.tsv
  st_entry "an entry that is not tracked is refused" 1 "$r" internal/edition/testdata/digests-golden/missing.tsv

  # V93: the layout of an event's evidence bundles, evidence/<seat>/<cid>/<file>, at any depth.
  seat53="a$(printf '%051d' 0)b"
  seat54="a$(printf '%052d' 0)b"
  slug60="$(printf '%060d' 0)"
  slug61="$(printf '%061d' 0)"
  st_evidence "an event bundle file evidence/<seat>/<cid>/<file> fails" 1 \
    evidence/user1/01-demo/answer.txt
  st_evidence "an event bundle one directory down (x/evidence/...) fails" 1 \
    x/evidence/user1/01-demo/answer.txt
  st_evidence "a nested <file> (evidence/<seat>/<cid>/a/b) fails" 1 \
    evidence/user1/01-demo/a/b
  st_evidence "a seat-shaped nesting under the practice bundle fails" 1 \
    challenges/01-demo/edition/practice/evidence/user1/01-demo/answer.txt
  st_evidence "an event bundle at the edges of both grammars, with spaces in the path, fails" 1 \
    "out dir/evidence/$seat53/01-$slug60/my file.txt"
  st_evidence "an event bundle under a directory whose name holds a newline fails" 1 \
    $'line\nbreak/evidence/user1/01-demo/f'
  st_evidence "the flat practice bundle passes" 0 \
    challenges/01-demo/edition/practice/evidence/a.txt
  st_evidence "a nesting under the practice bundle that is not seat/cid passes (the practice layout's own check)" 0 \
    challenges/01-demo/edition/practice/evidence/Sub_Dir/01-demo/f \
    challenges/01-demo/edition/practice/evidence/notes/readme.txt
  st_evidence "evidence as a part of a segment (myevidence/, evidence-x/) passes" 0 \
    myevidence/user1/01-demo/f evidence-x/user1/01-demo/f
  st_evidence "a segment outside the seat grammar (a capital, an end hyphen, 54 characters) passes" 0 \
    evidence/User1/01-demo/f evidence/user1-/01-demo/f "evidence/$seat54/01-demo/f"
  st_evidence "a segment outside the challenge id grammar (one digit, a capital, a 61-character slug) passes" 0 \
    evidence/user1/1-demo/f evidence/user1/01-Demo/f "evidence/user1/01-$slug61/f"
  st_evidence "a seat segment that ends in a newline passes (the segment is not a seat)" 0 \
    $'evidence/user1\n/01-demo/f'
  st_evidence "a path that ends at <cid> (no segment after it) passes" 0 \
    evidence/user1/01-demo

  r="$(st_repo ev-untracked)" || st_die ev-untracked
  mkdir -p "$r/evidence/user1/01-demo" || st_die "the directory of the untracked bundle"
  printf 'x\n' >"$r/evidence/user1/01-demo/f" || st_die "the untracked bundle file"
  st_expect "an untracked event bundle passes (only tracked paths are the repository's)" 0 "$r"

  # The named exclusion, called with a list of its own (EVIDENCE_ALLOWED_PATHS is empty).
  r="$(st_repo ev-allowed)" || st_die ev-allowed
  st_put "$r" x/evidence/user1/01-demo/f "a fixture that needs the shape"
  st_call "a path named as an allowed entry passes" 0 scan_evidence "$r" x/evidence/user1/01-demo/f
  st_call "the same tree without the entry fails" 1 scan_evidence "$r"
  st_call "an allowed entry that is a directory is refused and excludes nothing" 1 scan_evidence "$r" x/evidence
  st_call "an allowed entry that is not tracked is refused" 1 scan_evidence "$r" x/evidence/user1/01-demo/f x/evidence/user1/01-demo/g

  r="$(st_repo ev-empty nobase)" || st_die ev-empty
  st_call "a tree with no tracked path passes (the scan still runs)" 0 scan_evidence "$r"
  st_call "a seat pattern without its anchors stops the scan" 2 st_unanchored_seat "$r"
  st_call "a challenge id pattern with a . stops the scan" 2 st_dot_challenge_id "$r"
  st_call "a seat pattern that is not a regular expression stops the scan" 2 st_unbalanced_seat "$r"

  # A scan that cannot run is NOT clean: point it at a directory that is not a repository.
  mkdir -p "$SELFTEST_WORK/not-a-repo" || st_die not-a-repo
  st_expect "a root that is not a git work tree does not pass" 2 "$SELFTEST_WORK/not-a-repo"
  st_call "the evidence scan of a root that is not a git work tree does not pass" 2 scan_evidence "$SELFTEST_WORK/not-a-repo"

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
    echo "usage: bash $0 [--selftest]" >&2
    exit 2
    ;;
esac

if [ -n "${CHECK_EDITION_HEADERS_ROOT:-}" ]; then
  root="$CHECK_EDITION_HEADERS_ROOT"
elif ! root="$(git rev-parse --show-toplevel 2>/dev/null)"; then
  echo "FAIL: not inside a git work tree; the scan did not run" >&2
  exit 2
fi
# Both checks run whatever the first gives; the exit is the larger status (2 over 1 over 0).
rc=0
scan "$root" || rc=$?
erc=0
scan_evidence "$root" ${EVIDENCE_ALLOWED_PATHS[@]+"${EVIDENCE_ALLOWED_PATHS[@]}"} || erc=$?
if [ "$erc" -gt "$rc" ]; then
  rc="$erc"
fi
exit "$rc"
