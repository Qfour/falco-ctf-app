#!/usr/bin/env bash
# Self-test of scripts/lib/casetable.sh (app#509): the shell reader of the shared
# grammar case tables that check-seat-grammar.sh and check-deploy-user-ids.sh both
# stand on. It touches no docker, helm or stub (those are the harness layer,
# scripts/lib/deploy-user-harness.sh, tested by scripts/test-deploy-user-harness.sh).
# The checks' own self-tests run a table against deliberately broken copies of
# deploy-user.sh; THIS proves the reader they run it with can fail:
#   - every placeholder decodes to its exact bytes, a trailing {LF} survives, an
#     unknown / unclosed placeholder is a BAD row (never a verdict), and the closed
#     set is what internal/casetable's TestShellPlaceholdersAreTheGoPlaceholders reads
#   - a table without the `# pattern: ` header on line 1 is BAD
#   - `#` and blank lines are skipped without shifting a line number; the split is on
#     the FIRST tab; an empty input reaches the row function; a bad verdict, a row
#     without a tab, and a row the function rejects are BAD, on their own line
#   - ct_mutate_line replaces exactly one line, keeps the file mode, copies the file's
#     own directory by default and a whole tree (any glob) when asked, and fails on 0 or
#     2 matches, on a failing line that is not in BAD_LINES, on no expected line at all,
#     and on a file outside the copy dir
# Usage: ./scripts/test-casetable-lib.sh   (make check-flags; CI flag-guard)
set -euo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
# shellcheck source=lib/casetable.sh
source "${REPO_ROOT}/scripts/lib/casetable.sh"
ct_init "${REPO_ROOT}"

T_N=0
# t_eq <what> <want> <got>
t_eq() {
  T_N=$((T_N + 1))
  if [[ "$2" != "$3" ]]; then
    fail "$1: want $(printf '%q' "$2"), got $(printf '%q' "$3")"
  fi
}
# t_group <name>: print the group's verdict, from the failures since the last group
T_RC0=0
t_group() {
  if [[ "${RC}" -eq "${T_RC0}" ]]; then pass "$1 (${T_N} checks)"; fi
  T_RC0="${RC}"; T_N=0
}
# t_status <what> <want status> <command...>: the command's exit status, set -e safe
t_status() {
  local what="$1" want="$2" got
  shift 2
  set +e; "$@" >/dev/null 2>&1; got=$?; set -e
  t_eq "${what}" "${want}" "${got}"
}

# t_rc <what> <want RC: 0|1> <command...>: the command (a ct_* function that reports
# through fail) leaves RC at <want>. The suite's own RC is saved and restored: this
# must not erase an earlier failure, nor leak the one it provokes.
t_rc() {
  local what="$1" want="$2" save="${RC}" got
  shift 2
  RC=0
  "$@" > /dev/null 2>&1
  got="${RC}"
  RC="${save}"
  t_eq "${what}" "${want}" "${got}"
}

BIDI="$(printf '\342\200\256')"
UUML="$(printf '\303\274')"
IUML="$(printf '\303\257')"
NL=$'\n'
TAB=$'\t'

echo "==> decode: the closed placeholder set, byte for byte"
ct_decode 'a{LF}b';        t_eq "{LF}" "a${NL}b" "${DECODED}"
ct_decode 'a{U+202E}b';    t_eq "{U+202E}" "a${BIDI}b" "${DECODED}"
ct_decode 'a{U+00FC}b';    t_eq "{U+00FC}" "a${UUML}b" "${DECODED}"
ct_decode 'a{U+00EF}b';    t_eq "{U+00EF}" "a${IUML}b" "${DECODED}"
ct_decode 'user1{LF}';     t_eq "a trailing {LF} survives" "user1${NL}" "${DECODED}"
ct_decode '{LF}{LF}x{LF}'; t_eq "{LF} repeated" "${NL}${NL}x${NL}" "${DECODED}"
ct_decode '{U+00FC}{U+00EF}{U+202E}'; t_eq "all three code points in one input" "${UUML}${IUML}${BIDI}" "${DECODED}"
ct_decode 'plain-text';    t_eq "no placeholder, no change" "plain-text" "${DECODED}"
ct_decode '';              t_eq "the empty input" "" "${DECODED}"
ct_decode 'a{U+2028}b';    t_eq "an unknown placeholder is left as it is" 'a{U+2028}b' "${DECODED}"
ct_decode '{lf}{LF';       t_eq "case matters, an unclosed one is left" "{lf}{LF" "${DECODED}"
for name in ${CT_PLACEHOLDERS}; do
  ct_decode "<${name}>"
  case "${DECODED}" in
    *'{'*|*'}'*) fail "CT_PLACEHOLDERS lists ${name}, but ct_decode leaves a brace" ;;
  esac
  T_N=$((T_N + 1))
done
t_eq "CT_PLACEHOLDERS" '{LF} {U+202E} {U+00FC} {U+00EF}' "${CT_PLACEHOLDERS}"
t_group "decode"

echo "==> header: line 1 is '# pattern: <regex>'"
HDR="${WORK}/hdr"; mkdir -p "${HDR}"
printf '# pattern: ^a$\nab\taccept\n' > "${HDR}/ok.tsv"
t_eq "the regex is read back" '^a$' "$(ct_header_pattern "${HDR}/ok.tsv")"
printf '# pattern: ^[a-z]{1,3}$\n' > "${HDR}/nl.tsv"
t_eq "a header with braces, as the last line" '^[a-z]{1,3}$' "$(ct_header_pattern "${HDR}/nl.tsv")"
printf '# pattern: ^a$' > "${HDR}/nonl.tsv"
t_eq "a header without a trailing newline" '^a$' "$(ct_header_pattern "${HDR}/nonl.tsv")"
for bad in 'ab\taccept\n' '#pattern: ^a$\n' ' # pattern: ^a$\n' '# pattern:\n' '# pattern: \n' '\n# pattern: ^a$\n' '# Pattern: ^a$\n' ''; do
  # shellcheck disable=SC2059  # the cases are printf formats on purpose
  printf "${bad}" > "${HDR}/bad.tsv"
  t_status "line 1 ${bad} is not a header" 1 ct_header_pattern "${HDR}/bad.tsv"
done
t_status "a missing file is not a header" 1 ct_header_pattern "${HDR}/missing.tsv"
t_group "header"

echo "==> run_table: the walk"
REC="${WORK}/rec"
# rec_row <label> <line> <verdict> <decoded input> [extra...]: records what it was
# given; rejects ("disagrees") the input 'bad'.
rec_row() {
  printf '%s|%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" "${5-}" >> "${REC}"
  [[ "$4" != bad ]]
}
walk() { # <table text, printf format> [extra...]
  local fmt="$1"
  shift
  # shellcheck disable=SC2059  # the tables are printf formats on purpose
  printf "${fmt}" > "${HDR}/t.tsv"
  : > "${REC}"
  ct_run_table "${HDR}/t.tsv" rec_row ${1+"$@"} 2>"${WORK}/walk.err"
}
H='# pattern: ^x$\n'
walk "${H}ab\taccept\ncd\treject\n" X
t_eq "rows, accepted, rejected" "2 1 1 0 " "${ROWS} ${ACCEPTED} ${REJECTED} ${BAD} ${BAD_LINES# }"
t_eq "the row function gets label, line, verdict, input, extra" "t.tsv|2|accept|ab|X${NL}t.tsv|3|reject|cd|X${NL}" "$(cat "${REC}")${NL}"
walk "${H}# a comment\n\n   \nab\taccept\n#x\tcomment\n\ncd\treject\n"
t_eq "comments and blank lines are skipped, line numbers are the file's" "t.tsv|5|accept|ab|${NL}t.tsv|8|reject|cd|${NL}" "$(cat "${REC}")${NL}"
t_eq "a line of spaces is not a skipped line (no tab: BAD)" " 4 " "${BAD_LINES}"
walk "${H}\treject\nab\taccept\n"
t_eq "an empty input (the line starts with a tab) reaches the row function" "t.tsv|2|reject||${NL}t.tsv|3|accept|ab|${NL}" "$(cat "${REC}")${NL}"
walk "${H}a\tb\taccept\n"
t_eq "the split is on the first tab: the verdict is 'b<TAB>accept', not a verdict" " 2 " "${BAD_LINES}"
t_eq "...and the row function never saw it" "" "$(cat "${REC}")"
walk "${H}ab\tmaybe\nab\n"
t_eq "a bad verdict and a row without a tab are BAD, each on its line" " 2 3 " "${BAD_LINES}"
t_eq "...with a message for each" "2" "$(grep -c -e 'verdict must be accept|reject' -e 'no tab' "${WORK}/walk.err")"
walk "${H}ab\taccept\nbad\treject\ncd\treject\n"
t_eq "a row the function rejects is BAD on its own line only" " 3 " "${BAD_LINES}"
t_eq "...and the walk goes on after it" "3 1 2 1" "${ROWS} ${ACCEPTED} ${REJECTED} ${BAD}"
walk "${H}user1\taccept\nuser{U+2028}1\treject\nuser1{LF\treject\nx}\treject\n{lf}\treject\n"
t_eq "an unknown / unclosed placeholder is BAD (lines 3 4 5 6), the plain row is not" " 3 4 5 6 " "${BAD_LINES}"
t_eq "...and the row function never saw them" "t.tsv|2|accept|user1|" "$(cat "${REC}")"
t_eq "...with the reason on stderr" "4" "$(grep -c 'unknown placeholder' "${WORK}/walk.err")"
walk "${H}a{LF}\treject\n{U+202E}\taccept\n"
t_eq "decoded placeholders reach the row function (a newline, a bidi control)" "t.tsv|2|reject|a${NL}|${NL}t.tsv|3|accept|${BIDI}|${NL}" "$(cat "${REC}")${NL}"
walk "ab\taccept\ncd\treject\n"
t_eq "no header on line 1: BAD at line 1, the rows are still walked" " 1 " "${BAD_LINES}"
t_eq "...(2 rows, one bad line)" "2 1" "${ROWS} ${BAD}"
walk "#pattern: ^x$\nab\taccept\n"
t_eq "'#pattern:' (no space) is not the header" " 1 " "${BAD_LINES}"
walk "ab\taccept\n# pattern: ^x$\n"
t_eq "the header is line 1, not any line" " 1 " "${BAD_LINES}"
walk "${H}ab\taccept"
t_eq "a last row without a newline is read" "1 0" "${ROWS} ${BAD}"
walk ""
t_eq "an empty file: no rows, and no header" "0 1" "${ROWS} ${BAD}"
t_group "run_table"

echo "==> expect_table: misread / truncated / disagreeing tables"
printf '%s\n%s\n' '# pattern: ^x$' "ab${TAB}accept" > "${HDR}/e.tsv"
t_rc "a table that holds what was expected passes" 0 ct_expect_table "t" 1 1 0 "${HDR}/e.tsv" rec_row
t_rc "fewer rows than expected is a failure" 1 ct_expect_table "t" 2 1 0 "${HDR}/e.tsv" rec_row
t_rc "fewer accept rows than expected is a failure" 1 ct_expect_table "t" 1 2 0 "${HDR}/e.tsv" rec_row
t_rc "fewer reject rows than expected is a failure" 1 ct_expect_table "t" 1 1 1 "${HDR}/e.tsv" rec_row
printf '%s\n%s\n' '# pattern: ^x$' "bad${TAB}accept" > "${HDR}/e2.tsv"
t_rc "a disagreeing row is a failure" 1 ct_expect_table "t" 1 1 0 "${HDR}/e2.tsv" rec_row
t_group "expect_table"

echo "==> line_of and mutate_line"
printf '%s\n' '# pattern: ^x$' "aa${TAB}accept" "bb${TAB}reject" "bb${TAB}accept" > "${HDR}/l.tsv"
t_eq "line_of: the first matching row" 3 "$(ct_line_of "${HDR}/l.tsv" '$1 == "bb"')"
t_eq "line_of: by verdict" 4 "$(ct_line_of "${HDR}/l.tsv" '$1 == "bb" && $2 == "accept"')"
t_status "line_of: no match fails" 1 ct_line_of "${HDR}/l.tsv" '$1 == "zz"'
MR="${WORK}/fakerepo"; mkdir -p "${MR}/charts/x"
printf '%s\n' '#!/usr/bin/env bash' "A='1'" "B='2'" "A2='3'" 'echo "$A"' > "${MR}/charts/x/run.sh"
printf '%s\n' '#!/usr/bin/env bash' "X='1'" > "${MR}/charts/x/other.sh"
chmod +x "${MR}/charts/x/run.sh"
SAVED_ROOT="${CT_REPO_ROOT}"
# shellcheck disable=SC2034  # read by ct_mutate_line
CT_REPO_ROOT="${MR}"
GOT="${WORK}/mutant.seen"
# mutant_runner <mutant script>: copies what it was given, reports line 7 as BAD.
mutant_runner() { cp "$1" "${GOT}"; ls "$(dirname "$1")" > "${GOT}.ls"; BAD=1 BAD_LINES=" 7 "; }
mutant_runner_empty() { BAD=0 BAD_LINES=" "; }
t_rc "mutate_line: the failing line is in BAD_LINES -> pass" 0 ct_mutate_line m1 charts/x/run.sh "B='" "B='9'" 7 mutant_runner
t_eq "mutate_line: exactly the one line is replaced, the rest is intact (incl. A2 and echo)" "#!/usr/bin/env bash${NL}A='1'${NL}B='9'${NL}A2='3'${NL}echo \"\$A\"" "$(cat "${GOT}")"
t_eq "mutate_line: the directory's other scripts are copied too" "other.sh${NL}run.sh" "$(cat "${GOT}.ls")"
t_eq "mutate_line: the original is untouched" "B='2'" "$(grep "^B=" "${MR}/charts/x/run.sh")"
t_status "mutate_line: the mutant is executable" 0 test -x "${WORK}/mut-m1/charts/x/run.sh"
t_rc "mutate_line: an expected line that is not failing -> FAIL" 1 ct_mutate_line m2 charts/x/run.sh "B='" "B='9'" 8 mutant_runner
t_rc "mutate_line: two lines match the prefix -> FAIL" 1 ct_mutate_line m3 charts/x/run.sh "A" "A='9'" 7 mutant_runner
t_rc "mutate_line: no line matches the prefix -> FAIL" 1 ct_mutate_line m4 charts/x/run.sh "NOPE=" "NOPE='9'" 7 mutant_runner
t_rc "mutate_line: no expected line (the row was not found) -> FAIL" 1 ct_mutate_line m5 charts/x/run.sh "B='" "B='9'" "" mutant_runner
t_rc "mutate_line: a mutant that disagrees on no row -> FAIL" 1 ct_mutate_line m6 charts/x/run.sh "B='" "B='9'" 7 mutant_runner_empty
# The copy range: a tree with another directory and a non-.sh file (a chart's templates/).
mkdir -p "${MR}/charts/x/templates/sub"
printf '%s\n' 'a: 1' "pattern: '^a$'" 'b: 2' > "${MR}/charts/x/templates/p.yaml"
printf '%s\n' "pattern: '^a$'" > "${MR}/charts/x/templates/sub/q.yaml"
printf '%s\n' '#!/usr/bin/env bash' "Z='1'" > "${MR}/charts/x/templates/sub/z.sh"
t_rc "mutate_line: a non-script file with a copy dir and glob * -> pass" 0 ct_mutate_line t1 charts/x/templates/p.yaml "pattern: '" "pattern: '^b$'" 7 mutant_runner charts/x/templates '*'
t_eq "mutate_line tree: the line is replaced in the mutant" "a: 1${NL}pattern: '^b\$'${NL}b: 2" "$(cat "${WORK}/mut-t1/charts/x/templates/p.yaml")"
t_eq "mutate_line tree: the subdirectory is copied with the same relative path" "pattern: '^a\$'" "$(cat "${WORK}/mut-t1/charts/x/templates/sub/q.yaml")"
t_eq "mutate_line tree: ...and its other files (glob *)" "yes" "$([[ -f "${WORK}/mut-t1/charts/x/templates/sub/z.sh" ]] && echo yes || echo no)"
t_eq "mutate_line tree: nothing outside the copy dir is copied" "no" "$([[ -e "${WORK}/mut-t1/charts/x/run.sh" ]] && echo yes || echo no)"
t_rc "mutate_line: a copy dir with the default glob copies no yaml -> FAIL (the file is not among the copied)" 1 ct_mutate_line t2 charts/x/templates/p.yaml "pattern: '" "pattern: '^b$'" 7 mutant_runner charts/x/templates
t_rc "mutate_line: a file outside the copy dir -> FAIL" 1 ct_mutate_line t3 charts/x/run.sh "B='" "B='9'" 7 mutant_runner charts/x/templates '*'
t_rc "mutate_line: the default copy (no copy dir) -> pass" 0 ct_mutate_line m7 charts/x/run.sh "B='" "B='9'" 7 mutant_runner
t_eq "mutate_line: the default copy is that one directory, not its subdirectories (templates/ exists now)" "no" "$([[ -e "${WORK}/mut-m7/charts/x/templates" ]] && echo yes || echo no)"
t_eq "mutate_line: the mutant script keeps its executable bit" "yes" "$([[ -x "${WORK}/mut-m1/charts/x/run.sh" ]] && echo yes || echo no)"
t_eq "mutate_line: ...and a file that was not executable stays so" "no" "$([[ -x "${WORK}/mut-t1/charts/x/templates/p.yaml" ]] && echo yes || echo no)"
CT_REPO_ROOT="${SAVED_ROOT}"
t_group "line_of / mutate_line"

ct_finish "casetable lib self-test"
