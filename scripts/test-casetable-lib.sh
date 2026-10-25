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
#   - ...and judges the mutant (app#522): a replacement that breaks the syntax is a FAIL
#     (bash -n; the copy would fail every row, the expected one too), one that rejects
#     everything / accepts everything fails a control row (a FAIL), --must that is not the
#     reason is a FAIL, an honest break passes; a control that is not one row of the
#     table, a runner that walked no table or skipped a row it was asked for, are FAILs
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
  "$@" > "${WORK}/t_rc.out" 2>&1
  got="${RC}"
  RC="${save}"
  t_eq "${what}" "${want}" "${got}"
}
# t_red <what> <text> <command...>: t_rc 1, and red for the intended reason: <text> is in
# the FAIL line (a FAIL for another reason proves nothing either).
t_red() {
  local what="$1" text="$2"
  shift 2
  t_rc "${what}" 1 "$@"
  T_N=$((T_N + 1))
  # One awk (no `| grep -q`: under pipefail its early exit is a SIGPIPE, not a verdict).
  if ! T_TEXT="${text}" awk 'index($0, "  FAIL: ") && index($0, ENVIRON["T_TEXT"]) { f = 1 } END { exit !f }' "${WORK}/t_rc.out"; then
    fail "${what}: red, but not for '${text}': $(awk 'index($0, "  FAIL: ") { print substr($0, 1, 200); exit }' "${WORK}/t_rc.out")"
  fi
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
walk "${H}# c\nab\taccept\n\ncd\treject\n"
t_eq "RAN_TABLE / RAN_LINES: the table and every row it walked (not the comment or blank lines)" "${HDR}/t.tsv| 3 5 " "${RAN_TABLE}|${RAN_LINES}"
printf "${H}ab\taccept\nbad\treject\ncd\treject\n# c\n" > "${HDR}/s.tsv"
: > "${REC}"
_ct_walk "${HDR}/s.tsv" " 4 3 " rec_row 2>"${WORK}/walk.err"
t_eq "a walk of some rows: only those reach the row function" "s.tsv|3|reject|bad|${NL}s.tsv|4|reject|cd|${NL}" "$(cat "${REC}")${NL}"
t_eq "...RAN_LINES is those rows, in table order, and the one that disagrees is BAD" "2 1 | 3 4 | 3 " "${ROWS} ${BAD} |${RAN_LINES}|${BAD_LINES}"
_ct_walk "${HDR}/s.tsv" " 2 5 9 " rec_row 2>"${WORK}/walk.err"
t_eq "a line asked for that is not a row (a comment, past the end) is BAD, and not run" "1 2 | 2 | 5 9 " "${ROWS} ${BAD} |${RAN_LINES}|${BAD_LINES}"
t_eq "...with the reason on stderr" "2" "$(grep -c 'not a row of the table' "${WORK}/walk.err")"
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

echo "==> line_of and mutate_line: the copy"
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
# The copy tests' table: the runner's row function fails the row 'seven' (line 7) only,
# so the default controls (line 2 accept, line 3 reject) hold.
printf '%s\n' '# pattern: ^x$' "a${TAB}accept" "b${TAB}reject" "c${TAB}accept" "d${TAB}reject" '# a comment' "seven${TAB}reject" "eight${TAB}accept" > "${HDR}/f.tsv"
seven_row() { [[ "$4" != seven ]] || { echo "    $1:$2: the copy tests' row function fails 'seven'" >&2; return 1; }; }
true_row() { return 0; }
# mutant_runner <mutant script>: copies what it was given, then walks the table (line 7 BAD).
mutant_runner() { cp "$1" "${GOT}"; ls "$(dirname "$1")" > "${GOT}.ls"; ct_run_table "${HDR}/f.tsv" seven_row; }
mutant_runner_empty() { ct_run_table "${HDR}/f.tsv" true_row; }
t_rc "mutate_line: the failing line is in BAD_LINES -> pass" 0 ct_mutate_line m1 charts/x/run.sh "B='" "B='9'" 7 mutant_runner
t_eq "mutate_line: exactly the one line is replaced, the rest is intact (incl. A2 and echo)" "#!/usr/bin/env bash${NL}A='1'${NL}B='9'${NL}A2='3'${NL}echo \"\$A\"" "$(cat "${GOT}")"
t_eq "mutate_line: the directory's other scripts are copied too" "other.sh${NL}run.sh" "$(cat "${GOT}.ls")"
t_eq "mutate_line: the original is untouched" "B='2'" "$(grep "^B=" "${MR}/charts/x/run.sh")"
t_status "mutate_line: the mutant is executable" 0 test -x "${WORK}/mut-m1/charts/x/run.sh"
t_red "mutate_line: an expected line that is not failing -> FAIL" "did not fail table line 8" ct_mutate_line m2 charts/x/run.sh "B='" "B='9'" 8 mutant_runner
t_red "mutate_line: two lines match the prefix -> FAIL" "has 2 lines starting with 'A'" ct_mutate_line m3 charts/x/run.sh "A" "A='9'" 7 mutant_runner
t_red "mutate_line: no line matches the prefix -> FAIL" "has 0 lines starting with" ct_mutate_line m4 charts/x/run.sh "NOPE=" "NOPE='9'" 7 mutant_runner
t_red "mutate_line: no expected line (the row was not found) -> FAIL" "no expected failing line" ct_mutate_line m5 charts/x/run.sh "B='" "B='9'" "" mutant_runner
t_red "mutate_line: a mutant that disagrees on no row -> FAIL" "did not fail table line 7" ct_mutate_line m6 charts/x/run.sh "B='" "B='9'" 7 mutant_runner_empty
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
t_red "mutate_line: a copy dir with the default glob copies no yaml -> FAIL (the file is not among the copied)" "is not among the copied files" ct_mutate_line t2 charts/x/templates/p.yaml "pattern: '" "pattern: '^b$'" 7 mutant_runner charts/x/templates
t_red "mutate_line: a file outside the copy dir -> FAIL" "is not under the copy dir" ct_mutate_line t3 charts/x/run.sh "B='" "B='9'" 7 mutant_runner charts/x/templates '*'
t_rc "mutate_line: the default copy (no copy dir) -> pass" 0 ct_mutate_line m7 charts/x/run.sh "B='" "B='9'" 7 mutant_runner
t_eq "mutate_line: the default copy is that one directory, not its subdirectories (templates/ exists now)" "no" "$([[ -e "${WORK}/mut-m7/charts/x/templates" ]] && echo yes || echo no)"
t_eq "mutate_line: the mutant script keeps its executable bit" "yes" "$([[ -x "${WORK}/mut-m1/charts/x/run.sh" ]] && echo yes || echo no)"
t_eq "mutate_line: ...and a file that was not executable stays so" "no" "$([[ -x "${WORK}/mut-t1/charts/x/templates/p.yaml" ]] && echo yes || echo no)"
t_group "line_of / mutate_line: the copy"

echo "==> mutate_line judges the mutant: it parses, it is about its row only, for the intended reason (app#522)"
# A grammar script and its table. g_row runs the script on the row's input: accept = exit
# 0, reject = exit 2 with 'invalid input' on stderr; otherwise the reason, `<label>:<line>:`.
mkdir -p "${MR}/charts/g"
printf '%s\n' '#!/usr/bin/env bash' "PATTERN='^[a-z]{1,3}\$'" \
  '[[ "$1" =~ ${PATTERN} ]] || { echo "invalid input" >&2; exit 2; }' 'echo "ok: $1"' > "${MR}/charts/g/gram.sh"
chmod +x "${MR}/charts/g/gram.sh"
G_TSV="${HDR}/g.tsv"
printf '%s\n' '# pattern: ^[a-z]{1,3}$' "a${TAB}accept" "abc${TAB}accept" "abcd${TAB}reject" "A${TAB}reject" "a-b${TAB}reject" '# a comment' "ab${TAB}accept" > "${G_TSV}"
g_row() { # <label> <line> <verdict> <input> <script>
  local out st
  out="$("$5" "$4" 2>&1)" && st=0 || st=$?
  if [[ "$3" == accept ]]; then
    [[ "${st}" -eq 0 ]] && return 0
    echo "    $1:$2: accept, but exit ${st}: ${out}" >&2
    return 1
  fi
  [[ "${st}" -eq 2 && "${out}" == *'invalid input'* ]] && return 0
  echo "    $1:$2: reject, but exit ${st}: ${out}" >&2
  return 1
}
silent_row() { [[ "$4" != abcd ]]; }   # fails line 4 and gives no reason
g_runner() { ct_run_table "${G_TSV}" g_row "$1"; }
g_rows_runner() { ct_run_mutant_rows "${G_TSV}" g_row "$1"; }
g_silent_runner() { ct_run_table "${G_TSV}" silent_row "$1"; }
g_none_runner() { BAD=1 BAD_LINES=" 4 "; }                  # the old way: BAD_LINES by hand
g_want_only_runner() { _ct_walk "${G_TSV}" " ${CT_MUT_WANT} " g_row "$1"; }
g_other_runner() { _ct_walk "${G_TSV}" " 2 5 " g_row "$1"; }
WIDE="PATTERN='^[a-z]{1,4}\$'"     # an honest widening: line 4 (abcd) only
NARROW="PATTERN='^[a-z]{1,2}\$'"   # an honest narrowing: line 3 (abc) only
gmut() { ct_mutate_line "$@"; }

t_eq "the grammar fixture: the original holds the table" "0 6" "$(g_runner "${MR}/charts/g/gram.sh" 2>/dev/null; echo "${BAD} ${ROWS}")"
t_rc "an honest widening passes (the whole table is run)" 0 gmut g1 charts/g/gram.sh "PATTERN='" "${WIDE}" 4 g_runner
t_eq "...and its controls are the first accept and the first reject row other than line 4" "1" "$(grep -c 'control line(s) 2 5 hold' "${WORK}/t_rc.out")"
t_rc "an honest narrowing passes" 0 gmut g2 charts/g/gram.sh "PATTERN='" "${NARROW}" 3 g_runner
t_rc "a runner on ct_run_mutant_rows passes" 0 gmut g3 charts/g/gram.sh "PATTERN='" "${WIDE}" 4 g_rows_runner
t_eq "...and walked only the expected line and the control rows" "3| 2 4 5 " "${ROWS}|${RAN_LINES}"

# The break app#522 is about: a replacement that does not parse. The copy fails EVERY row,
# the expected one too, so the old check (line 4 in BAD_LINES) was green on it.
mkdir -p "${WORK}/broken"
sed "s/^PATTERN=.*/PATTERN='^[a-z]{1,4}\$/" "${MR}/charts/g/gram.sh" > "${WORK}/broken/gram.sh"
chmod +x "${WORK}/broken/gram.sh"
g_runner "${WORK}/broken/gram.sh" 2>/dev/null
t_eq "a copy that does not parse fails every row, line 4 included (the old check's only condition)" " 2 3 4 5 6 8 " "${BAD_LINES}"
t_red "a replacement that breaks the syntax -> FAIL (bash -n), even though line 4 fails" "does not parse (bash -n)" gmut s1 charts/g/gram.sh "PATTERN='" "PATTERN='^[a-z]{1,4}\$" 4 g_runner
t_eq "...and the mutant is not run" "no" "$([[ -s "${WORK}/mut-s1.err" ]] && grep -q 'g.tsv:' "${WORK}/mut-s1.err" && echo yes || echo no)"
printf '%s\n' '#!/usr/bin/env bash' "T='1'" > "${MR}/charts/x/tool"
t_red "a file named without .sh but with a #! bash line is a script too -> FAIL (bash -n)" "does not parse (bash -n)" gmut s2 charts/x/tool "T='" "T='9" 7 mutant_runner charts/x '*'
t_rc "a yaml file with the same unclosed quote is not a script: no bash -n -> pass" 0 gmut s3 charts/x/templates/p.yaml "pattern: '" "pattern: '^b" 7 mutant_runner charts/x/templates '*'

# A replacement that breaks every row of a verdict: the expected line fails, for no reason
# of its own. The control rows catch it.
t_red "a replacement that rejects everything -> FAIL: the accept control fails too" "fails control line 2 too" gmut r1 charts/g/gram.sh '[[ "$1" =~' 'echo "invalid input" >&2; exit 2' 3 g_runner
t_red "a replacement that accepts everything -> FAIL: the reject control fails too" "fails control line 5 too" gmut r2 charts/g/gram.sh "PATTERN='" "PATTERN='^.*\$'" 4 g_runner
t_rc "...unless the call names the accept control only (a break that flips every reject row by design)" 0 gmut --control accept r3 charts/g/gram.sh "PATTERN='" "PATTERN='^.*\$'" 4 g_runner
t_red "a replacement that accepts everything, on ct_run_mutant_rows -> FAIL the same way" "fails control line 5 too" gmut r4 charts/g/gram.sh "PATTERN='" "PATTERN='^.*\$'" 4 g_rows_runner

# --must: red for the intended reason.
t_rc "--must that is the expected line's reason -> pass" 0 gmut --must 'accept, but exit 2: invalid input' u1 charts/g/gram.sh "PATTERN='" "${NARROW}" 3 g_runner
t_red "--must that is not the reason -> FAIL" "not for the intended reason" gmut --must 'reject, but' u2 charts/g/gram.sh "PATTERN='" "${NARROW}" 3 g_runner
t_red "--must that is another row's reason only -> FAIL (the expected line's reason is read)" "not for the intended reason" gmut --control accept --must 'g.tsv:5:' u3 charts/g/gram.sh "PATTERN='" "PATTERN='^.*\$'" 4 g_runner
t_red "--must, and the row function gave no reason -> FAIL" "no reason on stderr" gmut --must 'reject, but' u4 charts/g/gram.sh "PATTERN='" "${WIDE}" 4 g_silent_runner
t_red "--must '' -> FAIL" "--must is empty" gmut --must '' u5 charts/g/gram.sh "PATTERN='" "${WIDE}" 4 g_runner
t_red "--must with no value -> FAIL" "--must needs a value" gmut --must
t_red "an unknown option -> FAIL" "unknown option --nope" gmut --nope x charts/g/gram.sh "PATTERN='" "${WIDE}" 4 g_runner

# --control: one row per flag, a row of the table, not the expected line.
t_rc "--control <line no> of an accept row -> pass, that row is the control" 0 gmut --control 8 c1 charts/g/gram.sh "PATTERN='" "${WIDE}" 4 g_runner
t_eq "...(the pass names it)" "1" "$(grep -c 'control line(s) 8 hold' "${WORK}/t_rc.out")"
t_rc "--control accept twice -> the first two accept rows" 0 gmut --control accept --control accept c2 charts/g/gram.sh "PATTERN='" "${WIDE}" 4 g_runner
t_eq "...(2 and 3)" "1" "$(grep -c 'control line(s) 2 3 hold' "${WORK}/t_rc.out")"
t_red "--control '' (its line_of found nothing) -> FAIL" "is not one row" gmut --control '' c3 charts/g/gram.sh "PATTERN='" "${WIDE}" 4 g_runner
t_red "--control 'accept 5' (two rows in one) -> FAIL" "is not one row" gmut --control 'accept 5' c4 charts/g/gram.sh "PATTERN='" "${WIDE}" 4 g_runner
t_red "--control 1 (the header) -> FAIL" "control line 1 is not an accept / reject row" gmut --control 1 c5 charts/g/gram.sh "PATTERN='" "${WIDE}" 4 g_runner
t_red "--control 99 (past the end) -> FAIL" "control line 99 is not an accept / reject row" gmut --control 99 c7 charts/g/gram.sh "PATTERN='" "${WIDE}" 4 g_runner
t_red "--control 4 (the expected line itself) -> FAIL" "is the expected failing line itself" gmut --control 4 c8 charts/g/gram.sh "PATTERN='" "${WIDE}" 4 g_runner
t_red "--control bogus -> FAIL" "is not accept, reject or a line number" gmut --control bogus c9 charts/g/gram.sh "PATTERN='" "${WIDE}" 4 g_runner
t_red "--control reject x3 when the table has 2 other reject rows -> FAIL" "no reject row other than line 4" gmut --control reject --control reject --control reject c10 charts/g/gram.sh "PATTERN='" "${WIDE}" 4 g_runner
t_red "...the same on ct_run_mutant_rows (the expected line alone is run, the reason is named)" "no reject row other than line 4" gmut --control reject --control reject --control reject c11 charts/g/gram.sh "PATTERN='" "${WIDE}" 4 g_rows_runner

# The runner's side of the contract.
t_red "a runner that walks no table (BAD_LINES by hand) -> FAIL" "walked no table" gmut p1 charts/g/gram.sh "PATTERN='" "${WIDE}" 4 g_none_runner
t_red "a runner that skips a control row -> FAIL" "did not run control line 2" gmut p2 charts/g/gram.sh "PATTERN='" "${WIDE}" 4 g_want_only_runner
t_red "a runner that skips the expected line -> FAIL" "did not run table line 4" gmut p3 charts/g/gram.sh "PATTERN='" "${WIDE}" 4 g_other_runner
t_red "ct_run_mutant_rows outside a ct_mutate_line runner -> FAIL" "called outside a ct_mutate_line runner" ct_run_mutant_rows "${G_TSV}" g_row "${MR}/charts/g/gram.sh"
CT_REPO_ROOT="${SAVED_ROOT}"
t_group "mutate_line: the judge"

ct_finish "casetable lib self-test"
