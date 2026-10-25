# shellcheck shell=bash
# The shell reader of the shared grammar case tables (`input<TAB>accept|reject`;
# app#509). Sourced, never executed (mode 100644). It is the READER layer: it knows
# the table format and how to mutate a copy of a script, and nothing about
# deploy-user.sh, helm, kubectl or docker. The stub helm / kubectl harness that the
# deploy-user.sh checks add on top is scripts/lib/deploy-user-harness.sh.
#
# Who uses it: scripts/check-seat-grammar.sh and scripts/check-deploy-user-ids.sh
# (both layers); the next grammar's check (app#472: gen-values.sh, the chart's
# regexMatch) is one more table plus one check_row function, not another copy of
# this reader. The Go reader is internal/casetable (it owns the format; this file
# reads the same one, and internal/casetable's
# TestShellPlaceholdersAreTheGoPlaceholders holds the closed placeholder set equal).
# Self-test: scripts/test-casetable-lib.sh (touches no docker, helm or stub).
#
# What is a contract and what is not: the TABLE format (path, two columns, the
# `# pattern: ` header, the placeholder set) is the cross-repo contract, listed in
# .claude/rules/falco-ctf-app-conventions.md. THIS file's path, its function names
# and its self-test are app-internal and not a contract: a reader that needs another
# shape is changed here, in one place. A check never copies this reader's code.
#
# API (every name is ct_*, or one of the globals below):
#   ct_init <repo root>              WORK dir + EXIT trap; sets CT_REPO_ROOT, RC=0
#   fail <msg> / pass <msg>          "  FAIL: ..." (stderr, RC=1) / "  ok:   ..."
#   ct_finish <name>                 exit 1 if RC != 0 ("<name> FAILED"), else "<name> passed"
#   ct_decode <placeholdered input>  -> DECODED (a variable: $(...) would strip a trailing
#                                    {LF}). The placeholders: CT_PLACEHOLDERS
#   ct_header_pattern <tsv>          prints the regex of line 1 `# pattern: <regex>`; rc 1
#                                    if line 1 is anything else
#   ct_run_table <tsv> <row fn> [extra args...]
#                                    walks the table: header required, blank and `#` lines
#                                    skipped, split on the FIRST tab, verdict accept|reject,
#                                    placeholders decoded, a brace left = unknown
#                                    placeholder = a BAD row (never a verdict). Calls
#                                    <row fn> <label> <line no> <verdict> <decoded input>
#                                    [extra args...]; rc != 0 = the row disagrees, and the
#                                    row fn prints why as `    <label>:<line no>: <why>`.
#                                    -> ROWS ACCEPTED REJECTED BAD BAD_LINES (" 3 7 "),
#                                    RAN_TABLE (<tsv>) RAN_LINES (the rows walked, " 2 3 ")
#   ct_expect_table <what> <min rows> <min accept> <min reject> <tsv> <row fn> [extra...]
#                                    ct_run_table + pass/fail (misread / truncated / BAD rows)
#   ct_line_of <tsv> <awk condition on $1 (input) and $2 (verdict)>
#                                    prints the line number of the first matching row
#   ct_mutate_line [--control <row>]... [--must <text>]
#                  <label> <repo-relative file> <line prefix> <replacement line>
#                  <expected failing line> <runner fn> [<copy dir> [<glob>]]
#                                    copies to a scratch tree, at the same repo-relative
#                                    paths, the files whose name matches <glob> (default
#                                    `*.sh`; `*` = everything) in <copy dir> (repo-relative;
#                                    default: the file's own directory, that directory only;
#                                    given: its whole tree, e.g. a chart's templates/),
#                                    replaces the ONE line of <file> starting with <line
#                                    prefix> (<file> under <copy dir>; modes kept), and hands
#                                    the mutant to <runner fn> <mutant file>, which walks the
#                                    table (ct_run_table, or ct_run_mutant_rows). FAIL unless
#                                    the mutant breaks that row, and that row only (app#522):
#                                    1. a *.sh file (or a #! bash / sh one) passes `bash -n`:
#                                       a copy that does not parse fails EVERY row, the
#                                       expected one too (it is not run);
#                                    2. the runner walked a table, and <expected failing
#                                       line> ran and is in BAD_LINES;
#                                    3. every control row ran and is NOT in BAD_LINES (a copy
#                                       that rejects everything fails an accept control, one
#                                       that accepts everything a reject control). <row> =
#                                       accept / reject (the first such row that is not the
#                                       expected line nor already a control) or a line no.;
#                                       one per --control, an empty one (a line_of that found
#                                       nothing) is a FAIL. Default: accept and reject. A break
#                                       that flips every row of one verdict by design names
#                                       the other verdict only, and says why with --must;
#                                    4. --must: the expected line's reason (`<label>:<line>:
#                                       ...` on the runner's stderr) carries <text>.
#                                    What it guarantees: without --must, that the expected
#                                    line fails and the control rows hold, not WHY the line
#                                    fails (a pattern mutant's reason is a generic `reject,
#                                    but exit 97`). The intended reason only with --must.
#   ct_run_mutant_rows <tsv> <row fn> [extra args...]
#                                    ct_run_table inside a ct_mutate_line runner, for the
#                                    expected line and the control rows only (resolved by
#                                    the rule ct_mutate_line checks with)
# Internal, not for a check: the _ct_* functions and the CT_MUT_* globals (the mutation in
# progress). The self-test calls _ct_walk directly.
#
# Every expectation is an exit status or an exact string, never "some output
# appeared". Written for bash 3.2 (macOS) as well as 5: no mapfile, no associative
# arrays, no ${x,,}, `${1+"$@"}` for a possibly empty list under `set -u`.
# The assigned-but-unused globals are the API of the sourcing script.
# shellcheck disable=SC2034

[[ "${BASH_SOURCE[0]}" != "$0" ]] || { echo "scripts/lib/casetable.sh is sourced, not executed" >&2; exit 2; }

# The closed placeholder set a table may spell (the Go reader's set; `{LF}` is a
# newline, `{U+XXXX}` the code point). The names are listed on ONE line of their
# own so a Go test can read them; ct_decode below decodes exactly these.
CT_PLACEHOLDERS='{LF} {U+202E} {U+00FC} {U+00EF}'

CT_BIDI="$(printf '\342\200\256')"   # U+202E, built at run time: this file stays ASCII
CT_UUML="$(printf '\303\274')"       # U+00FC
CT_IUML="$(printf '\303\257')"       # U+00EF
CT_LF=$'\n'

RC=0
fail() { echo "  FAIL: $1" >&2; RC=1; }
pass() { echo "  ok:   $1"; }

ct_finish() {
  if [[ "${RC}" -ne 0 ]]; then
    echo "$1 FAILED" >&2
    exit 1
  fi
  echo "$1 passed"
}

ct_init() {
  CT_REPO_ROOT="$1"
  WORK="$(mktemp -d)"
  trap 'rm -rf "${WORK}"' EXIT
  RC=0
}

ct_decode() {
  DECODED="$1"
  DECODED="${DECODED//\{LF\}/${CT_LF}}"
  DECODED="${DECODED//\{U+202E\}/${CT_BIDI}}"
  DECODED="${DECODED//\{U+00FC\}/${CT_UUML}}"
  DECODED="${DECODED//\{U+00EF\}/${CT_IUML}}"
}

ct_header_pattern() {
  local first=""
  IFS= read -r first < "$1" || [[ -n "${first}" ]] || return 1
  case "${first}" in
    '# pattern: '?*) printf '%s' "${first#'# pattern: '}" ;;
    *) return 1 ;;
  esac
}

# --- the table walk ---------------------------------------------------------
# _ct_walk <tsv> <only> <row fn> [extra args...]: the walk of ct_run_table and
# ct_run_mutant_rows. <only> is "" (every row) or " 3 7 " (those rows only; one of them
# that is not a row of the table, a `#` / blank line or past the end, is a BAD line).
_ct_walk() {
  local tsv="$1" only="$2" fn="$3" label line lineno=0 input verdict n
  shift 3
  label="$(basename "${tsv}")"
  ROWS=0 ACCEPTED=0 REJECTED=0 BAD=0 BAD_LINES=" " RAN_TABLE="${tsv}" RAN_LINES=" "
  # Line 1 is the canonical `# pattern: ` literal (the Go reader treats it as a
  # comment and pins it elsewhere; a table without it has lost what platform's
  # parity test reads).
  if ! ct_header_pattern "${tsv}" > /dev/null; then
    echo "    ${label}:1: line 1 is not '# pattern: <regex>'" >&2
    BAD=$((BAD + 1)); BAD_LINES="${BAD_LINES}1 "
  fi
  while IFS= read -r line || [[ -n "${line}" ]]; do
    lineno=$((lineno + 1))
    case "${line}" in ''|'#'*) continue ;; esac
    [[ -z "${only}" || "${only}" == *" ${lineno} "* ]] || continue
    RAN_LINES="${RAN_LINES}${lineno} "
    # First tab only (an empty input makes the line start with a tab).
    if [[ "${line}" != *$'\t'* ]]; then
      echo "    ${label}:${lineno}: no tab" >&2; BAD=$((BAD + 1)); BAD_LINES="${BAD_LINES}${lineno} "; continue
    fi
    input="${line%%$'\t'*}"
    verdict="${line#*$'\t'}"
    case "${verdict}" in
      accept) ACCEPTED=$((ACCEPTED + 1)) ;;
      reject) REJECTED=$((REJECTED + 1)) ;;
      *) echo "    ${label}:${lineno}: verdict must be accept|reject" >&2; BAD=$((BAD + 1)); BAD_LINES="${BAD_LINES}${lineno} "; continue ;;
    esac
    ROWS=$((ROWS + 1))
    ct_decode "${input}"
    # The placeholder set is closed (the table's header): a brace left after
    # decoding is an unknown placeholder, an error of this reader, not a verdict.
    case "${DECODED}" in
      *'{'*|*'}'*)
        echo "    ${label}:${lineno}: a brace is left after decoding: an unknown placeholder" >&2
        BAD=$((BAD + 1)); BAD_LINES="${BAD_LINES}${lineno} "; continue ;;
    esac
    "${fn}" "${label}" "${lineno}" "${verdict}" "${DECODED}" ${1+"$@"} \
      || { BAD=$((BAD + 1)); BAD_LINES="${BAD_LINES}${lineno} "; }
  done < "${tsv}"
  for n in ${only}; do
    case "${RAN_LINES}" in
      *" ${n} "*) ;;
      *) echo "    ${label}:${n}: not a row of the table" >&2; BAD=$((BAD + 1)); BAD_LINES="${BAD_LINES}${n} " ;;
    esac
  done
  return 0
}

ct_run_table() {
  local tsv="$1"
  shift
  _ct_walk "${tsv}" "" ${1+"$@"}
}

ct_expect_table() {
  local what="$1" min_rows="$2" min_accept="$3" min_reject="$4"
  shift 4
  ct_run_table "$@"
  if [[ "${ROWS}" -lt "${min_rows}" || "${ACCEPTED}" -lt "${min_accept}" || "${REJECTED}" -lt "${min_reject}" ]]; then
    fail "${what}: the table was misread or truncated: ${ROWS} rows (${ACCEPTED} accept / ${REJECTED} reject)"
  elif [[ "${BAD}" -ne 0 ]]; then
    fail "${what}: ${BAD} of ${ROWS} rows disagree with the script"
  else
    pass "${what}: all ${ROWS} rows (${ACCEPTED} accept / ${REJECTED} reject) behave as the table says"
  fi
}

# --- the self-test's mutation helpers ---------------------------------------
ct_line_of() {
  local n
  n="$(awk -F'\t' "$2 { print NR; exit }" "$1")"
  [[ -n "${n}" ]] || { echo "FAIL: no row of $1 matches $2" >&2; return 1; }
  printf '%s' "${n}"
}

# _ct_mut_controls <tsv> <expected failing line> <control spec> -> CT_MUT_CTL_LINES
# (" 2 5 "), or rc 1 and the reason in CT_MUT_CTL_ERR. ct_run_mutant_rows (before the
# rows are run) and ct_mutate_line (after) both resolve with this, so they agree.
_ct_mut_controls() {
  local tsv="$1" want="$2" spec="$3" tok n
  CT_MUT_CTL_LINES=" " CT_MUT_CTL_ERR=""
  for tok in ${spec}; do
    case "${tok}" in
      accept|reject)
        # The first row of that verdict that is neither the expected line nor a
        # control already chosen ('accept accept' = two accept rows).
        n="$(awk -F'\t' -v v="${tok}" -v w="${want}" -v have="${CT_MUT_CTL_LINES}" '
          /^#/ || $0 == "" || NR == w || index(have, " " NR " ") { next }
          index($0, "\t") && substr($0, index($0, "\t") + 1) == v { print NR; exit }' "${tsv}")"
        if [[ -z "${n}" ]]; then
          CT_MUT_CTL_ERR="no ${tok} row other than line ${want} in $(basename "${tsv}") to be a control"
          return 1
        fi ;;
      *[!0-9]*)
        CT_MUT_CTL_ERR="control '${tok}' is not accept, reject or a line number"
        return 1 ;;
      *)
        n=$((10#${tok}))
        if [[ "${n}" -eq "${want}" ]]; then
          CT_MUT_CTL_ERR="control line ${n} is the expected failing line itself"
          return 1
        fi
        if ! awk -F'\t' -v n="${n}" '
            NR == n { v = substr($0, index($0, "\t") + 1); ok = !/^#/ && index($0, "\t") && (v == "accept" || v == "reject"); exit }
            END { exit !ok }' "${tsv}"; then
          CT_MUT_CTL_ERR="control line ${n} is not an accept / reject row of $(basename "${tsv}")"
          return 1
        fi ;;
    esac
    CT_MUT_CTL_LINES="${CT_MUT_CTL_LINES}${n} "
  done
  if [[ "${CT_MUT_CTL_LINES}" == " " ]]; then
    CT_MUT_CTL_ERR="no control row: a mutant is judged on at least one row it must leave as it is"
    return 1
  fi
  return 0
}

# _ct_reason <stderr file> <line no>: the first reason a row function gave for that
# table line (`    <label>:<line>: <why>`), 150 characters; "" if none. Always rc 0.
_ct_reason() {
  awk -v n="$2" '$0 ~ ("^ *[^ ]+:" n ": ") { sub(/^ +/, ""); print substr($0, 1, 150); exit }' "$1"
}

# _ct_is_shell <file>: rc 0 for a *.sh file or one whose first line is a #! naming bash / sh.
_ct_is_shell() {
  local first="" re='^#!.*[/ ](ba)?sh([[:space:]]|$)'
  case "$1" in *.sh) return 0 ;; esac
  IFS= read -r first < "$1" || true
  [[ "${first}" =~ ${re} ]]
}

ct_run_mutant_rows() {
  local tsv="$1"
  shift
  ROWS=0 ACCEPTED=0 REJECTED=0 BAD=0 BAD_LINES=" " RAN_TABLE="" RAN_LINES=" "
  if [[ -z "${CT_MUT_WANT:-}" ]]; then
    fail "ct_run_mutant_rows: called outside a ct_mutate_line runner"
    return 0
  fi
  # A control that does not resolve: the expected line alone is walked, and
  # ct_mutate_line, resolving the same spec against the same table, names the reason.
  _ct_mut_controls "${tsv}" "${CT_MUT_WANT}" "${CT_MUT_CONTROL}" || CT_MUT_CTL_LINES=" "
  _ct_walk "${tsv}" " ${CT_MUT_WANT}${CT_MUT_CTL_LINES}" ${1+"$@"}
}

ct_mutate_line() {
  local control="" must="" has_must=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --control|--must)
        if [[ $# -lt 2 ]]; then fail "ct_mutate_line: $1 needs a value"; return 0; fi
        if [[ "$1" == --must ]]; then must="$2"; has_must=1; shift 2; continue; fi
        # One row per --control: an empty one (its line_of found nothing) or two in one
        # would quietly leave a mutant with fewer controls than its call names.
        case "$2" in
          ''|*[[:space:]]*) fail "ct_mutate_line: --control '$2' is not one row (accept, reject or a line number)"; return 0 ;;
        esac
        control="${control} $2"
        shift 2 ;;
      --*) fail "ct_mutate_line: unknown option $1"; return 0 ;;
      *) break ;;
    esac
  done
  [[ -n "${control}" ]] || control='accept reject'
  local label="$1" rel="$2" prefix="$3" repl="$4" want="$5" runner="$6"
  local srcdir="${7:-$(dirname "${rel}")}" glob="${8:-*.sh}" depth=()
  local root file mutant l n=0 err why c
  # No <copy dir> given: the file's own directory only. One given: its whole tree.
  [[ $# -ge 7 ]] || depth=(-maxdepth 1)
  root="${WORK}/mut-${label}"
  mutant="${root}/${rel}"
  err="${WORK}/mut-${label}.err"
  if [[ -z "${want}" ]]; then
    fail "self-test ${label}: no expected failing line (the table row it is about was not found)"
    return 0
  fi
  if [[ "${has_must}" -eq 1 && -z "${must}" ]]; then
    fail "self-test ${label}: --must is empty (every reason would carry it)"
    return 0
  fi
  case "${rel}" in
    "${srcdir}"/*) ;;
    *) fail "self-test ${label}: ${rel} is not under the copy dir ${srcdir}"; return 0 ;;
  esac
  # Copy the tree (every file whose name matches <glob>, mode kept, same
  # repo-relative path).
  while IFS= read -r file; do
    mkdir -p "${root}/$(dirname "${file}")"
    cp -p "${CT_REPO_ROOT}/${file}" "${root}/${file}"
  done < <(cd "${CT_REPO_ROOT}" && find "${srcdir}" ${depth[@]+"${depth[@]}"} -type f -name "${glob}" | sort)
  if [[ ! -f "${mutant}" ]]; then
    fail "self-test ${label}: ${rel} is not among the copied files (${srcdir}, ${glob})"
    return 0
  fi
  # Rewrite the one definition line (no sed -i: BSD and GNU differ).
  while IFS= read -r l; do
    case "${l}" in
      "${prefix}"*) printf '%s\n' "${repl}"; n=$((n + 1)) ;;
      *) printf '%s\n' "${l}" ;;
    esac
  done < "${mutant}" > "${mutant}.new"
  if [[ "${n}" -ne 1 ]]; then
    fail "self-test ${label}: ${rel} has ${n} lines starting with '${prefix}' (want exactly 1 to mutate)"
    return 0
  fi
  # cat, not mv: the mutant keeps the original's mode.
  cat "${mutant}.new" > "${mutant}"
  rm -f "${mutant}.new"
  # 1. A script that does not parse fails every row at once, the expected one
  # included: a broken copy, not the break the self-test is about. It is not run.
  # (Run from the scratch tree: the message names the repo-relative path.)
  if _ct_is_shell "${mutant}" && ! (cd "${root}" && bash -n "${rel}") 2> "${err}"; then
    why="$(tr '\n' ' ' < "${err}")"
    fail "self-test ${label}: '${repl}' does not parse (bash -n): ${why:0:200}"
    return 0
  fi
  BAD=0 BAD_LINES=" " ROWS=0 RAN_TABLE="" RAN_LINES=" "
  CT_MUT_WANT="${want}" CT_MUT_CONTROL="${control}"
  "${runner}" "${mutant}" 2> "${err}"
  CT_MUT_WANT="" CT_MUT_CONTROL=""
  # 2. The runner walked a table (the controls resolve against it), and the row the
  # mutant is about ran and fails.
  if [[ -z "${RAN_TABLE}" ]]; then
    fail "self-test ${label}: the runner walked no table (ct_run_table / ct_run_mutant_rows): no row of it can be judged"
    return 0
  fi
  if ! _ct_mut_controls "${RAN_TABLE}" "${want}" "${control}"; then
    fail "self-test ${label}: ${CT_MUT_CTL_ERR}"
    return 0
  fi
  case "${RAN_LINES}" in
    *" ${want} "*) ;;
    *) fail "self-test ${label}: the runner did not run table line ${want} (the row the mutant is about)"; return 0 ;;
  esac
  case "${BAD_LINES}" in
    *" ${want} "*) ;;
    *) fail "self-test ${label}: '${repl}' did not fail table line ${want} (failing lines:${BAD_LINES})"; return 0 ;;
  esac
  # 3. The control rows ran and keep their verdict: the mutant changed that row, not these.
  for c in ${CT_MUT_CTL_LINES}; do
    case "${RAN_LINES}" in
      *" ${c} "*) ;;
      *) fail "self-test ${label}: the runner did not run control line ${c}"; return 0 ;;
    esac
    case "${BAD_LINES}" in
      *" ${c} "*)
        fail "self-test ${label}: '${repl}' fails control line ${c} too, not table line ${want} alone (broken for another reason?): $(_ct_reason "${err}" "${c}")"
        return 0 ;;
    esac
  done
  # 4. ...for the intended reason.
  why="$(_ct_reason "${err}" "${want}")"
  # One awk, no `| grep -q` (under pipefail an early exit of grep is a SIGPIPE, not a
  # verdict); the text goes in through the environment (-v would read backslashes).
  if [[ -n "${must}" ]] && ! CT_MUST="${must}" awk -v n="${want}" '
      $0 ~ ("^ *[^ ]+:" n ": ") && index($0, ENVIRON["CT_MUST"]) { found = 1 } END { exit !found }' "${err}"; then
    fail "self-test ${label}: '${repl}' fails table line ${want}, but not for the intended reason: '${must}' is not in '${why:-no reason on stderr}'"
    return 0
  fi
  pass "self-test ${label}: '${repl}' fails table line ${want} (${BAD} row(s) in all; control line(s)${CT_MUT_CTL_LINES% } hold): ${why}"
  return 0
}
