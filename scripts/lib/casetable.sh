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
#                                    [extra args...]; rc != 0 = the row disagrees.
#                                    -> ROWS ACCEPTED REJECTED BAD BAD_LINES (" 3 7 ")
#   ct_expect_table <what> <min rows> <min accept> <min reject> <tsv> <row fn> [extra...]
#                                    ct_run_table + pass/fail (misread / truncated / BAD rows)
#   ct_line_of <tsv> <awk condition on $1 (input) and $2 (verdict)>
#                                    prints the line number of the first matching row
#   ct_mutate_line <label> <repo-relative file> <line prefix> <replacement line>
#                  <expected failing line> <runner fn> [<copy dir> [<glob>]]
#                                    copies to a scratch tree, at the same repo-relative
#                                    paths, the files whose name matches <glob> (default
#                                    `*.sh`; `*` = everything) in <copy dir> (repo-relative;
#                                    default: the file's own directory, that directory only;
#                                    given: its whole tree, e.g. a chart's templates/),
#                                    replaces the ONE line of <file>
#                                    starting with <line prefix>, and hands the mutant file
#                                    to <runner fn> <mutant file> (which runs the table with
#                                    ct_run_table); the row at <expected failing line> must
#                                    then be in BAD_LINES, or the self-test proves nothing:
#                                    FAIL. <file> must be under <copy dir>. File modes are
#                                    kept (a mutant script stays executable).
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
ct_run_table() {
  local tsv="$1" fn="$2" label line lineno=0 input verdict
  shift 2
  label="$(basename "${tsv}")"
  ROWS=0 ACCEPTED=0 REJECTED=0 BAD=0 BAD_LINES=" "
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
  return 0
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

ct_mutate_line() {
  local label="$1" rel="$2" prefix="$3" repl="$4" want="$5" runner="$6"
  local srcdir="${7:-$(dirname "${rel}")}" glob="${8:-*.sh}" depth=()
  local root file mutant l n=0
  # No <copy dir> given: the file's own directory only. One given: its whole tree.
  [[ $# -ge 7 ]] || depth=(-maxdepth 1)
  root="${WORK}/mut-${label}"
  mutant="${root}/${rel}"
  if [[ -z "${want}" ]]; then
    fail "self-test ${label}: no expected failing line (the table row it is about was not found)"
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
  "${runner}" "${mutant}" 2>"${WORK}/mut-${label}.err"
  case "${BAD_LINES}" in
    *" ${want} "*) pass "self-test ${label}: '${repl}' fails table line ${want} (${BAD} row(s) in all): $(grep -F ":${want}:" "${WORK}/mut-${label}.err" | head -n 1 | sed 's/^ *//' | cut -c1-150)" ;;
    *) fail "self-test ${label}: '${repl}' did not fail table line ${want} (failing lines:${BAD_LINES})" ;;
  esac
  return 0
}
