#!/usr/bin/env bash
# Self-test of scripts/sourcehygiene-scan.py (ADR-0045, app#511 F2): proves the reference
# scanner's --selftest can fail. The scanner's own --selftest runs the shared cases, three
# data mutants, the reader's negatives and planted trees; THIS runs the scanner against
# deliberately broken copies of ITS OWN CODE and of its three data files, so a scanner whose
# --selftest quietly stopped catching things is red here:
#   - the unmodified copy passes (the control every mutant is judged against);
#   - code mutants: the ZWJ rule dropped / U+FE0F treated as always forbidden / the bidi
#     rows not read / the bidi rule not applied / the lone-CR and BOM rules dropped / a range
#     read as half-open; data mutants: U+FE0F always in the table, the bidi rows, the Tag row
#     or the edge cases dropped, .pdf dropped from binary-ext.tsv: each makes `--selftest`
#     exit 1 for the intended reason (a crash, or a failure for another reason, is not accepted);
#   - a data file that cannot be read is a FAIL (never a skip); a Unicode version that differs
#     from the data header is a WARN, not a FAIL; a wrong command line is exit 2;
#   - the app tree is clean outside invisible-allowlist.txt (what flag-guard runs too).
# The mutation helper has the shape of ct_mutate_line (scripts/lib/casetable.sh): a copy in
# a scratch tree, exactly one line replaced, the copy must still parse, the control passes,
# and the failure must carry the intended reason. It cannot BE ct_mutate_line: that one
# judges accept|reject case tables, and these tables are not that format.
#
# Usage: ./scripts/test-sourcehygiene-scan.sh --selftest   (CI flag-guard)
set -euo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
# shellcheck source=lib/casetable.sh
source "${REPO_ROOT}/scripts/lib/casetable.sh"
ct_init "${REPO_ROOT}"

if [[ "${1:-}" != "--selftest" || $# -ne 1 ]]; then
  echo "usage: $0 --selftest" >&2
  exit 2
fi

SCAN_REL="scripts/sourcehygiene-scan.py"
RANGES_REL="internal/sourcehygiene/testdata/hidden-ranges.tsv"
CASES_REL="internal/sourcehygiene/testdata/hidden-cases.tsv"
BINEXT_REL="internal/sourcehygiene/testdata/binary-ext.tsv"

# mk_checkout <dir>: the scanner and its three data files, at their repo-relative paths.
mk_checkout() {
  local d="$1" f
  for f in "${SCAN_REL}" "${RANGES_REL}" "${CASES_REL}" "${BINEXT_REL}"; do
    mkdir -p "${d}/$(dirname "${f}")"
    cp -p "${REPO_ROOT}/${f}" "${d}/${f}"
  done
}

# run_py <args...>: python3 <args>; OUT / ERR files and ST (the exit status), set -e safe.
OUT="${WORK}/run.out"
ERR="${WORK}/run.err"
ST=0
run_py() {
  set +e
  python3 "$@" > "${OUT}" 2> "${ERR}"
  ST=$?
  set -e
}

# has <what> <text>: the text is in the last run's stdout or stderr.
has() {
  grep -qF -- "$1" "${OUT}" "${ERR}"
}

# expect <what> <want status> <must text> -- <python args...>
expect() {
  local what="$1" want="$2" must="$3"
  shift 4
  run_py "$@"
  if [[ "${ST}" -ne "${want}" ]]; then
    fail "${what}: exit ${ST}, want ${want} ($(head -c 300 "${ERR}" | tr '\n' ' '))"
  elif [[ -n "${must}" ]] && ! has "${must}"; then
    fail "${what}: exit ${ST} as wanted, but '${must}' is in neither stdout nor stderr ($(head -c 300 "${ERR}" | tr '\n' ' '))"
  else
    pass "${what} (exit ${ST})"
  fi
}

# --- the control: the unmodified copy ----------------------------------------
CK="${WORK}/ck"
mk_checkout "${CK}"
SCAN="${CK}/${SCAN_REL}"
expect "control: the unmodified copy passes --selftest" 0 "OK sourcehygiene-scan --selftest" -- "${SCAN}" --selftest

# --- the mutants --------------------------------------------------------------
# mutate <label> <file> <line prefix> <replacement line> <must text>
mutate() {
  local label="$1" rel="$2" prefix="$3" repl="$4" must="$5" root n=0 l
  root="${WORK}/mut-${label}"
  mk_checkout "${root}"
  while IFS= read -r l || [[ -n "${l}" ]]; do
    case "${l}" in
      "${prefix}"*) printf '%s\n' "${repl}"; n=$((n + 1)) ;;
      *) printf '%s\n' "${l}" ;;
    esac
  done < "${root}/${rel}" > "${root}/${rel}.new"
  if [[ "${n}" -ne 1 ]]; then
    fail "mutant ${label}: ${rel} has ${n} lines starting with '${prefix}' (want exactly 1 to mutate)"
    return 0
  fi
  cat "${root}/${rel}.new" > "${root}/${rel}"
  rm -f "${root}/${rel}.new"
  case "${rel}" in
    *.py)
      if ! python3 -c 'import ast, sys; ast.parse(open(sys.argv[1]).read())' "${root}/${rel}" 2> "${ERR}"; then
        fail "mutant ${label}: '${repl}' does not parse: $(head -c 200 "${ERR}" | tr '\n' ' ')"
        return 0
      fi ;;
  esac
  expect "mutant ${label}: --selftest goes red for the intended reason" 1 "${must}" -- "${root}/${SCAN_REL}" --selftest
}

# drop_lines <label> <file> <text every dropped line holds> <must text>
drop_lines() {
  local label="$1" rel="$2" word="$3" must="$4" root
  root="${WORK}/mut-${label}"
  mk_checkout "${root}"
  if ! grep -qF -- "${word}" "${root}/${rel}"; then
    fail "mutant ${label}: no line of ${rel} holds '${word}' to drop"
    return 0
  fi
  grep -vF -- "${word}" "${root}/${rel}" > "${root}/${rel}.new" || true
  cat "${root}/${rel}.new" > "${root}/${rel}"
  rm -f "${root}/${rel}.new"
  expect "mutant ${label}: --selftest goes red for the intended reason" 1 "${must}" -- "${root}/${SCAN_REL}" --selftest
}

TAB="$(printf '\t')"
mutate zwj-rule-dropped "${SCAN_REL}" '            elif rule == "zwjInEmoji":' \
  '            elif rule == "zwjInEmoji" and False:' 'ZWJ between letters is red: scan gives none, the file says 1:2 U+200D'
mutate fe0f-always "${SCAN_REL}" '            if rule == "always" or rule == "bidi":' \
  '            if rule in ("always", "bidi", "vsAfterSymbol"):' 'warning sign + VS16 is green: scan gives 1:2 U+FE0F, the file says none'
mutate bidi-rows-not-read "${SCAN_REL}" '        rows.append((lo, hi, cols[2], cols[3]))' \
  '        rows.append((lo, hi, cols[2], cols[3])) if cols[2] != "bidi" else None' "no row has rule 'bidi'"
mutate bidi-rule-not-applied "${SCAN_REL}" '            if rule == "always" or rule == "bidi":' \
  '            if rule == "always":' 'a bidi control in a word: U+202E: scan gives none, the file says 1:2 U+202E'
mutate lone-cr-dropped "${SCAN_REL}" '            elif rule == "loneCR":' \
  '            elif rule == "loneCR" and False:' 'a lone CR in the middle is red: scan gives none, the file says 1:3 U+000D'
mutate bom-rule-dropped "${SCAN_REL}" '            elif rule == "bomAtStart":' \
  '            elif rule == "bomAtStart" and False:' 'BOM after the first byte is red: scan gives none, the file says 1:2 U+FEFF'
mutate range-half-open "${SCAN_REL}" '        if i >= 0 and cp <= self.rows[i][1]:' \
  '        if i >= 0 and cp < self.rows[i][1]:' 'scan gives none, the file says'
# The walk (review-5x of #536): an end-anchored path rule, a walk that skips what it cannot list,
# symlinks to directories left out of the listing, `..` accepted by --also-untracked.
mutate path-rule-end-anchored "${SCAN_REL}" '        if not re.fullmatch(r"[!-~]+", rel):' \
  '        if not re.match(r"^[!-~]+$", rel):' "walk 'a file name that ends in LF is not printable ASCII (no walk, no git)'"
mutate symlinked-dirs-not-listed "${SCAN_REL}" '        names = list(files) + [x for x in dirs if os.path.islink(os.path.join(d, x))]' \
  '        names = list(files)' "walk 'a symlink to a directory whose name is not printable ASCII is a problem'"
mutate also-untracked-dotdot "${SCAN_REL}" '        if (rel == "" or os.path.isabs(rel) or os.path.normpath(rel) != rel or rel == "." or rel == ".."' \
  '        if (rel == "" or os.path.isabs(rel) or os.path.normpath(rel) != rel or rel == "."' "walk 'git: --also-untracked of .. is refused'"
if [[ "$(id -u)" -ne 0 ]]; then # a root user can list a mode-000 directory: that mutant is not observable
  mutate walk-errors-skipped "${SCAN_REL}" '    for d, dirs, files in os.walk(base, onerror=onerror):' \
    '    for d, dirs, files in os.walk(base):' "walk 'a directory that cannot be listed is a FAIL, not a skipped subtree'"
fi
mutate fe0f-always-in-table "${RANGES_REL}" 'U+FE0E'"${TAB}"'U+FE0F'"${TAB}" \
  'U+FE0E'"${TAB}"'U+FE0E'"${TAB}"'vsAfterSymbol'"${TAB}"'VARIATION SELECTOR-15'$'\n''U+FE0F'"${TAB}"'U+FE0F'"${TAB}"'always'"${TAB}"'VARIATION SELECTOR-16' \
  'warning sign + VS16 is green: scan gives 1:2 U+FE0F, the file says none'
drop_lines table-without-bidi-lines "${RANGES_REL}" "${TAB}bidi${TAB}" "no row has rule 'bidi'"
drop_lines table-without-the-tag-row "${RANGES_REL}" "TAG CHARACTER" 'Tag characters hiding ASCII: every one is reported: scan gives none'
drop_lines cases-without-the-edge-rows "${CASES_REL}" 'edge: ' 'no case has a finding at U+'
drop_lines cases-cut-below-the-floor "${CASES_REL}" '{U+' 'fewer than the floor'
drop_lines binary-ext-without-pdf "${BINEXT_REL}" '.pdf' "walk 'a file with an extension of binary-ext.tsv is not scanned'"

# --- a data file that cannot be read is a FAIL, never a skip ---------------------
for f in "${RANGES_REL}" "${CASES_REL}" "${BINEXT_REL}"; do
  U="${WORK}/unreadable"
  rm -rf "${U}"
  mk_checkout "${U}"
  rm "${U}/${f}"
  expect "no ${f##*/}: --selftest FAIL" 1 "cannot read the data file" -- "${U}/${SCAN_REL}" --selftest
  expect "no ${f##*/}: a tree scan FAIL too" 1 "cannot read the data file" -- "${U}/${SCAN_REL}" "${REPO_ROOT}"
done
rm -rf "${U}"
mk_checkout "${U}"
sed -e 's/^# unicode: .*/# unicode: 1.0.0/' "${REPO_ROOT}/${RANGES_REL}" > "${U}/${RANGES_REL}"
expect "a different Unicode version is a WARN, not a FAIL" 0 "WARN unicode: data 1.0.0 / python" -- "${U}/${SCAN_REL}" --selftest

# --- the command line --------------------------------------------------------------
expect "--selftest with a directory is exit 2" 2 "usage:" -- "${SCAN}" --selftest "${REPO_ROOT}"
expect "no argument is exit 2" 2 "usage:" -- "${SCAN}"

# --- the real tree, with the real allowlist ------------------------------------------
expect "the app tree is clean outside invisible-allowlist.txt" 0 "0 problems" -- \
  "${SCAN}" "${REPO_ROOT}" --allowlist "${REPO_ROOT}/internal/sourcehygiene/testdata/invisible-allowlist.txt"

ct_finish "sourcehygiene-scan self-test"
