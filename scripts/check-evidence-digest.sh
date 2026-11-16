#!/usr/bin/env bash
# ADR-0056 V16, the shell side: the canonical digest of an evidence bundle, held to the
# shared case table internal/edition/testdata/bundle-digest/cases.tsv that the Go side
# (internal/edition/bundle_digest_test.go) runs too. The shell implementation is
# charts/ctf-user/evidence-bundle.sh (evidence_bundle_digest), sourced by deploy-user.sh.
# No cluster, no helm, no kubectl, no docker: it reads the case directories and hashes them.
#
# Three things are checked:
#   1. every row: the digest of the row's directory is the digest column (the empty bundle
#      has no directory in git, so an empty one is made; `empty` is the only such row);
#      the table's CRLF and UTF-8 content cases are among the rows that ran.
#   2. every row's `input` column (the exact bytes the digest is the sha256 of, spelled for
#      printf) hashes to its digest column, so the table is right under THIS shell's hash
#      too, not only under Go's.
#   3. self-test: copies of the library with ONE mistake each (the names in reverse order,
#      a space for the NUL, no LF after an entry) must be caught by the table, on the rows
#      the mistake changes, or this check proves nothing and fails. (The mistake "a
#      locale's collation instead of LC_ALL=C" is held by the `byte-order` row only where
#      the locale's order differs from byte order, which a C.UTF-8 CI runner does not;
#      the table's own header says why that row exists.)
#
# Written for bash 3.2 (macOS) and 5. Usage: ./scripts/check-evidence-digest.sh
# (make check-flags).
set -euo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
# shellcheck source=lib/casetable.sh
source "${REPO_ROOT}/scripts/lib/casetable.sh"
LIB="${REPO_ROOT}/charts/ctf-user/evidence-bundle.sh"
TABLE="${REPO_ROOT}/internal/edition/testdata/bundle-digest/cases.tsv"
CASES_DIR="${REPO_ROOT}/internal/edition/testdata/bundle-digest"
MIN_CASES=12

ct_init "${REPO_ROOT}"
for f in "${LIB}" "${TABLE}"; do
  [[ -f "${f}" ]] || { echo "FAIL: ${f} not found" >&2; exit 1; }
done
mkdir -p "${WORK}/empty-bundle"

# digest_cases <library file> -> one line "<rows run>|<failing case ids>|<case ids run>"
digest_cases() {
  (
    # shellcheck source=/dev/null
    source "$1"
    local ran=0 bad="" ids="" line id rest digest dir got
    while IFS= read -r line || [[ -n "${line}" ]]; do
      case "${line}" in '' | '#'*) continue ;; esac
      id="${line%%$'\t'*}"
      rest="${line#*$'\t'}"
      digest="${rest%%$'\t'*}"
      dir="${CASES_DIR}/${id}"
      if [[ ! -d "${dir}" ]]; then
        [[ "${id}" == empty ]] || { echo "case ${id}: no directory (only \`empty\` is the empty bundle)" >&2; exit 1; }
        dir="${WORK}/empty-bundle"
      fi
      ran=$((ran + 1))
      ids="${ids} ${id}"
      got="$(evidence_bundle_digest "${dir}")" || got="error"
      if [[ "${got}" != "${digest}" ]]; then bad="${bad} ${id}"; fi
    done < "${TABLE}"
    printf '%s|%s|%s\n' "${ran}" "${bad}" "${ids}"
  )
}

echo "==> the shell digest against the shared case table"
OUT="$(digest_cases "${LIB}")" || fail "the case table could not be run"
RAN="${OUT%%|*}"
REST="${OUT#*|}"
BAD="${REST%%|*}"
IDS="${REST#*|}"
if [[ "${RAN}" -lt "${MIN_CASES}" ]]; then
  fail "only ${RAN} rows ran, want at least ${MIN_CASES}: the table is not being read"
elif [[ -n "${BAD}" ]]; then
  fail "the shell digest differs from the table on:${BAD}"
else
  pass "all ${RAN} rows give the table's digest"
fi
for id in content-crlf content-utf8 byte-order empty; do
  case " ${IDS} " in
    *" ${id} "*) ;;
    *) fail "the table has no row ${id} (CRLF, UTF-8, byte order and the empty bundle must be covered)" ;;
  esac
done

echo "==> every row's input column hashes to its digest column (this shell's sha256)"
(
  # shellcheck source=/dev/null
  source "${LIB}"
  n=0
  while IFS= read -r line || [[ -n "${line}" ]]; do
    case "${line}" in '' | '#'*) continue ;; esac
    rest="${line#*$'\t'}"
    digest="${rest%%$'\t'*}"
    input=""
    case "${rest}" in *$'\t'*) input="${rest#*$'\t'}" ;; esac
    got="$(printf '%b' "${input}" | evidence_sha256_hex)" || got="error"
    n=$((n + 1))
    if [[ "${got}" != "${digest}" ]]; then echo "  FAIL: row ${line%%$'\t'*}: its input column does not hash to its digest column" >&2; exit 1; fi
  done < "${TABLE}"
  echo "  ok:   ${n} input columns"
) || fail "an input column of the table does not hash to its digest column"

echo "==> self-test: a library with one mistake is caught by the table"
# mutant <label> <text to replace> <replacement> <case that must fail>
mutant() {
  local label="$1" from="$2" to="$3" must="$4" l n=0 file="${WORK}/mutant-${1}.sh" out bad
  while IFS= read -r l; do
    case "${l}" in
      *"${from}"*) printf '%s%s%s\n' "${l%%"${from}"*}" "${to}" "${l#*"${from}"}"; n=$((n + 1)) ;;
      *) printf '%s\n' "${l}" ;;
    esac
  done < "${LIB}" > "${file}"
  if [[ "${n}" -ne 1 ]]; then
    fail "mutant ${label}: '${from}' is on ${n} lines of the library, want exactly 1"
    return 0
  fi
  out="$(digest_cases "${file}")" || { fail "mutant ${label}: the table could not be run"; return 0; }
  bad="${out#*|}"
  bad="${bad%%|*}"
  case " ${bad} " in
    *" ${must} "*) pass "mutant ${label}: caught on${bad}" ;;
    *) fail "mutant ${label}: the table did not catch it on ${must} (failing:${bad:- none})" ;;
  esac
}
mutant reverse-order '"${EVIDENCE_ENTRIES[@]}" | LC_ALL=C sort)' '"${EVIDENCE_ENTRIES[@]}" | LC_ALL=C sort -r)' two-files
mutant space-for-nul "tr '\\t' '\\0'" "tr '\\t' ' '" one-file
mutant no-lf '"${hex}"$'"'"'\n'"'" '"${hex}"' one-file

ct_finish "shell bundle digest check"
