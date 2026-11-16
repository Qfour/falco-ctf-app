# shellcheck shell=bash
# The evidence-bundle helpers of deploy-user.sh (ADR-0056 D9 / D11, A5c). Sourced, never
# executed (mode 100644), by charts/ctf-user/deploy-user.sh and by
# scripts/check-evidence-digest.sh (V16, shell side). Written for bash 3.2 (macOS) as well
# as 5: no mapfile, no associative arrays, no ${x,,}, no `local -n`.
#
# What lives here is the PURE part: the canonical digest of a bundle (the one other
# implementation of internal/edition.BundleDigest; both run the shared case table
# internal/edition/testdata/bundle-digest) and the reader of a values file's investigate
# scope. The rules about a bundle (the B2 name grammar, the limits) and everything that
# touches a cluster stay in deploy-user.sh. This file copies the DEFINITION of the digest
# only, never a rule about a bundle's content (D9).
#
# API:
#   evidence_sha256_hex             stdin -> lower-case hex sha256 (sha256sum, else shasum -a 256)
#   evidence_read_entries <dir>     -> EVIDENCE_ENTRIES (every entry name, dot entries too, in
#                                   no particular order); rc 1 unless <dir> is a directory
#   evidence_sorted_names <dir>     -> the entry names, byte order (LC_ALL=C sort), one per line;
#                                   rc 1 for a name holding TAB or LF
#   evidence_bundle_digest <dir>    -> D9's digest of the files of <dir>; rc 1 unless every entry
#                                   is a regular file (not a link, not a directory)
#   evidence_scope_cids <values>    -> the challenge ids of the plant.mounts entries marked
#                                   `evidence: true` in a generated values file, one per line;
#                                   rc 3 for an `evidence:` line that is not in that form
# Neither digest function reads a name's grammar: deploy-user.sh checks B2 first.
# shellcheck disable=SC2034

[[ "${BASH_SOURCE[0]}" != "$0" ]] || { echo "charts/ctf-user/evidence-bundle.sh is sourced, not executed" >&2; exit 2; }

EVIDENCE_ENTRIES=()

evidence_sha256_hex() {
  local out
  if command -v sha256sum >/dev/null 2>&1; then
    out="$(sha256sum)" || return 1
  elif command -v shasum >/dev/null 2>&1; then
    out="$(shasum -a 256)" || return 1
  else
    echo "evidence: neither sha256sum nor shasum is available" >&2
    return 1
  fi
  printf '%s\n' "${out%% *}"
}

# The glob trio (`*`, `.[!.]*`, `..?*`) lists dot entries too; a glob that matches nothing
# stays a literal pattern, so each candidate is confirmed to exist (`-e`, or `-L` for a
# dangling link) before it is counted.
evidence_read_entries() {
  local dir="$1" p
  EVIDENCE_ENTRIES=()
  [[ -d "${dir}" ]] || return 1
  for p in "${dir}"/* "${dir}"/.[!.]* "${dir}"/..?*; do
    if [[ -e "${p}" || -L "${p}" ]]; then
      EVIDENCE_ENTRIES+=("${p##*/}")
    fi
  done
  return 0
}

evidence_sorted_names() {
  local name
  evidence_read_entries "$1" || return 1
  if [[ "${#EVIDENCE_ENTRIES[@]}" -eq 0 ]]; then
    return 0
  fi
  for name in "${EVIDENCE_ENTRIES[@]}"; do
    case "${name}" in
      *$'\t'* | *$'\n'*) return 1 ;;
    esac
  done
  (set -o pipefail; printf '%s\n' "${EVIDENCE_ENTRIES[@]}" | LC_ALL=C sort)
}

# name NUL hex(sha256(content)) LF, one entry per file in byte order of the names; the
# digest is the sha256 of that sequence. The NUL cannot live in a shell variable: the list
# is kept with a TAB and turned into NUL on the way to the hash.
evidence_bundle_digest() {
  local dir="$1" names name hex list="" result
  names="$(evidence_sorted_names "${dir}")" || return 1
  if [[ -n "${names}" ]]; then
    while IFS= read -r name; do
      [[ -f "${dir}/${name}" && ! -L "${dir}/${name}" ]] || return 1
      hex="$(evidence_sha256_hex < "${dir}/${name}")" || return 1
      list="${list}${name}"$'\t'"${hex}"$'\n'
    done <<< "${names}"
  fi
  result="$(set -o pipefail; printf '%s' "${list}" | LC_ALL=C tr '\t' '\0' | evidence_sha256_hex)" || return 1
  printf '%s\n' "${result}"
}

# gen-values.sh writes an investigate challenge's mount as
#       evidence: true
#       challenge: <cid>
# (render_plant_block). Anything else that carries an `evidence:` key is not understood,
# and an unread entry would read as "no investigate challenge here": rc 3, fail-closed.
evidence_scope_cids() {
  LC_ALL=C awk '
    want {
      want = 0
      if ($0 ~ /^      challenge: [0-9][0-9]-[a-z0-9-]+$/) { sub(/^      challenge: /, ""); print; next }
      bad = 1
    }
    /^ *evidence:/ {
      if ($0 == "      evidence: true") { want = 1 } else { bad = 1 }
      next
    }
    END { if (want) bad = 1; exit (bad ? 3 : 0) }' "$1"
}
