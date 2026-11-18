#!/usr/bin/env bash
# ADR-0056 V17 / V48 / V49 / V50 (A5c): deploy-user.sh --evidence-dir / --evidence-digests,
# with stub `helm` / `kubectl` on PATH that only record their calls (the harness
# scripts/lib/deploy-user-harness.sh; no cluster, no helm, no docker). Nothing here is
# run against a real cluster, and nothing here can reach one: the stubs are first on PATH
# and hide the real tools (checked first, below).
#
#   accept  -> deploy-user.sh reaches `helm upgrade` (the stub exits 97 there), and the
#              recorded calls are exactly what D11 says: the Secret ctf-evidence-<cid> is
#              made by `kubectl create secret generic ... --from-file=<name>=<path>`, one
#              argument per file (never the directory), labelled, after the namespace
#              exists and before helm; the only `kubectl apply` is the namespace's;
#              every other ctf-evidence-* is deleted by label before helm; the chart gets
#              the NAMES only (evidence.challenges.<cid>.names[i]); a sentinel written into
#              a bundle is in no recorded call and no output (V50).
#   reject  -> a non-zero exit with the reason on stderr and NOT ONE helm / kubectl call:
#              V17 (--flags-file without the two arguments, one argument alone, neither,
#              arguments with no investigate challenge, a digest mismatch), V48 (a missing or
#              extra <cid>/, a digests row set that is not the scope), V49 (a file of 512 KiB
#              + 1, a bundle of 512 KiB + 1 in two files, a seat of 2 MiB + 1, 65 files, a
#              name outside B2, a link, a subdirectory, an empty bundle) and the shape of
#              the digests file. The limits themselves pass (exactly 64 files, 512 KiB, 2 MiB).
#   practice (V65 / V66, A5c-2): none of the three arguments -> the practice edition's path:
#              the Secrets come from <cid>/edition/practice/evidence/ only (the golden
#              fixture's edition and one built here), the names in byte order, no answers.tsv /
#              digests.tsv / content in any call; each of V66's trees (a byte changed, a run id
#              that is not all zeros, no practice/, a link, a name outside B2, ...) and an
#              event's digests file of the practice shape are refused with no call.
#   A5e (V94): with the stub helm letting `helm upgrade` through (that one block only) and
#              the assert replaced by an argv recorder in a scratch copy of the chart dir,
#              in all / scenario / single-challenge (with and without a values file) mode:
#              the assert runs after helm, its 5th argument is helm's -f file (- for none)
#              and its <cid>/<name> arguments are helm's names[i] values, as a set.
#   self-test: copies of deploy-user.sh with ONE guard removed or moved (a limit one too
#              wide, the digest comparison, the label-selector delete, the practice path's
#              run id / seat / link / bundle dir) must turn the case that guard is about red,
#              or this check proves nothing.
#
# The bundles are placeholders (`x`, SENTINEL-AAA, the case table's files). The digest used
# to build a digests file for a fixture is the library's (evidence-bundle.sh), which
# scripts/check-evidence-digest.sh holds to the shared case table.
# Usage: ./scripts/check-deploy-user-evidence.sh   (make check-flags)
set -euo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
# shellcheck source=lib/casetable.sh
source "${REPO_ROOT}/scripts/lib/casetable.sh"
# shellcheck source=lib/deploy-user-harness.sh
source "${REPO_ROOT}/scripts/lib/deploy-user-harness.sh"
# shellcheck source=../charts/ctf-user/evidence-bundle.sh
source "${REPO_ROOT}/charts/ctf-user/evidence-bundle.sh"
DEPLOY="${REPO_ROOT}/charts/ctf-user/deploy-user.sh"
CASES_DIR="${REPO_ROOT}/internal/edition/testdata/bundle-digest"

ct_init "${REPO_ROOT}"
ct_init_stubs
unset FALCO_CTF_REGISTRY FALCO_CTF_IMAGE_TAG
CDIR="${WORK}/challenges"
SDIR="${WORK}/scenarios"
EVD="${WORK}/evd"
DG="${WORK}/digests.tsv"
FLAGS="${WORK}/flags.yaml"
RUN_ID='0123456789abcdef0123456789abcdef'
HEADER="# falco-ctf evidence-digests v1 run=${RUN_ID}"

# The stubs must hide the real tools before anything runs.
ct_run bash -c 'command -v kubectl; command -v helm'
if [[ "$(cat "${CT_RUN_OUT}")" != "${CT_STUB_BIN}/kubectl${CT_LF}${CT_STUB_BIN}/helm" ]]; then
  echo "FAIL: the stub kubectl / helm are not first on PATH ($(tr '\n' ' ' < "${CT_RUN_OUT}")): refusing to run" >&2
  exit 1
fi

# --- fixtures ----------------------------------------------------------------
# write_values <cid>...: values-all.yaml in the form gen-values.sh writes, an
# `evidence: true` mount per cid, plus an evade challenge so --flags-file can be valid.
write_values() {
  local n=0 cid
  {
    printf 'plant:\n  seedScript:\n    - sh\n  mounts:\n'
    for cid in "$@"; do
      n=$((n + 1))
      printf '    - path: /opt/fx/ev%d\n      readOnly: true\n      evidence: true\n      challenge: %s\n' "${n}" "${cid}"
    done
  } > "${CDIR}/values-all.yaml"
}
# write_digests [header]: a row for seat user1 per <cid>/ of the tree, digests by the library
write_digests() {
  local d cid
  {
    printf '%s\n' "${1:-${HEADER}}"
    for d in "${EVD}"/*/; do
      cid="${d%/}"
      cid="${cid##*/}"
      printf 'user1\t%s\t%s\n' "${cid}" "$(evidence_bundle_digest "${d%/}")"
    done
  } > "${DG}"
}
# mkbytes <path> <n>: n bytes (placeholder content)
mkbytes() { head -c "$2" /dev/zero > "$1"; }
# good_setup: two investigate challenges, valid bundles and digests
good_setup() {
  rm -rf "${CDIR}" "${SDIR}" "${EVD}"
  mkdir -p "${CDIR}/03-fx" "${SDIR}" "${EVD}/40-ev" "${EVD}/41-ev"
  printf 'challengeId: 03-fx\ntype: evade\nexpectedFlag: FALCO{dev-fx-default}\n' > "${CDIR}/03-fx/falco-rule.yaml"
  printf 'flags:\n  03-fx: FALCO{dev-fx-rotated}\n' > "${FLAGS}"
  write_values 40-ev 41-ev
  cp -R "${CASES_DIR}/two-files/." "${EVD}/40-ev/"
  printf 'SENTINEL-AAA\n' > "${EVD}/41-ev/x"
  write_digests
}
run_deploy() { ct_run "${DEPLOY}" --challenges-dir "${CDIR}" --scenarios-dir "${SDIR}" ${1+"$@"} -- user1 all; }
TAB=$'\t'

# --- verdicts (they report through fail and always return 0) -----------------
# check_reject <label> <want status> <stderr marker> [deploy flags...]
check_reject() {
  local label="$1" want="$2" marker="$3"
  shift 3
  run_deploy ${1+"$@"}
  if [[ "${RUN_STATUS}" -ne "${want}" ]]; then
    fail "${label}: reject, but exit ${RUN_STATUS} (want ${want}): $(tr '\n' ' ' < "${CT_RUN_ERR}" | cut -c1-160)"
  elif [[ -s "${CT_CALLS}" ]]; then
    fail "${label}: reject, but helm/kubectl was called: $(cut -d' ' -f1-4 "${CT_CALLS}" | tr '\n' ';' | cut -c1-160)"
  elif ! grep -qF -- "${marker}" "${CT_RUN_ERR}"; then
    fail "${label}: reject, but stderr lacks '${marker}': $(tr '\n' ' ' < "${CT_RUN_ERR}" | cut -c1-160)"
  elif ! ct_no_bidi_output "${label}"; then
    RC=1
  else
    pass "${label}"
  fi
  return 0
}
# check_reached <label> [deploy flags...]: reached helm upgrade
check_reached() {
  local label="$1"
  shift
  run_deploy ${1+"$@"}
  if ct_check_reached_upgrade "${label}"; then pass "${label}"; else RC=1; fi
  return 0
}
EVFLAGS=()
set_evflags() { EVFLAGS=(--evidence-dir "${EVD}" --evidence-digests "${DG}"); }
# line_no <fixed text>: the number of the first recorded call line equal to the text (0: none)
line_no() {
  local n
  n="$(grep -nxF -- "$1" "${CT_CALLS}" | head -n 1 | cut -d: -f1 || true)"
  printf '%s' "${n:-0}"
}

# --- accept -------------------------------------------------------------------
case_accept() {
  local evd create40 create41 helm_line n l_ns l_del l_c40 l_c41 l_helm s
  good_setup
  set_evflags
  run_deploy --flags-file "${FLAGS}" "${EVFLAGS[@]}"
  ct_check_reached_upgrade accept || { RC=1; return 0; }
  evd="$(cd "${EVD}" && pwd)"
  create40="kubectl -n ctf-user1 create secret generic ctf-evidence-40-ev --from-file=a=${evd}/40-ev/a --from-file=b=${evd}/40-ev/b"
  create41="kubectl -n ctf-user1 create secret generic ctf-evidence-41-ev --from-file=x=${evd}/41-ev/x"
  l_c40="$(line_no "${create40}")"
  l_c41="$(line_no "${create41}")"
  l_del="$(line_no 'kubectl -n ctf-user1 delete secret -l app.kubernetes.io/managed-by=deploy-user,falco-ctf/evidence-of,falco-ctf/evidence-of notin (40-ev,41-ev)')"
  l_ns="$(line_no 'kubectl create namespace ctf-user1 --dry-run=client -o yaml')"
  l_helm="$(grep -n '^helm upgrade ' "${CT_CALLS}" | head -n 1 | cut -d: -f1)"
  if [[ "${l_c40}" -eq 0 || "${l_c41}" -eq 0 ]]; then
    fail "accept: the Secrets are not made by 'create secret generic' with one --from-file=<name>=<path> per file: $(grep -F 'create secret' "${CT_CALLS}" | cut -c1-200)"; return 0
  fi
  if [[ "${l_del}" -eq 0 ]]; then fail "accept: the ctf-evidence-* outside the scope are not deleted by label selector before helm"; return 0; fi
  if ! [[ "${l_ns}" -gt 0 && "${l_ns}" -lt "${l_del}" && "${l_del}" -lt "${l_c40}" && "${l_c40}" -lt "${l_c41}" && "${l_c41}" -lt "${l_helm}" ]]; then
    fail "accept: the order is not namespace (${l_ns}) < delete by label (${l_del}) < create 40 (${l_c40}) < create 41 (${l_c41}) < helm (${l_helm})"; return 0
  fi
  if [[ "$(grep -cE '^kubectl (-n [^ ]+ )?apply' "${CT_CALLS}")" -ne 1 ]]; then
    fail "accept: more than the namespace's one kubectl apply was called"; return 0
  fi
  for s in '^kubectl .*--from-file=[^=]*$' "--from-file=${evd}/40-ev( |\$)" "--from-file=${evd}/40-ev/( |\$)" '--from-file=[^= ]*=[^ ]*/( |$)'; do
    if grep -qE -- "${s}" "${CT_CALLS}"; then fail "accept: a --from-file argument is a directory or has no name (${s})"; return 0; fi
  done
  for s in 'delete secret ctf-evidence-40-ev --ignore-not-found' 'delete secret ctf-evidence-41-ev --ignore-not-found' \
    'label secret ctf-evidence-40-ev --overwrite app.kubernetes.io/managed-by=deploy-user falco-ctf/evidence-of=40-ev' \
    'label secret ctf-evidence-41-ev --overwrite app.kubernetes.io/managed-by=deploy-user falco-ctf/evidence-of=41-ev'; do
    grep -qxF -- "kubectl -n ctf-user1 ${s}" "${CT_CALLS}" || { fail "accept: no call '${s}'"; return 0; }
  done
  helm_line="$(grep '^helm upgrade ' "${CT_CALLS}" | head -n 1)"
  for s in ' --set-string evidence.challenges.40-ev.names[0]=a ' ' --set-string evidence.challenges.40-ev.names[1]=b ' ' --set-string evidence.challenges.41-ev.names[0]=x ' ' --set-string challenge.flags.03-fx='; do
    case "${helm_line}" in *"${s}"*) ;; *) fail "accept: helm upgrade lacks '${s}'"; return 0 ;; esac
  done
  # V50: the content of a bundle is in no call, no output; helm gets names only
  n="$(grep -c 'SENTINEL' "${CT_CALLS}" "${CT_RUN_OUT}" "${CT_RUN_ERR}" | cut -d: -f2 | tr -d '\n' || true)"
  if [[ "${n}" != "000" ]]; then fail "accept: the sentinel written into a bundle reached a call or an output (${n})"; return 0; fi
  pass "accept: Secrets by name (--from-file=<name>=<path>), labelled, no apply, stale ones deleted by label, names only to helm, no content anywhere (V49, V50)"
}
case_accept_lockdown() {
  local l_svc l_ns
  good_setup
  set_evflags
  run_deploy --egress-lockdown --api-server-cidr 10.0.0.1/32 "${EVFLAGS[@]}"
  ct_check_reached_upgrade lockdown || { RC=1; return 0; }
  l_svc="$(line_no 'kubectl get svc kubernetes -n default -o jsonpath={.spec.clusterIP}')"
  l_ns="$(line_no 'kubectl create namespace ctf-user1 --dry-run=client -o yaml')"
  if [[ "${l_svc}" -gt 0 && "${l_svc}" -lt "${l_ns}" ]]; then
    pass "accept with --egress-lockdown: the ClusterIP lookup still comes before the namespace step"
  else
    fail "accept with --egress-lockdown: the ClusterIP lookup (${l_svc}) is not before the namespace step (${l_ns})"
  fi
}
case_no_scope_cleanup() {
  good_setup
  write_values
  run_deploy --flags-file "${FLAGS}"
  ct_check_reached_upgrade "no investigate challenge" || { RC=1; return 0; }
  if grep -qxF 'kubectl -n ctf-user1 delete secret -l app.kubernetes.io/managed-by=deploy-user,falco-ctf/evidence-of' "${CT_CALLS}" \
    && ! grep -q 'create secret' "${CT_CALLS}" && ! grep -q 'evidence.challenges' "${CT_CALLS}"; then
    pass "no investigate challenge, no evidence argument: an earlier deploy's ctf-evidence-* is deleted (no notin), nothing is created, helm gets no evidence value"
  else
    fail "no investigate challenge: the stale-Secret delete or the absence of a create is wrong: $(grep -F 'secret' "${CT_CALLS}" | cut -c1-200)"
  fi
}

# A `label` that fails must not leave an unlabelled Secret (the selector would miss it) and
# must not go on to helm: the Secret is deleted again, then exit 1.
case_label_fails() {
  local l_lab l_del
  good_setup
  set_evflags
  CT_KUBECTL_FAIL='label secret ctf-evidence-40-ev' run_deploy "${EVFLAGS[@]}"
  l_lab="$(line_no 'kubectl -n ctf-user1 label secret ctf-evidence-40-ev --overwrite app.kubernetes.io/managed-by=deploy-user falco-ctf/evidence-of=40-ev')"
  l_del="$(grep -nxF 'kubectl -n ctf-user1 delete secret ctf-evidence-40-ev --ignore-not-found' "${CT_CALLS}" | tail -n 1 | cut -d: -f1 || true)"
  if [[ "${RUN_STATUS}" -ne 1 ]]; then
    fail "label fails: exit ${RUN_STATUS}, want 1"
  elif grep -q '^helm upgrade ' "${CT_CALLS}"; then
    fail "label fails: helm upgrade was called"
  elif [[ "${l_lab}" -eq 0 || "${l_del:-0}" -le "${l_lab}" ]]; then
    fail "label fails: the Secret was not deleted again after the failed label (label at ${l_lab}, last delete at ${l_del:-none})"
  elif grep -q 'ctf-evidence-41-ev' "${CT_CALLS}"; then
    fail "label fails: the script went on to the next challenge"
  elif ! grep -qF 'it was deleted again, helm was not run' "${CT_RUN_ERR}"; then
    fail "label fails: stderr does not say the Secret was deleted again: $(tr '\n' ' ' < "${CT_RUN_ERR}" | cut -c1-160)"
  else
    pass "a failed label deletes the Secret again and stops before helm"
  fi
}

echo "==> accept: the calls D11 prescribes (V49, V50)"
case_accept
case_accept_lockdown
case_no_scope_cleanup
case_label_fails

# --- V17: the arguments ----------------------------------------------------------
echo "==> V17: the arguments (no kubectl / helm call, exit 2)"
good_setup
check_reject "--flags-file without --evidence-dir and --evidence-digests (V17 a)" 2 'both are required' --flags-file "${FLAGS}"
check_reject "--evidence-dir alone (V17 b)" 2 'go together' --evidence-dir "${EVD}"
check_reject "--evidence-digests alone (V17 c)" 2 'go together' --evidence-digests "${DG}"
check_reject "neither argument, no practice edition in the tree (V17, V66)" 1 'has no practice edition'
write_values
check_reject "arguments, but no investigate challenge in scope" 2 'has no investigate challenge' --evidence-dir "${EVD}" --evidence-digests "${DG}"

# --- V17 d / V48: the digests -----------------------------------------------------
echo "==> V17 (d) / V48: the digests file and the <cid>/ set (exit 1, no call)"
# reject_with <label> <marker> <mutation function>: good setup, the mutation, the verdict
reject_with() {
  local label="$1" marker="$2" mut="$3"
  good_setup
  "${mut}"
  set_evflags
  check_reject "${label}" 1 "${marker}" "${EVFLAGS[@]}"
}
m_content() { printf 'changed\n' >> "${EVD}/40-ev/a"; }
m_rename() { mv "${EVD}/40-ev/b" "${EVD}/40-ev/c"; }
m_one_row() { write_digests; head -n 2 "${DG}" > "${DG}.new"; cat "${DG}.new" > "${DG}"; }
m_extra_row() { printf 'user1\t99-xx\t%s\n' "$(printf '%064d' 0)" >> "${DG}"; }
m_dup_row() { sed -n '2p' "${DG}" > "${DG}.new"; cat "${DG}.new" >> "${DG}"; }
m_header_v2() { write_digests "# falco-ctf evidence-digests v2 run=${RUN_ID}"; }
m_zero_run() { write_digests '# falco-ctf evidence-digests v1 run=00000000000000000000000000000000'; }
m_upper() { { printf '%s\n' "${HEADER}"; printf 'user1\t40-ev\t%s\n' "$(printf '%064d' 0 | tr 0 A)"; } > "${DG}"; }
m_two_columns() { printf '%s\nuser1\t40-ev\n' "${HEADER}" > "${DG}"; }
m_cr() { { printf '%s\n' "${HEADER}"; printf 'user1\t40-ev\t%s\r\n' "$(printf '%064d' 0)"; } > "${DG}"; }
m_no_lf() { { sed -n '1,2p' "${DG}"; printf 'user1\t41-ev\t%s' "$(printf '%064d' 0)"; } > "${DG}.new"; cat "${DG}.new" > "${DG}"; }
m_header_only() { printf '%s\n' "${HEADER}" > "${DG}"; }
m_empty() { : > "${DG}"; }
m_nul() { printf '%s\n\000' "${HEADER}" > "${DG}"; }
m_other_seat() { sed "s/^user1${TAB}/user2${TAB}/" "${DG}" > "${DG}.new"; cat "${DG}.new" > "${DG}"; }
m_missing_dir() { rm -rf "${EVD}/41-ev"; }
m_extra_dir() { mkdir -p "${EVD}/99-xx"; }
m_extra_file() { : > "${EVD}/README"; }
m_dir_link() { mv "${EVD}/41-ev" "${WORK}/elsewhere"; ln -s "${WORK}/elsewhere" "${EVD}/41-ev"; }
m_empty_bundle() { rm -f "${EVD}/41-ev/x"; }
reject_with "a changed byte: the digest is not the row (V17 d)" 'is not the row of the digests file' m_content
reject_with "a renamed file: the digest is not the row (V17 d, the name is in the digest)" 'is not the row of the digests file' m_rename
reject_with "no row for one challenge of the scope (V48)" 'has 1 rows for seat user1' m_one_row
reject_with "a row of this seat for a challenge outside the scope (V48)" 'not an investigate challenge of this scope' m_extra_row
reject_with "a second row for one (seat, challenge)" 'has a second row' m_dup_row
reject_with "header v2" 'line 1 is not the v1 header' m_header_v2
reject_with "run id all zeros" 'all zeros' m_zero_run
reject_with "upper-case digest" 'not 64 lower-case hex' m_upper
reject_with "a row of two columns" 'does not have three columns' m_two_columns
reject_with "a CR at the end of a row" 'not 64 lower-case hex' m_cr
reject_with "no final newline" 'does not end with a newline' m_no_lf
reject_with "a header and no row" 'empty or has no row' m_header_only
reject_with "an empty file" 'empty or has no row' m_empty
reject_with "a NUL byte" 'NUL byte' m_nul
reject_with "rows of another seat only (this seat has none)" 'has 0 rows for seat user1' m_other_seat
reject_with "a <cid>/ of the scope is missing (V48)" 'no 41-ev/ directory' m_missing_dir
reject_with "a <cid>/ outside the scope" 'not an investigate challenge of this scope' m_extra_dir
reject_with "a plain file beside the <cid>/ dirs" 'not an investigate challenge of this scope' m_extra_file
reject_with "a <cid>/ that is a link" 'is not a directory' m_dir_link
reject_with "a bundle with no file" 'holds no file' m_empty_bundle

# --- V49: names, kinds, limits --------------------------------------------------------
echo "==> V49: names, kinds and limits (before any cluster call)"
m_upper_name() { : > "${EVD}/40-ev/Upper"; }
m_dot_name() { : > "${EVD}/40-ev/.hid"; }
m_long_name() { : > "${EVD}/40-ev/$(printf '%064d' 0)"; }
m_bidi_name() { : > "${EVD}/40-ev/a$(printf '\342\200\256')"; }
m_space_name() { : > "${EVD}/40-ev/a b"; }
m_link_file() { ln -s a "${EVD}/40-ev/l"; }
m_subdir() { mkdir "${EVD}/40-ev/sub"; }
m_65() { local i; rm -f "${EVD}/40-ev"/*; for i in $(seq 1 65); do : > "${EVD}/40-ev/f${i}"; done; }
m_file_over() { rm -f "${EVD}/40-ev"/*; mkbytes "${EVD}/40-ev/big" 524289; }
m_bundle_over() { rm -f "${EVD}/40-ev"/*; mkbytes "${EVD}/40-ev/p" 262144; mkbytes "${EVD}/40-ev/q" 262145; }
reject_with "a file name with a capital (outside B2)" 'outside ^[a-z0-9]' m_upper_name
reject_with "a file name starting with a dot" 'outside ^[a-z0-9]' m_dot_name
reject_with "a file name of 64 characters" 'outside ^[a-z0-9]' m_long_name
reject_with "a file name with a bidi control (never echoed raw)" 'outside ^[a-z0-9]' m_bidi_name
reject_with "a file name with a space" 'outside ^[a-z0-9]' m_space_name
reject_with "a link in a bundle" 'is not a regular file' m_link_file
reject_with "a directory in a bundle" 'is not a regular file' m_subdir
reject_with "65 files in a bundle" 'at most 64 files' m_65
reject_with "one file of 512 KiB + 1 byte" 'larger than 524288 bytes' m_file_over
reject_with "a bundle of 512 KiB + 1 byte in two files" 'larger than 524288 bytes' m_bundle_over
case_seat_over() {
  local i
  good_setup
  write_values 40-ev 41-ev 42-ev 43-ev 44-ev
  rm -rf "${EVD}"
  for i in 40 41 42 43; do mkdir -p "${EVD}/${i}-ev"; mkbytes "${EVD}/${i}-ev/big" 524288; done
  mkdir -p "${EVD}/44-ev"; mkbytes "${EVD}/44-ev/x" 1
  write_digests
  set_evflags
  check_reject "a seat of 2 MiB + 1 byte (four bundles of 512 KiB and one byte)" 1 'together' "${EVFLAGS[@]}"
}
case_seat_over
echo "==> V49: the limits themselves pass"
case_limit_files() {
  local i
  good_setup
  rm -f "${EVD}/40-ev"/*
  for i in $(seq 1 64); do : > "${EVD}/40-ev/f${i}"; done
  write_digests
  set_evflags
  check_reached "exactly 64 files in a bundle" "${EVFLAGS[@]}"
}
case_limit_bundle() {
  good_setup
  rm -f "${EVD}/40-ev"/*
  mkbytes "${EVD}/40-ev/big" 524288
  write_digests
  set_evflags
  check_reached "exactly 512 KiB in a bundle" "${EVFLAGS[@]}"
}
case_limit_seat() {
  local i
  good_setup
  write_values 40-ev 41-ev 42-ev 43-ev
  rm -rf "${EVD}"
  for i in 40 41 42 43; do mkdir -p "${EVD}/${i}-ev"; mkbytes "${EVD}/${i}-ev/big" 524288; done
  write_digests
  set_evflags
  check_reached "exactly 2 MiB in a seat (four bundles of 512 KiB)" "${EVFLAGS[@]}"
}
case_limit_files
case_limit_bundle
case_limit_seat

# --- the reader of the scope, tied to the generator (A5c-1 review R2#1) -------------------------
echo "==> the scope reader against gen-values.sh's own output, and its fail-closed refusals"
# gen-values.sh --emit-evidence-fixture renders, from two investigate challenges, the plant
# block the real generator writes. evidence_scope_cids must read exactly those challenges,
# and a deploy over that very file must reach helm.
case_generated_scope() {
  local fx="${WORK}/evfx" out want
  rm -rf "${fx}"
  mkdir -p "${fx}"
  if ! "${REPO_ROOT}/challenges/gen-values.sh" --emit-evidence-fixture "${fx}" > /dev/null 2>&1; then
    fail "gen-values.sh --emit-evidence-fixture failed: no generated values to read"
    return 0
  fi
  out="$(evidence_scope_cids "${fx}/values.yaml")" || { fail "evidence_scope_cids refused gen-values.sh's own output"; return 0; }
  want="$(cut -f2 "${fx}/map" | LC_ALL=C sort)"
  if [[ -z "${want}" || "${out}" != "${want}" ]]; then
    fail "evidence_scope_cids read [$(printf '%s' "${out}" | tr '\n' ' ')], the generator's evidence map holds [$(printf '%s' "${want}" | tr '\n' ' ')]"
    return 0
  fi
  pass "the scope read from gen-values.sh's own output is its evidence map ($(printf '%s' "${out}" | tr '\n' ' '))"
  good_setup
  cp "${fx}/values.yaml" "${CDIR}/values-all.yaml"
  set_evflags
  check_reached "a deploy over gen-values.sh's own values reaches helm" "${EVFLAGS[@]}"
}
case_generated_scope
# scope_bad <label> <lines...>: the reader refuses (rc 3). scope_ok <label> <expected output> <lines...>
scope_bad() {
  local label="$1" f="${WORK}/scope.yaml" rc=0
  shift
  printf '%s\n' "$@" > "${f}"
  evidence_scope_cids "${f}" > /dev/null || rc=$?
  if [[ "${rc}" -eq 3 ]]; then pass "scope reader refuses: ${label}"; else fail "scope reader: ${label}: rc ${rc}, want 3 (fail-closed)"; fi
}
scope_ok() {
  local label="$1" want="$2" f="${WORK}/scope.yaml" out rc=0
  shift 2
  printf '%s\n' "$@" > "${f}"
  out="$(evidence_scope_cids "${f}")" || rc=$?
  if [[ "${rc}" -eq 0 && "${out}" == "${want}" ]]; then pass "scope reader reads: ${label}"; else fail "scope reader: ${label}: rc ${rc}, read [${out}], want [${want}]"; fi
}
EV='      evidence: true'
CH='      challenge: 40-ev'
scope_ok "one entry" '40-ev' '    - path: /x' '      readOnly: true' "${EV}" "${CH}"
scope_ok "two entries" "40-ev${CT_LF}41-ev" "${EV}" "${CH}" "${EV}" '      challenge: 41-ev'
scope_ok "an empty file" ''
scope_ok "a commented-out key" '' '      # evidence: true' '# evidence: true'
scope_ok "the seed script's own words (a comment, a path)" '' '      # evidence bundle (ADR-0056 D11): x' '      cp "/opt/ctf/evidence-src/40-ev/a" "x"'
scope_bad "evidence: true and then another key" "${EV}" '      path: /x'
scope_bad "evidence: true at the end of the file" "${EV}"
scope_bad "evidence at 4 spaces" '    evidence: true' '    challenge: 40-ev'
scope_bad "evidence at 8 spaces" '        evidence: true' '        challenge: 40-ev'
scope_bad "evidence: \"true\"" '      evidence: "true"' "${CH}"
scope_bad "evidence: true with a comment" '      evidence: true # c' "${CH}"
scope_bad "evidence: True" '      evidence: True' "${CH}"
scope_bad "evidence: false" '      evidence: false' "${CH}"
scope_bad "a quoted key" '      "evidence": true' "${CH}"
scope_bad "the key in a flow mapping" '    - {path: /x, evidence: true, challenge: 40-ev}'
scope_bad "a top-level evidence key (the chart's values shape)" 'evidence:' '  challenges: {}'
scope_bad "a comment between the two lines" "${EV}" '      # c' "${CH}"
scope_bad "two evidence lines in a row" "${EV}" "${EV}" "${CH}"
scope_bad "challenge: with an underscore" "${EV}" '      challenge: 40_ev'
scope_bad "challenge: with a capital" "${EV}" '      challenge: 40-EV'
scope_bad "challenge: without the two digits" "${EV}" '      challenge: 4-ev'
scope_bad "challenge: at another indentation" "${EV}" '    challenge: 40-ev'
scope_bad "challenge: with a comment" "${EV}" '      challenge: 40-ev # c'
scope_bad "challenge: with a trailing space" "${EV}" '      challenge: 40-ev '

# The refusals a deploy makes of what the reader returns (no kubectl / helm call).
case_scope_malformed() {
  good_setup
  printf 'plant:\n  mounts:\n    - path: /x\n%s\n      path: /y\n' "${EV}" > "${CDIR}/values-all.yaml"
  set_evflags
  check_reject "a scope file with an evidence entry the reader cannot read" 1 'not in the form gen-values.sh writes' "${EVFLAGS[@]}"
}
case_scope_flow_form() {
  good_setup
  printf 'plant:\n  mounts:\n    - {path: /x, evidence: true, challenge: 40-ev}\n' > "${CDIR}/values-all.yaml"
  set_evflags
  check_reject "an evidence mount written as a flow mapping is not read as 'no investigate challenge'" 1 'not in the form gen-values.sh writes' "${EVFLAGS[@]}"
}
case_scope_duplicate() {
  good_setup
  write_values 40-ev 40-ev
  set_evflags
  check_reject "the same investigate challenge twice in the values" 1 'is listed twice' "${EVFLAGS[@]}"
}
case_scope_long_id() {
  good_setup
  write_values "40-$(printf '%061d' 0)"
  set_evflags
  check_reject "an investigate challenge id of 64 characters (outside the id grammar)" 1 'is not a challenge id' "${EVFLAGS[@]}"
}
case_scope_malformed
case_scope_flow_form
case_scope_duplicate
case_scope_long_id

# --- the golden digests file, and the lockdown order (A5c-1 review R4#2, R2#2) -------------------
echo "==> the golden digests file is read by deploy-user.sh; the lockdown lookup stays behind the checks"
# internal/edition/testdata/digests-golden/digests.tsv is WriteDigests' output (a Go test holds
# the bytes). Its digests are placeholders, so a deploy cannot accept it; what it must do is get
# PAST the shape checks (header, columns, seat / cid / digest grammars, both rows of user1) and
# stop only at the comparison with the bundle.
case_golden() {
  good_setup
  cp "${REPO_ROOT}/internal/edition/testdata/digests-golden/digests.tsv" "${DG}"
  set_evflags
  check_reject "the golden digests file passes every shape check and stops at the digest" 1 'is not the row of the digests file' "${EVFLAGS[@]}"
}
case_golden
case_lockdown_digest() {
  good_setup
  m_content
  set_evflags
  check_reject "--egress-lockdown, a digest mismatch: not one kubectl call (the ClusterIP lookup is behind the checks)" 1 'is not the row of the digests file' --egress-lockdown --api-server-cidr 10.0.0.1/32 "${EVFLAGS[@]}"
}
case_lockdown_one_arg() {
  good_setup
  check_reject "--egress-lockdown, --evidence-dir alone: not one kubectl call" 2 'go together' --egress-lockdown --api-server-cidr 10.0.0.1/32 --evidence-dir "${EVD}"
}
case_lockdown_digest
case_lockdown_one_arg

# --- V65 / V66: the practice edition's path (A5c-2) ------------------------------------------
# None of --flags-file / --evidence-dir / --evidence-digests, investigate challenges in scope:
# each challenge's <cid>/edition/practice/ of the challenges dir is the bundle (evidence/) and
# its digests file (digests.tsv: run id all zeros, seat *). 01-demo is the golden fixture's
# edition as committed (internal/edition/testdata/render-golden/01-demo/edition: a Go test holds
# it to the renderer, V67, and reads its digests file with ParsePracticeDigests); 41-ev is built
# here, with names whose byte order (LC_ALL=C) is not the order of an English locale, and its
# digests by the library. Both trees are temporary and flat (no seat-shaped path is tracked).
echo "==> V65: the practice edition's path (none of the three arguments), the golden tree"
GOLDEN_EDITION="${REPO_ROOT}/internal/edition/testdata/render-golden/01-demo/edition"
PHEADER='# falco-ctf evidence-digests v1 run=00000000000000000000000000000000'
# names of 41-ev's practice bundle, in the order deploy-user.sh must give them (byte order)
PRACTICE_41_NAMES='a-b a.b a0 a_b x'
# write_practice_digests <cid> [header] [seat]: the practice digests file of <cid>, one row
write_practice_digests() {
  local p="${CDIR}/$1/edition/practice"
  {
    printf '%s\n' "${2:-${PHEADER}}"
    printf '%s\t%s\t%s\n' "${3:-*}" "$1" "$(evidence_bundle_digest "${p}/evidence")"
  } > "${p}/digests.tsv"
}
practice_setup() {
  local p n
  rm -rf "${CDIR}" "${SDIR}" "${EVD}"
  mkdir -p "${CDIR}/03-fx" "${CDIR}/01-demo" "${SDIR}"
  printf 'challengeId: 03-fx\ntype: evade\nexpectedFlag: FALCO{dev-fx-default}\n' > "${CDIR}/03-fx/falco-rule.yaml"
  printf 'flags:\n  03-fx: FALCO{dev-fx-rotated}\n' > "${FLAGS}"
  write_values 01-demo 41-ev
  cp -R "${GOLDEN_EDITION}" "${CDIR}/01-demo/edition"
  p="${CDIR}/41-ev/edition/practice"
  mkdir -p "${p}/evidence"
  for n in x a_b a0 a.b a-b; do printf 'SENTINEL-PRA %s\n' "${n}" > "${p}/evidence/${n}"; done
  printf 'SENTINEL-ANS\n' > "${p}/answers.tsv"
  write_practice_digests 41-ev
}
case_practice_accept() {
  local cdir ev01 ev41 create01 create41 l_ns l_del l_c01 l_c41 l_helm helm_line s n i tok name path ok
  practice_setup
  run_deploy
  ct_check_reached_upgrade "practice accept" || { RC=1; return 0; }
  cdir="$(cd "${CDIR}" && pwd)"
  ev01="${cdir}/01-demo/edition/practice/evidence"
  ev41="${cdir}/41-ev/edition/practice/evidence"
  create01="kubectl -n ctf-user1 create secret generic ctf-evidence-01-demo --from-file=a.txt=${ev01}/a.txt --from-file=b.txt=${ev01}/b.txt"
  create41="kubectl -n ctf-user1 create secret generic ctf-evidence-41-ev"
  for n in ${PRACTICE_41_NAMES}; do create41="${create41} --from-file=${n}=${ev41}/${n}"; done
  l_c01="$(line_no "${create01}")"
  l_c41="$(line_no "${create41}")"
  l_del="$(line_no 'kubectl -n ctf-user1 delete secret -l app.kubernetes.io/managed-by=deploy-user,falco-ctf/evidence-of,falco-ctf/evidence-of notin (01-demo,41-ev)')"
  l_ns="$(line_no 'kubectl create namespace ctf-user1 --dry-run=client -o yaml')"
  l_helm="$(grep -n '^helm upgrade ' "${CT_CALLS}" | head -n 1 | cut -d: -f1)"
  if [[ "${l_c01}" -eq 0 || "${l_c41}" -eq 0 ]]; then
    fail "practice accept: the Secrets are not made from practice/evidence/ by name, in byte order: $(grep -F 'create secret' "${CT_CALLS}" | cut -c1-300)"; return 0
  fi
  if ! [[ "${l_ns}" -gt 0 && "${l_ns}" -lt "${l_del}" && "${l_del}" -lt "${l_c01}" && "${l_c01}" -lt "${l_c41}" && "${l_c41}" -lt "${l_helm}" ]]; then
    fail "practice accept: the order is not namespace (${l_ns}) < delete by label (${l_del}) < create 01 (${l_c01}) < create 41 (${l_c41}) < helm (${l_helm})"; return 0
  fi
  # every --from-file is <name>=<a practice evidence/ dir>/<name>, and there are 2 + 5 of them
  grep -oE -- '--from-file=[^ ]*' "${CT_CALLS}" > "${WORK}/from-file" || true
  n=0
  while IFS= read -r tok; do
    n=$((n + 1))
    tok="${tok#--from-file=}"
    name="${tok%%=*}"
    path="${tok#*=}"
    ok=0
    if [[ "${path}" == "${ev01}/${name}" || "${path}" == "${ev41}/${name}" ]]; then ok=1; fi
    if [[ "${ok}" -ne 1 ]]; then fail "practice accept: a --from-file outside practice/evidence/ or not by its own name: ${tok}"; return 0; fi
  done < "${WORK}/from-file"
  if [[ "${n}" -ne 7 ]]; then fail "practice accept: ${n} --from-file arguments, want 7 (the files of the two evidence/ dirs)"; return 0; fi
  # neither answers.tsv nor digests.tsv reaches a call (a --from-file or a name)
  if grep -qE 'answers\.tsv|digests\.tsv' "${CT_CALLS}"; then
    fail "practice accept: answers.tsv or digests.tsv reached a kubectl / helm call: $(grep -E 'answers\.tsv|digests\.tsv' "${CT_CALLS}" | cut -c1-200)"; return 0
  fi
  helm_line="$(grep '^helm upgrade ' "${CT_CALLS}" | head -n 1)"
  for s in ' --set-string evidence.challenges.01-demo.names[0]=a.txt ' ' --set-string evidence.challenges.01-demo.names[1]=b.txt '; do
    case "${helm_line}" in *"${s}"*) ;; *) fail "practice accept: helm upgrade lacks '${s}'"; return 0 ;; esac
  done
  i=0
  for name in ${PRACTICE_41_NAMES}; do
    s=" --set-string evidence.challenges.41-ev.names[${i}]=${name} "
    case "${helm_line}" in *"${s}"*) ;; *) fail "practice accept: helm upgrade lacks '${s}' (the names in byte order)"; return 0 ;; esac
    i=$((i + 1))
  done
  for s in 'evidence.challenges.01-demo.names[2]=' 'evidence.challenges.41-ev.names[5]=' 'challenge.flags.'; do
    case "${helm_line}" in *"${s}"*) fail "practice accept: helm upgrade has '${s}'"; return 0 ;; esac
  done
  n="$(grep -c 'SENTINEL' "${CT_CALLS}" "${CT_RUN_OUT}" "${CT_RUN_ERR}" | cut -d: -f2 | tr -d '\n' || true)"
  if [[ "${n}" != "000" ]]; then fail "practice accept: a bundle's or answers.tsv's content reached a call or an output (${n})"; return 0; fi
  n="$(grep -c 'deploying the practice edition of 01-demo 41-ev' "${CT_RUN_ERR}" || true)"
  if [[ "${n}" != "1" ]]; then fail "practice accept: stderr says the practice path was taken ${n} times, want once"; return 0; fi
  pass "practice accept: ctf-evidence-<cid> from practice/evidence/ only (golden 01-demo and a built 41-ev), names in byte order, no answers.tsv / digests.tsv / content in any call, one stderr line (V65)"
}
case_practice_accept

echo "==> V66: the practice edition's path is fail-closed (exit 1, no kubectl / helm call)"
# practice_reject_with <label> <marker> <mutation function>
practice_reject_with() {
  local label="$1" marker="$2" mut="$3"
  practice_setup
  "${mut}"
  check_reject "practice: ${label}" 1 "${marker}"
}
P41="${CDIR}/41-ev/edition/practice"
pm_byte() { printf '\001' | dd of="${CDIR}/01-demo/edition/practice/evidence/a.txt" bs=1 seek=0 conv=notrunc 2>/dev/null; }
pm_append() { printf 'x' >> "${P41}/evidence/x"; }
pm_rename() { mv "${P41}/evidence/x" "${P41}/evidence/y"; }
pm_run_event() { write_practice_digests 41-ev "# falco-ctf evidence-digests v1 run=${RUN_ID}"; }
pm_run_one() { write_practice_digests 41-ev "# falco-ctf evidence-digests v1 run=$(printf '%031d' 0)1"; }
pm_header_v2() { write_practice_digests 41-ev '# falco-ctf evidence-digests v2 run=00000000000000000000000000000000'; }
pm_seat_user() { write_practice_digests 41-ev "" user1; }
pm_seat_two_stars() { write_practice_digests 41-ev "" '**'; }
pm_other_cid() { sed "s/${TAB}41-ev${TAB}/${TAB}01-demo${TAB}/" "${P41}/digests.tsv" > "${WORK}/d.new"; cat "${WORK}/d.new" > "${P41}/digests.tsv"; }
pm_extra_row() { printf '*\t01-demo\t%s\n' "$(printf '%064d' 0)" >> "${P41}/digests.tsv"; }
pm_dup_row() { sed -n '2p' "${P41}/digests.tsv" > "${WORK}/d.new"; cat "${WORK}/d.new" >> "${P41}/digests.tsv"; }
pm_header_only() { printf '%s\n' "${PHEADER}" > "${P41}/digests.tsv"; }
pm_no_lf() { printf '%s\n*\t41-ev\t%s' "${PHEADER}" "$(evidence_bundle_digest "${P41}/evidence")" > "${P41}/digests.tsv"; }
pm_no_practice() { rm -rf "${P41}"; }
pm_no_edition() { rm -rf "${CDIR}/41-ev/edition"; }
pm_no_cid_dir() { rm -rf "${CDIR}/41-ev"; }
pm_no_evidence() { rm -rf "${P41}/evidence"; }
pm_no_digests() { rm -f "${P41}/digests.tsv"; }
pm_digests_dir() { rm -f "${P41}/digests.tsv"; mkdir "${P41}/digests.tsv"; }
pm_digests_link() { mv "${P41}/digests.tsv" "${WORK}/elsewhere.tsv"; ln -s "${WORK}/elsewhere.tsv" "${P41}/digests.tsv"; }
pm_practice_link() { rm -rf "${WORK}/elsewhere"; mv "${P41}" "${WORK}/elsewhere"; ln -s "${WORK}/elsewhere" "${P41}"; }
pm_evidence_link() { rm -rf "${WORK}/elsewhere"; mv "${P41}/evidence" "${WORK}/elsewhere"; ln -s "${WORK}/elsewhere" "${P41}/evidence"; }
pm_edition_link() { rm -rf "${WORK}/elsewhere"; mv "${CDIR}/41-ev/edition" "${WORK}/elsewhere"; ln -s "${WORK}/elsewhere" "${CDIR}/41-ev/edition"; }
pm_file_link() { ln -s x "${P41}/evidence/l"; }
pm_subdir() { mkdir "${P41}/evidence/sub"; }
pm_upper_name() { : > "${P41}/evidence/Upper"; }
pm_dot_name() { : > "${P41}/evidence/.hid"; }
pm_space_name() { : > "${P41}/evidence/a b"; }
pm_65() { local i; rm -f "${P41}/evidence"/*; for i in $(seq 1 65); do : > "${P41}/evidence/f${i}"; done; write_practice_digests 41-ev; }
pm_file_over() { rm -f "${P41}/evidence"/*; mkbytes "${P41}/evidence/big" 524289; write_practice_digests 41-ev; }
pm_empty_bundle() { rm -f "${P41}/evidence"/*; write_practice_digests 41-ev; }
practice_reject_with "a byte of the golden evidence/ changed: the digest is not the row (V66)" 'is not the row of the practice digests file of 01-demo' pm_byte
practice_reject_with "a byte appended to a file of evidence/" 'is not the row of the practice digests file of 41-ev' pm_append
practice_reject_with "a renamed file of evidence/ (the name is in the digest)" 'is not the row of the practice digests file of 41-ev' pm_rename
practice_reject_with "digests.tsv with an event run id (V66)" 'the run id is not all zeros' pm_run_event
practice_reject_with "digests.tsv with 31 zeros and a one" 'the run id is not all zeros' pm_run_one
practice_reject_with "digests.tsv header v2" 'line 1 is not the v1 header' pm_header_v2
practice_reject_with "digests.tsv with a seat of the seat grammar" 'the seat is not *' pm_seat_user
practice_reject_with "digests.tsv with the seat **" 'the seat is not *' pm_seat_two_stars
practice_reject_with "digests.tsv whose row is another challenge's" 'which is not the challenge of this practice edition' pm_other_cid
practice_reject_with "digests.tsv with a second row for another challenge" 'which is not the challenge of this practice edition' pm_extra_row
practice_reject_with "digests.tsv with its row twice" 'has a second row' pm_dup_row
practice_reject_with "digests.tsv with a header and no row" 'empty or has no row' pm_header_only
practice_reject_with "digests.tsv with no final newline" 'does not end with a newline' pm_no_lf
practice_reject_with "no practice/ (V66)" 'has no practice edition' pm_no_practice
practice_reject_with "no edition/" 'has no practice edition' pm_no_edition
practice_reject_with "no <cid>/ in the challenges dir" 'has no practice edition' pm_no_cid_dir
practice_reject_with "no practice/evidence/" 'has no practice edition' pm_no_evidence
practice_reject_with "no digests.tsv" 'has no digests file' pm_no_digests
practice_reject_with "digests.tsv is a directory" 'has no digests file' pm_digests_dir
practice_reject_with "digests.tsv is a link" 'has no digests file' pm_digests_link
practice_reject_with "practice/ is a link" 'is a link' pm_practice_link
practice_reject_with "practice/evidence/ is a link" 'is a link' pm_evidence_link
practice_reject_with "edition/ is a link" 'is a link' pm_edition_link
practice_reject_with "a link in evidence/ (V66)" 'is not a regular file' pm_file_link
practice_reject_with "a directory in evidence/" 'is not a regular file' pm_subdir
practice_reject_with "a name with a capital in evidence/ (outside B2, V66)" 'outside ^[a-z0-9]' pm_upper_name
practice_reject_with "a name starting with a dot in evidence/" 'outside ^[a-z0-9]' pm_dot_name
practice_reject_with "a name with a space in evidence/" 'outside ^[a-z0-9]' pm_space_name
practice_reject_with "65 files in evidence/" 'at most 64 files' pm_65
practice_reject_with "a file of 512 KiB + 1 byte in evidence/" 'larger than 524288 bytes' pm_file_over
practice_reject_with "an empty evidence/" 'holds no file' pm_empty_bundle

echo "==> V66: some of the three arguments with a practice tree in scope: the practice path is not taken"
case_practice_partial() {
  practice_setup
  check_reject "practice tree, --flags-file only (V66: not the practice path)" 2 'both are required' --flags-file "${FLAGS}"
  practice_setup
  check_reject "practice tree, --evidence-dir only" 2 'go together' --evidence-dir "${P41}/evidence"
  practice_setup
  check_reject "practice tree, --evidence-digests only (the practice digests file itself)" 2 'go together' --evidence-digests "${P41}/digests.tsv"
  if grep -q 'deploying the practice edition' "${CT_RUN_ERR}"; then fail "practice tree, one argument: stderr says the practice path was taken"; fi
}
case_practice_partial

echo "==> V66: an event's digests file of the practice edition's shape is refused"
case_event_practice_digests() {
  good_setup
  cp "${GOLDEN_EDITION}/practice/digests.tsv" "${DG}"
  set_evflags
  check_reject "event: the golden practice digests.tsv as --evidence-digests (run id all zeros, V66)" 1 'the run id is all zeros' "${EVFLAGS[@]}"
}
m_star_rows() { sed "s/^user1${TAB}/*${TAB}/" "${DG}" > "${DG}.new"; cat "${DG}.new" > "${DG}"; }
m_star_extra() { printf '*\t40-ev\t%s\n' "$(printf '%064d' 0)" >> "${DG}"; }
case_event_practice_digests
reject_with "event: every row of the seat * (V66)" 'the seat is outside the seat grammar' m_star_rows
reject_with "event: the rows of user1 and one row of the seat *" 'line 4: the seat is outside the seat grammar' m_star_extra

# --- A5e (ADR-0056 V94): what deploy-user.sh gives the assert ------------------------------
echo "==> A5e (V94): the assert is given helm's -f and the chart's names (helm upgrade let through)"
# Everything above stops at `helm upgrade` (the stub exits 97), so deploy-user.sh's call of
# the assert is never reached there. Here, and only here: (1) the stub helm lets `upgrade`
# through (CT_HELM_UPGRADE_PASS=1, exported around one ct_run); (2) deploy-user.sh runs
# from a scratch copy of its directory (the directory of ${DEPLOY}: the real one, or a
# mutant's below) whose assert-flag-isolation.sh only records its argv. The real assert
# is neither run nor replaced; after this block a deploy stops at 97 again (checked).
A5E_ARGV="${WORK}/a5e-argv"
A5E_DEPLOY=""
a5e_tree() {
  local src root="${WORK}/a5e-tree"
  src="$(cd "$(dirname "${DEPLOY}")" && pwd)"
  rm -rf "${root}"
  mkdir -p "${root}/charts/ctf-user"
  cp -p "${src}"/*.sh "${src}/values.yaml" "${root}/charts/ctf-user/"
  # the recorder: line 1 says whether `helm upgrade` was already called, then one line per argument
  cat > "${root}/charts/ctf-user/assert-flag-isolation.sh" <<'REC'
#!/usr/bin/env bash
if grep -q '^helm upgrade ' "${CALLS_LOG}"; then echo after-helm=yes; else echo after-helm=no; fi > "${A5E_ARGV}"
for a in "$@"; do printf '%s\n' "${a}"; done >> "${A5E_ARGV}"
exit 0
REC
  chmod +x "${root}/charts/ctf-user/assert-flag-isolation.sh"
  A5E_DEPLOY="${root}/charts/ctf-user/deploy-user.sh"
}
# a5e_run <challenge-id> [deploy flags...]
a5e_run() {
  local cid="$1"
  shift
  rm -f "${A5E_ARGV}"
  export A5E_ARGV
  export CT_HELM_UPGRADE_PASS=1
  ct_run "${A5E_DEPLOY}" --challenges-dir "${CDIR}" --scenarios-dir "${SDIR}" ${1+"$@"} -- user1 "${cid}"
  unset CT_HELM_UPGRADE_PASS
}
# a5e_check <label>: deploy-user.sh exited 0; the assert was called once helm upgrade had
# been; its 5th argument is the file after helm's -f (- when helm got none); its
# <cid>/<name> arguments are, as a set, helm's evidence.challenges.<cid>.names[<i>] values
a5e_check() {
  local label="$1" helm_line want_vf tok c want_names="" got_names="" l i
  local -a av=()
  if [[ "${RUN_STATUS}" -ne 0 ]]; then
    fail "${label}: deploy-user.sh exited ${RUN_STATUS}: $(tr '\n' ' ' < "${CT_RUN_ERR}" | cut -c1-200)"; return 0
  fi
  helm_line="$(grep '^helm upgrade ' "${CT_CALLS}" | head -n 1 || true)"
  if [[ -z "${helm_line}" ]]; then fail "${label}: no helm upgrade was recorded"; return 0; fi
  if [[ ! -f "${A5E_ARGV}" ]]; then fail "${label}: the assert was not called"; return 0; fi
  while IFS= read -r l; do av+=("${l}"); done < "${A5E_ARGV}"
  if [[ "${av[0]:-}" != after-helm=yes ]]; then fail "${label}: the assert was called before helm upgrade (${av[0]:-})"; return 0; fi
  if [[ "${#av[@]}" -lt 6 ]]; then fail "${label}: the assert was given $(( ${#av[@]} - 1 )) arguments, want at least 5"; return 0; fi
  case "${helm_line}" in
    *" -f "*) want_vf="${helm_line#* -f }"; want_vf="${want_vf%% *}" ;;
    *) want_vf=- ;;
  esac
  if [[ "${av[5]}" != "${want_vf}" ]]; then
    fail "${label}: the assert's 5th argument is '${av[5]}', helm upgrade was given -f '${want_vf}'"; return 0
  fi
  set -f
  for tok in ${helm_line}; do
    case "${tok}" in
      evidence.challenges.*.names\[*\]=*)
        c="${tok#evidence.challenges.}"
        c="${c%%.names\[*}"
        want_names="${want_names}${c}/${tok#*=}${CT_LF}"
        ;;
    esac
  done
  set +f
  i=6
  while [[ "${i}" -lt "${#av[@]}" ]]; do
    got_names="${got_names}${av[i]}${CT_LF}"
    i=$((i + 1))
  done
  want_names="$(printf '%s' "${want_names}" | LC_ALL=C sort)"
  got_names="$(printf '%s' "${got_names}" | LC_ALL=C sort)"
  if [[ "${got_names}" != "${want_names}" ]]; then
    fail "${label}: the assert's names [${got_names//${CT_LF}/ }] are not helm's [${want_names//${CT_LF}/ }]"; return 0
  fi
  pass "${label} (values ${want_vf##*/}, names [${got_names//${CT_LF}/ }])"
}
case_a5e_assert_args() {
  a5e_tree
  # all: values-all.yaml, both challenges' names
  good_setup
  set_evflags
  a5e_run all "${EVFLAGS[@]}"
  a5e_check "A5e all: the assert gets helm's values-all.yaml and the names"
  # scenario:<name>: values-scenario-<name>.yaml
  good_setup
  mkdir -p "${SDIR}/sc1"
  printf 'id: sc1\ntitle: sc1\nchallenges:\n  - 40-ev\n  - 41-ev\n' > "${SDIR}/sc1/scenario.yaml"
  cp "${CDIR}/values-all.yaml" "${CDIR}/values-scenario-sc1.yaml"
  set_evflags
  a5e_run scenario:sc1 "${EVFLAGS[@]}"
  a5e_check "A5e scenario: the assert gets helm's values-scenario-sc1.yaml and the names"
  # one challenge with its values.yaml (40-ev alone; values-all.yaml stays a second candidate)
  good_setup
  rm -rf "${EVD}/41-ev"
  write_digests
  mkdir -p "${CDIR}/40-ev"
  write_values 40-ev
  cp "${CDIR}/values-all.yaml" "${CDIR}/40-ev/values.yaml"
  write_values 40-ev 41-ev
  set_evflags
  a5e_run 40-ev "${EVFLAGS[@]}"
  a5e_check "A5e single challenge: the assert gets helm's 40-ev/values.yaml, not values-all.yaml"
  # one challenge with no values.yaml: helm gets no -f, the assert gets -
  good_setup
  mkdir -p "${CDIR}/02-tr"
  printf 'challengeId: 02-tr\ntype: trigger\nexpectedRules: [r]\n' > "${CDIR}/02-tr/falco-rule.yaml"
  a5e_run 02-tr
  a5e_check "A5e single challenge with no values file: the assert gets -"
}
case_a5e_assert_args
# the stub's pass mode did not leak: a deploy stops at helm upgrade (97) again, and the
# real assert is still the real one
good_setup
set_evflags
check_reached "after the A5e block, helm upgrade stops the run again (exit 97)" "${EVFLAGS[@]}"
if [[ -n "${CT_HELM_UPGRADE_PASS+x}" ]] || ! grep -q '^self_check_builtin_only()' "${REPO_ROOT}/charts/ctf-user/assert-flag-isolation.sh"; then
  fail "the A5e block leaked: CT_HELM_UPGRADE_PASS is still set, or the real assert was replaced"
else
  pass "the A5e block left the stub helm and the real assert as they were"
fi

# --- self-test ---------------------------------------------------------------------------
echo "==> self-test: a deploy-user.sh with one guard removed turns its case red"
# mutant <label> <text to replace> <replacement>: sets DEPLOY to the copy (next to the files
# it needs), or fails when the text is not on exactly one line
mutant_deploy() {
  local label="$1" from="$2" to="$3" file="${4:-deploy-user.sh}" l n=0 root="${WORK}/mut-${1}"
  mkdir -p "${root}/charts/ctf-user"
  cp -p "${REPO_ROOT}"/charts/ctf-user/*.sh "${REPO_ROOT}/charts/ctf-user/values.yaml" "${root}/charts/ctf-user/"
  while IFS= read -r l; do
    case "${l}" in
      *"${from}"*) printf '%s%s%s\n' "${l%%"${from}"*}" "${to}" "${l#*"${from}"}"; n=$((n + 1)) ;;
      *) printf '%s\n' "${l}" ;;
    esac
  done < "${REPO_ROOT}/charts/ctf-user/${file}" > "${root}/charts/ctf-user/${file}.new"
  if [[ "${n}" -ne 1 ]]; then
    fail "mutant ${label}: '${from}' is on ${n} lines of ${file}, want exactly 1"
    return 1
  fi
  cat "${root}/charts/ctf-user/${file}.new" > "${root}/charts/ctf-user/${file}"
  rm -f "${root}/charts/ctf-user/${file}.new"
  MUTANT="${root}/charts/ctf-user/deploy-user.sh"
}
# go_red <label> <case function>: with DEPLOY = the mutant, the case reports a failure
go_red() {
  local label="$1" fn="$2" save="${RC}" got real="${DEPLOY}"
  DEPLOY="${MUTANT}"
  RC=0
  "${fn}" > /dev/null 2>&1
  got="${RC}"
  RC="${save}"
  DEPLOY="${real}"
  if [[ "${got}" -ne 0 ]]; then pass "mutant ${label}: ${fn} goes red"; else fail "mutant ${label}: ${fn} stayed green"; fi
}
case_file_over() { reject_with "x" 'larger than' m_file_over; }
case_65() { reject_with "x" 'at most' m_65; }
case_content() { reject_with "x" 'is not the row' m_content; }
if mutant_deploy bytes "EVIDENCE_MAX_BUNDLE_BYTES='524288'" "EVIDENCE_MAX_BUNDLE_BYTES='524289'"; then go_red bytes case_file_over; fi
if mutant_deploy files "EVIDENCE_MAX_FILES='64'" "EVIDENCE_MAX_FILES='65'"; then go_red files case_65; fi
if mutant_deploy digest '[[ "${got}" == "${want}" ]] ||' 'true ||'; then go_red digest case_content; fi
if mutant_deploy stale 'delete secret -l "${EVIDENCE_SELECTOR}"' 'get secret -l "${EVIDENCE_SELECTOR}"'; then go_red stale case_accept; fi
if mutant_deploy scope-key '/evidence["\047[:space:]]*:/ {' '/^ *evidence:/ {' evidence-bundle.sh; then go_red scope-key case_scope_flow_form; fi
if mutant_deploy early-lookup 'API_SERVER_CLUSTER_IP=""' 'API_SERVER_CLUSTER_IP=""; kubectl get svc kubernetes -n default > /dev/null' ; then go_red early-lookup case_lockdown_digest; fi
if mutant_deploy label-cleanup 'if kubectl -n "${NS}" delete secret "ctf-evidence-${cid}" --ignore-not-found >/dev/null; then' 'if true; then'; then go_red label-cleanup case_label_fails; fi
if mutant_deploy apply 'create secret generic "ctf-evidence-${cid}" "${FROM_FILE_ARGS[@]}"' 'create secret generic "ctf-evidence-${cid}" --from-file="${EVIDENCE_DIR}/${cid}"'; then go_red dir-argument case_accept; fi
# the practice path (A5c-2): each of its own guards, removed, turns its case red
case_practice_run() { practice_reject_with "x" 'not all zeros' pm_run_event; }
case_practice_seat() { practice_reject_with "x" 'the seat is not' pm_seat_user; }
case_practice_link() { practice_reject_with "x" 'is a link' pm_practice_link; }
case_practice_byte() { practice_reject_with "x" 'is not the row' pm_byte; }
if mutant_deploy practice-run 'if [[ "${line}" != "${EVIDENCE_DIGESTS_PREFIX}${EVIDENCE_PRACTICE_RUN_ID}" ]]; then' 'if false; then'; then go_red practice-run case_practice_run; fi
if mutant_deploy practice-seat '[[ "${seat}" == "${EVIDENCE_PRACTICE_SEAT}" ]] ||' 'true ||'; then go_red practice-seat case_practice_seat; fi
if mutant_deploy practice-link 'if [[ -L "$2" ]]; then' 'if false; then'; then go_red practice-link case_practice_link; fi
if mutant_deploy practice-bundle-dir 'EVIDENCE_BUNDLE_DIRS+=("${root}/${EVIDENCE_PRACTICE_EVIDENCE_DIR}")' 'EVIDENCE_BUNDLE_DIRS+=("${root}")'; then go_red practice-bundle-dir case_practice_accept; fi
if mutant_deploy practice-digest '[[ "${got}" == "${want}" ]] ||' 'true ||'; then go_red practice-digest case_practice_byte; fi
# A5e (V94): the assert's call removed, its 5th argument another file, its names from
# another spelling than helm's: each turns the behaviour case red
if mutant_deploy a5e-no-assert '"${CHART_DIR}/assert-flag-isolation.sh" "${NS}"' ': "${NS}"'; then go_red a5e-no-assert case_a5e_assert_args; fi
if mutant_deploy a5e-other-values '"${SCOPE_VALUES_FILE:--}"' '"${CHALLENGES_DIR}/values-all.yaml"'; then go_red a5e-other-values case_a5e_assert_args; fi
if mutant_deploy a5e-other-names 'ASSERT_NAME_ARGS+=("${cid}/${name}")' 'ASSERT_NAME_ARGS+=("${cid}/x${name}")'; then go_red a5e-other-names case_a5e_assert_args; fi

ct_finish "deploy-user evidence check"
