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
#   self-test: copies of deploy-user.sh with ONE guard removed or moved (a limit one too
#              wide, the digest comparison, the label-selector delete) must turn the case
#              that guard is about red, or this check proves nothing.
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
check_reject "neither argument with investigate challenges in scope: the practice-edition deploy is A5c-2's" 2 'practice-edition deploy is implemented in A5c-2'
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

# --- self-test ---------------------------------------------------------------------------
echo "==> self-test: a deploy-user.sh with one guard removed turns its case red"
# mutant <label> <text to replace> <replacement>: sets DEPLOY to the copy (next to the files
# it needs), or fails when the text is not on exactly one line
mutant_deploy() {
  local label="$1" from="$2" to="$3" l n=0 root="${WORK}/mut-${1}"
  mkdir -p "${root}/charts/ctf-user"
  cp -p "${REPO_ROOT}"/charts/ctf-user/*.sh "${REPO_ROOT}/charts/ctf-user/values.yaml" "${root}/charts/ctf-user/"
  while IFS= read -r l; do
    case "${l}" in
      *"${from}"*) printf '%s%s%s\n' "${l%%"${from}"*}" "${to}" "${l#*"${from}"}"; n=$((n + 1)) ;;
      *) printf '%s\n' "${l}" ;;
    esac
  done < "${REPO_ROOT}/charts/ctf-user/deploy-user.sh" > "${root}/charts/ctf-user/deploy-user.sh.new"
  if [[ "${n}" -ne 1 ]]; then
    fail "mutant ${label}: '${from}' is on ${n} lines of deploy-user.sh, want exactly 1"
    return 1
  fi
  cat "${root}/charts/ctf-user/deploy-user.sh.new" > "${root}/charts/ctf-user/deploy-user.sh"
  rm -f "${root}/charts/ctf-user/deploy-user.sh.new"
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
if mutant_deploy label-cleanup 'if kubectl -n "${NS}" delete secret "ctf-evidence-${cid}" --ignore-not-found >/dev/null; then' 'if true; then'; then go_red label-cleanup case_label_fails; fi
if mutant_deploy apply 'create secret generic "ctf-evidence-${cid}" "${FROM_FILE_ARGS[@]}"' 'create secret generic "ctf-evidence-${cid}" --from-file="${EVIDENCE_DIR}/${cid}"'; then go_red dir-argument case_accept; fi

ct_finish "deploy-user evidence check"
