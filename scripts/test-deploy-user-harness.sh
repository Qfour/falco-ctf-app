#!/usr/bin/env bash
# Self-test of scripts/lib/deploy-user-harness.sh (app#509): the stub helm / kubectl
# harness the deploy-user.sh grammar checks stand on (the table reader's own
# self-test is scripts/test-casetable-lib.sh). It proves:
#   - the stubs record their calls, `helm upgrade` exits 97 (the number is spelled
#     here too, so changing the stub or the constant alone is red), `helm status`
#     exits 1, `kubectl get svc kubernetes` answers a ClusterIP, a piped kubectl
#     drops its stdin, and the stub is first on PATH
#   - ct_run: status / stdout / stderr, stdin /dev/null, the call log truncated per
#     run, `set -e` left as it was found
#   - the record format: one line "<tool> <argv joined by single spaces>", byte for
#     byte what check-flags-file-validation.sh's own per-argument writer produced
#   - the shared verdicts: reached-upgrade, reject (exit 2 / 1 for an empty arg, no
#     call, the stderr marker), and a raw bidi control in the output
#   - no *.sh outside scripts/lib/ holds a stub copy (static, with a planted copy
#     shown red), and the callers (check-flags-file-validation.sh, check-seat-grammar.sh)
#     go red under a broken stub (app#521)
# Usage: ./scripts/test-deploy-user-harness.sh   (make check-flags; CI flag-guard)
set -euo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
# shellcheck source=lib/casetable.sh
source "${REPO_ROOT}/scripts/lib/casetable.sh"
# shellcheck source=lib/deploy-user-harness.sh
source "${REPO_ROOT}/scripts/lib/deploy-user-harness.sh"
ct_init "${REPO_ROOT}"
ct_init_stubs

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

NL=$'\n'

echo "==> stubs: helm / kubectl record every call, helm upgrade exits 97"
ct_run helm status rel -n ns
t_eq "helm status exits 1 (not installed)" 1 "${RUN_STATUS}"
ct_run helm upgrade --install rel chart -n ns
t_eq "helm upgrade exits 97 (the literal)" 97 "${RUN_STATUS}"
t_eq "helm upgrade exits CT_UPGRADE_EXIT" "${CT_UPGRADE_EXIT}" "${RUN_STATUS}"
t_eq "the call is recorded verbatim, one line" "helm upgrade --install rel chart -n ns" "$(cat "${CT_CALLS}")"
ct_run helm version
t_eq "any other helm call exits 0" 0 "${RUN_STATUS}"
t_eq "ct_run truncates the call log first" "helm version" "$(cat "${CT_CALLS}")"
ct_run kubectl get svc kubernetes -n default -o jsonpath=x
t_eq "kubectl get svc kubernetes answers a ClusterIP" 0 "${RUN_STATUS}"
t_eq "...on stdout" "10.96.0.1" "$(cat "${CT_RUN_OUT}")"
ct_run bash -c 'echo y | kubectl apply -f -; kubectl create namespace n --dry-run=client -o yaml | kubectl apply -f -'
t_eq "kubectl apply reads and drops its stdin" 0 "${RUN_STATUS}"
t_eq "...all three calls are recorded (the two stubs of a pipe run at once: compared sorted)" "kubectl apply -f -${NL}kubectl apply -f -${NL}kubectl create namespace n --dry-run=client -o yaml" "$(sort "${CT_CALLS}")"
ct_run bash -c 'echo out; echo err >&2; exit 3'
t_eq "ct_run reports the command's status" 3 "${RUN_STATUS}"
t_eq "...its stdout" "out" "$(cat "${CT_RUN_OUT}")"
t_eq "...its stderr" "err" "$(cat "${CT_RUN_ERR}")"
ct_run bash -c 'cat; echo "eof"'
t_eq "stdin is /dev/null" "eof" "$(cat "${CT_RUN_OUT}")"
ct_run bash -c 'command -v helm'
t_eq "the stub is first on PATH" "${CT_STUB_BIN}/helm" "$(cat "${CT_RUN_OUT}")"
# The record format is ONE line, "<tool> <argv joined by single spaces>". It is the
# format scripts/check-flags-file-validation.sh's own stub wrote (one printf ' %s' per
# argument): byte for byte the same for any argv of one or more words, an empty,
# spaced, '%s'-carrying or option-like word included, which is why that script moved
# onto this harness without a record-format option (app#521). Pinned against the old
# writer, kept here as the reference.
argv_ref() { printf '%s' "$1"; shift; printf ' %s' "$@"; printf '\n'; }
argv_rec() { # <tool> <argv...>: the line the stub records
  ct_run "$@"
  cat "${CT_CALLS}"
}
for argv_case in \
  'helm|upgrade|--install|r|c|-n|ns|--set-string|challenge.flags.03-stealth-read=FALCO{dev-x}' \
  'helm|upgrade|--set-string|k=a b|--values|-f' \
  'kubectl|get||pods' \
  'kubectl|apply|-f|-|%s|%d|--x=%' \
  'helm|status|*|?|[a]' \
  'helm|-n'; do
  IFS='|' read -r -a argv_words <<< "${argv_case}"
  t_eq "the record of '${argv_case}' is the per-argument writer's, byte for byte" \
    "$(argv_ref "${argv_words[@]}")" "$(argv_rec "${argv_words[@]}")"
done
t_eq "the one difference: no argument at all ('helm ' vs 'helm')" "helm " "$(ct_run helm; cat "${CT_CALLS}")"

ct_run helm upgrade --install a b
ct_run helm upgrade --install c d
t_eq "ct_upgrade_call is the first recorded helm upgrade" "helm upgrade --install c d" "$(ct_upgrade_call)"
ct_run kubectl get pods
t_eq "ct_upgrade_call is empty without one" "" "$(ct_upgrade_call)"
case $- in *e*) t_eq "ct_run leaves set -e as it found it (on)" 0 0 ;; *) t_eq "set -e is on" on off ;; esac
set +e
ct_run true
case $- in *e*) t_eq "ct_run leaves set -e as it found it (off)" off on ;; *) t_eq "ct_run leaves set -e as it found it (off)" 0 0 ;; esac
set -e
t_group "stubs"

echo "==> the shared verdicts"
ct_run bash -c 'exit 97'
t_status "exit 97 = reached helm upgrade" 0 ct_check_reached_upgrade w
ct_run bash -c 'exit 2'
t_status "exit 2 is not 'reached helm upgrade'" 1 ct_check_reached_upgrade w
ct_run bash -c 'echo "invalid thing" >&2; exit 2'
t_status "a reject: exit 2, no calls, the marker" 0 ct_check_reject w "x" "invalid thing"
t_status "...the wrong marker" 1 ct_check_reject w "x" "other"
t_status "...a non-empty arg must not be the usage error" 1 ct_check_reject w "" "invalid thing"
ct_run bash -c 'echo "usage" >&2; exit 1'
t_status "an empty arg is the usage error: exit 1, no marker needed" 0 ct_check_reject w "" "invalid thing"
t_status "...exit 1 for a non-empty arg is wrong" 1 ct_check_reject w "x" "usage"
ct_run bash -c 'echo "invalid thing" >&2; helm version; exit 2'
t_status "a reject that called helm is caught" 1 ct_check_reject w "x" "invalid thing"
ct_run bash -c "echo \"invalid thing \$(printf '\\342\\200\\256')\" >&2; exit 2"
t_status "a reject that echoed a raw bidi control to stderr is caught" 1 ct_check_reject w "x" "invalid thing"
t_status "ct_no_bidi_output catches U+202E on stderr" 1 ct_no_bidi_output w
ct_run bash -c "printf '\\342\\200\\256'"
t_status "...and on stdout" 1 ct_no_bidi_output w
ct_run bash -c "printf '\\342\\200\\255 ok \\303\\274'"
t_status "...but not a neighbouring code point (U+202D) or a plain non-ASCII letter" 0 ct_no_bidi_output w
t_group "verdicts"

echo "==> a stub copy is not allowed outside scripts/lib/ (static)"
# What a stub copy looks like: a `helm upgrade` exit, a write to the call log, a
# `printf 'helm %s'` record. Searched in every *.sh but this harness, this self-test
# (it holds the patterns) and scripts/check-missions-allowlist-assert.sh, whose kubectl
# stub is NOT a copy: it runs the probe `kubectl exec` carries against a fake root (no
# call log, no helm, no exit 97). Named, not pattern-excluded.
T_STUB_RE='upgrade\) *exit|>> *"?\$\{?(CALLS_LOG|CT_CALLS)|printf .(helm|kubectl) %s'
# t_find_stub_copies <root>: prints file:line:text for each hit
t_find_stub_copies() {
  local f
  while IFS= read -r f; do
    case "${f}" in
      ./scripts/lib/* | ./scripts/test-deploy-user-harness.sh | ./scripts/check-missions-allowlist-assert.sh) continue ;;
    esac
    { grep -nE "${T_STUB_RE}" "$1/${f}" || true; } | sed "s|^|${f#./}:|"
  done < <(cd "$1" && find . -name '*.sh' -not -path './.git/*' -not -path './node_modules/*' | sort)
}
t_eq "no *.sh outside scripts/lib/ writes a stub" "" "$(t_find_stub_copies "${REPO_ROOT}")"
# The detector itself: plant the old check-flags-file-validation.sh stub (per-argument
# writer + exit 97) in a scratch tree; it must be listed with file:line, and the same
# text under scripts/lib/ must not be.
PLANT="${WORK}/plant"
mkdir -p "${PLANT}/scripts/lib"
cat > "${PLANT}/scripts/check-planted.sh" <<'PLANTED'
#!/usr/bin/env bash
cat > "${STUB_BIN}/helm" <<'STUB'
printf 'helm' >> "${CALLS_LOG}"
case "${a}" in
    upgrade) exit 97 ;;
STUB
PLANTED
cp "${PLANT}/scripts/check-planted.sh" "${PLANT}/scripts/lib/ok.sh"
FOUND="$(t_find_stub_copies "${PLANT}")"
t_eq "a planted stub copy is listed (file:line), the one under scripts/lib/ is not" \
  "scripts/check-planted.sh:3:printf 'helm' >> \"\${CALLS_LOG}\"${NL}scripts/check-planted.sh:5:    upgrade) exit 97 ;;" "${FOUND}"
echo "    planted -> $(printf '%s' "${FOUND}" | tr '\n' ';' | cut -c1-160)"
t_group "static"

echo "==> a caller stands on the harness's stubs (a broken stub turns it red)"
# scripts/check-flags-file-validation.sh had its own stub copy until app#521; a copy
# would stay green under a broken harness, so these mutants show the callers stand on
# it (the static check above is what stops a copy coming back). check-deploy-user-ids.sh
# is the same by construction and slow (54 s), so it is not re-run here.
# t_replace_once <file> <text to replace> <replacement>: rewrites the ONE line that
# contains the text (line by line, like ct_mutate_line: ${x/"a"/"b"} keeps the quotes
# around the replacement under bash 3.2); rc 1 unless exactly one line matches
t_replace_once() {
  local file="$1" from="$2" to="$3" l n=0
  while IFS= read -r l; do
    case "${l}" in
      *"${from}"*) printf '%s%s%s\n' "${l%%"${from}"*}" "${to}" "${l#*"${from}"}"; n=$((n + 1)) ;;
      *) printf '%s\n' "${l}" ;;
    esac
  done < "${file}" > "${file}.new"
  [[ "${n}" -eq 1 ]] || { rm -f "${file}.new"; return 1; }
  cat "${file}.new" > "${file}"
  rm -f "${file}.new"
}
printf '%s\n' 'a' '  printf '"'"'helm %s\n'"'"' "$*" >> "${CALLS_LOG}"' 'b' > "${WORK}/rep.txt"
t_replace_once "${WORK}/rep.txt" 'printf '"'"'helm %s\n'"'"' "$*"' ': ' || fail "t_replace_once: no single match"
t_eq "t_replace_once: quotes, a backslash and \$* are replaced as written (bash 3.2 = 5)" \
  'a|  :  >> "${CALLS_LOG}"|b' "$(tr '\n' '|' < "${WORK}/rep.txt" | sed 's/|$//')"
# t_caller_red <label> <caller script> <harness text to replace> <replacement> <stderr marker>
t_caller_red() {
  local label="$1" caller="$2" from="$3" to="$4" marker="$5" root="${WORK}/caller-${1}" rc
  mkdir -p "${root}"
  cp -R "${REPO_ROOT}/scripts" "${root}/scripts"
  for d in charts internal challenges scenarios; do ln -s "${REPO_ROOT}/${d}" "${root}/${d}"; done
  if ! t_replace_once "${root}/scripts/lib/deploy-user-harness.sh" "${from}" "${to}"; then
    fail "caller mutant ${label}: '${from}' is not on exactly one line of the harness"
    return 0
  fi
  set +e
  "${root}/scripts/${caller}" >/dev/null 2>"${root}/err"
  rc=$?
  set -e
  T_N=$((T_N + 1))
  if [[ "${rc}" -eq 0 ]]; then
    fail "caller mutant ${label}: ${caller} stayed green"
  elif ! grep -qF -- "${marker}" "${root}/err"; then
    fail "caller mutant ${label}: red, but not for '${marker}': $(tr '\n' ' ' < "${root}/err" | cut -c1-200)"
  else
    echo "    mutant ${label} (${caller}): exit ${rc}, '$(grep -F -- "${marker}" "${root}/err" | head -n 1 | sed 's/^ *//' | cut -c1-110)'"
  fi
}
t_caller_red upgrade-exit check-flags-file-validation.sh 'upgrade) exit 97' 'upgrade) exit 96' 'did not reach helm upgrade'
t_caller_red helm-no-record check-flags-file-validation.sh 'printf '"'"'helm %s\n'"'"' "$*" >> "${CALLS_LOG}"' ': ' "no 'helm upgrade' call was recorded"
# kubectl's record: flags-file never reads a kubectl line, the seat check does (the
# namespace the script creates), and a reject row's "no call" is vacuous without it
t_caller_red kubectl-no-record check-seat-grammar.sh 'printf '"'"'kubectl %s\n'"'"' "$*" >> "${CALLS_LOG}"' ': ' 'the namespace the script creates is not exactly ctf-<seat>'
# ...so the reject verdict itself is checked against a run that DID call kubectl
ct_run bash -c 'echo "invalid thing" >&2; kubectl get pods; exit 2'
t_status "a reject that called kubectl is caught (the stub's record is what makes 'no call' mean something)" 1 ct_check_reject w "x" "invalid thing"
t_group "callers"

ct_finish "deploy-user harness self-test"
