# shellcheck shell=bash
# The deploy-user.sh HARNESS layer (app#509, app#519 review-5x R4#1): stub `helm` /
# `kubectl` on a PATH dir that record their calls, a runner, and the verdicts every
# deploy-user.sh grammar check shares. Sourced, never executed (mode 100644), AFTER
# scripts/lib/casetable.sh (the reader layer: it needs its WORK dir, CT_BIDI and
# `ct_init`). A check that does not run deploy-user.sh (the chart's regexMatch,
# gen-values.sh) sources the reader layer only.
#
# Users: scripts/check-seat-grammar.sh, scripts/check-deploy-user-ids.sh and
# scripts/check-flags-file-validation.sh (part B, app#521). Any other script that stubs
# helm / kubectl to record calls and tells `helm upgrade` by exit 97 is a copy of this
# file and belongs here. scripts/check-missions-allowlist-assert.sh's kubectl stub is not
# one: it runs the probe `kubectl exec` carries against a fake root (no call log, no
# helm, no CT_UPGRADE_EXIT), so there is nothing to share.
# Self-test: scripts/test-deploy-user-harness.sh (touches no docker or
# helm: the stubs are the point).
#
# Not a contract: this file's path and names are app-internal, like the reader's.
#
# API:
#   ct_init_stubs                    after ct_init: the stubs, CT_STUB_BIN, CT_CALLS,
#                                    CT_RUN_OUT, CT_RUN_ERR
#   ct_run <cmd...>                  run it with the stubs first on PATH and CALLS_LOG set,
#                                    stdin /dev/null; -> RUN_STATUS, CT_RUN_OUT, CT_RUN_ERR
#                                    (the files), CT_CALLS truncated first; `set -e` is left
#                                    as it was found
#   ct_upgrade_call                  prints the first recorded `helm upgrade ...` line
#   ct_check_reached_upgrade <where> the run exited CT_UPGRADE_EXIT (the stub's `helm upgrade`)
#   ct_check_reject <where> <arg as given> <stderr marker>
#                                    exit 2 (1 for an empty arg), NOT ONE helm / kubectl call,
#                                    the marker on stderr, no raw bidi control in the output
#   ct_no_bidi_output <where>        rc 1 if a raw U+202E reached CT_RUN_OUT / CT_RUN_ERR
# shellcheck disable=SC2034

[[ "${BASH_SOURCE[0]}" != "$0" ]] || { echo "scripts/lib/deploy-user-harness.sh is sourced, not executed" >&2; exit 2; }
declare -F ct_run_table > /dev/null || { echo "scripts/lib/deploy-user-harness.sh: source scripts/lib/casetable.sh first" >&2; exit 2; }

# The status the stub `helm upgrade` exits with: how an accept row is told apart
# from a script that stopped earlier. (The stub heredoc below spells the number
# itself, so a change to either one alone is red: test-deploy-user-harness.sh.)
CT_UPGRADE_EXIT=97

# --- stub helm / kubectl ----------------------------------------------------
# One printf per call = one write(2) of one whole line: `kubectl create ... | kubectl
# apply` runs two stubs at once, and a line written in pieces could interleave.
ct_write_stubs() {
  cat > "${CT_STUB_BIN}/helm" <<'STUB'
#!/usr/bin/env bash
printf 'helm %s\n' "$*" >> "${CALLS_LOG}"
for a in "$@"; do
  case "${a}" in
    status) exit 1 ;;
    upgrade) exit 97 ;;
  esac
done
exit 0
STUB
  cat > "${CT_STUB_BIN}/kubectl" <<'STUB'
#!/usr/bin/env bash
printf 'kubectl %s\n' "$*" >> "${CALLS_LOG}"
case " $* " in
  *" get svc kubernetes "*) printf '10.96.0.1'; exit 0 ;;
esac
cat >/dev/null 2>&1 < /dev/stdin || true
exit 0
STUB
  chmod +x "${CT_STUB_BIN}/helm" "${CT_STUB_BIN}/kubectl"
}

ct_init_stubs() {
  CT_STUB_BIN="${WORK}/bin"
  CT_CALLS="${WORK}/calls.log"
  CT_RUN_OUT="${WORK}/run.out"
  CT_RUN_ERR="${WORK}/run.err"
  mkdir -p "${CT_STUB_BIN}"
  ct_write_stubs
}

ct_run() {
  local was_e=0
  case $- in *e*) was_e=1 ;; esac
  : > "${CT_CALLS}"
  set +e
  PATH="${CT_STUB_BIN}:${PATH}" CALLS_LOG="${CT_CALLS}" \
    "$@" >"${CT_RUN_OUT}" 2>"${CT_RUN_ERR}" </dev/null
  RUN_STATUS=$?
  [[ "${was_e}" -eq 1 ]] && set -e
  return 0
}

ct_upgrade_call() {
  grep -E '^helm upgrade ' "${CT_CALLS}" | head -n 1 || true
}

# --- the verdicts every deploy-user.sh grammar check shares -----------------
ct_no_bidi_output() {
  if grep -qF -- "${CT_BIDI}" "${CT_RUN_ERR}" "${CT_RUN_OUT}"; then
    echo "    $1: a raw bidi control reached the output" >&2
    return 1
  fi
  return 0
}

ct_check_reached_upgrade() {
  if [[ "${RUN_STATUS}" -ne "${CT_UPGRADE_EXIT}" ]]; then
    echo "    $1: accept, but exit ${RUN_STATUS} (want ${CT_UPGRADE_EXIT} = reached helm upgrade): $(tr '\n' ' ' < "${CT_RUN_ERR}" | cut -c1-200)" >&2
    return 1
  fi
  return 0
}

ct_check_reject() {
  local where="$1" arg="$2" msg="$3" want=2
  [[ -z "${arg}" ]] && want=1
  if [[ "${RUN_STATUS}" -ne "${want}" ]]; then
    echo "    ${where}: reject, but exit ${RUN_STATUS} (want ${want})" >&2
    return 1
  fi
  if [[ -s "${CT_CALLS}" ]]; then
    echo "    ${where}: reject, but helm/kubectl was called: $(cut -d' ' -f1-3 "${CT_CALLS}" | tr '\n' ';' | cut -c1-160)" >&2
    return 1
  fi
  if [[ -n "${arg}" ]] && ! grep -qF "${msg}" "${CT_RUN_ERR}"; then
    echo "    ${where}: reject, but stderr does not carry '${msg}'" >&2
    return 1
  fi
  ct_no_bidi_output "${where}" || return 1
  return 0
}
