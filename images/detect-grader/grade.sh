#!/usr/bin/env sh
# detect-grader entrypoint — capture-replay grading for `type: detect` challenges.
#
# Contract (design §3.1/§3.2, mirrors internal/scoreboard/detect/localexec.go):
#   IN  (env, operator-controlled only):
#     CHALLENGE_ID   — selects the baked capture pair /opt/grader/captures/<id>/{evasion,benign}.scap
#     CONDITION_FILE — path to the UNTRUSTED participant condition, delivered as a
#                      read-only file mount (never argv/env). Default /input/condition.
#   OUT:
#     - stdout: one JSON line {"evasionFires":N,"benignFires":M,"invalid":BOOL}
#     - /dev/termination-log: the same JSON (kubelet surfaces it as the pod's
#       terminationMessage; the scoreboard reads it for UI feedback ONLY).
#     - EXIT CODE is the verdict authority the scoreboard trusts (Job Succeeded):
#         0  = PASS  (evasionFires>0 AND benignFires==0)  → Job Succeeded → solve
#         !0 = FAIL  (invalid condition, missed evasion, false positive, or infra)
#              → Job not Succeeded → the scoreboard maps to invalid/no-solve
#              (fail-closed). The scoreboard NEVER trusts the counts for the verdict.
#
# Safety: the participant controls ONLY the condition body. name/output/priority
# and the curated macro vocabulary are fixed here. `falco -V` is the compile gate
# BEFORE any replay — Falco's condition grammar is a closed expression language
# with no shell/OS access, so a malformed/"injection" condition is merely a
# compile error (invalid), never executed. Replay is driverless (engine.kind:
# replay) so this container runs with NO privilege / NO kernel driver.

set -eu

RULE_NAME="${RULE_NAME:-participant_detect}"
CONDITION_FILE="${CONDITION_FILE:-/input/condition}"
CAPTURE_DIR="/opt/grader/captures/${CHALLENGE_ID:-}"
WORK="$(mktemp -d)"
TERM_LOG="/dev/termination-log"

# emit writes the result JSON to stdout and (best-effort) the termination log,
# then exits with the given code. Counts are feedback-only; the exit code is the
# verdict.
emit() {
  _ef="$1"; _bf="$2"; _invalid="$3"; _code="$4"
  _json="{\"evasionFires\":${_ef},\"benignFires\":${_bf},\"invalid\":${_invalid}}"
  printf '%s\n' "$_json"
  # /dev/termination-log is provided writable by kubelet even with a read-only
  # rootfs; under a plain `docker run` it may be absent/unwritable — write only
  # when we can create it, so the shell never emits a redirect error.
  if ( : > "$TERM_LOG" ) 2>/dev/null; then
    printf '%s' "$_json" > "$TERM_LOG" 2>/dev/null || true
  fi
  rm -rf "$WORK" 2>/dev/null || true
  exit "$_code"
}

# --- guards ------------------------------------------------------------------
[ -n "${CHALLENGE_ID:-}" ]     || emit 0 0 true 3   # no mission selected → invalid
[ -r "$CONDITION_FILE" ]       || emit 0 0 true 3   # condition not delivered → invalid
[ -d "$CAPTURE_DIR" ]          || emit 0 0 true 4   # captures missing (44.2 bakes them)
EVASION="${CAPTURE_DIR}/evasion.scap"
BENIGN="${CAPTURE_DIR}/benign.scap"
[ -r "$EVASION" ] && [ -r "$BENIGN" ] || emit 0 0 true 4

# Size-cap the condition (defence-in-depth; the scoreboard also caps at 4 KiB).
_size="$(wc -c < "$CONDITION_FILE" 2>/dev/null || echo 999999)"
[ "$_size" -le 4096 ] || emit 0 0 true 3

# --- assemble the rules file (curated macros + wrapped condition) ------------
# Keep the curated macro vocabulary IDENTICAL to detect.curatedMacros in
# internal/scoreboard/detect/detect.go. If a mission's allowedMacros grows, add
# the macro both here and there (and re-record captures if semantics change).
RULES="${WORK}/participant.yaml"
{
  cat /opt/grader/macros.yaml 2>/dev/null || true
  printf -- '- rule: %s\n' "$RULE_NAME"
  printf '  desc: participant-authored detection (graded by capture replay)\n'
  printf '  condition: >\n'
  # Indent every line of the untrusted condition into a YAML block scalar so
  # newlines/quotes cannot break the document structure. It is still just a
  # Falco condition; `falco -V` is the gate.
  sed 's/^/    /' "$CONDITION_FILE"
  printf '\n'
  # NOTE: Falco's output template has no substitution token for "the firing
  # rule's own name" (confirmed against the official supported-fields
  # reference: no field named `rule` or `evt.rule` exists). RULE_NAME is
  # already known at generation time as a shell variable, so it is emitted
  # as a literal via printf %s (twice) rather than guessed at as a token —
  # the invalid `%rule` token made every `falco -V` compile fail, which is
  # why detect grading was always "invalid" (issue #77).
  printf '  output: "%s rule=%s file=%%fd.name proc=%%proc.name"\n' "$RULE_NAME" "$RULE_NAME"
  printf '  priority: WARNING\n'
} > "$RULES"

# --- 1) compile gate: falco -V (invalid condition → exit non-zero) -----------
if ! falco -V "$RULES" >/dev/null 2>&1; then
  emit 0 0 true 2   # LOAD_ERR_COMPILE_CONDITION etc. → invalid, do NOT replay
fi

# --- replay helper: engine.kind=replay, count fires of the wrapped rule ------
# Prints the fire count on stdout and RETURNS falco's own exit code so the caller
# can distinguish a clean "0 fires" from a post-compile infra failure (corrupt
# capture, OOM, driverless-replay error). We must NOT treat a crashed replay's
# (0) fire count as a verdict — a benign replay that crashes with 0 fires would
# otherwise look like "no false positive" and mis-solve (design §3.3 fail-closed;
# mirrors LocalExec.replay).
replay() {
  _cap="$1"
  _cfg="${WORK}/replay.yaml"
  _out="${WORK}/replay.out"
  {
    printf 'engine:\n  kind: replay\n  replay:\n    capture_file: %s\n' "$_cap"
    printf 'stdout_output:\n  enabled: true\n'
    printf 'json_output: true\njson_include_output_property: true\n'
    printf 'http_output:\n  enabled: false\n'
    printf 'grpc:\n  enabled: false\ngrpc_output:\n  enabled: false\n'
    printf 'load_plugins: []\n'
  } > "$_cfg"
  falco -c "$_cfg" -r "$RULES" > "$_out" 2>/dev/null
  _rc="$?"
  # Count matching alert lines. `grep -c` exits 1 on zero matches (prints "0"),
  # which is a valid "0 fires" — capture the printed count and ignore grep's
  # exit so it does not clobber falco's exit code ($_rc, the infra signal).
  # Tolerate an optional space after the colon (`"rule":"X"` and `"rule": "X"`)
  # so this count stays IDENTICAL to internal/scoreboard/detect countFires
  # regardless of how Falco's JSON encoder spaces the field — otherwise a
  # space-emitting encoder would under-count benign FPs and mis-SOLVE
  # (fail-closed correctness of the k8s grader). ERE `?` is a metacharacter but
  # RULE_NAME is the fixed literal `participant_detect` (no regex metachars).
  _n="$(grep -Ec '"rule": ?"'"${RULE_NAME}"'"' "$_out" 2>/dev/null)" || true
  printf '%s' "${_n:-0}"
  return "$_rc"
}

# --- 2) two driverless replay passes ----------------------------------------
# Disable errexit around replay: grep -c legitimately exits non-zero on 0 fires,
# and we inspect falco's exit code explicitly (fail-closed on a replay crash).
set +e
EF="$(replay "$EVASION")"; EF_RC="$?"
[ "$EF_RC" -eq 0 ] || emit 0 0 false 5      # evasion replay infra failure → fail-closed
BF="$(replay "$BENIGN")"; BF_RC="$?"
[ "$BF_RC" -eq 0 ] || emit "$EF" 0 false 5  # benign replay infra failure → fail-closed
set -e

# Guard against a non-numeric count (defensive; grep -c always prints a number).
case "$EF" in ''|*[!0-9]*) EF=0 ;; esac
case "$BF" in ''|*[!0-9]*) BF=0 ;; esac

# --- verdict: pass = fires on evasion AND zero false positives on benign -----
if [ "$EF" -gt 0 ] && [ "$BF" -eq 0 ]; then
  emit "$EF" "$BF" false 0   # PASS → Job Succeeded → solve
fi
emit "$EF" "$BF" false 1     # missed evasion or false positive → no solve
