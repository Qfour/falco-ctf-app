#!/usr/bin/env bash
# ADR-0056 V2 (the scoreboard part) and D13: the answers table's Secret is reachable
# from the scoreboard container only. Fail-closed render checks of charts/scoreboard
# with `answersSecret.enabled`, which the chart-lint job's default render never
# exercises (the default is disabled):
#
#   * a SENTINEL secret name and key are rendered; each appears exactly once in the
#     whole output, the name as the Deployment's volume `secretName` and the key in
#     ANSWERS_FILE, and in no other document;
#   * the Secret is mounted once, readOnly, and ANSWERS_FILE is set once;
#   * the default render (disabled) has neither;
#   * the render FAILS, for the stated reason, when the table would be placed outside
#     the event mode (flagsSecret disabled) or where the detect grader lives
#     (env.detectGraderNamespace equal to the scoreboard namespace, either the
#     release namespace or the namespace the Deployment is rendered in), or when the
#     key is not a file name.
#
# Needs helm and the vendored dependency (make helm-dep-build). Exit status: 0 iff
# every check held. A render that fails when it should succeed is a failure, and an
# expected failure that fails for another reason is a failure (fail-closed).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

chart="charts/scoreboard"
sentinel_name="sentinel-answers-secret-zzzz"
sentinel_key="sentinel-answers-key-zzzz.tsv"
rc=0

fail() {
  echo "  FAIL: $*" >&2
  rc=1
}

# count_of TEXT NEEDLE: the number of lines of TEXT that contain NEEDLE.
count_of() {
  local n
  n="$(grep -cF -- "$2" <<<"$1" || true)"
  echo "$n"
}

# kinds_of TEXT NEEDLE: the `kind:` of the document of every line that contains NEEDLE.
kinds_of() {
  awk -v pat="$2" '/^---/ {kind=""} /^kind:/ {kind=$2} index($0, pat) {print kind}' <<<"$1"
}

positive=""
if ! positive="$(helm template "$chart" --namespace scoreboard \
  --set flagsSecret.enabled=true \
  --set answersSecret.enabled=true \
  --set "answersSecret.name=${sentinel_name}" \
  --set "answersSecret.key=${sentinel_key}" \
  --set env.detectGraderNamespace=detect-grader 2>&1)"; then
  echo "FAIL: helm template failed with answersSecret enabled:" >&2
  echo "$positive" >&2
  exit 1
fi

echo "== answersSecret enabled =="
for needle in "$sentinel_name" "$sentinel_key"; do
  n="$(count_of "$positive" "$needle")"
  if [ "$n" -ne 1 ]; then
    fail "the sentinel ${needle} appears on ${n} line(s) of the render, want exactly 1"
  fi
  kinds="$(kinds_of "$positive" "$needle")"
  if [ "$kinds" != "Deployment" ]; then
    fail "the sentinel ${needle} appears in a document of kind '${kinds}', want only Deployment"
  fi
done
if ! grep -qE "^[[:space:]]*secretName:[[:space:]]*${sentinel_name}[[:space:]]*$" <<<"$positive"; then
  fail "the Secret name is not the Deployment volume's secretName"
fi
if ! grep -qE "^[[:space:]]*value:[[:space:]]*/etc/ctf-answers/${sentinel_key}[[:space:]]*$" <<<"$positive"; then
  fail "ANSWERS_FILE is not /etc/ctf-answers/<key>"
fi
if [ "$(count_of "$positive" "name: ANSWERS_FILE")" -ne 1 ]; then
  fail "ANSWERS_FILE is not set exactly once"
fi
if [ "$(count_of "$positive" "mountPath: /etc/ctf-answers")" -ne 1 ]; then
  fail "the answers Secret is not mounted exactly once"
fi
# The two lines of the mount (mountPath, then readOnly). Not a pipe into grep -q:
# under pipefail an early exit of the reader would read as a failure.
mount_lines="$(grep -A1 -F "mountPath: /etc/ctf-answers" <<<"$positive" || true)"
if ! grep -qE '^[[:space:]]*readOnly:[[:space:]]*true[[:space:]]*$' <<<"$mount_lines"; then
  fail "the answers mount is not readOnly"
fi

echo "== answersSecret disabled (default) =="
default=""
if ! default="$(helm template "$chart" --namespace scoreboard 2>&1)"; then
  echo "FAIL: helm template failed for the default values:" >&2
  echo "$default" >&2
  exit 1
fi
if [ "$(count_of "$default" "ANSWERS_FILE")" -ne 0 ] || [ "$(count_of "$default" "ctf-answers")" -ne 0 ]; then
  fail "the default render mentions ANSWERS_FILE or the answers mount"
fi

# expect_refusal DESCRIPTION REASON ARGS...: helm template with ARGS must fail, and
# its output must contain REASON.
expect_refusal() {
  local desc="$1" reason="$2" out
  shift 2
  echo "== refuses: ${desc} =="
  if out="$(helm template "$chart" "$@" 2>&1)"; then
    fail "${desc}: the render succeeded, want a refusal"
    return
  fi
  if ! grep -qF -- "$reason" <<<"$out"; then
    fail "${desc}: the render failed, but not with '${reason}':"
    echo "$out" >&2
  fi
}

expect_refusal "answersSecret without flagsSecret (outside the event mode)" "ADR-0056 D8" \
  --namespace scoreboard --set answersSecret.enabled=true
expect_refusal "grader namespace equal to the release namespace" "ADR-0056 D13" \
  --namespace other-ns --set flagsSecret.enabled=true --set answersSecret.enabled=true \
  --set env.detectGraderNamespace=other-ns
expect_refusal "grader namespace equal to the Deployment's namespace" "ADR-0056 D13" \
  --namespace other-ns --set flagsSecret.enabled=true --set answersSecret.enabled=true \
  --set env.detectGraderNamespace=scoreboard
expect_refusal "a key that is not a file name" "answersSecret.key" \
  --namespace scoreboard --set flagsSecret.enabled=true --set answersSecret.enabled=true \
  --set "answersSecret.key=../x"

echo
if [ "$rc" -ne 0 ]; then
  echo "FAIL: the answers Secret checks of charts/scoreboard did not hold (ADR-0056 D13, V2) - see FAIL lines above." >&2
  exit 1
fi
echo "OK: the answers Secret of charts/scoreboard is mounted into the scoreboard container only, and the render refuses the placements D8 / D13 forbid."
