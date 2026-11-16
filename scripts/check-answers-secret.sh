#!/usr/bin/env bash
# ADR-0056 V2 (the scoreboard part) and D13: the answers table's Secret is reachable
# from the scoreboard container only. Fail-closed render checks of charts/scoreboard
# with `answersSecret.enabled`, which the chart-lint job's default render never
# exercises (the default is disabled):
#
#   * a SENTINEL secret name and key are rendered, and the render is read by
#     scripts/check-answers-secret.py (the shared reader scripts/lib/chartparse.py,
#     by structure, not by counting strings): the sentinel name is the `secretName` of
#     one Deployment volume and appears nowhere else; the volumeMounts naming that
#     volume, over containers, initContainers and ephemeralContainers, are exactly
#     one, in the container `scoreboard`, readOnly; the key appears only as the value
#     of its ANSWERS_FILE. That python check is shown able to fail by its own
#     `--selftest` (no helm; `make check-answers-secret-selftest`);
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
structure=""
if structure="$(python3 -I scripts/check-answers-secret.py check \
  --sentinel-name "$sentinel_name" --sentinel-key "$sentinel_key" <<<"$positive" 2>&1)"; then
  echo "  ok: the Secret is mounted into the scoreboard container only, readOnly"
else
  fail "the answers Secret is not confined to the scoreboard container:"
  echo "$structure" >&2
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
