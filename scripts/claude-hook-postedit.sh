#!/usr/bin/env bash
# PostToolUse hook: lightweight lint after Write/Edit.
# Receives tool result JSON on stdin; extracts file_path and runs targeted checks.
# Failures are advisory (exit 0) so Claude is not blocked by local toolchain absence.

set -euo pipefail

INPUT=$(cat)
FILE=$(printf '%s' "$INPUT" | jq -r '.tool_input.file_path // ""' 2>/dev/null || true)

[[ -z "$FILE" ]] && exit 0
[[ ! -f "$FILE" ]] && exit 0

case "$FILE" in
  *.go)
    # Check formatting -- non-zero means file needs gofmt
    if command -v gofmt >/dev/null 2>&1; then
      UNFORMATTED=$(gofmt -l "$FILE")
      if [[ -n "$UNFORMATTED" ]]; then
        echo "gofmt: $FILE is not formatted (run gofmt -w $FILE)" >&2
      fi
    fi
    # Lightweight vet on the package
    if command -v go >/dev/null 2>&1; then
      PKG=$(dirname "$FILE")
      go vet "./$PKG" 2>&1 || true
    fi
    ;;
  */charts/*/templates/*.yaml|*/charts/*/values.yaml|*/charts/*/Chart.yaml)
    # Lint + render the chart when a chart file changes.
    if command -v helm >/dev/null 2>&1; then
      # chart dir = two levels up from templates/, or the dir of values/Chart.
      CHART_DIR=$(dirname "$FILE")
      [[ "$(basename "$CHART_DIR")" == "templates" ]] && CHART_DIR=$(dirname "$CHART_DIR")
      # P21 item 5: charts/{scoreboard,auth-policy,collector} depend on
      # charts/falco-ctf-common (a local file:// path dep) — helm lint/
      # template fail without a built charts/<chart>/charts/ dir. Best-effort
      # and silent: this hook is advisory (exit 0 regardless), and a bare
      # `helm dependency build` also refreshes any OTHER Helm repos configured
      # on this machine (unrelated global ~/.config/helm state), which must
      # not leak noise into hook stderr.
      if grep -q '^dependencies:' "$CHART_DIR/Chart.yaml" 2>/dev/null; then
        helm dependency build "$CHART_DIR" >/dev/null 2>&1 || true
      fi
      helm lint "$CHART_DIR" >/dev/null 2>&1 || echo "helm lint: failed for $CHART_DIR" >&2
      # library charts (charts/falco-ctf-common) are not installable — `helm
      # template` on one always fails regardless of content, so there is
      # nothing to render-check here; its callers are checked instead.
      if ! grep -qE '^type:[[:space:]]*library[[:space:]]*$' "$CHART_DIR/Chart.yaml" 2>/dev/null; then
        helm template "$CHART_DIR" >/dev/null 2>&1 || echo "helm template: render failed for $CHART_DIR" >&2
      fi
    fi
    ;;
  */challenges/*/falco-rule.yaml)
    # Validate challenge schema: required type field + evade flag format
    SLUG=$(basename "$(dirname "$FILE")")
    if ! grep -qE '^type:' "$FILE" 2>/dev/null; then
      echo "challenge schema: $SLUG - 'type:' field missing (must be trigger|evade)" >&2
    else
      TYPE=$(grep -m1 '^type:' "$FILE" | awk '{print $2}')
      TYPE=${TYPE//\"/}
      TYPE=${TYPE//\'/}
      if [[ "$TYPE" != "trigger" && "$TYPE" != "evade" ]]; then
        echo "challenge schema: $SLUG - type '$TYPE' invalid (must be trigger|evade)" >&2
      fi
      if [[ "$TYPE" == "evade" ]]; then
        FLAG=$(grep -m1 '^expectedFlag:' "$FILE" | awk '{print $2}')
        FLAG=${FLAG//\"/}
        FLAG=${FLAG//\'/}
        if [[ -z "$FLAG" ]]; then
          echo "challenge schema: $SLUG - evade challenge requires expectedFlag" >&2
        elif ! echo "$FLAG" | grep -qE '^FALCO\{[^}]+\}$'; then
          echo "challenge schema: $SLUG - expectedFlag must match FALCO{...}, got '$FLAG'" >&2
        fi
      fi
    fi
    ;;
  */Dockerfile|*/Dockerfile.*)
    # BuildKit lint -- catches syntax errors and deprecated instructions early
    if command -v docker >/dev/null 2>&1; then
      DIR=$(dirname "$FILE")
      docker build --check -f "$FILE" "$DIR" 2>&1 || true
    fi
    ;;
esac

exit 0
