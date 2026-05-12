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
  */deploy/*.yaml|*/deploy/**/*.yaml)
    # Validate kustomize overlays when a deploy manifest changes
    if command -v kubectl >/dev/null 2>&1; then
      REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
      for d in "$REPO_ROOT"/deploy/*/overlays/*/; do
        [[ -d "$d" ]] || continue
        kubectl kustomize "$d" >/dev/null 2>&1 \
          || echo "kustomize: build failed for $d" >&2
      done
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
