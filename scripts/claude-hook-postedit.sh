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
    # Check formatting — non-zero means file needs gofmt
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
  deploy/*.yaml|deploy/**/*.yaml)
    # Validate kustomize overlays when a deploy manifest changes
    if command -v kubectl >/dev/null 2>&1; then
      for d in deploy/*/overlays/*/; do
        [[ -d "$d" ]] || continue
        kubectl kustomize "$d" >/dev/null 2>&1 \
          || echo "kustomize: build failed for $d" >&2
      done
    fi
    ;;
esac

exit 0
