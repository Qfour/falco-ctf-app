#!/usr/bin/env bash
# Pattern-aware Stop hook.
# Detects changed file patterns (vs main) and runs appropriate gates automatically.
# All failures are advisory (exit 0); secrets check is the only blocker (in pre-commit hook).

set -euo pipefail

cd "$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

CHANGED=$(git diff --name-only main...HEAD 2>/dev/null || true)
[[ -z "$CHANGED" ]] && exit 0

# ---- Pattern detection ----
HAS_GO=$(echo "$CHANGED"    | grep -cE '^(cmd|internal)/|^go\.(mod|sum)$|^(scoreboard|auth-policy)/Dockerfile$' || true)
HAS_CHART=$(echo "$CHANGED"  | grep -cE '^charts/' || true)
HAS_IMAGE=$(echo "$CHANGED"  | grep -cE '^images/|^Dockerfile\.(test|tidy|gen)$' || true)

# ---- A: Go pattern — run make test if new commits haven't been tested ----
if [[ "$HAS_GO" -gt 0 ]]; then
    LAST_GO_COMMIT=$(git log --format='%H' -1 -- cmd/ internal/ go.mod go.sum scoreboard/Dockerfile auth-policy/Dockerfile 2>/dev/null || echo "")
    LAST_TESTED=$(cat .claude/last-test-commit 2>/dev/null || echo "")
    if [[ -n "$LAST_GO_COMMIT" && "$LAST_TESTED" != "$LAST_GO_COMMIT" ]]; then
        echo "==> [Stop] Go 変更を検出 — make test を実行中..."
        if make test; then
            mkdir -p .claude
            echo "$LAST_GO_COMMIT" > .claude/last-test-commit
            echo "==> [Stop] make test PASSED — .claude/last-test-commit を更新"
        else
            echo "==> [Stop] make test FAILED — 修正してから再実行してください" >&2
        fi
    fi
fi

# ---- B: Chart pattern — run make lint (helm lint) ----
if [[ "$HAS_CHART" -gt 0 ]]; then
    echo "==> [Stop] Chart 変更を検出 — make lint を実行中..."
    make lint || echo "==> [Stop] make lint FAILED" >&2
fi

# ---- D: Image pattern — warn if scan-logs missing ----
if [[ "$HAS_IMAGE" -gt 0 ]]; then
    SCAN_FILES=$(ls scan-logs/ 2>/dev/null | wc -l || echo "0")
    if [[ "$SCAN_FILES" -eq 0 ]]; then
        echo "⚠️  [Stop] イメージ変更あり — make scan TAG=local の実行を確認してください" >&2
    fi
fi

exit 0
